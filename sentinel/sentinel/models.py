# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""Core data model. Nothing in this module knows about any business domain."""
from __future__ import annotations

import hashlib
import json
import math
import uuid
from datetime import datetime, UTC
from enum import Enum
from typing import Any

from .factrule import name_problem
from pydantic import BaseModel, ConfigDict, Field, field_validator, PrivateAttr


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:16]}"


def utcnow() -> datetime:
    return datetime.now(UTC)


class Route(str, Enum):
    """How an incident gets resolved. Ordered from least to most autonomous."""

    HITL = "hitl"
    LLM = "llm"
    AUTO = "auto"

    @property
    def level(self) -> int:
        return {Route.HITL: 0, Route.LLM: 1, Route.AUTO: 2}[self]

    @classmethod
    def from_level(cls, level: int) -> Route:
        return [cls.HITL, cls.LLM, cls.AUTO][max(0, min(2, level))]


class IncidentState(str, Enum):
    OPEN = "open"
    SUPPRESSED = "suppressed"          # inhibited by a parent incident
    RESOLVING = "resolving"            # an auto/LLM resolver is working on it
    AWAITING_HUMAN = "awaiting_human"  # HITL review open
    RESOLVED = "resolved"              # action executed successfully, not yet dispositioned
    FAILED = "failed"                  # could not be resolved; needs a human disposition
    DISPOSITIONED = "dispositioned"    # terminal

    @property
    def terminal(self) -> bool:
        return self is IncidentState.DISPOSITIONED


class Event(BaseModel):
    """Canonical envelope. Every receiver normalises its source into this shape."""

    model_config = ConfigDict(frozen=True)

    id: str = Field(default_factory=lambda: new_id("evt"))
    type: str
    source: str
    tenant: str = "default"
    occurred_at: datetime = Field(default_factory=utcnow)
    idempotency_key: str | None = None
    correlation_id: str | None = None
    payload: dict[str, Any] = Field(default_factory=dict)

    @field_validator("type", "source")
    @classmethod
    def _not_blank(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("must not be blank")
        return v.strip()

    @property
    def dedupe_key(self) -> str:
        """Duplicates are recognised per tenant and source: the same key from two systems is two events."""
        if not self.idempotency_key:
            return self.id
        return f"{self.tenant}\x1f{self.source}\x1f{self.idempotency_key}"


class ActionSpec(BaseModel):
    """Declared metadata for an action an overlay can perform."""

    name: str
    description: str = ""
    reversible: bool = False   # has a compensating action
    safe: bool = False         # idempotent and does not change business state (re-sync, refresh): may run unattended
    max_attempts: int = 3
    timeout_s: float | None = None   # hard limit per attempt; a timed-out step's outcome is unknown -> a human checks
    params_schema: dict[str, Any] = Field(default_factory=dict)  # JSON-schema-ish: {"field": "str"|"int"|...}


class PlaybookStep(BaseModel):
    """One step of a playbook (or of a proposal, where only action steps appear).

    action  do something (params may be templates)       lookup  read-only tool; result kept under `as`
    close   finish with no action (with `disposition`)   when    the step runs only if this holds
    """

    model_config = ConfigDict(populate_by_name=True)

    action: str | None = None
    params: dict[str, Any] = Field(default_factory=dict)  # values may be "{{payload.x}}" templates
    lookup: str | None = None
    args: dict[str, Any] = Field(default_factory=dict)
    as_: str | None = Field(default=None, alias="as")
    close: bool = False
    when: dict[str, Any] | None = None
    disposition: str | None = None                       # disposition code when this step runs

    def model_post_init(self, _ctx: Any) -> None:
        kinds = sum([self.action is not None, self.lookup is not None, self.close])
        if kinds != 1:
            raise ValueError("a playbook step is exactly one of: action, lookup, close")
        if self.close and not self.disposition:
            raise ValueError("a close step needs a disposition")

    @property
    def kind(self) -> str:
        return "action" if self.action is not None else "lookup" if self.lookup is not None else "close"

    @property
    def result_name(self) -> str:
        return self.as_ or (self.lookup or "").replace(".", "_")

    def plain(self) -> dict[str, Any]:
        """Only the fields that are set (the definition hash and YAML use this)."""
        d = self.model_dump(mode="json", by_alias=True, exclude_defaults=True)
        if self.action is not None:
            d.setdefault("params", {})
        return d


class EscalationRule(BaseModel):
    """How often an unanswered review is sent again once it has reached the top of the role tree."""
    model_config = ConfigDict(extra="forbid")
    repeat: int | None = Field(default=None, ge=0)   # re-sends at the top; then only the daily overdue list
    stop_at: str | list[str] | None = None           # the highest role(s) it climbs to (e.g. the function heads)

    def stops(self) -> list[str]:
        return [self.stop_at] if isinstance(self.stop_at, str) else list(self.stop_at or [])


class ClearEvent(BaseModel):
    """An event that says the problem is gone (an order fulfilled, a location back up)."""
    model_config = ConfigDict(extra="forbid")
    type: str
    same: list[str] = Field(min_length=1)            # facts that must be equal between the case and the event


class ClearLookup(BaseModel):
    """A read-only lookup asked on a schedule while the case is open; the case closes when it holds."""
    model_config = ConfigDict(extra="forbid")
    tool: str
    args: dict[str, Any] = Field(default_factory=dict)          # templates: {{facts.x}}, {{payload.y}}
    condition: dict[str, Any]                                    # over {result, facts, payload}
    every_minutes: int = Field(default=30, ge=1)


class ClearWhen(BaseModel):
    model_config = ConfigDict(extra="forbid")
    events: list[ClearEvent] = Field(default_factory=list)
    lookup: ClearLookup | None = None


def strict_number(v: Any) -> Any:
    """A YAML/JSON number: never a boolean, text or NaN/infinity (None passes for optional settings)."""
    if v is None:
        return v
    if isinstance(v, bool) or not isinstance(v, int | float) or not math.isfinite(v):
        raise ValueError("a finite number (not true/false or text)")
    return v


class DataTrust(BaseModel):
    """Data trust caps autonomy per scope (Layer A -> B). A scope's score (0..1, e.g. a store's record accuracy,
    receiving lag, unit errors) is set by monitoring; below ``act_min`` agents there only PROPOSE, below
    ``propose_min`` they only OBSERVE, whatever trust their templates earned elsewhere. Scores older than
    ``max_age_hours`` count as unknown; ``unknown`` says what an unknown score means (none: no cap)."""
    model_config = ConfigDict(extra="forbid")
    act_min: float = Field(default=0.95, ge=0, le=1)
    propose_min: float = Field(default=0.80, ge=0, le=1)
    max_age_hours: float = Field(default=48, gt=0)
    unknown: str = "none"                                         # none | PROPOSE | OBSERVE
    sources: list[str] | None = None        # service principals that may post scores (None: any service token)

    @field_validator("act_min", "propose_min", "max_age_hours", mode="before")
    @classmethod
    def _numbers(cls, v: Any) -> Any:
        return strict_number(v)

    @field_validator("sources", mode="before")
    @classmethod
    def _sources(cls, v: Any) -> Any:
        if v is not None and (not isinstance(v, list) or not v or any(name_problem(x) is not None for x in v)):
            raise ValueError("sources: a non-empty list of service principal ids")
        return v

    def model_post_init(self, _ctx: Any) -> None:
        if self.propose_min > self.act_min:
            raise ValueError("data_trust: propose_min must not be above act_min")
        self.unknown = self.unknown if self.unknown == "none" else self.unknown.upper()
        if self.unknown not in ("none", "PROPOSE", "OBSERVE"):
            raise ValueError("data_trust: unknown is none, PROPOSE or OBSERVE")


class CaseDefaults(BaseModel):
    """The registry's ``defaults:`` - for every exception that does not set its own."""
    model_config = ConfigDict(extra="forbid")
    escalation: EscalationRule | None = None
    expires_after_hours: float | None = Field(default=None, ge=0)
    pause_on: list[str] = Field(default_factory=list)
    digest_hour: int = Field(default=9, ge=0, le=23)             # when the daily overdue list goes out
    timezone: str = "UTC"
    data_trust: DataTrust | None = None                           # scope data trust caps agent modes


class Hold(BaseModel):
    """A review whose clock is stopped: paused by a person (waiting on a customer) or held by a silence."""
    kind: str                                                    # pause | silence
    reason: str
    since: datetime
    until: datetime
    remaining_s: float = 0.0                                     # SLA left when it was paused
    by: str | None = None
    silence_id: str | None = None


class Silence(BaseModel):
    """Planned noise: cases that match are still recorded but nobody is sent a card and nothing runs on
    its own until the silence ends (a stock count tonight, a warehouse move)."""
    id: str = Field(default_factory=lambda: new_id("sil"))
    pattern: str | None = None                                   # one exception, or all of them
    facts: dict[str, Any] = Field(default_factory=dict)          # fact -> value or [values]
    starts_at: datetime
    ends_at: datetime
    reason: str
    by: str
    created_at: datetime = Field(default_factory=utcnow)
    ended_at: datetime | None = None
    ended_by: str | None = None

    def active(self, now: datetime) -> bool:
        return self.ended_at is None and self.starts_at <= now < self.ends_at

    def covers(self, pattern_id: str, facts: dict[str, Any]) -> bool:
        if self.pattern and self.pattern != pattern_id:
            return False
        for k, v in self.facts.items():
            have = facts.get(k)
            if isinstance(v, list) and have not in v or not isinstance(v, list) and have != v:
                return False
        return True


class Capability(BaseModel):
    """A business capability (Inventory & Replenishment, Finance & MIS): what the business does, who is
    accountable, what it must never do, and how its results are measured. Exceptions belong to one; the
    capability caps how far they may be automated and can be switched to observe only (instrumented and
    measured, nothing acted on without a person) while the business decides whether to deploy it."""
    model_config = ConfigDict(extra="forbid")
    title: str
    owner: str | None = None                                   # the accountable role
    description: str = ""
    intent: list[str] = Field(default_factory=list)            # what it exists for and must never do (people change it)
    outcomes: list[str] = Field(default_factory=list)          # metrics that show whether it works
    max_route: Route = Route.AUTO                              # no exception in it may be automated further
    mode: str = "act"                                          # act | observe (every exception in shadow)

    @field_validator("mode")
    @classmethod
    def _mode(cls, v: str) -> str:
        if v not in ("act", "observe"):
            raise ValueError("mode is act or observe")
        return v


class Provenance(BaseModel):
    """What decided a case: its capability, the method of work and the exact definition it ran under, and
    the registry version that was live. Kept on the case and on its disposition, so outcomes can be compared
    method by method and any decision traced back to the rules that made it."""
    capability: str | None = None
    method: str | None = None            # the method's name and version as the registry states it
    definition: str | None = None        # hash of what the exception means (playbook, match, limits ...)
    config: str | None = None            # registry version live when the case opened ("v7"); None = files
    trial: str | None = None             # a candidate method being tried on this case (randomised trial)
    agent: str | None = None             # the agent identity that ran it: template@scope (ADR-003 C1)
    agent_mode: str | None = None        # its mode in that scope when the case opened (OFF/OBSERVE/PROPOSE/ACT)


class Pattern(BaseModel):
    """A registry entry: what an incident type is and how it may be resolved."""

    id: str
    description: str = ""
    event_types: list[str]
    match: dict[str, Any] = Field(default_factory=dict)       # fact -> value, "*", [values] or {op: value}
    route: Route = Route.HITL                                  # default route; learning may override
    max_route: Route = Route.AUTO                              # ceiling learning may promote to
    playbook: list[PlaybookStep] = Field(default_factory=list)  # deterministic resolution (needed for AUTO)
    allowed_actions: list[str] = Field(default_factory=list)   # what LLM / humans may choose
    disposition_codes: list[str] = Field(default_factory=lambda: ["resolved", "no_action", "false_positive"])
    owner_role: str = "operator"
    escalation_role: str | None = None
    owner_slot: str | None = None        # role slot (ADR-003): the tenant's slot_bindings decide owner_role
    escalation_slot: str | None = None   # role slot for escalation_role; a template names slots, never org roles
    sla_minutes: int = 240
    severity: str = "medium"
    llm_min_confidence: float = 0.8
    group_window_minutes: int | None = None                    # None: an open incident absorbs repeats while open
    inhibited_by: list[str] = Field(default_factory=list)      # pattern ids whose open incident suppresses this one
    inhibit_on: list[str] = Field(default_factory=list)        # facts that must be equal between parent and child
    playbook_disposition: str = "resolved"
    llm_instructions: str = ""
    model_task: str | None = None                              # model route for the LLM step (None = "diagnose")
    sop: str = ""                                              # the team's procedure for this exception (Markdown)
    brief_fields: list[str] = Field(default_factory=list)      # payload fields the model sees (empty: all)
    trust_by: list[str] = Field(default_factory=list)          # earn trust separately per these facts (e.g. channel)
    trust_pool_min: int | None = Field(default=None, ge=1)     # pooled trust: a segment uses the template's trust
                                                               # until it has this many decisions of its own
    digest_above: int | None = Field(default=None, ge=1)       # past this many open cases: one digest, not a card each
    digest_every_minutes: int = Field(default=60, ge=5)        # how often that digest goes out
    money_fact: str | None = None                              # fact or payload field with the money at stake (ranking)
    data_trust_exempt: bool = False                            # not capped by scope data trust (e.g. the data checks)
    spot_check_rate: float | None = Field(default=None, ge=0, le=1)   # share of unattended decisions a person checks
    claims: list[str] = Field(default_factory=list)            # facts naming the object it acts on (store, article)
    claim_minutes: int = Field(default=60, ge=1)               # another template may not act on it alone this long
    llm_max_steps: int = Field(default=1, ge=1, le=10)         # actions a model may propose in one resolution
    diagnose: bool = True                                      # human-route cases: the model prepares a proposal first
    shadow: bool = False                                       # recommend only: a person approves everything
    effort_minutes: float | None = None                        # a person's time per case (value report)
    priority: int = 0                                          # higher wins when several patterns match
    outcome_check: dict[str, Any] | None = None                # {verifier, after_minutes, params, codes}
    escalation: EscalationRule | None = None                   # None: the registry default (else unlimited)
    clear_when: ClearWhen | None = None                        # how Sentinel sees the problem is gone
    expires_after_hours: float | None = Field(default=None, ge=0)  # close untouched cases; 0 = never
    pause_on: list[str] = Field(default_factory=list)          # reasons a person may stop the clock
    capability: str | None = None                              # the business capability it belongs to
    method: str | None = None                                  # its method of work, named and versioned ("match@2")
    layer: str = ""                                            # registry layer that defined it (trunk, retail, ...)
    overridden_in: list[str] = Field(default_factory=list)     # layers that changed it

    _slots_resolved: bool = PrivateAttr(default=False)          # owner/escalation role came from slot_bindings

    def slot_info(self) -> dict[str, str]:
        """The role slots this pattern names, for explanations (empty when it names roles directly)."""
        return {k: v for k, v in (("owner_slot", self.owner_slot), ("escalation_slot", self.escalation_slot)) if v}

    @field_validator("trust_pool_min", "digest_above", "digest_every_minutes", "spot_check_rate", "claim_minutes",
                     mode="before")
    @classmethod
    def _no_bools(cls, v: Any) -> Any:
        """Settings added in v0.18-v0.24 are strict: a YAML number, never true/false or text ("0.5")."""
        return strict_number(v)

    @field_validator("money_fact", mode="before")
    @classmethod
    def _fact_name(cls, v: Any) -> Any:
        if v is not None and name_problem(v) is not None:
            raise ValueError("a fact name (non-empty text)")
        return v

    @field_validator("data_trust_exempt", mode="before")
    @classmethod
    def _strict_flag(cls, v: Any) -> Any:
        if not isinstance(v, bool):
            raise ValueError("true or false")
        return v

    @field_validator("claims", "trust_by", "inhibit_on", "brief_fields", mode="before")
    @classmethod
    def _fact_names(cls, v: Any) -> Any:
        if not isinstance(v, list) or any(name_problem(x) is not None for x in v):
            raise ValueError("a list of fact names (non-empty text)")
        return v

    # fields whose change alters what the pattern means; trust earned under the old meaning is reset
    _BEHAVIOUR_FIELDS = ("event_types", "match", "max_route", "playbook", "allowed_actions", "disposition_codes",
                         "llm_min_confidence", "inhibited_by", "inhibit_on", "playbook_disposition")

    def definition_hash(self, fingerprint: str | None = None) -> str:
        """What the pattern means. ``fingerprint`` is the hash of the fingerprint rules for its event types:
        they decide which facts the pattern matches and groups on, so changing them changes its meaning too."""
        data = self.model_dump(mode="json", include=set(self._BEHAVIOUR_FIELDS))
        data["playbook"] = [st.plain() for st in self.playbook]   # unchanged for action-only playbooks
        if self.trust_by:                                          # only when set, so older hashes stay stable
            data["trust_by"] = list(self.trust_by)
        if self.llm_max_steps != 1:
            data["llm_max_steps"] = self.llm_max_steps
        if self.trust_pool_min is not None:                        # only when set, so older hashes stay stable
            data["trust_pool_min"] = self.trust_pool_min
        if fingerprint:
            data["fingerprint"] = fingerprint
        return hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()[:16]

    def matches(self, event_type: str, facts: dict[str, Any]) -> bool:
        """``match`` uses the same condition language as playbook ``when`` (operators, all/any/not), plus two
        shorthands: "*" means the fact is present, and a list means one of these values."""
        if event_type not in self.event_types:
            return False
        from .expr import match_facts
        return match_facts(self.match, facts)


class Proposal(BaseModel):
    """A recommended resolution, from a playbook, an LLM or a human. Empty steps = close without acting."""

    steps: list[PlaybookStep] = Field(default_factory=list)
    disposition_code: str = "resolved"
    confidence: float = 1.0
    rationale: str = ""
    source: str = "playbook"            # playbook | llm | human
    proposed_by: list[str] = Field(default_factory=list)   # people whose decision forwarded it: never its approver

    @property
    def actions(self) -> list[str]:
        return [st.action for st in self.steps]

    def same_as(self, steps: list[PlaybookStep], code: str) -> bool:
        return ([(s.action, s.params) for s in self.steps] == [(s.action, s.params) for s in steps]
                and self.disposition_code == code)


class Incident(BaseModel):
    id: str = Field(default_factory=lambda: new_id("inc"))
    tenant: str = "default"
    pattern_id: str
    fingerprint: str
    state: IncidentState = IncidentState.OPEN
    route: Route
    shadow: bool = False
    event_ids: list[str] = Field(default_factory=list)
    first_event: dict[str, Any] = Field(default_factory=dict)
    facts: dict[str, Any] = Field(default_factory=dict)
    proposal: Proposal | None = None
    parent_id: str | None = None
    attempts: int = 0
    last_error: str | None = None
    provenance: Provenance | None = None
    created_at: datetime = Field(default_factory=utcnow)
    updated_at: datetime = Field(default_factory=utcnow)
    odd_facts: list[str] = Field(default_factory=list)  # scope facts that arrived as no plain value: a person decides


class ReviewTask(BaseModel):
    id: str = Field(default_factory=lambda: new_id("rev"))
    incident_id: str
    assignee_role: str
    reason: str
    proposal: Proposal | None = None
    due_at: datetime
    escalation_level: int = 0
    open: bool = True
    created_at: datetime = Field(default_factory=utcnow)
    hold: Hold | None = None            # clock stopped (paused or silenced)
    quiet: bool = False                 # stopped re-sending: on the daily overdue list only
    top_repeats: int = 0                # times sent again at the top of the role tree
    rounds: int = 0                     # times sent again after a hold ended
    reported_at: datetime | None = None  # the source last reported the problem again
    digested: bool = False              # the template is past its digest threshold: no card, on its digest


class DecisionKind(str, Enum):
    APPROVE = "approve"   # execute the proposal as-is
    MODIFY = "modify"     # execute a different action/params
    REJECT = "reject"     # close without executing (disposition only)


class Decision(BaseModel):
    kind: DecisionKind
    actor: str
    action: str | None = None                       # shorthand for a single step
    params: dict[str, Any] = Field(default_factory=dict)
    steps: list[PlaybookStep] | None = None         # or several steps
    disposition_code: str | None = None
    note: str = ""

    def resolved_steps(self) -> list[PlaybookStep]:
        if self.steps is not None:
            return list(self.steps)
        return [PlaybookStep(action=self.action, params=self.params)] if self.action else []


class Disposition(BaseModel):
    id: str = Field(default_factory=lambda: new_id("dsp"))
    incident_id: str
    pattern_id: str
    fingerprint: str
    code: str
    resolver: str                       # auto | llm | human | parent
    steps: list[PlaybookStep] = Field(default_factory=list)
    proposal_source: str | None = None
    agreed_with_proposal: bool | None = None
    shadow: bool = False
    reversed: bool = False
    outcome: str | None = None          # held | failed | unknown (set by the outcome verifier)
    outcome_detail: str = ""
    actor: str | None = None
    note: str = ""
    provenance: Provenance | None = None
    created_at: datetime = Field(default_factory=utcnow)
    spot_check: str | None = None       # pending | passed | failed: a person checks an unattended decision
    spot_checked_by: str | None = None
    trust_charged: bool = False         # this decision already lowered trust once (a mistake counts once)


class PatternState(BaseModel):
    """Learned state per pattern. Persisted; survives restarts."""

    pattern_id: str                 # "<pattern>" or "<pattern>@<fact>=<value>|..." for a segment
    route: Route
    streak: int = 0                 # consecutive good outcomes at the current level
    samples: int = 0
    agreements: int = 0
    reversals: int = 0
    pending_promotion: Route | None = None
    promotion_approvals: list[str] = Field(default_factory=list)   # people who approved the pending promotion
    definition_hash: str | None = None                             # pattern definition the trust was earned on
    outcomes_held: int = 0
    outcomes_failed: int = 0
    cap: Route | None = None        # a person's or oversight's hold on this scope: pooled trust never goes above it
    updated_at: datetime = Field(default_factory=utcnow)


class ActionResult(BaseModel):
    ok: bool
    detail: str = ""
    data: dict[str, Any] = Field(default_factory=dict)
    retryable: bool = True


class WorkItem(BaseModel):
    """A unit of background work: resolve an incident, check an outcome, deliver a review card."""

    id: str = Field(default_factory=lambda: new_id("wrk"))
    kind: str
    incident_id: str | None = None
    payload: dict[str, Any] = Field(default_factory=dict)
    status: str = "queued"            # queued | leased | done | dead
    attempts: int = 0
    max_attempts: int = 5
    run_after: datetime = Field(default_factory=utcnow)
    lease_until: datetime | None = None
    leased_by: str | None = None
    last_error: str | None = None
    dedupe_key: str | None = None
