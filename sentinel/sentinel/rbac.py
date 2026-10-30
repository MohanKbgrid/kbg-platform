# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""People, roles and approval authority.

Model
  * Roles form a tree (each role has an optional parent). A parent outranks its children:
    it sees their review queues and inherits their authority. SLA escalation walks up the tree.
  * People hold roles through assignments, optionally scoped to facts (a store manager is
    assigned `store_manager` with scope {location: STORE_FLG} and only acts on that location).
  * Authority rules say what a role may do with an action: `approve` (execute it) or `propose`
    (suggest it; someone senior must approve). Rules can carry an amount limit read from a param.
  * Meta actions guard the control surface: `__promote__`, `__set_route__`, `__kill_switch__`,
    `__reverse__`. Promotions to AUTO need two distinct approvers by default.

Org layer (ADR-003 C1), all optional; a directory that uses none of it behaves exactly as before:
  * Dotted lines: ``Role.dotted`` lists roles that also see this role's queue (visibility only: no
    inherited authority, never on the escalation path).
  * Time-bound assignments: ``valid_from`` / ``valid_to``. Outside that window the assignment does not count;
    the history stays in the file.
  * Typed hierarchical scopes: ``scopes:`` declares dimensions whose values roll up (a category tree within one
    dimension, or store -> region across dimensions). An assignment scoped to a higher value covers everything
    below it.
  * Vacancy and stop list: ``holders(role, facts)`` returns the people holding a role in scope, or the nearest
    role above that has someone, never climbing past a role in ``stop_at``. ``vacancy: escalate`` makes new
    reviews for a vacant role go to that nearest held role (off by default).

With no Directory configured the engine runs in open mode (actor is free text), which keeps
prototypes and tests simple; production deployments configure one.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any
from collections.abc import Callable, Iterable

import yaml
from pydantic import BaseModel, Field, field_validator

from .factrule import scope_problem
from .models import PlaybookStep, strict_number

META_ACTIONS = ("__promote__", "__set_route__", "__kill_switch__", "__reverse__", "__configure__", "__access__",
                "__silence__",
                "__privacy__")


class Role(BaseModel):
    id: str
    name: str = ""
    parent: str | None = None
    description: str = ""
    dotted: list[str] = Field(default_factory=list)   # dotted-line roles: they see this queue, nothing more


class Person(BaseModel):
    id: str
    name: str = ""
    contact: dict[str, str] = Field(default_factory=dict)   # email, phone, whatsapp ...
    edges: list[str] = Field(default_factory=list)          # preferred delivery channels, in order
    active: bool = True
    language: str = ""                                      # cards in hi, ta, te, kn, mr, bn, gu, ml, pa (default en)


class Assignment(BaseModel):
    person_id: str
    role_id: str
    scope: dict[str, Any] = Field(default_factory=dict)     # fact -> value | [values]; empty = everywhere

    @field_validator("scope", mode="before")
    @classmethod
    def _scope_rule(cls, v: Any) -> Any:
        if v is None:
            return {}
        if (why := scope_problem(v, lists=True)) is not None:
            raise ValueError(f"scope: {why}")
        return v
    valid_from: datetime | date | None = None               # None: since always
    valid_to: datetime | date | None = None                 # None: until changed; exclusive end

    def model_post_init(self, _ctx: Any) -> None:
        if self.valid_from is not None and self.valid_to is not None and \
                _instant(self.valid_to) <= _instant(self.valid_from):
            raise ValueError(f"assignment {self.person_id}/{self.role_id}: valid_to must be after valid_from")

    def current(self, at: datetime) -> bool:
        return ((self.valid_from is None or _instant(self.valid_from) <= at)
                and (self.valid_to is None or at < _instant(self.valid_to)))


def _instant(v: datetime | date) -> datetime:
    if isinstance(v, datetime):
        return v if v.tzinfo else v.replace(tzinfo=UTC)
    return datetime(v.year, v.month, v.day, tzinfo=UTC)


class OversightRule(BaseModel):
    """Who oversees which agents (Layer D). The role must own none of them: it is not a template's owner or
    escalation role, nor above one on the solid line (ADR-003 invariant 5)."""
    role: str
    templates: list[str] = Field(default_factory=lambda: ["*"])   # pattern ids, capability ids or "*"

    def covers(self, pattern_id: str, capability: str | None) -> bool:
        return "*" in self.templates or pattern_id in self.templates or (capability in self.templates
                                                                         if capability else False)


AGENT_MODES = ("OFF", "OBSERVE", "PROPOSE", "ACT")
AGENT_GRANTS = ("VIEW", "EDIT")


class AgentPolicy(BaseModel):
    """How far an agent (a template run in a scope) may go (ADR-003 C1). Most specific row wins: a pattern id
    beats its capability, which beats "*"; then the row with more scope keys.

      OFF      the template takes no cases in that scope (events go to people as unmatched)
      OBSERVE  shadow: it proposes, a person decides everything
      PROPOSE  a person approves each proposal (never unattended)
      ACT      acts on its own up to the route it has earned, inside the pattern's ceiling and the limits

    ``grants`` name what it may touch unattended: VIEW or EDIT per action (or object). With grants set, an
    unattended step on an action without EDIT goes to a person. APPROVE is never grantable to an agent."""
    template: str = "*"                                     # pattern id, capability id or "*"
    scope: dict[str, Any] = Field(default_factory=dict)

    @field_validator("scope", mode="before")
    @classmethod
    def _scope_rule(cls, v: Any) -> Any:
        if v is None:
            return {}
        if (why := scope_problem(v, lists=True)) is not None:
            raise ValueError(f"scope: {why}")
        return v
    mode: str
    grants: dict[str, str] = Field(default_factory=dict)
    valid_from: datetime | date | None = None
    valid_to: datetime | date | None = None

    def model_post_init(self, _ctx: Any) -> None:
        self.mode = str(self.mode).upper()
        if self.mode not in AGENT_MODES:
            raise ValueError(f"agent mode must be one of {AGENT_MODES}, got {self.mode!r}")
        for obj, g in list(self.grants.items()):
            g = str(g).upper()
            if g == "APPROVE" or obj == "__approve__":
                raise ValueError(f"agent {self.template}: APPROVE is never grantable to an agent")
            if g not in AGENT_GRANTS:
                raise ValueError(f"agent {self.template}: grant on {obj!r} must be VIEW or EDIT, got {g!r}")
            self.grants[obj] = g

    def current(self, at: datetime) -> bool:
        return ((self.valid_from is None or _instant(self.valid_from) <= at)
                and (self.valid_to is None or at < _instant(self.valid_to)))


class ScopeDimension(BaseModel):
    """A fact whose values roll up. ``parents`` maps a value to the value above it: in the same dimension
    (a category tree: rice -> staples -> grocery) or, with ``rolls_up_to``, in another dimension
    (store TVM01 -> region south). An assignment scoped to a value covers every value below it."""
    parents: dict[str, str] = Field(default_factory=dict)
    rolls_up_to: str | None = None


class AuthorityRule(BaseModel):
    role_id: str
    action: str                                             # action name, "*" or a META action
    level: str = "approve"                                  # approve | propose
    patterns: list[str] = Field(default_factory=lambda: ["*"])
    max_amount: float | None = None

    @field_validator("max_amount", mode="before")
    @classmethod
    def _amount(cls, v: Any) -> Any:
        return strict_number(v)
    amount_param: str = "amount"

    @field_validator("amount_param", mode="before")
    @classmethod
    def _param(cls, v: Any) -> Any:
        from .factrule import name_problem
        if name_problem(v) is not None:
            raise ValueError("amount_param: a parameter name (non-empty text)")
        return v
    inherit: bool = True            # False: senior roles do not inherit it (only this role holds it)
    needs_proposal: bool = False    # approve only a proposal someone else made (never act on one's own)

    def model_post_init(self, _ctx: Any) -> None:
        if self.level not in ("approve", "propose"):
            raise ValueError(f"authority level must be approve|propose, got {self.level!r}")
        if self.max_amount is not None and self.max_amount < 0:
            raise ValueError("max_amount must be >= 0")


class UnattendedRule(BaseModel):
    """How far an automatic playbook (`auto`) or the model (`llm`) may go on its own, per action.

        unattended:
          - {resolver: "*", action: post_salesman_shortage, max_amount: 2000}
          - {resolver: llm, action: refund_payment, max_amount: 500, patterns: [refund_small]}

    Without a rule for an action, the lowest amount limit any person has for it applies, so a playbook or
    the model never does on its own more than the most junior approver could."""
    resolver: str = "*"                                     # auto | llm | *
    action: str                                             # action name or "*"
    patterns: list[str] = Field(default_factory=lambda: ["*"])
    max_amount: float | None = None                         # None: no limit

    @field_validator("max_amount", mode="before")
    @classmethod
    def _amount(cls, v: Any) -> Any:
        return strict_number(v)
    amount_param: str = "amount"

    @field_validator("amount_param", mode="before")
    @classmethod
    def _param(cls, v: Any) -> Any:
        from .factrule import name_problem
        if name_problem(v) is not None:
            raise ValueError("amount_param: a parameter name (non-empty text)")
        return v

    def model_post_init(self, _ctx: Any) -> None:
        if self.resolver not in ("auto", "llm", "*"):
            raise ValueError(f"unattended resolver must be auto|llm|*, got {self.resolver!r}")
        if self.max_amount is not None and self.max_amount < 0:
            raise ValueError("max_amount must be >= 0")


@dataclass
class Authorization:
    allowed: bool
    reason: str
    escalate_to: str | None = None
    proposable: bool = False      # the person may propose these steps; escalate_to may approve them


class DirectoryError(ValueError):
    pass


class ValueSettings(BaseModel):
    """What an hour of people's time costs, for the value report (money saved by automatic resolutions)."""
    currency: str = "INR"
    hourly_cost: float = Field(default=400.0, ge=0)          # loaded cost of an operations person, per hour
    default_minutes: float = Field(default=8.0, gt=0)        # a person's effort per case unless a pattern says
    model_cost_rate: float = Field(default=84.0, gt=0)       # model prices are in USD: this many per USD


class ConfigApproval(BaseModel):
    """Maker-checker for configuration: a version is published only after ``approvals`` people who hold
    __configure__, other than its author, have approved it."""
    approvals: int = Field(default=1, ge=1, le=5)
    kinds: list[str] = Field(default_factory=lambda: ["registry", "people", "connectors", "models"])


class ScimGrant(BaseModel):
    role: str
    scope: dict[str, Any] = Field(default_factory=dict)

    @field_validator("scope", mode="before")
    @classmethod
    def _scope_rule(cls, v: Any) -> Any:
        if v is None:
            return {}
        if (why := scope_problem(v, lists=True)) is not None:
            raise ValueError(f"scope: {why}")
        return v


class ScimSettings(BaseModel):
    """Provisioning from the company directory (Entra ID, Okta, Google): which roles each group gives."""
    group_roles: dict[str, list[str | ScimGrant]] = Field(default_factory=dict)   # group name -> roles
    default_roles: list[str] = Field(default_factory=list)                     # every provisioned person

    def grants(self, group: str) -> list[ScimGrant]:
        return [g if isinstance(g, ScimGrant) else ScimGrant(role=g) for g in self.group_roles.get(group, [])]

    def roles(self) -> set[str]:
        return {g.role for grp in self.group_roles for g in self.grants(grp)} | set(self.default_roles)


class Directory:
    def __init__(self, roles: Iterable[Role], people: Iterable[Person] = (), assignments: Iterable[Assignment] = (),
                 rules: Iterable[AuthorityRule] = (), *, two_person_auto_promotion: bool = True,
                 unattended: Iterable[UnattendedRule] = (), config_approval: ConfigApproval | None = None,
                 value: ValueSettings | None = None, scim: ScimSettings | None = None,
                 scopes: dict[str, ScopeDimension] | None = None, stop_at: Iterable[str] = (),
                 vacancy: str = "off", sod: Iterable[Any] = (), agents: Iterable[AgentPolicy] = (),
                 oversight: Iterable[OversightRule] = ()) -> None:
        self.scim = scim
        self.oversight: list[OversightRule] = list(oversight)
        self.agents: list[AgentPolicy] = list(agents)
        self.sod = list(sod)                                   # sentinel.org.SodRule pairs (C2)
        self.scopes: dict[str, ScopeDimension] = dict(scopes or {})
        self.stop_at: list[str] = list(stop_at)
        if vacancy not in ("off", "escalate"):
            raise DirectoryError(f"vacancy must be off|escalate, got {vacancy!r}")
        self.vacancy = vacancy
        self.clock: Callable[[], datetime] | None = None       # the engine sets its clock; None = wall clock
        self.roles: dict[str, Role] = {}
        for r in roles:
            if r.id in self.roles:
                raise DirectoryError(f"duplicate role {r.id}")
            self.roles[r.id] = r
        self.people: dict[str, Person] = {}
        for p in people:
            if p.id in self.people:
                raise DirectoryError(f"duplicate person {p.id}")
            self.people[p.id] = p
        self.assignments = list(assignments)
        self.rules = list(rules)
        self.unattended = list(unattended)
        self.two_person_auto_promotion = two_person_auto_promotion
        self.config_approval = config_approval
        self.value = value
        self._validate()

    # ---- structure ----------------------------------------------------
    def _validate(self) -> None:
        for r in self.roles.values():
            if r.parent is not None and r.parent not in self.roles:
                raise DirectoryError(f"role {r.id}: unknown parent {r.parent!r}")
        for r in self.roles:                       # cycle check
            seen = set()
            cur: str | None = r
            while cur is not None:
                if cur in seen:
                    raise DirectoryError(f"role hierarchy has a cycle through {cur!r}")
                seen.add(cur)
                cur = self.roles[cur].parent
        for a in self.assignments:
            if a.person_id not in self.people:
                raise DirectoryError(f"assignment for unknown person {a.person_id!r}")
            if a.role_id not in self.roles:
                raise DirectoryError(f"assignment to unknown role {a.role_id!r}")
        for rule in self.rules:
            if rule.role_id not in self.roles:
                raise DirectoryError(f"authority rule for unknown role {rule.role_id!r}")
        for r in self.roles.values():
            for d in r.dotted:
                if d not in self.roles:
                    raise DirectoryError(f"role {r.id}: unknown dotted-line role {d!r}")
                if d == r.id or d in self.ancestors(r.id):
                    raise DirectoryError(f"role {r.id}: dotted line to {d!r} duplicates the solid line")
        for dim, spec in self.scopes.items():
            if spec.rolls_up_to is not None:
                if spec.rolls_up_to == dim:
                    raise DirectoryError(f"scope {dim}: rolls_up_to itself; leave it out for a tree")
                seen_dims, cur = {dim}, spec.rolls_up_to
                while cur is not None:
                    if cur in seen_dims:
                        raise DirectoryError(f"scope {dim}: rolls up in a cycle through {cur!r}")
                    seen_dims.add(cur)
                    cur = self.scopes[cur].rolls_up_to if cur in self.scopes else None
            else:
                for v in spec.parents:
                    seen, cur = set(), v
                    while cur is not None:
                        if cur in seen:
                            raise DirectoryError(f"scope {dim}: value tree has a cycle through {cur!r}")
                        seen.add(cur)
                        cur = spec.parents.get(cur)
        for o in self.oversight:
            if o.role not in self.roles:
                raise DirectoryError(f"oversight: unknown role {o.role!r}")
        for r in self.stop_at:
            if r not in self.roles:
                raise DirectoryError(f"stop_at: unknown role {r!r}")
        if self.stop_at:
            stops = set(self.stop_at)
            for r in self.roles:
                if not ({r, *self.ancestors(r)} & stops):
                    raise DirectoryError(f"stop_at: role {r!r} has no stop role at or above it; escalation from "
                                         "it would climb to the top of the tree")

    def ancestors(self, role_id: str) -> list[str]:
        out, cur = [], self.roles[role_id].parent
        while cur is not None:
            out.append(cur)
            cur = self.roles[cur].parent
        return out

    def descendants(self, role_id: str) -> set[str]:
        out: set[str] = set()
        frontier = [role_id]
        while frontier:
            cur = frontier.pop()
            for r in self.roles.values():
                if r.parent == cur and r.id not in out:
                    out.add(r.id)
                    frontier.append(r.id)
        return out

    def parent_of(self, role_id: str) -> str | None:
        return self.roles[role_id].parent if role_id in self.roles else None

    def agent_policy(self, pattern_id: str, capability: str | None, facts: dict[str, Any] | None = None,
                     at: datetime | None = None) -> AgentPolicy | None:
        """The agent policy for this template in this scope now (most specific wins), or None."""
        if not self.agents:
            return None
        when = at if at is not None else self.now()
        best: tuple[tuple[int, int, int, int], AgentPolicy] | None = None
        for pol in self.agents:
            rank = 2 if pol.template == pattern_id else 1 if capability and pol.template == capability else \
                0 if pol.template == "*" else -1
            if rank < 0 or not pol.current(when) or not self.scope_ok(pol.scope, facts or {}):
                continue
            # template, then number of scope keys, then how deep those keys sit (ward below site, rice below
            # staples), then, on a true tie, the LEAST autonomous mode: row order never decides
            key = (rank, len(pol.scope), self.scope_depth(pol.scope), -AGENT_MODES.index(pol.mode))
            if best is None or key > best[0]:
                best = (key, pol)
        return best[1] if best else None

    def scope_depth(self, scope: dict[str, Any]) -> int:
        """How specific a scope is: dimensions lower in a roll-up chain and values deeper in a tree count more."""
        total = 0
        for dim, want in scope.items():
            ups, cur, seen = 0, dim, set()
            while cur in self.scopes and self.scopes[cur].rolls_up_to and cur not in seen:
                seen.add(cur)
                ups += 1
                cur = self.scopes[cur].rolls_up_to
            below = 0                                  # dimensions that roll up into this one sit below it
            total += ups * 100
            spec = self.scopes.get(dim)
            if spec is not None and spec.rolls_up_to is None:
                for v in (want if isinstance(want, list) else [want]):
                    d, c = 0, spec.parents.get(str(v))
                    while c is not None and d < 100:
                        d, c = d + 1, spec.parents.get(c)
                    below = max(below, d)
            total += below
        return total

    def overseers(self, pattern_id: str, capability: str | None = None) -> list[str]:
        """Oversight roles for this template (empty: no oversight configured for it)."""
        return [o.role for o in self.oversight if o.covers(pattern_id, capability)]

    def oversight_problems(self, patterns: Iterable[Any]) -> list[str]:
        """ADR-003 invariant 5: an oversight role owns none of the agents it oversees."""
        out = []
        for p in patterns:
            owners = {r for r in (p.owner_role, p.escalation_role) if r and r in self.roles}
            owning = set(owners) | {a for r in owners for a in self.ancestors(r)}
            for role in self.overseers(p.id, getattr(p, "capability", None)):
                if role in owning:
                    why = "owns it" if role in owners else "is above its owner on the solid line"
                    out.append(f"oversight: {role!r} oversees {p.id} but {why}; the watched must not grade itself")
        return out

    def oversight_overlaps(self, patterns: Iterable[Any]) -> list[str]:
        """People who hold an oversight role and also a role owning an agent it oversees (a warning)."""
        out = []
        pats = list(patterns)
        for person in self.people.values():
            held = {a.role_id for a in self.assignments if a.person_id == person.id}
            for p in pats:
                watch = set(self.overseers(p.id, getattr(p, "capability", None))) & held
                owns = {p.owner_role, p.escalation_role} & held
                if watch and owns:
                    out.append(f"{person.id} holds oversight {sorted(watch)} and owning role {sorted(owns)} "
                               f"for {p.id}")
        return out

    def dotted_viewers(self, role_id: str) -> set[str]:
        """Roles with a dotted line to this role or to any role above it (they see its queue)."""
        return {d for r in (role_id, *self.ancestors(role_id)) for d in self.roles[r].dotted}

    # ---- time and scope ---------------------------------------------------
    def now(self) -> datetime:
        return self.clock() if self.clock is not None else datetime.now(UTC)

    def _current(self, a: Assignment, at: datetime | None) -> bool:
        if a.valid_from is None and a.valid_to is None:
            return True
        return a.current(at if at is not None else self.now())

    def expand_facts(self, facts: dict[str, Any]) -> dict[str, set[Any]]:
        """Each fact's value with every value above it in its scope dimension, plus rolled-up dimensions the
        facts imply (store TVM01 -> region south). Undeclared facts map to their own value only."""
        out: dict[str, set[Any]] = {k: {v} for k, v in facts.items() if not isinstance(v, dict | list)}
        frontier = [k for k in out if k in self.scopes]
        done: set[str] = set()
        while frontier:
            dim = frontier.pop()
            if dim in done:
                continue
            done.add(dim)
            spec = self.scopes[dim]
            values = set(out.get(dim, set()))
            if spec.rolls_up_to is None:
                for v in list(values):
                    cur = spec.parents.get(str(v))
                    while cur is not None:
                        out[dim].add(cur)
                        cur = spec.parents.get(cur)
            else:
                up = {spec.parents[str(v)] for v in values if str(v) in spec.parents}
                if up:
                    target = spec.rolls_up_to
                    out.setdefault(target, set()).update(up)
                    done.discard(target)
                    if target in self.scopes:
                        frontier.append(target)
        return out

    def scope_ok(self, scope: dict[str, Any], facts: dict[str, Any]) -> bool:
        if not self.scopes:
            return _scope_ok(scope, facts)
        expanded = self.expand_facts(facts)
        for k, want in scope.items():
            got = expanded.get(k, set())
            wants = want if isinstance(want, list) else [want]
            if not any(w in got or str(w) in {str(g) for g in got} for w in wants):
                return False
        return True

    # ---- people ---------------------------------------------------------
    def roles_of(self, person_id: str, facts: dict[str, Any] | None = None, at: datetime | None = None) -> set[str]:
        """Roles a person holds for an incident with these facts (scope-matched, current assignments)."""
        p = self.people.get(person_id)
        if p is None or not p.active:
            return set()
        facts = facts or {}
        out = set()
        for a in self.assignments:
            if a.person_id == person_id and self._current(a, at) and self.scope_ok(a.scope, facts):
                out.add(a.role_id)
        return out

    def people_in(self, role_id: str, facts: dict[str, Any] | None = None,
                  at: datetime | None = None) -> list[Person]:
        facts = facts or {}
        ids = {a.person_id for a in self.assignments
               if a.role_id == role_id and self._current(a, at) and self.scope_ok(a.scope, facts)}
        return [self.people[i] for i in sorted(ids) if self.people[i].active]

    def cap_escalation(self, from_role: str | None, to_role: str | None) -> str | None:
        """Where to escalate from ``from_role``, never past the stop list: if ``to_role`` sits above the first stop
        role on ``from_role``'s solid line, the stop role is named instead (the case stops there and that person
        takes it further outside Sentinel). Unchanged without a stop list or when ``to_role`` is not above."""
        if not self.stop_at or to_role is None or from_role not in self.roles:
            return to_role
        chain = [from_role, *self.ancestors(from_role)]
        stops = set(self.stop_at)
        first = next((r for r in chain if r in stops), None)
        if first is None or to_role not in chain:
            return to_role
        return first if chain.index(to_role) > chain.index(first) else to_role

    def holders(self, role_id: str, facts: dict[str, Any] | None = None,
                at: datetime | None = None) -> tuple[str, list[Person]]:
        """Who to route to for ``role_id`` in this scope, now: its own people, else the nearest role above with
        someone in scope. Never climbs past a role in ``stop_at``: if the stop role is vacant too, the result
        is (that stop role, []) so the gap is visible instead of paging the top of the tree."""
        if role_id not in self.roles:
            return role_id, []
        stops = set(self.stop_at)
        for r in (role_id, *self.ancestors(role_id)):
            people = self.people_in(r, facts, at)
            if people:
                return r, people
            if r in stops:
                return r, []
        return role_id, []

    def can_see(self, person_id: str, role_id: str, facts: dict[str, Any] | None = None) -> bool:
        """A person sees a queue if they hold that role, any role above it, or a dotted-line role to it."""
        held = self.roles_of(person_id, facts)
        if role_id in held or bool(held & set(self.ancestors(role_id))):
            return True
        return role_id in self.roles and bool(held & self.dotted_viewers(role_id))

    def can_act(self, person_id: str, role_id: str, facts: dict[str, Any] | None = None) -> bool:
        """Holds the role or one above it on the solid line. A dotted line sees the queue but does not act."""
        held = self.roles_of(person_id, facts)
        return role_id in held or (role_id in self.roles and bool(held & set(self.ancestors(role_id))))

    # ---- authority ------------------------------------------------------
    def _rules_for(self, held: set[str]) -> list[AuthorityRule]:
        below: set[str] = set()
        for r in held:
            below |= self.descendants(r)            # seniors inherit their team's rules (not inherit: false ones)
        return [rule for rule in self.rules
                if rule.role_id in held or (rule.role_id in below and rule.inherit)]

    def authorize_steps(self, person_id: str, pattern_id: str, assignee_role: str, steps: list[PlaybookStep],
                        facts: dict[str, Any], proposed_by: list[str] | None = None) -> Authorization:
        p = self.people.get(person_id)
        if p is None:
            return Authorization(False, f"unknown person {person_id!r}")
        if not p.active:
            return Authorization(False, f"{person_id} is deactivated")
        if not self.can_act(person_id, assignee_role, facts):
            return Authorization(False, f"{person_id} is not in role {assignee_role!r} or above it for this scope",
                                 escalate_to=assignee_role)
        held = self.roles_of(person_id, facts)
        rules = self._rules_for(held)
        blocked: tuple[PlaybookStep, str] | None = None
        proposable = True
        for st in steps:
            ok, why = self._step_allowed(rules, pattern_id, st, person_id, proposed_by or [])
            if not ok:
                blocked = blocked or (st, why)
                proposable = proposable and not why.startswith(("no authority", "needs a proposal"))
        if blocked is None:
            return Authorization(True, "ok")
        st, why = blocked
        wanted = self._who_can(pattern_id, st)
        to = self.cap_escalation(assignee_role, wanted)
        if to != wanted and to is not None and person_id in {p.id for p in self.people_in(to, facts)}:
            # the stop role is this person's own: nobody above may be paged, so Sentinel has nowhere to send it
            return Authorization(False, f"{person_id}: {why}; the role that may approve ({wanted}) is past the stop "
                                        f"list, so take it further outside Sentinel")
        return Authorization(False, f"{person_id}: {why}", escalate_to=to, proposable=proposable and to is not None)

    def authorize_meta(self, person_id: str, meta: str, pattern_id: str) -> Authorization:
        if meta not in META_ACTIONS:
            raise DirectoryError(f"unknown meta action {meta}")
        p = self.people.get(person_id)
        if p is None or not p.active:
            return Authorization(False, f"unknown or inactive person {person_id!r}")
        rules = self._rules_for(self.roles_of(person_id))
        for rule in rules:
            if rule.action == meta and _pattern_ok(rule.patterns, pattern_id) and rule.level == "approve":
                return Authorization(True, "ok")
        return Authorization(False, f"{person_id} lacks {meta} on {pattern_id}")

    def unattended_limit(self, resolver: str, pattern_id: str, action: str) -> tuple[float | None, str, str]:
        """(limit, amount param, where the limit comes from) for an action run without a person."""
        explicit = [r for r in self.unattended if r.resolver in (resolver, "*") and r.action in (action, "*")
                    and _pattern_ok(r.patterns, pattern_id)]
        if explicit:
            if any(r.max_amount is None for r in explicit):
                return None, "amount", "unattended rule"
            best = max(explicit, key=lambda r: r.max_amount or 0)
            return best.max_amount, best.amount_param, "unattended rule"
        people = [r for r in self.rules if r.action == action and r.level == "approve"
                  and r.max_amount is not None and _pattern_ok(r.patterns, pattern_id)]
        if people:
            low = min(people, key=lambda r: r.max_amount or 0)
            return low.max_amount, low.amount_param, f"the lowest approval limit ({low.role_id})"
        return None, "amount", ""

    def authorize_unattended(self, resolver: str, pattern_id: str, steps: list[PlaybookStep]) -> Authorization:
        for st in steps:
            if not st.action:
                continue
            limit, param, source = self.unattended_limit(resolver, pattern_id, st.action)
            if limit is None:
                continue
            amt = st.params.get(param)
            if not isinstance(amt, (int, float)) or isinstance(amt, bool):
                return Authorization(False, f"{st.action} has an amount limit for unattended runs ({source}) but "
                                            f"no numeric {param!r} to check")
            if amt > limit:
                return Authorization(False, f"{st.action} {param}={amt:g} is above what {resolver} may do alone "
                                            f"({limit:g}, {source})")
        return Authorization(True, "ok")

    def _step_allowed(self, rules: list[AuthorityRule], pattern_id: str, st: PlaybookStep,
                      person_id: str | None = None, proposed_by: list[str] | None = None) -> tuple[bool, str]:
        candidates = [r for r in rules if r.action in (st.action, "*") and r.action not in META_ACTIONS
                      and _pattern_ok(r.patterns, pattern_id)]
        if not candidates:
            return False, f"no authority for {st.action}"
        approve = [r for r in candidates if r.level == "approve"]
        if not approve:
            return False, f"may only propose {st.action}"
        others = [x for x in (proposed_by or []) if x != person_id]
        if not others:
            approve = [r for r in approve if not r.needs_proposal]
            if not approve:
                return False, f"needs a proposal: {st.action} is approved only on someone else's proposal"
        for r in approve:
            if r.max_amount is None:
                return True, "ok"
            amt = st.params.get(r.amount_param)
            if isinstance(amt, (int, float)) and not isinstance(amt, bool) and amt <= r.max_amount:
                return True, "ok"
        return False, f"{st.action} exceeds approval limit"

    def _who_can(self, pattern_id: str, st: PlaybookStep) -> str | None:
        """Lowest role able to approve this step: where escalation should go."""
        best: tuple[int, str] | None = None
        for role_id in self.roles:
            # who may approve it once proposed (a forward always carries its proposer)
            ok, _ = self._step_allowed(self._rules_for({role_id}), pattern_id, st, None, ["(proposer)"])
            if ok:
                depth = len(self.ancestors(role_id))
                if best is None or depth > best[0]:
                    best = (depth, role_id)
        return best[1] if best else None


def _scope_ok(scope: dict[str, Any], facts: dict[str, Any]) -> bool:
    for k, want in scope.items():
        got = facts.get(k)
        if isinstance(want, list):
            if got not in want:
                return False
        elif got != want:
            return False
    return True


def _pattern_ok(patterns: list[str], pattern_id: str) -> bool:
    return "*" in patterns or pattern_id in patterns


def _sod(raw: Any, path: str) -> list[Any]:
    from .org import SodRule
    if not raw:
        return []
    if not isinstance(raw, list):
        raise DirectoryError(f"{path}: sod: a list of {{first, second, description}}")
    return [SodRule.model_validate(r) for r in raw]


def load_directory(path: str | Path, **kw: Any) -> Directory:
    """YAML: roles (map id -> {name, parent, description} or list), people, assignments, authority."""
    return parse_directory(yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}, str(path), **kw)


def parse_directory(data: Any, path: str = "people", **kw: Any) -> Directory:
    """A directory from already-parsed YAML (a mapping)."""
    if not isinstance(data, dict):
        raise DirectoryError(f"{path}: top level must be a mapping")
    unknown = set(data) - {"roles", "people", "assignments", "authority", "unattended", "config_approval", "value",
                           "version", "scim", "scopes", "stop_at", "vacancy", "sod", "agents", "oversight"}
    if unknown:
        raise DirectoryError(f"{path}: unknown top-level keys {sorted(unknown)}")
    raw_roles = data.get("roles") or {}
    if isinstance(raw_roles, dict):
        roles = [Role(id=k, **(v or {})) if isinstance(v, dict) else Role(id=k, description=str(v))
                 for k, v in raw_roles.items()]
    else:
        roles = [Role.model_validate(r) for r in raw_roles]
    return Directory(roles=roles,
                     people=[Person.model_validate(p) for p in data.get("people") or []],
                     assignments=[Assignment.model_validate(a) for a in data.get("assignments") or []],
                     rules=[AuthorityRule.model_validate(r) for r in data.get("authority") or []],
                     unattended=[UnattendedRule.model_validate(r) for r in data.get("unattended") or []],
                     config_approval=(ConfigApproval.model_validate(data["config_approval"])
                                      if data.get("config_approval") else None),
                     value=ValueSettings.model_validate(data["value"]) if data.get("value") else None,
                     scim=ScimSettings.model_validate(data["scim"]) if data.get("scim") else None,
                     scopes={str(k): ScopeDimension.model_validate(v or {})
                             for k, v in (data.get("scopes") or {}).items()},
                     stop_at=[str(r) for r in data.get("stop_at") or []],
                     vacancy=str(data.get("vacancy") or "off"),
                     sod=_sod(data.get("sod"), path),
                     agents=[AgentPolicy.model_validate(a) for a in data.get("agents") or []],
                     oversight=[OversightRule.model_validate(o) for o in data.get("oversight") or []], **kw)
