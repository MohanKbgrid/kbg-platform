# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""An optional Cedar backend for ``org.authorise`` (ADR-003 C2). The built-in engine stays the default.

    pip install "kbg-sentinel[cedar]"          # cedarpy (Apache-2.0); never imported unless you use this module

    from sentinel.cedar_authz import CedarBackend
    backend = CedarBackend.from_path("examples/cedar")          # a .cedar file, or a directory of them
    ok = authorise(directory, Agent("r06@TVM01", bound_role="store_manager"), "task.count",
                   scope={"store": "TVM01"}, amount=None, backend=backend)

What stays in Sentinel and what moves to Cedar. ADR-003 splits the org layer (C1: who holds which role, where and
when, the tree, the stop list, agent identities) from authority policy (C2: what a role may do, how much, who may not
do both of two things). C1 stays in the ``Directory``. For each question this module reads the C1 facts and gives
them to Cedar as entities; **C2 is decided by the Cedar policies**:

* ``Sentinel::Person`` / ``Sentinel::Agent`` principal with ``held`` (roles held now, in this scope), ``covers`` (those
  roles and every role below them: seniors inherit their team's rules) and, for agents, ``hasHuman`` (somebody holds
  the bound role or one above it, up to the stop list). An agent's ``held`` and ``covers`` are those of its human, so
  an agent is never stronger than its human.
* ``Sentinel::Role`` entities, a role being ``in`` each role that reports to it.
* Action ``Sentinel::Action::"<action>"``, resource ``Sentinel::Object::"<object>"``.
* Context: ``amount`` (decimal, absolute value, rounded UP to 4 places; absent when no amount), ``amountParam``,
  ``pattern``, ``scope`` (a set of ``"dimension=value"`` strings), ``done`` (actions this actor already did on the
  object, for separation of duties), ``hasProposers``, ``isProposer`` (the actor is among the proposers).

Always on, appended to every policy set and not removable (Cedar's forbid beats any permit): an agent never approves
(ADR-003 invariant 1), an agent never acts on someone's proposal, nobody approves their own proposal, and a principal
who holds no role in scope (including an agent with no human) is refused.

**Fail closed.** No policy set, a policy set that does not parse or validate, a Cedar error, an exception while
translating the request, a malformed amount, a missing ``cedarpy``: the decision is a refusal with the reason, never
an exception to the caller and never an allow.

Not carried over: the built-in ``escalate_to`` hint (where to send a refused request) is routing, which is org
structure; this backend returns ``None`` for it. A caller-supplied ``sod=`` override is refused (separation of duties
lives in the policies: write the pair as a ``forbid``). ``generate_policies(directory)`` writes a policy set equal to
a directory's authority rules and separation-of-duties pairs, as a starting point and for the parity tests.
"""
from __future__ import annotations

import json
import logging
import re
from collections.abc import Iterable, Mapping
from datetime import datetime
from decimal import ROUND_CEILING, ROUND_FLOOR, Decimal, InvalidOperation
from pathlib import Path
from typing import Any

from .org import APPROVE, Agent, Decision, Person
from .rbac import META_ACTIONS, Directory

log = logging.getLogger("sentinel.cedar")

NS = "Sentinel"
_MAX_DEC = Decimal("922337203685477.5807")        # the largest Cedar decimal
_BASE_IDS = ("sentinel-base-agent-never-approves", "sentinel-base-agent-no-proposals",
             "sentinel-base-not-own-proposal", "sentinel-base-holds-no-role")

BASE_POLICIES = f'''
@id("sentinel-base-agent-never-approves")
forbid (principal is {NS}::Agent, action == {NS}::Action::"{APPROVE}", resource);

@id("sentinel-base-agent-no-proposals")
forbid (principal is {NS}::Agent, action, resource) when {{ context.hasProposers }};

@id("sentinel-base-not-own-proposal")
forbid (principal, action, resource) when {{ context.isProposer }};

@id("sentinel-base-holds-no-role")
forbid (principal, action, resource) when {{ principal.held.isEmpty() }};
'''

_BASE_WHY = {
    "sentinel-base-agent-never-approves": "{actor} is an agent: approving is never granted to an agent",
    "sentinel-base-agent-no-proposals": "{actor} is an agent: approving is never granted to an agent",
    "sentinel-base-not-own-proposal": "{actor} proposed this and may not approve it",
    "sentinel-base-holds-no-role": "{actor} holds no role in this scope now (or, for an agent, nobody holds its "
                                   "bound role): no authority to use",
}

_SCHEMA_TYPES = f'''namespace {NS} {{
  entity Role in [Role];
  entity Person = {{ "active": Bool, "held": Set<Role>, "covers": Set<Role> }};
  entity Agent = {{ "hasHuman": Bool, "held": Set<Role>, "covers": Set<Role> }};
  entity Object;
  type Ctx = {{ "amount"?: __cedar::decimal, "amountParam": String, "pattern": String, "scope": Set<String>,
               "done": Set<String>, "hasProposers": Bool, "isProposer": Bool }};
{{actions}}}}
'''


def schema_for(actions: Iterable[str]) -> str:
    """A Cedar schema (Cedar schema syntax) declaring the entity types, the context and these actions."""
    names = sorted({*actions, APPROVE})
    acts = "".join(f'  action {_lit(a)} appliesTo {{ principal: [Person, Agent], resource: [Object], '
                   f'context: Ctx }};\n' for a in names)
    return _SCHEMA_TYPES.replace("{actions}", acts)


def available() -> bool:
    try:
        import cedarpy  # noqa: F401
    except ImportError:
        return False
    return True


class CedarUnavailable(RuntimeError):
    """The ``cedar`` extra is not installed (``pip install "kbg-sentinel[cedar]"``)."""


_CTRL = re.compile(r"[\x00-\x1f\x7f]")


def _lit(s: str) -> str:
    """A Cedar string literal for ``s``."""
    if _CTRL.search(s):
        raise ValueError(f"{s!r}: control characters cannot be written into a Cedar policy")
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _ref(kind: str, ident: str) -> dict[str, Any]:
    return {"__entity": {"type": f"{NS}::{kind}", "id": ident}}


def _decimal(value: Decimal) -> dict[str, Any]:
    return {"__extn": {"fn": "decimal", "arg": format(value, "f")}}


def _amount(amount: Any) -> dict[str, Any] | None:
    """Cedar decimal for the absolute amount, rounded up to 4 places and clamped to Cedar's range, or None."""
    if amount is None:
        return None
    if isinstance(amount, str):
        raise ValueError(f"amount {amount!r} is not a number")
    try:
        d = abs(Decimal(str(amount)))
    except (InvalidOperation, ValueError):
        raise ValueError(f"amount {amount!r} is not a number") from None
    if not d.is_finite():
        raise ValueError(f"amount {amount!r} is not a finite number")
    d = min(d.quantize(Decimal("0.0001"), rounding=ROUND_CEILING), _MAX_DEC)   # round toward "bigger"
    return _decimal(d)


def _scope_tokens(scope: Mapping[str, Any]) -> list[str]:
    out = []
    for k, v in scope.items():
        for item in (v if isinstance(v, (list, tuple, set, frozenset)) else [v]):
            out.append(f"{k}={item}")
    return sorted(set(out))


class CedarBackend:
    """Evaluates ``authorise(...)`` with a Cedar policy set. Thread-safe once built."""

    name = "cedar"

    def __init__(self, policies: str | None, *, schema: str | dict | None = None) -> None:
        self.load_error: str | None = None
        self._policies: Any = None
        self._ids: dict[str, str] = {}
        self._schema = schema
        try:
            if not available():
                raise CedarUnavailable('the cedar extra is not installed: pip install "kbg-sentinel[cedar]"')
            if policies is None or not policies.strip():
                raise ValueError("no policy set loaded: every request is refused")
            import cedarpy
            text = policies + "\n" + BASE_POLICIES
            self._policies = cedarpy.PolicySet.from_str(text)
            parsed = json.loads(cedarpy.policies_to_json_str(text))["staticPolicies"]
            self._ids = {k: (v.get("annotations") or {}).get("id") or k for k, v in parsed.items()}
            if schema is not None:
                res = cedarpy.validate_policies(text, schema)
                if not res.validation_passed:
                    errs = [getattr(e, "error", str(e)) for e in getattr(res, "errors", [])] or ["validation failed"]
                    raise ValueError("policy set does not validate against the schema: " + "; ".join(map(str, errs)))
        except Exception as e:  # noqa: BLE001 - recorded; every request is then refused (fail closed)
            self._policies = None
            self.load_error = f"{type(e).__name__}: {e}"[:600]
            log.error("cedar backend not usable, refusing every request: %s", self.load_error)

    @classmethod
    def from_path(cls, path: str | Path, *, schema_path: str | Path | None = None) -> CedarBackend:
        """A ``.cedar`` file, or a directory of them (read in name order). A missing path gives a backend that
        refuses everything and says why in ``load_error``."""
        p = Path(path)
        try:
            files = sorted(p.glob("*.cedar")) if p.is_dir() else [p]
            text = "\n".join(f.read_text(encoding="utf-8") for f in files)
            if not files:
                raise ValueError(f"no .cedar files in {p}")
            schema = Path(schema_path).read_text(encoding="utf-8") if schema_path else None
        except (OSError, ValueError, UnicodeDecodeError) as e:
            b = cls(None)
            b.load_error = f"{type(e).__name__}: {e}"[:600]
            return b
        return cls(text, schema=schema)

    @property
    def ready(self) -> bool:
        return self._policies is not None

    # ---- the question ---------------------------------------------------------------------------------------
    def authorise(self, directory: Directory, actor: Person | Agent | str, action: str, obj: str | None = None,
                  scope: Mapping[str, Any] | None = None, amount: float | None = None, *,
                  pattern: str = "*", amount_param: str = "amount", proposed_by: Iterable[str] = (),
                  done_on_object: Mapping[str, Iterable[str]] | None = None,
                  sod: Iterable[Any] | None = None, at: datetime | None = None) -> Decision:
        who = actor if isinstance(actor, (Person, Agent)) else Person(str(actor))
        checks = ["cedar"]

        def no(reason: str, role: str | None = None) -> Decision:
            return Decision(False, reason, getattr(who, "id", str(actor)), str(action), role, None, checks)
        try:
            if self._policies is None:
                return no(f"cedar: {self.load_error or 'no policy set'}; refused")
            if sod is not None:
                return no("cedar: a sod= override is not honoured by the Cedar backend; write the pair as a "
                          "forbid policy")
            req, entities, role = self._translate(directory, who, action, obj, scope, amount, pattern,
                                                  amount_param, proposed_by, done_on_object, at)
            import cedarpy
            res = cedarpy.is_authorized(req, self._policies, entities)
            errors = list(getattr(res.diagnostics, "errors", []) or [])
            if errors:                                           # a policy that errors is a refusal, not a skip
                return no("cedar: policy evaluation error: " + "; ".join(map(str, errors))[:300], role)
            reasons = [self._ids.get(r, r) for r in (res.diagnostics.reasons or [])]
            if res.allowed:
                checks.append("policy:" + ",".join(reasons))
                return Decision(True, "ok", who.id, action, role, None, checks)
            base = [r for r in reasons if r in _BASE_WHY]
            if base:
                checks.append("forbid:" + base[0])
                if base[0] == "sentinel-base-agent-never-approves":
                    checks.append("agent_never_approves")
                return no(_BASE_WHY[base[0]].format(actor=who.id), role)
            if reasons:
                checks.append("forbid:" + ",".join(reasons))
                return no(f"cedar: {who.id} is refused {action} by policy {', '.join(reasons)}", role)
            return no(f"cedar: no policy permits {who.id} to {action}", role)
        except Exception as e:  # noqa: BLE001 - fail closed, whatever went wrong
            log.error("cedar authorise failed, refusing: %s", e)
            return no(f"cedar: could not evaluate ({type(e).__name__}: {str(e)[:200]}); refused")

    # ---- Sentinel request -> Cedar request ------------------------------------------------------------------
    def _translate(self, d: Directory, who: Person | Agent, action: str, obj: str | None,
                   scope: Mapping[str, Any] | None, amount: Any, pattern: str, amount_param: str,
                   proposed_by: Iterable[str], done_on_object: Mapping[str, Iterable[str]] | None,
                   at: datetime | None) -> tuple[dict[str, Any], list[dict[str, Any]], str | None]:
        facts = dict(scope or {})
        proposers = {str(p) for p in proposed_by}
        role: str | None = None
        held: set[str] = set()
        has_human = False
        active = True
        if isinstance(who, Agent):
            if who.bound_role in d.roles:
                role, people = d.holders(who.bound_role, facts, at)
                has_human = bool(people)
                held = {role} if people else set()
        else:
            person = d.people.get(who.id)
            active = person is not None and person.active
            held = d.roles_of(who.id, facts, at) if active else set()
            role = ",".join(sorted(held)) or None
        covers = set(held)
        for r in held:
            covers |= d.descendants(r)
        attrs: dict[str, Any] = {"held": [_ref("Role", r) for r in sorted(held)],
                                 "covers": [_ref("Role", r) for r in sorted(covers)]}
        if isinstance(who, Agent):
            attrs["hasHuman"] = has_human
            ptype = "Agent"
        else:
            attrs["active"] = active
            ptype = "Person"
        children: dict[str, list[str]] = {r: [] for r in d.roles}
        for r in d.roles.values():
            if r.parent in children:
                children[r.parent].append(r.id)
        entities: list[dict[str, Any]] = [
            {"uid": {"type": f"{NS}::Role", "id": r}, "attrs": {},
             "parents": [{"type": f"{NS}::Role", "id": c} for c in sorted(kids)]} for r, kids in children.items()]
        entities.append({"uid": {"type": f"{NS}::{ptype}", "id": who.id}, "attrs": attrs, "parents": []})
        entities.append({"uid": {"type": f"{NS}::Object", "id": obj or ""}, "attrs": {}, "parents": []})
        ctx: dict[str, Any] = {
            "amountParam": str(amount_param), "pattern": str(pattern), "scope": _scope_tokens(facts),
            "done": sorted({str(a) for a in (done_on_object or {}).get(who.id, ())}),
            "hasProposers": bool(proposers), "isProposer": who.id in proposers}
        dec = _amount(amount)
        if dec is not None:
            ctx["amount"] = dec
        req = {"principal": {"type": f"{NS}::{ptype}", "id": who.id},
               "action": {"type": f"{NS}::Action", "id": str(action)},
               "resource": {"type": f"{NS}::Object", "id": obj or ""}, "context": ctx}
        return req, entities, role


# ------------------------------------------------------------------------------------------------ generator
def generate_policies(directory: Directory) -> str:
    """Cedar policies equal to the directory's authority rules and separation-of-duties pairs.

    One ``permit`` per ``approve`` rule that ``authorise`` consults (``propose`` rules and rules for ``__meta__``
    actions grant nothing there), one ``forbid`` pair per SoD rule. Limits are rounded DOWN to 4 places, amounts are
    rounded UP, so the Cedar side is never looser than the rule."""
    out = ["// generated from the people configuration's authority rules and SoD pairs"]
    for i, r in enumerate(directory.rules):
        if r.level != "approve":
            out.append(f"// rule {i} ({r.role_id}, {r.action}) only proposes: it grants nothing to authorise()")
            continue
        if r.action in META_ACTIONS:
            out.append(f"// rule {i} ({r.role_id}, {r.action}) is a meta action: decided elsewhere, not by authorise()")
            continue
        act = "action" if r.action == "*" else f"action == {NS}::Action::{_lit(r.action)}"
        who = "covers" if r.inherit else "held"
        conds = [f"principal.{who}.contains({NS}::Role::{_lit(r.role_id)})"]
        if "*" not in r.patterns:
            conds.append("[" + ", ".join(_lit(p) for p in r.patterns) + "].contains(context.pattern)")
        if r.max_amount is not None:
            lim = Decimal(str(r.max_amount)).quantize(Decimal("0.0001"), rounding=ROUND_FLOOR)
            if lim > _MAX_DEC:
                lim = _MAX_DEC
            conds.append(f"context.amountParam == {_lit(r.amount_param)} && context has amount && "
                         f'context.amount.lessThanOrEqual(decimal({_lit(format(lim, "f"))}))')
        if r.needs_proposal:
            conds.append("context.hasProposers")
        rid = f"authority-{i}-{r.role_id}-{r.action}"
        out.append(f"@id({_lit(rid)})\npermit (principal, {act}, resource) when {{\n  " + " &&\n  ".join(conds) +
                   "\n};")
    for j, s in enumerate(getattr(directory, "sod", [])):
        for a, b in ((s.first, s.second), (s.second, s.first)):
            out.append(f'@id({_lit(f"sod-{j}-{a}-after-{b}")})\n'
                       f"forbid (principal, action == {NS}::Action::{_lit(a)}, resource) when {{ "
                       f"context.done.contains({_lit(b)}) }};")
    return "\n\n".join(out) + "\n"


__all__ = ["BASE_POLICIES", "CedarBackend", "CedarUnavailable", "available", "generate_policies", "schema_for"]
