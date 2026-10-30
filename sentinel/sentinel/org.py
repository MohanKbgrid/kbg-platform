# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""The authority contract domain cores import (ADR-003 C2): ``authorise(actor, action, ...)``.

Sentinel asks; the domain core decides. Every agent-triggerable write in a core calls ``authorise`` where the write
happens, against its synced copy of the people configuration, so it keeps working offline.

    from sentinel.org import Agent, authorise
    ok = authorise(directory, Agent("r06@TVM01", bound_role="store_manager"), "task.count",
                   scope={"store": "TVM01"}, amount=None)
    if not ok.allowed: refuse(ok.reason)

An action is allowed only if ALL of these hold:
  1. A person actor holds, now and in this scope, a role whose authority rules approve the action (and amount;
     limits bound the amount's size, so a negative amount is checked as its magnitude).
     An agent actor is never stronger than its human: a person holding the agent's bound role in this scope today
     could do the same without an approver. If nobody holds that role in scope, the nearest held role above
     decides (``Directory.holders``), never a role past the stop list.
  2. No segregation-of-duties pair is broken: the actor has not done the paired action on the same object.
  3. Nobody approves their own proposal; an agent never approves anything (APPROVE is never grantable to an agent).

The domain supplies only the vocabulary (actions, amounts, its Limits rows); the engine is generic.
"""
from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from pydantic import BaseModel

from .models import PlaybookStep
from .rbac import Authorization, Directory

APPROVE = "__approve__"     # approving someone else's proposal: never grantable to an agent


class SodRule(BaseModel):
    """Two actions one actor may not both do on the same object (raise and approve a PO; count and adjust)."""
    first: str
    second: str
    description: str = ""

    def model_post_init(self, _ctx: Any) -> None:
        if self.first == self.second:
            raise ValueError(f"sod: {self.first!r} is paired with itself; a pair names two different actions")

    def pair_of(self, action: str) -> str | None:
        if action == self.first:
            return self.second
        if action == self.second:
            return self.first
        return None


@dataclass(frozen=True)
class Person:
    id: str


@dataclass(frozen=True)
class Agent:
    """An agent identity acting in a scope under a bound role (the template's slot, bound by the tenant)."""
    id: str
    bound_role: str
    on_behalf_of: str | None = None     # the template or capability it runs for (audit only)


@dataclass
class Decision:
    allowed: bool
    reason: str
    actor: str
    action: str
    decided_by_role: str | None = None   # the role whose authority decided (the agent's human, for agents)
    escalate_to: str | None = None
    checks: list[str] = field(default_factory=list)

    def __bool__(self) -> bool:          # if authorise(...): ...
        return self.allowed


def authorise(directory: Directory, actor: Person | Agent | str, action: str, obj: str | None = None,
              scope: Mapping[str, Any] | None = None, amount: float | None = None, *,
              pattern: str = "*", amount_param: str = "amount", proposed_by: Iterable[str] = (),
              done_on_object: Mapping[str, Iterable[str]] | None = None,
              sod: Iterable[SodRule] | None = None, at: datetime | None = None, backend: Any = None) -> Decision:
    """May ``actor`` do ``action`` on ``obj`` in ``scope`` for ``amount``? See the module docstring for the rule.

    ``backend`` is optional: an object with the same ``authorise`` method (see ``sentinel.cedar_authz``) that decides
    the question instead of the built-in engine below. ``None`` (the default) is the built-in engine, unchanged.

    ``done_on_object`` maps actor id -> actions that actor already did on this object (for SoD).
    ``proposed_by`` is who proposed what is being approved (the actor may not be one of them).
    ``sod`` defaults to the directory's own ``sod`` rules."""
    if backend is not None:
        return backend.authorise(directory, actor, action, obj, scope, amount, pattern=pattern,
                                 amount_param=amount_param, proposed_by=proposed_by,
                                 done_on_object=done_on_object, sod=sod, at=at)
    if isinstance(actor, str):
        actor = Person(actor)
    facts = dict(scope or {})
    checks: list[str] = []
    rules = list(sod if sod is not None else getattr(directory, "sod", []))

    def no(reason: str, escalate_to: str | None = None, role: str | None = None) -> Decision:
        return Decision(False, reason, actor.id, action, role, escalate_to, checks)

    # 3. self-approval and agents approving
    proposers = set(proposed_by)
    if isinstance(actor, Agent) and (action == APPROVE or proposers):
        checks.append("agent_never_approves")
        return no(f"{actor.id} is an agent: approving is never granted to an agent")
    if actor.id in proposers:
        checks.append("not_own_proposal")
        return no(f"{actor.id} proposed this and may not approve it")

    # 2. segregation of duties on this object
    done = {a for a in (done_on_object or {}).get(actor.id, ())}
    for r in rules:
        other = r.pair_of(action)
        if other is not None and other in done:
            checks.append(f"sod:{r.first}/{r.second}")
            return no(f"{actor.id} already did {other} on {obj or 'this object'}; {action} needs someone else"
                      + (f" ({r.description})" if r.description else ""))
    if rules:
        checks.append("sod")

    # 1. authority in scope, now
    # limits bound the size of an amount: a write-off of -100000 is as large as +100000
    step = PlaybookStep(action=action if action != APPROVE else "__approve__",
                        params={amount_param: abs(amount)} if amount is not None else {})
    if isinstance(actor, Agent):
        if actor.bound_role not in directory.roles:
            return no(f"{actor.id}: bound role {actor.bound_role!r} is not in the people configuration")
        role, people = directory.holders(actor.bound_role, facts, at)
        checks.append(f"ceiling:{role}")
        if not people:
            return no(f"{actor.id}: nobody holds {actor.bound_role!r} (or a role above it) in this scope, so the "
                      "agent has no human whose authority it can use", role=role)
        ok, why = directory._step_allowed(directory._rules_for({role}), pattern, step, None, [])
        if not ok:
            wanted = directory._who_can(pattern, step)
            to = directory.cap_escalation(role, wanted)
            if to == role and wanted != role:                    # its own role is the stop: nowhere to send it
                return no(f"{actor.id} acts as {role!r}, which may not: {why}; {wanted!r} is past the stop list",
                          role=role)
            return no(f"{actor.id} acts as {role!r}, which may not: {why}", escalate_to=to, role=role)
        return Decision(True, "ok", actor.id, action, role, None, checks)

    person = directory.people.get(actor.id)
    if person is None or not person.active:
        return no(f"unknown or inactive person {actor.id!r}")
    held = directory.roles_of(actor.id, facts, at)
    checks.append("held:" + ",".join(sorted(held)))
    if not held:
        return no(f"{actor.id} holds no role in this scope now")
    ok, why = directory._step_allowed(directory._rules_for(held), pattern, step, actor.id, list(proposers))
    if not ok:
        to = directory._who_can(pattern, step)
        capped = {directory.cap_escalation(r, to) for r in held} - {None}
        nearest = max(capped, key=lambda r: (len(directory.ancestors(r)) if r in directory.roles else -1, r),
                      default=to)                               # the nearest stop any held role reaches
        if nearest in held and nearest != to:                    # the stop is the person's own role
            return no(f"{actor.id}: {why}; {to!r} is past the stop list, so take it further outside Sentinel")
        return no(f"{actor.id}: {why}", escalate_to=nearest)
    return Decision(True, "ok", actor.id, action, ",".join(sorted(held)), None, checks)


def as_authorization(d: Decision) -> Authorization:
    """The engine's own result type, for callers that already handle it."""
    return Authorization(d.allowed, d.reason, escalate_to=d.escalate_to)


__all__ = ["APPROVE", "Agent", "Decision", "Person", "SodRule", "as_authorization", "authorise"]
