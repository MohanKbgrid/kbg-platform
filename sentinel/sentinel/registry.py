# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""The registry: pattern definitions + matching + validation against actions."""
from __future__ import annotations

from typing import Any

from .actions import ActionRegistry
from .models import Pattern, Route

UNMATCHED = Pattern(
    id="__unmatched__",
    description="No registry pattern matched. Always goes to a human; dispositions here seed new patterns.",
    event_types=["*"],
    route=Route.HITL,
    max_route=Route.HITL,
    disposition_codes=["resolved", "no_action", "false_positive", "new_pattern_needed"],
    owner_role="supervisor",
)


class RegistryError(ValueError):
    pass


class Registry:
    def __init__(self, patterns: list[Pattern] | None = None, fallback: Pattern = UNMATCHED) -> None:
        self._patterns: dict[str, Pattern] = {}
        self.fallback = fallback
        for p in patterns or []:
            self.add(p)

    def add(self, p: Pattern) -> None:
        if p.id in self._patterns or p.id == self.fallback.id:
            raise RegistryError(f"duplicate pattern id {p.id}")
        if p.route.level > p.max_route.level:
            raise RegistryError(f"{p.id}: route {p.route.value} above max_route {p.max_route.value}")
        if p.route is Route.AUTO and not any(st.kind in ("action", "close") for st in p.playbook):
            raise RegistryError(f"{p.id}: AUTO route requires a playbook")
        if not 0 <= p.llm_min_confidence <= 1:
            raise RegistryError(f"{p.id}: llm_min_confidence must be within [0,1]")
        if p.sla_minutes <= 0:
            raise RegistryError(f"{p.id}: sla_minutes must be positive")
        self._patterns[p.id] = p

    def get(self, pattern_id: str) -> Pattern:
        if pattern_id == self.fallback.id:
            return self.fallback
        return self._patterns[pattern_id]

    def all(self) -> list[Pattern]:
        return list(self._patterns.values())

    def match(self, event_type: str, facts: dict[str, Any]) -> Pattern:
        candidates = [p for p in self._patterns.values() if p.matches(event_type, facts)]
        if not candidates:
            return self.fallback
        # most specific first: priority, exact-value matches (beat wildcards), match keys, then id for determinism
        def exact(p: Pattern) -> int:
            return sum(1 for v in p.match.values() if v != "*")
        candidates.sort(key=lambda p: (-p.priority, -exact(p), -len(p.match), p.id))
        return candidates[0]

    def validate(self, actions: ActionRegistry,
                 tools: set[str] | dict[str, dict[str, str]] | None = None) -> list[str]:
        """Cross-check patterns against registered actions (and lookup tools, when given). Returns problems.
        Playbook params are checked against each action's declared params, and lookup args against each
        tool's, when ``tools`` maps names to their params."""
        from .actions import schema_problems
        from .expr import check_condition, check_match, check_template
        problems: list[str] = []
        tool_params = tools if isinstance(tools, dict) else {}
        for p in self._patterns.values():
            problems += [f"{p.id}: match: {m}" for m in check_match(p.match)]
            for a in p.allowed_actions:
                if not actions.has(a):
                    problems.append(f"{p.id}: allowed action {a!r} is not registered")
            names: set[str] = set()
            for i, step in enumerate(p.playbook):
                where = f"{p.id}: playbook step {i + 1}"
                for m in check_condition(step.when) + check_template(step.params) + check_template(step.args):
                    problems.append(f"{where}: {m}")
                if step.disposition and step.disposition not in p.disposition_codes:
                    problems.append(f"{where}: disposition {step.disposition!r} not in {p.disposition_codes}")
                if step.kind == "lookup":
                    if tools is not None and step.lookup not in tools:
                        problems.append(f"{where}: lookup tool {step.lookup!r} is not available")
                    else:
                        problems += [f"{where}: {m}" for m in
                                     schema_problems(step.lookup, tool_params.get(step.lookup) or {}, step.args)]
                    names.add(step.result_name)
                elif step.kind == "action":
                    if not actions.has(step.action):
                        problems.append(f"{p.id}: playbook action {step.action!r} is not registered")
                    else:
                        if step.action not in p.allowed_actions:
                            problems.append(f"{p.id}: playbook action {step.action!r} missing from allowed_actions")
                        spec = actions.get(step.action).spec
                        problems += [f"{where}: {m}" for m in
                                     schema_problems(step.action, spec.params_schema, step.params)]
            lk = p.clear_when.lookup if p.clear_when else None
            if lk is not None:
                where = f"{p.id}: clear_when lookup"
                problems += [f"{where}: {m}" for m in check_condition(lk.condition) + check_template(lk.args)]
                if tools is not None and lk.tool not in tools:
                    problems.append(f"{where}: lookup tool {lk.tool!r} is not available")
            for reason in p.pause_on:
                if not reason.replace("_", "").isalnum() or not reason.islower():
                    problems.append(f"{p.id}: pause reason {reason!r}: use lowercase words joined by _")
            for inh in p.inhibited_by:
                if inh not in self._patterns:
                    problems.append(f"{p.id}: inhibited_by unknown pattern {inh!r}")
        return problems


def ceiling(p: Pattern) -> Route:
    """Highest route a pattern can ever reach. AUTO needs a deterministic playbook."""
    if p.max_route is Route.AUTO and not any(st.kind in ("action", "close") for st in p.playbook):
        return Route.LLM
    return p.max_route
