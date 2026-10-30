# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""Guardrails (what may run unattended) and learning (how trust is earned and lost)."""
from __future__ import annotations

from dataclasses import dataclass, field

from .models import Disposition, PatternState, Route, utcnow


@dataclass
class Guardrails:
    shadow: bool = False                      # global dry run: recommend, never execute without a human
    allow_irreversible_unattended: bool = False  # irreversible actions always need a human unless this is True
    max_unattended_per_hour: int = 50         # circuit breaker per pattern; beyond this, route to humans
    shadow_patterns: set[str] = field(default_factory=set)

    def is_shadow(self, pattern_id: str) -> bool:
        return self.shadow or pattern_id in self.shadow_patterns


@dataclass
class LearningPolicy:
    promote_streak: dict[Route, int] = field(default_factory=lambda: {Route.HITL: 10, Route.LLM: 20})
    min_agreement_rate: float = 0.9
    auto_promote: bool = False                # False: promotions wait for a human sign-off
    demote_on_reversal: bool = True


def next_route(current: Route, ceiling: Route, llm_available: bool) -> Route | None:
    if current.level >= ceiling.level:
        return None
    nxt = Route.from_level(current.level + 1)
    if nxt is Route.LLM and not llm_available:
        nxt = Route.AUTO if ceiling is Route.AUTO else None
    return nxt


class Learner:
    """Updates PatternState from dispositions. Pure logic; the engine persists the result."""

    def __init__(self, policy: LearningPolicy | None = None) -> None:
        self.policy = policy or LearningPolicy()

    def observe(self, state: PatternState, d: Disposition, ceiling: Route, llm_available: bool) -> list[str]:
        """Apply one disposition. Returns notes describing what changed."""
        notes: list[str] = []
        if d.shadow:
            # shadow runs still teach: a human agreeing with the shadow proposal counts at HITL level
            pass
        good = self._is_good(state.route, d)
        if good is None:
            return notes
        state.samples += 1
        if good:
            state.agreements += 1
            state.streak += 1
        else:
            if state.streak:
                notes.append(f"streak reset at {state.streak}")
            state.streak = 0
            if state.pending_promotion:
                notes.append(f"pending promotion to {state.pending_promotion.value} withdrawn")
                state.pending_promotion = None
                state.promotion_approvals = []
        state.updated_at = utcnow()

        need = self.policy.promote_streak.get(state.route)
        target = next_route(state.route, ceiling, llm_available)
        rate = state.agreements / state.samples if state.samples else 0.0
        if (good and need is not None and target is not None and state.streak >= need
                and rate >= self.policy.min_agreement_rate and state.pending_promotion is None):
            if self.policy.auto_promote:
                notes.append(f"promoted {state.route.value} -> {target.value}")
                self._set_route(state, target)
            else:
                state.pending_promotion = target
                notes.append(f"promotion to {target.value} proposed (streak {state.streak}, agreement {rate:.0%})")
        return notes

    def observe_reversal(self, state: PatternState) -> list[str]:
        notes: list[str] = []
        state.reversals += 1
        state.streak = 0
        state.pending_promotion = None
        state.promotion_approvals = []
        if self.policy.demote_on_reversal and state.route is not Route.HITL:
            old = state.route
            self._set_route(state, Route.from_level(state.route.level - 1))
            notes.append(f"demoted {old.value} -> {state.route.value} after reversal")
        state.updated_at = utcnow()
        return notes

    def observe_outcome(self, state: PatternState, held: bool) -> list[str]:
        """A later check of whether the fix held. A failed outcome costs trust like a reversal."""
        if held:
            state.outcomes_held += 1
            state.updated_at = utcnow()
            return []
        state.outcomes_failed += 1
        notes = ["outcome check failed"]
        state.streak = 0
        if state.pending_promotion:
            notes.append(f"pending promotion to {state.pending_promotion.value} withdrawn")
        state.pending_promotion = None
        state.promotion_approvals = []
        if self.policy.demote_on_reversal and state.route is not Route.HITL:
            old = state.route
            self._set_route(state, Route.from_level(state.route.level - 1))
            notes.append(f"demoted {old.value} -> {state.route.value} after failed outcome")
        state.updated_at = utcnow()
        return notes

    @staticmethod
    def _set_route(state: PatternState, route: Route) -> None:
        state.route = route
        state.streak = 0
        state.samples = 0
        state.agreements = 0
        state.pending_promotion = None
        state.promotion_approvals = []

    @staticmethod
    def _is_good(route: Route, d: Disposition) -> bool | None:
        if d.resolver == "parent":
            return None
        if d.resolver == "human":
            # did the human accept what the system proposed?
            return d.agreed_with_proposal
        if d.resolver in ("auto", "llm"):
            return not d.reversed
        return None
