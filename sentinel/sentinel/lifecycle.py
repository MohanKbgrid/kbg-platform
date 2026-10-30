# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""Incident state machine. Every state change goes through `transition`."""
from __future__ import annotations

from .models import Incident, IncidentState as S, utcnow

ALLOWED: dict[S, set[S]] = {
    S.OPEN: {S.SUPPRESSED, S.RESOLVING, S.AWAITING_HUMAN, S.DISPOSITIONED},
    S.SUPPRESSED: {S.DISPOSITIONED, S.OPEN},
    S.RESOLVING: {S.RESOLVED, S.AWAITING_HUMAN, S.FAILED},
    S.AWAITING_HUMAN: {S.RESOLVING, S.DISPOSITIONED, S.FAILED},
    S.RESOLVED: {S.DISPOSITIONED},
    S.FAILED: {S.AWAITING_HUMAN, S.DISPOSITIONED},
    S.DISPOSITIONED: set(),
}


class IllegalTransition(RuntimeError):
    pass


def can(src: S, dst: S) -> bool:
    return dst in ALLOWED[src]


def transition(incident: Incident, dst: S, now=None) -> Incident:
    if not can(incident.state, dst):
        raise IllegalTransition(f"{incident.id}: {incident.state.value} -> {dst.value} not allowed")
    incident.state = dst
    incident.updated_at = now or utcnow()
    return incident
