# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""Repeat events with worse facts: the incident's facts stay current and a now-more-urgent case is due sooner."""
from __future__ import annotations

from datetime import timedelta

from sentinel import Bucket, Event, FingerprintRule, Pattern, Route
from tests.conftest import make_overlay


def overlay(backend):
    ov = make_overlay(backend, patterns=[
        Pattern(id="late_minor", event_types=["order.late"], match={"age": "<48h"}, route=Route.HITL,
                allowed_actions=["notify"], owner_role="ops", sla_minutes=240),
        Pattern(id="late_major", event_types=["order.late"], match={"age": ">48h"}, route=Route.HITL,
                allowed_actions=["notify"], owner_role="ops", sla_minutes=30, severity="high")])
    ov.fingerprint_rules.append(FingerprintRule(event_type="order.late", fields={"order": "order_id"},
                                                buckets={"age": Bucket(field="hours", edges=[48],
                                                                       labels=["<48h", ">48h"])},
                                                group_by=["order"]))
    return ov


def late(hours, key):
    return Event(type="order.late", source="scan", idempotency_key=key, payload={"order_id": "O1", "hours": hours})


def test_worse_repeat_updates_facts_and_pulls_the_review_forward(engine_factory, backend, clock):
    eng = engine_factory(ov=overlay(backend))
    opened = clock()
    first = eng.ingest(late(47, "a"))
    rv = eng.store.open_review_for(first.incident_id)
    assert rv.due_at == opened + timedelta(minutes=240)
    clock.advance(hours=2)
    again = eng.ingest(late(49, "b"))
    assert again.status == "grouped" and again.incident_id == first.incident_id
    inc = eng.store.get_incident(first.incident_id)
    assert inc.facts["age"] == ">48h" and inc.pattern_id == "late_minor"          # facts current, pattern kept
    rv = eng.store.open_review_for(first.incident_id)
    assert rv.due_at == opened + timedelta(minutes=30) and "now looks like late_major" in rv.reason
    assert [r.id for r in eng.sweep()] == [rv.id]                                  # already overdue: escalated
    kinds = [a["kind"] for a in eng.store.audit_log(first.incident_id)]
    assert "facts_changed" in kinds and "review_due_moved" in kinds
    assert eng.ingest(late(51, "c")).status == "grouped"                          # same facts: nothing new
    assert [a["kind"] for a in eng.store.audit_log(first.incident_id)].count("facts_changed") == 1


def test_facts_of_an_incident_being_resolved_are_left_alone(engine_factory, backend):
    eng = engine_factory(ov=overlay(backend))
    first = eng.ingest(late(30, "a"))
    inc = eng.store.get_incident(first.incident_id)
    from sentinel import IncidentState
    assert eng.store.update_facts(inc.id, {"x": 1}, [IncidentState.RESOLVING.value]) is False
    assert eng.store.get_incident(inc.id).facts["age"] == "<48h"
