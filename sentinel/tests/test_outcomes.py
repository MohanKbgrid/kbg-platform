# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""Outcome verification: trust is earned on results, not on approvals."""
from __future__ import annotations

import pytest

from sentinel import EngineError, IncidentState as S, Route
from tests.conftest import job_event


@pytest.fixture
def oc_overlay(overlay):
    verdicts = {"next": True}
    overlay.verifiers["job_ran"] = lambda incident, disposition, params, services: verdicts["next"]
    overlay.patterns[0] = overlay.patterns[0].model_copy(update={
        "outcome_check": {"verifier": "job_ran", "after_minutes": 30, "max_checks": 3}})
    overlay._verdicts = verdicts           # handle for tests
    return overlay


def test_held_outcome_is_recorded_after_the_wait(engine_factory, oc_overlay, clock):
    eng = engine_factory(ov=oc_overlay)
    r = eng.ingest(job_event())
    assert eng.work("w")["done"] == 0                     # not due yet
    clock.advance(minutes=31)
    assert eng.work("w")["done"] == 1
    assert eng.store.get_disposition(r.incident_id).outcome == "held"
    st = eng.store.get_pattern_state("job_timeout")
    assert st.outcomes_held == 1 and st.route is Route.AUTO
    assert eng.report()["patterns"]["job_timeout"]["outcome_held_rate"] == 1.0


def test_failed_outcome_demotes_and_raises_a_follow_up_incident(engine_factory, oc_overlay, clock, notes):
    eng = engine_factory(ov=oc_overlay)
    oc_overlay._verdicts["next"] = False
    r = eng.ingest(job_event())
    clock.advance(minutes=31)
    eng.work("w")
    assert eng.store.get_disposition(r.incident_id).outcome == "failed"
    st = eng.store.get_pattern_state("job_timeout")
    assert st.outcomes_failed == 1 and st.route is Route.LLM
    follow = [i for i in eng.store.incidents() if i.first_event["type"] == "sentinel.outcome_failed"]
    assert len(follow) == 1 and follow[0].state is S.AWAITING_HUMAN
    assert follow[0].first_event["payload"]["incident_id"] == r.incident_id
    assert any(k == "outcome_failed" for k, _ in notes)


def test_undeterminable_outcome_retries_then_settles_unknown(engine_factory, oc_overlay, clock):
    eng = engine_factory(ov=oc_overlay, retry_base_s=60)
    oc_overlay._verdicts["next"] = None
    r = eng.ingest(job_event())
    for _ in range(6):
        clock.advance(minutes=60)
        eng.work("w")
    d = eng.store.get_disposition(r.incident_id)
    assert d.outcome == "unknown"
    st = eng.store.get_pattern_state("job_timeout")
    assert st.outcomes_held == 0 and st.outcomes_failed == 0
    assert not [a for a in eng.store.audit_log() if a["kind"] == "work_failed"]      # deferrals are not failures


def test_no_check_for_shadow_rejects_or_reversed(engine_factory, oc_overlay, clock):
    eng = engine_factory(ov=oc_overlay)
    r = eng.ingest(job_event())
    eng.reverse(r.incident_id, actor="x")
    clock.advance(minutes=31)
    eng.work("w")
    assert eng.store.get_disposition(r.incident_id).outcome is None


def test_unregistered_verifier_refused(engine_factory, overlay):
    overlay.patterns[0] = overlay.patterns[0].model_copy(update={"outcome_check": {"verifier": "ghost"}})
    with pytest.raises(EngineError, match="not registered"):
        engine_factory(ov=overlay)
