# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""S6 (ADR-003): pooled trust. A template running in many scopes learns once, pooled across them; a scope uses
its own trust only after it has `trust_pool_min` decisions of its own. Off unless the pattern sets it."""
from __future__ import annotations

import pytest

from sentinel import Decision, DecisionKind, LearningPolicy, Pattern, PlaybookStep, Route
from tests.conftest import job_event, make_overlay


def timeout(**over):
    base = dict(id="job_timeout", event_types=["job.failed"], match={"error": "TIMEOUT"}, route=Route.HITL,
                playbook=[PlaybookStep(action="retry", params={"ref": "{{payload.ref}}"})],
                allowed_actions=["retry", "notify"], owner_role="ops", trust_by=["system"], trust_pool_min=3)
    base.update(over)
    return Pattern(**base)


@pytest.fixture
def eng(engine_factory, backend):
    return engine_factory(ov=make_overlay(backend, patterns=[timeout()]),
                          learning=LearningPolicy(promote_streak={Route.HITL: 2, Route.LLM: 2}))


def approve_open(eng):
    for r in eng.store.open_reviews():
        eng.decide(r.id, Decision(kind=DecisionKind.APPROVE, actor="op"))


def test_thin_scopes_learn_together(eng, backend):
    p = eng.registry.get("job_timeout")
    for i in range(2):                                    # two scopes, one decision each
        eng.ingest(job_event(ref=f"S{i}", system=f"store{i}"))
        approve_open(eng)
    pool = eng.store.get_pattern_state("job_timeout")
    assert pool is not None and pool.samples == 2 and pool.pending_promotion is Route.AUTO
    assert eng.store.get_pattern_state("job_timeout@system=store0").pending_promotion is None
    eng.approve_promotion("job_timeout", actor="mohan")
    assert eng.effective_route(p, {"system": "store77"}) is Route.AUTO      # a scope never seen uses the pool
    backend.calls.clear()
    eng.ingest(job_event(ref="N1", system="store77"))
    assert backend.calls == [("retry", {"ref": "N1"})]


def test_a_scope_with_its_own_evidence_uses_its_own_trust(eng):
    p = eng.registry.get("job_timeout")
    eng.set_route("job_timeout", Route.AUTO, actor="setup")
    from sentinel.models import PatternState
    st = PatternState(pattern_id="job_timeout@system=risky", route=Route.HITL)   # learned low, not held by hand
    eng.store.put_pattern_state(st)
    assert eng.effective_route(p, {"system": "risky"}) is Route.AUTO         # 0 own decisions: pooled
    st.samples = 3
    eng.store.put_pattern_state(st)
    assert eng.effective_route(p, {"system": "risky"}) is Route.HITL         # its own evidence now decides


def test_a_reversal_in_one_scope_demotes_the_pool(eng):
    p = eng.registry.get("job_timeout")
    eng.set_route("job_timeout", Route.AUTO, actor="setup")
    r = eng.ingest(job_event(ref="B1", system="store1"))
    assert eng.store.get_incident(r.incident_id).state.value == "dispositioned"
    eng.reverse(r.incident_id, actor="lead", note="wrong store")
    assert eng.store.get_pattern_state("job_timeout").route is not Route.AUTO
    assert eng.effective_route(p, {"system": "store2"}) is not Route.AUTO     # other thin scopes drop with it


def test_pooling_is_off_unless_set(engine_factory, backend):
    eng = engine_factory(ov=make_overlay(backend, patterns=[timeout(trust_pool_min=None)]),
                         learning=LearningPolicy(promote_streak={Route.HITL: 2, Route.LLM: 2}))
    for i in range(2):
        eng.ingest(job_event(ref=f"S{i}", system=f"store{i}"))
        approve_open(eng)
    assert eng.store.get_pattern_state("job_timeout") is None                # as before: the base never learns


def test_pooling_is_part_of_the_definition_only_when_set():
    assert timeout(trust_pool_min=None).definition_hash() == Pattern(
        id="job_timeout", event_types=["job.failed"], match={"error": "TIMEOUT"}, route=Route.HITL,
        playbook=[PlaybookStep(action="retry", params={"ref": "{{payload.ref}}"})],
        allowed_actions=["retry", "notify"], owner_role="ops", trust_by=["system"]).definition_hash()
    assert timeout().definition_hash() != timeout(trust_pool_min=None).definition_hash()


def test_trace_says_the_route_is_pooled(eng):
    eng.set_route("job_timeout", Route.AUTO, actor="setup")
    t = eng.trace(job_event(ref="T1", system="new_store"))
    assert "pooled across scopes" in t["route"]["why"] and t["route"]["route"] == "auto"


def test_a_scope_held_by_hand_stays_held_whatever_the_pool(eng, backend):
    p = eng.registry.get("job_timeout")
    eng.set_route("job_timeout", Route.AUTO, actor="setup")
    eng.set_route("job_timeout@system=thin", Route.HITL, actor="lead")          # thin scope: pool would say AUTO
    assert eng.effective_route(p, {"system": "thin"}) is Route.HITL
    st = eng.store.get_pattern_state("job_timeout@system=mature")
    eng.set_route("job_timeout@system=mature", Route.AUTO, actor="setup")
    st = eng.store.get_pattern_state("job_timeout@system=mature")
    st.samples = 5
    eng.store.put_pattern_state(st)
    eng.set_route("job_timeout@system=mature", Route.HITL, actor="lead")        # resets samples: still held
    assert eng.effective_route(p, {"system": "mature"}) is Route.HITL
    backend.calls.clear()
    eng.ingest(job_event(ref="H1", system="thin"))
    eng.ingest(job_event(ref="H2", system="mature"))
    assert backend.calls == []
    eng.set_route("job_timeout@system=thin", Route.AUTO, actor="setup")         # raising releases the hold
    assert eng.store.get_pattern_state("job_timeout@system=thin").cap is None
    assert eng.effective_route(p, {"system": "thin"}) is Route.AUTO
    eng.set_route("job_timeout@system=fresh", Route.HITL, actor="lead")          # no open case: trace routes it
    assert eng.trace(job_event(ref="T2", system="fresh"))["route"]["route"] == "hitl"
