# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""Learning loop: trust is earned slowly, lost immediately, and promotions need a human."""
from __future__ import annotations

import json

import pytest

from sentinel import Decision, DecisionKind, EngineError, Guardrails, LearningPolicy, Route, ScriptedLLM
from tests.conftest import job_event, stuck_event


def approve_open(engine):
    for r in engine.store.open_reviews():
        engine.decide(r.id, Decision(kind=DecisionKind.APPROVE, actor="op"))


def final(ref):
    return json.dumps({"final": {"action": "hold", "params": {"ref": ref}, "disposition_code": "resolved",
                                 "confidence": 0.95, "rationale": "r"}})


def test_hitl_streak_proposes_promotion_and_human_approves(engine_factory, notes):
    # no LLM configured: HITL -> AUTO directly (pattern has a playbook)
    eng = engine_factory(guardrails=Guardrails(),
                         learning=LearningPolicy(promote_streak={Route.HITL: 3, Route.LLM: 3}))
    eng.set_route("job_timeout", Route.HITL, actor="setup")
    for i in range(3):
        eng.ingest(job_event(ref=f"J{i}", system=f"s{i}"))
        approve_open(eng)
    st = eng.store.get_pattern_state("job_timeout")
    assert st.route is Route.HITL and st.pending_promotion is Route.AUTO
    assert any(k == "promotion_proposed" for k, _ in notes)
    eng.approve_promotion("job_timeout", actor="mohan")
    assert eng.effective_route(eng.registry.get("job_timeout")) is Route.AUTO
    with pytest.raises(EngineError):
        eng.approve_promotion("job_timeout", actor="mohan")


def test_disagreement_resets_streak_and_withdraws_promotion(engine_factory):
    eng = engine_factory(guardrails=Guardrails(), learning=LearningPolicy(promote_streak={Route.HITL: 2}))
    eng.set_route("job_timeout", Route.HITL, actor="setup")
    for i in range(2):
        eng.ingest(job_event(ref=f"J{i}", system=f"s{i}"))
        approve_open(eng)
    assert eng.store.get_pattern_state("job_timeout").pending_promotion is Route.AUTO
    eng.ingest(job_event(ref="J9", system="s9"))
    rev = eng.store.open_reviews()[0]
    eng.decide(rev.id, Decision(kind=DecisionKind.MODIFY, actor="op", action="notify",
                                params={"ref": "J9", "msg": "not a retry"}))
    st = eng.store.get_pattern_state("job_timeout")
    assert st.streak == 0 and st.pending_promotion is None


def test_hitl_to_llm_when_llm_available(engine_factory):
    llm = ScriptedLLM(fn=lambda s, m: final(json.loads(m[0]["content"])["incident"]["facts"]["ref"]))
    eng = engine_factory(llm=llm, learning=LearningPolicy(promote_streak={Route.HITL: 2, Route.LLM: 2}))
    eng.set_route("item_stuck_long", Route.HITL, actor="setup")
    for i in range(2):
        eng.ingest(stuck_event(ref=f"I{i}"))
        approve_open(eng)  # human agrees with the LLM diagnosis
    assert eng.store.get_pattern_state("item_stuck_long").pending_promotion is Route.LLM
    eng.approve_promotion("item_stuck_long", actor="mohan")
    eng.ingest(stuck_event(ref="I7"))
    assert eng.store.get_disposition(eng.store.incidents()[-1].id).resolver == "llm"


def test_reversal_demotes_immediately(engine_factory):
    eng = engine_factory()
    r = eng.ingest(job_event())
    assert eng.effective_route(eng.registry.get("job_timeout")) is Route.AUTO
    eng.reverse(r.incident_id, actor="mohan", note="should not have retried")
    st = eng.store.get_pattern_state("job_timeout")
    assert st.route is Route.LLM and st.reversals == 1
    # no LLM client here, so effective route is HITL until someone re-earns trust
    assert eng.effective_route(eng.registry.get("job_timeout")) is Route.HITL


def test_auto_promote_respects_ceiling(engine_factory):
    eng = engine_factory(guardrails=Guardrails(),
                         learning=LearningPolicy(promote_streak={Route.HITL: 1, Route.LLM: 1}, auto_promote=True))
    eng.ingest(job_event(error="AUTH", ref="J1"))
    rev = eng.store.open_reviews()[0]
    eng.decide(rev.id, Decision(kind=DecisionKind.REJECT, actor="op", disposition_code="no_action"))
    # job_failed_other has no proposal -> no learning signal, stays HITL
    assert eng.store.get_pattern_state("job_failed_other").route is Route.HITL


def test_reject_promotion(engine_factory):
    eng = engine_factory(guardrails=Guardrails(), learning=LearningPolicy(promote_streak={Route.HITL: 1}))
    eng.set_route("job_timeout", Route.HITL, actor="setup")
    eng.ingest(job_event())
    approve_open(eng)
    eng.reject_promotion("job_timeout", actor="mohan", note="not yet")
    st = eng.store.get_pattern_state("job_timeout")
    assert st.pending_promotion is None and st.streak == 0


def test_report_shape(engine):
    engine.ingest(job_event())
    rep = engine.report()
    assert rep["patterns"]["job_timeout"]["automation_rate"] == 1.0
    assert set(rep["patterns"]) >= {"job_timeout", "__unmatched__"}
