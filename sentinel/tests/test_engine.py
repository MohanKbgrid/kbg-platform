# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""Engine behaviour: routes, human decisions, grouping, inhibition, failures, SLA, reversal, guardrails."""
from __future__ import annotations

import json
import time

import pytest

from sentinel import (ActionResult, Decision, DecisionKind, EngineError, Guardrails, IncidentState as S,
                      PlaybookStep, Route, ScriptedLLM)
from tests.conftest import job_event, stuck_event


def final(action="hold", params=None, code="resolved", conf=0.95, why="looks stuck"):
    return {"final": {"action": action, "params": params if params is not None else {"ref": "I1"},
                      "disposition_code": code, "confidence": conf, "rationale": why}}


def review_of(engine, inc_id):
    r = engine.store.open_review_for(inc_id)
    assert r is not None, "expected an open review"
    return r

# ------------------------------------------------------------------ AUTO

def test_auto_route_executes_playbook_and_dispositions(engine, backend):
    r = engine.ingest(job_event())
    inc = engine.store.get_incident(r.incident_id)
    assert r.status == "new" and inc.state is S.DISPOSITIONED
    assert backend.calls == [("retry", {"ref": "J1"})]
    d = engine.store.get_disposition(inc.id)
    assert d.resolver == "auto" and d.code == "resolved" and d.steps[0].action == "retry"


def test_auto_irreversible_needs_human_by_default(engine_factory, backend):
    eng = engine_factory(guardrails=Guardrails())  # default: irreversible needs a human
    r = eng.ingest(job_event())
    inc = eng.store.get_incident(r.incident_id)
    assert inc.state is S.AWAITING_HUMAN and backend.calls == []
    rev = review_of(eng, inc.id)
    assert "irreversible" in rev.reason and rev.proposal.steps[0].action == "retry"
    eng.decide(rev.id, Decision(kind=DecisionKind.APPROVE, actor="mohan"))
    assert backend.calls == [("retry", {"ref": "J1"})]
    d = eng.store.get_disposition(inc.id)
    assert d.resolver == "human" and d.agreed_with_proposal is True

# ------------------------------------------------------------------ LLM

def test_llm_confident_reversible_action_executes(engine_factory, backend):
    llm = ScriptedLLM([final()])
    eng = engine_factory(llm=llm)
    r = eng.ingest(stuck_event())
    assert eng.store.get_incident(r.incident_id).state is S.DISPOSITIONED
    assert backend.calls == [("hold", {"ref": "I1"})]
    assert eng.store.get_disposition(r.incident_id).resolver == "llm"


def test_llm_low_confidence_goes_to_human_with_diagnosis(engine_factory, backend):
    eng = engine_factory(llm=ScriptedLLM([final(conf=0.4)]))
    r = eng.ingest(stuck_event())
    rev = review_of(eng, r.incident_id)
    assert "confidence" in rev.reason and rev.proposal.source == "llm" and backend.calls == []


def test_llm_irreversible_action_needs_human_even_when_confident(engine_factory, backend):
    eng = engine_factory(llm=ScriptedLLM([final(action="cancel", conf=0.99)]), guardrails=Guardrails())
    r = eng.ingest(stuck_event())
    assert "irreversible" in review_of(eng, r.incident_id).reason and backend.calls == []


def test_llm_tool_loop_then_final(engine_factory, backend):
    llm = ScriptedLLM([{"tool": "lookup", "args": {"ref": "I1"}}, final()])
    eng = engine_factory(llm=llm)
    eng.ingest(stuck_event())
    second_call = llm.calls[1]
    assert any("tool_result" in m["content"] for m in second_call if m["role"] == "user")
    assert backend.calls == [("hold", {"ref": "I1"})]


@pytest.mark.parametrize("bad", [
    "I think you should hold it",                                   # no JSON
    "{not json}",                                                   # broken JSON
    json.dumps(final(action="delete_everything")),                  # action not allowed
    json.dumps(final(params={"ref": 5})),                           # bad params
    json.dumps(final(code="made_up")),                              # bad disposition code
    json.dumps(final(conf="high")),                                 # bad confidence
    json.dumps({"tool": "ghost_tool", "args": {}}),                 # unknown tool
    json.dumps({"something": "else"}),                              # neither tool nor final
])
def test_llm_bad_output_is_repaired_once(engine_factory, backend, bad):
    eng = engine_factory(llm=ScriptedLLM([bad, final()]))
    r = eng.ingest(stuck_event())
    assert eng.store.get_incident(r.incident_id).state is S.DISPOSITIONED
    assert backend.calls == [("hold", {"ref": "I1"})]


def test_llm_persistently_bad_falls_back_to_human_with_playbook(engine_factory, backend):
    eng = engine_factory(llm=ScriptedLLM(["nope", "still nope"]))
    r = eng.ingest(stuck_event())
    rev = review_of(eng, r.incident_id)
    assert "LLM could not resolve" in rev.reason
    assert rev.proposal.source == "playbook" and backend.calls == []


def test_llm_exception_and_timeout(engine_factory, backend):
    eng = engine_factory(llm=ScriptedLLM([ConnectionError("down")]))
    r = eng.ingest(stuck_event(ref="I1"))
    assert "ConnectionError" in review_of(eng, r.incident_id).reason

    def slow(system, messages):
        time.sleep(2)
        return json.dumps(final())
    eng2 = engine_factory(llm=ScriptedLLM(fn=slow), llm_timeout_s=0.2)
    r2 = eng2.ingest(stuck_event(ref="I2"))
    assert "timed out" in review_of(eng2, r2.incident_id).reason


def test_llm_never_runs_away(engine_factory):
    eng = engine_factory(llm=ScriptedLLM(fn=lambda s, m: json.dumps({"tool": "lookup", "args": {}})))
    r = eng.ingest(stuck_event())
    assert "steps" in review_of(eng, r.incident_id).reason


def test_llm_route_degrades_to_hitl_without_client(engine, backend):
    r = engine.ingest(stuck_event())
    inc = engine.store.get_incident(r.incident_id)
    assert inc.route is Route.HITL and inc.state is S.AWAITING_HUMAN


def test_brief_contains_history_and_allowed_actions(engine_factory):
    llm = ScriptedLLM([final(), final(params={"ref": "I2"})])
    eng = engine_factory(llm=llm)
    eng.ingest(stuck_event(ref="I1"))
    eng.ingest(stuck_event(ref="I2"))
    brief = json.loads(llm.calls[1][0]["content"])
    assert {a["action"] for a in brief["allowed_actions"]} == {"hold", "cancel", "notify"}
    assert brief["how_humans_resolved_this_before"][0]["steps"][0]["action"] == "hold"

# ------------------------------------------------------------------ HITL decisions

def test_hitl_with_llm_diagnosis(engine_factory, backend):
    eng = engine_factory(llm=ScriptedLLM([final(action="retry", params={"ref": "J9"})]))
    r = eng.ingest(job_event(error="AUTH", ref="J9"))
    rev = review_of(eng, r.incident_id)
    assert rev.proposal.source == "llm" and rev.assignee_role == "ops"


def test_decide_modify_and_reject(engine, backend):
    r1 = engine.ingest(job_event(error="AUTH", ref="J2"))
    rev = review_of(engine, r1.incident_id)
    engine.decide(rev.id, Decision(kind=DecisionKind.MODIFY, actor="a", action="notify",
                                   params={"ref": "J2", "msg": "check creds"}))
    assert backend.calls == [("notify", {"ref": "J2", "msg": "check creds"})]
    assert engine.store.get_disposition(r1.incident_id).agreed_with_proposal is None  # nothing was proposed

    r2 = engine.ingest(job_event(error="AUTH", ref="J3"))
    rev2 = review_of(engine, r2.incident_id)
    engine.decide(rev2.id, Decision(kind=DecisionKind.REJECT, actor="a", disposition_code="false_positive"))
    d = engine.store.get_disposition(r2.incident_id)
    assert d.code == "false_positive" and d.steps == [] and len(backend.calls) == 1


def test_decide_validation(engine):
    r = engine.ingest(job_event(error="AUTH"))
    rev = review_of(engine, r.incident_id)
    with pytest.raises(EngineError, match="nothing to approve"):
        engine.decide(rev.id, Decision(kind=DecisionKind.APPROVE, actor="a"))
    with pytest.raises(EngineError, match="not allowed"):
        engine.decide(rev.id, Decision(kind=DecisionKind.MODIFY, actor="a", action="hold", params={"ref": "x"}))
    with pytest.raises(EngineError, match="missing param"):
        engine.decide(rev.id, Decision(kind=DecisionKind.MODIFY, actor="a", action="retry", params={}))
    with pytest.raises(EngineError, match="disposition_code"):
        engine.decide(rev.id, Decision(kind=DecisionKind.REJECT, actor="a", disposition_code="whatever"))
    with pytest.raises(EngineError, match="needs a disposition_code"):
        engine.decide(rev.id, Decision(kind=DecisionKind.REJECT, actor="a"))
    with pytest.raises(EngineError, match="unknown review"):
        engine.decide("rev_nope", Decision(kind=DecisionKind.REJECT, actor="a", disposition_code="resolved"))
    engine.decide(rev.id, Decision(kind=DecisionKind.REJECT, actor="a", disposition_code="no_action"))
    with pytest.raises(EngineError, match="closed"):
        engine.decide(rev.id, Decision(kind=DecisionKind.REJECT, actor="a", disposition_code="no_action"))


def test_unmatched_events_go_to_supervisor(engine):
    from sentinel import Event
    r = engine.ingest(Event(type="brand.new.thing", source="x"))
    inc = engine.store.get_incident(r.incident_id)
    assert inc.pattern_id == "__unmatched__"
    assert review_of(engine, inc.id).assignee_role == "supervisor"

# ------------------------------------------------------------------ grouping & inhibition

def test_grouping_window(engine, clock, backend):
    r1 = engine.ingest(job_event(error="AUTH", ref="J1"))
    r2 = engine.ingest(job_event(error="AUTH", ref="J2"))  # same signature: system+error
    assert r2.status == "grouped" and r2.incident_id == r1.incident_id
    assert len(engine.store.event_ids(r1.incident_id)) == 2
    clock.advance(minutes=61)
    r3 = engine.ingest(job_event(error="AUTH", ref="J3"))
    assert r3.status == "new" and r3.incident_id != r1.incident_id


def test_dispositioned_incident_does_not_absorb_new_events(engine):
    r1 = engine.ingest(job_event())  # auto-resolved immediately
    r2 = engine.ingest(job_event())
    assert r2.status == "new" and r2.incident_id != r1.incident_id


def test_inhibition_and_cascade(engine, backend):
    from sentinel import Event
    parent = engine.ingest(Event(type="site.down", source="mon", payload={"site": "S1"}))
    child = engine.ingest(stuck_event(site="S1"))
    other_site = engine.ingest(stuck_event(site="S2", ref="I9"))
    assert child.status == "suppressed"
    assert engine.store.get_incident(child.incident_id).parent_id == parent.incident_id
    assert other_site.status == "new"                   # inhibit_on site: different site not suppressed
    rev = review_of(engine, parent.incident_id)
    engine.decide(rev.id, Decision(kind=DecisionKind.MODIFY, actor="lead", action="notify",
                                   params={"ref": "S1", "msg": "site back"}))
    c = engine.store.get_incident(child.incident_id)
    assert c.state is S.DISPOSITIONED
    assert engine.store.get_disposition(c.id).code == "resolved_by_parent"

# ------------------------------------------------------------------ failures

def test_transient_failure_is_retried(engine, backend):
    backend.fail_next["retry"] = [RuntimeError("blip"), ActionResult(ok=False, detail="503")]
    r = engine.ingest(job_event())
    assert engine.store.get_incident(r.incident_id).state is S.DISPOSITIONED
    assert backend.count("retry") == 1


def test_permanent_failure_goes_to_human_then_human_fixes(engine, backend):
    backend.fail_next["retry"] = [ActionResult(ok=False, detail="order locked", retryable=False)]
    r = engine.ingest(job_event())
    inc = engine.store.get_incident(r.incident_id)
    assert inc.state is S.AWAITING_HUMAN and "order locked" in inc.last_error
    rev = review_of(engine, inc.id)
    assert "execution failed" in rev.reason
    engine.decide(rev.id, Decision(kind=DecisionKind.APPROVE, actor="a"))  # retry again, new run key
    assert engine.store.get_incident(inc.id).state is S.DISPOSITIONED and backend.count("retry") == 1


def test_exhausted_retries(engine, backend):
    backend.fail_next["retry"] = [RuntimeError("x")] * 3
    r = engine.ingest(job_event())
    assert engine.store.get_incident(r.incident_id).state is S.AWAITING_HUMAN
    attempts = [a for a in engine.store.audit_log(r.incident_id) if a["kind"] == "action_attempt"]
    assert len(attempts) == 3


def test_handler_returning_garbage(engine_factory, backend, overlay):
    from sentinel import ActionSpec
    overlay.actions.register(ActionSpec(name="bad"), lambda c, p: "ok?")
    overlay.patterns.append(overlay.patterns[0].model_copy(update={
        "id": "bad_p", "match": {"error": "BAD"}, "playbook": [PlaybookStep(action="bad")],
        "allowed_actions": ["bad"]}))
    eng = engine_factory(ov=overlay)
    r = eng.ingest(job_event(error="BAD"))
    assert "returned str" in eng.store.get_incident(r.incident_id).last_error


def test_failing_multistep_does_not_rerun_completed_steps(engine_factory, overlay, backend):
    overlay.patterns.append(overlay.patterns[0].model_copy(update={
        "id": "two_step", "match": {"error": "TWO"}, "priority": 9,
        "playbook": [PlaybookStep(action="hold", params={"ref": "{{payload.ref}}"}),
                     PlaybookStep(action="retry", params={"ref": "{{payload.ref}}"})],
        "allowed_actions": ["hold", "retry"]}))
    eng = engine_factory(ov=overlay)
    backend.fail_next["retry"] = [ActionResult(ok=False, detail="no", retryable=False)]
    r = eng.ingest(job_event(error="TWO"))
    assert backend.count("hold") == 1 and backend.count("retry") == 0
    assert eng.store.get_incident(r.incident_id).state is S.AWAITING_HUMAN

# ------------------------------------------------------------------ SLA

def test_sla_escalation(engine, clock, notes):
    engine.ingest(job_event(error="AUTH"))
    assert engine.sweep() == []
    clock.advance(minutes=241)
    esc = engine.sweep()
    assert len(esc) == 1 and esc[0].assignee_role == "lead" and esc[0].escalation_level == 1
    assert engine.sweep() == []          # due date moved forward
    assert any(k == "review_escalated" for k, _ in notes)

# ------------------------------------------------------------------ reversal

def test_reverse_compensates_reversible_and_flags_the_rest(engine_factory, overlay, backend, notes):
    overlay.patterns.append(overlay.patterns[0].model_copy(update={
        "id": "mixed", "match": {"error": "MIX"}, "priority": 9,
        "playbook": [PlaybookStep(action="hold", params={"ref": "R"}),
                     PlaybookStep(action="notify", params={"ref": "R", "msg": "held"})],
        "allowed_actions": ["hold", "notify"]}))
    eng = engine_factory(ov=overlay)
    r = eng.ingest(job_event(error="MIX"))
    d = eng.reverse(r.incident_id, actor="mohan", note="wrong call")
    assert d.reversed and backend.count("unhold") == 1
    assert ("manual_undo_needed", {"incident": r.incident_id, "actions": ["notify"]}) in notes
    with pytest.raises(EngineError, match="already reversed"):
        eng.reverse(r.incident_id, actor="mohan")

# ------------------------------------------------------------------ guardrails

def test_shadow_mode_never_executes_but_learns(engine_factory, backend):
    eng = engine_factory(guardrails=Guardrails(shadow=True, allow_irreversible_unattended=True))
    r = eng.ingest(job_event())
    inc = eng.store.get_incident(r.incident_id)
    assert inc.shadow and inc.state is S.AWAITING_HUMAN and backend.calls == []
    rev = review_of(eng, inc.id)
    assert "shadow" in rev.reason
    eng.decide(rev.id, Decision(kind=DecisionKind.APPROVE, actor="a"))   # human did the same in the old system
    d = eng.store.get_disposition(inc.id)
    assert d.shadow and d.agreed_with_proposal and backend.calls == []
    assert eng.report()["patterns"]["job_timeout"]["shadow_agreement"] == 1.0
    with pytest.raises(EngineError, match="shadow"):
        eng.reverse(inc.id, actor="a")


def test_circuit_breaker(engine_factory, backend):
    eng = engine_factory(guardrails=Guardrails(allow_irreversible_unattended=True, max_unattended_per_hour=2))
    for i in range(3):
        eng.ingest(job_event(ref=f"J{i}", system=f"s{i}"))
    assert backend.count("retry") == 2
    open_reviews = eng.store.open_reviews()
    assert len(open_reviews) == 1 and "circuit breaker" in open_reviews[0].reason


def test_kill_switch_and_ceiling(engine, backend):
    engine.set_route("job_timeout", Route.HITL, actor="mohan")
    r = engine.ingest(job_event())
    assert engine.store.get_incident(r.incident_id).state is S.AWAITING_HUMAN and backend.calls == []
    with pytest.raises(EngineError, match="ceiling"):
        engine.set_route("job_failed_other", Route.AUTO, actor="mohan")  # no playbook


def test_receiver_normalises_and_dedupes(engine, backend):
    out = engine.receive("jobs", {"id": "X1", "system": "billing", "error_code": "TIMEOUT", "ref": "J1"})
    again = engine.receive("jobs", {"id": "X1", "system": "billing", "error_code": "TIMEOUT", "ref": "J1"})
    assert out[0].status == "new" and again[0].status == "duplicate" and backend.count("retry") == 1
    with pytest.raises(EngineError, match="no receiver"):
        engine.receive("nope", {})


def test_invalid_registry_refuses_to_start(overlay, engine_factory):
    overlay.patterns[0] = overlay.patterns[0].model_copy(update={"allowed_actions": ["retry", "ghost"]})
    with pytest.raises(EngineError, match="ghost"):
        engine_factory(ov=overlay)


def test_audit_trail_tells_the_story(engine):
    r = engine.ingest(job_event())
    kinds = [a["kind"] for a in engine.store.audit_log(r.incident_id)]
    assert kinds[0] == "created"
    assert kinds.index("action_attempt") < kinds.index("dispositioned")


def test_safe_action_runs_unattended_under_strict_guardrails(engine_factory, overlay, backend):
    from sentinel import ActionSpec
    overlay.actions.register(ActionSpec(name="resync", safe=True, params_schema={"ref": "str"}),
                             lambda c, p: backend.do("resync", p))
    overlay.patterns.append(overlay.patterns[0].model_copy(update={
        "id": "resync_p", "match": {"error": "SYNC"}, "priority": 9,
        "playbook": [PlaybookStep(action="resync", params={"ref": "{{payload.ref}}"})],
        "allowed_actions": ["resync"]}))
    eng = engine_factory(ov=overlay, guardrails=Guardrails())
    r = eng.ingest(job_event(error="SYNC"))
    assert eng.store.get_incident(r.incident_id).state is S.DISPOSITIONED and backend.count("resync") == 1


def test_open_incident_absorbs_repeats_without_window(engine, clock):
    r1 = engine.ingest(stuck_event(age=10))          # item_stuck_short: no window -> absorbs while open
    clock.advance(days=3)
    r2 = engine.ingest(stuck_event(age=10))
    assert r2.status == "grouped" and r2.incident_id == r1.incident_id
