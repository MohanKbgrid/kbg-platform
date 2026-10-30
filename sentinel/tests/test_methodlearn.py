# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""Learning methods of work: a candidate method is proposed from what people keep doing, backtested on past
cases, watched in shadow, promoted by someone with the authority (maker-checker applies) and rolled back.
The system never approves its own change and never widens what an exception may do."""
from __future__ import annotations

import pytest

from sentinel import AuthorizationError, Decision, DecisionKind, Guardrails
from sentinel.methodlearn import MethodLearnError
from sentinel.rbac import AuthorityRule, ConfigApproval
from tests.conftest import job_event
from tests.test_rbac import make_directory


def _dir(**kw):
    d = make_directory(**kw)
    d.rules.append(AuthorityRule(role_id="ops_head", action="__configure__"))
    return d


@pytest.fixture
def eng(engine_factory):
    return engine_factory(directory=_dir(), guardrails=Guardrails())


def _decide(eng, clock, ref, action="retry", params=None, actor="ravi", code=None):
    clock.advance(minutes=61)                         # job_failed_other groups repeats within an hour
    r = eng.ingest(job_event(error="AUTH", ref=ref))
    rev = eng.store.open_review_for(r.incident_id)
    eng.decide(rev.id, Decision(kind=DecisionKind.MODIFY, actor=actor, action=action,
                                params=params if params is not None else {"ref": ref}, disposition_code=code))
    return r.incident_id


def _history(eng, clock, n=6):
    for i in range(n):
        _decide(eng, clock, f"J{i}")
    _decide(eng, clock, "JX", action="notify", params={"ref": "JX", "msg": "vendor asked us to wait"})


def test_a_method_is_proposed_from_what_people_keep_doing(eng, clock):
    _history(eng, clock)
    new = eng.propose_methods(min_cases=5)
    assert len(new) == 1
    c = new[0]
    assert c["pattern_id"] == "job_failed_other" and c["name"] == "job_failed_other@2"
    assert c["steps"] == [{"action": "retry", "params": {"ref": "{{payload.ref}}"}}]
    assert c["support"]["cases"] == 6 and c["support"]["decided"] == 7
    assert c["backtest"]["agreement"] == pytest.approx(6 / 7, abs=0.001)
    assert c["backtest"]["current"]["basis"] == "no proposal to compare"
    assert eng.propose_methods(min_cases=5) == []                         # not proposed twice


def test_bad_evidence_is_not_learned_from(eng, clock):
    for i in range(6):
        inc = _decide(eng, clock, f"J{i}")
        if i < 2:
            eng.reverse(inc, actor="hari", note="wrong fix")                # reversed: not evidence
    assert eng.propose_methods(min_cases=5) == []
    # a step outside what the exception allows is never learned, whatever people did
    p = eng.registry.get("job_failed_other")
    assert "hold" not in p.allowed_actions


def test_shadow_promote_and_roll_back(eng, clock):
    _history(eng, clock)
    cid = eng.propose_methods(min_cases=5)[0]["id"]
    with pytest.raises(AuthorizationError):
        eng.decide_method(cid, "shadow", "ravi")                          # not ops' call
    eng.decide_method(cid, "shadow", "hari")
    with pytest.raises(MethodLearnError, match="shadow case"):
        eng.decide_method(cid, "promote", "hari", min_shadow_cases=3)     # it has not earned it yet
    for i in range(3):
        _decide(eng, clock, f"S{i}")
    _decide(eng, clock, "SX", action="notify", params={"ref": "SX", "msg": "different"})
    c = next(x for x in eng.method_candidates() if x["id"] == cid)
    assert c["shadow"]["cases"] == 4 and c["shadow"]["agreed"] == 3 and c["shadow"]["agreement"] == 0.75
    with pytest.raises(MethodLearnError, match="75%"):
        eng.decide_method(cid, "promote", "hari", min_shadow_cases=3, min_agreement=0.8)
    c = eng.decide_method(cid, "promote", "hari", min_shadow_cases=3, min_agreement=0.7)
    assert c["status"] == "promoted"
    p = eng.registry.get("job_failed_other")
    assert p.method == "job_failed_other@2" and p.playbook[0].action == "retry"
    assert p.route.value == "hitl"                                        # still a person; trust starts again

    clock.advance(minutes=61)
    r = eng.ingest(job_event(error="AUTH", ref="N1"))
    inc = eng.store.get_incident(r.incident_id)
    assert inc.provenance.method == "job_failed_other@2"
    assert eng.store.open_review_for(inc.id).proposal.steps[0].params == {"ref": "N1"}

    eng.decide_method(cid, "rollback", "hari", note="the vendor changed their API")
    p = eng.registry.get("job_failed_other")
    assert p.playbook == [] and p.method is None
    kinds = [a["kind"] for a in eng.store.recent_audit(200)]
    assert {"method_proposed", "method_shadow_started", "method_promoted", "method_rolled_back"} <= set(kinds)


def test_promotion_waits_for_a_second_person_with_maker_checker(engine_factory, clock):
    eng = engine_factory(directory=_dir(config_approval=ConfigApproval(approvals=1)), guardrails=Guardrails())
    _history(eng, clock)
    cid = eng.propose_methods(min_cases=5)[0]["id"]
    eng.decide_method(cid, "shadow", "hari")
    for i in range(3):
        _decide(eng, clock, f"S{i}")
    c = eng.decide_method(cid, "promote", "hari", min_shadow_cases=3)
    assert c["status"] == "awaiting_approval" and eng.registry.get("job_failed_other").playbook == []
    eng.approve_config(c["config_version"], "hema")
    assert next(x for x in eng.method_candidates() if x["id"] == cid)["status"] == "promoted"
    assert eng.registry.get("job_failed_other").method == "job_failed_other@2"


def test_parameters_people_choose_case_by_case_are_not_guessed(eng, clock):
    for i in range(6):
        _decide(eng, clock, f"J{i}", action="notify", params={"ref": f"J{i}", "msg": f"note {i * 7}"})
    assert eng.propose_methods(min_cases=5) == []          # the message varies with nothing the case carries
    clock.advance(days=200)
    assert eng.propose_methods(min_cases=1, days=30) == []  # old cases are not evidence



def test_console_lists_and_decides_candidates(eng, clock):
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from sentinel.api import Principal, create_app, token_hash
    _history(eng, clock)
    toks = {"hari": Principal("person", "hari"), "ravi": Principal("person", "ravi")}
    app = create_app(eng, {token_hash(k): v for k, v in toks.items()}, config_sync_s=0)
    with TestClient(app) as c:
        hdr = lambda t: {"Authorization": f"Bearer {t}"}                   # noqa: E731
        assert c.post("/console/api/methods/propose", json={}, headers=hdr("ravi")).status_code == 403
        new = c.post("/console/api/methods/propose", json={}, headers=hdr("hari")).json()
        assert [x["name"] for x in new] == ["job_failed_other@2"]
        cid = new[0]["id"]
        assert c.post(f"/console/api/methods/candidates/{cid}/promote", json={}, headers=hdr("hari")).status_code == 409
        assert c.post(f"/console/api/methods/candidates/{cid}/shadow", json={}, headers=hdr("ravi")).status_code == 403
        assert c.post(f"/console/api/methods/candidates/{cid}/shadow", json={}, headers=hdr("hari")).json()["status"] == "shadow"
        assert c.get("/console/api/methods/candidates", headers=hdr("ravi")).json()[0]["status"] == "shadow"


# ------------------------------------------------------------------------------- randomised trial
def _trial_engine(engine_factory):
    from sentinel import Pattern, PlaybookStep, Route
    from tests.conftest import Backend, make_overlay
    ov = make_overlay(Backend(), patterns=[
        Pattern(id="job_failed_other", event_types=["job.failed"], match={"system": "*"}, route=Route.HITL,
                allowed_actions=["retry", "notify", "cancel"], owner_role="ops", group_window_minutes=60,
                playbook=[PlaybookStep(action="notify", params={"ref": "{{payload.ref}}", "msg": "looking into it"})],
                outcome_check={"verifier": "fixed", "after_minutes": 10})])
    # the job is fixed only when it was retried: the method really matters
    ov.verifiers = {"fixed": lambda *, incident, disposition, params, services:
                    any(s.action == "retry" for s in disposition.steps)}
    return engine_factory(ov=ov, directory=_dir(), guardrails=Guardrails())


def _approve_new_cases(eng, clock, n, prefix):
    arms = {"trial": 0, "current": 0}
    for i in range(n):
        clock.advance(minutes=61)
        r = eng.ingest(job_event(error="AUTH", ref=f"{prefix}{i}"))
        inc = eng.store.get_incident(r.incident_id)
        arms["trial" if inc.provenance.trial else "current"] += 1
        assert inc.route.value == "hitl"
        rev = eng.store.open_review_for(inc.id)
        eng.decide(rev.id, Decision(kind=DecisionKind.APPROVE, actor="ravi"))
        clock.advance(minutes=11)
        eng.work("w")
    return arms


def test_a_randomised_trial_shows_whether_the_method_causes_better_outcomes(engine_factory, clock):
    eng = _trial_engine(engine_factory)
    _history(eng, clock)                                   # people kept replacing the notify with a retry
    c = eng.propose_methods(min_cases=5)[0]
    assert c["steps"][0]["action"] == "retry" and c["backtest"]["current"]["agreement"] == 0
    with pytest.raises(MethodLearnError, match="shadow"):
        eng.decide_method(c["id"], "trial", "hari")
    eng.decide_method(c["id"], "shadow", "hari")
    eng.decide_method(c["id"], "trial", "hari", share=0.5)
    arms = _approve_new_cases(eng, clock, 40, "T")
    assert arms["trial"] >= 10 and arms["current"] >= 10                   # random, roughly half each
    rep = eng.method_trial(c["id"])
    assert rep["candidate_arm"]["held_rate"] == 1.0 and rep["current_arm"]["held_rate"] == 0.0
    assert rep["verdict"] == "better" and rep["interval"][0] > 0
    rows = {m["method"]: m for m in eng.method_evidence()["methods"] if m["pattern"] == "job_failed_other"}
    assert rows["job_failed_other@2"]["cases"] == arms["trial"]           # the trial arm is its own row
    assert eng.decide_method(c["id"], "promote", "hari")["status"] == "promoted"


def test_a_trial_that_shows_the_method_worse_blocks_its_promotion(engine_factory, clock):
    eng = _trial_engine(engine_factory)
    for i in range(6):                                      # people kept choosing notify over the retry here
        _decide(eng, clock, f"J{i}", action="notify", params={"ref": f"J{i}", "msg": "vendor"})
    eng.registry.get("job_failed_other").playbook[0] = eng.registry.get("job_failed_other").playbook[0].model_copy(
        update={"action": "retry", "params": {"ref": "{{payload.ref}}"}})
    c = eng.propose_methods(min_cases=5)[0]
    assert c["steps"][0]["action"] == "notify"
    eng.decide_method(c["id"], "shadow", "hari")
    eng.decide_method(c["id"], "trial", "hari")
    _approve_new_cases(eng, clock, 40, "W")
    rep = eng.method_trial(c["id"])
    assert rep["verdict"] == "worse"
    with pytest.raises(MethodLearnError, match="worse"):
        eng.decide_method(c["id"], "promote", "hari")
    eng.decide_method(c["id"], "reject", "hari", note="the trial showed it worse")
    clock.advance(minutes=61)
    r = eng.ingest(job_event(error="AUTH", ref="after"))
    assert eng.store.get_incident(r.incident_id).provenance.trial is None    # the trial is over
