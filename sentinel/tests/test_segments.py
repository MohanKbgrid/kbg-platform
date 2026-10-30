# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""Trust per segment: a pattern with `trust_by` earns (and loses) trust separately for each value."""
from __future__ import annotations

import hashlib
import json

import pytest

from sentinel import Decision, DecisionKind, LearningPolicy, Pattern, PlaybookStep, Route
from tests.conftest import job_event, make_overlay


def timeout(**over):
    base = dict(id="job_timeout", event_types=["job.failed"], match={"error": "TIMEOUT"}, route=Route.HITL,
                playbook=[PlaybookStep(action="retry", params={"ref": "{{payload.ref}}"})],
                allowed_actions=["retry", "notify"], owner_role="ops", trust_by=["system"])
    base.update(over)
    return Pattern(**base)


@pytest.fixture
def eng(engine_factory, backend):
    return engine_factory(ov=make_overlay(backend, patterns=[timeout()]),
                          learning=LearningPolicy(promote_streak={Route.HITL: 2, Route.LLM: 2}))


def approve_open(eng):
    for r in eng.store.open_reviews():
        eng.decide(r.id, Decision(kind=DecisionKind.APPROVE, actor="op"))


def test_segments_learn_independently(eng, backend):
    p = eng.registry.get("job_timeout")
    for i in range(2):
        eng.ingest(job_event(ref=f"B{i}", system="billing"))
        approve_open(eng)
    eng.ingest(job_event(ref="P0", system="payroll"))
    approve_open(eng)
    segs = {s["segment"]: s for s in eng.segments(p)}
    assert segs["system=billing"]["pending_promotion"] == "auto"
    assert segs["system=payroll"]["pending_promotion"] is None and segs["system=payroll"]["streak"] == 1
    assert eng.store.get_pattern_state("job_timeout") is None                # the base state never learns
    eng.approve_promotion("job_timeout@system=billing", actor="mohan")
    assert eng.effective_route(p, {"system": "billing"}) is Route.AUTO
    assert eng.effective_route(p, {"system": "payroll"}) is Route.HITL
    backend.calls.clear()
    eng.ingest(job_event(ref="B9", system="billing"))
    eng.ingest(job_event(ref="P9", system="payroll"))
    assert backend.calls == [("retry", {"ref": "B9"})]                       # payroll still goes to a person
    rep = eng.report()["patterns"]["job_timeout"]
    assert {s["segment"]: s["route"] for s in rep["segments"]} == {"system=billing": "auto",
                                                                  "system=payroll": "hitl"}


def test_kill_switch_on_the_pattern_lowers_every_segment(eng, backend):
    p = eng.registry.get("job_timeout")
    eng.set_route("job_timeout@system=billing", Route.AUTO, actor="setup")
    assert eng.effective_route(p, {"system": "billing"}) is Route.AUTO
    eng.set_route("job_timeout", Route.HITL, actor="setup")                   # kill switch
    assert eng.effective_route(p, {"system": "billing"}) is Route.HITL
    backend.calls.clear()
    eng.ingest(job_event(ref="B1", system="billing"))
    assert backend.calls == [] and eng.store.open_reviews()
    for s in eng.store.open_reviews():                                        # ...and it earns its way back
        eng.decide(s.id, Decision(kind=DecisionKind.APPROVE, actor="op"))
    eng.ingest(job_event(ref="B2", system="billing2"))                        # a new segment starts low too
    assert eng.effective_route(p, {"system": "billing2"}) is Route.HITL
    eng.ingest(job_event(ref="B3", system="billing"))
    approve_open(eng)
    assert eng.store.get_pattern_state("job_timeout@system=billing").pending_promotion is Route.AUTO
    eng.set_route("job_timeout", Route.AUTO, actor="setup")                   # raise everything again
    assert eng.effective_route(p, {"system": "billing"}) is Route.AUTO
    assert eng.effective_route(p, {"system": "new"}) is Route.AUTO            # new segments start where it stands


def test_reversal_demotes_only_that_segment(eng):
    p = eng.registry.get("job_timeout")
    eng.set_route("job_timeout@system=billing", Route.AUTO, actor="setup")
    eng.set_route("job_timeout@system=payroll", Route.AUTO, actor="setup")
    r = eng.ingest(job_event(ref="B1", system="billing"))
    eng.reverse(r.incident_id, actor="op", note="wrong")
    assert eng.effective_route(p, {"system": "billing"}) is Route.HITL
    assert eng.effective_route(p, {"system": "payroll"}) is Route.AUTO


def test_hash_unchanged_without_trust_by():
    p = timeout(trust_by=[])
    data = p.model_dump(mode="json", include=set(p._BEHAVIOUR_FIELDS) - {"trust_by"})
    data["playbook"] = [s.plain() for s in p.playbook]
    old = hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()[:16]
    assert p.definition_hash() == old and timeout().definition_hash() != old


def test_api_accepts_segment_ids(eng):
    from fastapi.testclient import TestClient

    from sentinel.api import create_app
    from sentinel.api import Principal, token_hash
    c = TestClient(create_app(eng, {token_hash("t"): Principal("person", "mohan")}, console=False))
    r = c.post("/v1/patterns/job_timeout%40system%3Dbilling/route", json={"route": "auto"},
               headers={"Authorization": "Bearer t"})
    assert r.status_code == 200, r.text
    assert r.json()["pattern_id"] == "job_timeout@system=billing"
    assert c.post("/v1/patterns/nope%40x%3D1/route", json={"route": "auto"},
                  headers={"Authorization": "Bearer t"}).status_code == 404


def test_configuration_round_trip_and_check(eng):
    import yaml
    text = eng.config_text("registry")
    pat = next(p for p in yaml.safe_load(text)["patterns"] if p["id"] == "job_timeout")
    assert pat["trust_by"] == ["system"]
    bad = text.replace("- system\n", "- channel\n", 1) if "- system\n" in text else text.replace(
        "trust_by: [system]", "trust_by: [channel]")
    _, probs = eng.check_config("registry", bad)
    assert any("trust_by ['channel']" in p.message for p in probs)
