# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""A6 bulk decisions, E3 model cost and quality per exception, E2 owner report, A5 suggested patterns,
A7 mobile review page."""
from __future__ import annotations

import json

import pytest

from sentinel import Decision, DecisionKind, Event, ScriptedLLM
from sentinel.rbac import AuthorityRule
from tests.conftest import job_event, stuck_event
from tests.test_rbac import make_directory


def test_bulk_decisions_check_each_review(engine_factory, backend):
    eng = engine_factory(directory=make_directory())
    ids = []
    for i in range(3):
        r = eng.ingest(job_event(error="AUTH", ref=f"K{i}", system=f"s{i}", key=f"k{i}"))
        ids.append(eng.store.open_review_for(r.incident_id).id)
    res = eng.decide_many([*ids, "rev_gone", ids[0]], "reject", "lata", disposition_code="no_action")
    assert len(res["decided"]) == 3 and res["refused"][0]["reason"] == "no longer open"
    r = eng.ingest(job_event(error="AUTH", ref="K9", system="billing", key="k9"))
    rid = eng.store.open_review_for(r.incident_id).id
    out = eng.decide_many([rid], "approve", "lata")
    assert out["refused"][0]["reason"] == "nothing proposed to approve"
    big = eng.ingest(job_event(error="TIMEOUT", ref="K10", key="k10"))          # proposal: retry
    rv = eng.store.open_review_for(big.incident_id)
    if rv is not None:
        assert eng.decide_many([rv.id], "approve", "ravi")["decided"]          # ravi may retry
    with pytest.raises(Exception, match="approve proposals or close"):
        eng.decide_many(ids, "modify", "lata")


def _final(ref, conf=0.95):
    return json.dumps({"final": {"action": "hold", "params": {"ref": ref, "reason": "stuck"},
                                 "disposition_code": "resolved", "confidence": conf, "rationale": "r"}})


def test_model_quality_and_owner_report(engine_factory, clock):
    from sentinel.routing import ModelRouter
    llm = ScriptedLLM(fn=lambda s, m: _final(json.loads(m[0]["content"])["incident"]["facts"]["ref"]))
    router = ModelRouter(routes={"diagnose": llm}, prices={})
    eng = engine_factory(llm=router)
    for i in range(3):
        eng.ingest(stuck_event(ref=f"M{i}", site=f"S{i}"))
    q = eng.model_quality(days=30)
    row = next(x for x in q["patterns"] if x["pattern"] == "item_stuck_long")
    assert row["calls"] >= 3 and row["model_resolved"] == 3 and row["error_rate"] == 0
    from sentinel.ownerreport import build
    clock.advance(days=31)
    rep = build(eng, (clock() - __import__("datetime").timedelta(days=31)).strftime("%Y-%m"))
    assert "3 resolved automatically" in rep["text"] and "item_stuck_long" in rep["text"]


def test_owner_report_is_sent_over_text_edges(engine_factory):
    from sentinel.ownerreport import build, send
    sent = []

    class Mail:
        name = "mail"

        def deliver(self, card):
            return ""

        def send_text(self, contact, subject, text):
            sent.append((contact.get("email"), subject))
    d = make_directory()
    d.people["hari"].contact["email"] = "hari@x.in"
    eng = engine_factory(directory=d)
    eng.overlay.edges["mail"] = Mail()
    rep = build(eng, "2026-09")
    out = send(eng, rep, ["hari", "nobody"])
    assert sent == [("hari@x.in", "Sentinel: 2026-09")] and out["skipped"][0]["person"] == "nobody"


def test_suggestions_from_unmatched_cases(engine_factory):
    eng = engine_factory()
    for i in range(4):
        r = eng.ingest(Event(type="shipment.rto", source="courier", idempotency_key=f"r{i}",
                             payload={"awb": f"AWB{i}", "courier": "delhivery", "reason": "refused"}))
        rv = eng.store.open_review_for(r.incident_id)
        eng.decide(rv.id, Decision(kind=DecisionKind.MODIFY, actor="op", action="notify",
                                   params={"ref": f"AWB{i}", "msg": "returned"}, disposition_code="resolved"))
    for i in range(2):
        eng.ingest(Event(type="shipment.lost", source="courier", idempotency_key=f"l{i}", payload={"awb": f"L{i}"}))
    sugs = eng.suggest_patterns(days=30)
    assert len(sugs) == 1 and sugs[0]["event_type"] == "shipment.rto" and sugs[0]["cases"] == 4
    p = sugs[0]["pattern"]
    assert p["route"] == "hitl" and p["allowed_actions"] == ["notify"]
    assert p["playbook"] == [{"action": "notify", "params": {"ref": "{{payload.awb}}", "msg": "returned"}}]
    assert sugs[0]["fingerprint"]["fields"] == {"awb": "awb", "courier": "courier", "reason": "reason"}
    from sentinel.config import dump_yaml
    import yaml
    doc = yaml.safe_load(eng.config_text("registry"))
    doc["patterns"].append(p)
    doc["fingerprints"].append(sugs[0]["fingerprint"])
    doc["roles"] = {**sugs[0]["roles"], **doc["roles"]}
    _, probs = eng.check_config("registry", dump_yaml(doc))
    assert not [x for x in probs if x.severity == "error"]              # a draft that publishes as it is


def test_bulk_api_and_mobile_page(engine_factory):
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from sentinel.api import Principal, create_app, token_hash
    d = make_directory()
    d.rules.append(AuthorityRule(role_id="ops_head", action="__configure__"))
    eng = engine_factory(directory=d)
    r = eng.ingest(job_event(error="AUTH", ref="B1", key="b1"))
    rid = eng.store.open_review_for(r.incident_id).id
    c = TestClient(create_app(eng, {token_hash("l"): Principal("person", "lata")}, config_sync_s=0))
    H = {"Authorization": "Bearer l"}
    assert c.post("/v1/reviews/bulk", json={"review_ids": [rid], "kind": "reject", "disposition_code": "no_action"},
                  headers=H).json()["decided"][0]["review"] == rid
    assert c.post("/v1/reviews/bulk", json={"review_ids": [], "kind": "reject"}, headers=H).status_code == 422
    page = c.get("/console/m")
    assert page.status_code == 200 and "m.js" in page.text
    assert c.get("/console/static/m.js").status_code == 200
    assert c.get("/console/api/model-quality", headers=H).status_code == 200
    assert c.get("/console/api/suggestions", headers=H).json() == []
