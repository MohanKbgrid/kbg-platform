# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""HTTP API, metrics, health, payload limits and audit redaction."""
from __future__ import annotations

import json

import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from sentinel import Event, Guardrails, MemoryEdge, PayloadError  # noqa: E402
from sentinel.api import Principal, create_app, token_hash  # noqa: E402
from sentinel.edges import sign  # noqa: E402
from tests.conftest import job_event  # noqa: E402
from tests.test_rbac import make_directory  # noqa: E402

TOKENS = {"svc-token": Principal("service", "ingest"), "ravi-token": Principal("person", "ravi"),
          "lata-token": Principal("person", "lata"), "hari-token": Principal("person", "hari")}
EDGE_SECRET = "e" * 32


@pytest.fixture
def api(engine_factory, overlay):
    overlay.edges["ask_ai"] = MemoryEdge("ask_ai")
    eng = engine_factory(ov=overlay, directory=make_directory(), guardrails=Guardrails())
    app = create_app(eng, {token_hash(k): v for k, v in TOKENS.items()}, edge_secrets={"ask_ai": EDGE_SECRET},
                     ingest_per_minute=1000)
    return eng, TestClient(app)


def h(token):
    return {"Authorization": f"Bearer {token}"}


def test_auth_is_required_and_scoped(api):
    eng, c = api
    ev = job_event().model_dump(mode="json")
    assert c.post("/v1/events", json=ev).status_code == 401
    assert c.post("/v1/events", json=ev, headers=h("nope")).status_code == 401
    assert c.post("/v1/events", json=ev, headers=h("ravi-token")).status_code == 403   # people don't ingest
    assert c.get("/v1/reviews", headers=h("svc-token")).status_code == 403             # services don't decide
    r = c.post("/v1/events", json=ev, headers=h("svc-token"))
    assert r.status_code == 200 and r.json()["status"] == "new"


def test_review_flow_over_http(api, backend):
    eng, c = api
    c.post("/v1/events", json=job_event(error="AUTH").model_dump(mode="json"), headers=h("svc-token"))
    cards = c.get("/v1/reviews", headers=h("ravi-token")).json()
    assert len(cards) == 1 and cards[0]["recipient_id"] == "ravi"
    rid = cards[0]["review_id"]
    fwd = c.post(f"/v1/reviews/{rid}/decision", headers=h("ravi-token"),
                 json={"kind": "modify", "action": "cancel", "params": {"ref": "J1"}})
    assert fwd.status_code == 200 and fwd.json()["state"] == "awaiting_human"   # proposed: goes to the lead
    assert backend.calls == []
    rid2 = eng.store.open_review_for(fwd.json()["incident_id"]).id
    ok = c.post(f"/v1/reviews/{rid2}/decision", headers=h("lata-token"), json={"kind": "approve"})
    assert ok.status_code == 200 and ok.json()["state"] == "dispositioned"
    again = c.post(f"/v1/reviews/{rid2}/decision", headers=h("lata-token"),
                   json={"kind": "reject", "disposition_code": "no_action"})
    assert again.status_code == 409
    assert c.post("/v1/reviews/rev_ghost/decision", headers=h("lata-token"),
                  json={"kind": "reject", "disposition_code": "no_action"}).status_code == 404
    inc = c.get(f"/v1/incidents/{ok.json()['incident_id']}", headers=h("ravi-token")).json()
    assert inc["disposition"]["code"] == "resolved" and any(a["kind"] == "proposal_forwarded" for a in inc["audit"])
    assert backend.calls == [("cancel", {"ref": "J1"})]


def test_signed_edge_answers(api, backend):
    eng, c = api
    eng.overlay.default_edges = ["ask_ai"]
    r = eng.ingest(job_event(error="AUTH"))
    rid = eng.store.open_review_for(r.incident_id).id
    eng.work("w")                                                     # the card goes out with its answer token
    card = next(c for c in eng.overlay.edges["ask_ai"].cards if c.recipient_id == "ravi")
    forged = json.dumps({"review_id": rid, "person_id": "hari",       # the edge cannot answer as someone else
                         "decision": {"kind": "modify", "action": "retry", "params": {"ref": "J1"}},
                         "answer_token": card.answer_token}).encode()
    ts, sig = sign(EDGE_SECRET, forged)
    assert c.post("/v1/edges/ask_ai/answers", content=forged,
                  headers={"X-Sentinel-Timestamp": ts, "X-Sentinel-Signature": sig}).status_code == 403
    no_token = json.dumps({"review_id": rid, "person_id": "ravi",
                           "decision": {"kind": "modify", "action": "retry", "params": {"ref": "J1"}}}).encode()
    ts, sig = sign(EDGE_SECRET, no_token)
    assert c.post("/v1/edges/ask_ai/answers", content=no_token,
                  headers={"X-Sentinel-Timestamp": ts, "X-Sentinel-Signature": sig}).status_code == 403
    body = json.dumps({"review_id": rid, "person_id": "ravi", "answer_token": card.answer_token,
                       "decision": {"kind": "modify", "action": "retry", "params": {"ref": "J1"}}}).encode()
    ts, sig = sign(EDGE_SECRET, body)
    bad = c.post("/v1/edges/ask_ai/answers", content=body,
                 headers={"X-Sentinel-Timestamp": ts, "X-Sentinel-Signature": "sha256=forged"})
    assert bad.status_code == 401
    assert c.post("/v1/edges/unknown/answers", content=body,
                  headers={"X-Sentinel-Timestamp": ts, "X-Sentinel-Signature": sig}).status_code == 401
    ok = c.post("/v1/edges/ask_ai/answers", content=body,
                headers={"X-Sentinel-Timestamp": ts, "X-Sentinel-Signature": sig, "Content-Type": "application/json"})
    assert ok.status_code == 200 and backend.calls == [("retry", {"ref": "J1"})]
    big = b"{" + b" " * 2_000_000 + b"}"
    assert c.post("/v1/edges/ask_ai/answers", content=big).status_code == 413


def test_control_surface_over_http(api):
    eng, c = api
    assert c.post("/v1/patterns/job_timeout/route", json={"route": "hitl"},
                  headers=h("ravi-token")).status_code == 403
    assert c.post("/v1/patterns/job_timeout/route", json={"route": "hitl"},
                  headers=h("lata-token")).json()["route"] == "hitl"
    assert c.post("/v1/patterns/ghost/route", json={"route": "hitl"}, headers=h("hari-token")).status_code == 404
    assert c.post("/v1/patterns/job_timeout/route", json={"route": "sideways"},
                  headers=h("hari-token")).status_code == 422
    assert c.post("/v1/patterns/job_timeout/promotion/approve", headers=h("hari-token")).status_code == 422


def test_health_metrics_and_limits(api):
    eng, c = api
    big = Event(type="job.failed", source="x", payload={"blob": "x" * 300_000})
    assert c.post("/v1/events", json=big.model_dump(mode="json"), headers=h("svc-token")).status_code == 413
    deep: dict = {}
    cur = deep
    for _ in range(30):
        cur["n"] = {}
        cur = cur["n"]
    with pytest.raises(PayloadError):
        eng.ingest(Event(type="job.failed", source="x", payload=deep))
    c.post("/v1/events", json=job_event(error="AUTH").model_dump(mode="json"), headers=h("svc-token"))
    assert c.get("/healthz").json()["status"] == "ok"
    eng.enqueue("noop")
    text = c.get("/metrics").text
    assert 'sentinel_events_total{status="new"} 1' in text
    assert "sentinel_open_reviews 1" in text and "sentinel_ingest_seconds_bucket" in text
    assert 'sentinel_work_items{status="queued"} 1' in text


def test_rate_limit(engine_factory):
    eng = engine_factory()
    c = TestClient(create_app(eng, {token_hash("s"): Principal("service", "s")}, ingest_per_minute=3))
    codes = [c.post("/v1/events", json=job_event(ref=f"R{i}", system=f"x{i}").model_dump(mode="json"),
                    headers=h("s")).status_code for i in range(5)]
    assert codes[:3] == [200, 200, 200] and codes[3:] == [429, 429]


def test_audit_redacts_secrets(engine):
    engine.store.audit(None, "probe", {"api_key": "sk-123", "nested": {"password": "p"}, "ok": "visible"})
    data = engine.store.audit_log()[-1]["data"]
    assert data == {"api_key": "***", "nested": {"password": "***"}, "ok": "visible"}
