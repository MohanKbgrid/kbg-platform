# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""Edges from configuration: review cards as A2UI for chat surfaces (Ask AI) and on WhatsApp, answers back."""
from __future__ import annotations

import hashlib
import hmac
import http.server
import json
import threading

import pytest
import yaml

from sentinel import Guardrails, IncidentState as S
from sentinel.rbac import AuthorityRule
from sentinel.edges import A2UIEdge, WhatsAppEdge, a2ui_messages, answer_from_user_action, build_edges, sign
from tests.conftest import job_event
from tests.test_rbac import make_directory


class Capture(http.server.BaseHTTPRequestHandler):
    def do_POST(self):  # noqa: N802
        body = self.rfile.read(int(self.headers["Content-Length"]))
        self.server.got.append((self.path, dict(self.headers), json.loads(body)))
        out = json.dumps({"messages": [{"id": "wamid.1"}]} if "messages" in self.path else {"ref": "askai-1"})
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(out.encode())

    def log_message(self, *a):
        pass


@pytest.fixture
def capture():
    srv = http.server.HTTPServer(("127.0.0.1", 0), Capture)
    srv.got = []
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv, f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


ENV = {"SENTINEL_SECRET_ASK_AI": "a" * 32, "SENTINEL_SECRET_WA_TOKEN": "wa-token", "SENTINEL_SECRET_WA_APP_SECRET": "app-secret", "SENTINEL_SECRET_WA_VERIFY": "verify-me"}


@pytest.fixture
def eng(engine_factory, capture, monkeypatch):
    for k, v in ENV.items():
        monkeypatch.setenv(k, v)
    _, base = capture
    d = make_directory()
    d.people["ravi"].edges = ["whatsapp"]
    d.people["ravi"].contact["whatsapp"] = "+91 98450 12345"
    d.people["asha"].edges = ["ask_ai"]
    e = engine_factory(directory=d, guardrails=Guardrails(), card_link_base="https://ops.example")
    d.rules.append(AuthorityRule(role_id="ops_head", action="__configure__"))
    text = yaml.safe_dump({"edges": {
        "ask_ai": {"kind": "a2ui", "url": f"{base}/cards", "secret_env": "SENTINEL_SECRET_ASK_AI"},
        "whatsapp": {"kind": "whatsapp", "phone_number_id": "555", "access_token_env": "SENTINEL_SECRET_WA_TOKEN",
                     "app_secret_env": "SENTINEL_SECRET_WA_APP_SECRET", "verify_token_env": "SENTINEL_SECRET_WA_VERIFY", "base_url": base}}})
    cv, probs = e.save_config("connectors", text, author="hari")
    assert not [p for p in probs if p.severity == "error"], probs
    e.publish_config(cv.id, actor="hari")
    return e


def test_a2ui_card_is_well_formed():
    from sentinel.edges import ReviewCard
    from datetime import datetime, UTC
    card = ReviewCard(review_id="rev_1", incident_id="inc_1", pattern_id="p", title="Order stuck", severity="high",
                      reason="no stock", facts={"order": "SH-1", "source": "x"}, assignee_role="ops",
                      escalation_level=0, due_at=datetime.now(UTC), proposal_steps=[{"action": "hold",
                      "params": {"ref": "SH-1"}}], proposal_confidence=0.9, answer_options=["approve", "modify",
                      "reject"], disposition_codes=["resolved", "no_action"], link="https://ops/reviews/rev_1")
    msgs = a2ui_messages(card)
    assert list(msgs[0]) == ["surfaceUpdate"] and list(msgs[1]) == ["beginRendering"]
    comps = {c["id"]: c["component"] for c in msgs[0]["surfaceUpdate"]["components"]}
    assert msgs[1]["beginRendering"]["root"] == "root" and "Card" in comps["root"]
    for c in comps.values():                                   # every reference points at a defined component
        kind, props = next(iter(c.items()))
        refs = [props["child"]] if "child" in props else props.get("children", {}).get("explicitList", [])
        assert all(r in comps for r in refs), (kind, refs)
    approve = comps["approve"]["Button"]["action"]
    ctx = {e["key"]: e["value"]["literalString"] for e in approve["context"]}
    assert approve["name"] == "sentinel.answer" and ctx == {"review_id": "rev_1", "decision": "approve"}
    rid, dec = answer_from_user_action({"name": "sentinel.answer", "context": {
        "review_id": "rev_1", "decision": "reject", "disposition_code": "no_action"}})
    assert rid == "rev_1" and dec["kind"] == "reject" and dec["disposition_code"] == "no_action"
    with pytest.raises(ValueError):
        answer_from_user_action({"name": "other"})


def test_cards_go_out_on_configured_edges(eng, capture):
    srv, _ = capture
    eng.ingest(job_event(error="AUTH", system="billing"))           # ops: asha (billing) and ravi
    assert eng.work("w")["done"] >= 2
    by = {path: (h, b) for path, h, b in srv.got}
    h, body = by["/cards"]
    assert "a2ui" in body and body["card"]["recipient_id"] == "asha"
    assert h["X-Sentinel-Signature"].startswith("sha256=")
    h, wa = by["/555/messages"]
    assert h["Authorization"] == "Bearer wa-token" and wa["to"] == "919845012345"
    assert wa["type"] == "interactive" and wa["interactive"]["action"]["buttons"][0]["reply"]["title"].startswith("Close")


def test_answers_come_back(eng, capture, backend):
    srv, _ = capture
    from fastapi.testclient import TestClient

    from sentinel.api import create_app
    c = TestClient(create_app(eng, {}, config_sync_s=0, console=False))
    # WhatsApp: verification handshake, then a signed button reply from ravi's number
    assert c.get("/v1/whatsapp/whatsapp", params={"hub.mode": "subscribe", "hub.verify_token": "verify-me",
                                                  "hub.challenge": "42"}).text == "42"
    assert c.get("/v1/whatsapp/whatsapp", params={"hub.mode": "subscribe", "hub.verify_token": "no"}).status_code == 403
    r = eng.ingest(job_event(error="AUTH", system="hr", ref="J2"))    # only ravi is in scope
    eng.work("w")                                                     # his card goes out on WhatsApp
    rev = eng.store.open_review_for(r.incident_id)
    payload = {"entry": [{"changes": [{"value": {"messages": [{"from": "919845012345", "type": "interactive",
               "interactive": {"type": "button_reply", "button_reply": {
                   "id": WhatsAppEdge.reply_id(rev.id, "reject", "no_action"), "title": "Close"}}}]}}]}]}
    body = json.dumps(payload).encode()
    bad = c.post("/v1/whatsapp/whatsapp", content=body, headers={"X-Hub-Signature-256": "sha256=00"})
    assert bad.status_code == 401
    sig = "sha256=" + hmac.new(b"app-secret", body, hashlib.sha256).hexdigest()
    ok = c.post("/v1/whatsapp/whatsapp", content=body, headers={"X-Hub-Signature-256": sig,
                                                                "Content-Type": "application/json"})
    assert ok.json() == {"answers": 1, "received": 1}
    assert eng.store.get_incident(r.incident_id).state is S.DISPOSITIONED
    assert eng.store.get_disposition(r.incident_id).code == "no_action"
    # a reply from a number nobody has is refused and recorded
    payload["entry"][0]["changes"][0]["value"]["messages"][0]["from"] = "910000000000"
    body = json.dumps(payload).encode()
    sig = "sha256=" + hmac.new(b"app-secret", body, hashlib.sha256).hexdigest()
    assert c.post("/v1/whatsapp/whatsapp", content=body, headers={"X-Hub-Signature-256": sig}).json()["answers"] == 0
    assert any(a["kind"] == "edge_answer_refused" for a in eng.store.recent_audit(20))
    # Ask AI: an A2UI userAction, signed with the edge secret
    r2 = eng.ingest(job_event(error="AUTH", system="billing", ref="J3"))
    eng.work("w")
    rev2 = eng.store.open_review_for(r2.incident_id)
    sent = [b for path, _, b in srv.got if path == "/cards" and b["card"]["review_id"] == rev2.id][-1]
    comps = {x["id"]: x["component"] for x in sent["a2ui"][0]["surfaceUpdate"]["components"]}
    ctx = {e["key"]: e["value"]["literalString"] for e in comps["close1"]["Button"]["action"]["context"]}
    msg = json.dumps({"person_id": "asha", "userAction": {
        "name": "sentinel.answer", "surfaceId": f"review-{rev2.id}", "sourceComponentId": "close1",
        "timestamp": "2026-10-10T10:00:00Z", "context": ctx}}).encode()
    ts, s = sign("a" * 32, msg)
    res = c.post("/v1/edges/ask_ai/a2ui", content=msg, headers={"X-Sentinel-Timestamp": ts, "X-Sentinel-Signature": s})
    assert res.status_code == 200, res.text
    assert eng.store.get_disposition(r2.incident_id).code == "false_positive"
    assert c.post("/v1/edges/ask_ai/a2ui", content=msg, headers={"X-Sentinel-Timestamp": ts,
                                                                 "X-Sentinel-Signature": "sha256=0"}).status_code == 401


def test_template_mode_and_configuration_checks(eng):
    e = WhatsAppEdge("wa", "1", "t", "s", "v", template={"name": "sentinel_review", "language": "en"})
    card = eng.build_card(eng.store.open_review_for(eng.ingest(job_event(error="AUTH", system="hr")).incident_id),
                          "ravi")
    m = e.message(card)
    assert m["type"] == "template" and m["template"]["name"] == "sentinel_review"
    assert m["template"]["components"][1]["parameters"][0]["payload"].startswith("sentinel:rev_")
    waiting = build_edges({"x": {"kind": "a2ui", "url": "https://a", "secret_env": "SENTINEL_SECRET_NOPE"}}, env={})
    with pytest.raises(Exception, match="waiting for key SENTINEL_SECRET_NOPE"):   # configured, waits for its key
        waiting["x"].deliver(card)
    with pytest.raises(ValueError, match="cannot be used by configuration"):     # never the server's own secrets
        build_edges({"x": {"kind": "a2ui", "url": "https://a", "secret_env": "ANTHROPIC_API_KEY"}}, env={})
    with pytest.raises(ValueError, match="kind must be"):
        build_edges({"x": {"kind": "sms"}}, env={})
    _, probs = eng.check_config("connectors", "edges: {x: {kind: whatsapp, phone_number_id: '1'}}\n")
    assert any(p.severity == "error" and "access_token_env" in p.message for p in probs)
    assert isinstance(eng.overlay.edges["ask_ai"], A2UIEdge)
