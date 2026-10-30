# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""B5: WhatsApp through Gupshup and Interakt - cards out, button replies back to a decision."""
from __future__ import annotations

import hashlib
import hmac
import http.server
import json
import threading
import urllib.parse

import pytest
import yaml

from sentinel import Guardrails
from sentinel.edges import build_edges
from sentinel.wa_providers import GupshupEdge, InteraktEdge
from tests.conftest import job_event
from tests.test_rbac import make_directory


class _H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):  # noqa: N802
        n = int(self.headers.get("Content-Length") or 0)
        self.server.got.append((self.path, dict(self.headers), self.rfile.read(n)))
        data = json.dumps({"status": "submitted", "messageId": "m-1", "result": True, "id": "i-1"}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *a):
        pass


@pytest.fixture
def capture():
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _H)
    srv.got = []
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv, f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


ENV = {"SENTINEL_SECRET_GUPSHUP_KEY": "gs-key", "SENTINEL_SECRET_GUPSHUP_INBOUND": "in-tok",
       "SENTINEL_SECRET_INTERAKT_KEY": "ik-base64", "SENTINEL_SECRET_INTERAKT_WEBHOOK": "whsec"}


@pytest.fixture
def eng(engine_factory, capture, monkeypatch):
    for k, v in ENV.items():
        monkeypatch.setenv(k, v)
    _, base = capture
    d = make_directory()
    d.people["ravi"].edges = ["wa_gupshup"]
    d.people["ravi"].contact["whatsapp"] = "+91 98450 12345"
    d.people["ravi"].language = "hi"
    d.people["asha"].edges = ["wa_interakt"]
    d.people["asha"].contact["whatsapp"] = "+91 98400 77777"
    e = engine_factory(directory=d, guardrails=Guardrails())
    from sentinel.rbac import AuthorityRule
    d.rules.append(AuthorityRule(role_id="ops_head", action="__configure__"))
    text = yaml.safe_dump({"edges": {
        "wa_gupshup": {"kind": "gupshup", "source": "919840011111", "app_name": "AcmeOps",
                       "api_key_env": "SENTINEL_SECRET_GUPSHUP_KEY", "inbound_token_env": "SENTINEL_SECRET_GUPSHUP_INBOUND",
                       "base_url": base},
        "wa_interakt": {"kind": "interakt", "api_key_env": "SENTINEL_SECRET_INTERAKT_KEY",
                        "signing_secret_env": "SENTINEL_SECRET_INTERAKT_WEBHOOK", "base_url": base,
                        "template": {"name": "sentinel_review", "language": "en", "languages": ["en", "ta"]}}}})
    cv, probs = e.save_config("connectors", text, author="hari")
    assert not [p for p in probs if p.severity == "error"], probs
    e.publish_config(cv.id, actor="hari")
    return e


def _review(eng, **kw):
    rv = eng.store.open_review_for(eng.ingest(job_event(**kw)).incident_id)
    eng.work("w")                                           # the worker delivers the cards
    return rv


def test_gupshup_card_and_reply(eng, capture):
    srv, _ = capture
    rv = _review(eng, error="AUTH", system="hr", ref="G1")
    card = eng.build_card(rv, "ravi")
    url, form = eng.overlay.edges["wa_gupshup"].message(card)
    assert url.endswith("/msg") and form["destination"] == "919845012345" and form["source"] == "919840011111"
    msg = json.loads(form["message"])
    assert msg["type"] == "quick_reply" and msg["options"][-1]["postbackText"].startswith(f"sentinel:{rv.id}:reject")
    assert msg["options"][-1]["title"].startswith("बंद करें")                # the reader's language
    path, headers, body = next(g for g in srv.got if g[0].endswith("/msg"))
    assert {k.lower(): v for k, v in headers.items()}["apikey"] == "gs-key"
    assert urllib.parse.parse_qs(body.decode())["src.name"] == ["AcmeOps"]

    from fastapi.testclient import TestClient

    from sentinel.api import create_app
    c = TestClient(create_app(eng, {}, console=False))
    sent = json.loads(urllib.parse.parse_qs(body.decode())["message"][0])
    code = sent["options"][-1]["postbackText"]
    reply = {"app": "AcmeOps", "type": "message", "payload": {
        "source": "919845012345", "type": "quick_reply", "payload": {"text": "Close", "postbackText": code},
        "sender": {"phone": "919845012345"}}}
    assert c.post("/v1/wa/wa_gupshup", json=reply).status_code == 401              # no token
    assert c.post("/v1/wa/wa_gupshup?token=wrong", json=reply).status_code == 401
    r = c.post("/v1/wa/wa_gupshup?token=in-tok", json=reply)
    assert r.json() == {"answers": 1, "received": 1}
    assert eng.store.get_disposition(rv.incident_id).actor.endswith("ravi")


def test_interakt_template_and_signed_reply(eng, capture):
    srv, _ = capture
    rv = _review(eng, error="AUTH", system="billing", ref="I9")
    card = eng.build_card(rv, "asha")
    m = eng.overlay.edges["wa_interakt"].message(card)
    assert m["countryCode"] == "+91" and m["phoneNumber"] == "9840077777" and m["type"] == "Template"
    assert m["template"]["bodyValues"][0] == card.title and m["template"]["buttonValues"]["0"][0].startswith(
        f"sentinel:{rv.id}:")
    path, headers, raw = next(g for g in srv.got if g[0].endswith("/message/"))
    assert headers["Authorization"] == "Basic ik-base64"
    m = json.loads(raw)

    from fastapi.testclient import TestClient

    from sentinel.api import create_app
    c = TestClient(create_app(eng, {}, console=False))
    payload = m["template"]["buttonValues"][str(len(m["template"]["buttonValues"]) - 1)][0]
    body = json.dumps({"type": "message_received", "data": {
        "customer": {"country_code": "+91", "phone_number": "9840077777"},
        "message": {"message": "Close", "message_content_type": "InteractiveButtonReply",
                    "button_payload": payload}}}).encode()
    sig = hmac.new(b"whsec", body, hashlib.sha256).hexdigest()
    assert c.post("/v1/wa/wa_interakt", content=body, headers={"Interakt-Signature": "bad"}).status_code == 401
    r = c.post("/v1/wa/wa_interakt", content=body, headers={"Interakt-Signature": f"sha256={sig}"})
    assert r.json()["answers"] == 1 and eng.store.get_disposition(rv.incident_id).actor.endswith("asha")
    assert c.post("/v1/wa/nope", json={}).status_code == 404


def test_configuration_needs(monkeypatch):
    monkeypatch.setenv("SENTINEL_SECRET_GUPSHUP_KEY", "k")
    with pytest.raises(ValueError, match="source"):
        build_edges({"g": {"kind": "gupshup", "api_key_env": "SENTINEL_SECRET_GUPSHUP_KEY"}})
    monkeypatch.setenv("SENTINEL_SECRET_INTERAKT_KEY", "k")
    with pytest.raises(ValueError, match="template.name"):
        build_edges({"i": {"kind": "interakt", "api_key_env": "SENTINEL_SECRET_INTERAKT_KEY"}})
    waiting = build_edges({"g": {"kind": "gupshup", "source": "91", "app_name": "a",
                                 "api_key_env": "SENTINEL_SECRET_GUPSHUP_MISSING"}})
    assert waiting["g"].missing == "SENTINEL_SECRET_GUPSHUP_MISSING"
    assert isinstance(GupshupEdge("g", "91", "a", "k"), GupshupEdge) and InteraktEdge
