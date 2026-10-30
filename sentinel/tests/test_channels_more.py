# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""D3 / B5: pluggable edge kinds; Slack (two-way), Teams and email edges."""
from __future__ import annotations

import hashlib
import hmac
import http.server
import json
import threading
import time
import urllib.parse

import pytest
import yaml

from sentinel import Guardrails
from sentinel.channels import EmailEdge
from sentinel.edges import EDGE_KINDS, build_edges, register_edge_kind
from sentinel.rbac import AuthorityRule
from tests.conftest import job_event
from tests.test_rbac import make_directory
from datetime import UTC


class Fake(http.server.BaseHTTPRequestHandler):
    def do_POST(self):  # noqa: N802
        body = self.rfile.read(int(self.headers["Content-Length"]))
        self.server.got.append((self.path, dict(self.headers), json.loads(body)))
        out = {"ok": True, "ts": "1700000000.1"} if "chat.postMessage" in self.path else {}
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(out).encode())

    def log_message(self, *a):
        pass


@pytest.fixture
def fake():
    srv = http.server.HTTPServer(("127.0.0.1", 0), Fake)
    srv.got = []
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv, f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


@pytest.fixture
def eng(engine_factory, fake, monkeypatch):
    monkeypatch.setenv("SENTINEL_SECRET_SLACK_BOT", "xoxb-1")
    monkeypatch.setenv("SENTINEL_SECRET_SLACK_SIGNING", "signing")
    monkeypatch.setenv("SENTINEL_SECRET_TEAMS_HOOK", fake[1] + "/teams")
    d = make_directory()
    d.people["ravi"].edges = ["slack"]
    d.people["ravi"].contact["slack"] = "U123"
    d.people["asha"].edges = ["teams"]
    d.rules.append(AuthorityRule(role_id="ops_head", action="__configure__"))
    e = engine_factory(directory=d, guardrails=Guardrails(), card_link_base="https://ops.example")
    text = yaml.safe_dump({"edges": {
        "slack": {"kind": "slack", "bot_token_env": "SENTINEL_SECRET_SLACK_BOT",
                  "signing_secret_env": "SENTINEL_SECRET_SLACK_SIGNING", "base_url": fake[1]},
        "teams": {"kind": "teams", "webhook_url_env": "SENTINEL_SECRET_TEAMS_HOOK",
                  "console_url": "https://ops.example"}}})
    e.publish_config(e.save_config("connectors", text, "hari")[0].id, actor="hari")
    return e


def test_slack_and_teams_cards_and_a_slack_answer(eng, fake, backend):
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from sentinel.api import create_app
    srv, _ = fake
    r = eng.ingest(job_event(error="TIMEOUT", ref="SL1", key="sl1"))        # needs a person: irreversible retry
    rid = eng.store.open_review_for(r.incident_id).id
    eng.work("w")
    slack = [g for g in srv.got if "chat.postMessage" in g[0]]
    teams = [g for g in srv.got if g[0] == "/teams"]
    assert slack and slack[0][1]["Authorization"] == "Bearer xoxb-1" and slack[0][2]["channel"] == "U123"
    buttons = slack[0][2]["blocks"][-1]["elements"]
    assert buttons[0]["value"] == f"sentinel:{rid}:approve"
    assert teams and teams[0][2]["attachments"][0]["content"]["actions"][0]["url"].split("/")[2] == "ops.example"
    c = TestClient(create_app(eng, {}, config_sync_s=0))
    payload = {"type": "block_actions", "user": {"id": "U123"}, "actions": [{"value": f"sentinel:{rid}:approve"}]}
    body = urllib.parse.urlencode({"payload": json.dumps(payload)}).encode()
    ts = str(int(time.time()))
    sig = "v0=" + hmac.new(b"signing", b"v0:" + ts.encode() + b":" + body, hashlib.sha256).hexdigest()
    bad = c.post("/v1/slack/slack", content=body, headers={"X-Slack-Request-Timestamp": ts,
                                                           "X-Slack-Signature": "v0=nope"})
    assert bad.status_code == 401
    stranger = urllib.parse.urlencode({"payload": json.dumps({**payload, "user": {"id": "U999"}})}).encode()
    s2 = "v0=" + hmac.new(b"signing", b"v0:" + ts.encode() + b":" + stranger, hashlib.sha256).hexdigest()
    assert c.post("/v1/slack/slack", content=stranger, headers={"X-Slack-Request-Timestamp": ts,
                                                                "X-Slack-Signature": s2}).json()["answers"] == 0
    ok = c.post("/v1/slack/slack", content=body, headers={"X-Slack-Request-Timestamp": ts, "X-Slack-Signature": sig,
                                                          "Content-Type": "application/x-www-form-urlencoded"})
    assert ok.json()["answers"] == 1 and backend.calls == [("retry", {"ref": "SL1"})]
    old = str(int(time.time()) - 3600)
    s3 = "v0=" + hmac.new(b"signing", b"v0:" + old.encode() + b":" + body, hashlib.sha256).hexdigest()
    assert c.post("/v1/slack/slack", content=body, headers={"X-Slack-Request-Timestamp": old,
                                                            "X-Slack-Signature": s3}).status_code == 401


def test_email_edge_with_a_fake_smtp_server():
    sent = []

    class SMTP:
        def __init__(self, host, port, timeout):
            self.host = host

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def starttls(self):
            sent.append("tls")

        def login(self, u, p):
            sent.append(("login", u))

        def send_message(self, m):
            sent.append(m)
    from datetime import datetime

    from sentinel.edges import ReviewCard
    e = EmailEdge("mail", "127.0.0.1", "sentinel@ops.example", username="u", password="p",
                  console_url="https://ops.example", smtp_factory=SMTP)
    card = ReviewCard(review_id="rev_1", incident_id="inc_1", pattern_id="p", title="Order stuck", severity="high",
                      reason="needs a person", facts={"order": "A1"}, assignee_role="ops", escalation_level=0,
                      due_at=datetime(2026, 10, 11, tzinfo=UTC), recipient_contact={"email": "ravi@x.in"})
    e.deliver(card)
    msg = sent[-1]
    assert sent[0] == "tls" and msg["To"] == "ravi@x.in" and "Order stuck" in msg["Subject"]
    assert "https://ops.example/console#/case?id=inc_1" in msg.get_content()
    from sentinel.edges import EdgeError
    with pytest.raises(EdgeError, match="no email"):
        e.deliver(card.model_copy(update={"recipient_contact": {}}))
    with pytest.raises(EdgeError):
        EmailEdge("m", "169.254.169.254", "a@b", smtp_factory=SMTP).deliver(card)      # egress refuses


def test_edge_kinds_are_pluggable():
    build_edges({})                                                              # loads the built-ins
    assert {"webhook", "a2ui", "whatsapp", "slack", "teams", "email"} <= set(EDGE_KINDS)

    class Pager:
        kind = "pager"

        def __init__(self, name, number):
            self.name, self.number = name, number

        def deliver(self, card):
            return "p1"
    register_edge_kind("pager", {"number"}, lambda n, c, secret: Pager(n, c["number"]))
    try:
        e = build_edges({"oncall": {"kind": "pager", "number": "123"}})["oncall"]
        assert e.number == "123"
        with pytest.raises(ValueError, match="unknown settings"):
            build_edges({"oncall": {"kind": "pager", "nope": 1}})
        with pytest.raises(ValueError, match="kind must be one of"):
            build_edges({"x": {"kind": "carrier-pigeon"}})
    finally:
        EDGE_KINDS.pop("pager", None)
