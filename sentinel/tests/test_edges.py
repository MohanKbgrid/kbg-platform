# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""Edges: review cards to the right people on the right channel, signed webhooks, answers back through RBAC."""
from __future__ import annotations

import http.server
import json
import threading
import time

import pytest

from sentinel import (AuthorizationError, Decision, DecisionKind, Guardrails, IncidentState as S, MemoryEdge,
                      WebhookEdge)
from sentinel.edges import sign, verify
from tests.conftest import job_event
from tests.test_rbac import make_directory


@pytest.fixture
def edged(engine_factory, overlay):
    ask_ai, whatsapp = MemoryEdge("ask_ai"), MemoryEdge("whatsapp")
    overlay.edges.update({"ask_ai": ask_ai, "whatsapp": whatsapp})
    overlay.default_edges = ["ask_ai"]
    d = make_directory()
    d.people["ravi"].edges = ["whatsapp"]
    eng = engine_factory(ov=overlay, directory=d, guardrails=Guardrails(), card_link_base="https://ops.example/")
    return eng, ask_ai, whatsapp


def test_cards_go_to_each_person_in_scope_on_their_channel(edged):
    eng, ask_ai, whatsapp = edged
    eng.ingest(job_event(error="AUTH", system="billing"))      # ops role: asha (billing scope), ravi
    assert eng.work("w")["done"] >= 2
    assert [c.recipient_id for c in ask_ai.cards] == ["asha"]
    assert [c.recipient_id for c in whatsapp.cards] == ["ravi"]
    card = whatsapp.cards[0]
    assert card.link.startswith("https://ops.example/reviews/rev_") and card.answer_options == ["modify", "reject"]
    assert {a["action"] for a in card.allowed_actions} == {"retry", "cancel", "notify"}
    assert {a["risk"] for a in card.allowed_actions} == {"irreversible"}
    assert len(eng.store.deliveries(card.review_id)) == 2


def test_out_of_scope_people_get_nothing(edged):
    eng, ask_ai, whatsapp = edged
    eng.ingest(job_event(error="AUTH", system="hr"))
    eng.work("w")
    assert ask_ai.cards == [] and [c.recipient_id for c in whatsapp.cards] == ["ravi"]


def test_answer_from_edge_decides_with_rbac(edged, backend):
    eng, _, whatsapp = edged
    r = eng.ingest(job_event(error="AUTH"))
    eng.work("w")
    rid, tok = whatsapp.cards[0].review_id, whatsapp.cards[0].answer_token
    with pytest.raises(AuthorizationError, match="answer token"):
        eng.answer("whatsapp", rid, "ravi", {"kind": "modify", "action": "retry", "params": {"ref": "J1"}})
    with pytest.raises(AuthorizationError, match="no card"):            # only someone the card went to
        eng.answer("whatsapp", rid, "hari", {"kind": "modify", "action": "retry", "params": {"ref": "J1"}},
                   answer_token=tok)
    inc = eng.answer("whatsapp", rid, "ravi", {"kind": "modify", "action": "retry", "params": {"ref": "J1"}},
                     answer_token=tok)
    assert inc.state is S.DISPOSITIONED and backend.calls == [("retry", {"ref": "J1"})]
    assert [d.status for d in eng.store.deliveries(rid) if d.person_id == "ravi"] == ["answered"]
    assert r.incident_id == inc.id


def test_a_proposal_from_an_edge_goes_to_the_approver(edged, backend):
    eng, _, whatsapp = edged
    r = eng.ingest(job_event(error="AUTH"))
    eng.work("w")
    rid, tok = whatsapp.cards[0].review_id, whatsapp.cards[0].answer_token
    inc = eng.answer("whatsapp", rid, "ravi", {"kind": "modify", "action": "cancel", "params": {"ref": "J1"}},
                     answer_token=tok)                       # ravi may only propose a cancel
    assert inc.state is S.AWAITING_HUMAN and backend.calls == []
    assert eng.store.open_review_for(r.incident_id).assignee_role == "lead"


def test_escalation_delivers_to_the_next_role(edged, clock):
    eng, ask_ai, _ = edged
    eng.ingest(job_event(error="AUTH", system="hr"))
    eng.work("w")
    clock.advance(minutes=241)
    eng.sweep()
    eng.work("w")
    assert [c.recipient_id for c in ask_ai.cards] == ["lata"] and ask_ai.cards[0].escalation_level == 1


def test_closed_reviews_are_not_delivered(edged):
    eng, ask_ai, whatsapp = edged
    r = eng.ingest(job_event(error="AUTH", system="hr"))
    rev = eng.store.open_review_for(r.incident_id)
    eng.decide(rev.id, Decision(kind=DecisionKind.REJECT, actor="ravi", disposition_code="no_action"))
    eng.work("w")
    assert whatsapp.cards == [] and ask_ai.cards == []


def test_unknown_edge_reference_refused(engine_factory, overlay):
    overlay.role_edges = {"ops": ["telegram"]}
    from sentinel import EngineError
    with pytest.raises(EngineError, match="telegram"):
        engine_factory(ov=overlay)

# ------------------------------------------------------------------ signing and webhooks

def test_signature_verification():
    body = b'{"x":1}'
    ts, sig = sign("s" * 32, body, ts=1_000_000)
    assert verify("s" * 32, body, ts, sig, now=1_000_100)
    assert not verify("s" * 32, b'{"x":2}', ts, sig, now=1_000_100)        # tampered
    assert not verify("t" * 32, body, ts, sig, now=1_000_100)              # wrong secret
    assert not verify("s" * 32, body, ts, sig, now=1_000_000 + 301)        # replayed too late
    assert not verify("s" * 32, body, "abc", sig)
    with pytest.raises(ValueError):
        WebhookEdge("w", "http://x", secret="short")


class _Hook(http.server.BaseHTTPRequestHandler):
    received: list = []
    fail_first = 0

    def do_POST(self):  # noqa: N802
        body = self.rfile.read(int(self.headers["Content-Length"]))
        if _Hook.fail_first > 0:
            _Hook.fail_first -= 1
            self.send_response(503)
            self.end_headers()
            return
        _Hook.received.append((body, self.headers["X-Sentinel-Timestamp"], self.headers["X-Sentinel-Signature"]))
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"ref": "gw-123"}).encode())

    def log_message(self, *a):
        pass


@pytest.fixture
def hook_server():
    _Hook.received, _Hook.fail_first = [], 0
    srv = http.server.HTTPServer(("127.0.0.1", 0), _Hook)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{srv.server_address[1]}/cards"
    srv.shutdown()


def test_webhook_edge_signs_and_retries(engine_factory, overlay, hook_server, clock):
    secret = "k" * 32
    overlay.edges["gateway"] = WebhookEdge("gateway", hook_server, secret, timeout_s=5)
    overlay.default_edges = ["gateway"]
    eng = engine_factory(ov=overlay, guardrails=Guardrails(), retry_base_s=1)
    _Hook.fail_first = 1
    r = eng.ingest(job_event(error="AUTH"))
    assert eng.work("w")["retry"] == 1                      # gateway returned 503
    clock.advance(seconds=5)
    assert eng.work("w")["done"] == 1
    body, ts, sig = _Hook.received[0]
    assert verify(secret, body, ts, sig, now=time.time())
    card = json.loads(body)
    assert card["incident_id"] == r.incident_id
    assert eng.store.deliveries(card["review_id"])[0].ref == "gw-123"
