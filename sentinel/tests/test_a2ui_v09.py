# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""A2UI v0.9 / v0.9.1 beside v0.8 on the A2UI edge: rendering, the action round trip, refusals.

Wire format taken from the A2UI project's specification/v0_9_1 (server_to_client.json, client_to_server.json and
the basic catalogue); v0.8 stays the default and keeps working."""
from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest
import yaml
from fastapi.testclient import TestClient

from sentinel import Guardrails
from sentinel.api import create_app
from sentinel.edges import (A2UI_CATALOG_V09, A2UIEdge, ReviewCard, a2ui_messages, a2ui_messages_v09,
                            answer_from_user_action, build_edges, render_a2ui, sign, user_action_from_message)
from sentinel.rbac import AuthorityRule
from tests.conftest import job_event
from tests.test_channels import capture  # noqa: F401 - the capture server fixture
from tests.test_rbac import make_directory

SECRET = "a" * 32
OTHER = "b" * 32


def _card() -> ReviewCard:
    return ReviewCard(review_id="rev_1", incident_id="inc_1", pattern_id="p", title="Order stuck", severity="high",
                      reason="no stock", facts={"order": "SH-1", "source": "x"}, assignee_role="ops",
                      escalation_level=0, due_at=datetime.now(UTC),
                      proposal_steps=[{"action": "hold", "params": {"ref": "SH-1"}}], proposal_confidence=0.9,
                      disposition_codes=["resolved", "no_action"], link="https://ops/reviews/rev_1",
                      answer_token="tok123")


def _make_eng(engine_factory, capture, monkeypatch, version):  # noqa: F811
    monkeypatch.setenv("SENTINEL_SECRET_ASK_AI", SECRET)
    monkeypatch.setenv("SENTINEL_SECRET_OTHER", OTHER)
    _, base = capture
    d = make_directory()
    d.people["asha"].edges = ["ask_ai"]
    e = engine_factory(directory=d, guardrails=Guardrails(), card_link_base="https://ops.example")
    d.rules.append(AuthorityRule(role_id="ops_head", action="__configure__"))
    ask = {"kind": "a2ui", "url": f"{base}/cards", "secret_env": "SENTINEL_SECRET_ASK_AI"}
    if version:
        ask["a2ui_version"] = version
    text = yaml.safe_dump({"edges": {"ask_ai": ask,
                                     "other": {"kind": "a2ui", "url": f"{base}/other",
                                               "secret_env": "SENTINEL_SECRET_OTHER"}}})
    cv, probs = e.save_config("connectors", text, author="hari")
    assert not [p for p in probs if p.severity == "error"], probs
    e.publish_config(cv.id, actor="hari")
    return e


@pytest.fixture
def eng9(engine_factory, capture, monkeypatch):  # noqa: F811
    return _make_eng(engine_factory, capture, monkeypatch, "v0.9.1")


@pytest.fixture
def eng8(engine_factory, capture, monkeypatch):  # noqa: F811
    return _make_eng(engine_factory, capture, monkeypatch, None)


def _post(c, edge, secret, payload):
    body = json.dumps(payload).encode()
    ts, s = sign(secret, body)
    return c.post(f"/v1/edges/{edge}/a2ui", content=body, headers={"X-Sentinel-Timestamp": ts,
                                                                    "X-Sentinel-Signature": s})


def _delivered(srv, review_id, path="/cards"):
    return [b for p, _, b in srv.got if p == path and b["card"]["review_id"] == review_id][-1]


def _action_v09(sent, button):
    comps = {c["id"]: c for c in sent["a2ui"][1]["updateComponents"]["components"]}
    ev = comps[button]["action"]["event"]
    sid = sent["a2ui"][0]["createSurface"]["surfaceId"]
    return {"version": "v0.9.1", "action": {"name": ev["name"], "surfaceId": sid, "sourceComponentId": button,
                                           "timestamp": "2026-10-30T10:00:00Z", "context": ev["context"]}}


# ------------------------------------------------------------------------------------------------ rendering
def test_v09_render_shape():
    for ver in ("v0.9", "v0.9.1"):
        msgs = a2ui_messages_v09(_card(), ver)
        assert [list(m) for m in msgs] == [["version", "createSurface"], ["version", "updateComponents"]]
        assert all(m["version"] == ver for m in msgs)
        assert msgs[0]["createSurface"] == {"surfaceId": "review-rev_1", "catalogId": A2UI_CATALOG_V09}
        assert msgs[1]["updateComponents"]["surfaceId"] == "review-rev_1"
        comps = {c["id"]: c for c in msgs[1]["updateComponents"]["components"]}
        assert comps["root"]["component"] == "Card" and comps["root"]["child"] == "col"
        for c in comps.values():                      # flat components; every reference is a defined id
            assert isinstance(c["component"], str)
            refs = [c["child"]] if "child" in c else c.get("children", [])
            assert all(r in comps for r in refs), c
        assert comps["title"]["text"] == "Order stuck" and comps["title"]["variant"] == "h3"   # plain string
        ev = comps["approve"]["action"]["event"]
        assert ev["name"] == "sentinel.answer"
        assert ev["context"] == {"review_id": "rev_1", "decision": "approve", "answer_token": "tok123"}
        assert comps["close0"]["action"]["event"]["context"]["disposition_code"] == "no_action"


def test_version_negotiation_and_unknown_version_refused():
    c = _card()
    assert render_a2ui(c) == a2ui_messages(c)                       # default is v0.8, unchanged
    assert render_a2ui(c, "v0.8") == a2ui_messages(c)
    assert "createSurface" in render_a2ui(c, "v0.9")[0]
    with pytest.raises(ValueError, match="unsupported A2UI version 'v0.7'"):
        render_a2ui(c, "v0.7")
    with pytest.raises(ValueError, match="edge x: unsupported A2UI version 'v1.0'"):
        A2UIEdge("x", "https://a", SECRET, a2ui_version="v1.0")
    with pytest.raises(ValueError, match="unsupported A2UI version"):
        build_edges({"x": {"kind": "a2ui", "url": "https://a", "secret_env": "SENTINEL_SECRET_X",
                           "a2ui_version": "0.9"}}, env={"SENTINEL_SECRET_X": SECRET})


def test_default_edge_stays_v08_and_v09_edge_renders_v09(eng8, eng9, capture):  # noqa: F811
    srv, _ = capture
    for eng, ver in ((eng8, None), (eng9, "v0.9.1")):
        r = eng.ingest(job_event(error="AUTH", system="billing", ref=f"J-{ver}"))
        eng.work("w")
        rev = eng.store.open_review_for(r.incident_id)
        sent = _delivered(srv, rev.id)
        if ver is None:
            assert "surfaceUpdate" in sent["a2ui"][0] and "a2ui_version" not in sent
        else:
            assert sent["a2ui_version"] == "v0.9.1" and "createSurface" in sent["a2ui"][0]


def test_user_action_from_message_both_versions():
    v8 = {"userAction": {"name": "sentinel.answer", "context": {"review_id": "r", "decision": "approve"}}}
    v9 = {"version": "v0.9", "action": {"name": "sentinel.answer", "surfaceId": "review-r", "sourceComponentId": "b",
                                        "timestamp": "t", "context": {"review_id": "r", "decision": "approve"}}}
    for msg in (v8, v9):
        assert answer_from_user_action(user_action_from_message(msg))[0] == "r"
    for bad, why in (({"version": "v0.7", **v8}, "unsupported A2UI version"),
                     ({"version": "v0.8", "action": v9["action"]}, "must declare version v0.9"),
                     ({"version": "v0.9", **v8}, "sends 'action'"),
                     ({"version": "v0.9", "action": {**v9["action"], "surfaceId": "review-other"}}, "surface"),
                     ({"version": "v0.9", "action": {"name": "x"}}, "missing"),
                     ({"nothing": 1}, "no A2UI action")):
        with pytest.raises(ValueError, match=why):
            user_action_from_message(bad)


# ------------------------------------------------------------------------------------------------ round trips
def test_v09_action_round_trip(eng9, capture):  # noqa: F811
    srv, _ = capture
    c = TestClient(create_app(eng9, {}, config_sync_s=0, console=False))
    r = eng9.ingest(job_event(error="AUTH", system="billing", ref="J9"))
    eng9.work("w")
    rev = eng9.store.open_review_for(r.incident_id)
    msg = {"person_id": "asha", **_action_v09(_delivered(srv, rev.id), "close1")}
    res = _post(c, "ask_ai", SECRET, msg)
    assert res.status_code == 200, res.text
    assert eng9.store.get_disposition(r.incident_id).code == "false_positive"
    assert _post(c, "ask_ai", SECRET, msg).status_code in (403, 409)         # single use: not twice


def test_v08_action_still_accepted_on_a_v09_edge(eng9, capture):  # noqa: F811
    srv, _ = capture
    c = TestClient(create_app(eng9, {}, config_sync_s=0, console=False))
    r = eng9.ingest(job_event(error="AUTH", system="billing", ref="J8"))
    eng9.work("w")
    rev = eng9.store.open_review_for(r.incident_id)
    ctx = _action_v09(_delivered(srv, rev.id), "close1")["action"]["context"]
    msg = {"person_id": "asha", "userAction": {"name": "sentinel.answer", "surfaceId": f"review-{rev.id}",
                                               "sourceComponentId": "close1", "timestamp": "t", "context": ctx}}
    assert _post(c, "ask_ai", SECRET, msg).status_code == 200
    assert eng9.store.get_disposition(r.incident_id).code == "false_positive"


def test_v09_action_from_another_person_or_edge_refused(eng9, capture):  # noqa: F811
    srv, _ = capture
    c = TestClient(create_app(eng9, {}, config_sync_s=0, console=False))
    r = eng9.ingest(job_event(error="AUTH", system="billing", ref="JX"))
    eng9.work("w")
    rev = eng9.store.open_review_for(r.incident_id)
    act = _action_v09(_delivered(srv, rev.id), "close1")
    # another person (ravi was never sent this card on this edge), even holding the right token
    assert _post(c, "ask_ai", SECRET, {"person_id": "ravi", **act}).status_code == 403
    # a person who does not exist
    assert _post(c, "ask_ai", SECRET, {"person_id": "nobody", **act}).status_code == 403
    # another tenant / edge: signed with a different secret, or sent to an edge the card never went out on
    assert _post(c, "ask_ai", OTHER, {"person_id": "asha", **act}).status_code == 401
    assert _post(c, "other", OTHER, {"person_id": "asha", **act}).status_code == 403
    # a surface that is not the review the context names
    forged = json.loads(json.dumps(act))
    forged["action"]["surfaceId"] = "review-rev_somebody_else"
    assert _post(c, "ask_ai", SECRET, {"person_id": "asha", **forged}).status_code == 422
    assert eng9.store.get_incident(r.incident_id).state.value != "dispositioned"        # none of it took effect


def test_unknown_version_refused_clearly_over_http(eng9, capture):  # noqa: F811
    srv, _ = capture
    c = TestClient(create_app(eng9, {}, config_sync_s=0, console=False))
    r = eng9.ingest(job_event(error="AUTH", system="billing", ref="JV"))
    eng9.work("w")
    rev = eng9.store.open_review_for(r.incident_id)
    act = _action_v09(_delivered(srv, rev.id), "close1")
    act["version"] = "v0.4"
    res = _post(c, "ask_ai", SECRET, {"person_id": "asha", **act})
    assert res.status_code == 422 and "unsupported A2UI version 'v0.4'" in res.json()["detail"]
