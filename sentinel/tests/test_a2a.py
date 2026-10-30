# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""A2A 1.0 server surface: Agent Card, SendMessage / GetTask / ListTasks over JSON-RPC, auth, scope, caps, audit,
and the rule that an agent can never approve."""
from __future__ import annotations

import json

import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from sentinel import Guardrails  # noqa: E402
from sentinel.api import Principal, create_app, token_hash  # noqa: E402
from sentinel.org import APPROVE, Agent, authorise  # noqa: E402
from sentinel.rbac import AgentPolicy  # noqa: E402
from tests.test_rbac import make_directory  # noqa: E402

TOKENS = {"agent-a": Principal("service", "framework-a"), "agent-b": Principal("service", "framework-b"),
          "ravi-token": Principal("person", "ravi"), "lata-token": Principal("person", "lata")}
V = {"A2A-Version": "1.0"}


def h(token, **extra):
    return {"Authorization": f"Bearer {token}", **extra}


@pytest.fixture
def a2a(engine_factory, overlay):
    eng = engine_factory(ov=overlay, directory=make_directory(), guardrails=Guardrails())
    app = create_app(eng, {token_hash(k): v for k, v in TOKENS.items()}, ingest_per_minute=1000, a2a=True,
                     config_sync_s=0, console=False)
    return eng, TestClient(app)


def rpc(c, token, method, params=None, rid=1, headers=V, **kw):
    body = {"jsonrpc": "2.0", "id": rid, "method": method}
    if params is not None:
        body["params"] = params
    return c.post("/a2a", json=body, headers={**h(token), **headers}, **kw)


def message(mid="m1", **data):
    d = {"type": "job.failed", "payload": {"system": "billing", "error_code": "AUTH", "ref": "J1"}, **data}
    return {"message": {"messageId": mid, "role": "ROLE_USER", "parts": [{"data": d, "mediaType": "application/json"}]}}


def send(c, token="agent-a", mid="m1", **data):
    r = rpc(c, token, "SendMessage", message(mid, **data))
    assert r.status_code == 200, r.text
    return r.json()


# ------------------------------------------------------------------------------------------------ switched off
def test_not_mounted_unless_asked(engine_factory, overlay):
    eng = engine_factory(ov=overlay)
    c = TestClient(create_app(eng, {token_hash("t"): Principal("service", "s")}, config_sync_s=0, console=False))
    assert c.get("/.well-known/agent-card.json").status_code == 404
    assert c.post("/a2a", json={}, headers=h("t")).status_code in (404, 405)


# ------------------------------------------------------------------------------------------------ Agent Card
def test_agent_card_follows_the_1_0_shape(a2a):
    _, c = a2a
    r = c.get("/.well-known/agent-card.json")                       # public: no token
    assert r.status_code == 200 and r.headers["etag"] and "max-age" in r.headers["cache-control"]
    card = r.json()
    for k in ("name", "description", "supportedInterfaces", "version", "capabilities", "defaultInputModes",
              "defaultOutputModes", "skills"):
        assert k in card, k
    itf = card["supportedInterfaces"][0]
    assert itf["protocolBinding"] == "JSONRPC" and itf["protocolVersion"] == "1.0" and itf["url"].endswith("/a2a")
    assert card["capabilities"] == {"streaming": False, "pushNotifications": False, "extendedAgentCard": False}
    assert card["securitySchemes"]["bearer"]["httpAuthSecurityScheme"]["scheme"] == "Bearer"
    assert {s["id"] for s in card["skills"]} == {"submit_case", "get_case"}
    for s in card["skills"]:
        assert s["name"] and s["description"] and s["tags"]
    assert c.get("/.well-known/agent-card.json", headers={"If-None-Match": r.headers["etag"]}).status_code == 304


# ------------------------------------------------------------------------------------------------ hand in / back
def test_hand_in_then_a_person_decides_and_it_comes_back(a2a, backend):
    eng, c = a2a
    out = send(c)
    task = out["result"]["task"]
    assert task["status"]["state"] == "TASK_STATE_WORKING" or task["status"]["state"] == "TASK_STATE_SUBMITTED"
    tid = task["id"]
    assert tid == eng.store.get_incident(tid).id and task["contextId"].startswith("ctx_")
    ev = eng.store.get_event(eng.store.event_ids(tid)[0])
    assert ev.source == "a2a:framework-a" and ev.idempotency_key == "m1" and ev.tenant == "default"
    got = rpc(c, "agent-a", "GetTask", {"id": tid}, rid="x").json()
    assert got["id"] == "x" and got["result"]["id"] == tid and "artifacts" not in got["result"]
    # a person works the review in Sentinel; the agent then takes the decision back
    cards = c.get("/v1/reviews", headers=h("ravi-token")).json()
    rid = cards[0]["review_id"]
    fwd = c.post(f"/v1/reviews/{rid}/decision", headers=h("ravi-token"),
                 json={"kind": "modify", "action": "cancel", "params": {"ref": "J1"}})
    rid2 = eng.store.open_review_for(fwd.json()["incident_id"]).id
    assert c.post(f"/v1/reviews/{rid2}/decision", headers=h("lata-token"), json={"kind": "approve"}).status_code == 200
    done = rpc(c, "agent-a", "GetTask", {"id": tid}).json()["result"]
    assert done["status"]["state"] == "TASK_STATE_COMPLETED"
    art = done["artifacts"][0]
    assert art["name"] == "decision" and art["parts"][0]["data"]["code"] == "resolved"
    assert art["parts"][0]["data"]["resolver"] == "human" and art["parts"][0]["data"]["reversed"] is False
    assert "actor" not in art["parts"][0]["data"]                   # no person's id goes to another system
    listed = rpc(c, "agent-a", "ListTasks", {"status": "TASK_STATE_COMPLETED"}).json()["result"]
    assert [t["id"] for t in listed["tasks"]] == [tid] and listed["totalSize"] == 1 and listed["nextPageToken"] == ""


def test_message_id_is_the_idempotency_key(a2a):
    eng, c = a2a
    a, b = send(c, mid="same"), send(c, mid="same")
    assert a["result"]["task"]["id"] == b["result"]["task"]["id"]
    assert a["result"]["task"]["contextId"] == b["result"]["task"]["contextId"]
    assert len(eng.store.incidents()) == 1
    kinds = [r["kind"] for r in eng.store.recent_audit(50)]
    assert kinds.count("a2a_task_submitted") == 1                   # the retry is not a second submission


def test_text_part_and_list_paging(a2a):
    _, c = a2a
    for i in range(3):
        r = rpc(c, "agent-a", "SendMessage", {"message": {
            "messageId": f"t{i}", "role": "ROLE_USER", "contextId": "ctx-fixed",
            "parts": [{"data": {"type": "job.failed", "payload": {"system": ["billing", "hr", "wms"][i],
                                                                    "error_code": "AUTH", "ref": f"R{i}"}}},
                                                  {"text": "please look"}]}})
        assert "task" in r.json()["result"]
    page1 = rpc(c, "agent-a", "ListTasks", {"pageSize": 2, "contextId": "ctx-fixed"}).json()["result"]
    assert len(page1["tasks"]) == 2 and page1["totalSize"] == 3 and page1["nextPageToken"] == "2"
    page2 = rpc(c, "agent-a", "ListTasks", {"pageSize": 2, "pageToken": "2", "contextId": "ctx-fixed"}).json()["result"]
    assert len(page2["tasks"]) == 1 and page2["nextPageToken"] == ""
    assert rpc(c, "agent-a", "ListTasks", {"pageSize": 0}).json()["error"]["code"] == -32602
    assert rpc(c, "agent-a", "ListTasks", {"pageToken": "abc"}).json()["error"]["code"] == -32602


# ------------------------------------------------------------------------------------------------ auth and scope
def test_bearer_auth_same_as_the_events_endpoint(a2a):
    _, c = a2a
    body = {"jsonrpc": "2.0", "id": 1, "method": "GetTask", "params": {"id": "x"}}
    assert c.post("/a2a", json=body, headers=V).status_code == 401
    assert c.post("/a2a", json=body, headers={**h("nope"), **V}).status_code == 401
    assert c.post("/a2a", json=body, headers={**h("ravi-token"), **V}).status_code == 403   # people are not agents


def test_rate_limit_applies(engine_factory, overlay):
    eng = engine_factory(ov=overlay)
    c = TestClient(create_app(eng, {token_hash("t"): Principal("service", "s")}, ingest_per_minute=2, a2a=True,
                              config_sync_s=0, console=False))
    codes = [rpc(c, "t", "GetTask", {"id": "x"}).status_code for _ in range(4)]
    assert codes[:2] == [200, 200] and 429 in codes


def test_size_cap(a2a):
    eng, c = a2a
    big = {"message": {"messageId": "big", "role": "ROLE_USER", "parts": [
        {"data": {"type": "job.failed", "payload": {"blob": "x" * (5 * eng.max_event_bytes)}}}]}}
    assert rpc(c, "agent-a", "SendMessage", big).status_code == 413
    medium = {"message": {"messageId": "med", "role": "ROLE_USER", "parts": [
        {"data": {"type": "job.failed", "payload": {"blob": "x" * (eng.max_event_bytes + 10)}}}]}}
    err = rpc(c, "agent-a", "SendMessage", medium).json()["error"]       # over the event limit but under the body cap
    assert err["code"] == -32602 and "limit" in json.dumps(err)
    assert eng.store.incidents() == []


def test_tenant_and_caller_scope(a2a):
    eng, c = a2a
    tid = send(c, "agent-a")["result"]["task"]["id"]
    # another caller sees nothing: not found, and the same answer as for an id that never existed
    other = rpc(c, "agent-b", "GetTask", {"id": tid}).json()["error"]
    ghost = rpc(c, "agent-b", "GetTask", {"id": "inc_ghost"}).json()["error"]
    assert other["code"] == ghost["code"] == -32001 and other["message"] == ghost["message"]
    assert rpc(c, "agent-b", "ListTasks", {}).json()["result"]["tasks"] == []
    assert rpc(c, "agent-b", "CancelTask", {"id": tid}).json()["error"]["code"] == -32001
    # the tenant is the server's: a caller cannot name another one
    msg = message("m-t")
    msg["tenant"] = "other-tenant"
    assert rpc(c, "agent-a", "SendMessage", msg).json()["error"]["code"] == -32602
    assert rpc(c, "agent-a", "ListTasks", {"tenant": "other-tenant"}).json()["error"]["code"] == -32602
    # a task submitted under another tenant is invisible even to the same caller
    eng.store.audit(tid, "a2a_task_submitted", {"by": "framework-a", "tenant": "other", "message_id": "z",
                                                "context_id": "c", "event_id": "e", "status": "new"})
    assert len(rpc(c, "agent-a", "ListTasks", {}).json()["result"]["tasks"]) == 1


def test_caller_cannot_pick_the_source_or_extra_keys(a2a):
    eng, c = a2a
    err = rpc(c, "agent-a", "SendMessage", message("m-s", source="billing")).json()["error"]
    assert err["code"] == -32602 and eng.store.incidents() == []


# ------------------------------------------------------------------------------------------------ protocol
def test_versions_and_unsupported_methods(a2a):
    _, c = a2a
    for hdrs in ({}, {"A2A-Version": "0.3"}, {"A2A-Version": "2.0"}):
        e = rpc(c, "agent-a", "GetTask", {"id": "x"}, headers=hdrs).json()["error"]
        assert e["code"] == -32009 and e["data"][0]["reason"] == "VERSION_NOT_SUPPORTED"
        assert e["data"][0]["domain"] == "a2a-protocol.org"
    assert rpc(c, "agent-a", "GetTask", {"id": "x"}, headers={"A2A-Version": "1.0.1"}).json()["error"]["code"] == -32001
    r = c.post("/a2a?A2A-Version=1.0", json={"jsonrpc": "2.0", "id": 1, "method": "GetTask", "params": {"id": "x"}},
               headers=h("agent-a"))
    assert r.json()["error"]["code"] == -32001                       # version as a request parameter
    codes = {m: rpc(c, "agent-a", m, {}).json()["error"]["code"] for m in
             ("SendStreamingMessage", "SubscribeToTask", "CreateTaskPushNotificationConfig",
              "GetExtendedAgentCard", "Nonsense")}
    assert codes == {"SendStreamingMessage": -32004, "SubscribeToTask": -32004,
                     "CreateTaskPushNotificationConfig": -32003, "GetExtendedAgentCard": -32007, "Nonsense": -32601}


def test_malformed_requests(a2a):
    _, c = a2a
    assert c.post("/a2a", content=b"{nope", headers={**h("agent-a"), **V}).json()["error"]["code"] == -32700
    assert c.post("/a2a", json=[1], headers={**h("agent-a"), **V}).json()["error"]["code"] == -32600
    assert c.post("/a2a", json={"jsonrpc": "1.0", "id": 1, "method": "GetTask"},
                  headers={**h("agent-a"), **V}).json()["error"]["code"] == -32600
    assert rpc(c, "agent-a", "SendMessage", {"message": {"messageId": "m", "role": "ROLE_AGENT",
                                                         "parts": [{"text": "x"}]}}).json()["error"]["code"] == -32602
    assert rpc(c, "agent-a", "SendMessage", {"message": {"messageId": "m", "role": "ROLE_USER",
                                                         "parts": []}}).json()["error"]["code"] == -32602
    e = rpc(c, "agent-a", "SendMessage", {"message": {"messageId": "m", "role": "ROLE_USER",
                                                      "parts": [{"url": "https://x"}]}}).json()["error"]
    assert e["code"] == -32005                                       # files and urls are not accepted


# ------------------------------------------------------------------------------------------------ audit
def test_refusals_and_submissions_are_audited(a2a):
    eng, c = a2a
    tid = send(c)["result"]["task"]["id"]
    rpc(c, "agent-a", "CancelTask", {"id": tid})
    rpc(c, "agent-a", "SendStreamingMessage", {})
    log = eng.store.recent_audit(50, ["a2a_task_submitted", "a2a_refused"])
    sub = next(r for r in log if r["kind"] == "a2a_task_submitted")
    assert sub["incident_id"] == tid and sub["data"]["by"] == "framework-a" and sub["data"]["tenant"] == "default"
    refused = [r["data"]["method"] for r in log if r["kind"] == "a2a_refused"]
    assert "CancelTask" in refused and "SendStreamingMessage" in refused


# ------------------------------------------------------------------------------------------------ never approves
def test_an_agent_can_never_approve(a2a, monkeypatch):
    eng, c = a2a
    tid = send(c)["result"]["task"]["id"]
    # 1. no A2A method reaches a decision, an answer, a promotion, a bulk action or a reversal
    def boom(*a, **k):
        raise AssertionError("an A2A call reached a decision path")
    for name in ("decide", "answer", "decide_many", "approve_promotion", "reject_promotion", "reverse", "set_route"):
        monkeypatch.setattr(eng, name, boom)
    attempts = [("SendMessage", {"message": {"messageId": "ap1", "role": "ROLE_USER", "taskId": tid,
                                             "parts": [{"data": {"decision": "approve"}}]}}),
                ("SendMessage", {"message": {"messageId": "ap2", "role": "ROLE_USER", "referenceTaskIds": [tid],
                                             "parts": [{"text": "approve it"}]}}),
                ("CancelTask", {"id": tid}), ("GetTask", {"id": tid}), ("ListTasks", {})]
    for m, p in attempts:
        rpc(c, "agent-a", m, p)
    assert eng.store.get_disposition(tid) is None
    assert rpc(c, "agent-a", "SendMessage", attempts[0][1]).json()["error"]["code"] == -32004
    from sentinel.a2a import A2AService
    assert set(A2AService.METHODS) == {"SendMessage", "GetTask", "ListTasks", "CancelTask"}
    # 2. the agent's service token cannot use the people's endpoints
    assert c.post(f"/v1/reviews/{eng.store.open_review_for(tid).id}/decision", headers=h("agent-a"),
                  json={"kind": "approve"}).status_code == 403
    # 3. Sentinel's own rule: APPROVE is not grantable to an agent identity
    with pytest.raises(ValueError, match="APPROVE is never grantable"):
        AgentPolicy(template="p", mode="ACT", grants={"__approve__": "EDIT"})
    d = authorise(make_directory(), Agent("a2a:framework-a", bound_role="ops_head"), APPROVE)
    assert not d.allowed and "agent_never_approves" in d.checks
