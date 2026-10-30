# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""A1: write actions defined in configuration (HTTP, schema, undo), end to end against a local server."""
from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
import yaml

from sentinel import Guardrails
from sentinel.config import dump_yaml
from tests.conftest import job_event
from tests.test_config import registry_doc


@pytest.fixture
def server():
    calls = []
    replies = {"status": 200, "body": {"order": {"status": "on_hold"}}}

    class H(BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802
            n = int(self.headers.get("Content-Length") or 0)
            calls.append({"path": self.path, "headers": dict(self.headers),
                          "body": json.loads(self.rfile.read(n) or b"null")})
            data = json.dumps(replies["body"]).encode()
            self.send_response(replies["status"])
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *a):
            pass
    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}", calls, replies
    srv.shutdown()


def connectors(base, **over):
    action = {"description": "Hold an order in the CRM", "params": {"ref": "str", "note?": "str"},
              "request": {"url": f"{base}/orders/{{{{params.ref}}}}/hold",
                          "headers": {"Authorization": "Bearer {{env.SENTINEL_SECRET_CRM}}"},
                          "body": {"reason": "{{params.note|default:sentinel}}", "case": "{{incident.id}}"}},
              "compensate": {"url": f"{base}/orders/{{{{params.ref}}}}/release"},
              "ok_when": {"body.order.status": "on_hold"}}
    action.update(over)
    return dump_yaml({"actions": {"crm.hold": action}})


def use_it(eng):
    doc = registry_doc(eng)
    for p in doc["patterns"]:
        if p["id"] == "job_timeout":
            p["allowed_actions"] = [*p["allowed_actions"], "crm.hold"]
            p["playbook"] = [{"action": "crm.hold", "params": {"ref": "{{payload.ref}}"}}]
    return dump_yaml(doc)


def publish(eng, kinds):
    ids = [eng.save_config(k, t, "m")[0].id for k, t in kinds.items()]
    return eng.publish_config_set(ids, actor="m")


def test_configured_action_runs_and_reverses(engine_factory, server, monkeypatch):
    base, calls, _ = server
    monkeypatch.setenv("SENTINEL_SECRET_CRM", "tok-1")
    eng = engine_factory(guardrails=Guardrails())                 # default guardrails: needs reversible
    publish(eng, {"connectors": connectors(base), "registry": use_it(eng)})
    assert eng.actions.get("crm.hold").spec.reversible is True
    r = eng.ingest(job_event(error="TIMEOUT", ref="A/1", key="h1"))
    assert eng.store.get_disposition(r.incident_id).resolver == "auto"
    call = calls[0]
    assert call["path"] == "/orders/A%2F1/hold"                    # params are escaped in the URL
    assert call["headers"]["Authorization"] == "Bearer tok-1"
    assert call["headers"]["Idempotency-Key"] and call["body"] == {"reason": "sentinel", "case": r.incident_id}
    eng.reverse(r.incident_id, actor="m", note="wrong")
    assert calls[-1]["path"] == "/orders/A%2F1/release"
    assert calls[-1]["headers"]["Idempotency-Key"].endswith(":undo")


def test_failures_and_reply_checks(engine_factory, server, monkeypatch):
    from sentinel.actions import ActionContext
    from sentinel.httpactions import parse_actions, registry_from
    base, calls, replies = server
    monkeypatch.setenv("SENTINEL_SECRET_CRM", "tok")
    reg = registry_from(parse_actions(yaml.safe_load(connectors(base))["actions"]))
    ctx = ActionContext(incident=None, event=None, actor="auto", idempotency_key="k1")
    run = reg.get("crm.hold").handler
    assert run(ctx, {"ref": "1"}).ok is True
    replies["body"] = {"order": {"status": "open"}}
    r = run(ctx, {"ref": "1"})
    assert r.ok is False and r.retryable is False and "does not show success" in r.detail
    replies.update(status=503, body={"error": "busy"})
    r = run(ctx, {"ref": "1"})
    assert r.ok is False and r.retryable is True and "503: busy" in r.detail
    replies.update(status=422, body={"errors": "bad order"})
    assert run(ctx, {"ref": "1"}).retryable is False
    blocked = registry_from(parse_actions({"x.y": {"request": {"url": "http://169.254.169.254/latest"}}}))
    r = blocked.get("x.y").handler(ctx, {})
    assert r.ok is False and r.retryable is False


def test_configuration_checks(engine_factory, server, monkeypatch):
    base, _, _ = server
    eng = engine_factory()
    _, probs = eng.check_config("connectors", connectors(base))
    msgs = [p.message for p in probs]
    assert any("SENTINEL_SECRET_CRM is not set" in m for m in msgs)
    clash = dump_yaml({"actions": {"retry": {"request": {"url": f"{base}/r"}}}})
    assert any("implements an action of that name" in p.message for p in eng.check_config("connectors", clash)[1])
    leak = dump_yaml({"actions": {"a.b": {"params": {"x": "str"}, "request": {"url": f"{base}/r",
                                                                               "body": {"k": "{{env.HOME}}"}}}}})
    assert any("body may not read environment" in p.message for p in eng.check_config("connectors", leak)[1])
    undeclared = dump_yaml({"actions": {"a.b": {"params": {"x": "str"}, "request": {"url": f"{base}/{{{{params.y}}}}"}}}})
    assert any("does not declare" in p.message for p in eng.check_config("connectors", undeclared)[1])
    assert any("lowercase" in p.message for p in eng.check_config("connectors", dump_yaml(
        {"actions": {"Bad Name": {"request": {"url": f"{base}/r"}}}}))[1])
    # a registry can only use the action once the connectors providing it are published with it
    res = eng.check_config_set({"registry": use_it(eng)})
    assert any("crm.hold" in p.message for p in res["registry"][1] if p.severity == "error")
    res = eng.check_config_set({"registry": use_it(eng), "connectors": connectors(base)})
    assert not [p for p in res["registry"][1] if p.severity == "error"]
    monkeypatch.setenv("SENTINEL_SECRET_CRM", "t")
    publish(eng, {"connectors": connectors(base), "registry": use_it(eng)})
    _, probs = eng.check_config("connectors", dump_yaml({"actions": {}}))
    assert any("job_timeout uses ['crm.hold']" in p.message for p in probs if p.severity == "error")


def test_restart_keeps_configured_actions(engine_factory, server, monkeypatch, tmp_path):
    from sentinel import Engine, SQLiteStore
    from tests.conftest import Backend, make_overlay
    base, calls, _ = server
    monkeypatch.setenv("SENTINEL_SECRET_CRM", "t")
    path = str(tmp_path / "r.db")
    eng = Engine(make_overlay(Backend()), store=SQLiteStore(path), guardrails=Guardrails())
    publish(eng, {"connectors": connectors(base), "registry": use_it(eng)})
    again = Engine(make_overlay(Backend()), store=SQLiteStore(path), guardrails=Guardrails())
    assert again.actions.has("crm.hold") and "crm.hold" in again.registry.get("job_timeout").allowed_actions
    again.ingest(job_event(error="TIMEOUT", ref="R1", key="rr"))
    assert calls and calls[-1]["path"] == "/orders/R1/hold"
