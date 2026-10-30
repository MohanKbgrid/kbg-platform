# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""B3/B4: connector templates (Shiprocket, Delhivery, Zoho Books, SAP B1, Tally), login tokens, lookups, XML."""
from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
import yaml

from sentinel import connauth, connectors
from sentinel.config import dump_yaml
from sentinel.httpactions import call, xml_to_dict
from sentinel.mcp import Connectors
from sentinel.sources import parse_sources, to_events, verify_signature


@pytest.mark.parametrize("name", connectors.names())
def test_every_template_passes_the_connectors_check(engine_factory, name):
    eng = engine_factory()
    doc = connectors.merge({}, name)
    _, probs = eng.check_config("connectors", dump_yaml(doc))
    assert [p.message for p in probs if p.severity == "error"] == [], name
    s = connectors.summary(name)
    assert s["settings"] and all(k.startswith("SENTINEL_SECRET_") for k in s["settings"])


def test_merge_refuses_clashes_and_writes_a_file(tmp_path):
    f = tmp_path / "connectors.yaml"
    out = connectors.add_to_file("shiprocket", f)
    assert "SENTINEL_SECRET_SHIPROCKET_EMAIL" in out["set_these"]
    connectors.add_to_file("delhivery", f)
    doc = yaml.safe_load(f.read_text())
    assert {"shiprocket_tracking", "delhivery_scans"} <= set(doc["sources"])
    with pytest.raises(ValueError, match="already"):
        connectors.add_to_file("shiprocket", f)
    with pytest.raises(KeyError):
        connectors.load("../etc")


@pytest.fixture
def fake():
    state = {"logins": 0, "seen": []}

    class H(BaseHTTPRequestHandler):
        def _reply(self, status, body, ctype="application/json"):
            data = body if isinstance(body, bytes) else json.dumps(body).encode()
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_POST(self):  # noqa: N802
            n = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(n)
            state["seen"].append(("POST", self.path, dict(self.headers), raw))
            if self.path.endswith("/auth/login"):
                state["logins"] += 1
                return self._reply(200, {"token": f"tok{state['logins']}"})
            if self.path == "/tally":
                return self._reply(200, b"<ENVELOPE><BODY><DATA><TALLYMESSAGE><VOUCHER VCHTYPE=\"Sales\">"
                                   b"<GUID>g-1</GUID><ALTERID>4</ALTERID><VOUCHERNUMBER>S/12</VOUCHERNUMBER>"
                                   b"</VOUCHER></TALLYMESSAGE><TALLYMESSAGE><VOUCHER VCHTYPE=\"Receipt\"><GUID>g-2"
                                   b"</GUID><ALTERID>1</ALTERID></VOUCHER></TALLYMESSAGE></DATA></BODY></ENVELOPE>",
                                   "text/xml")
            return self._reply(200, {"status": "ok"})

        def do_GET(self):  # noqa: N802
            state["seen"].append(("GET", self.path, dict(self.headers), b""))
            if "/courier/track/awb/" in self.path:
                if self.headers.get("Authorization") == "Bearer tok1":
                    return self._reply(401, {"message": "expired"})
                return self._reply(200, {"tracking_data": {"shipment_status": 7, "awb": self.path.rsplit("/", 1)[1]}})
            return self._reply(404, {})

        def log_message(self, *a):
            pass
    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}", state
    srv.shutdown()
    connauth.configure({})


def _local(name, base, monkeypatch):
    monkeypatch.setenv("SENTINEL_SECRET_SHIPROCKET_EMAIL", "ops@acme.in")
    monkeypatch.setenv("SENTINEL_SECRET_SHIPROCKET_PASSWORD", "pw")
    text = json.dumps(connectors.merge({}, name)).replace("https://apiv2.shiprocket.in", base)
    return Connectors(json.loads(text))


def test_shiprocket_login_lookup_relogin_and_action(fake, monkeypatch):
    base, state = fake
    conn = _local("shiprocket", base, monkeypatch)
    track = next(t for t in conn.connect_tools() if t.name == "shiprocket.track_awb")
    out = track.fn({"awb": "AWB123"}, {})
    assert out == {"shipment_status": 7, "awb": "AWB123"}
    assert state["logins"] == 2                                   # the first token was refused, fetched again
    login = next(s for s in state["seen"] if s[1].endswith("/auth/login"))
    assert json.loads(login[3]) == {"email": "ops@acme.in", "password": "pw"}
    assert track.fn({"awb": "X"}, {})["awb"] == "X" and state["logins"] == 2   # cached
    act = conn.actions["shiprocket.ndr_reattempt"]
    res = call(act, act.request, None, {"awb": "AWB123", "comments": "customer asked for Monday"})
    assert res.ok
    sent = [s for s in state["seen"] if s[1].endswith("/ndr/AWB123/action")][-1]
    assert sent[2]["Authorization"] == "Bearer tok2" and json.loads(sent[3])["action"] == "re-attempt"
    assert conn.actions["shiprocket.cancel_order"].compensate is None   # honest: cannot be undone


def test_shiprocket_webhook_token_and_events(monkeypatch):
    monkeypatch.setenv("SENTINEL_SECRET_SHIPROCKET_WEBHOOK", "hook-secret")
    src = parse_sources(connectors.load("shiprocket")["connectors"]["sources"])["shiprocket_tracking"]
    body = {"awb": "A9", "courier_name": "Xpressbees", "current_status": "RTO INITIATED", "order_id": "SH-1"}
    raw = json.dumps(body).encode()
    assert verify_signature(src, raw, {"x-api-key": "hook-secret"})
    assert not verify_signature(src, raw, {"x-api-key": "nope"})
    ev = to_events(src, body)
    assert [e.type for e in ev] == ["shipment.rto"] and ev[0].payload["awb"] == "A9"


def test_tally_xml_poll_and_escaping(fake, monkeypatch):
    base, state = fake
    from sentinel.sources import run_once
    monkeypatch.setenv("SENTINEL_SECRET_TALLY_URL", f"{base}/tally")
    monkeypatch.setenv("SENTINEL_SECRET_TALLY_COMPANY", "Northwind & Co")
    src = parse_sources(connectors.load("tally")["connectors"]["sources"])["tally_daybook"]
    events, st = run_once(src, {})
    assert [e.payload["guid"] for e in events] == ["g-1", "g-2"]
    assert events[0].payload["voucher_type"] == "Sales" and events[0].payload["number"] == "S/12"
    sent = state["seen"][-1]
    assert b"<SVCURRENTCOMPANY>Northwind &amp; Co</SVCURRENTCOMPANY>" in sent[3]
    assert sent[2]["Content-Type"].startswith("text/xml")
    with pytest.raises(ValueError):
        xml_to_dict('<!DOCTYPE x [<!ENTITY a "b">]><x>&a;</x>')


def test_unknown_auth_and_writing_lookups_are_refused(engine_factory):
    eng = engine_factory()
    bad = {"lookups": {"x.get": {"params": {"id": "str"}, "request": {"method": "GET",
                                                                      "url": "https://a.example/{{params.id}}",
                                                                      "headers": {"A": "{{auth.nope}}"}}}}}
    _, probs = eng.check_config("connectors", dump_yaml(bad))
    assert any("auth.nope" in p.message for p in probs if p.severity == "error")
    post = {"lookups": {"x.post": {"request": {"method": "POST", "url": "https://a.example/q"}}}}
    _, probs = eng.check_config("connectors", dump_yaml(post))
    assert any("reads_only" in p.message for p in probs)
