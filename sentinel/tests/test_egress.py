# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""Configuration cannot reach into the server's network or read its secrets (review finding H2)."""
from __future__ import annotations

import http.server
import threading
import urllib.request

import pytest

from sentinel import egress, envsecrets
from sentinel.sources import Source, SourceError, fetch


class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "http://169.254.169.254/latest/meta-data/")
            self.end_headers()
            return
        body = b"[" + b"1," * 1500 + b"1]"
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


@pytest.fixture
def server():
    srv = http.server.HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


def test_internal_addresses_need_to_be_allowed(monkeypatch):
    monkeypatch.delenv("SENTINEL_EGRESS_ALLOW", raising=False)
    for url in ("http://127.0.0.1:5432/", "http://10.0.0.5/api", "http://192.168.1.10/", "http://[::1]/",
                "http://localhost/"):
        with pytest.raises(egress.EgressError, match="internal address"):
            egress.check_url(url)
    with pytest.raises(egress.EgressError, match="metadata"):
        egress.check_url("http://169.254.169.254/latest/meta-data/")
    with pytest.raises(egress.EgressError, match="only http"):
        egress.check_url("file:///etc/passwd")
    monkeypatch.setenv("SENTINEL_EGRESS_ALLOW", "10.20.0.0/16, wms.local")
    egress.check_url("http://10.20.3.4/api")                           # an office system, allowed
    with pytest.raises(egress.EgressError):
        egress.check_url("http://10.21.0.1/")
    with pytest.raises(egress.EgressError, match="metadata"):           # never, even with an allow list
        egress.check_url("http://169.254.169.254/")


def test_no_redirects_and_a_size_cap(server, monkeypatch):
    with pytest.raises(egress.EgressError, match="redirects are not followed"):
        egress.open_url(urllib.request.Request(server + "/redirect"), 5,
                        base_opener=urllib.request.build_opener(urllib.request.ProxyHandler({})))
    monkeypatch.setenv("SENTINEL_EGRESS_MAX_BYTES", "1000")
    with pytest.raises(egress.EgressError, match="larger than 1000"):
        egress.open_url(urllib.request.Request(server + "/big"), 5,
                        base_opener=urllib.request.build_opener(urllib.request.ProxyHandler({})))


def test_poll_sources_go_through_the_checks(server, monkeypatch):
    s = Source.model_validate({"name": "x", "kind": "poll", "url": server + "/data", "every_s": 60,
                               "emit": [{"type": "t"}]})
    op = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    assert len(fetch(s, None, opener=op)[1]) == 1501
    monkeypatch.delenv("SENTINEL_EGRESS_ALLOW")
    with pytest.raises(SourceError, match="internal address"):
        fetch(s, None, opener=op)


def test_configuration_reads_only_its_own_secrets(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-real")
    monkeypatch.setenv("SENTINEL_PG", "postgresql://u:pw@db/x")
    monkeypatch.setenv("SENTINEL_SECRET_WMS", "w")
    monkeypatch.setenv("LEGACY_TOKEN", "l")
    sc = envsecrets.scope()
    assert sc.get("SENTINEL_SECRET_WMS") == "w" and "ANTHROPIC_API_KEY" not in sc and "SENTINEL_PG" not in sc
    assert "LEGACY_TOKEN" not in sc
    monkeypatch.setenv("SENTINEL_CONFIG_SECRETS", "LEGACY_TOKEN")
    assert envsecrets.scope()["LEGACY_TOKEN"] == "l"
    from sentinel.providers import build_client
    with pytest.raises(ValueError, match="cannot be used by configuration"):     # key sent to a configurable URL
        build_client({"provider": "openai_compatible", "model": "m", "base_url": "https://evil.example",
                      "api_key_env": "ANTHROPIC_API_KEY"})
    s = Source.model_validate({"name": "x", "kind": "poll", "url": "https://x.example/?k={{env.ANTHROPIC_API_KEY}}",
                               "every_s": 60, "emit": [{"type": "t"}]})
    from sentinel.sources import check_source
    assert any("cannot be used by configuration" in m for _, m in check_source(s))
