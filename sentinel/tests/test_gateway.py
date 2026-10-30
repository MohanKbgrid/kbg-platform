# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""Model gateway: one Mac mini, many customers - auth, allowlists, fair share, metering, no prompt logging."""
from __future__ import annotations

import concurrent.futures as cf
import json
import logging
import socket
import threading
import time

import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from sentinel import ModelUnavailable, OllamaClient  # noqa: E402
from sentinel.api import token_hash  # noqa: E402
from sentinel.cli import main  # noqa: E402
from sentinel.gateway import create_gateway, load_gateway_config  # noqa: E402
from tests.fake_model_server import FakeModelServer  # noqa: E402

ACME, NORTHWIND, ADMIN = "tok-acme-0123456789", "tok-northwind-0123456789", "tok-admin-0123456789"
QWEN, EMBED = "qwen2.5:7b-instruct", "nomic-embed-text"


@pytest.fixture
def upstream():
    s = FakeModelServer(reply=lambda body: json.dumps({"final": {"action": None}}))
    yield s
    s.close()


def _cfg(upstream, **over):
    base = {"upstream": upstream.url, "max_concurrent": 4, "queue_timeout_s": 5,
            "admins": [{"sha256": token_hash(ADMIN)}],
            "tenants": [{"name": "acme", "sha256": token_hash(ACME), "max_concurrent": 2, "per_minute": 600,
                         "models": [QWEN, EMBED]},
                        {"name": "northwind", "sha256": token_hash(NORTHWIND), "max_concurrent": 2, "per_minute": 600,
                         "models": [QWEN]}]}
    base.update(over)
    return load_gateway_config(base)


def _client(upstream, **over):
    return TestClient(create_gateway(_cfg(upstream, **over)))


def _chat(c, tok, model=QWEN, **extra):
    return c.post("/api/chat", headers={"Authorization": f"Bearer {tok}"},
                  json={"model": model, "messages": [{"role": "user", "content": "hi"}], **extra})


def test_forwards_chat_and_meters_usage(upstream, tmp_path):
    with _client(upstream, usage_dir=str(tmp_path)) as c:
        r = _chat(c, ACME)
        assert r.status_code == 200 and r.json()["message"]["content"]
        assert upstream.requests[-1]["body"]["stream"] is False        # forced off: Ollama streams by default
        assert "authorization" not in {k.lower() for k in upstream.requests[-1]["headers"]}   # token not forwarded
        u = c.get("/usage", headers={"Authorization": f"Bearer {ADMIN}"}).json()
        assert u["acme"][QWEN]["requests"] == 1 and u["acme"][QWEN]["prompt_tokens"] == 120
        assert u["acme"][QWEN]["completion_tokens"] == 30
        m = c.get("/metrics", headers={"Authorization": f"Bearer {ADMIN}"}).text
        assert 'sentinel_gateway_requests_total{model="qwen2.5:7b-instruct",status="200",tenant="acme"} 1' in m
    ledger = (next(tmp_path.glob("usage-*.jsonl"))).read_text().splitlines()
    rec = json.loads(ledger[0])
    assert rec["tenant"] == "acme" and rec["prompt_tokens"] == 120 and "messages" not in rec and "hi" not in ledger[0]


def test_openai_and_embedding_paths(upstream):
    with _client(upstream) as c:
        h = {"Authorization": f"Bearer {ACME}"}
        r = c.post("/v1/chat/completions", headers=h, json={"model": QWEN, "messages": []})
        assert r.status_code == 200 and r.json()["usage"]["prompt_tokens"] == 100
        r = c.post("/api/embed", headers=h, json={"model": EMBED, "input": ["abc"]})
        assert r.status_code == 200 and r.json()["embeddings"][0][0] == 3.0


@pytest.mark.parametrize("headers", [{}, {"Authorization": "Bearer wrong"}, {"Authorization": "Basic x"}])
def test_rejects_missing_or_bad_tokens(upstream, headers):
    with _client(upstream) as c:
        assert c.post("/api/chat", headers=headers, json={"model": QWEN}).status_code == 401
        assert c.get("/api/tags", headers=headers).status_code == 401
        assert c.get("/usage", headers=headers).status_code == 401
        assert c.get("/metrics", headers=headers).status_code == 401
    assert upstream.requests == []


@pytest.mark.parametrize("method,path", [("POST", "/api/pull"), ("DELETE", "/api/delete"), ("POST", "/api/create"),
                                         ("POST", "/api/push"), ("POST", "/api/copy"), ("GET", "/api/ps")])
def test_admin_endpoints_of_ollama_are_never_reachable(upstream, method, path):
    with _client(upstream) as c:
        r = c.request(method, path, headers={"Authorization": f"Bearer {ACME}"}, json={"model": QWEN})
        assert r.status_code == 403
    assert upstream.requests == []


def test_model_allowlist_per_customer(upstream):
    with _client(upstream) as c:
        assert _chat(c, NORTHWIND, model=EMBED).status_code == 403
        tags = c.get("/api/tags", headers={"Authorization": f"Bearer {NORTHWIND}"}).json()["models"]
        assert [t["name"] for t in tags] == [QWEN]


@pytest.mark.parametrize("body,code", [(b"not json", 400), (b'{"messages": []}', 400),
                                       (json.dumps({"model": QWEN, "stream": True}).encode(), 400)])
def test_bad_requests(upstream, body, code):
    with _client(upstream) as c:
        r = c.post("/api/chat", headers={"Authorization": f"Bearer {ACME}", "Content-Type": "application/json"},
                   content=body)
        assert r.status_code == code


def test_body_size_limit(upstream):
    with _client(upstream, max_body_bytes=1000) as c:
        assert _chat(c, ACME, pad="x" * 2000).status_code == 413


def test_rate_limit_per_customer(upstream):
    cfg = {"tenants": [{"name": "acme", "sha256": token_hash(ACME), "per_minute": 3},
                       {"name": "northwind", "sha256": token_hash(NORTHWIND), "per_minute": 3}]}
    with _client(upstream, **cfg) as c:
        codes = [_chat(c, ACME).status_code for _ in range(5)]
        assert codes[:3] == [200, 200, 200] and codes[3:] == [429, 429]
        assert _chat(c, NORTHWIND).status_code == 200                       # the other customer is unaffected


def _parallel(c, toks):
    with cf.ThreadPoolExecutor(len(toks)) as ex:
        return list(ex.map(lambda t: _chat(c, t).status_code, toks))


def test_one_customer_cannot_take_the_whole_machine(upstream):
    upstream.hold_s = 0.3
    cfg = {"max_concurrent": 3, "tenants": [
        {"name": "acme", "sha256": token_hash(ACME), "max_concurrent": 1, "per_minute": 600},
        {"name": "northwind", "sha256": token_hash(NORTHWIND), "max_concurrent": 2, "per_minute": 600}]}
    with _client(upstream, **cfg) as c:
        assert _parallel(c, [ACME] * 4) == [200] * 4
        assert upstream.max_in_flight == 1                               # acme's cap
        upstream.max_in_flight = 0
        assert _parallel(c, [ACME, ACME, NORTHWIND, NORTHWIND, NORTHWIND]) == [200] * 5
        assert upstream.max_in_flight == 3                               # global cap, shared fairly


def test_busy_host_answers_503_quickly_so_clients_fall_back(upstream):
    upstream.hold_s = 1.0
    cfg = {"queue_timeout_s": 0.2, "tenants": [{"name": "acme", "sha256": token_hash(ACME), "max_concurrent": 1}]}
    with _client(upstream, **cfg) as c:
        codes = sorted(_parallel(c, [ACME, ACME]))
        assert codes == [200, 503]
        m = c.get("/metrics", headers={"Authorization": f"Bearer {ADMIN}"}).text
        assert 'sentinel_gateway_rejected_total{reason="busy",tenant="acme"} 1' in m


def test_upstream_down_and_errors(upstream):
    with _client(upstream) as c:
        upstream.fail_with = 500
        assert _chat(c, ACME).status_code == 500
        assert c.get("/healthz").status_code == 200
    dead = load_gateway_config({"upstream": "http://127.0.0.1:9", "tenants": [{"name": "m",
                                                                                "sha256": token_hash(ACME)}]})
    with TestClient(create_gateway(dead)) as c:
        assert _chat(c, ACME).status_code == 502
        assert c.get("/healthz").json() == {"status": "degraded", "upstream": "down"}


def test_prompts_never_reach_the_logs(upstream, caplog):
    with caplog.at_level(logging.DEBUG), _client(upstream) as c:
        c.post("/api/chat", headers={"Authorization": f"Bearer {ACME}"},
               json={"model": QWEN, "messages": [{"role": "user", "content": "SECRET-ORDER-DETAILS"}]})
    assert caplog.records and all("SECRET-ORDER-DETAILS" not in r.getMessage() and
                                  "SECRET-ORDER-DETAILS" not in str(r.__dict__) for r in caplog.records)


@pytest.mark.parametrize("cfg,msg", [
    ({"upstream": "ftp://x"}, "http"),
    ({"tenants": [{"name": "a", "sha256": "abc"}]}, "64 hex"),
    ({"tenants": [{"name": "a", "sha256": "a" * 64}, {"name": "b", "sha256": "a" * 64}]}, "already used"),
    ({"tenants": [{"name": "a", "sha256": "a" * 64}, {"name": "a", "sha256": "b" * 64}]}, "unique"),
    ({"tenants": [{"name": "a", "sha256": "a" * 64, "max_concurrent": 0}]}, "limits"),
])
def test_config_validation(cfg, msg):
    with pytest.raises(ValueError, match=msg):
        load_gateway_config(cfg)


def test_new_token_command(capsys):
    assert main(["new-token"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["token"].startswith("sk-") and out["sha256"] == token_hash(out["token"])


def test_end_to_end_engine_client_through_real_gateway(upstream):
    """OllamaClient -> gateway (real HTTP server) -> model host, as deployed."""
    import uvicorn
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    server = uvicorn.Server(uvicorn.Config(create_gateway(_cfg(upstream)), host="127.0.0.1", port=port,
                                           log_config=None, access_log=False))
    t = threading.Thread(target=server.run, daemon=True)
    t.start()
    try:
        for _ in range(100):
            if server.started:
                break
            time.sleep(0.05)
        url = f"http://127.0.0.1:{port}"
        ok = OllamaClient(QWEN, url, api_key=ACME, trust_env=False)
        assert json.loads(ok.complete("s", [{"role": "user", "content": "x"}])) == {"final": {"action": None}}
        assert ok.last_usage == {"prompt_tokens": 120, "completion_tokens": 30}
        with pytest.raises(Exception) as ei:
            OllamaClient(QWEN, url, api_key="wrong", trust_env=False).complete("s", [])
        assert "401" in str(ei.value) and not isinstance(ei.value, ModelUnavailable)
        upstream.fail_with = 503
        with pytest.raises(ModelUnavailable):
            ok.complete("s", [])
    finally:
        server.should_exit = True
        t.join(5)


def test_tenants_cannot_change_how_the_host_runs_models(upstream):
    with _client(upstream, max_num_ctx=8192, max_num_predict=512, keep_alive="10m") as c:
        r = _chat(c, ACME, keep_alive="-1", options={"num_ctx": 131072, "num_predict": 100000, "temperature": 0,
                                                     "num_gpu": 99, "use_mmap": False}, raw=True)
        assert r.status_code == 200
        sent = upstream.requests[-1]["body"]
        assert sent["keep_alive"] == "10m" and "raw" not in sent
        assert sent["options"] == {"num_ctx": 8192, "num_predict": 512, "temperature": 0}


def test_upstream_wait_follows_the_client(upstream):
    upstream.hold_s = 3.0
    with _client(upstream) as c:
        t0 = time.perf_counter()
        r = c.post("/api/chat", headers={"Authorization": f"Bearer {ACME}", "X-Request-Timeout": "1"},
                   json={"model": QWEN, "messages": [{"role": "user", "content": "hi"}]})
        assert r.status_code == 504 and time.perf_counter() - t0 < 2.8      # gave up when the client would
