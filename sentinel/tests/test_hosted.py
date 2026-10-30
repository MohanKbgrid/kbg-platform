# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""D1: hosted mode - tenants separated by schema, engine, tokens, secrets and worker turns."""
from __future__ import annotations

import hashlib
import threading

import pytest
import yaml

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from sentinel import SQLiteStore, hosted  # noqa: E402
from sentinel.envsecrets import TENANT, SecretNameError, require_allowed  # noqa: E402
from tests.conftest import job_event  # noqa: E402


def sha(t):
    return hashlib.sha256(t.encode()).hexdigest()


@pytest.fixture
def two(tmp_path):
    for name in ("acme", "beta"):
        (tmp_path / f"{name}-tokens.yaml").write_text(yaml.safe_dump(
            {"tokens": [{"sha256": sha(f"{name}-svc"), "service": "ingest"},
                        {"sha256": sha(f"{name}-person"), "person": "ops1"}]}))
    spec = {"tenants": {
        "acme": {"schema": "t_acme", "overlay": "tests.test_templates_cli:_overlay", "tokens": "acme-tokens.yaml",
                 "hosts": ["acme.example.in"], "weight": 2},
        "beta": {"schema": "t_beta", "overlay": "tests.test_templates_cli:_overlay", "tokens": "beta-tokens.yaml",
                 "hosts": ["beta.example.in"]}}}
    f = tmp_path / "tenants.yaml"
    f.write_text(yaml.safe_dump(spec))
    stores = {}

    def factory(name, schema):
        stores[name] = SQLiteStore(str(tmp_path / f"{schema}.db"))
        return stores[name]
    h = hosted.build(f, async_mode=False, store_factory=factory)
    return h, TestClient(hosted.asgi_app(h, tmp_path)), stores


def test_requests_reach_only_their_tenant(two):
    h, c, stores = two
    ev = job_event(error="AUTH", ref="H1").model_dump(mode="json")
    r = c.post("/t/acme/v1/events", json=ev, headers={"Authorization": "Bearer acme-svc"})
    assert r.status_code == 200 and r.json()["status"] == "new"
    assert c.post("/t/beta/v1/events", json=ev, headers={"Authorization": "Bearer acme-svc"}).status_code == 401
    r2 = c.post("/v1/events", json=ev, headers={"Authorization": "Bearer beta-svc", "Host": "beta.example.in"})
    assert r2.status_code == 200
    assert len(stores["acme"].incidents()) == 1 and len(stores["beta"].incidents()) == 1
    assert c.get("/healthz", headers={"Host": "nobody.example.in"}).status_code == 404
    assert c.get("/t/acme/healthz").json()["status"] == "ok"


def test_each_tenant_reads_only_its_own_secrets(monkeypatch):
    token = TENANT.set("acme")
    try:
        require_allowed("SENTINEL_SECRET_ACME_SHOPIFY", "x")
        with pytest.raises(SecretNameError, match="tenant acme"):
            require_allowed("SENTINEL_SECRET_BETA_SHOPIFY", "x")
        with pytest.raises(SecretNameError):
            require_allowed("SENTINEL_GATEWAY_KEY", "x")
        from sentinel.envsecrets import scope
        monkeypatch.setenv("SENTINEL_SECRET_ACME_A", "1")
        monkeypatch.setenv("SENTINEL_SECRET_BETA_B", "2")
        assert "SENTINEL_SECRET_ACME_A" in scope() and "SENTINEL_SECRET_BETA_B" not in scope()
    finally:
        TENANT.reset(token)
    require_allowed("SENTINEL_SECRET_BETA_SHOPIFY", "x")                # outside hosted mode: the usual rule


def test_workers_take_turns_by_weight(two):
    h, _, _ = two
    stop = threading.Event()
    t = threading.Thread(target=lambda: hosted.run_workers(h, stop, threads=1, idle_s=0.01))
    t.start()
    import time
    time.sleep(0.6)
    stop.set()
    t.join(5)
    a, b = h.tenants["acme"].turns, h.tenants["beta"].turns
    assert a > 0 and b > 0 and 1.4 <= a / b <= 2.6


def test_spec_checks(tmp_path):
    f = tmp_path / "t.yaml"
    f.write_text(yaml.safe_dump({"tenants": {"Bad Name": {"schema": "s", "overlay": "x:y", "tokens": "t"}}}))
    with pytest.raises(ValueError, match="lowercase"):
        hosted.load_spec(f)
    f.write_text(yaml.safe_dump({"tenants": {"aa": {"schema": "s", "overlay": "x:y", "packs": "p", "tokens": "t"}}}))
    with pytest.raises(ValueError, match="exactly one"):
        hosted.load_spec(f)
