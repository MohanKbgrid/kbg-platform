# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""Fleet view: each site's status endpoint and collecting them, with upgrade commands for sites behind."""
from __future__ import annotations

import socket
import threading
import time

import pytest

pytest.importorskip("fastapi")
from sentinel.api import Principal, create_app, token_hash  # noqa: E402
from sentinel.fleet import FleetFile, Site, collect, site_status  # noqa: E402
from tests.conftest import job_event  # noqa: E402


def test_site_status(engine_factory):
    eng = engine_factory()
    eng.ingest(job_event(error="AUTH", ref="F1", key="f1"))
    s = site_status(eng)
    assert s["version"] and s["health"] == "ok" and s["open_reviews"] == 1 and s["last_backup"] is None
    assert "licence" not in s and s["live"] == s["patterns"]


@pytest.fixture
def site(engine_factory):
    import uvicorn
    eng = engine_factory()
    app = create_app(eng, {token_hash("fleet-tok"): Principal("service", "fleet"),
                           token_hash("svc"): Principal("service", "ingest")}, config_sync_s=0)
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_config=None))
    threading.Thread(target=server.run, daemon=True).start()
    for _ in range(200):
        if server.started:
            break
        time.sleep(0.02)
    yield f"http://127.0.0.1:{port}"
    server.should_exit = True


def test_collect_flags_and_upgrade_commands(site, monkeypatch):
    monkeypatch.setenv("SENTINEL_SECRET_FLEET_A", "fleet-tok")
    monkeypatch.setenv("SENTINEL_SECRET_FLEET_B", "svc")
    fleet = FleetFile(target_version="99.0.0", sites={
        "a": Site(url=site, token_env="SENTINEL_SECRET_FLEET_A"),
        "b": Site(url=site, token_env="SENTINEL_SECRET_FLEET_B"),           # wrong token: refused
        "c": Site(url="http://127.0.0.1:9", token_env="SENTINEL_SECRET_FLEET_A"),
        "d": Site(url=site, token_env="SENTINEL_SECRET_FLEET_NOPE")})
    res = collect(fleet, timeout_s=3)
    rows = {r["name"]: r for r in res["sites"]}
    assert rows["a"]["reachable"] and "behind" in rows["a"]["flags"] and "no backup" in rows["a"]["flags"]
    assert any("migrate" in c for c in rows["a"]["upgrade"])
    assert rows["b"]["error"] == "HTTP 403" and rows["c"]["reachable"] is False
    assert "not set" in rows["d"]["error"] and res["summary"]["attention"] == 4
