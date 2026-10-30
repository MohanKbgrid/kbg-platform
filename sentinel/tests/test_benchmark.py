# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""E5: anonymised benchmarks across sites."""
from __future__ import annotations

import json

import pytest

from sentinel import benchmark as bm
from tests.conftest import job_event


def _snap(site, auto, mins, industry="retail", month="2026-09", exc="template:retail-fulfilment/order_stuck"):
    return {"format": bm.FORMAT, "site": site, "month": month, "industry": industry,
            "exceptions": {exc: {"cases": 100, "automatic": auto, "reversed": 0.01, "within_sla": 0.9,
                                 "minutes_to_close": mins}}}


def test_snapshot_shares_only_shared_exceptions_and_rates(engine_factory, clock):
    eng = engine_factory()
    eng.registry.get("job_timeout").layer = "template:ops"
    month = clock().strftime("%Y-%m")
    for i in range(bm.MIN_CASES + 2):
        eng.ingest(job_event(error="TIMEOUT", ref=f"B{i}", system=f"s{i}", key=f"b{i}"))
    for i in range(3):
        eng.ingest(job_event(error="AUTH", ref=f"H{i}", system=f"h{i}", key=f"h{i}"))   # not shared: left out
    snap = bm.snapshot(eng, month, industry="retail")
    assert list(snap["exceptions"]) == ["template:ops/job_timeout"]
    row = snap["exceptions"]["template:ops/job_timeout"]
    assert row["cases"] == bm.MIN_CASES + 2 and row["automatic"] == 1.0 and row["within_sla"] == 1.0
    text = json.dumps(snap)
    assert "B1" not in text and "s1" not in text and eng.overlay.name not in text      # no case data
    assert bm.snapshot(eng, month)["site"] == snap["site"]                            # a stable random id


def test_build_needs_k_sites_and_compare_places_a_site(tmp_path):
    snaps = [_snap(f"site{i}", 0.2 + i * 0.1, 60 - i * 5) for i in range(5)]
    snaps.append(_snap("site0", 0.9, 10, month="2026-08"))          # an older month of the same site is ignored
    snaps.append(_snap("lonely", 0.5, 30, industry="dairy"))
    bench = bm.build(snaps, k=5)
    retail = bench["benchmarks"]["retail"]["template:retail-fulfilment/order_stuck"]
    assert retail["sites"] == 5 and retail["automatic"]["p50"] == pytest.approx(0.4)
    assert "dairy" not in bench["benchmarks"]                       # one site: never published
    assert bench["benchmarks"]["all"]["template:retail-fulfilment/order_stuck"]["sites"] == 6
    rows = bm.compare(_snap("me", 0.7, 12), bench, "retail")
    by = {r["measure"]: r for r in rows}
    assert by["automatic"]["standing"] == "top quarter" and by["minutes_to_close"]["standing"] == "top quarter"
    assert bm.compare(_snap("me", 0.7, 12, industry="dairy"), bench, "dairy")        # falls back to all sites
    with pytest.raises(ValueError):
        bm.build(snaps, k=2)


def test_cli_and_console(tmp_path, capsys, monkeypatch):
    from sentinel.cli import main
    d = tmp_path / "snaps"
    d.mkdir()
    for i in range(5):
        (d / f"{i}.json").write_text(json.dumps(_snap(f"s{i}", 0.5, 30)))
    out = tmp_path / "bench.json"
    assert main(["benchmark", "build", str(d), "--out", str(out)]) == 0
    capsys.readouterr()
    base = ["--overlay", "tests.test_templates_cli:_overlay", "--db", str(tmp_path / "b.db")]
    assert main([*base, "benchmark", "compare", str(out), "--month", "2026-09"]) == 0
    assert json.loads(capsys.readouterr().out) == []                # nothing shared on this site yet
    assert main([*base, "benchmark", "snapshot", "--month", "2026-09", "--out", str(tmp_path / "s.json")]) == 0


def test_console_endpoint(engine_factory, tmp_path, monkeypatch):
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from sentinel.api import Principal, create_app, token_hash
    eng = engine_factory()
    c = TestClient(create_app(eng, {token_hash("p"): Principal("person", "hari")}))
    h = {"Authorization": "Bearer p"}
    assert c.get("/console/api/benchmark", headers=h).json() == {"configured": False, "rows": []}
    f = tmp_path / "bench.json"
    f.write_text(json.dumps(bm.build([_snap(f"s{i}", 0.5, 30) for i in range(5)])))
    monkeypatch.setenv("SENTINEL_BENCHMARK", str(f))
    r = c.get("/console/api/benchmark?month=2026-09", headers=h).json()
    assert r["configured"] and r["k"] == 5 and r["rows"] == []
    assert not any(a["kind"] == "benchmark_snapshot" for a in eng.store.audit_log())
