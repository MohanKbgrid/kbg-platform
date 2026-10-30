# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""DuckDB analytics: reports agree with the engine, read-only, Parquet snapshots, works on SQLite and Postgres."""
from __future__ import annotations

import json
import os
from datetime import timedelta

import pytest

pytest.importorskip("duckdb")

from sentinel import Decision, DecisionKind, ModelRouter, ScriptedLLM, SQLiteStore  # noqa: E402
from sentinel.analytics import Analytics, AnalyticsError  # noqa: E402
from sentinel.cli import main  # noqa: E402
from tests.conftest import job_event, new_store, stuck_event  # noqa: E402


def _final(ref):
    return json.dumps({"final": {"action": "hold", "params": {"ref": ref}, "disposition_code": "resolved",
                                 "confidence": 0.95, "rationale": "r"}})


def _ref(m):
    return json.loads(m[0]["content"])["incident"]["facts"]["ref"]


@pytest.fixture(params=["sqlite"] + (["postgres"] if os.environ.get("SENTINEL_TEST_PG") else []))
def populated(request, engine_factory, clock, tmp_path):
    if request.param == "sqlite":
        path = str(tmp_path / "sentinel.db")
        store, kw = SQLiteStore(path), {"sqlite": path}
    else:
        store = new_store()
        kw = {"pg": os.environ["SENTINEL_TEST_PG"], "schema": store.schema}
    claude = ScriptedLLM(fn=lambda s, m: _final(_ref(m)))
    claude.model = "claude"
    answers = iter([True, False] + [True] * 50)
    slm = ScriptedLLM(fn=lambda s, m: _final(_ref(m) if next(answers) else "WRONG"))
    slm.model = "slm"
    eng = engine_factory(llm=ModelRouter(default=claude, candidates={"diagnose": slm}), store=store)

    now = clock.now
    clock.now = now - timedelta(days=60)                     # old history, outside a 30-day window
    eng.ingest(job_event(ref="J0", key="j0"))
    clock.now = now
    for i in range(1, 4):                                    # auto-resolved
        eng.ingest(job_event(ref=f"J{i}", key=f"j{i}"))
        clock.advance(minutes=1)
    eng.ingest(stuck_event(ref="I1", site="S1"))             # model-resolved, shadow candidate agrees
    eng.ingest(stuck_event(ref="I2", site="S2"))             # ... and disagrees
    eng.ingest(stuck_event(ref="I3", site="S1", age=2))      # person review, left open
    eng.ingest(job_event(error="E42", ref="J8", key="j8"))   # person review
    eng.ingest(job_event(error="E43", ref="J9", key="j9"))
    clock.advance(minutes=30)
    rv = next(r for r in eng.store.open_reviews() if eng.store.get_incident(r.incident_id).facts.get("error") == "E42")
    eng.decide(rv.id, Decision(kind=DecisionKind.MODIFY, actor="priya", action="retry", params={"ref": "J8"}))
    j1 = next(i for i in eng.store.incidents() if i.pattern_id == "job_timeout" and i.created_at == now)
    eng.reverse(j1.id, actor="lead", note="wrong")
    yield eng, kw
    eng.store.close() if request.param == "sqlite" else None


def test_reports_agree_with_the_engine(populated):
    eng, kw = populated
    rep = eng.report()["patterns"]
    with Analytics(**kw) as an:
        auto = {r["pattern_id"]: r for r in an.automation()}
        for pid, row in auto.items():
            assert row["automation_rate"] == rep[pid]["automation_rate"], pid
            assert row["closed"] == len([d for d in eng.store.dispositions(pid) if not d.shadow])
        jt = auto["job_timeout"]
        assert (jt["closed"], jt["auto"], jt["reversed"]) == (4, 4, 1)
        assert auto["item_stuck_long"]["model"] == 2
        jf = auto["job_failed_other"]
        assert (jf["closed"], jf["person"], jf["automation_rate"]) == (1, 1, 0.0)
        recent = {r["pattern_id"]: r["closed"] for r in an.automation(days=30)}
        assert recent["job_timeout"] == 3                     # the 60-day-old one is outside the window

        weekly = an.weekly()
        assert sum(w["closed"] for w in weekly) == sum(r["closed"] for r in auto.values()) and len(weekly) >= 2

        trust = {r["pattern_id"]: r for r in an.trust()}
        st = eng.store.get_pattern_state("job_timeout")
        assert trust["job_timeout"]["reversals"] == st.reversals == 1
        assert trust["job_timeout"]["route"] == st.route.value

        svc = {r["pattern_id"]: r for r in an.service()}
        assert svc["job_failed_other"]["open_reviews"] == 1 and svc["job_failed_other"]["closed"] == 1
        assert svc["job_failed_other"]["p50_minutes"] == pytest.approx(30.0, abs=1)
        assert svc["item_stuck_short"]["open_reviews"] == 1 and svc["item_stuck_short"]["closed"] == 0
        assert svc["job_timeout"]["p50_minutes"] == 0.0

        models = {(r["model"], r["shadow"]): r for r in an.models()}
        runs = eng.store.model_runs()
        shadows = [a["data"] for a in eng.store.audit_log() if a["kind"] == "model_shadow"]
        assert models[("claude", False)]["calls"] == sum(1 for r in runs if not r["shadow"]) >= 2
        assert models[("claude", False)]["shadow_agreement"] is None
        slm = models[("slm", True)]
        assert slm["calls"] == sum(1 for r in runs if r["shadow"]) == len(shadows)
        compared = [s["agreed"] for s in shadows if s["agreed"] is not None]     # None: nothing to compare
        assert slm["shadow_compared"] == len(compared) >= 2
        assert slm["shadow_agreement"] == round(sum(compared) / len(compared), 3) < 1

        hot = an.hotspots(["site"])
        by = {(r["value"], r["pattern_id"]): r for r in hot}
        assert by[("S1", "item_stuck_long")]["incidents"] == 1 and by[("S1", "item_stuck_short")]["still_open"] == 1
        sys_hot = an.hotspots(["system"], top=1)
        assert len(sys_hot) == 1 and sys_hot[0]["value"] == "billing"

        everything = an.all()
        assert set(everything) == {"automation", "weekly", "trust", "service", "models", "hotspots", "evaluations"}


def test_parquet_snapshot_round_trip(populated, tmp_path):
    _, kw = populated
    with Analytics(**kw) as an:
        counts = an.snapshot(str(tmp_path / "snap"))
        live = an.automation()
    assert counts["dispositions"] >= 7 and counts["model_runs"] >= 4 and counts["audit"] > 0
    with Analytics(parquet_dir=str(tmp_path / "snap")) as snap:
        assert snap.automation() == live
        with pytest.raises(AnalyticsError):
            snap.snapshot(str(tmp_path / "again"))


def test_source_is_read_only(populated):
    _, kw = populated
    with Analytics(**kw) as an:
        src = an._src
        with pytest.raises(Exception, match="(?i)read.only|read-only|readonly"):
            an.con.execute(f"DELETE FROM {src}.dispositions")


def test_cli_without_overlay(populated, capsys, tmp_path):
    eng, kw = populated
    if "sqlite" not in kw:
        pytest.skip("CLI path tested on the SQLite file")
    assert main(["--db", kw["sqlite"], "analytics", "automation", "--json"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert {r["pattern_id"] for r in out["automation"]} >= {"job_timeout", "item_stuck_long"}
    assert main(["--db", kw["sqlite"], "analytics", "hotspots", "--fact", "site", "--top", "3"]) == 0
    text = capsys.readouterr().out
    assert "== hotspots ==" in text and "S1" in text
    assert main(["--db", kw["sqlite"], "analytics", "--snapshot", str(tmp_path / "s")]) == 0
    assert main(["--db", kw["sqlite"], "analytics", "--parquet", str(tmp_path / "s")]) == 0
    assert "== models ==" in capsys.readouterr().out


def test_bad_inputs(tmp_path):
    with pytest.raises(ValueError):
        Analytics()
    with pytest.raises(AnalyticsError, match="no such"):
        Analytics(sqlite=str(tmp_path / "missing.db"))
    import sqlite3
    other = tmp_path / "other.db"
    sqlite3.connect(other).execute("CREATE TABLE x(a)").connection.close()
    with pytest.raises(AnalyticsError, match="not a Sentinel store"):
        Analytics(sqlite=str(other))
    path = str(tmp_path / "s.db")
    SQLiteStore(path).close()
    with Analytics(sqlite=path) as an:
        assert an.automation() == [] and an.models() == [] and an.hotspots() == []
        with pytest.raises(ValueError):
            an.hotspots(["site') OR 1=1 --"])
        with pytest.raises(ValueError):
            an.automation(days=0)
    assert main(["--db", str(tmp_path / "missing.db"), "analytics"]) == 2


def test_store_from_before_model_metering(tmp_path):
    path = str(tmp_path / "old.db")
    st = SQLiteStore(path)
    st._x("DROP TABLE model_runs")
    st.close()
    import sqlite3
    sqlite3.connect(path).execute("DROP TABLE IF EXISTS model_runs").connection.commit()
    with Analytics(sqlite=path) as an:
        assert an.models() == []
