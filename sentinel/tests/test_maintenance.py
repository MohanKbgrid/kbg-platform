# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""Production upkeep: retention with an archive, backups with manifests, restores that check themselves."""
from __future__ import annotations

import gzip
import json
import os
from datetime import timedelta

import pytest

from sentinel import Decision, DecisionKind, SQLiteStore
from sentinel import backup, retention
from sentinel.cli import main
from tests.conftest import job_event, new_store


def busy(engine_factory, store, clock):
    eng = engine_factory(store=store)
    for i in range(5):
        eng.ingest(job_event(ref=f"J{i}", system=f"s{i}", key=f"k{i}"))           # closed automatically
    r = eng.ingest(job_event(error="AUTH", ref="H1", key="h1"))                  # a person closes it
    rv = eng.store.open_review_for(r.incident_id)
    eng.decide(rv.id, Decision(kind=DecisionKind.REJECT, actor="op", disposition_code="no_action"))
    eng.store.audit(None, "config_published", {"kind": "registry"})              # governance record
    return eng


def test_retention_archives_then_removes_old_closed_cases(engine_factory, clock, tmp_path):
    store = new_store()
    eng = busy(engine_factory, store, clock)
    old = [i.id for i in eng.store.incidents()]
    clock.advance(days=400)
    fresh = eng.ingest(job_event(error="AUTH", ref="NEW", key="new"))            # open, and recent
    dry = retention.run(eng.store, clock(), 365)
    assert dry["applied"] is False and dry["would_remove"]["incidents"] == len(old)
    assert len(eng.store.incidents()) == len(old) + 1                          # nothing removed yet
    with pytest.raises(ValueError, match="archive directory"):
        retention.run(eng.store, clock(), 365, apply=True)
    with pytest.raises(ValueError, match="30 days"):
        retention.run(eng.store, clock(), 7)
    out = retention.run(eng.store, clock(), 365, archive_dir=tmp_path, apply=True)
    assert out["removed"]["incidents"] == len(old) and out["archived_rows"] > len(old)
    left = eng.store.incidents()
    assert [i.id for i in left] == [fresh.incident_id]
    assert eng.store.open_review_for(fresh.incident_id) is not None
    assert all(eng.store.get_disposition(i) is None for i in old)
    kinds = [a["kind"] for a in eng.store.recent_audit(50)]
    assert "config_published" in kinds and "retention_applied" in kinds
    with gzip.open(out["archive"], "rt") as f:
        rows = [json.loads(line) for line in f]
    tables = {r["table"] for r in rows}
    assert {"incidents", "events", "dispositions", "audit", "reviews"} <= tables
    assert sum(r["table"] == "incidents" for r in rows) == len(old)
    again = retention.run(eng.store, clock(), 365, archive_dir=tmp_path, apply=True)
    assert again["removed"].get("incidents", 0) == 0 and again["archive"] is None
    duckdb = pytest.importorskip("duckdb")
    sql = f"SELECT count(*) FROM read_json_auto('{out['archive']}') WHERE \"table\" = 'incidents'"
    n = duckdb.sql(sql).fetchone()[0]
    assert n == len(old)


def test_sqlite_backup_and_restore(engine_factory, clock, tmp_path):
    store = SQLiteStore(str(tmp_path / "live.db"))
    eng = busy(engine_factory, store, clock)
    before = len(eng.store.incidents())
    b = backup.backup(eng.store, tmp_path / "bk")
    assert b["rows"]["incidents"] == before and backup.verify(b["path"])["integrity"] == "ok"
    eng.ingest(job_event(error="AUTH", ref="LATER", key="later"))
    assert len(eng.store.incidents()) == before + 1
    backup.restore(eng.store, b["path"])
    assert len(eng.store.incidents()) == before
    p = tmp_path / "bk" / os.path.basename(b["path"])
    with open(p, "r+b") as f:                                                   # damage it
        f.seek(200)
        f.write(b"\x00garbage\x00")
    with pytest.raises(backup.BackupError, match="does not match"):
        backup.restore(eng.store, p)


def test_prune_keeps_the_newest(tmp_path, clock):
    store = SQLiteStore(str(tmp_path / "x.db"))
    for i in range(4):
        backup.backup(store, tmp_path / "bk", keep=2, now=clock() + timedelta(hours=i))
    names = sorted(p.name for p in (tmp_path / "bk").iterdir())
    assert len([n for n in names if n.endswith(".db")]) == 2 and len([n for n in names if n.endswith(".json")]) == 2


@pytest.mark.skipif(not os.environ.get("SENTINEL_TEST_PG"), reason="needs SENTINEL_TEST_PG")
def test_postgres_backup_and_restore(engine_factory, clock, tmp_path):
    store = new_store()
    eng = busy(engine_factory, store, clock)
    before = len(eng.store.incidents())
    try:
        b = backup.backup(eng.store, tmp_path)
    except backup.BackupError as e:
        pytest.skip(str(e))
    assert b["path"].endswith(".dump") and backup.verify(b["path"])["tables_with_data"] > 5
    eng.ingest(job_event(error="AUTH", ref="LATER", key="later"))
    backup.restore(eng.store, b["path"])
    assert len(eng.store.incidents()) == before
    eng.ingest(job_event(error="AUTH", ref="AFTER", key="after"))                # still works after the restore
    assert len(eng.store.incidents()) == before + 1


def test_cli(tmp_path, capsys, engine_factory, clock):
    db = str(tmp_path / "c.db")
    busy(engine_factory, SQLiteStore(db), clock)
    assert main(["--db", db, "backup", "--out", str(tmp_path / "b"), "--keep", "3"]) == 0
    made = json.loads(capsys.readouterr().out)
    assert main(["--db", db, "verify-backup", made["path"]]) == 0
    assert main(["--db", db, "restore", made["path"]]) == 2                          # needs --yes
    assert main(["--db", db, "restore", made["path"], "--yes"]) == 0
    assert main(["--db", db, "retention", "--keep-days", "365"]) == 0
    capsys.readouterr()
    assert main(["--db", db, "vectors-index", "--dim", "8"]) == 2


def test_retention_walks_many_batches(engine_factory, clock, tmp_path, monkeypatch):
    monkeypatch.setattr(retention, "BATCH", 3)            # force many small batches
    monkeypatch.setattr(retention, "CHUNK", 4)
    eng = engine_factory(store=new_store())
    for i in range(11):
        eng.ingest(job_event(ref=f"J{i}", system=f"s{i}", key=f"k{i}"))
    clock.advance(days=400)
    dry = retention.run(eng.store, clock(), 365)
    assert dry["would_remove"]["incidents"] == 11
    out = retention.run(eng.store, clock(), 365, archive_dir=tmp_path, apply=True)
    assert out["removed"]["incidents"] == 11 and eng.store.incidents() == []
