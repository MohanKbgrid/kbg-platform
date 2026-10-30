# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""CLI round trip on a file-backed store, with a generic overlay."""
from __future__ import annotations

import json

from sentinel import Engine, SQLiteStore
from sentinel.cli import main
from tests.conftest import job_event
from tests.toy_overlay import build_overlay


def test_cli_queue_round_trip(tmp_path, capsys):
    db = str(tmp_path / "t.db")
    eng = Engine(build_overlay(), store=SQLiteStore(db))
    eng.ingest(job_event(error="AUTH", ref="J7"))
    eng.store.close()
    base = ["--overlay", "tests.toy_overlay:build_overlay", "--db", db]

    assert main(base + ["validate"]) == 0
    capsys.readouterr()
    assert main(base + ["reviews"]) == 0
    rows = json.loads(capsys.readouterr().out)
    assert len(rows) == 1 and rows[0]["role"] == "ops"
    rid = rows[0]["review"]
    assert main(base + ["modify", rid, "--action", "retry", "--params", '{"ref": "J7"}', "--by", "op"]) == 0
    assert json.loads(capsys.readouterr().out)["state"] == "dispositioned"
    assert main(base + ["approve", rid, "--by", "op"]) == 2          # closed review -> clean error, exit 2
    assert "closed" in capsys.readouterr().err
    assert main(base + ["report"]) == 0
    assert json.loads(capsys.readouterr().out)["patterns"]["job_failed_other"]["dispositions"] == 1


def test_cli_requires_overlay(monkeypatch, capsys):
    monkeypatch.delenv("SENTINEL_OVERLAY", raising=False)
    assert main(["report"]) == 2
    assert "--overlay" in capsys.readouterr().err
