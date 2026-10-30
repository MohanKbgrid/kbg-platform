# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""Retention: archive and remove what is no longer needed in the live database.

    sentinel retention --keep-days 365 --archive-dir /var/backups/sentinel/archive        # what would go
    sentinel retention --keep-days 365 --archive-dir /var/backups/sentinel/archive --apply

What goes, once older than ``keep_days`` (by last change):

* closed incidents with everything that belongs to them - their events, reviews, deliveries, dispositions,
  action runs, audit entries, model calls, finished work items and similar-case vectors;
* model calls with no incident, and finished work items (after ``work_days``, default 30);
* events no incident refers to.

What stays: open cases of any age, the learning itself (trust earned per pattern and segment), the
configuration history, access tokens, and audit entries that are not about a case (configuration published,
access given, promotions) - those are the governance record. Removing old events also ends their
duplicate protection: an event re-sent after the retention period is treated as new.

Everything removed is first written to a gzip JSON-lines archive (one file per run, ``{"table", "row"}``
per line), which DuckDB reads directly: ``SELECT * FROM read_json_auto('archive-*.jsonl.gz')``.
Rows are written and fsynced before they are deleted, and each batch is deleted in one transaction.
"""
# ruff: noqa: S608 - table and column names are this module's constants; every value is a bound parameter
from __future__ import annotations

import gzip
import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

BATCH = 200
CHUNK = 900               # bound parameters per statement (well under SQLite's and PostgreSQL's limits)
CASE_TABLES = [            # (table, column holding the incident id)
    ("incident_events", "incident_id"), ("dispositions", "incident_id"), ("action_runs", "incident_id"),
    ("audit", "incident_id"), ("model_runs", "incident_id"), ("work_items", "incident_id"),
    ("case_vectors", "incident_id"),
]


class _Q:
    """The same SQL for both stores: `{s}.` prefixes and `?` placeholders."""

    def __init__(self, store: Any) -> None:
        self.store = store
        self.pg = type(store).__name__ == "PostgresStore"

    def __call__(self, sql: str, args: tuple | list = ()) -> list[dict[str, Any]]:
        sql = sql.replace("?", "%s") if self.pg else sql.replace("{s}.", "")
        cur = self.store._x(sql, tuple(args))
        try:
            rows = cur.fetchall()
        except Exception:  # noqa: BLE001 - statements without results
            return []
        return [dict(r) for r in rows]

    def tables(self) -> set[str]:
        if self.pg:
            return {r["table_name"] for r in self("SELECT table_name FROM information_schema.tables "
                                                  "WHERE table_schema = ?", (self.store.schema,))}
        return {r["name"] for r in self("SELECT name FROM sqlite_master WHERE type='table'")}


def _marks(n: int) -> str:
    return ",".join("?" * n)


class Archive:
    def __init__(self, directory: str | Path, now: datetime) -> None:
        self.dir = Path(directory)
        self.dir.mkdir(parents=True, exist_ok=True)
        import secrets
        self.path = self.dir / f"archive-{now.strftime('%Y%m%dT%H%M%SZ')}-{secrets.token_hex(3)}.jsonl.gz"
        self._f = gzip.open(self.path, "xt", encoding="utf-8")      # a new file, never one already there
        self.rows = 0

    def write(self, table: str, rows: list[dict[str, Any]]) -> None:
        for r in rows:
            self._f.write(json.dumps({"table": table, "row": r}, default=str) + "\n")
        self.rows += len(rows)

    def sync(self) -> None:
        self._f.flush()
        raw = getattr(self._f, "fileobj", None)
        if raw is not None:
            raw.flush()
            os.fsync(raw.fileno())

    def close(self) -> None:
        self._f.close()
        if self.rows == 0:                            # nothing was removed: no empty archive files
            self.path.unlink(missing_ok=True)


def run(store: Any, now: datetime, keep_days: float, *, archive_dir: str | Path | None = None,
        apply: bool = False, work_days: float = 30) -> dict[str, Any]:
    """Archive and delete (``apply=True``) or just count (the default). Returns counts per table."""
    if keep_days < 30:
        raise ValueError("keep at least 30 days (open cases are never removed, but recent history is needed)")
    if apply and archive_dir is None:
        raise ValueError("an archive directory is required to remove data")
    q = _Q(store)
    have = q.tables()
    cutoff = (now - timedelta(days=keep_days)).timestamp()
    work_cut = (now - timedelta(days=work_days)).timestamp()
    counts: dict[str, int] = {}
    arch = Archive(archive_dir, now) if (apply and archive_dir is not None) else None

    def take(table: str, where: str, args: list[Any]) -> list[dict[str, Any]]:
        if table not in have:
            return []
        rows = q(f"SELECT * FROM {{s}}.{table} WHERE {where}", args)
        counts[table] = counts.get(table, 0) + len(rows)
        return rows

    def remove(batch: dict[str, tuple[str, list[Any], list[dict[str, Any]]]]) -> None:
        if arch is None:
            return
        for key, (_, _, rows) in batch.items():
            arch.write(key.split("#")[0], rows)
        arch.sync()                                   # on disk before anything is deleted
        with store.transaction():
            for key, (where, args, rows) in batch.items():
                if rows:
                    if key == "audit":                # sealed rows leave their hash behind (auditchain)
                        from .auditchain import tombstone
                        tombstone(store, where, args, "retention", now.timestamp())
                    q(f"DELETE FROM {{s}}.{key.split('#')[0]} WHERE {where}", args)

    try:
        # 1. closed cases, in batches, walking the (updated_ts, id) index (no OFFSET: each batch costs the same)
        last: tuple[float, str] = (float("-inf"), "")
        while True:
            page = q("SELECT id, updated_ts FROM {s}.incidents WHERE state = 'dispositioned' AND updated_ts < ? "
                     "AND (updated_ts > ? OR (updated_ts = ? AND id > ?)) ORDER BY updated_ts, id LIMIT ?",
                     (cutoff, last[0], last[0], last[1], BATCH))
            if not page:
                break
            last = (page[-1]["updated_ts"], page[-1]["id"])
            ids = [r["id"] for r in page]
            m = _marks(len(ids))
            batch: dict[str, tuple[str, list[Any], list[dict[str, Any]]]] = {}
            revs = take("reviews", f"incident_id IN ({m})", ids)
            batch["reviews"] = (f"incident_id IN ({m})", ids, revs)
            rids = [r["id"] for r in revs]
            if rids:
                rm = _marks(len(rids))
                batch["deliveries"] = (f"review_id IN ({rm})", rids, take("deliveries", f"review_id IN ({rm})", rids))
            ev_ids = [r["event_id"] for r in q(f"SELECT event_id FROM {{s}}.incident_events WHERE incident_id IN ({m})",
                                                ids)]
            for table, col in CASE_TABLES:
                extra = " AND status IN ('done', 'dead')" if table == "work_items" else ""
                batch[table] = (f"{col} IN ({m}){extra}", ids, take(table, f"{col} IN ({m}){extra}", ids))
            ev_ids = sorted(set(ev_ids))
            keep: set[str] = set()                    # events a remaining case still refers to
            for i in range(0, len(ev_ids), CHUNK - BATCH):
                part = ev_ids[i:i + CHUNK - BATCH]
                keep |= {r["event_id"] for r in q(
                    f"SELECT event_id FROM {{s}}.incident_events WHERE event_id IN ({_marks(len(part))}) "
                    f"AND incident_id NOT IN ({m})", [*part, *ids])}
            gone = [e for e in ev_ids if e not in keep]
            for i in range(0, len(gone), CHUNK):
                part = gone[i:i + CHUNK]
                gm = _marks(len(part))
                batch[f"events#{i}"] = (f"id IN ({gm})", part, take("events", f"id IN ({gm})", part))
            batch["incidents"] = (f"id IN ({m})", ids, take("incidents", f"id IN ({m})", ids))
            remove(batch)
        # 2. loose rows, in bounded batches (never all of them in memory)
        loose = {
            "model_runs": ("incident_id IS NULL AND ts < ?", [cutoff]),
            "work_items": ("status IN ('done', 'dead') AND created_ts < ?", [work_cut]),
            "events": ("received_ts < ? AND NOT EXISTS (SELECT 1 FROM {s}.incident_events "
                       "WHERE incident_events.event_id = events.id)", [cutoff]),
        }
        for table, (where, args) in loose.items():
            if table not in have:
                continue
            if arch is None:                          # counting only
                n = q(f"SELECT COUNT(*) AS n FROM {{s}}.{table} WHERE {where}", args)[0]["n"]
                counts[table] = counts.get(table, 0) + int(n)
                continue
            while True:
                ids = [r["id"] for r in q(f"SELECT id FROM {{s}}.{table} WHERE {where} LIMIT ?", [*args, CHUNK])]
                if not ids:
                    break
                im = _marks(len(ids))
                remove({table: (f"id IN ({im})", ids, take(table, f"id IN ({im})", ids))})
                if len(ids) < CHUNK:
                    break
    finally:
        if arch is not None:
            arch.close()
    out: dict[str, Any] = {"applied": arch is not None, "cutoff": datetime.fromtimestamp(cutoff, UTC).isoformat(),
                           "removed" if arch is not None else "would_remove": dict(sorted(counts.items()))}
    if arch is not None:
        out["archive"] = str(arch.path) if arch.rows else None
        out["archived_rows"] = arch.rows
        store.audit(None, "retention_applied", {"keep_days": keep_days, "archive": out["archive"],
                                                "rows": arch.rows, "tables": dict(sorted(counts.items()))})
    return out
