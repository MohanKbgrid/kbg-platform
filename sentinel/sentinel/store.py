# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""Persistence.

`Store` is the contract. `SQLiteStore` is the reference implementation: zero
dependencies, durable on disk, usable in-memory for tests. A Postgres store
implements the same methods (see docs/PORTING.md); the SQL is deliberately
plain so it ports with minimal change.

Durability rules the engine relies on:
  * insert_event is the inbox: a duplicate dedupe_key returns False and the
    event is not processed again.
  * claim_action_run is the idempotency guard for side effects: a key can be
    claimed once; a second claim returns the earlier run instead.
  * transaction() makes a group of writes atomic.
"""
from __future__ import annotations

import json
import re
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime
from typing import Any, Protocol
from collections.abc import Iterator

from datetime import timedelta, UTC

from .observe import redact
from .models import Disposition, Event, Incident, IncidentState, PatternState, ReviewTask, WorkItem, utcnow

_SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
  id TEXT PRIMARY KEY, dedupe_key TEXT NOT NULL UNIQUE, tenant TEXT NOT NULL, type TEXT NOT NULL,
  body TEXT NOT NULL, received_ts REAL NOT NULL);
CREATE TABLE IF NOT EXISTS incidents (
  id TEXT PRIMARY KEY, tenant TEXT NOT NULL, pattern_id TEXT NOT NULL, fingerprint TEXT NOT NULL,
  state TEXT NOT NULL, parent_id TEXT, body TEXT NOT NULL, created_ts REAL NOT NULL, updated_ts REAL NOT NULL);
CREATE INDEX IF NOT EXISTS ix_inc_fp ON incidents(fingerprint, state);
CREATE INDEX IF NOT EXISTS ix_inc_pattern ON incidents(pattern_id, tenant, state);
CREATE INDEX IF NOT EXISTS ix_inc_parent ON incidents(parent_id);
CREATE INDEX IF NOT EXISTS ix_inc_state ON incidents(state, updated_ts);
CREATE TABLE IF NOT EXISTS incident_events (
  incident_id TEXT NOT NULL, event_id TEXT NOT NULL, seq INTEGER NOT NULL,
  PRIMARY KEY (incident_id, event_id));
CREATE TABLE IF NOT EXISTS reviews (
  id TEXT PRIMARY KEY, incident_id TEXT NOT NULL, is_open INTEGER NOT NULL, due_ts REAL NOT NULL, body TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS ix_rev_open ON reviews(is_open, due_ts);
CREATE INDEX IF NOT EXISTS ix_rev_inc ON reviews(incident_id);
CREATE INDEX IF NOT EXISTS ix_rev_open_role ON reviews(is_open, json_extract(body, '$.assignee_role'), due_ts);
CREATE TABLE IF NOT EXISTS dispositions (
  id TEXT PRIMARY KEY, incident_id TEXT NOT NULL UNIQUE, pattern_id TEXT NOT NULL, body TEXT NOT NULL,
  created_ts REAL NOT NULL);
CREATE INDEX IF NOT EXISTS ix_dsp_pattern ON dispositions(pattern_id, created_ts);
CREATE TABLE IF NOT EXISTS pattern_state (pattern_id TEXT PRIMARY KEY, body TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS action_runs (
  idempotency_key TEXT PRIMARY KEY, incident_id TEXT NOT NULL, action TEXT NOT NULL, status TEXT NOT NULL,
  result TEXT, created_ts REAL NOT NULL);
CREATE TABLE IF NOT EXISTS work_items (
  id TEXT PRIMARY KEY, kind TEXT NOT NULL, incident_id TEXT, payload TEXT NOT NULL, status TEXT NOT NULL,
  attempts INTEGER NOT NULL, max_attempts INTEGER NOT NULL, run_after_ts REAL NOT NULL, lease_until_ts REAL,
  leased_by TEXT, last_error TEXT, dedupe_key TEXT UNIQUE, created_ts REAL NOT NULL);
CREATE INDEX IF NOT EXISTS ix_work_ready ON work_items(status, run_after_ts);
CREATE TABLE IF NOT EXISTS deliveries (
  id TEXT PRIMARY KEY, review_id TEXT NOT NULL, person_id TEXT, edge TEXT NOT NULL, status TEXT NOT NULL,
  body TEXT NOT NULL, created_ts REAL NOT NULL);
CREATE INDEX IF NOT EXISTS ix_dlv_review ON deliveries(review_id);
CREATE TABLE IF NOT EXISTS audit (
  seq INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL, incident_id TEXT, kind TEXT NOT NULL, data TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS ix_audit_inc ON audit(incident_id, seq);
CREATE TABLE IF NOT EXISTS model_runs (
  id TEXT PRIMARY KEY, ts REAL NOT NULL, task TEXT NOT NULL, model TEXT NOT NULL, incident_id TEXT,
  ok INTEGER NOT NULL, shadow INTEGER NOT NULL, escalated INTEGER NOT NULL, latency_ms REAL NOT NULL,
  prompt_tokens INTEGER, completion_tokens INTEGER, chars_in INTEGER NOT NULL, chars_out INTEGER NOT NULL,
  est_cost REAL NOT NULL, fallback_reason TEXT, error TEXT);
CREATE INDEX IF NOT EXISTS ix_mrun_ts ON model_runs(ts);
CREATE INDEX IF NOT EXISTS ix_mrun_inc ON model_runs(incident_id);
CREATE INDEX IF NOT EXISTS ix_actrun_inc ON action_runs(incident_id);
CREATE INDEX IF NOT EXISTS ix_audit_ts ON audit(ts);
CREATE INDEX IF NOT EXISTS ix_work_done ON work_items(status, created_ts);
CREATE INDEX IF NOT EXISTS ix_work_inc ON work_items(incident_id);
CREATE INDEX IF NOT EXISTS ix_incev_event ON incident_events(event_id);
CREATE INDEX IF NOT EXISTS ix_events_ts ON events(received_ts);
CREATE INDEX IF NOT EXISTS ix_inc_created ON incidents(created_ts, id);
CREATE TABLE IF NOT EXISTS case_vectors (
  incident_id TEXT PRIMARY KEY, pattern_id TEXT NOT NULL, tenant TEXT NOT NULL, model TEXT NOT NULL,
  dim INTEGER NOT NULL, vec TEXT NOT NULL, created_ts REAL NOT NULL);
CREATE INDEX IF NOT EXISTS ix_cvec_pattern ON case_vectors(pattern_id, tenant, model, created_ts);
CREATE TABLE IF NOT EXISTS config_versions (
  id TEXT PRIMARY KEY, kind TEXT NOT NULL, version INTEGER NOT NULL, status TEXT NOT NULL, body TEXT NOT NULL,
  created_ts REAL NOT NULL, UNIQUE (kind, version));
CREATE TABLE IF NOT EXISTS source_state (name TEXT PRIMARY KEY, body TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS api_tokens (id TEXT PRIMARY KEY, hash TEXT NOT NULL UNIQUE, body TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS audit_seals (
  seal_no INTEGER PRIMARY KEY, from_no INTEGER NOT NULL, to_no INTEGER NOT NULL, batch_digest TEXT NOT NULL,
  prev_hash TEXT NOT NULL, seal_hash TEXT NOT NULL, signature TEXT, created_ts REAL NOT NULL);
CREATE TABLE IF NOT EXISTS audit_tombstones (
  chain_no INTEGER PRIMARY KEY, row_hash TEXT NOT NULL, removed_ts REAL NOT NULL, reason TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS audit_redactions (
  chain_no INTEGER PRIMARY KEY, original_hash TEXT NOT NULL, redacted_hash TEXT NOT NULL, redacted_ts REAL NOT NULL);
"""

_OPEN_STATES = tuple(s.value for s in IncidentState if not s.terminal)


_FACT_KEY = re.compile(r"^[A-Za-z0-9_\-]{1,64}$")


def _fact_key(k: str) -> str:
    if not _FACT_KEY.match(k):
        raise ValueError(f"fact name {k!r}: letters, digits, _ and - only")
    return k


def _search_where(pattern: str | None, state: str | None, tenant: str | None, since_ts: float | None,
                  until_ts: float | None, text: str | None, before: tuple[float, str] | None,
                  ph: str) -> tuple[list[str], list[Any]]:
    """Filters shared by both stores (``ph`` is the placeholder: ? or %s)."""
    where: list[str] = []
    args: list[Any] = []
    for col, v in (("pattern_id", pattern), ("state", state), ("tenant", tenant)):
        if v:
            where.append(f"{col} = {ph}")
            args.append(v)
    if since_ts is not None:
        where.append(f"created_ts >= {ph}")
        args.append(since_ts)
    if until_ts is not None:
        where.append(f"created_ts < {ph}")
        args.append(until_ts)
    if text:
        t = text.strip()
        like = "%" + t.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
        body = "body" if ph == "?" else "body::text"      # facts and the first event, as stored
        op = "LIKE" if ph == "?" else "ILIKE"             # SQLite LIKE ignores ASCII case already
        where.append(f"(id = {ph} OR fingerprint {op} {ph} ESCAPE '\\' OR {body} {op} {ph} ESCAPE '\\')")
        args += [t, like, like]
    if before is not None:
        where.append(f"(created_ts < {ph} OR (created_ts = {ph} AND id < {ph}))")
        args += [before[0], before[0], before[1]]
    return where, args


def _ts(dt: datetime) -> float:
    try:
        return dt.timestamp()
    except (OverflowError, OSError, ValueError):
        return float("-inf")


class _Result:
    """Fully-fetched query result, safe to use after the store lock is released."""

    __slots__ = ("_rows", "rowcount")

    def __init__(self, rows: list[Any], rowcount: int) -> None:
        self._rows = rows
        self.rowcount = rowcount

    def fetchone(self) -> Any:
        return self._rows[0] if self._rows else None

    def fetchall(self) -> list[Any]:
        return list(self._rows)

    def __iter__(self):
        return iter(self._rows)


class Store(Protocol):
    def transaction(self) -> Any: ...
    def lock(self, key: str) -> None: ...
    def mutex(self, key: str) -> Any: ...
    def close_review(self, review_id: str) -> bool: ...
    def insert_event(self, event: Event) -> bool: ...
    def event_seen(self, dedupe_key: str) -> bool: ...
    def get_event(self, event_id: str) -> Event | None: ...
    def update_event(self, event: Event) -> None: ...
    def update_audit_data(self, seq: int, data: dict[str, Any]) -> None: ...
    def delete_case_vector(self, incident_id: str) -> None: ...
    def put_incident(self, inc: Incident) -> None: ...
    def update_facts(self, incident_id: str, facts: dict[str, Any], states: list[str]) -> bool: ...
    def get_incident(self, incident_id: str) -> Incident | None: ...
    def find_open_incident(self, fingerprint: str, since: datetime) -> Incident | None: ...
    def open_incidents(self, pattern_id: str, tenant: str) -> list[Incident]: ...
    def children(self, parent_id: str) -> list[Incident]: ...
    def incidents(self, state: IncidentState | None = None) -> list[Incident]: ...
    def attach_event(self, incident_id: str, event_id: str) -> int: ...
    def event_ids(self, incident_id: str) -> list[str]: ...
    def put_review(self, r: ReviewTask) -> None: ...
    def get_review(self, review_id: str) -> ReviewTask | None: ...
    def open_review_for(self, incident_id: str) -> ReviewTask | None: ...
    def reviews_for_incident(self, incident_id: str) -> list[ReviewTask]: ...
    def open_reviews(self, due_before: datetime | None = None) -> list[ReviewTask]: ...
    def review_counts(self, now: datetime) -> dict[str, int]: ...
    def open_reviews_for_roles(self, roles: list[str] | None, limit: int = 200,
                               offset: int = 0) -> list[tuple[ReviewTask, dict[str, Any]]]: ...
    def open_reviews_of_pattern(self, pattern_id: str, limit: int = 1000) -> list[tuple[ReviewTask, dict[str, Any]]]:
        ...
    def count_open_reviews_of_pattern(self, pattern_id: str) -> int: ...
    def disposition_stats(self) -> dict[str, dict[str, int]]: ...
    def put_disposition(self, d: Disposition) -> None: ...
    def get_disposition(self, incident_id: str) -> Disposition | None: ...
    def dispositions(self, pattern_id: str | None = None) -> list[Disposition]: ...
    def get_pattern_state(self, pattern_id: str) -> PatternState | None: ...
    def count_unattended(self, pattern_id: str, since: datetime, cap: int) -> int: ...
    def recent_dispositions(self, pattern_id: str, limit: int) -> list[Disposition]: ...
    def put_pattern_state(self, s: PatternState) -> None: ...
    def pattern_states(self, prefix: str) -> list[PatternState]: ...
    def claim_action_run(self, key: str, incident_id: str, action: str) -> dict[str, Any] | None: ...
    def release_action_run(self, key: str) -> None: ...
    def finish_action_run(self, key: str, status: str, result: dict[str, Any]) -> None: ...
    def audit(self, incident_id: str | None, kind: str, data: dict[str, Any] | None = None) -> None: ...
    def enqueue(self, item: WorkItem) -> bool: ...
    def lease(self, worker_id: str, now: datetime, limit: int, lease_seconds: float) -> list[WorkItem]: ...
    def complete(self, item_id: str, worker_id: str) -> bool: ...
    def extend_lease(self, item_id: str, worker_id: str, until: datetime) -> bool: ...
    def fail(self, item_id: str, worker_id: str, error: str, retry_at: datetime | None) -> str | None: ...
    def get_work(self, item_id: str) -> WorkItem | None: ...
    def live_work_for(self, incident_id: str, kind: str) -> int: ...
    def put_delivery(self, d: Any) -> None: ...
    def deliveries(self, review_id: str) -> list[Any]: ...
    def queue_stats(self, now: datetime) -> dict[str, Any]: ...
    def audit_log(self, incident_id: str | None = None) -> list[dict[str, Any]]: ...
    def put_model_run(self, run: Any) -> None: ...
    def model_runs(self, since_ts: float | None = None) -> list[dict[str, Any]]: ...
    def model_runs_for(self, incident_id: str) -> list[dict[str, Any]]: ...
    def usage_rows(self, since_ts: float, until_ts: float) -> dict[str, list[dict[str, Any]]]: ...
    def action_runs_for(self, incident_id: str) -> list[dict[str, Any]]: ...
    def search_incidents(self, *, pattern: str | None = None, state: str | None = None, tenant: str | None = None,
                         since_ts: float | None = None, until_ts: float | None = None,
                         facts: dict[str, str] | None = None, text: str | None = None,
                         before: tuple[float, str] | None = None, limit: int = 50) -> list[Incident]: ...
    def put_case_vector(self, incident_id: str, pattern_id: str, tenant: str, model: str,
                        vec: list[float]) -> None: ...
    def has_case_vector(self, incident_id: str, model: str) -> bool: ...
    def add_config_version(self, kind: str, make: Any) -> Any: ...
    def put_config_version(self, cv: Any) -> None: ...
    def get_config_version(self, version_id: str) -> Any: ...
    def config_versions(self, kind: str) -> list[Any]: ...
    def published_config(self, kind: str) -> Any: ...
    def get_source_state(self, name: str) -> dict[str, Any] | None: ...
    def put_source_state(self, name: str, state: dict[str, Any]) -> None: ...
    def recent_audit(self, limit: int = 100, kinds: list[str] | None = None) -> list[dict[str, Any]]: ...
    def model_spend_since(self, ts: float) -> float: ...
    def put_api_token(self, t: Any) -> None: ...
    def api_token_by_hash(self, h: str) -> Any: ...
    def api_tokens(self) -> list[Any]: ...
    def similar_cases(self, pattern_id: str, tenant: str, model: str, vec: list[float], k: int,
                      exclude: str | None = None) -> list[tuple[str, float]]: ...


class SQLiteStore:
    def __init__(self, path: str = ":memory:", synchronous: str = "FULL") -> None:
        self.path = path
        self._lock = threading.RLock()
        self._depth = 0
        self._conn = sqlite3.connect(path, check_same_thread=False, isolation_level=None, timeout=30)
        self._conn.row_factory = sqlite3.Row
        if path != ":memory:":
            self._conn.execute("PRAGMA journal_mode=WAL")
            if synchronous.upper() not in ("FULL", "NORMAL"):
                raise ValueError("synchronous must be FULL or NORMAL")
            # FULL survives power loss; NORMAL (WAL) survives process crashes and is much faster
            self._conn.execute(f"PRAGMA synchronous={synchronous.upper()}")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.executescript(_SCHEMA)
        self._migrate()

    def _migrate(self) -> None:
        """Idempotent upgrades for databases created by older versions."""
        cols = {r[1] for r in self._conn.execute("PRAGMA table_info(dispositions)").fetchall()}
        if "unattended" not in cols:
            self._conn.execute("ALTER TABLE dispositions ADD COLUMN unattended INTEGER NOT NULL DEFAULT 0")
            self._conn.execute("UPDATE dispositions SET unattended = CASE WHEN json_extract(body, '$.resolver') "
                               "IN ('auto','llm') AND json_extract(body, '$.shadow') = 0 THEN 1 ELSE 0 END")
        self._conn.execute("CREATE INDEX IF NOT EXISTS ix_dsp_unattended ON dispositions(pattern_id, unattended, "
                           "created_ts)")
        self._conn.execute("CREATE INDEX IF NOT EXISTS ix_rev_inc_open ON reviews(incident_id, is_open)")
        acols = {r[1] for r in self._conn.execute("PRAGMA table_info(audit)").fetchall()}
        if "chain_no" not in acols:                      # tamper-evident audit (sentinel.auditchain)
            self._conn.execute("ALTER TABLE audit ADD COLUMN chain_no INTEGER")
            self._conn.execute("ALTER TABLE audit ADD COLUMN row_hash TEXT")
        self._conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS ix_audit_chain ON audit(chain_no)")
        self._conn.execute("CREATE INDEX IF NOT EXISTS ix_audit_unsealed ON audit(seq) WHERE chain_no IS NULL")

    # ---- transactions -------------------------------------------------
    @contextmanager
    def transaction(self) -> Iterator[None]:
        with self._lock:
            outer = self._depth == 0
            if outer:
                self._conn.execute("BEGIN IMMEDIATE")
            self._depth += 1
            try:
                yield
            except BaseException:
                self._depth -= 1
                if outer:
                    self._conn.execute("ROLLBACK")
                raise
            else:
                self._depth -= 1
                if outer:
                    self._conn.execute("COMMIT")

    def lock(self, key: str) -> None:
        """Cross-process lock hook. SQLite is single-writer already, so this is a no-op."""

    @contextmanager
    def mutex(self, key: str) -> Iterator[None]:
        """Held across a long step without a transaction. One process per SQLite file: nothing to do."""
        yield

    def close_review(self, review_id: str) -> bool:
        """Close a review if it is still open. False when someone else closed it first."""
        cur = self._x("UPDATE reviews SET is_open=0, body=json_set(body, '$.open', json('false')) "
                      "WHERE id=? AND is_open=1", (review_id,))
        return cur.rowcount == 1

    def _x(self, sql: str, args: tuple = ()) -> _Result:
        # execute AND fetch under the lock: a shared connection must never be read by two threads at once
        with self._lock:
            cur = self._conn.execute(sql, args)
            rows = cur.fetchall() if cur.description is not None else []
            return _Result(rows, cur.rowcount)

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def __del__(self) -> None:  # best effort; explicit close() preferred
        try:
            self._conn.close()
        except Exception:  # noqa: BLE001, S110 - interpreter shutdown; nothing useful to do
            pass

    # ---- events -------------------------------------------------------
    def insert_event(self, event: Event) -> bool:
        try:
            self._x("INSERT INTO events(id, dedupe_key, tenant, type, body, received_ts) VALUES (?,?,?,?,?,?)",
                    (event.id, event.dedupe_key, event.tenant, event.type, event.model_dump_json(), _ts(utcnow())))
            return True
        except sqlite3.IntegrityError:
            return False

    def event_seen(self, dedupe_key: str) -> bool:
        """True when an event with this dedupe key is already in the inbox."""
        return self._x("SELECT 1 FROM events WHERE dedupe_key=?", (dedupe_key,)).fetchone() is not None

    def update_event(self, event: Event) -> None:
        """Rewrite a stored event's body (privacy erasure and scrubbing only; ids and keys stay)."""
        self._x("UPDATE events SET body=? WHERE id=?", (event.model_dump_json(), event.id))

    def update_audit_data(self, seq: int, data: dict[str, Any]) -> None:
        self._x("UPDATE audit SET data=? WHERE seq=?", (json.dumps(data, default=str), seq))

    def delete_case_vector(self, incident_id: str) -> None:
        self._x("DELETE FROM case_vectors WHERE incident_id=?", (incident_id,))

    def get_event(self, event_id: str) -> Event | None:
        row = self._x("SELECT body FROM events WHERE id=?", (event_id,)).fetchone()
        return Event.model_validate_json(row["body"]) if row else None

    # ---- incidents ----------------------------------------------------
    def put_incident(self, inc: Incident) -> None:
        self._x(
            "INSERT INTO incidents(id, tenant, pattern_id, fingerprint, state, parent_id, body, created_ts, "
            "updated_ts) "
            "VALUES (?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET state=excluded.state, "
            "parent_id=excluded.parent_id, body=excluded.body, updated_ts=excluded.updated_ts, "
            "pattern_id=excluded.pattern_id",
            (inc.id, inc.tenant, inc.pattern_id, inc.fingerprint, inc.state.value, inc.parent_id,
             inc.model_dump_json(), _ts(inc.created_at), _ts(inc.updated_at)))

    def get_incident(self, incident_id: str) -> Incident | None:
        row = self._x("SELECT body FROM incidents WHERE id=?", (incident_id,)).fetchone()
        return Incident.model_validate_json(row["body"]) if row else None

    def find_open_incident(self, fingerprint: str, since: datetime) -> Incident | None:
        q = ("SELECT body FROM incidents WHERE fingerprint=? AND created_ts>=? AND state IN (%s) "  # noqa: S608
             "ORDER BY created_ts DESC LIMIT 1" % ",".join("?" * len(_OPEN_STATES)))
        row = self._x(q, (fingerprint, _ts(since), *_OPEN_STATES)).fetchone()
        return Incident.model_validate_json(row["body"]) if row else None

    def open_incidents(self, pattern_id: str, tenant: str) -> list[Incident]:
        q = ("SELECT body FROM incidents WHERE pattern_id=? AND tenant=? AND state IN (%s) "  # noqa: S608
             "ORDER BY created_ts, rowid" % ",".join("?" * len(_OPEN_STATES)))
        return [Incident.model_validate_json(r["body"]) for r in self._x(q, (pattern_id, tenant, *_OPEN_STATES))]

    def children(self, parent_id: str) -> list[Incident]:
        return [Incident.model_validate_json(r["body"])
                for r in self._x("SELECT body FROM incidents WHERE parent_id=? ORDER BY created_ts, rowid",
                                 (parent_id,))]

    def incidents(self, state: IncidentState | None = None) -> list[Incident]:
        if state is None:
            rows = self._x("SELECT body FROM incidents ORDER BY created_ts, rowid")
        else:
            rows = self._x("SELECT body FROM incidents WHERE state=? ORDER BY created_ts, rowid", (state.value,))
        return [Incident.model_validate_json(r["body"]) for r in rows]

    def attach_event(self, incident_id: str, event_id: str) -> int:
        """Link an event to an incident without touching the incident row. Returns the new event count."""
        with self.transaction():
            n = self._x("SELECT COUNT(*) AS n FROM incident_events WHERE incident_id=?", (incident_id,)).fetchone()["n"]
            self._x("INSERT OR IGNORE INTO incident_events(incident_id, event_id, seq) VALUES (?,?,?)",
                    (incident_id, event_id, n))
            return n + 1

    def event_ids(self, incident_id: str) -> list[str]:
        return [r["event_id"] for r in
                self._x("SELECT event_id FROM incident_events WHERE incident_id=? ORDER BY seq", (incident_id,))]

    # ---- reviews ------------------------------------------------------
    def put_review(self, r: ReviewTask) -> None:
        self._x("INSERT INTO reviews(id, incident_id, is_open, due_ts, body) VALUES (?,?,?,?,?) "
                "ON CONFLICT(id) DO UPDATE SET is_open=excluded.is_open, due_ts=excluded.due_ts, body=excluded.body",
                (r.id, r.incident_id, int(r.open), _ts(r.due_at), r.model_dump_json()))

    def get_review(self, review_id: str) -> ReviewTask | None:
        row = self._x("SELECT body FROM reviews WHERE id=?", (review_id,)).fetchone()
        return ReviewTask.model_validate_json(row["body"]) if row else None

    def open_review_for(self, incident_id: str) -> ReviewTask | None:
        row = self._x("SELECT body FROM reviews WHERE incident_id=? AND is_open=1 LIMIT 1", (incident_id,)).fetchone()
        return ReviewTask.model_validate_json(row["body"]) if row else None

    def reviews_for_incident(self, incident_id: str) -> list[ReviewTask]:
        return [ReviewTask.model_validate_json(r["body"])
                for r in self._x("SELECT body FROM reviews WHERE incident_id=?", (incident_id,))]

    def open_reviews(self, due_before: datetime | None = None) -> list[ReviewTask]:
        if due_before is None:
            rows = self._x("SELECT body FROM reviews WHERE is_open=1 ORDER BY due_ts")
        else:
            rows = self._x("SELECT body FROM reviews WHERE is_open=1 AND due_ts<? ORDER BY due_ts", (_ts(due_before),))
        return [ReviewTask.model_validate_json(r["body"]) for r in rows]

    def review_counts(self, now: datetime) -> dict[str, int]:
        r = self._x("SELECT COUNT(*) AS n, COALESCE(SUM(CASE WHEN due_ts < ? THEN 1 ELSE 0 END), 0) AS overdue "
                    "FROM reviews WHERE is_open=1", (_ts(now),)).fetchone()
        return {"open": int(r["n"]), "overdue": int(r["overdue"])}

    def open_reviews_for_roles(self, roles: list[str] | None, limit: int = 200,
                               offset: int = 0) -> list[tuple[ReviewTask, dict[str, Any]]]:
        """Open reviews (with their incident's facts) for these roles, soonest due first; None = all roles."""
        sql = ("SELECT r.body AS rb, i.body AS ib FROM reviews r JOIN incidents i ON i.id = r.incident_id "
               "WHERE r.is_open=1")
        args: list[Any] = []
        if roles is not None:
            if not roles:
                return []
            sql += f" AND json_extract(r.body, '$.assignee_role') IN ({','.join('?' * len(roles))})"
            args += list(roles)
        sql += " ORDER BY r.due_ts LIMIT ? OFFSET ?"
        rows = self._x(sql, (*args, limit, offset))
        return [(ReviewTask.model_validate_json(x["rb"]), json.loads(x["ib"]).get("facts") or {}) for x in rows]

    def open_reviews_of_pattern(self, pattern_id: str, limit: int = 1000) -> list[tuple[ReviewTask, dict[str, Any]]]:
        """Open reviews of one pattern with their incident (facts, first event), soonest due first."""
        rows = self._x("SELECT r.body AS rb, i.body AS ib FROM reviews r JOIN incidents i ON i.id = r.incident_id "
                       "WHERE r.is_open=1 AND i.pattern_id=? ORDER BY r.due_ts LIMIT ?", (pattern_id, limit))
        return [(ReviewTask.model_validate_json(x["rb"]), json.loads(x["ib"])) for x in rows]

    def count_open_reviews_of_pattern(self, pattern_id: str) -> int:
        row = self._x("SELECT COUNT(*) AS n FROM reviews r JOIN incidents i ON i.id = r.incident_id "
                      "WHERE r.is_open=1 AND i.pattern_id=?", (pattern_id,)).fetchone()
        return int(row["n"]) if row else 0

    def disposition_stats(self) -> dict[str, dict[str, int]]:
        """Counts per pattern for the report, computed in the database."""
        j = "json_extract(body, '$.{}')"
        res, sh = j.format("resolver"), j.format("shadow")
        ag, oc = j.format("agreed_with_proposal"), j.format("outcome")
        # only this method's own column expressions are interpolated
        rows = self._x(
            f"SELECT pattern_id, COUNT(*) AS n, "  # noqa: S608
            f"SUM(CASE WHEN {res}='auto' THEN 1 ELSE 0 END) AS auto, "
            f"SUM(CASE WHEN {res}='llm' THEN 1 ELSE 0 END) AS llm, "
            f"SUM(CASE WHEN {res}='human' THEN 1 ELSE 0 END) AS human, "
            f"SUM(CASE WHEN {res}='parent' THEN 1 ELSE 0 END) AS parent, "
            f"SUM(CASE WHEN {sh}=0 AND {res}!='parent' THEN 1 ELSE 0 END) AS real, "
            f"SUM(CASE WHEN {sh}=0 AND {res} IN ('auto','llm') THEN 1 ELSE 0 END) AS real_unattended, "
            f"SUM(CASE WHEN {sh}=1 AND {ag} IS NOT NULL THEN 1 ELSE 0 END) AS shadow_n, "
            f"SUM(CASE WHEN {sh}=1 AND {ag}=1 THEN 1 ELSE 0 END) AS shadow_agreed, "
            f"SUM(CASE WHEN {oc} IN ('held','failed') THEN 1 ELSE 0 END) AS outcome_n, "
            f"SUM(CASE WHEN {oc}='held' THEN 1 ELSE 0 END) AS outcome_held "
            "FROM dispositions GROUP BY pattern_id")
        return {r["pattern_id"]: {k: int(r[k] or 0) for k in r.keys() if k != "pattern_id"} for r in rows}

    # ---- dispositions -------------------------------------------------
    def put_disposition(self, d: Disposition) -> None:
        unattended = int(d.resolver in ("auto", "llm") and not d.shadow)
        self._x("INSERT INTO dispositions(id, incident_id, pattern_id, body, created_ts, unattended) "
                "VALUES (?,?,?,?,?,?) ON CONFLICT(incident_id) DO UPDATE SET body=excluded.body",
                (d.id, d.incident_id, d.pattern_id, d.model_dump_json(), _ts(d.created_at), unattended))

    def get_disposition(self, incident_id: str) -> Disposition | None:
        row = self._x("SELECT body FROM dispositions WHERE incident_id=?", (incident_id,)).fetchone()
        return Disposition.model_validate_json(row["body"]) if row else None

    def dispositions(self, pattern_id: str | None = None) -> list[Disposition]:
        if pattern_id is None:
            rows = self._x("SELECT body FROM dispositions ORDER BY created_ts")
        else:
            rows = self._x("SELECT body FROM dispositions WHERE pattern_id=? ORDER BY created_ts", (pattern_id,))
        return [Disposition.model_validate_json(r["body"]) for r in rows]

    def count_unattended(self, pattern_id: str, since: datetime, cap: int) -> int:
        """Unattended (auto/llm, non-shadow) resolutions since a time, counted up to `cap` only:
        the circuit breaker just needs to know whether the limit is reached, so cost is bounded by it."""
        done = self._x("SELECT COUNT(*) AS n FROM (SELECT 1 FROM dispositions WHERE pattern_id=? AND unattended=1 "
                       "AND created_ts>=? LIMIT ?)", (pattern_id, _ts(since), cap)).fetchone()["n"]
        flying = self._x("SELECT COUNT(*) AS n FROM (SELECT 1 FROM incidents WHERE pattern_id=? AND state IN "
                         "('resolving','resolved') LIMIT ?)", (pattern_id, cap)).fetchone()["n"]
        return int(done) + int(flying)            # in flight counts too: workers cannot overshoot together

    def recent_dispositions(self, pattern_id: str, limit: int) -> list[Disposition]:
        rows = self._x("SELECT body FROM dispositions WHERE pattern_id=? ORDER BY created_ts DESC LIMIT ?",
                       (pattern_id, limit))
        return [Disposition.model_validate_json(r["body"]) for r in reversed(rows.fetchall())]

    # ---- learned pattern state ---------------------------------------
    def get_pattern_state(self, pattern_id: str) -> PatternState | None:
        row = self._x("SELECT body FROM pattern_state WHERE pattern_id=?", (pattern_id,)).fetchone()
        return PatternState.model_validate_json(row["body"]) if row else None

    def put_pattern_state(self, s: PatternState) -> None:
        self._x("INSERT INTO pattern_state(pattern_id, body) VALUES (?,?) "
                "ON CONFLICT(pattern_id) DO UPDATE SET body=excluded.body", (s.pattern_id, s.model_dump_json()))

    def pattern_states(self, prefix: str) -> list[PatternState]:
        rows = self._x("SELECT body FROM pattern_state WHERE substr(pattern_id, 1, ?) = ? ORDER BY pattern_id",
                       (len(prefix), prefix))
        return [PatternState.model_validate_json(r["body"]) for r in rows]

    # ---- action idempotency ------------------------------------------
    def claim_action_run(self, key: str, incident_id: str, action: str) -> dict[str, Any] | None:
        """Claim a key. Returns None if newly claimed, else the existing run row."""
        with self.transaction():
            row = self._x("SELECT * FROM action_runs WHERE idempotency_key=?", (key,)).fetchone()
            if row:
                return {"status": row["status"], "action": row["action"],
                        "result": json.loads(row["result"]) if row["result"] else None}
            self._x("INSERT INTO action_runs(idempotency_key, incident_id, action, status, created_ts) "
                    "VALUES (?,?,?,?,?)", (key, incident_id, action, "running", _ts(utcnow())))
            return None

    def finish_action_run(self, key: str, status: str, result: dict[str, Any]) -> None:
        self._x("UPDATE action_runs SET status=?, result=? WHERE idempotency_key=?",
                (status, json.dumps(result, default=str), key))

    def release_action_run(self, key: str) -> None:
        """Allow a failed run's key to be retried."""
        self._x("DELETE FROM action_runs WHERE idempotency_key=? AND status!='ok'", (key,))

    # ---- work queue ---------------------------------------------------
    @staticmethod
    def _work(row: Any) -> WorkItem:
        def dt(v: Any) -> datetime | None:
            return None if v is None else datetime.fromtimestamp(v, tz=UTC)
        return WorkItem(id=row["id"], kind=row["kind"], incident_id=row["incident_id"],
                        payload=json.loads(row["payload"]) if isinstance(row["payload"], str) else row["payload"],
                        status=row["status"], attempts=row["attempts"], max_attempts=row["max_attempts"],
                        run_after=dt(row["run_after_ts"]), lease_until=dt(row["lease_until_ts"]),
                        leased_by=row["leased_by"], last_error=row["last_error"], dedupe_key=row["dedupe_key"])

    def enqueue(self, item: WorkItem) -> bool:
        """Queue work. A duplicate dedupe_key is ignored (returns False)."""
        try:
            self._x("INSERT INTO work_items(id, kind, incident_id, payload, status, attempts, max_attempts, "
                    "run_after_ts, lease_until_ts, leased_by, last_error, dedupe_key, created_ts) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (item.id, item.kind, item.incident_id, json.dumps(item.payload, default=str), "queued", 0,
                     item.max_attempts, _ts(item.run_after), None, None, None, item.dedupe_key, _ts(utcnow())))
            return True
        except sqlite3.IntegrityError:
            return False

    def lease(self, worker_id: str, now: datetime, limit: int, lease_seconds: float) -> list[WorkItem]:
        """Atomically take up to `limit` ready items (or items whose lease expired)."""
        with self.transaction():
            rows = self._x("SELECT id FROM work_items WHERE (status='queued' AND run_after_ts<=?) "
                           "OR (status='leased' AND lease_until_ts<?) ORDER BY run_after_ts LIMIT ?",
                           (_ts(now), _ts(now), limit)).fetchall()
            ids = [r["id"] for r in rows]
            until = _ts(now + timedelta(seconds=lease_seconds))
            for i in ids:
                self._x("UPDATE work_items SET status='leased', attempts=attempts+1, lease_until_ts=?, leased_by=? "
                        "WHERE id=?", (until, worker_id, i))
            return [self._work(self._x("SELECT * FROM work_items WHERE id=?", (i,)).fetchone()) for i in ids]

    def complete(self, item_id: str, worker_id: str) -> bool:
        cur = self._x("UPDATE work_items SET status='done', lease_until_ts=NULL WHERE id=? AND status='leased' "
                      "AND leased_by=?", (item_id, worker_id))
        return cur.rowcount == 1

    def extend_lease(self, item_id: str, worker_id: str, until: datetime) -> bool:
        """Keep a lease while the work runs; False if it was lost (expired and taken by someone else)."""
        cur = self._x("UPDATE work_items SET lease_until_ts=? WHERE id=? AND status='leased' AND leased_by=?",
                      (_ts(until), item_id, worker_id))
        return cur.rowcount == 1

    def fail(self, item_id: str, worker_id: str, error: str, retry_at: datetime | None) -> str | None:
        """Record a failure. Returns the new status (queued | dead) or None if the lease was lost."""
        with self.transaction():
            row = self._x("SELECT attempts, max_attempts FROM work_items WHERE id=? AND status='leased' "
                          "AND leased_by=?", (item_id, worker_id)).fetchone()
            if row is None:
                return None
            dead = retry_at is None or row["attempts"] >= row["max_attempts"]
            status = "dead" if dead else "queued"
            self._x("UPDATE work_items SET status=?, last_error=?, lease_until_ts=NULL, run_after_ts=COALESCE(?, "
                    "run_after_ts) WHERE id=?", (status, error[:2000], None if dead else _ts(retry_at), item_id))
            return status

    def live_work_for(self, incident_id: str, kind: str) -> int:
        return self._x("SELECT COUNT(*) AS n FROM work_items WHERE incident_id=? AND kind=? AND status IN "
                       "('queued','leased')", (incident_id, kind)).fetchone()["n"]

    def get_work(self, item_id: str) -> WorkItem | None:
        row = self._x("SELECT * FROM work_items WHERE id=?", (item_id,)).fetchone()
        return self._work(row) if row else None

    def queue_stats(self, now: datetime) -> dict[str, Any]:
        rows = self._x("SELECT status, COUNT(*) AS n FROM work_items GROUP BY status").fetchall()
        counts = {r["status"]: r["n"] for r in rows}
        oldest = self._x("SELECT MIN(run_after_ts) AS t FROM work_items WHERE status='queued' AND run_after_ts<=?",
                         (_ts(now),)).fetchone()["t"]
        return {"counts": counts, "oldest_ready_age_s": round(_ts(now) - oldest, 3) if oldest else 0.0}

    # ---- deliveries ---------------------------------------------------
    def put_delivery(self, d: Any) -> None:
        self._x("INSERT INTO deliveries(id, review_id, person_id, edge, status, body, created_ts) VALUES "
                "(?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET status=excluded.status, body=excluded.body",
                (d.id, d.review_id, d.person_id, d.edge, d.status, d.model_dump_json(), _ts(d.created_at)))

    def deliveries(self, review_id: str) -> list[Any]:
        from .edges import Delivery
        return [Delivery.model_validate_json(r["body"]) for r in
                self._x("SELECT body FROM deliveries WHERE review_id=? ORDER BY created_ts", (review_id,))]

    # ---- audit --------------------------------------------------------
    def audit(self, incident_id: str | None, kind: str, data: dict[str, Any] | None = None) -> None:
        self._x("INSERT INTO audit(ts, incident_id, kind, data) VALUES (?,?,?,?)",
                (_ts(utcnow()), incident_id, kind, json.dumps(redact(data or {}), default=str)))

    def audit_log(self, incident_id: str | None = None) -> list[dict[str, Any]]:
        if incident_id is None:
            rows = self._x("SELECT * FROM audit ORDER BY seq")
        else:
            rows = self._x("SELECT * FROM audit WHERE incident_id=? ORDER BY seq", (incident_id,))
        return [{"seq": r["seq"], "ts": r["ts"], "incident_id": r["incident_id"], "kind": r["kind"],
                 "data": json.loads(r["data"])} for r in rows]

    # ---- model calls (metering; never prompts or replies) ---------------
    def put_model_run(self, run: Any) -> None:
        self._x("INSERT OR IGNORE INTO model_runs(id, ts, task, model, incident_id, ok, shadow, escalated, latency_ms, "
                "prompt_tokens, completion_tokens, chars_in, chars_out, est_cost, fallback_reason, error) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (run.id, run.ts, run.task, run.model, run.incident_id, int(run.ok), int(run.shadow),
                 int(run.escalated), run.latency_ms, run.prompt_tokens, run.completion_tokens, run.chars_in,
                 run.chars_out, run.est_cost, run.fallback_reason, (run.error or "")[:500] or None))

    def model_runs(self, since_ts: float | None = None) -> list[dict[str, Any]]:
        rows = self._x("SELECT * FROM model_runs WHERE ts >= ? ORDER BY ts", (since_ts or 0.0,))
        return [dict(r) for r in rows]

    def model_runs_for(self, incident_id: str) -> list[dict[str, Any]]:
        return [dict(r) for r in self._x("SELECT * FROM model_runs WHERE incident_id=? ORDER BY ts", (incident_id,))]

    def usage_rows(self, since_ts: float, until_ts: float) -> dict[str, list[dict[str, Any]]]:
        """Raw material for metering one period (see sentinel.usage)."""
        a = (since_ts, until_ts)
        q = {
            "incidents": "SELECT tenant, pattern_id, COUNT(*) AS n FROM incidents WHERE created_ts >= ? AND "
                         "created_ts < ? GROUP BY tenant, pattern_id",
            "events": "SELECT tenant, COUNT(*) AS n FROM events WHERE received_ts >= ? AND received_ts < ? "
                      "GROUP BY tenant",
            "dispositions": "SELECT i.tenant AS tenant, d.pattern_id AS pattern_id, "
                            "json_extract(d.body, '$.resolver') AS resolver, "
                            "json_extract(d.body, '$.shadow') AS shadow, "
                            "json_extract(d.body, '$.reversed') AS reversed, "
                            "json_extract(d.body, '$.outcome') AS outcome, json_extract(d.body, '$.actor') AS actor, "
                            "json_extract(d.body, '$.code') AS code "
                            "FROM dispositions d JOIN incidents i ON i.id = d.incident_id "
                            "WHERE d.created_ts >= ? AND d.created_ts < ?",
            "models": "SELECT COALESCE(i.tenant, 'default') AS tenant, i.pattern_id AS pattern_id, COUNT(*) AS calls, "
                      "COALESCE(SUM(m.est_cost), 0) AS cost, COALESCE(SUM(m.prompt_tokens), 0) AS tokens_in, "
                      "COALESCE(SUM(m.completion_tokens), 0) AS tokens_out FROM model_runs m LEFT JOIN incidents i "
                      "ON i.id = m.incident_id WHERE m.ts >= ? AND m.ts < ? GROUP BY 1, 2",
            "messages": "SELECT edge, COUNT(*) AS n FROM deliveries WHERE created_ts >= ? AND created_ts < ? "
                        "GROUP BY edge",
        }
        out = {k: [dict(r) for r in self._x(sql, a)] for k, sql in q.items()}
        for r in out["dispositions"]:
            r["shadow"], r["reversed"] = bool(r["shadow"]), bool(r["reversed"])
        return out

    def action_runs_for(self, incident_id: str) -> list[dict[str, Any]]:
        rows = self._x("SELECT * FROM action_runs WHERE incident_id=? ORDER BY created_ts", (incident_id,))
        return [{**dict(r), "result": json.loads(r["result"]) if r["result"] else None} for r in rows]

    def search_incidents(self, *, pattern: str | None = None, state: str | None = None, tenant: str | None = None,
                         since_ts: float | None = None, until_ts: float | None = None,
                         facts: dict[str, str] | None = None, text: str | None = None,
                         before: tuple[float, str] | None = None, limit: int = 50) -> list[Incident]:
        """Newest first, one page at a time (pass the last row's (created_ts, id) as ``before``)."""
        where, args = _search_where(pattern, state, tenant, since_ts, until_ts, text, before, "?")
        for k, v in (facts or {}).items():
            where.append("CAST(json_extract(body, ?) AS TEXT) = ?")
            args += [f'$.facts."{_fact_key(k)}"', str(v)]
        # only fixed column names and placeholders are joined into the text; every value is a parameter
        sql = "SELECT body FROM incidents" + (" WHERE " + " AND ".join(where) if where else "")  # noqa: S608
        sql += " ORDER BY created_ts DESC, id DESC LIMIT ?"
        return [Incident.model_validate_json(r["body"]) for r in self._x(sql, (*args, max(1, min(limit, 500))))]

    # ---- case vectors (similar-case search) ------------------------------
    SIMILAR_SCAN_LIMIT = 5000      # newest vectors compared per query (exact search in Python)

    def put_case_vector(self, incident_id: str, pattern_id: str, tenant: str, model: str,
                        vec: list[float]) -> None:
        self._x("INSERT OR REPLACE INTO case_vectors(incident_id, pattern_id, tenant, model, dim, vec, created_ts) "
                "VALUES (?,?,?,?,?,?,?)",
                (incident_id, pattern_id, tenant, model, len(vec), json.dumps(vec), _ts(utcnow())))

    def has_case_vector(self, incident_id: str, model: str) -> bool:
        return self._x("SELECT 1 FROM case_vectors WHERE incident_id=? AND model=?",
                       (incident_id, model)).fetchone() is not None

    def similar_cases(self, pattern_id: str, tenant: str, model: str, vec: list[float], k: int,
                      exclude: str | None = None) -> list[tuple[str, float]]:
        from .similarity import cosine
        rows = self._x("SELECT incident_id, vec FROM case_vectors WHERE pattern_id=? AND tenant=? AND model=? "
                       "AND dim=? ORDER BY created_ts DESC LIMIT ?",
                       (pattern_id, tenant, model, len(vec), self.SIMILAR_SCAN_LIMIT))
        scored = [(r["incident_id"], cosine(vec, json.loads(r["vec"]))) for r in rows if r["incident_id"] != exclude]
        scored.sort(key=lambda t: -t[1])
        return scored[:k]

    # ---- configuration versions ------------------------------------------
    def add_config_version(self, kind: str, make: Any) -> Any:
        """Insert make(next_version_number) atomically and return it."""
        with self.transaction():
            row = self._x("SELECT COALESCE(MAX(version), 0) AS v FROM config_versions WHERE kind=?", (kind,)).fetchone()
            cv = make(int(row["v"]) + 1)
            self.put_config_version(cv)
            return cv

    def put_config_version(self, cv: Any) -> None:
        self._x("INSERT INTO config_versions(id, kind, version, status, body, created_ts) VALUES (?,?,?,?,?,?) "
                "ON CONFLICT(id) DO UPDATE SET status=excluded.status, body=excluded.body",
                (cv.id, cv.kind, cv.version, cv.status, cv.model_dump_json(), _ts(cv.created_at)))

    def get_config_version(self, version_id: str) -> Any:
        from .config import ConfigVersion
        r = self._x("SELECT body FROM config_versions WHERE id=?", (version_id,)).fetchone()
        return ConfigVersion.model_validate_json(r["body"]) if r else None

    def config_versions(self, kind: str) -> list[Any]:
        from .config import ConfigVersion
        return [ConfigVersion.model_validate_json(r["body"]) for r in
                self._x("SELECT body FROM config_versions WHERE kind=? ORDER BY version DESC", (kind,))]

    def published_config(self, kind: str) -> Any:
        from .config import ConfigVersion
        r = self._x("SELECT body FROM config_versions WHERE kind=? AND status='published' ORDER BY version DESC "
                    "LIMIT 1", (kind,)).fetchone()
        return ConfigVersion.model_validate_json(r["body"]) if r else None

    def model_spend_since(self, ts: float) -> float:
        r = self._x("SELECT COALESCE(SUM(est_cost), 0) AS s FROM model_runs WHERE ts >= ? AND NOT shadow",
                    (ts,)).fetchone()
        return float(r["s"])

    def put_api_token(self, t: Any) -> None:
        self._x("INSERT INTO api_tokens(id, hash, body) VALUES (?,?,?) "
                "ON CONFLICT(id) DO UPDATE SET body=excluded.body",
                (t.id, t.hash, t.model_dump_json()))

    def api_token_by_hash(self, h: str) -> Any:
        from .access import ApiToken
        r = self._x("SELECT body FROM api_tokens WHERE hash=?", (h,)).fetchone()
        return ApiToken.model_validate_json(r["body"]) if r else None

    def api_tokens(self) -> list[Any]:
        from .access import ApiToken
        return [ApiToken.model_validate_json(r["body"]) for r in self._x("SELECT body FROM api_tokens ORDER BY id")]

    def recent_audit(self, limit: int = 100, kinds: list[str] | None = None) -> list[dict[str, Any]]:
        """Newest audit entries first, optionally only some kinds."""
        if kinds:
            marks = ",".join("?" * len(kinds))
            rows = self._x(f"SELECT * FROM audit WHERE kind IN ({marks}) ORDER BY seq DESC LIMIT ?",  # noqa: S608
                           (*kinds, limit))
        else:
            rows = self._x("SELECT * FROM audit ORDER BY seq DESC LIMIT ?", (limit,))
        return [{"seq": r["seq"], "ts": r["ts"], "incident_id": r["incident_id"], "kind": r["kind"],
                 "data": json.loads(r["data"])} for r in rows]

    # ---- data source state (cursors) -----------------------------------
    def get_source_state(self, name: str) -> dict[str, Any] | None:
        r = self._x("SELECT body FROM source_state WHERE name=?", (name,)).fetchone()
        return json.loads(r["body"]) if r else None

    def put_source_state(self, name: str, state: dict[str, Any]) -> None:
        self._x("INSERT INTO source_state(name, body) VALUES (?,?) ON CONFLICT(name) DO UPDATE SET body=excluded.body",
                (name, json.dumps(state, default=str)))

    def update_facts(self, incident_id: str, facts: dict[str, Any], states: list[str]) -> bool:
        """Replace only the facts of an incident, and only while it is in one of `states`."""
        with self.transaction():
            row = self._x("SELECT body, state FROM incidents WHERE id=?", (incident_id,)).fetchone()
            if row is None or row["state"] not in states:
                return False
            body = json.loads(row["body"])
            body["facts"] = facts
            self._x("UPDATE incidents SET body=? WHERE id=? AND state=?", (json.dumps(body), incident_id, row["state"]))
            return True
