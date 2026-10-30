# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""PostgreSQL store (plain PostgreSQL 15+; any host). Same contract as SQLiteStore.

    pip install "kbg-sentinel[postgres]"
    store = PostgresStore("postgresql://user:pass@host:5432/db", schema="sentinel")

Differences from SQLite that matter in production:
  * Bodies are JSONB, so the registry/dispositions can be queried and indexed directly
    (e.g. learning dashboards, pgvector similarity on dispositions).
  * `lock(key)` takes a transaction-scoped advisory lock, so several worker processes can
    ingest concurrently without double-creating incidents for the same fingerprint.
  * `claim_action_run` is a single INSERT .. ON CONFLICT, atomic across processes.
  * Everything lives in its own schema; RLS can be added per tenant without code changes.
  * A connection pool: threads work in parallel, and a lost connection (restart, failover, network) is
    replaced instead of breaking the process.
"""
from __future__ import annotations

import json
import os
import re
import threading
import time
from contextlib import contextmanager
from datetime import datetime
from typing import Any
from collections.abc import Iterator

from datetime import timedelta

from .observe import redact
from .models import Disposition, Event, Incident, IncidentState, PatternState, ReviewTask, WorkItem, utcnow
from .store import _ts

try:  # optional dependency
    import psycopg
    from psycopg.rows import dict_row
except ImportError:  # pragma: no cover
    psycopg = None  # type: ignore[assignment]
try:
    from psycopg_pool import ConnectionPool
except ImportError:  # pragma: no cover
    ConnectionPool = None  # type: ignore[assignment,misc]

_OPEN_STATES = [s.value for s in IncidentState if not s.terminal]
_IDENT = re.compile(r"^[a-z_][a-z0-9_]{0,62}$")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS {s}.events (
  id TEXT PRIMARY KEY, dedupe_key TEXT NOT NULL UNIQUE, tenant TEXT NOT NULL, type TEXT NOT NULL,
  body JSONB NOT NULL, received_ts DOUBLE PRECISION NOT NULL);
CREATE TABLE IF NOT EXISTS {s}.incidents (
  id TEXT PRIMARY KEY, tenant TEXT NOT NULL, pattern_id TEXT NOT NULL, fingerprint TEXT NOT NULL,
  state TEXT NOT NULL, parent_id TEXT, body JSONB NOT NULL, created_ts DOUBLE PRECISION NOT NULL,
  updated_ts DOUBLE PRECISION NOT NULL);
CREATE INDEX IF NOT EXISTS ix_inc_fp ON {s}.incidents(fingerprint, state);
CREATE INDEX IF NOT EXISTS ix_inc_pattern ON {s}.incidents(pattern_id, tenant, state);
CREATE INDEX IF NOT EXISTS ix_inc_parent ON {s}.incidents(parent_id);
CREATE INDEX IF NOT EXISTS ix_inc_state ON {s}.incidents(state, updated_ts);
CREATE TABLE IF NOT EXISTS {s}.incident_events (
  incident_id TEXT NOT NULL, event_id TEXT NOT NULL, seq INTEGER NOT NULL, PRIMARY KEY (incident_id, event_id));
CREATE TABLE IF NOT EXISTS {s}.reviews (
  id TEXT PRIMARY KEY, incident_id TEXT NOT NULL, is_open BOOLEAN NOT NULL, due_ts DOUBLE PRECISION NOT NULL,
  body JSONB NOT NULL);
CREATE INDEX IF NOT EXISTS ix_rev_open ON {s}.reviews(is_open, due_ts);
CREATE INDEX IF NOT EXISTS ix_rev_inc ON {s}.reviews(incident_id);
CREATE INDEX IF NOT EXISTS ix_rev_open_role ON {s}.reviews((body->>'assignee_role'), due_ts) WHERE is_open;
CREATE TABLE IF NOT EXISTS {s}.dispositions (
  id TEXT PRIMARY KEY, incident_id TEXT NOT NULL UNIQUE, pattern_id TEXT NOT NULL, body JSONB NOT NULL,
  created_ts DOUBLE PRECISION NOT NULL);
CREATE INDEX IF NOT EXISTS ix_dsp_pattern ON {s}.dispositions(pattern_id, created_ts);
CREATE TABLE IF NOT EXISTS {s}.pattern_state (pattern_id TEXT PRIMARY KEY, body JSONB NOT NULL);
CREATE TABLE IF NOT EXISTS {s}.action_runs (
  idempotency_key TEXT PRIMARY KEY, incident_id TEXT NOT NULL, action TEXT NOT NULL, status TEXT NOT NULL,
  result JSONB, created_ts DOUBLE PRECISION NOT NULL);
CREATE TABLE IF NOT EXISTS {s}.work_items (
  id TEXT PRIMARY KEY, kind TEXT NOT NULL, incident_id TEXT, payload JSONB NOT NULL, status TEXT NOT NULL,
  attempts INTEGER NOT NULL, max_attempts INTEGER NOT NULL, run_after_ts DOUBLE PRECISION NOT NULL,
  lease_until_ts DOUBLE PRECISION, leased_by TEXT, last_error TEXT, dedupe_key TEXT UNIQUE,
  created_ts DOUBLE PRECISION NOT NULL);
CREATE INDEX IF NOT EXISTS ix_work_ready ON {s}.work_items(status, run_after_ts);
CREATE TABLE IF NOT EXISTS {s}.deliveries (
  id TEXT PRIMARY KEY, review_id TEXT NOT NULL, person_id TEXT, edge TEXT NOT NULL, status TEXT NOT NULL,
  body JSONB NOT NULL, created_ts DOUBLE PRECISION NOT NULL);
CREATE INDEX IF NOT EXISTS ix_dlv_review ON {s}.deliveries(review_id);
CREATE TABLE IF NOT EXISTS {s}.audit (
  seq BIGSERIAL PRIMARY KEY, ts DOUBLE PRECISION NOT NULL, incident_id TEXT, kind TEXT NOT NULL, data JSONB NOT NULL);
CREATE INDEX IF NOT EXISTS ix_audit_inc ON {s}.audit(incident_id, seq);
CREATE TABLE IF NOT EXISTS {s}.model_runs (
  id TEXT PRIMARY KEY, ts DOUBLE PRECISION NOT NULL, task TEXT NOT NULL, model TEXT NOT NULL, incident_id TEXT,
  ok BOOLEAN NOT NULL, shadow BOOLEAN NOT NULL, escalated BOOLEAN NOT NULL, latency_ms DOUBLE PRECISION NOT NULL,
  prompt_tokens INTEGER, completion_tokens INTEGER, chars_in INTEGER NOT NULL, chars_out INTEGER NOT NULL,
  est_cost DOUBLE PRECISION NOT NULL, fallback_reason TEXT, error TEXT);
CREATE INDEX IF NOT EXISTS ix_mrun_ts ON {s}.model_runs(ts);
CREATE INDEX IF NOT EXISTS ix_mrun_inc ON {s}.model_runs(incident_id);
CREATE INDEX IF NOT EXISTS ix_actrun_inc ON {s}.action_runs(incident_id);
CREATE INDEX IF NOT EXISTS ix_audit_ts ON {s}.audit(ts);
CREATE INDEX IF NOT EXISTS ix_work_done ON {s}.work_items(status, created_ts);
CREATE INDEX IF NOT EXISTS ix_work_inc ON {s}.work_items(incident_id);
CREATE INDEX IF NOT EXISTS ix_incev_event ON {s}.incident_events(event_id);
CREATE INDEX IF NOT EXISTS ix_events_ts ON {s}.events(received_ts);
CREATE INDEX IF NOT EXISTS ix_inc_created ON {s}.incidents(created_ts, id);
CREATE TABLE IF NOT EXISTS {s}.config_versions (
  id TEXT PRIMARY KEY, kind TEXT NOT NULL, version INTEGER NOT NULL, status TEXT NOT NULL, body JSONB NOT NULL,
  created_ts DOUBLE PRECISION NOT NULL, UNIQUE (kind, version));
CREATE TABLE IF NOT EXISTS {s}.source_state (name TEXT PRIMARY KEY, body JSONB NOT NULL);
CREATE TABLE IF NOT EXISTS {s}.api_tokens (id TEXT PRIMARY KEY, hash TEXT NOT NULL UNIQUE, body JSONB NOT NULL);
CREATE TABLE IF NOT EXISTS {s}.audit_seals (
  seal_no BIGINT PRIMARY KEY, from_no BIGINT NOT NULL, to_no BIGINT NOT NULL, batch_digest TEXT NOT NULL,
  prev_hash TEXT NOT NULL, seal_hash TEXT NOT NULL, signature TEXT, created_ts DOUBLE PRECISION NOT NULL);
CREATE TABLE IF NOT EXISTS {s}.audit_tombstones (
  chain_no BIGINT PRIMARY KEY, row_hash TEXT NOT NULL, removed_ts DOUBLE PRECISION NOT NULL, reason TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS {s}.audit_redactions (
  chain_no BIGINT PRIMARY KEY, original_hash TEXT NOT NULL, redacted_hash TEXT NOT NULL,
  redacted_ts DOUBLE PRECISION NOT NULL);
"""


# changes whenever the schema text or the upgrade steps change, so a new version migrates exactly once
_SCHEMA_HASH = __import__("hashlib").sha256((_SCHEMA + "|migrate-v3").encode()).hexdigest()[:16]


def _j(v: Any) -> str:
    return json.dumps(v, default=str)


class PostgresStore:
    SIMILAR_SCAN_LIMIT = 5000      # without pgvector: newest vectors compared per query

    def __init__(self, dsn: str, schema: str = "sentinel", use_pgvector: bool | None = None, *,
                 pool_size: int | None = None, statement_timeout_ms: int | None = None,
                 lock_timeout_ms: int | None = None, connect_timeout_s: float = 30.0,
                 migrate: bool | None = None) -> None:
        """A pool of connections (``SENTINEL_PG_POOL``, default 8): each thread works on its own connection,
        broken connections are replaced (a database restart or failover heals by itself), and every session
        has a statement and lock timeout so nothing waits forever."""
        if psycopg is None or ConnectionPool is None:
            raise ImportError('pip install "psycopg[binary]" psycopg-pool to use PostgresStore')
        if not _IDENT.match(schema):
            raise ValueError(f"invalid schema name {schema!r}")
        self.schema = schema
        self.dsn = dsn
        self._lock = threading.RLock()                  # guards small caches only, never database work
        self._tl = threading.local()                    # the connection of this thread's open transaction
        self._vix: tuple[float, set[int]] | None = None
        env = os.environ
        size = int(pool_size or env.get("SENTINEL_PG_POOL") or 8)
        self.statement_timeout_ms = int(statement_timeout_ms if statement_timeout_ms is not None
                                        else env.get("SENTINEL_PG_STATEMENT_TIMEOUT_MS") or 120_000)
        self.lock_timeout_ms = int(lock_timeout_ms if lock_timeout_ms is not None
                                   else env.get("SENTINEL_PG_LOCK_TIMEOUT_MS") or 30_000)

        def configure(conn: Any) -> None:
            conn.execute(f"SET statement_timeout = {self.statement_timeout_ms}")
            conn.execute(f"SET lock_timeout = {self.lock_timeout_ms}")

        self._pool = ConnectionPool(
            dsn, min_size=1, max_size=max(1, size), open=False, timeout=connect_timeout_s,
            name=f"sentinel-{schema}", configure=configure, check=ConnectionPool.check_connection,
            reconnect_timeout=0,             # keep trying to reconnect for as long as the database is away
            kwargs={"autocommit": True, "row_factory": dict_row, "application_name": f"sentinel:{schema}"[:63],
                    "keepalives": 1, "keepalives_idle": 30,
                    "keepalives_interval": 10, "keepalives_count": 3, "connect_timeout": int(connect_timeout_s)})
        self._pool.open(wait=True, timeout=connect_timeout_s)
        if migrate is None:
            migrate = (env.get("SENTINEL_AUTO_MIGRATE") or "1").strip().lower() not in ("0", "false", "no")
        try:
            current = self._schema_current(use_pgvector)
            if not current and not migrate:
                raise RuntimeError(f"the {schema} schema is older than this version of Sentinel; run "
                                   "`sentinel migrate` (SENTINEL_AUTO_MIGRATE is off)")
            if not current:
                # several processes (API, workers) may start together: one creates / migrates, the rest wait
                with self.transaction():
                    self._x("SET LOCAL lock_timeout = 0")
                    self._x("SET LOCAL statement_timeout = 0")
                    self._conn.execute("SELECT pg_advisory_xact_lock(hashtext(%s))", (f"sentinel_migrate:{schema}",))
                    self._conn.execute(f"CREATE SCHEMA IF NOT EXISTS {schema}")
                    for stmt in _SCHEMA.format(s=schema).split(";"):
                        if stmt.strip():
                            self._conn.execute(stmt)
                    self._migrate()
                    self.pgvector = self._case_vectors(use_pgvector)
                    self._conn.execute(f"CREATE TABLE IF NOT EXISTS {schema}.schema_version "
                                       "(id INTEGER PRIMARY KEY, hash TEXT NOT NULL, applied_ts DOUBLE PRECISION)")
                    self._conn.execute(f"INSERT INTO {schema}.schema_version(id, hash, applied_ts) "  # noqa: S608
                                       "VALUES (1, %s, %s) ON CONFLICT (id) DO UPDATE SET hash=excluded.hash, "
                                       "applied_ts=excluded.applied_ts", (_SCHEMA_HASH, time.time()))
        except Exception:
            self._pool.close()
            raise

    def schema_version(self) -> str | None:
        try:
            row = self._x(f"SELECT hash FROM {self.schema}.schema_version WHERE id = 1").fetchone()  # noqa: S608
        except Exception:  # noqa: BLE001
            return None
        return row["hash"] if row else None

    def _schema_current(self, use_pgvector: bool | None) -> bool:
        """Is the schema already at this version? Then no DDL runs at start (DDL takes table locks that
        would queue behind, and block, live traffic from other processes)."""
        s = self.schema
        try:
            row = self._x(f"SELECT hash FROM {s}.schema_version WHERE id = 1").fetchone()  # noqa: S608
        except Exception:  # noqa: BLE001 - no table yet: a fresh or older schema
            return False
        if row is None or row["hash"] != _SCHEMA_HASH:
            return False
        col = self._x("SELECT udt_name FROM information_schema.columns WHERE table_schema=%s AND "
                      "table_name='case_vectors' AND column_name='vec'", (s,)).fetchone()
        if col is None:
            return False
        have = col["udt_name"] == "vector"
        if use_pgvector and not have:
            raise RuntimeError(f"{s}.case_vectors was created without pgvector")
        self.pgvector = have
        return True

    @property
    def _conn(self) -> Any:
        """The connection of this thread's open transaction (schema setup and savepoints)."""
        c = getattr(self._tl, "conn", None)
        if c is None:
            raise RuntimeError("no open transaction on this thread")
        return c

    def _migrate(self) -> None:
        """Idempotent upgrades for schemas created by older versions. When you add a step here, bump the
        "migrate-vN" tag in _SCHEMA_HASH so existing databases run it once."""
        s = self.schema   # validated against _IDENT in __init__, so safe to interpolate  # noqa: S608
        self._conn.execute(f"ALTER TABLE {s}.dispositions ADD COLUMN IF NOT EXISTS unattended BOOLEAN")
        self._conn.execute(f"UPDATE {s}.dispositions SET unattended = (body->>'resolver' IN ('auto','llm') AND "  # noqa: S608
                           f"(body->>'shadow')::boolean = false) WHERE unattended IS NULL")
        self._conn.execute(f"CREATE INDEX IF NOT EXISTS ix_dsp_unattended ON {s}.dispositions(pattern_id, "
                           f"unattended, created_ts)")
        self._conn.execute(f"CREATE INDEX IF NOT EXISTS ix_rev_inc_open ON {s}.reviews(incident_id, is_open)")
        self._conn.execute(f"ALTER TABLE {s}.audit ADD COLUMN IF NOT EXISTS chain_no BIGINT")
        self._conn.execute(f"ALTER TABLE {s}.audit ADD COLUMN IF NOT EXISTS row_hash TEXT")
        self._conn.execute(f"CREATE UNIQUE INDEX IF NOT EXISTS ix_audit_chain ON {s}.audit(chain_no)")
        self._conn.execute(f"CREATE INDEX IF NOT EXISTS ix_audit_unsealed ON {s}.audit(seq) WHERE chain_no IS NULL")

    def _q(self, sql: str) -> str:
        return sql.replace("{s}", self.schema)

    def _x(self, sql: str, args: tuple | list = ()) -> Any:
        c = getattr(self._tl, "conn", None)
        if c is not None:                                # inside this thread's transaction
            return c.execute(self._q(sql), args)
        with self._pool.connection() as c:
            cur = c.execute(self._q(sql), args)
            from .store import _Result
            return _Result(cur.fetchall() if cur.description is not None else [], cur.rowcount)

    @contextmanager
    def transaction(self) -> Iterator[None]:
        c = getattr(self._tl, "conn", None)
        if c is not None:
            with c.transaction():                        # nested: a savepoint on the same connection
                yield
            return
        with self._pool.connection() as c:
            self._tl.conn = c
            try:
                with c.transaction():
                    yield
            finally:
                self._tl.conn = None

    def ping(self) -> bool:
        """Can the database be reached right now?"""
        try:
            self._x("SELECT 1")
            return True
        except Exception:  # noqa: BLE001
            return False

    def pool_stats(self) -> dict[str, int]:
        return dict(self._pool.get_stats())

    def lock(self, key: str) -> None:
        """Transaction-scoped advisory lock; serialises same-key work across processes."""
        self._x("SELECT pg_advisory_xact_lock(hashtext(%s))", (key,))

    @contextmanager
    def mutex(self, key: str) -> Iterator[None]:
        """A lock across processes held for a long step (running a case's actions) without keeping a
        transaction open: a session advisory lock on a connection of its own, released at the end (or when
        the process dies). Waits at most the lock timeout."""
        with self._pool.connection() as c:
            k = f"sentinel-mutex:{self.schema}:{key}"
            c.execute("SELECT pg_advisory_lock(hashtext(%s))", (k,))
            try:
                yield
            finally:
                c.execute("SELECT pg_advisory_unlock(hashtext(%s))", (k,))

    def close_review(self, review_id: str) -> bool:
        cur = self._x("UPDATE {s}.reviews SET is_open=false, body=jsonb_set(body, '{open}', 'false') "
                      "WHERE id=%s AND is_open RETURNING id", (review_id,))
        return cur.fetchone() is not None

    def close(self) -> None:
        self._pool.close()

    def drop(self) -> None:
        """Remove the whole schema (tests only)."""
        self._x(f"DROP SCHEMA IF EXISTS {self.schema} CASCADE")

    # ---- events -------------------------------------------------------
    def insert_event(self, event: Event) -> bool:
        cur = self._x("INSERT INTO {s}.events(id, dedupe_key, tenant, type, body, received_ts) "
                      "VALUES (%s,%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING RETURNING id",
                      (event.id, event.dedupe_key, event.tenant, event.type, event.model_dump_json(), _ts(utcnow())))
        return cur.fetchone() is not None

    def event_seen(self, dedupe_key: str) -> bool:
        return self._x("SELECT 1 FROM {s}.events WHERE dedupe_key=%s", (dedupe_key,)).fetchone() is not None

    def update_event(self, event: Event) -> None:
        self._x("UPDATE {s}.events SET body=%s WHERE id=%s", (event.model_dump_json(), event.id))

    def update_audit_data(self, seq: int, data: dict[str, Any]) -> None:
        self._x("UPDATE {s}.audit SET data=%s WHERE seq=%s", (_j(data), seq))

    def delete_case_vector(self, incident_id: str) -> None:
        self._x("DELETE FROM {s}.case_vectors WHERE incident_id=%s", (incident_id,))

    def get_event(self, event_id: str) -> Event | None:
        row = self._x("SELECT body FROM {s}.events WHERE id=%s", (event_id,)).fetchone()
        return Event.model_validate(row["body"]) if row else None

    # ---- incidents ----------------------------------------------------
    def put_incident(self, inc: Incident) -> None:
        self._x("INSERT INTO {s}.incidents(id, tenant, pattern_id, fingerprint, state, parent_id, body, created_ts, "
                "updated_ts) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT (id) DO UPDATE SET "
                "state=excluded.state, parent_id=excluded.parent_id, body=excluded.body, "
                "updated_ts=excluded.updated_ts, pattern_id=excluded.pattern_id",
                (inc.id, inc.tenant, inc.pattern_id, inc.fingerprint, inc.state.value, inc.parent_id,
                 inc.model_dump_json(), _ts(inc.created_at), _ts(inc.updated_at)))

    def get_incident(self, incident_id: str) -> Incident | None:
        row = self._x("SELECT body FROM {s}.incidents WHERE id=%s", (incident_id,)).fetchone()
        return Incident.model_validate(row["body"]) if row else None

    def find_open_incident(self, fingerprint: str, since: datetime) -> Incident | None:
        row = self._x("SELECT body FROM {s}.incidents WHERE fingerprint=%s AND created_ts>=%s AND state = ANY(%s) "
                      "ORDER BY created_ts DESC LIMIT 1", (fingerprint, _ts(since), _OPEN_STATES)).fetchone()
        return Incident.model_validate(row["body"]) if row else None

    def open_incidents(self, pattern_id: str, tenant: str) -> list[Incident]:
        rows = self._x("SELECT body FROM {s}.incidents WHERE pattern_id=%s AND tenant=%s AND state = ANY(%s) "
                       "ORDER BY created_ts", (pattern_id, tenant, _OPEN_STATES)).fetchall()
        return [Incident.model_validate(r["body"]) for r in rows]

    def children(self, parent_id: str) -> list[Incident]:
        rows = self._x("SELECT body FROM {s}.incidents WHERE parent_id=%s ORDER BY created_ts", (parent_id,))
        return [Incident.model_validate(r["body"]) for r in rows.fetchall()]

    def incidents(self, state: IncidentState | None = None) -> list[Incident]:
        if state is None:
            rows = self._x("SELECT body FROM {s}.incidents ORDER BY created_ts")
        else:
            rows = self._x("SELECT body FROM {s}.incidents WHERE state=%s ORDER BY created_ts", (state.value,))
        return [Incident.model_validate(r["body"]) for r in rows.fetchall()]

    def attach_event(self, incident_id: str, event_id: str) -> int:
        with self.transaction():
            n = self._x("SELECT COUNT(*) AS n FROM {s}.incident_events WHERE incident_id=%s",
                        (incident_id,)).fetchone()["n"]
            self._x("INSERT INTO {s}.incident_events(incident_id, event_id, seq) VALUES (%s,%s,%s) "
                    "ON CONFLICT DO NOTHING", (incident_id, event_id, n))
            return n + 1

    def event_ids(self, incident_id: str) -> list[str]:
        rows = self._x("SELECT event_id FROM {s}.incident_events WHERE incident_id=%s ORDER BY seq", (incident_id,))
        return [r["event_id"] for r in rows.fetchall()]

    # ---- reviews ------------------------------------------------------
    def put_review(self, r: ReviewTask) -> None:
        self._x("INSERT INTO {s}.reviews(id, incident_id, is_open, due_ts, body) VALUES (%s,%s,%s,%s,%s) "
                "ON CONFLICT (id) DO UPDATE SET is_open=excluded.is_open, due_ts=excluded.due_ts, body=excluded.body",
                (r.id, r.incident_id, r.open, _ts(r.due_at), r.model_dump_json()))

    def get_review(self, review_id: str) -> ReviewTask | None:
        row = self._x("SELECT body FROM {s}.reviews WHERE id=%s", (review_id,)).fetchone()
        return ReviewTask.model_validate(row["body"]) if row else None

    def open_review_for(self, incident_id: str) -> ReviewTask | None:
        row = self._x("SELECT body FROM {s}.reviews WHERE incident_id=%s AND is_open LIMIT 1",
                      (incident_id,)).fetchone()
        return ReviewTask.model_validate(row["body"]) if row else None

    def reviews_for_incident(self, incident_id: str) -> list[ReviewTask]:
        return [ReviewTask.model_validate(r["body"]) for r in
                self._x("SELECT body FROM {s}.reviews WHERE incident_id=%s", (incident_id,)).fetchall()]

    def open_reviews(self, due_before: datetime | None = None) -> list[ReviewTask]:
        if due_before is None:
            rows = self._x("SELECT body FROM {s}.reviews WHERE is_open ORDER BY due_ts")
        else:
            rows = self._x("SELECT body FROM {s}.reviews WHERE is_open AND due_ts<%s ORDER BY due_ts",
                           (_ts(due_before),))
        return [ReviewTask.model_validate(r["body"]) for r in rows.fetchall()]

    def review_counts(self, now: datetime) -> dict[str, int]:
        r = self._x("SELECT COUNT(*) AS n, COUNT(*) FILTER (WHERE due_ts < %s) AS overdue FROM {s}.reviews "
                    "WHERE is_open", (_ts(now),)).fetchone()
        return {"open": int(r["n"]), "overdue": int(r["overdue"])}

    def open_reviews_for_roles(self, roles: list[str] | None, limit: int = 200,
                               offset: int = 0) -> list[tuple[ReviewTask, dict[str, Any]]]:
        sql = ("SELECT r.body AS rb, i.body->'facts' AS facts FROM {s}.reviews r JOIN {s}.incidents i "
               "ON i.id = r.incident_id WHERE r.is_open")
        args: list[Any] = []
        if roles is not None:
            if not roles:
                return []
            sql += " AND r.body->>'assignee_role' = ANY(%s)"
            args.append(list(roles))
        sql += " ORDER BY r.due_ts LIMIT %s OFFSET %s"
        rows = self._x(sql, (*args, limit, offset)).fetchall()
        return [(ReviewTask.model_validate(x["rb"]), x["facts"] or {}) for x in rows]

    def open_reviews_of_pattern(self, pattern_id: str, limit: int = 1000) -> list[tuple[ReviewTask, dict[str, Any]]]:
        rows = self._x("SELECT r.body AS rb, i.body AS ib FROM {s}.reviews r JOIN {s}.incidents i "
                       "ON i.id = r.incident_id WHERE r.is_open AND i.pattern_id = %s ORDER BY r.due_ts LIMIT %s",
                       (pattern_id, limit)).fetchall()
        return [(ReviewTask.model_validate(x["rb"]), x["ib"] or {}) for x in rows]

    def count_open_reviews_of_pattern(self, pattern_id: str) -> int:
        row = self._x("SELECT COUNT(*) AS n FROM {s}.reviews r JOIN {s}.incidents i ON i.id = r.incident_id "
                      "WHERE r.is_open AND i.pattern_id = %s", (pattern_id,)).fetchone()
        return int(row["n"]) if row else 0

    def disposition_stats(self) -> dict[str, dict[str, int]]:
        rows = self._x(
            "SELECT pattern_id, COUNT(*) AS n, "
            "COUNT(*) FILTER (WHERE body->>'resolver'='auto') AS auto, "
            "COUNT(*) FILTER (WHERE body->>'resolver'='llm') AS llm, "
            "COUNT(*) FILTER (WHERE body->>'resolver'='human') AS human, "
            "COUNT(*) FILTER (WHERE body->>'resolver'='parent') AS parent, "
            "COUNT(*) FILTER (WHERE NOT (body->>'shadow')::boolean AND body->>'resolver'<>'parent') AS real, "
            "COUNT(*) FILTER (WHERE NOT (body->>'shadow')::boolean AND body->>'resolver' IN ('auto','llm')) "
            "AS real_unattended, "
            "COUNT(*) FILTER (WHERE (body->>'shadow')::boolean AND body->>'agreed_with_proposal' IS NOT NULL) "
            "AS shadow_n, "
            "COUNT(*) FILTER (WHERE (body->>'shadow')::boolean AND (body->>'agreed_with_proposal')::boolean) "
            "AS shadow_agreed, "
            "COUNT(*) FILTER (WHERE body->>'outcome' IN ('held','failed')) AS outcome_n, "
            "COUNT(*) FILTER (WHERE body->>'outcome'='held') AS outcome_held "
            "FROM {s}.dispositions GROUP BY pattern_id").fetchall()
        return {r["pattern_id"]: {k: int(v or 0) for k, v in r.items() if k != "pattern_id"} for r in rows}

    # ---- dispositions -------------------------------------------------
    def put_disposition(self, d: Disposition) -> None:
        unattended = d.resolver in ("auto", "llm") and not d.shadow
        self._x("INSERT INTO {s}.dispositions(id, incident_id, pattern_id, body, created_ts, unattended) "
                "VALUES (%s,%s,%s,%s,%s,%s) ON CONFLICT (incident_id) DO UPDATE SET body=excluded.body",
                (d.id, d.incident_id, d.pattern_id, d.model_dump_json(), _ts(d.created_at), unattended))

    def get_disposition(self, incident_id: str) -> Disposition | None:
        row = self._x("SELECT body FROM {s}.dispositions WHERE incident_id=%s", (incident_id,)).fetchone()
        return Disposition.model_validate(row["body"]) if row else None

    def dispositions(self, pattern_id: str | None = None) -> list[Disposition]:
        if pattern_id is None:
            rows = self._x("SELECT body FROM {s}.dispositions ORDER BY created_ts")
        else:
            rows = self._x("SELECT body FROM {s}.dispositions WHERE pattern_id=%s ORDER BY created_ts", (pattern_id,))
        return [Disposition.model_validate(r["body"]) for r in rows.fetchall()]

    def count_unattended(self, pattern_id: str, since: datetime, cap: int) -> int:
        done = self._x("SELECT COUNT(*) AS n FROM (SELECT 1 FROM {s}.dispositions WHERE pattern_id=%s AND "
                       "unattended AND created_ts>=%s LIMIT %s) q", (pattern_id, _ts(since), cap)).fetchone()["n"]
        flying = self._x("SELECT COUNT(*) AS n FROM (SELECT 1 FROM {s}.incidents WHERE pattern_id=%s AND state IN "
                         "('resolving','resolved') LIMIT %s) q", (pattern_id, cap)).fetchone()["n"]
        return int(done) + int(flying)            # in flight counts too: workers cannot overshoot together

    def recent_dispositions(self, pattern_id: str, limit: int) -> list[Disposition]:
        rows = self._x("SELECT body FROM {s}.dispositions WHERE pattern_id=%s ORDER BY created_ts DESC LIMIT %s",
                       (pattern_id, limit)).fetchall()
        return [Disposition.model_validate(r["body"]) for r in reversed(rows)]

    # ---- learned pattern state ---------------------------------------
    def get_pattern_state(self, pattern_id: str) -> PatternState | None:
        row = self._x("SELECT body FROM {s}.pattern_state WHERE pattern_id=%s", (pattern_id,)).fetchone()
        return PatternState.model_validate(row["body"]) if row else None

    def put_pattern_state(self, s: PatternState) -> None:
        self._x("INSERT INTO {s}.pattern_state(pattern_id, body) VALUES (%s,%s) "
                "ON CONFLICT (pattern_id) DO UPDATE SET body=excluded.body", (s.pattern_id, s.model_dump_json()))

    def pattern_states(self, prefix: str) -> list[PatternState]:
        rows = self._x("SELECT body FROM {s}.pattern_state WHERE left(pattern_id, %s) = %s ORDER BY pattern_id",
                       (len(prefix), prefix))
        return [PatternState.model_validate(r["body"]) for r in rows.fetchall()]

    # ---- action idempotency ------------------------------------------
    def claim_action_run(self, key: str, incident_id: str, action: str) -> dict[str, Any] | None:
        cur = self._x("INSERT INTO {s}.action_runs(idempotency_key, incident_id, action, status, created_ts) "
                      "VALUES (%s,%s,%s,'running',%s) ON CONFLICT DO NOTHING RETURNING idempotency_key",
                      (key, incident_id, action, _ts(utcnow())))
        if cur.fetchone() is not None:
            return None
        row = self._x("SELECT status, action, result FROM {s}.action_runs WHERE idempotency_key=%s", (key,)).fetchone()
        return {"status": row["status"], "action": row["action"], "result": row["result"]}

    def finish_action_run(self, key: str, status: str, result: dict[str, Any]) -> None:
        self._x("UPDATE {s}.action_runs SET status=%s, result=%s WHERE idempotency_key=%s", (status, _j(result), key))

    def release_action_run(self, key: str) -> None:
        self._x("DELETE FROM {s}.action_runs WHERE idempotency_key=%s AND status<>'ok'", (key,))

    # ---- work queue ---------------------------------------------------
    def enqueue(self, item: WorkItem) -> bool:
        cur = self._x("INSERT INTO {s}.work_items(id, kind, incident_id, payload, status, attempts, max_attempts, "
                      "run_after_ts, dedupe_key, created_ts) VALUES (%s,%s,%s,%s,'queued',0,%s,%s,%s,%s) "
                      "ON CONFLICT DO NOTHING RETURNING id",
                      (item.id, item.kind, item.incident_id, _j(item.payload), item.max_attempts,
                       _ts(item.run_after), item.dedupe_key, _ts(utcnow())))
        return cur.fetchone() is not None

    def lease(self, worker_id: str, now: datetime, limit: int, lease_seconds: float) -> list[WorkItem]:
        """SKIP LOCKED: many workers lease concurrently without blocking or double-taking an item."""
        until = _ts(now + timedelta(seconds=lease_seconds))
        rows = self._x("UPDATE {s}.work_items SET status='leased', attempts=attempts+1, lease_until_ts=%s, "
                       "leased_by=%s WHERE id IN (SELECT id FROM {s}.work_items WHERE (status='queued' AND "
                       "run_after_ts<=%s) OR (status='leased' AND lease_until_ts<%s) ORDER BY run_after_ts "
                       "LIMIT %s FOR UPDATE SKIP LOCKED) RETURNING *",
                       (until, worker_id, _ts(now), _ts(now), limit)).fetchall()
        from .store import SQLiteStore
        return [SQLiteStore._work(r) for r in rows]

    def complete(self, item_id: str, worker_id: str) -> bool:
        cur = self._x("UPDATE {s}.work_items SET status='done', lease_until_ts=NULL WHERE id=%s AND "
                      "status='leased' AND leased_by=%s", (item_id, worker_id))
        return cur.rowcount == 1

    def extend_lease(self, item_id: str, worker_id: str, until: datetime) -> bool:
        cur = self._x("UPDATE {s}.work_items SET lease_until_ts=%s WHERE id=%s AND status='leased' AND "
                      "leased_by=%s", (_ts(until), item_id, worker_id))
        return cur.rowcount == 1

    def fail(self, item_id: str, worker_id: str, error: str, retry_at: datetime | None) -> str | None:
        with self.transaction():
            row = self._x("SELECT attempts, max_attempts FROM {s}.work_items WHERE id=%s AND status='leased' AND "
                          "leased_by=%s FOR UPDATE", (item_id, worker_id)).fetchone()
            if row is None:
                return None
            dead = retry_at is None or row["attempts"] >= row["max_attempts"]
            status = "dead" if dead else "queued"
            self._x("UPDATE {s}.work_items SET status=%s, last_error=%s, lease_until_ts=NULL, "
                    "run_after_ts=COALESCE(%s, run_after_ts) WHERE id=%s",
                    (status, error[:2000], None if dead else _ts(retry_at), item_id))
            return status

    def live_work_for(self, incident_id: str, kind: str) -> int:
        return self._x("SELECT COUNT(*) AS n FROM {s}.work_items WHERE incident_id=%s AND kind=%s AND status IN "
                       "('queued','leased')", (incident_id, kind)).fetchone()["n"]

    def get_work(self, item_id: str) -> WorkItem | None:
        row = self._x("SELECT * FROM {s}.work_items WHERE id=%s", (item_id,)).fetchone()
        from .store import SQLiteStore
        return SQLiteStore._work(row) if row else None

    def queue_stats(self, now: datetime) -> dict[str, Any]:
        rows = self._x("SELECT status, COUNT(*) AS n FROM {s}.work_items GROUP BY status").fetchall()
        counts = {r["status"]: r["n"] for r in rows}
        oldest = self._x("SELECT MIN(run_after_ts) AS t FROM {s}.work_items WHERE status='queued' AND "
                         "run_after_ts<=%s", (_ts(now),)).fetchone()["t"]
        return {"counts": counts, "oldest_ready_age_s": round(_ts(now) - oldest, 3) if oldest else 0.0}

    # ---- deliveries ---------------------------------------------------
    def put_delivery(self, d: Any) -> None:
        self._x("INSERT INTO {s}.deliveries(id, review_id, person_id, edge, status, body, created_ts) VALUES "
                "(%s,%s,%s,%s,%s,%s,%s) ON CONFLICT (id) DO UPDATE SET status=excluded.status, body=excluded.body",
                (d.id, d.review_id, d.person_id, d.edge, d.status, d.model_dump_json(), _ts(d.created_at)))

    def deliveries(self, review_id: str) -> list[Any]:
        from .edges import Delivery
        rows = self._x("SELECT body FROM {s}.deliveries WHERE review_id=%s ORDER BY created_ts", (review_id,))
        return [Delivery.model_validate(r["body"]) for r in rows.fetchall()]

    # ---- audit --------------------------------------------------------
    def audit(self, incident_id: str | None, kind: str, data: dict[str, Any] | None = None) -> None:
        self._x("INSERT INTO {s}.audit(ts, incident_id, kind, data) VALUES (%s,%s,%s,%s)",
                (_ts(utcnow()), incident_id, kind, _j(redact(data or {}))))

    def audit_log(self, incident_id: str | None = None) -> list[dict[str, Any]]:
        if incident_id is None:
            rows = self._x("SELECT * FROM {s}.audit ORDER BY seq")
        else:
            rows = self._x("SELECT * FROM {s}.audit WHERE incident_id=%s ORDER BY seq", (incident_id,))
        return [{"seq": r["seq"], "ts": r["ts"], "incident_id": r["incident_id"], "kind": r["kind"],
                 "data": r["data"]} for r in rows.fetchall()]

    # ---- model calls (metering; never prompts or replies) ---------------
    def put_model_run(self, run: Any) -> None:
        self._x("INSERT INTO {s}.model_runs(id, ts, task, model, incident_id, ok, shadow, escalated, latency_ms, "
                "prompt_tokens, completion_tokens, chars_in, chars_out, est_cost, fallback_reason, error) "
                "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING",
                (run.id, run.ts, run.task, run.model, run.incident_id, run.ok, run.shadow, run.escalated,
                 run.latency_ms, run.prompt_tokens, run.completion_tokens, run.chars_in, run.chars_out,
                 run.est_cost, run.fallback_reason, (run.error or "")[:500] or None))

    def model_runs(self, since_ts: float | None = None) -> list[dict[str, Any]]:
        rows = self._x("SELECT * FROM {s}.model_runs WHERE ts >= %s ORDER BY ts", (since_ts or 0.0,))
        return [dict(r) for r in rows.fetchall()]

    def model_runs_for(self, incident_id: str) -> list[dict[str, Any]]:
        rows = self._x("SELECT * FROM {s}.model_runs WHERE incident_id=%s ORDER BY ts", (incident_id,))
        return [dict(r) for r in rows.fetchall()]

    def usage_rows(self, since_ts: float, until_ts: float) -> dict[str, list[dict[str, Any]]]:
        a = (since_ts, until_ts)
        q = {
            "incidents": "SELECT tenant, pattern_id, COUNT(*) AS n FROM {s}.incidents WHERE created_ts >= %s AND "
                         "created_ts < %s GROUP BY tenant, pattern_id",
            "events": "SELECT tenant, COUNT(*) AS n FROM {s}.events WHERE received_ts >= %s AND received_ts < %s "
                      "GROUP BY tenant",
            "dispositions": "SELECT i.tenant AS tenant, d.pattern_id AS pattern_id, d.body->>'resolver' AS resolver, "
                            "COALESCE((d.body->>'shadow')::boolean, false) AS shadow, "
                            "COALESCE((d.body->>'reversed')::boolean, false) AS reversed, "
                            "d.body->>'outcome' AS outcome, d.body->>'actor' AS actor, d.body->>'code' AS code "
                            "FROM {s}.dispositions d JOIN {s}.incidents i ON i.id = d.incident_id "
                            "WHERE d.created_ts >= %s AND d.created_ts < %s",
            "models": "SELECT COALESCE(i.tenant, 'default') AS tenant, i.pattern_id AS pattern_id, COUNT(*) AS calls, "
                      "COALESCE(SUM(m.est_cost), 0) AS cost, COALESCE(SUM(m.prompt_tokens), 0) AS tokens_in, "
                      "COALESCE(SUM(m.completion_tokens), 0) AS tokens_out FROM {s}.model_runs m LEFT JOIN "
                      "{s}.incidents i ON i.id = m.incident_id WHERE m.ts >= %s AND m.ts < %s GROUP BY 1, 2",
            "messages": "SELECT edge, COUNT(*) AS n FROM {s}.deliveries WHERE created_ts >= %s AND created_ts < %s "
                        "GROUP BY edge",
        }
        return {k: [dict(r) for r in self._x(sql, a).fetchall()] for k, sql in q.items()}

    def action_runs_for(self, incident_id: str) -> list[dict[str, Any]]:
        rows = self._x("SELECT * FROM {s}.action_runs WHERE incident_id=%s ORDER BY created_ts", (incident_id,))
        return [dict(r) for r in rows.fetchall()]

    def search_incidents(self, *, pattern: str | None = None, state: str | None = None, tenant: str | None = None,
                         since_ts: float | None = None, until_ts: float | None = None,
                         facts: dict[str, str] | None = None, text: str | None = None,
                         before: tuple[float, str] | None = None, limit: int = 50) -> list[Incident]:
        from .store import _fact_key, _search_where
        where, args = _search_where(pattern, state, tenant, since_ts, until_ts, text, before, "%s")
        for k, v in (facts or {}).items():
            where.append("body->'facts'->>%s = %s")
            args += [_fact_key(k), str(v)]
        # only fixed column names and placeholders are joined into the text; every value is a parameter
        sql = "SELECT body FROM {s}.incidents" + (" WHERE " + " AND ".join(where) if where else "")  # noqa: S608
        sql += " ORDER BY created_ts DESC, id DESC LIMIT %s"
        return [Incident.model_validate(r["body"]) for r in self._x(sql, (*args, max(1, min(limit, 500)))).fetchall()]

    # ---- case vectors (similar-case search) ------------------------------
    def _case_vectors(self, want: bool | None) -> bool:
        """Create the vector table: pgvector when available (or required), a float array otherwise."""
        s = self.schema
        existing = self._conn.execute(
            "SELECT udt_name FROM information_schema.columns WHERE table_schema=%s AND table_name='case_vectors' "
            "AND column_name='vec'", (s,)).fetchone()
        if existing is not None:
            have = existing["udt_name"] == "vector"
            if want and not have:
                raise RuntimeError(f"{s}.case_vectors was created without pgvector")
            return have
        use = False
        if want is not False:
            try:
                with self._conn.transaction():          # savepoint: a refusal must not abort the migration
                    self._conn.execute("CREATE EXTENSION IF NOT EXISTS vector")
                use = True
            except Exception as e:  # noqa: BLE001 - not installed / not permitted / created concurrently
                use = self._conn.execute("SELECT 1 FROM pg_extension WHERE extname='vector'").fetchone() is not None
                if want and not use:
                    raise RuntimeError(f"pgvector requested but unavailable: {e}") from e
        col = "vector" if use else "DOUBLE PRECISION[]"
        self._conn.execute(f"CREATE TABLE IF NOT EXISTS {s}.case_vectors (incident_id TEXT PRIMARY KEY, "
                           "pattern_id TEXT NOT NULL, tenant TEXT NOT NULL, model TEXT NOT NULL, "
                           f"dim INTEGER NOT NULL, vec {col} NOT NULL, created_ts DOUBLE PRECISION NOT NULL)")
        self._conn.execute(f"CREATE INDEX IF NOT EXISTS ix_cvec_pattern ON {s}.case_vectors(pattern_id, tenant, model, "
                           f"created_ts)")
        return use

    def put_case_vector(self, incident_id: str, pattern_id: str, tenant: str, model: str,
                        vec: list[float]) -> None:
        from .similarity import vector_literal
        val: Any = vector_literal(vec) if self.pgvector else [float(x) for x in vec]
        sql = ("INSERT INTO {s}.case_vectors(incident_id, pattern_id, tenant, model, dim, vec, created_ts) "
               + ("VALUES (%s,%s,%s,%s,%s,%s::vector,%s) " if self.pgvector else "VALUES (%s,%s,%s,%s,%s,%s,%s) ")
               + "ON CONFLICT (incident_id) DO UPDATE SET model=excluded.model, dim=excluded.dim, vec=excluded.vec, "
               "created_ts=excluded.created_ts")
        self._x(sql, (incident_id, pattern_id, tenant, model, len(vec), val, _ts(utcnow())))

    def has_case_vector(self, incident_id: str, model: str) -> bool:
        return self._x("SELECT 1 FROM {s}.case_vectors WHERE incident_id=%s AND model=%s",
                       (incident_id, model)).fetchone() is not None

    def vector_indexes(self) -> set[int]:
        """Dimensions that have an HNSW index (see ``ensure_vector_index``); cached for a minute."""
        now = time.monotonic()
        if self._vix is None or now - self._vix[0] > 60:
            rows = self._x("SELECT indexname FROM pg_indexes WHERE schemaname=%s AND indexname LIKE 'ix_cvec_hnsw_%%'",
                           (self.schema,)).fetchall()
            self._vix = (now, {int(r["indexname"].rsplit("_", 1)[1]) for r in rows})
        return self._vix[1]

    def ensure_vector_index(self, dim: int, m: int = 16, ef_construction: int = 64) -> str:
        """An HNSW index (cosine) over the case vectors of one dimension. Worth it once there are tens of
        thousands of cases per pattern; until then the exact scan is fast. Builds without blocking writes."""
        if not self.pgvector:
            raise RuntimeError("needs the pgvector extension")
        dim, m, ef = int(dim), int(m), int(ef_construction)
        name = f"ix_cvec_hnsw_{dim}"
        with self._pool.connection() as c:            # autocommit, outside a transaction: CONCURRENTLY works
            c.execute("SET statement_timeout = 0")       # a large index takes minutes to build
            try:
                c.execute(self._q(
                    f"CREATE INDEX CONCURRENTLY IF NOT EXISTS {name} ON {{s}}.case_vectors "
                    f"USING hnsw ((vec::vector({dim})) vector_cosine_ops) WITH (m = {m}, ef_construction = {ef}) "
                    f"WHERE dim = {dim}"))
            finally:
                c.execute(f"SET statement_timeout = {self.statement_timeout_ms}")
        self._vix = None
        return name

    def similar_cases(self, pattern_id: str, tenant: str, model: str, vec: list[float], k: int,
                      exclude: str | None = None) -> list[tuple[str, float]]:
        if self.pgvector and len(vec) in self.vector_indexes():
            from .similarity import vector_literal
            n = int(len(vec))                         # inlined (an int) so the partial index applies
            q = vector_literal(vec)
            with self.transaction():
                try:                                  # pgvector >= 0.8: keep scanning until k rows pass the filter
                    with self._conn.transaction():
                        self._x("SET LOCAL hnsw.iterative_scan = relaxed_order")
                except Exception:  # noqa: BLE001,S110 - older pgvector: plain HNSW scan
                    pass
                self._x(f"SET LOCAL hnsw.ef_search = {max(40, 4 * int(k))}")
                rows = self._x(f"SELECT incident_id, 1 - ((vec::vector({n})) <=> %s::vector({n})) AS sim "  # noqa: S608
                               "FROM {s}.case_vectors WHERE pattern_id=%s AND tenant=%s AND model=%s "
                               f"AND dim = {n} AND incident_id <> %s "
                               f"ORDER BY (vec::vector({n})) <=> %s::vector({n}) LIMIT %s",
                               (q, pattern_id, tenant, model, exclude or "", q, k)).fetchall()
            out = [(r["incident_id"], float(r["sim"])) for r in rows]
            return sorted(out, key=lambda t: -t[1])
        if self.pgvector:
            from .similarity import vector_literal
            q = vector_literal(vec)
            rows = self._x("SELECT incident_id, 1 - (vec <=> %s::vector) AS sim FROM {s}.case_vectors "
                           "WHERE pattern_id=%s AND tenant=%s AND model=%s AND dim=%s AND incident_id <> %s "
                           "ORDER BY vec <=> %s::vector LIMIT %s",
                           (q, pattern_id, tenant, model, len(vec), exclude or "", q, k)).fetchall()
            return [(r["incident_id"], float(r["sim"])) for r in rows]
        from .similarity import cosine
        rows = self._x("SELECT incident_id, vec FROM {s}.case_vectors WHERE pattern_id=%s AND tenant=%s AND model=%s "
                       "AND dim=%s ORDER BY created_ts DESC LIMIT %s",
                       (pattern_id, tenant, model, len(vec), self.SIMILAR_SCAN_LIMIT)).fetchall()
        scored = [(r["incident_id"], cosine(vec, list(r["vec"]))) for r in rows if r["incident_id"] != exclude]
        scored.sort(key=lambda t: -t[1])
        return scored[:k]

    # ---- configuration versions ------------------------------------------
    def add_config_version(self, kind: str, make: Any) -> Any:
        """Insert make(next_version_number) atomically (serialised per kind) and return it."""
        with self.transaction():
            self.lock(f"config:{kind}")
            row = self._x("SELECT COALESCE(MAX(version), 0) AS v FROM {s}.config_versions WHERE kind=%s",
                          (kind,)).fetchone()
            cv = make(int(row["v"]) + 1)
            self.put_config_version(cv)
            return cv

    def put_config_version(self, cv: Any) -> None:
        self._x("INSERT INTO {s}.config_versions(id, kind, version, status, body, created_ts) "
                "VALUES (%s,%s,%s,%s,%s,%s) ON CONFLICT (id) DO UPDATE SET status=excluded.status, body=excluded.body",
                (cv.id, cv.kind, cv.version, cv.status, cv.model_dump_json(), _ts(cv.created_at)))

    def get_config_version(self, version_id: str) -> Any:
        from .config import ConfigVersion
        r = self._x("SELECT body FROM {s}.config_versions WHERE id=%s", (version_id,)).fetchone()
        return ConfigVersion.model_validate(r["body"]) if r else None

    def config_versions(self, kind: str) -> list[Any]:
        from .config import ConfigVersion
        rows = self._x("SELECT body FROM {s}.config_versions WHERE kind=%s ORDER BY version DESC", (kind,))
        return [ConfigVersion.model_validate(r["body"]) for r in rows.fetchall()]

    def published_config(self, kind: str) -> Any:
        from .config import ConfigVersion
        r = self._x("SELECT body FROM {s}.config_versions WHERE kind=%s AND status='published' "
                    "ORDER BY version DESC LIMIT 1", (kind,)).fetchone()
        return ConfigVersion.model_validate(r["body"]) if r else None

    def recent_audit(self, limit: int = 100, kinds: list[str] | None = None) -> list[dict[str, Any]]:
        """Newest audit entries first, optionally only some kinds."""
        if kinds:
            rows = self._x("SELECT * FROM {s}.audit WHERE kind = ANY(%s) ORDER BY seq DESC LIMIT %s",
                           (list(kinds), limit))
        else:
            rows = self._x("SELECT * FROM {s}.audit ORDER BY seq DESC LIMIT %s", (limit,))
        return [{"seq": r["seq"], "ts": r["ts"], "incident_id": r["incident_id"], "kind": r["kind"],
                 "data": r["data"]} for r in rows.fetchall()]

    # ---- data source state (cursors) -----------------------------------
    def get_source_state(self, name: str) -> dict[str, Any] | None:
        r = self._x("SELECT body FROM {s}.source_state WHERE name=%s", (name,)).fetchone()
        return r["body"] if r else None

    def model_spend_since(self, ts: float) -> float:
        r = self._x("SELECT COALESCE(SUM(est_cost), 0) AS s FROM {s}.model_runs WHERE ts >= %s AND NOT shadow",
                    (ts,)).fetchone()
        return float(r["s"])

    def put_api_token(self, t: Any) -> None:
        self._x("INSERT INTO {s}.api_tokens(id, hash, body) VALUES (%s,%s,%s) "
                "ON CONFLICT (id) DO UPDATE SET body=excluded.body", (t.id, t.hash, t.model_dump_json()))

    def api_token_by_hash(self, h: str) -> Any:
        from .access import ApiToken
        r = self._x("SELECT body FROM {s}.api_tokens WHERE hash=%s", (h,)).fetchone()
        return ApiToken.model_validate(r["body"]) if r else None

    def api_tokens(self) -> list[Any]:
        from .access import ApiToken
        return [ApiToken.model_validate(r["body"]) for r in
                self._x("SELECT body FROM {s}.api_tokens ORDER BY id").fetchall()]

    def put_source_state(self, name: str, state: dict[str, Any]) -> None:
        self._x("INSERT INTO {s}.source_state(name, body) VALUES (%s,%s) "
                "ON CONFLICT (name) DO UPDATE SET body=excluded.body", (name, _j(state)))

    def update_facts(self, incident_id: str, facts: dict[str, Any], states: list[str]) -> bool:
        """Replace only the facts of an incident, and only while it is in one of `states` (atomic)."""
        cur = self._x("UPDATE {s}.incidents SET body = jsonb_set(body, '{facts}', %s::jsonb) "
                      "WHERE id=%s AND state = ANY(%s) RETURNING id", (_j(facts), incident_id, list(states)))
        return cur.fetchone() is not None
