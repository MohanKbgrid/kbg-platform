# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""Monthly partitions for the largest append-only tables on PostgreSQL (opt-in, for high-volume sites).

``audit`` and ``model_runs`` grow with every case and are read mostly by time. Partitioning them by month
keeps indexes small and vacuum cheap. Retention stays row-based, because audit rows about configuration and
access are kept while case rows go. ``events`` is not partitioned: duplicate detection needs a unique key
across all months, which a partitioned table cannot enforce.

``convert`` rewrites a table as a partitioned one in a single transaction (it waits for, then blocks, writers;
stop API and workers for large tables). ``maintain`` creates the next months' partitions; rows outside them
land in a default partition and are never lost.
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

TABLES = {
    "audit": {"pk": "(seq, ts)", "indexes": [
        "CREATE INDEX IF NOT EXISTS ix_audit_inc ON {s}.audit(incident_id, seq)",
        "CREATE INDEX IF NOT EXISTS ix_audit_ts ON {s}.audit(ts)",
        "CREATE INDEX IF NOT EXISTS ix_audit_chain ON {s}.audit(chain_no)",
        "CREATE INDEX IF NOT EXISTS ix_audit_unsealed ON {s}.audit(seq) WHERE chain_no IS NULL"]},
    "model_runs": {"pk": "(id, ts)", "indexes": [
        "CREATE INDEX IF NOT EXISTS ix_mrun_ts ON {s}.model_runs(ts)",
        "CREATE INDEX IF NOT EXISTS ix_mrun_inc ON {s}.model_runs(incident_id)"]},
}


def _pg(store: Any) -> None:
    if type(store).__name__ != "PostgresStore":
        raise ValueError("partitions are for PostgreSQL; SQLite sites do not need them")


def _months(start: datetime, end: datetime) -> list[datetime]:
    out, cur = [], start.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    while cur <= end:
        out.append(cur)
        cur = (cur.replace(day=28) + timedelta(days=4)).replace(day=1)
    return out


def _name(table: str, m: datetime) -> str:
    return f"{table}_{m.strftime('%Y%m')}"


def status(store: Any) -> dict[str, Any]:
    _pg(store)
    s = store.schema
    out = {}
    for t in TABLES:
        row = store._x("SELECT c.relkind FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
                       "WHERE n.nspname = %s AND c.relname = %s", (s, t)).fetchone()
        parts = [r["relname"] for r in store._x(
            "SELECT c.relname FROM pg_inherits i JOIN pg_class c ON c.oid = i.inhrelid JOIN pg_class p ON "
            "p.oid = i.inhparent JOIN pg_namespace n ON n.oid = p.relnamespace WHERE n.nspname = %s AND "
            "p.relname = %s ORDER BY 1", (s, t)).fetchall()]
        out[t] = {"partitioned": bool(row) and row["relkind"] == "p", "partitions": parts}
    return out


def _create_month(store: Any, table: str, m: datetime) -> None:
    s = store.schema
    nxt = _months(m, m.replace(day=28) + timedelta(days=4))[-1]
    store._x(f"CREATE TABLE IF NOT EXISTS {s}.{_name(table, m)} PARTITION OF {s}.{table} "  # noqa: S608
             f"FOR VALUES FROM ({m.timestamp()}) TO ({nxt.timestamp()})")


def convert(store: Any, table: str, *, now: datetime | None = None, ahead: int = 2) -> dict[str, Any]:
    """Rewrite ``table`` as monthly partitions (one transaction; safe to run twice)."""
    _pg(store)
    if table not in TABLES:
        raise ValueError(f"only {sorted(TABLES)} can be partitioned")
    if status(store)[table]["partitioned"]:
        return {"table": table, "already": True}
    s, spec = store.schema, TABLES[table]
    now = now or datetime.now(UTC)
    with store.transaction():
        store._x(f"LOCK TABLE {s}.{table} IN ACCESS EXCLUSIVE MODE")  # noqa: S608
        lo = store._x(f"SELECT MIN(ts) AS lo FROM {s}.{table}").fetchone()["lo"]  # noqa: S608
        first = datetime.fromtimestamp(lo, UTC) if lo is not None else now
        months = _months(first, now.replace(day=1) + timedelta(days=31 * ahead))
        store._x(f"CREATE TABLE {s}.{table}__p (LIKE {s}.{table} INCLUDING DEFAULTS) PARTITION BY RANGE (ts)")
        for m in months:
            nxt = _months(m, m.replace(day=28) + timedelta(days=4))[-1]
            store._x(f"CREATE TABLE {s}.{_name(table, m)}__p PARTITION OF {s}.{table}__p "  # noqa: S608
                     f"FOR VALUES FROM ({m.timestamp()}) TO ({nxt.timestamp()})")
        store._x(f"CREATE TABLE {s}.{table}_default__p PARTITION OF {s}.{table}__p DEFAULT")
        n = store._x(f"INSERT INTO {s}.{table}__p SELECT * FROM {s}.{table}").rowcount  # noqa: S608
        if table == "audit":                          # the seq default must outlive the old table
            seq = store._x("SELECT pg_get_serial_sequence(%s, 'seq') AS q", (f"{s}.audit",)).fetchone()["q"]
            if seq:
                store._x(f"ALTER SEQUENCE {seq} OWNED BY NONE")
        store._x(f"DROP TABLE {s}.{table}")
        store._x(f"ALTER TABLE {s}.{table}__p RENAME TO {table}")
        for m in months:
            store._x(f"ALTER TABLE {s}.{_name(table, m)}__p RENAME TO {_name(table, m)}")
        store._x(f"ALTER TABLE {s}.{table}_default__p RENAME TO {table}_default")
        store._x(f"ALTER TABLE {s}.{table} ADD PRIMARY KEY {spec['pk']}")
        for sql in spec["indexes"]:
            store._x(sql.replace("{s}", s))
    store.audit(None, "table_partitioned", {"table": table, "rows": n, "months": len(months)})
    return {"table": table, "rows": n, "partitions": len(months) + 1}


def maintain(store: Any, *, now: datetime | None = None, ahead: int = 2) -> list[str]:
    """Create the coming months' partitions for every partitioned table (run daily)."""
    if type(store).__name__ != "PostgresStore":
        return []
    now = now or datetime.now(UTC)
    made = []
    st = status(store)
    for t, info in st.items():
        if not info["partitioned"]:
            continue
        for m in _months(now, now.replace(day=1) + timedelta(days=31 * ahead)):
            if _name(t, m) not in info["partitions"]:
                try:
                    with store.transaction():
                        _create_month(store, t, m)
                    made.append(_name(t, m))
                except Exception as e:  # noqa: BLE001 - rows for that month are already in the default partition
                    store.audit(None, "partition_skipped", {"table": t, "month": m.strftime("%Y-%m"),
                                                            "error": str(e)[:300]})
    return made
