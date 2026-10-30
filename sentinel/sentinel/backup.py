# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""Backups and restores of the Sentinel database.

    sentinel --pg "$SENTINEL_PG" backup --out /var/backups/sentinel --keep 14
    sentinel --pg "$SENTINEL_PG" restore /var/backups/sentinel/sentinel-20261010T020000Z.dump --yes
    sentinel --db sentinel.db backup --out ./backups

PostgreSQL: ``pg_dump`` of the Sentinel schema in custom format (compressed, restorable table by table),
restored with ``pg_restore --clean``. The pg_dump on the path must be at least the server's major version;
the site bundle runs it inside the database container so the versions always match. SQLite: an online copy
with SQLite's backup API, so the service can keep running.

Each backup gets a manifest next to it (``.json``): when, which Sentinel version, row counts per table and
the file's SHA-256. ``verify`` checks the file against the manifest and that the database tool can read
it. Restores are refused if the file does not match its manifest.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import sqlite3
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

TABLES = ["events", "incidents", "incident_events", "reviews", "dispositions", "pattern_state", "action_runs",
          "work_items", "deliveries", "audit", "model_runs", "case_vectors", "config_versions", "source_state",
          "api_tokens"]


class BackupError(RuntimeError):
    pass


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _counts(store: Any) -> dict[str, int]:
    from .retention import _Q
    q = _Q(store)
    have = q.tables()
    return {t: int(q(f"SELECT COUNT(*) AS n FROM {{s}}.{t}")[0]["n"]) for t in TABLES if t in have}  # noqa: S608


def _run(cmd: list[str], env: dict[str, str] | None = None) -> str:
    exe = shutil.which(cmd[0])
    if exe is None:
        raise BackupError(f"{cmd[0]} is not installed here (install the PostgreSQL client tools of the server's "
                          "version, or run the backup inside the database container)")
    r = subprocess.run([exe, *cmd[1:]], capture_output=True, text=True, env=env, check=False)  # noqa: S603
    if r.returncode != 0:
        raise BackupError(f"{cmd[0]} failed: {r.stderr.strip()[-2000:]}")
    return r.stdout


def _pg_env(dsn: str) -> tuple[list[str], dict[str, str]]:
    """--dbname without the password (it would show in the process list); the password goes in PGPASSWORD."""
    from psycopg.conninfo import conninfo_to_dict, make_conninfo
    parts = conninfo_to_dict(dsn)
    env = dict(os.environ)
    pw = parts.pop("password", None)
    if pw:
        env["PGPASSWORD"] = str(pw)
    return ["--dbname", make_conninfo(**{k: str(v) for k, v in parts.items()})], env


def backup(store: Any, out_dir: str | Path, *, keep: int | None = None, now: datetime | None = None) -> dict[str, Any]:
    now = now or datetime.now(UTC)
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    stamp = now.strftime("%Y%m%dT%H%M%SZ")
    kind = type(store).__name__
    counts = _counts(store)
    if kind == "PostgresStore":
        path = out / f"sentinel-{stamp}.dump"
        args, env = _pg_env(store.dsn)
        _run(["pg_dump", *args, "--format=custom", "--no-owner", "--no-privileges",
              f"--schema={store.schema}", f"--file={path}"], env)
    else:
        if store.path in (":memory:", ""):
            raise BackupError("an in-memory database cannot be backed up")
        path = out / f"sentinel-{stamp}.db"
        dst = sqlite3.connect(path)
        try:
            with store._lock:
                store._conn.backup(dst)
        finally:
            dst.close()
    from . import __version__
    manifest = {"file": path.name, "created_at": now.isoformat(), "sentinel": __version__,
                "store": "postgres" if kind == "PostgresStore" else "sqlite",
                "schema": getattr(store, "schema", None), "sha256": _sha256(path), "bytes": path.stat().st_size,
                "rows": counts}
    path.with_suffix(".json").write_text(json.dumps(manifest, indent=2))
    removed = prune(out, keep) if keep else []
    store.audit(None, "backup_made", {"file": str(path), "bytes": manifest["bytes"], "pruned": len(removed)})
    return {**manifest, "path": str(path), "pruned": removed}


def prune(out_dir: str | Path, keep: int) -> list[str]:
    """Keep the newest `keep` backups (and their manifests)."""
    if keep < 1:
        raise ValueError("keep at least one backup")
    files = sorted([p for p in Path(out_dir).glob("sentinel-*") if p.suffix in (".dump", ".db")], reverse=True)
    gone = []
    for p in files[keep:]:
        p.unlink(missing_ok=True)
        p.with_suffix(".json").unlink(missing_ok=True)
        gone.append(p.name)
    return gone


def verify(path: str | Path) -> dict[str, Any]:
    path = Path(path)
    man_path = path.with_suffix(".json")
    if not path.exists():
        raise BackupError(f"{path} does not exist")
    if not man_path.exists():
        raise BackupError(f"{man_path.name} (the manifest) is missing")
    man = json.loads(man_path.read_text())
    if _sha256(path) != man["sha256"]:
        raise BackupError(f"{path.name} does not match its manifest (changed or damaged)")
    if path.suffix == ".dump":
        listing = _run(["pg_restore", "--list", str(path)])
        tables = sum(1 for line in listing.splitlines() if " TABLE DATA " in line)
        detail = {"tables_with_data": tables}
    else:
        con = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        try:
            ok = con.execute("PRAGMA integrity_check").fetchone()[0]
        finally:
            con.close()
        if ok != "ok":
            raise BackupError(f"{path.name}: integrity check says {ok}")
        detail = {"integrity": ok}
    return {"file": path.name, "ok": True, "created_at": man["created_at"], "rows": man["rows"], **detail}


def restore(store: Any, path: str | Path) -> dict[str, Any]:
    """Replace the store's contents with a backup. Stop the API and workers first."""
    path = Path(path)
    v = verify(path)
    kind = type(store).__name__
    if kind == "PostgresStore":
        if path.suffix != ".dump":
            raise BackupError("a PostgreSQL store restores from a .dump file")
        man = json.loads(path.with_suffix(".json").read_text())
        if man.get("schema") and man["schema"] != store.schema:
            raise BackupError(f"the backup is of schema {man['schema']!r}, this store uses {store.schema!r}")
        args, env = _pg_env(store.dsn)
        _run(["pg_restore", *args, "--clean", "--if-exists", "--no-owner", "--no-privileges",
              "--single-transaction", f"--schema={store.schema}", str(path)], env)
    else:
        if path.suffix != ".db":
            raise BackupError("a SQLite store restores from a .db file")
        src = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        try:
            with store._lock:
                src.backup(store._conn)
        finally:
            src.close()
    now_counts = _counts(store)
    mismatch = {t: (n, now_counts.get(t)) for t, n in v["rows"].items() if now_counts.get(t) != n}
    if mismatch:
        raise BackupError(f"restored, but row counts differ from the manifest: {mismatch}")
    store.audit(None, "backup_restored", {"file": str(path), "created_at": v["created_at"]})
    return {"restored": path.name, "rows": now_counts}
