# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""Write sql/postgres_schema.sql from sentinel/pg_store.py (run after changing the store's tables).

    python scripts/gen_schema.py            # write
    python scripts/gen_schema.py --check    # exit 1 if the file is out of date (CI)
"""
from __future__ import annotations

import sys
from pathlib import Path

from sentinel.pg_store import _SCHEMA

HEADER = """-- Sentinel tables for PostgreSQL 15+ (any distribution: self-hosted, RDS, Cloud SQL, Azure ...).
-- Generated from sentinel/pg_store.py by scripts/gen_schema.py - do not edit by hand. PostgresStore
-- creates and upgrades the same objects on connect; apply this file instead when schema changes must go
-- through migrations. Every statement is idempotent.
--
-- Notes:
--   * Workers connect directly with a server-side connection string; do not expose this schema through a
--     public REST layer (PostgREST etc.). Add row-level security per tenant if dashboards read these tables.
--   * Run `sentinel worker` processes for the queue; several can share it (SKIP LOCKED).
--   * Similar-case search: with pgvector, `vec` is of type vector (CREATE EXTENSION vector needs a privileged
--     user once); without it, DOUBLE PRECISION[]. `sentinel vectors-index --dim N` adds an HNSW index.

CREATE SCHEMA IF NOT EXISTS sentinel;
"""

UPGRADES = """
-- upgrades of schemas made by older versions (PostgresStore also applies these on connect)
ALTER TABLE sentinel.dispositions ADD COLUMN IF NOT EXISTS unattended BOOLEAN;
UPDATE sentinel.dispositions SET unattended = (body->>'resolver' IN ('auto','llm') AND
  (body->>'shadow')::boolean = false) WHERE unattended IS NULL;
CREATE INDEX IF NOT EXISTS ix_dsp_unattended ON sentinel.dispositions(pattern_id, unattended, created_ts);
CREATE INDEX IF NOT EXISTS ix_rev_inc_open ON sentinel.reviews(incident_id, is_open);

-- similar-case vectors (pgvector variant; use DOUBLE PRECISION[] for vec where the extension is unavailable)
CREATE EXTENSION IF NOT EXISTS vector;
CREATE TABLE IF NOT EXISTS sentinel.case_vectors (
  incident_id TEXT PRIMARY KEY, pattern_id TEXT NOT NULL, tenant TEXT NOT NULL, model TEXT NOT NULL,
  dim INTEGER NOT NULL, vec vector NOT NULL, created_ts DOUBLE PRECISION NOT NULL);
CREATE INDEX IF NOT EXISTS ix_cvec_pattern ON sentinel.case_vectors(pattern_id, tenant, model, created_ts);
"""


def render() -> str:
    return HEADER + _SCHEMA.replace("{s}", "sentinel").rstrip() + "\n" + UPGRADES


def main() -> int:
    path = Path(__file__).resolve().parent.parent / "sql" / "postgres_schema.sql"
    text = render()
    if "--check" in sys.argv:
        if path.read_text() != text:
            print("sql/postgres_schema.sql is out of date: run python scripts/gen_schema.py", file=sys.stderr)
            return 1
        return 0
    path.write_text(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
