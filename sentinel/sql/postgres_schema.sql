-- Sentinel tables for PostgreSQL 15+ (any distribution: self-hosted, RDS, Cloud SQL, Azure ...).
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

CREATE TABLE IF NOT EXISTS sentinel.events (
  id TEXT PRIMARY KEY, dedupe_key TEXT NOT NULL UNIQUE, tenant TEXT NOT NULL, type TEXT NOT NULL,
  body JSONB NOT NULL, received_ts DOUBLE PRECISION NOT NULL);
CREATE TABLE IF NOT EXISTS sentinel.incidents (
  id TEXT PRIMARY KEY, tenant TEXT NOT NULL, pattern_id TEXT NOT NULL, fingerprint TEXT NOT NULL,
  state TEXT NOT NULL, parent_id TEXT, body JSONB NOT NULL, created_ts DOUBLE PRECISION NOT NULL,
  updated_ts DOUBLE PRECISION NOT NULL);
CREATE INDEX IF NOT EXISTS ix_inc_fp ON sentinel.incidents(fingerprint, state);
CREATE INDEX IF NOT EXISTS ix_inc_pattern ON sentinel.incidents(pattern_id, tenant, state);
CREATE INDEX IF NOT EXISTS ix_inc_parent ON sentinel.incidents(parent_id);
CREATE INDEX IF NOT EXISTS ix_inc_state ON sentinel.incidents(state, updated_ts);
CREATE TABLE IF NOT EXISTS sentinel.incident_events (
  incident_id TEXT NOT NULL, event_id TEXT NOT NULL, seq INTEGER NOT NULL, PRIMARY KEY (incident_id, event_id));
CREATE TABLE IF NOT EXISTS sentinel.reviews (
  id TEXT PRIMARY KEY, incident_id TEXT NOT NULL, is_open BOOLEAN NOT NULL, due_ts DOUBLE PRECISION NOT NULL,
  body JSONB NOT NULL);
CREATE INDEX IF NOT EXISTS ix_rev_open ON sentinel.reviews(is_open, due_ts);
CREATE INDEX IF NOT EXISTS ix_rev_inc ON sentinel.reviews(incident_id);
CREATE INDEX IF NOT EXISTS ix_rev_open_role ON sentinel.reviews((body->>'assignee_role'), due_ts) WHERE is_open;
CREATE TABLE IF NOT EXISTS sentinel.dispositions (
  id TEXT PRIMARY KEY, incident_id TEXT NOT NULL UNIQUE, pattern_id TEXT NOT NULL, body JSONB NOT NULL,
  created_ts DOUBLE PRECISION NOT NULL);
CREATE INDEX IF NOT EXISTS ix_dsp_pattern ON sentinel.dispositions(pattern_id, created_ts);
CREATE TABLE IF NOT EXISTS sentinel.pattern_state (pattern_id TEXT PRIMARY KEY, body JSONB NOT NULL);
CREATE TABLE IF NOT EXISTS sentinel.action_runs (
  idempotency_key TEXT PRIMARY KEY, incident_id TEXT NOT NULL, action TEXT NOT NULL, status TEXT NOT NULL,
  result JSONB, created_ts DOUBLE PRECISION NOT NULL);
CREATE TABLE IF NOT EXISTS sentinel.work_items (
  id TEXT PRIMARY KEY, kind TEXT NOT NULL, incident_id TEXT, payload JSONB NOT NULL, status TEXT NOT NULL,
  attempts INTEGER NOT NULL, max_attempts INTEGER NOT NULL, run_after_ts DOUBLE PRECISION NOT NULL,
  lease_until_ts DOUBLE PRECISION, leased_by TEXT, last_error TEXT, dedupe_key TEXT UNIQUE,
  created_ts DOUBLE PRECISION NOT NULL);
CREATE INDEX IF NOT EXISTS ix_work_ready ON sentinel.work_items(status, run_after_ts);
CREATE TABLE IF NOT EXISTS sentinel.deliveries (
  id TEXT PRIMARY KEY, review_id TEXT NOT NULL, person_id TEXT, edge TEXT NOT NULL, status TEXT NOT NULL,
  body JSONB NOT NULL, created_ts DOUBLE PRECISION NOT NULL);
CREATE INDEX IF NOT EXISTS ix_dlv_review ON sentinel.deliveries(review_id);
CREATE TABLE IF NOT EXISTS sentinel.audit (
  seq BIGSERIAL PRIMARY KEY, ts DOUBLE PRECISION NOT NULL, incident_id TEXT, kind TEXT NOT NULL, data JSONB NOT NULL);
CREATE INDEX IF NOT EXISTS ix_audit_inc ON sentinel.audit(incident_id, seq);
CREATE TABLE IF NOT EXISTS sentinel.model_runs (
  id TEXT PRIMARY KEY, ts DOUBLE PRECISION NOT NULL, task TEXT NOT NULL, model TEXT NOT NULL, incident_id TEXT,
  ok BOOLEAN NOT NULL, shadow BOOLEAN NOT NULL, escalated BOOLEAN NOT NULL, latency_ms DOUBLE PRECISION NOT NULL,
  prompt_tokens INTEGER, completion_tokens INTEGER, chars_in INTEGER NOT NULL, chars_out INTEGER NOT NULL,
  est_cost DOUBLE PRECISION NOT NULL, fallback_reason TEXT, error TEXT);
CREATE INDEX IF NOT EXISTS ix_mrun_ts ON sentinel.model_runs(ts);
CREATE INDEX IF NOT EXISTS ix_mrun_inc ON sentinel.model_runs(incident_id);
CREATE INDEX IF NOT EXISTS ix_actrun_inc ON sentinel.action_runs(incident_id);
CREATE INDEX IF NOT EXISTS ix_audit_ts ON sentinel.audit(ts);
CREATE INDEX IF NOT EXISTS ix_work_done ON sentinel.work_items(status, created_ts);
CREATE INDEX IF NOT EXISTS ix_work_inc ON sentinel.work_items(incident_id);
CREATE INDEX IF NOT EXISTS ix_incev_event ON sentinel.incident_events(event_id);
CREATE INDEX IF NOT EXISTS ix_events_ts ON sentinel.events(received_ts);
CREATE INDEX IF NOT EXISTS ix_inc_created ON sentinel.incidents(created_ts, id);
CREATE TABLE IF NOT EXISTS sentinel.config_versions (
  id TEXT PRIMARY KEY, kind TEXT NOT NULL, version INTEGER NOT NULL, status TEXT NOT NULL, body JSONB NOT NULL,
  created_ts DOUBLE PRECISION NOT NULL, UNIQUE (kind, version));
CREATE TABLE IF NOT EXISTS sentinel.source_state (name TEXT PRIMARY KEY, body JSONB NOT NULL);
CREATE TABLE IF NOT EXISTS sentinel.api_tokens (id TEXT PRIMARY KEY, hash TEXT NOT NULL UNIQUE, body JSONB NOT NULL);
CREATE TABLE IF NOT EXISTS sentinel.audit_seals (
  seal_no BIGINT PRIMARY KEY, from_no BIGINT NOT NULL, to_no BIGINT NOT NULL, batch_digest TEXT NOT NULL,
  prev_hash TEXT NOT NULL, seal_hash TEXT NOT NULL, signature TEXT, created_ts DOUBLE PRECISION NOT NULL);
CREATE TABLE IF NOT EXISTS sentinel.audit_tombstones (
  chain_no BIGINT PRIMARY KEY, row_hash TEXT NOT NULL, removed_ts DOUBLE PRECISION NOT NULL, reason TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS sentinel.audit_redactions (
  chain_no BIGINT PRIMARY KEY, original_hash TEXT NOT NULL, redacted_hash TEXT NOT NULL,
  redacted_ts DOUBLE PRECISION NOT NULL);

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
