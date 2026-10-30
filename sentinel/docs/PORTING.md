# Running on PostgreSQL

The same engine runs on SQLite (dev, tests, single process) and PostgreSQL (production, many workers).
The full test suite passes on both; the multi-process test runs only on PostgreSQL.

## 1. Schema

Any PostgreSQL 15+ works: self-hosted (the Docker bundle in `deploy/` ships PostgreSQL 16 with pgvector),
or a managed service. Nothing depends on a particular vendor. Apply `sql/postgres_schema.sql` as a
migration (or let `PostgresStore` create it on first connect). Everything lives in schema `sentinel`;
workers connect directly with a server-side connection string. Add RLS by `tenant` if dashboards read
these tables.

## 2. Wire it up

```python
from acme_sentinel import build_overlay          # any overlay package
from sentinel import Engine, load_models
from sentinel.pg_store import PostgresStore

engine = Engine(build_overlay(systems=real_acme_clients),
                store=PostgresStore(os.environ["SENTINEL_PG"], schema="sentinel"),
                llm=load_models("models.yaml"))      # Claude + the small model; or AnthropicClient()
```

Replace the overlay's in-memory systems (e.g. `AcmeSystems`) with real clients implementing the same methods (Shopify Admin API, Ajio seller
API, the Silver-layer tables for stock, the payment gateway, messaging). Tests keep using the fakes.

## 3. Where events come from

| Source | How it reaches `engine.receive(...)` |
|---|---|
| Webhooks (Shopify, gateway) | FastAPI endpoint → `engine.receive("payment_gateway", body)` |
| Channel sync failures | The outbound job queue calls `receive("channel_sync", ...)` on final failure |
| Scheduled scans | pg_cron (or the worker loop) runs `scan_unfulfilled` and the stock reconciler |
| Manual | Ops desk / store app posts to `receive("manual", {...})` |

Receiving is cheap and idempotent: put it directly behind the endpoint, or behind your existing
outbox/queue if you want intake decoupled from resolution.

## 4. Worker loop (maintenance)

```python
while True:
    engine.recover()   # re-drive anything a crash left mid-flight (safe to repeat)
    engine.sweep()     # escalate overdue reviews
    time.sleep(60)
```

Run `recover()` at every worker start. Several workers can run concurrently: ingestion takes a
Postgres advisory lock per fingerprint and action claims are atomic.

## 5. Human-in-the-loop surface

Until a UI exists, the CLI works the queue. The notifier hook (`Overlay.notifier`) receives
`review_opened`, `review_escalated`, `promotion_proposed` and `manual_undo_needed` — send these to
Slack/WhatsApp/email with deep links. A UI needs only: list open reviews by role, show the incident
(facts, proposal, rationale, audit), and call `engine.decide(...)`.

## 6. Go-live sequence (per pattern)

1. **Shadow** — `Guardrails(shadow_patterns={...})`. People work as today and record outcomes.
   Watch `shadow_agreement` in `engine.report()`.
2. **Supervised** — remove from shadow. Agent diagnoses, people approve or edit.
3. **Earned** — when a promotion is proposed, review its dispositions, then `approve-promotion`.
4. **Watch reversals** — any reversal demotes automatically; the kill switch is `set-route <pattern> hitl`.

## Known limits

- An LLM call that times out keeps running in a background thread until the provider returns; the
  incident has already moved to a human, so nothing acts on the late answer.
- Grouping counts are updated when events attach, but facts are taken from the first event; a worsening
  bucket on a grouped event is linked, not re-evaluated. Re-evaluation on escalation is the next feature.
- Learning is per pattern. Per-fingerprint trust (e.g. trusted for Shopify, not Ajio) is a planned extension.
- Similar-incident retrieval for the LLM uses the pattern's recent dispositions; pgvector similarity
  over dispositions is planned for v0.4.
