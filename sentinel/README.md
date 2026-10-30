# kbg-sentinel

A portable, event-driven agentic framework. Business transactions (systemic or manual) raise events;
Sentinel recognises what kind of incident each one is, decides whether to auto-resolve, ask an LLM
agent, or hand it to a person, records how it was dispositioned, and learns from that record so more of
the work becomes automatic over time — with a person signing off every step up in autonomy.

```
transaction ─► receiver ─► Event ─► fingerprint ─► group / inhibit ─► registry match
                                                                        │
                       ┌────────────────────────────────────────────────┤ route
                       ▼                      ▼                         ▼
                    AUTO                     LLM                       HITL
               (playbook steps)    (agent + read-only tools)   (agent diagnosis → person)
                       └──────────► guarded, idempotent actions ◄───────┘
                                                │
                                           disposition ─► learning (promote / demote route)
```

This repo is **domain-free**. Each project supplies an **overlay** in its own repo: a registry YAML
(fingerprints, patterns, roles) plus Python actions, read-only tools and receivers.

| Overlay | Repo | Exemplar role |
|---|---|---|
| Acme Home | `MohanKbgrid/acme-sentinel` | Order Fulfilment Executive |

## Open-source stack

Everything runs on open-source components and self-hosts on any Linux server or cloud. Claude is the one
hosted service, used as the frontier model, and it is optional.

| Piece | Technology |
|---|---|
| System of record, queue, learning, similar cases | PostgreSQL 15+ with pgvector (the bundle ships 16) |
| Analytics | DuckDB, in-process, read-only over Postgres / SQLite / Parquet / archives |
| Frontier model | Claude (Anthropic API) |
| Small model + embeddings | Ollama on a shared host (e.g. the office Mac mini) behind `sentinel gateway` |
| Deeper investigations (optional) | CrewAI crews, using Sentinel's tools and model clients |
| API, workers, console | FastAPI, uvicorn, Python 3.11+, plain HTML/JS |
| Sign-in | Tokens, or any OpenID Connect provider (Keycloak, Entra ID, Google Workspace ...) |
| Monitoring | Prometheus + Grafana (dashboard included) |
| Packaging | Docker Compose with nightly backups ([deploy/](deploy/README.md)) |

CI fails if a runtime dependency is not under an approved open-source licence (`scripts/check_licences.py`).

## What it does

![Sentinel console](docs/console-exceptions.png)

**Recognise and route.** Events arrive from signed webhooks, polled APIs, database tables or overlay code,
are fingerprinted, grouped and matched to an exception pattern, which decides: automatic playbook, a model,
or a person. Repeat events keep an open case's facts current.

**Resolve safely.** Branching playbooks with read-only lookups; models (Claude, the small local model, or a
CrewAI crew) with read-only tools, the team's own procedure (SOP) and similar past cases in the brief,
masked personal data, fallbacks and escalation. Only allowed, schema-checked actions run, through
guardrails, idempotently, with outcome checks afterwards.

**People in the loop.** Reviews in the console, on Ask AI (A2UI cards) or WhatsApp, routed to the right
people by role and scope, with approval limits, escalation on SLA and an audit trail of every decision.

**Learn.** Every disposition is a label. Trust is earned on results (per pattern, or per segment such as
channel), promoted only with a person's sign-off (two for automatic), and lost at once on a reversal.
`sentinel evaluate` measures a model on past cases before it gets real ones.

**Run it without code.** The console edits exceptions, people and roles, models and connectors as
versioned, checked configuration (publish, roll back), gives access, and shows learning, insights and
activity. Templates for retail fulfilment, dairy distribution and manufacturing.

**Operate it.** Workers on a Postgres queue, Prometheus metrics and a Grafana dashboard, a model gateway for
a shared Mac mini, DuckDB analytics, nightly verified backups, restore drills, retention with archives.

Version by version: [CHANGELOG](CHANGELOG.md).

## Quick start

```powershell
git clone https://github.com/MohanKbgrid/kbg-sentinel.git; cd kbg-sentinel
pip install -e ".[dev]"
python -m pytest                      # SQLite (Postgres-only tests skip)
python examples\quickstart.py         # a complete overlay in one file
```

Run the suite on PostgreSQL as well (adds the multi-process test):

```powershell
$env:SENTINEL_TEST_PG = "postgresql://user:pass@localhost:5432/sentinel_test"; python -m pytest
```

Use it from an overlay repo:

```toml
dependencies = ["kbg-sentinel @ git+https://github.com/MohanKbgrid/kbg-sentinel.git@<commit>"]
```

Work a review queue from the command line (installed as `sentinel`):

```powershell
sentinel --overlay acme_sentinel:build_overlay --db acme.db reviews
sentinel --overlay acme_sentinel:build_overlay --db acme.db approve rev_xxx --by priya
```

## What's guaranteed

| Property | How |
|---|---|
| No event processed twice | Inbox table, unique dedupe key per event |
| No side effect executed twice | Every action step claims an idempotency key; re-drives skip completed steps |
| Crash-safe | `recover()` re-drives in-flight incidents; a step with unknown outcome goes to a person, never re-runs blind |
| Irreversible actions need a person | Only `reversible` (with compensation) or `safe` (idempotent, no business-state change) actions run unattended |
| LLM can't go rogue | Allowed actions only, schema-checked params, valid disposition codes, read-only tools, step cap, timeout, one repair attempt, then a person |
| Trust is earned slowly, lost instantly | Promotion needs a streak + agreement rate + a person's sign-off; any reversal demotes one level at once |
| Blast radius capped | Per-pattern circuit breaker on unattended resolutions per hour; per-pattern kill switch |
| Multiple workers safe | Postgres advisory locks per fingerprint; atomic action claims (tested with 6 processes) |
| Full audit | Every decision, attempt, compensation, learning change and reversal in an append-only audit log; secrets redacted |
| Only authorised people decide | RBAC on every decision, reversal, promotion and route change; refusals are audited |
| No silent stalls | Async jobs are created in the same transaction as their incident; expired leases are retaken; failures dead-letter to a person |
| PII stays out of models | Masked before every LLM call (incl. tool results), restored only for the actions |
| Performance stays flat | Per-event cost is bounded by limits, not history (see OPERATIONS for measured numbers) |
| Recoverable | Nightly backups checked against a manifest (SHA-256, row counts); restores re-check before they are accepted |
| Access is revocable | Console and system tokens stored hashed, expire, revoke at once; sign-in only for people in the people configuration |

## Layout

```
sentinel/
  models.py          Event, Pattern, Incident, Proposal, Decision, Disposition, PatternState
  fingerprint.py     facts + stable signatures from events
  registry.py        pattern matching (most specific wins) and validation
  engine.py          the pipeline, HITL decisions, reversal, SLA sweep, recovery, work queue, report
  rbac.py            roles, people, scoped assignments, approval authority
  worker.py          background worker loop
  routing.py         model router, metering, escalation, PII masking
  providers.py       Ollama / OpenAI-compatible clients, fallback, models file
  gateway.py         model gateway for a shared small-model host
  analytics.py       DuckDB reports and Parquet snapshots
  similarity.py      embedders, masked case text, vector helpers
  evaluate.py        replay past cases through a candidate model
  config.py          versioned configuration: parse, check, serialise, diff
  templates/         domain templates (registry + people)
  console/           console API and the static web UI
  expr.py            templates and conditions used by configuration
  sources.py         data sources (webhook, poll, sql)     mcp.py  MCP client and lookup tools
  edges.py           review cards, signatures, webhook / A2UI / WhatsApp edges
  access.py          stored access tokens        sso.py  OpenID Connect sign-in
  sop.py             procedures in the model brief   crew.py  CrewAI crews as a model (optional)
  backup.py          backups, verify, restore    retention.py  archive and remove old closed cases
  api.py             FastAPI app
  observe.py         metrics, JSON logs, redaction
  policy.py          guardrails and the learning policy
  llm.py             provider-agnostic agent loop (Claude client included)
  actions.py tools.py  action and tool registries
  store.py           SQLite store (reference)     pg_store.py  PostgreSQL store
  overlay.py         Overlay contract + registry YAML loader
  cli.py             operator CLI
examples/quickstart.py   examples/loadtest.py
deploy/              Dockerfile, site compose bundle, Mac mini gateway install
scripts/check_licences.py  scripts/gen_schema.py
sql/postgres_schema.sql  (generated)
docs/                ARCHITECTURE.md  EXTENDING.md  OVERLAY_CONTRACT.md  PORTING.md  OPERATIONS.md
tests/               unit, engine, learning, RBAC, queue, layers, outcomes, routing, edges, API, chaos, hardening
```

Read next: [ARCHITECTURE](docs/ARCHITECTURE.md) · [EXTENDING](docs/EXTENDING.md) (add a role or a project) · [OVERLAY_CONTRACT](docs/OVERLAY_CONTRACT.md) (what an overlay provides)
· [PORTING](docs/PORTING.md) (running on PostgreSQL) · [OPERATIONS](docs/OPERATIONS.md) (run, monitor, upgrade).
