# Architecture

Sentinel borrows its front half from observability pipelines (receivers, normalisation, fingerprints,
grouping, inhibition, routing) and its back half from durable workflow engines (idempotent execution,
human-in-the-loop, compensation), then adds the piece neither has: a registry that learns from
dispositions and earns autonomy per incident type.

## 1. Event (canonical envelope)

Every source — webhook, scheduled scan, reconciler, staff entry — is normalised by an overlay
*receiver* into one shape: `type`, `source`, `tenant`, `payload`, `idempotency_key`. The idempotency key
is what makes redelivery harmless. Choose it so that a *meaningfully new* situation gets a new key
(ACME's SLA scanner uses `unfulfilled:{order}:{age bucket}`, so an order re-raises only when it gets worse).

## 2. Fingerprint

A `FingerprintRule` per event type extracts **facts** (named fields, numeric values bucketed into labels
like `>48h` or `large`) and builds a **signature** from the `group_by` facts plus tenant and type.

- Facts drive registry matching.
- The signature drives grouping, and is what learning is keyed on.

Pick `group_by` deliberately: per-order (`[order]`) makes one incident per order; per-SKU-location makes
one incident per stock line; dropping a field merges incidents across it.

## 3. Group and inhibit

- **Grouping:** if an open incident has the same signature, the event is linked to it instead of
  creating a new one. Default: absorb while open. `group_window_minutes` time-boxes it if wanted.
  Links live in their own table so grouping never rewrites the incident (this fixed a real lost-update
  race found in testing).
- **Inhibition:** a pattern lists `inhibited_by` parent patterns and `inhibit_on` facts that must match
  (e.g. `location`). While a matching parent is open, new children are created `SUPPRESSED`; when the
  parent is dispositioned, children close as `resolved_by_parent`. One warehouse outage = one ticket, not forty.

## 4. Registry match

Patterns match on event type plus fact constraints (`value`, `[list]`, or `"*"` for "present").
When several match: higher `priority`, then more exact-value constraints (exact beats wildcard), then
more constraints, then id. No match goes to the built-in `__unmatched__` pattern, owned by a
supervisor; those dispositions are the raw material for new patterns.

A pattern declares: its default `route`, its `max_route` ceiling, an optional deterministic `playbook`,
the `allowed_actions` (for agents and humans), `disposition_codes`, owner/escalation roles, SLA,
severity, the LLM confidence bar, and LLM instructions.

## 5. Route and resolve

Effective route = learned route from `pattern_state`, capped by the ceiling (AUTO needs a playbook),
and LLM degrades to HITL if no model is configured.

| Route | What happens |
|---|---|
| AUTO | Render the playbook from the event and execute it. |
| LLM | Agent loop: the model may call read-only tools, then must return one proposal (JSON). Validated against allowed actions, param schemas and codes. Executed if confidence ≥ the pattern bar. |
| HITL | The agent (if configured) or the playbook still produces a proposal, so the person reviews a diagnosis rather than investigating from scratch. |

Before anything runs unattended, guardrails apply:

1. **Shadow mode** (global or per pattern): compute the proposal, never execute; people keep working
   in the existing system and record what they did. This measures agreement before go-live.
2. **Irreversible actions** go to a person unless the action is `reversible` (has a compensator) or
   `safe` (idempotent, changes no business state, e.g. re-push a sync).
3. **Circuit breaker**: more than N unattended resolutions per pattern per hour routes to people.

Anything the agent can't do cleanly — bad JSON after one repair, disallowed action, timeout, provider
error, step cap — becomes a review with the reason and whatever proposal exists.

## 6. Execute (idempotent)

Each step of a proposal claims a key `incident:run:step:action` before running. Outcomes:

- New claim → run, with retries for retryable failures (`max_attempts` per action).
- Existing `ok` → already done, skip (this is how crash recovery avoids repeats).
- Existing `running` → the process died mid-step; outcome unknown → a human verifies. Never re-run blind.
- Failure → incident `FAILED` → review with the error. A human's new decision starts a new run number.

## 7. Human decisions

Reviews carry a proposal, reason, assignee role and SLA. A person can **approve** the proposal,
**modify** (choose other allowed actions/params), or **reject** (close with a disposition code and no
action). Whether the human *agreed* with the proposal is recorded — this is the learning signal.
`sweep()` escalates overdue reviews to the escalation role and notifies.

## 8. Disposition and learning

Every incident ends in exactly one disposition: code, resolver (`auto|llm|human|parent`), steps run,
proposal source, agreement, shadow flag. Then the learner updates the pattern's state:

- good outcome (human agreed with the proposal, or unattended resolution not reversed) → streak + 1
- disagreement → streak reset, any pending promotion withdrawn
- streak ≥ threshold *and* agreement rate ≥ 90% → **promotion proposed** (HITL→LLM→AUTO), which a
  person approves or rejects (`auto_promote=True` exists for low-risk deployments)
- **reversal** (a person says the outcome was wrong) → compensators run in reverse order, anything
  that couldn't be undone is flagged, and the pattern is **demoted one level immediately**

## 9. Incident lifecycle

```
OPEN ──► RESOLVING ──► RESOLVED ──► DISPOSITIONED
  │          │  └──► FAILED ──┐          ▲
  │          └──► AWAITING_HUMAN ◄───────┘ (decide)
  └──► SUPPRESSED ───────────────────────► DISPOSITIONED (parent closes)
```

All transitions go through one function; illegal ones raise. A property-based test random-walks the graph.

## 10. Testing and hardening (what was actually verified)

- Framework: 141 tests; 139 run on SQLite and all 141 on PostgreSQL 16 (two multi-process tests need Postgres).
- Chaos suite: random interleavings of every feature in async mode, invariants checked after each step; soaked at 3,000 scenarios.
  Each overlay repo adds its own scenario suite.
- Property-based: random sequences of events, failures, decisions, clock jumps and sweeps, with and
  without shadow mode and strict guardrails; checked after every step that no incident is stranded,
  every terminal incident has exactly one disposition, shadow mode executes nothing, no irreversible
  action ever ran unattended under strict guardrails, and every successful action maps to exactly one
  external call. Soaked at 600 scenarios.
- Failure injection: provider errors, timeouts, malformed/out-of-policy LLM output, flaky adapters,
  non-retryable failures, handlers returning garbage, crash mid-step (known-done and unknown outcome).
- Concurrency: duplicate deliveries racing, bursts on one fingerprint, two people deciding the same review.

Bugs found and fixed by this suite: exact matches losing to wildcards in pattern ranking; a lost-update
race where a resolving thread overwrote concurrently grouped events; and duplicate tickets for an
incident still awaiting a human once a time window elapsed.


## 11. Added in v0.2

- **RBAC** (`rbac.py`): a decision runs only if the person holds the review's role (or one above it) for
  the incident's scope, and has `approve` authority for every step within its amount limit. A refusal names
  the lowest role that could approve (`escalate_to`). Meta rights guard promotions, route changes, the
  kill switch and reversals; promotions to `auto` need two different approvers.
- **Work queue**: in async mode ingest commits the incident and its `resolve` job in one transaction.
  Workers lease jobs; failures retry with exponential backoff and dead-letter to a person. Other job kinds:
  `outcome_check`, `deliver`, and any the overlay registers.
- **Recovery** only takes incidents untouched for longer than a lease, so it never races a live worker.
- **Versioning**: `PatternState` remembers the definition hash its trust was earned on; a change in
  behaviour fields resets it (`pattern_changed` in the audit).
- **Outcome checks**: after a fix, a verifier decides held / failed / not yet. Failed costs trust like a
  reversal and re-raises the problem as `sentinel.outcome_failed`.
- **Model router**: the LLM resolver asks the router for the `diagnose` model; a candidate model runs the
  same loop in shadow and its agreement is recorded. A PII vault masks the brief and every tool result,
  and unmasks the model's reply before actions run.
- **Edges**: `_to_human` and `sweep` queue `deliver` jobs per recipient; the card is built at delivery
  time, so a review answered in the meantime is not sent.

## 12. Added in v0.3: open models, gateway, analytics

- **Providers** (`providers.py`): `OllamaClient` (native `/api/chat`, JSON mode, keep-alive, `/api/embed`) and
  `OpenAICompatibleClient`, both standard-library HTTP. Errors are classified: unreachable, timeout, 429 and
  5xx are `ModelUnavailable` (an outage); anything else is a configuration error.
- **Per-pattern model task**: `Pattern.model_task` picks the router route for the LLM step (default
  `diagnose`). It is not a behaviour field, so moving a pattern between models keeps its earned trust.
- **Fallback**: `FallbackClient(primary, fallback)` answers from the fallback on any primary failure; an
  outage also starts a cool-down during which the primary is skipped.
- **Escalation**: `ModelRouter.escalations[task]` is re-asked when the primary's answer is unusable or its
  confidence is below `escalate_below`; audited as `model_escalated`.
- **Metering**: every call is stored in `model_runs` (model that actually answered, provider token counts,
  latency, estimated cost, fallback reason, escalation flag), never prompts or replies.
- **Gateway** (`gateway.py`): authenticates customers by token hash; forwards only chat and embedding
  endpoints for allowed models; per-customer rate and concurrency caps inside a global cap; busy beyond the
  queue timeout answers 503 so the caller falls back; usage ledger and metrics per customer and model.
- **Analytics** (`analytics.py`): DuckDB attaches the store read-only and builds views over the JSON bodies;
  reports run as SQL. Parquet snapshots preserve history outside the live database.
- **Deployment**: workers expose `/metrics` themselves (they do most of the work in async mode); the
  Postgres store takes an advisory lock while creating or migrating its schema so processes can start together.

## 13. Added in v0.4: similar cases and model evaluation

- **Case vectors**: when an incident is dispositioned (not `parent`), its case text - pattern, facts and event
  payload, masked, with PII tokens normalised to `[PII]` - is embedded and stored as `case_vectors`
  (incident, pattern, tenant, model, dimension, vector). In async mode this is an `embed` work item; in sync
  mode it runs inline and a failure is only logged. `backfill_embeddings()` covers history.
- **Storage**: PostgreSQL uses a pgvector `vector` column and `<=>` cosine distance when the extension can be
  created or already exists; otherwise a float array with exact cosine in Python over the newest 5,000
  vectors of the pattern. SQLite stores JSON. Search is always within one pattern, tenant, embedding model
  and dimension, so vectors from different models never mix.
- **Retrieval**: before the model step the engine embeds the new case and adds up to `similar_k` nearest
  closed cases (similarity, facts, steps, code, resolver, reversed, outcome) to the brief as
  `similar_past_cases`; recent history stays as before. Delivered review cards carry a short version.
  Retrieval failures never block resolution.
- **Evaluation** (`evaluate.py`): picks closed cases decided by people (optionally also unattended ones), not
  reversed and not failed; rebuilds each brief with history and similar cases from before that case only;
  runs the candidate through the same validated loop (nothing executes); scores exact / action / code
  agreement and agreement with the primary model's proposal from the audit trail; verdict per pattern from
  `min_cases`, `threshold` and `max_error_rate`. Calls are metered as task `eval`; a summary is audited
  as `model_evaluation`.

## 14. Added in v0.5: configuration as data, and the console

- **Configuration kinds**: `registry` (roles, fingerprints, patterns), `people` (role tree, people, scoped
  assignments, authority) and `models`. Each save is a `ConfigVersion` (number, text, author, note,
  checksum, status draft / published / superseded) in `config_versions`.
- **Checks** (`config.py`): YAML and schema errors; actions, playbook steps and outcome verifiers the overlay
  does not provide; roles the people configuration lacks (including the fallback pattern's); a broken role
  tree; model routes that patterns need. Warnings: event types without fingerprint rules, authority for
  unknown actions, unknown edges, nobody holding `__configure__`, and coverage (a queue with no people, or
  only people above it, or everyone scoped on facts the pattern never carries).
- **Sets**: registry and people can be checked and published together (`publish_config_set`), each against
  the other as proposed - needed when a template renames roles. Application order: people, registry, models.
- **Publishing** requires `__configure__` (when people are configured), refuses errors, builds the new
  objects first (a models file that cannot be built is refused), records the version and audit entry in one
  transaction, then swaps the engine's registry, fingerprinter, directory or model router in place.
  Republishing an old version creates a new version that copies it. A pattern whose behaviour fields
  changed starts from zero trust through the existing definition hash.
- **Sync**: engines apply the published versions at start; workers check every 15 s and API processes run a
  background sync; a version that cannot be applied is audited once and the previous configuration keeps
  running.
- **Console**: `sentinel/console` mounts `/console/api` (person tokens; same RBAC) and serves static HTML,
  CSS and JavaScript at `/console`. Structured edits are made on the configuration as JSON in the browser and
  saved as YAML by the server, so the form editors and the YAML editor produce the same versions.

## 15. Added in v0.6: connectors and branching playbooks

- **Expressions** (`expr.py`): templates with dotted paths (list indexes allowed) and a fixed set of filters;
  conditions with eq / ne / gt / gte / lt / lte / in / not_in / contains / exists / empty / matches and any /
  all / not. Nothing is evaluated as code. Checked at configuration time (unknown filters or operators).
- **Data sources** (`sources.py`, configuration kind `connectors`): `webhook` sources are posted to
  `/v1/hooks/{name}` (HMAC verified against a secret from the environment) or `/v1/sources/{name}` (service
  token); `poll` and `sql` sources are fetched by workers: `schedule_sources()` queues one `poll` job per
  source per interval (dedupe key `poll:{name}:{slot}`), the job fetches with the stored cursor, maps, ingests
  and advances the cursor in `source_state`. SQL runs read-only. Emit rules: type, `when`, `each` (fan-out),
  idempotency `key`, payload. Secrets (`{{env.X}}`) only in a poll's url and headers.
- **MCP** (`mcp.py`): JSON-RPC 2.0 over stdio or HTTP (JSON or SSE replies, session id), `initialize`,
  `tools/list` (paginated), `tools/call`. Only allowlisted tools; `readOnlyHint: false` or
  `destructiveHint: true` refuses a tool even if listed; unannotated tools are allowed with a warning. A server
  that cannot be reached at publish still gets its tools registered and checked on first use; a call that fails
  reconnects once. Tools are named `server.tool` and merged with the overlay's tools for the model and
  playbooks.
- **Playbooks**: a step is an `action`, a `lookup` (result stored under `as`), or a `close` (with a
  disposition); any step may have a `when` and a `disposition`. The proposal holds only the action steps that
  applied. No applicable action or close, a failed lookup or an expression error means no proposal: the case
  goes to a person (audited as `playbook_no_branch` / `playbook_lookup_failed`). The definition hash of an
  action-only playbook is unchanged from earlier versions, so existing trust is kept.
- **Brief masking** now covers the case (incident, event, history, similar cases) and leaves tool and action
  names intact; before, a tool's name could be masked as personal data.

## 16. Added in v0.7: knowing more per case

- **SOPs** (`sop.py`): a pattern's `sop` goes into the brief unmasked (instructions, not case data); long
  procedures are split at headings and paragraphs and the sections nearest the case are chosen with the
  lexical embedder (the opening section is always kept). Not part of the definition hash.
- **Trust per segment**: `trust_by: [fact, ...]` keys pattern state as `pattern@fact=value|...`. Learning,
  reversals and outcome checks use the segment's state; a new segment starts at the pattern's current route.
  Setting the pattern's route sets every segment's. `trust_by` is in the definition hash only when set.
- **Crews** (`crew.py`): a `crew` model provider wraps a CrewAI crew (investigators plus a decider) as a
  `complete()` client. The resolver puts the case's tools in a context variable (`CASE_TOOLS`, carried into
  the worker thread), so a crew's tool calls are unmasked, run, recorded and masked by Sentinel. Repairs go
  to the crew's own model, not a new crew run.
- **Fact refresh**: a repeat event updates an open incident's facts atomically (only in waiting states) and
  pulls a review's due time forward when the case now matches a more urgent pattern.

## 17. Added in v0.8: people

- **Access** (`access.py`): stored tokens (hash only) for people and services, optional expiry,
  revocation, last use; the API checks the tokens file first, then the store. `__access__` right.
- **SSO** (`sso.py`): OpenID Connect authorization code with PKCE; state, nonce and verifier in a short-lived
  HttpOnly cookie (any replica can finish a sign-in); the ID token is taken from the token endpoint over TLS
  (OIDC Core 3.1.3.7) and its issuer, audience, expiry and nonce are checked; the person is matched on email or
  id and must be active. A sign-in issues a short-lived stored token.
- **Edges from configuration**: `A2UIEdge` (signed webhook carrying the card and its A2UI v0.8 rendering, or v0.9/v0.9.1 with `a2ui_version`;
  button presses return as `userAction`s), `WhatsAppEdge` (Cloud API interactive buttons or templates; replies
  verified with the app secret and matched to people by number). Configured edges are merged with the
  overlay's own.

## 18. Added in v0.9: production upkeep

- **Backups** (`backup.py`): pg_dump of the schema (custom format) or SQLite's online backup, with a manifest
  (SHA-256, rows per table); restore verifies the file first and the row counts after. The site bundle's
  `maintenance` service runs `sentinel maintain` nightly.
- **Retention** (`retention.py`): closed cases older than the horizon, with their rows in every table, are
  written to a gzip JSON-lines archive (fsynced) and deleted in one transaction per batch. Learning,
  configuration, tokens and governance audit entries stay.
- **HNSW** for similar cases: a partial expression index per embedding size
  (`(vec::vector(N)) vector_cosine_ops WHERE dim = N`), built concurrently; searches use it when present,
  with iterative scans where pgvector supports them.
- `sql/postgres_schema.sql` is generated from the store (`scripts/gen_schema.py`; CI checks it).

Operational detail lives in [OPERATIONS.md](OPERATIONS.md).

## 19. Added in v0.10: from custom build to configuration

- **Hardening** (H1-H14): pooled PostgreSQL connections with timeouts, egress and secret allowlists,
  unattended amount limits, lease heartbeats with fencing, cross-process locks, count-based health, indexes
  and keyset retention, single-use answer tokens for edges, scoped case reads and SSO signature checks,
  per-source dedupe and cursor tie-breakers, model budgets and prompt-injection checks, gateway limits,
  versioned migrations, default timeouts.
- **Configuration checks**: playbook params and lookup args against declared schemas; `match:` uses the
  playbook condition language; fingerprint rules are part of a pattern's meaning.
- **Write actions in configuration** (`httpactions.py`): HTTP calls with a parameter schema, success
  checks, optional undo, idempotency keys and egress checks, merged over the overlay's code actions.
- **Read-only views** (`explain.py`): `trace` (one event through matching, grouping, routing and the
  playbook without storing anything; against a draft too), `replay` (recent cases through a draft vs the
  running registry), `case` (one incident's story) and case search.
- **Going live** (`golive.py`): per-pattern `shadow:` in the registry, readiness checklist, switch as a
  published change. **Maker-checker**: `config_approval` in people.yaml.
- **Templates**: `template:` layers, stub actions, `sentinel template init`.
- **Operator reports** (`usage.py`, `value.py`, `fleet.py`): a signed and chained monthly usage export, a value
  report in the site's currency, a fleet view. Nothing here gates a feature.
- **Personal data** (`privacy.py`): access reports, erasure, scrubbing personal fields by age; docs/privacy.

## 20. Added in v0.11: platform

- **Tamper-evident audit** (`auditchain.py`): settled audit rows are sealed in signed, hash-chained batches
  without a global write lock; retention leaves tombstones and erasure leaves redactions, so the chain still
  verifies; export, independent verification and SIEM forwarding.
- **Hosted mode** (`hosted.py`): one service, many tenants, each with its own schema, pool, engine, tokens,
  SSO and secrets scope (`SENTINEL_SECRET_<TENANT>_...`); routing by host or path; weighted worker
  turns. Every engine now copies its overlay, so publishing on one never changes another.
- **Packs and catalogue** (`packs.py`, `catalogue.py`, `testing.py`): versioned packs with namespaced actions
  and tools, capabilities a site grants, settings and golden cases; console changes kept as a layer and
  re-applied over upgraded packs; a signed catalogue with file digests, dependency resolution and upgrades
  that keep settings and grants.
- **Connectors** (`connauth.py`, `connectors/`): login tokens (cached per tenant, refreshed after a 401),
  read-only HTTP lookups, XML polls and bodies, token-mode webhooks; ready-made templates for Shiprocket,
  Delhivery, Zoho Books, SAP Business One and TallyPrime. Slack, Teams and email edges, and pluggable edge
  kinds (`channels.py`, `edges.py`). Expect sources for "did not happen by" exceptions.
- **Operations**: bulk decisions, a phone review page, model cost and quality per exception, the monthly
  owner report, patterns drafted from unmatched cases, the visual playbook builder, monthly partitions on
  PostgreSQL, an exact cross-worker circuit breaker.
- **Admin**: environments and signed configuration bundles (`bundles.py`); SCIM provisioning with group
  roles (`scim.py`); cards in nine Indian languages (`i18n.py`); anonymised benchmarks across sites
  (`benchmark.py`); signed images, SBOMs, scans and security policies (`SECURITY.md`, `docs/security/`).

## 21. Added in v0.12: keys, Indian providers and live channels

- **Keys** (`secretstore.py`): connector and platform keys entered on the console's Keys page (or `sentinel
  secret set`), AES-256-GCM under a per-tenant key derived from `SENTINEL_MASTER_KEY`, bound to the key's
  name; never returned, audited, applied to every process at its next sync, and preferred over the
  environment. The page lists every key the published connectors, models and templates in use need.
- **Waiting for keys**: an edge, source, lookup or action whose key is missing reports "waiting for key" and
  the case goes to a person; nothing fails at publish.
- **WhatsApp through Gupshup and Interakt** (`wa_providers.py`): edge kinds with quick replies or approved
  templates; answers back on `/v1/wa/<edge>`, by shared token or signature.
- **Channel and warehouse templates**: Shopify, Amazon SP-API (LWA login), Flipkart, Ajio and Myntra (through
  the seller's partner endpoint) and a REST warehouse system. The ACME overlay's `LiveAcmeSystems` runs its
  playbooks on them (`ACME_SYSTEMS=live`).
- **Security**: the penetration test scope and checklist for an outside firm (`docs/security/PEN_TEST_SCOPE.md`).

## 22. Added in v0.13: how long a case lives

- **Persistence** (`persistence.py`): the protocol incident tools share, per exception with registry
  `defaults:`. A repeat limit at the top of the role tree, after which a review goes quiet and is listed in a
  daily digest; closing at the source by a `clear_when` event (matched on facts) or a scheduled read-only
  lookup; expiry of untouched cases; pauses that stop the SLA clock and come back by time or a new report;
  silences that hold matching cases (no unattended action, no cards) until they end.
- System closures use resolver `system` (codes `resolved_in_source`, `expired`): no learning, no case
  vectors; reviews carry `hold`, `quiet`, `top_repeats`, `rounds` and `reported_at`.

## 23. Added in v0.13: analytics that act

- **Metrics** (`kpi.py`, configuration kind `metrics`): datasets copied into an in-process DuckDB with
  external access off; KPIs as checked expressions over them, with dimensions, targets, owners and who may
  ask; queries by dimension and time grain, compared with the period before.
- **Both directions.** Monitors turn a KPI breach into an event (`kpi.breach`) that the registry routes to
  the KPI's owner like any other exception, report it again while it lasts and send `kpi.recovered`, which
  closes it at the source. Agents read KPIs through the `metrics.query` lookup and outcome checks measure
  the KPI after a fix (`verifier: metric`). People raise a case from a number (`kpi.raised`) in Ask AI or on
  the console.
- **Ask AI**: a catalogue with tool definitions, answers with a summary, a typed widget and A2UI v0.8
  messages, and a `sentinel.raise` userAction.
- **Escalation ceiling**: `escalation.stop_at` names the highest role(s) a review climbs to.

## 24. Added in v0.13: capabilities, methods and trusted data

The platform + domain pack split: the framework runs the loop (observe, case, route, decide, act, verify,
learn) and knows nothing of any business; an overlay (a domain pack) supplies the business's capabilities,
their intent and limits, exceptions, methods, metrics and connectors as versioned configuration, with code
only where a calculation or an integration needs it.

- **Capabilities** (`Capability`, registry `capabilities:`): an accountable role, intent, outcome metrics, an
  automation ceiling (`max_route`, checked when the registry loads) and `mode: observe` (every exception in
  shadow). `capabilities.py` reports each one's exceptions, outcomes, cases and stage.
- **Methods and provenance** (`Provenance` on incidents and dispositions): capability, method name, the
  exception's definition hash and the registry version. Evidence per method version (`method_evidence`)
  sits beside the existing replay, shadow and maker-checker publishing, so a method is proposed, tested on
  past cases, run in shadow, published by someone with the authority and rolled back by republishing.
- **Method learning** (`methodlearn.py`): candidates mined from human dispositions (actions within
  `allowed_actions`, parameters generalised to case facts or constants), backtested on recent cases, compared
  in shadow on every resolved case (`observe` from `_disposition`), promoted through an ordinary registry
  publish (maker-checker) and rolled back by restoring the exception's previous definition. Candidates live in
  source state; proposals run daily from the sweep. Randomised trials assign new cases to the candidate by a
  hash of (candidate, case) at creation (`Provenance.trial`, route forced to a person) and compare verified
  outcomes between arms.
- **Lookup datasets** (`kpi._lookup_rows`): rows through a connector lookup's full reply, paged, mapped by
  templates; templates carry standard `datasets:` (`connectors.with_datasets`).
- **Postgres outbox** (`connectors/postgres-outbox.yaml`): reads the application's trigger-written outbox through an `sql` source with
  bound `params` and a `(created_at, id)` cursor.
- **Decision trace** (`explain.case` -> `trace`): observation, method, proposal, decisions, resolution,
  actions and outcome as one chain, with its gaps.
- **Trusted data** (`DataChecks` on datasets): freshness, row count, keys, nulls and invalid-row rules
  checked on every load; untrusted data stops monitors acting and verifiers judging, and raises
  `data.untrusted` for the dataset's owner until `data.trusted`.
