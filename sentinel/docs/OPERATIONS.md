# Operations

How to run Sentinel in production, what to watch, and how it behaves under load.

## Processes

| Process | Command | Scale |
|---|---|---|
| API | `sentinel serve --overlay acme_sentinel:build_overlay --pg $SENTINEL_PG --directory people.yaml --tokens tokens.yaml --async` | 1+ behind a load balancer |
| Workers | `sentinel worker --overlay acme_sentinel:build_overlay --pg $SENTINEL_PG --directory people.yaml --threads 4 --metrics-port 9101` | as many as needed; they share the queue |
| Model gateway (Mac mini) | `sentinel gateway --config gateway.yaml --host 0.0.0.0 --port 8090` | one per small-model host |
| Maintenance | `sentinel maintain --pg $SENTINEL_PG --backup-dir /backups --keep 14 --retention-days 365` | exactly one |

Add `--models models.yaml` (or `SENTINEL_MODELS`) to the API and workers to enable model steps. The
Docker bundle in `deploy/` runs all of this; see [deploy/README.md](../deploy/README.md).

With `--async` the API only records events and queues the work; workers resolve incidents, check
outcomes and deliver review cards. Several worker processes can share one Postgres queue: leases use
`FOR UPDATE SKIP LOCKED`, and a lease that expires (crashed worker) is picked up again. Each worker also
runs `recover()` and `sweep()` on a timer.

### Database connections

Each process keeps a pool of PostgreSQL connections (`SENTINEL_PG_POOL`, default 8; give each process at
least twice as many as it has threads, since a thread working a case holds one connection as the case's lock). A connection that is cut - database restart, failover,
network blip - is replaced on the next use; nothing needs restarting. Every session has a statement timeout
(`SENTINEL_PG_STATEMENT_TIMEOUT_MS`, default 120000) and a lock timeout (`SENTINEL_PG_LOCK_TIMEOUT_MS`,
default 30000), so nothing waits forever. A worker whose loop fails 30 times in a row (the database away
for minutes) exits with status 1 so Docker or systemd starts a fresh one; the bundle restarts it
automatically. Connections are named `sentinel:<schema>` in `pg_stat_activity`.

## Configuration files

**tokens.yaml**: only hashes are stored. Make a hash with `sentinel token-hash <token>`.

```yaml
tokens:
  - {sha256: 4f2a..., service: shopify-webhooks}   # may POST /v1/events and /v1/sources/{source}
  - {sha256: 9c1e..., person: priya}               # works reviews, subject to RBAC
edge_secrets_env:
  ask_ai: SENTINEL_EDGE_ASK_AI                     # HMAC secret read from this env var
```

**people.yaml**: roles (tree), people, scoped assignments and approval authority.

```yaml
roles:
  ops_head: {name: Operations Head}
  fulfilment_lead: {name: Fulfilment Lead, parent: ops_head}
  fulfilment_exec: {name: Fulfilment Executive, parent: fulfilment_lead}
people:
  - {id: priya, name: Priya, edges: [ask_ai, whatsapp], contact: {whatsapp: "+91..."}}
assignments:
  - {person_id: priya, role_id: fulfilment_exec, scope: {location: [WH_CHN]}}
authority:
  - {role_id: fulfilment_exec, action: reallocate_order}
  - {role_id: fulfilment_exec, action: cancel_order, level: propose}
  - {role_id: fulfilment_lead, action: cancel_order}
  - {role_id: finance_ops, action: refund_payment, max_amount: 10000}
  - {role_id: ops_head, action: __promote__}
  - {role_id: ops_head, action: __set_route__}
  - {role_id: fulfilment_lead, action: __kill_switch__}
  - {role_id: ops_head, action: __reverse__}
```

A senior role inherits the authority of every role below it and sees their queues, unless the rule says
`inherit: false` (only that role holds it). A rule with `needs_proposal: true` approves only what someone
else proposed: a playbook's proposal, or a case escalated to that role, is not enough (a buyer approves
the planner's purchase order, never one nobody proposed). An incident that
lacks a scoped fact is outside that person's scope (a location-scoped executive cannot act on a
channel-sync incident, which has no location). `sentinel validate` warns when a pattern's role has no
active people, or when everyone in it is scoped on a fact the pattern never produces. Promotions to
`auto` need two different approvers. Lowering a pattern's autonomy (the kill switch) needs only
`__kill_switch__`; raising it needs `__set_route__`.

**Propose, then approve.** When someone approves or modifies a case with steps they may only propose (`level:
propose`), or above their `max_amount`, nothing runs: their decision becomes the proposal of a new review for
the lowest role that may approve it ("approval needed: proposed by ..."), and the trail records
`proposal_forwarded`. The proposer cannot approve their own forward. A step with no authority at all is
refused as before.

Automatic playbooks and the model are held to amount limits too. By default an action that any person has
an amount limit for (`max_amount`) runs unattended only up to the **lowest** such limit; a larger amount goes
to a person, with the reason on the review. Set limits explicitly with `unattended:`:

```yaml
unattended:
  - {resolver: "*", action: refund_payment, max_amount: 2000}       # auto and model alike
  - {resolver: llm, action: post_shortage, max_amount: 500, patterns: [short_collection_minor]}
  - {resolver: auto, action: push_stock_to_channel}                  # no amount: no limit
```

**Editor support.** Every configuration kind has a JSON Schema in `schemas/`; add
`# yaml-language-server: $schema=<path>/schemas/<kind>.schema.json` as the first line of a file for autocomplete
and early errors (see `docs/SCHEMAS.md`). `sentinel validate` and the console check remain the full check.

## Environments and promotion (dev, staging, production)

Name each site's environment with `SENTINEL_ENV=dev|staging|prod`; it appears in `/healthz` and as a badge
on the console (red for production). Build and try configuration in dev, then move exactly what was tested:

```
sentinel --overlay ... bundle export --out bundle.json            # on staging (registry, models, connectors)
sentinel --overlay ... bundle plan bundle.json                    # on production: the diff and any problems
sentinel --overlay ... bundle import bundle.json --by mohan       # publishes every changed kind together
```

Set the same `SENTINEL_SECRET_BUNDLE_KEY` on both sites so bundles are signed and checked, and
`SENTINEL_ENV_ACCEPTS=staging` on production so it takes bundles only from staging. Import refuses a changed,
unsigned or unfit bundle (an action or tool production does not have) and publishes nothing; maker-checker
and the `__configure__` right apply as in the console. People are left out by default (`--kinds` adds them)
because contacts and roles usually differ between environments.

## Models

`models.yaml` names the models and decides which one handles what (see `deploy/site/config/models.yaml.example`):

- `routes`: task -> model. A pattern's `model_task` picks the task (`triage` for routine patterns,
  default `diagnose`).
- `{model: local, fallback: claude, cooldown_s: 60}`: when the small-model host is unreachable or busy,
  Claude answers and the host is skipped for the cool-down.
- `escalate` / `escalate_below`: an unusable answer, or one below the confidence threshold, is re-asked of
  the escalation model.
- `candidates`: shadow-test a model on another's work (`sentinel analytics models` shows agreement).
- `prices`: per 1k tokens, for cost reports.

Customer details are masked before every model call, local or Claude.

Cost and safety limits:

- `daily_budget: 500` in `models.yaml` caps the estimated spend per UTC day (in the currency of `prices`);
  once it is used up, model steps go to people until the next day.
- A pattern's `brief_fields: [order_id, age_hours]` sends the model only those payload fields (cheaper, and
  less text for anyone to steer it with).
- Tool results longer than 8,000 characters are cut, and a case that has sent more than 120,000 characters
  to the model goes to a person.
- Case text that reads like instructions to a model ("ignore previous instructions", "system:", a JSON
  answer) sends the model's proposal to a person instead of running it, and is recorded as
  `possible_prompt_injection`. The model is also told that case text is data, never instructions.

### Crews for deeper investigation (optional)

`pip install 'kbg-sentinel[crewai]'` adds the `crew` provider: a CrewAI crew of investigators plus a
decider that answers like any other model. Name it in `models.yaml`, give it the model it thinks with, and
route a task to it:

```yaml
models:
  claude: {provider: anthropic, model: claude-sonnet-5-5}
  investigators:
    provider: crew
    llm: claude
    max_iter: 6
    agents:
      - {role: Stock investigator, goal: Find where the stock for the order really is}
      - {role: Order investigator, goal: Establish what the customer was promised and what has happened since}
routes:
  investigate: investigators
```

Patterns with `model_task: investigate` use it. The crew sees the masked brief, uses the same read-only
lookup tools (each call is unmasked, run, recorded in the case and masked again by Sentinel), cannot act,
and its answer is validated, guarded and learned from like any model's. All its model calls go through the
named model client; CrewAI telemetry is off. A crew makes several model calls, so raise `llm_timeout_s`.

## Trust per segment

A pattern can earn trust separately for each value of some facts:

```yaml
  - id: order_stuck_no_stock
    trust_by: [channel]           # Ajio and Myntra orders earn promotions independently
```

Each segment keeps its own streak, promotions (approve them on the Exceptions page, or
`POST /v1/patterns/order_stuck_no_stock%40channel%3Dajio/promotion/approve`) and reversals. A reversal
demotes only its own segment. Setting the pattern's own route (`POST /v1/patterns/order_stuck_no_stock/route`)
sets every segment at once, and new segments start there: lowering it is the kill switch, after which each
segment earns its way back. Adding or changing `trust_by` changes the pattern's meaning, so earned trust
starts again.

## Console

The API serves the console at `/console` (the bundle: `http://<server>:8080/console`). People sign in with
their own person token from `tokens.yaml` (`sentinel new-token`). Give the people who may change
configuration the `__configure__` right:

```yaml
authority:
  - {role_id: ops_head, action: __configure__}
```

Anyone signed in can read and save drafts; publishing needs `__configure__`. Published configuration is
stored in the database and overrides the overlay's own YAML files from then on - every API and worker process
applies it within about 15 seconds, and new processes start with it. To go back to the files, publish their
content again (Changes → Edit a copy) or roll back to an earlier version. Every save and publish is in the
audit trail and on the Activity page.

### Going live

**Go live** (Configure) takes a site from first events to unattended work in three moves, with a checklist
that says what is still missing: events arriving and sources fetching cleanly, cards reaching people,
a model with a daily budget, every exception staffed, two people who can configure and two-person
approval on, a recent backup, reviews within SLA, few unmatched cases, no dead background work.

1. Put the exceptions in shadow (`shadow: true` per pattern, or **Back to shadow**): Sentinel proposes and a
   person decides every case.
2. Watch agreement - how often people chose what Sentinel proposed. An exception is **ready** at 20 shadow
   cases with 90% agreement or better.
3. **Go live** per exception, or take every ready one live at once. Live, an exception acts as far as its
   earned route, guardrails and unattended limits allow.

Every switch is a published registry change: versioned, in the audit trail, and with two-person approval it
waits for a second person. Shadow set in code (`Guardrails(shadow_patterns=...)`) is shown but cannot be
switched from the console. Command line: `sentinel golive status | live <patterns> --by <p> | shadow ...`.

### Two-person approval (maker-checker)

To make every configuration change need a second person, add to the people configuration:

```yaml
config_approval: {approvals: 1, kinds: [registry, people, connectors, models]}
```

The author of a version can no longer publish it alone: **Publish** marks it *awaiting approval*, and another
person with `__configure__` opens it on the Changes page and chooses **Approve and publish** (publishing
someone else's draft counts as approving it). Versions saved together (people and exceptions from the set-up
wizard, say) are published together once each is approved. A rollback is a new version and needs approval
too. Approvals belong to one exact version: editing it means a new version and new approvals. The check
refuses a policy that the active `__configure__` holders could never satisfy. From the command line:
`sentinel config waiting` and `sentinel config approve <version_id> --by <person>`.

### Access and single sign-on

The **Access** page (needs the `__access__` right) gives tokens to people and systems and revokes them.
A token is shown once, stored only as a hash, may expire, and stops working the moment it is revoked.
Tokens in `tokens.yaml` keep working; use them for the first administrator and for break-glass access.

For single sign-on add an `sso:` section to `tokens.yaml` (see `deploy/site/config/tokens.yaml.example`) and
register Sentinel as an OpenID Connect client at your identity provider (Keycloak, Entra ID, Google
Workspace, Okta, Authentik, Zitadel) with the redirect URL `https://<server>/console/sso/callback`. The
sign-in page then shows "Sign in with your company account". A person gets in only if the provider's
`email` (or the configured claim) matches a person's `contact.email` or id in the people configuration and
that person is active; everyone else is refused, and refusals are in the audit trail. Sessions last
`session_hours` and end when the person signs out.

The ID token's RS256 signature is checked against the provider's published keys, and every provider address
must be https. With `claim: email` the provider must mark the address verified; Microsoft Entra ID does not
send that flag, so use `claim: preferred_username` there (or set `require_verified_email: false` if you accept
the risk). The first sign-in ties a person to the provider's account id; a later sign-in by a different
account with the same email is refused. If someone really changed accounts, reset the link with
`POST /console/api/access/sso-reset/<person>` (needs `__access__`).

**Provisioning from the company directory (SCIM).** Entra ID, Okta, Google and JumpCloud can create,
update and remove people here. Add a `scim:` section to the people configuration that says which roles each
directory group gives (optionally with a scope), and roles every provisioned person gets:

```yaml
scim:
  group_roles:
    "Ops - Fulfilment": [fulfilment_exec]
    "Ops - Leads": [fulfilment_lead, {role: finance_ops, scope: {region: south}}]
  default_roles: []
```

In the directory's SCIM app use the tenant URL `https://<server>/scim/v2` and the secret token from
`SENTINEL_SECRET_SCIM_TOKEN` (hosted: `SENTINEL_SECRET_<TENANT>_SCIM_TOKEN`), or a tokens.yaml service token
named `scim`. A provisioned person's id is the part of their user name before the `@` (someone the people
configuration already lists with the same email keeps their id). Their roles come only from their groups;
deactivating or removing them in the directory makes them inactive here at once, including people the
people configuration lists. Provisioned people are not part of the people configuration text; changes are
audited (`scim_*`) and reach every process at its next configuration sync.

Who sees what: case details (`/v1/incidents/...`) only for people in the roles that work the case, or above
them, within their scope, and for `__configure__` holders; people's contact details only for `__configure__`
or `__access__` holders, who are also the only ones who may draft changes to people.

### Working many cases, and from a phone

- **Bulk decisions.** On Reviews, filter to one exception, select cases and **Approve selected** (each
  case's own proposal) or **Close selected** with a code. Every case is decided on its own with the same
  authority checks; ones that cannot be decided are listed with the reason. API: `POST /v1/reviews/bulk`.
- **Mobile page** at `/console/m`: the cases waiting for the person, one card each, with big Approve and
  Close buttons. Sign in with a token or the company account; "keep me signed in" is for a person's own
  phone only.
- **Suggestions.** The Exceptions page lists groups of recent unmatched cases with how people handled them,
  each as a draft pattern (and fingerprint rule) to add, review and save. With a model configured it
  writes the description and instructions (`task: suggest`).
- **Models by exception** (Learning page): calls, errors, escalations, latency, spend and cost per case for
  each exception and model, how often people agreed with the model, and how often its own fixes were reversed.
- **Owner report.** `sentinel report owner --month 2026-10` prints last month in a few lines (cases,
  automation, time and money saved, model spend, reversals, escalations, the busiest exceptions); `--send
  hari,hema` sends it by email, Slack or Teams. With `SENTINEL_OWNER_REPORT=hari,hema` the maintenance
  service sends it in the first days of each month.

### How long a case lives: repeats, closing at the source, expiry, pauses and silences

Duplicates are dropped by their idempotency key and repeats join the open case with the same fingerprint, so
one problem is one case. What happens when nobody answers, or the problem goes away, is set per exception
(the exception editor's **When nobody answers** section, or YAML), with site defaults in the registry:

```yaml
defaults:                          # for every exception that does not set its own
  escalation: {repeat: 2}          # at the top of the role tree, sent again twice; then no more cards
  expires_after_hours: 168         # untouched for a week (and not reported again): closed as expired
  pause_on: [awaiting_customer, awaiting_vendor]
  digest_hour: 9                   # the daily overdue list, in the site's time zone
  timezone: Asia/Kolkata
patterns:
  - id: order_stuck_no_stock
    clear_when:
      events: [{type: order.fulfilled, same: [order]}]     # this event closes the case for the same order
      lookup:                                              # or ask the WMS every 30 minutes
        tool: wms.order
        args: {order_id: "{{facts.order}}"}
        condition: {result.status: {in: [picked, shipped]}}
        every_minutes: 30
  - id: location_down
    expires_after_hours: 0         # never expires, whatever the default
```

- **Repeat limit.** A review past its SLA goes to the escalation role, then up the role tree one level per SLA.
  At the top it is sent again at most `repeat` times; then it goes quiet: no more cards, it stays overdue on
  the console ("past every escalation") and goes on the **daily overdue list**, sent to the people of its
  role over email, Slack or Teams at `digest_hour`. Without a rule it is sent again every SLA, as before.
- **Closing at the source.** A `clear_when` event closes the open cases whose `same` facts match (the event's
  fingerprint rule supplies its facts, else its payload's top-level fields). An event type that only clears
  is recorded and goes no further; it is never an unmatched case. A `clear_when` lookup is asked every
  `every_minutes` while the case is open. The case closes as `resolved_in_source`, its review is withdrawn
  and suppressed children close with it. A case whose action is running is left alone.
- **Expiry.** A case nobody has decided, paused or reported again for `expires_after_hours` closes as
  `expired`. The sweep checks every five minutes.
- **Pauses.** A person who can work the case pauses it (Pause on the review) for one of its `pause_on`
  reasons, for up to 30 days (72 hours if not said). The clock stops: no escalation, no expiry. It comes back
  when the time is up, with the SLA time that was left, or at once when the source reports the problem again.
- **Silences** (the Silences page; needs `__silence__` or `__kill_switch__`). For planned work, for one
  exception or all, where facts match (`location=WH_CHN`), for up to 14 days. Matching cases are recorded but
  nothing runs on its own and nobody is sent a card; existing reviews stop escalating. When the silence ends,
  or is ended early, the held cases go to people with a fresh SLA.

Closing at the source and expiry are not decisions, so they teach nothing: earned trust does not move, and
the cases are not used as similar-case examples. The Value page shows each exception's cleared and expired
cases, and marks **tune** an exception where they are 30% or more of its cases: its match is too wide, it
needs a `clear_when`, or it should expire sooner.

### Cases and tracing an event

**Cases** lists every exception Sentinel has handled, newest first. Search by order number or any reference
(it looks through each case's facts and first event, within the chosen time window), by exception, state, or
a fact (`channel=amazon`). A case opens on its whole story in time order: when it opened and on which
route, grouped repeats, the model's calls, every action run and its result, reviews and where their cards
went, decisions, the outcome check, and any reversal. People see only the cases their roles work.
**Reverse this fix** (needs `__reverse__`) undoes what can be undone, records the mistake with your note,
and takes away the trust the exception had earned.

**Trace an event** answers "why did this go there?" without touching anything: paste an event (or open a
case and choose *Trace its event again*) and Sentinel shows the facts it reads, every exception that could
match and which clause failed for the ones that did not, whether it would be grouped, suppressed or ignored
as a duplicate, the route and why, each playbook step, and who would get the review. Nothing is stored, no
action runs, no model is asked. With `__configure__` you can also run the playbook's read-only lookups and
trace against your unsaved exception changes before publishing them. From the command line:

```
sentinel --overlay ... trace event.json                      # {type, source, payload}
sentinel --overlay ... trace payload.json --type order.unfulfilled --registry draft.yaml --lookups
sentinel --overlay ... case inc_0123abcd
```

### Replaying a draft before publishing it

On the Changes page, an exceptions draft has **Replay last 30 days** (needs `__configure__`). Sentinel runs
the first event of every recent case through the running exceptions and through the draft, and lists what
the draft would change: which exception cases go to, their route, the outcome, and the actions a playbook
would take, with examples linked to the cases. Nothing is stored and no lookups run. Grouping, suppression
and the circuit breaker depend on what was open at the time and are left out. From the command line:
`sentinel --overlay ... config replay draft.yaml --days 30`.

## Data sources and lookup tools

Configure them in the console (Data sources & tools) or as the `connectors` configuration; see
`deploy/site/config/connectors.yaml.example`. Put secrets in the environment (`.env`) and refer to them as
`{{env.NAME}}` (or `secret_env: NAME`) - the check warns when one is not set in the process.

Configuration can be published from the console, so it is kept away from the server itself:

- **Secrets:** configuration may only read variables named `SENTINEL_SECRET_...` or `SENTINEL_EDGE_...`,
  `SENTINEL_GATEWAY_KEY`, or those listed in `SENTINEL_CONFIG_SECRETS`. The database password, the Claude key
  and everything else in the process are out of its reach.
- **Network:** polled sources, SQL sources, MCP servers, edges and model servers named in configuration may
  not reach loopback, private or reserved addresses unless allowed in `SENTINEL_EGRESS_ALLOW` (CIDRs or host
  names, e.g. `10.20.0.0/16,wms.acme.local` for a warehouse system or the office Mac mini on the office
  network). Cloud metadata and link-local addresses are always refused, redirects are not followed and
  responses over 10 MB (`SENTINEL_EGRESS_MAX_BYTES`) are refused.
- **Programs:** an MCP server over stdio runs a program on the server, so configuration may only name a
  command the overlay allows (`Overlay.mcp_commands`) or one listed, exactly as written, in a YAML file named
  by `SENTINEL_MCP_COMMANDS`. It starts with a minimal environment.

Signed webhooks go to
`/v1/hooks/<source>` and need no token; unsigned ones go to `/v1/sources/<source>` with a service token. Poll
and SQL sources are fetched by the workers on their interval; "Fetch now" runs one immediately. The last
fetch, cursor and error of each source are on the page; failures retry with backoff and show as dead work items
after three attempts. Give an SQL source a read-only database user.

Cursors: a cursor on a timestamp alone should be queried with `>=` (rows sharing the last timestamp are read
again and recognised as duplicates by their keys). Better, add a unique tie-breaker - `cursor: {field:
item.updated_at, tie: item.id}` - and query `WHERE (updated_at, id) > (%(cursor)s, %(cursor_tie)s)` (or
`{{cursor}}` / `{{cursor_tie}}` in a polled URL): then no row is skipped or re-read. Duplicates are recognised
per tenant and source, so the same key from two systems is two events.

### CloudEvents (open standard, structured and binary)

`POST /v1/cloudevents` accepts [CloudEvents 1.0](https://cloudevents.io) over HTTP, in both modes, for any system
or broker that already speaks it. It is the same receiver as `POST /v1/events`: the same service bearer token,
rate limit and size caps (the body is capped at four times `max_event_bytes`, the payload at `max_event_bytes`),
and the same idempotency rule.

| CloudEvents | Sentinel event |
|---|---|
| `id` | `idempotency_key` (a repeated id from the same `source` is a duplicate, whichever mode it came in) |
| `source`, `type` | `source`, `type` |
| `time` | `occurred_at` (RFC 3339 with an offset; absent means now) |
| `subject` | `payload.ce_subject` |
| `data` | `payload` (a JSON object as is; any other JSON value as `{"value": ...}`) |
| extension `tenant`, `correlationid` | `tenant`, `correlation_id` (other extensions are ignored) |

- **Structured:** `Content-Type: application/cloudevents+json`, the whole event as the JSON body (`data_base64`
  is accepted when it holds JSON).
- **Binary:** `ce-id`, `ce-type`, `ce-source`, `ce-specversion: 1.0` (and optionally `ce-time`, `ce-subject`)
  headers, percent-decoded, with the data as the body (`application/json`, or `text/*`).
- **Refused with a clear message:** a missing or empty `id`, `source`, `type` or `specversion`, a `specversion`
  other than `1.0`, a `time` that is not RFC 3339 with an offset, a malformed body (400); batch mode,
  other formats and other data types (415); oversize (413); no or a wrong token (401, 403).

### "Did not happen by" exceptions (expect sources)

Some exceptions are the absence of something: an indent not received by 05:30, a settlement not filed by
21:00, a GST return not submitted by the due date. An `expect` source checks at a time each day:

```yaml
sources:
  indents_by_0530:
    kind: expect
    at: "05:30"
    tz: Asia/Kolkata                      # or an offset like +05:30
    days: [mon, tue, wed, thu, fri, sat]  # optional
    expected: [{route: R1}, {route: R2}, {route: R3}]
    match_on: "{{item.route}}"
    present: {url: "https://erp.example/api/indents?date=today", items: body.indents}   # or dsn_env + query
    emit:
      - type: indent.missing
        key: "{{item.route}}:{{item.date}}"
        payload: {route: "{{item.route}}", date: "{{item.date}}", deadline: "{{item.deadline}}"}
```

At the time, workers read what is there and raise one event per expected item that is missing (each gets
`date` and `deadline`). Without `expected`, one event is raised when nothing at all is there. It runs once a
day; re-running by hand raises nothing new because the key carries the date.

### Actions defined in configuration

An API call that changes something (hold an order, reassign a shipment, raise a ticket) can be defined under
`actions:` in the connectors configuration instead of in the overlay's code. Each declares its parameters
(checked against every playbook step and model proposal), the request (method, URL, headers, JSON body;
secrets only from allowlisted `SENTINEL_SECRET_*` variables and only in the URL or headers), what counts as
success (`ok_status`, `ok_when` on the reply), and optionally `compensate:` - the call that undoes it, which
makes the action reversible and so eligible to run unattended. `safe: true` is for calls that change nothing
that matters. Every call carries the step's idempotency key and goes through the outbound-address checks;
429 and 5xx replies are retried, anything else goes to a person. See `sentinel/httpactions.py` for the full
shape. Publish the connectors and the exceptions that use the new action together (the set-up check refuses
an exception that uses an action nobody provides, and a connectors change that removes one still in use).

### Keys

Connectors are configured first and wait for their keys. The console's **Keys** page lists every key the
published connectors and models name, what each is (from the connector templates), where it is used and
whether it is set: entered here, from the server's environment, or missing. A person with `__configure__`
pastes a key and saves it; it is encrypted (AES-256-GCM, a key per tenant derived from `SENTINEL_MASTER_KEY`)
and never shown again, only its last four characters and who set it. A key saved here is used instead of an
environment variable of the same name, by every process, at once, and the connectors are rebuilt with it.
**Test login** buttons try each `auth:` login. An edge whose key is missing waits: its cards stay in the
console until the key arrives. From the command line: `sentinel secret list`, `sentinel secret set NAME --by
mohan` (reads the value from standard input) and `sentinel secret clear NAME --by mohan`.

Generate the master key once with `sentinel new-master-key` and keep it only in the server's environment:
not in the database, its backups or git. Without it the Keys page is read-only and keys come from the
environment.

### Ready-made connectors

`sentinel connector list` shows the connector templates: **Shiprocket** and **Delhivery** (NDR, RTO and lost
shipments from their webhooks; tracking lookups; re-attempt and cancel actions), **Zoho Books** (overdue
invoices; invoice and customer lookups; the payment reminder), **SAP Business One** Service Layer (open sales
orders; business partner and stock lookups; close a sales order, undone by reopening it) and **TallyPrime**
(today's Day Book as voucher events; outstanding bills and ledger balances; no writes). Sales channels and the
warehouse: **Shopify** (paid orders not fulfilled, fulfillment webhooks; order and SKU lookups; hold a
fulfillment, undone by releasing it, set available stock, cancel), **Amazon SP-API** (unshipped orders through
an LWA login; order items; set a listing's quantity), **Flipkart** (shipments awaiting dispatch; set stock),
**Ajio** and **Myntra** (no public seller API: through the partner or aggregator endpoint the seller has, with
open orders and stock updates) and a **warehouse system** of the usual REST shape (location health, stock
reconciliation; stock and order lookups; expedite a pick, move an order, both undone, and a cycle count;
change the paths to the WMS). **Postgres outbox** (any application that writes events to a table): Sentinel reads
the application's `sentinel_outbox` table, which its database triggers fill in the same transaction as the
change (orders fulfilled or cancelled, sync jobs failing and recovering), with a read-only login and a cursor;
The application holds no Sentinel URL or secret and nothing is lost while Sentinel is down. **Gupshup** and
**Interakt** are WhatsApp edges. A connector added before its
keys are entered waits for them: its sources, lookups and actions report "waiting for key" and cases go to a
person until the key is saved on the Keys page. `sentinel connector
show <name>` lists the environment variables to set and the fingerprint rules to add for its events;
`sentinel connector add <name> --into connectors.yaml` merges it (or **Add to draft** on the Data sources page).
Check the fields against the customer's account and `sentinel trace` a sample before going live.

Connectors configuration also takes:

- `auth:` login tokens for APIs that issue them (a login call, where the token is in the reply, how long it
  lasts). Use `{{auth.<name>}}` in URLs and headers; tokens are cached per process and tenant and fetched again
  after a 401.
- `lookups:` read-only tools the model and playbooks may use: an HTTP GET (or a read-only query sent as POST,
  declared `reads_only: true`), with `result:` choosing the part of the reply to keep.
- `format: xml` on a polled source, and XML request bodies (strings), for Tally and SOAP services. XML replies
  become nested objects (attributes as `_NAME`); DOCTYPE and entity declarations are refused. The `xml` filter
  escapes values placed in XML.
- `signature: {mode: token}` for webhooks that send a shared token in a header instead of an HMAC.
- `params:` on an `sql` source: named values for the query (`%(tenant)s`), which may be `{{env.X}}` templates;
  always bound as parameters, never pasted into the query. `correlation:` on an emit rule gives the event's
  correlation id (an order, a batch, a job), shown in the case's decision trace.

SAP ECC has no Service Layer: read it through an outbox table or a read-only view with a `sql` source.

## Metrics: KPIs, monitors and Ask AI

Configuration kind `metrics` (the console's **Metrics** page, or YAML) defines **datasets**, **metrics**
(KPIs) and **monitors**. Data is copied into DuckDB inside the Sentinel process and queried there, never
against the live systems; the DuckDB connection has external access switched off, so a metric's SQL can only
read the loaded datasets. An overlay can ship its own metrics (`Overlay.metrics`) until one is published.

```yaml
datasets:
  orders:  {kind: sql, dsn_env: SENTINEL_SECRET_OMS_DB, refresh_minutes: 15,
            query: "select * from orders where paid_at > now() - interval '90 days'"}
  counts:  {kind: http, url: "{{env.SENTINEL_SECRET_WMS_URL}}/counts", items: body.rows,
            headers: {Authorization: "Bearer {{env.SENTINEL_SECRET_WMS_TOKEN}}"}}
  export:  {kind: file, path: nightly/orders.csv}        # under SENTINEL_DATA_DIR; .csv, .json or .jsonl
  demo:    {kind: overlay, name: orders}                  # rows from the overlay's code
  cases:   {kind: sentinel, name: cases}                  # Sentinel's own cases (or reviews)
metrics:
  otif:
    title: On time in full
    dataset: orders
    time: promised_at                                     # the column periods are counted on
    filter: delivered_at is not null
    value: avg(case when on_time and in_full then 1.0 else 0 end)
    format: percent                                       # percent | number | hours | currency
    dimensions: [location, channel]
    target: {gte: 0.97}
    owner: OPS-07                                         # the KPI's owner role
    roles: []                                             # who may ask it (empty: everyone signed in)
monitors:
  otif_by_location:
    metric: otif
    by: [location]
    window_days: 1
    every_minutes: 60
    when: {target_ok: false}                              # over value, target_ok, baseline, change_pct, rows
    min_rows: 10
```

**Analytics to agents.** Each monitor runs on its interval (the workers schedule it, like polled sources).
For each group that breaches it ingests a `kpi.breach` event (monitor, metric, title, value, target, baseline,
change, rows and the group's dimensions); add a fingerprint rule and an exception for it, owned by the KPI's
owner. While the breach lasts every run reports it again, so the case keeps its facts current and does not
expire; when the group recovers the monitor sends `kpi.recovered`, which closes the case at the source with
`clear_when: {events: [{type: kpi.recovered, same: [metric, location]}]}`. The configuration check warns
when a monitor's events have no fingerprint rule or no exception, or no exception closes on recovery.

**Agents reading analytics.** With metrics configured the model and playbooks get a `metrics.query` lookup
(metric, `by`, `filters`, `days`), and an outcome check `{verifier: metric, params: {metric: otif, facts:
[location]}}` measures the metric for the case's facts since the fix: back on target is a held outcome, still
missing is a failed one (which costs the exception its trust and raises the problem again).

**Ask AI.** The chat gateway calls these with the person's own token:

- `GET /v1/ask/catalog`: the metrics this person may ask, and tool definitions (`sentinel_metric`,
  `sentinel_raise`) its model can use as they are.
- `POST /v1/ask/metric` `{metric, by, filters, days, grain, compare}`: the numbers, a one-line summary for
  the model to answer with, a typed `widget` (kpi, line, bar) for the app's chart renderer, and A2UI v0.8
  messages (a headline, the rows, a `Chart` custom component carrying the widget, and a button).
- `POST /v1/ask/raise` `{metric, filters, note}`, or the A2UI button (`sentinel.raise`, signed like answers,
  to `/v1/edges/<edge>/a2ui`): a person asks the agent to act on what they are looking at. It opens a
  `kpi.raised` case with the metric's current value, for the exception that handles that metric.

**Datasets from a connector.** `kind: lookup` reads rows through a connector's read-only lookup (its login,
paging and XML handled by the connector) and maps them to columns in configuration, so the same KPIs and checks
work whichever system holds the data:

```yaml
datasets:
  bank_lines:
    kind: lookup
    lookup: zoho.bank_transactions          # from the zoho-books connector
    args: {page: "{{page}}", since: "{{now|days_before:60|strftime:%Y-%m-%d}}"}
    pages: {size: 200, max: 25}             # {{page}} counts up until a short or empty page
    each: null                              # or a list inside each item: one row per entry (Tally ledger entries)
    where: {item.status: {not_in: [excluded]}}
    columns:
      line_id: "{{item.transaction_id}}"
      matched: "{{item.status|in:categorized,matched,manually_added}}"
      age_hours: "{{item.date|hours_since}}"
    vars: {monthly_burn: 4200000}           # constants ({{vars.x}}); append: [...] adds rows
```

Connector templates ship ready-made datasets with the standard finance columns (`bank_lines`, `cash_position`,
`invoices`): **zoho-books** and **tally**. `sentinel.connectors.
with_datasets(metrics, "tally")` (or `{"bank_lines": "tally", "invoices": "zoho-books"}`) switches a metrics
configuration's datasets to them, keeping the business's owner and adding the template's checks. Mapping
filters: `date:%Y%m%d`, `days_before:N`, `strftime:FMT`, `one`, `get:PATH`, `eq/ne/in/gt/lt`, `present`, `not`,
`pick:A,B`, `neg`. A lookup used by a dataset returns its whole reply (not the shortened one the model sees).

**Derived columns.** Any dataset can add `derive:` - columns computed in order from the loaded rows (each may
use the ones before it), whatever the source. A business rule is then written once in configuration, not in
each source's query:

```yaml
  stock_position:
    kind: sql                               # or overlay, http, file, lookup
    derive:
      projected: on_hand + coalesce(on_order, 0) - daily_demand * lead_time_days
      cover_at_arrival: projected / nullif(daily_demand, 0)
      decision: "case when cover_at_arrival < floor_days then 'order_now' else 'ok' end"
```
Expressions are SQL over the dataset's columns (no statements); a mistake fails the load with the column named.

**Data you can trust before anyone acts on it.** A dataset may carry `checks` and an `owner` role:

```yaml
datasets:
  bank_lines:
    kind: sql
    dsn_env: SENTINEL_SECRET_ERP_DB
    query: select * from bank_lines where booked_at > now() - interval '45 days'
    owner: TEC-04                          # who fixes the data
    checks:
      fresh: booked_at                     # newest value must be recent ...
      max_age_hours: 26                    # ... within this many hours
      min_rows: 100
      unique: [line_id]                    # a key: no two rows share it
      not_null: [amount, account]
      invalid:                             # name -> condition marking a wrong row; any such row fails
        no_account: "account is null or account = ''"
      types: {booked_at: time, matched: boolean, amount: number}   # boolean | integer | number | time | text
```

`types` declares what each column must hold. A value that does not fit ("yes" for a boolean, "13/10/2026"
for a time) is stored as null and counted, so the dataset is untrusted and its metrics still run. A column
without a declared type that mixes text with other values is untrusted too. Trust is decided before a
monitor queries the metric, so a malformed feed raises a data case, never a failed monitor.

Checks run each time the dataset is loaded. While one fails the dataset is **not trusted**: its monitors
neither raise a breach nor close one (what is open stays open), metric answers and the Ask AI card say so,
an outcome check on it gives no verdict, and a `data.untrusted` event (dataset, problems, owner) goes to the
exception you route it to, again every hour while it lasts; `data.trusted` follows once the checks pass, so
`clear_when: {events: [{type: data.trusted, same: [dataset]}]}` closes the case at the source. The Metrics
page shows each dataset's state. The configuration check warns when datasets have checks but no exception
handles `data.untrusted`.

## Capabilities, methods of work and the decision trace

The registry's `capabilities:` say what the business does and who is accountable for it; each exception
names its capability and its method of work:

```yaml
capabilities:
  finance_mis:
    title: Finance & MIS
    owner: FIN-07                              # the accountable role
    intent:                                    # what it is for and must never do; people change it
      - Every rupee in the bank is matched to the books within two working days
      - Never post or reverse a ledger entry without a person
    outcomes: [unreconciled_lines]             # metrics that show whether it works
    max_route: hitl                            # no exception in it may be automated further
    mode: act                                  # or observe: measured, every exception in shadow
patterns:
  - id: recon_break
    capability: finance_mis
    method: bank_match@1                       # its method of work, named and versioned
    ...
```

- A role may own several capabilities and a capability may span several roles; capabilities are not the org
  chart and not a list of agents. `mode: observe` instruments a capability (its cases are recorded, measured
  and proposed) without deploying it: nothing happens without a person. `max_route` is the explicit limit on
  automation for everything in it; an exception set above it is refused.
- **Provenance.** Every case records its capability, method, a fingerprint of the exception's exact
  definition and the registry version that was live (`incident.provenance`, copied to the disposition).
- **Decision trace.** The case story (`GET /console/api/cases/<id>`, and the case page) has a `trace`: the
  observed events (with correlation ids), capability, method and version, the proposal, each decision, the
  resolution, the actions and the verified outcome, and `gaps` naming any link that is missing.
- **Changing a method.** Edit the exception (new playbook, new name: `bank_match@2`), replay it on past cases
  (`POST /console/api/config/registry/replay`), run it in shadow, then publish under maker-checker.
  `GET /console/api/methods` (the Capabilities page) compares each version on real cases: cases, unattended,
  agreement with people, reversals and verified outcomes. Publishing the earlier version rolls it back.
  Learning proposes; people with `__configure__` (and approval, if configured) decide.
- **Learning a better method.** Once a day (or **Look for better methods** on the Capabilities page,
  `POST /console/api/methods/propose`) Sentinel looks at each exception's recent cases that people decided and
  finds the resolution they keep choosing: the same actions, with parameters it can read from the case (a
  fact or payload field) or that are always the same. If it differs from the current method and enough cases
  support it (5 and 60% by default), it becomes a **proposed method** (`stock_push@2`), backtested: how often it
  would have done what people did, against the current method. Only actions the exception already allows are
  used; reversed fixes and failed outcomes are not evidence; a parameter people choose case by case is never
  guessed. **Watch in shadow** compares it with every resolved case without executing anything; **Promote**
  (`__configure__`, maker-checker applies) needs 10 shadow cases at 80% agreement by default and publishes it as
  the exception's playbook, after which the exception earns its trust again; **Roll back** puts the previous
  definition back and keeps every other registry change.
- **Proving a method causes better outcomes.** Agreement with people shows a method is plausible, not that
  it works better. **Try on new cases** (`POST .../candidates/<id>/trial`, needs an `outcome_check` on the
  exception) runs a randomised trial: a share of new cases (half by default, fixed by the case id) get the
  candidate's proposal, the rest the current method's, and every trial case goes to a person. **Trial
  results** (`GET .../candidates/<id>/trial`) compares the arms' verified outcomes, handling time and
  agreement, with a 95% interval on the difference in outcomes held: *better*, *worse* or *not clear yet* (10
  verified outcomes per arm at least). Because the arms are random, the difference is the method's doing. A
  method in trial is promoted only once it is shown better, and never when it is shown worse; trial cases do
  not move the current method's trust. `GET /console/api/methods/candidates` lists them.
- `GET /console/api/capabilities` (the **Capabilities** page): each capability with its exceptions, outcome
  metrics, cases and stage: *planned* (nothing yet), *observed* (exceptions or metrics), *measured* (an
  outcome is measured), *verified* (outcomes held on real cases) and *acting* (some of it runs without a
  person).

## Similar cases and evaluating a model

Add an embedder to `models.yaml` (`embedder: local-embed`, an Ollama `nomic-embed-text` on the Mac mini, or
`{provider: hashing}` for a no-model fallback). New closed cases are embedded automatically; embed the
history once with `sentinel ... embed-backfill`. The deploy bundle's Postgres has pgvector; on another
Postgres, `CREATE EXTENSION vector` needs a privileged user once, otherwise Sentinel falls back to exact
search in Python (fine to tens of thousands of cases per pattern).

With pgvector the search is exact until you add an index. Once a pattern has tens of thousands of cases,
build an HNSW index for the embedder's size (it is built without blocking writes, and searches use it at
once):

```
sentinel --pg "$SENTINEL_PG" vectors-index --dim 768        # nomic-embed-text
```

Before routing a pattern to the small model, measure it:

```
sentinel --models models.yaml ... evaluate --candidate local --limit 200 --threads 4
```

It replays recent cases people decided, never executes anything, and prints per pattern the agreement with
people and with Claude and a verdict (`ready` needs 20 cases, 90% exact agreement and under 5% errors by
default; see `--min-cases`, `--threshold`). Then set `model_task: triage` on the ready patterns. Tools read
today's systems, so stock-dependent cases may score lower than live use.

## Model gateway (shared small-model host)

Ollama listens on 127.0.0.1 only; the gateway is the one door in. `gateway.yaml` lists each customer site
with a token hash, allowed models, `per_minute` and `max_concurrent`, inside a machine-wide
`max_concurrent`. Only chat and embedding endpoints are forwarded (never pull, delete, create, push);
streaming is refused. A request waiting longer than `queue_timeout_s` gets 503, so the site falls back
to Claude instead of waiting. `GET /usage` (admin token) and the monthly `usage-YYYY-MM.jsonl` ledger give
tokens per customer and model for billing. Prompts and replies are never logged or stored.

## Analytics

`sentinel --pg $SENTINEL_PG analytics [automation|weekly|trust|service|models|hotspots] [--days N]
[--fact location] [--json]`. DuckDB attaches the store read-only, so reports never write to or lock the
live database. `--snapshot DIR` writes every table to Parquet; `--parquet DIR` analyses a snapshot.
Offline sites: the Docker image includes the DuckDB extensions; elsewhere set
`SENTINEL_DUCKDB_EXTENSIONS` to a directory where they were installed.

## Edges

Each person lists preferred edges; roles and the overlay can set fallbacks. Cards are delivered through
the queue (retried with backoff). `WebhookEdge` POSTs the card with:

```
X-Sentinel-Timestamp: <unix seconds>
X-Sentinel-Signature: sha256=<hex HMAC-SHA256(secret, "<timestamp>.<body>")>
```

Answers come back to `POST /v1/edges/{edge}/answers` signed the same way (5-minute replay window), with
body `{review_id, person_id, answer_token, decision: {kind, action?, params?, disposition_code?, note?}}`.
Every delivered card carries its own single-use `answer_token` (valid 7 days), bound to that review, person
and edge: an edge can only answer for the person it delivered the card to, once. The person is still
checked against RBAC. To verify answers with a different secret from the one that signs cards, set
`answer_secret_env` on the edge. Bodies over 1 MB are refused.

Edges can be set up without code, in the connectors configuration (secrets come from environment
variables):

```yaml
edges:
  ask_ai:                       # Ask AI or any chat surface that renders A2UI
    kind: a2ui
    url: "https://askai.example.in/sentinel/cards"
    secret_env: SENTINEL_EDGE_ASK_AI
  whatsapp:                     # WhatsApp Business Cloud API (or a BSP exposing it: set base_url)
    kind: whatsapp
    phone_number_id: "1234567890"
    access_token_env: SENTINEL_SECRET_WA_ACCESS_TOKEN
    app_secret_env: SENTINEL_SECRET_WA_APP_SECRET
    verify_token_env: SENTINEL_SECRET_WA_VERIFY_TOKEN
    template: {name: sentinel_review, language: en}    # optional, see below
  ops_hook: {kind: webhook, url: "https://...", secret_env: SENTINEL_SECRET_OPS_HOOK}
```

- **A2UI.** The signed body is `{"card": {...}, "a2ui": [surfaceUpdate, beginRendering]}` (A2UI v0.8,
  standard catalogue): the case, the proposal and buttons (Approve, Close with a code). A button press
  comes back as `POST /v1/edges/ask_ai/a2ui` with `{"person_id": ..., "userAction": {...}}`, signed like
  answers.
- **WhatsApp.** Cards go to the person's `contact.whatsapp` (or `phone`) as an interactive message with
  reply buttons. Outside WhatsApp's 24-hour service window only approved templates may be sent: create a
  template whose body has two parameters (title, reason) and two quick-reply buttons, and name it under
  `template`. Point the app's webhook at `https://<server>/v1/whatsapp/whatsapp` with the verify token;
  replies are checked against the app secret, matched to the person by number and go through RBAC like any
  answer. Unknown numbers and refused answers are recorded in the audit trail.

## Usage and value

**No licence.** Sentinel is open source (Apache-2.0). Nothing is gated, capped or switched off by a licence
check, and there is no licence key to set. `SENTINEL_SITE_ID` names the site in the fleet view and the usage export.

**Usage export.** `sentinel usage --month 2026-10 --out usage-2026-10.json` (or **Download signed export**)
reports, per tenant: cases, events, automatic resolutions that were not reversed and did not fail their
outcome check, decisions by people and distinct reviewers, reversals, domains, model calls and cost, and
review cards sent. A month is final a week after it ends (the reversal window). The export is signed with
`SENTINEL_SECRET_USAGE_KEY` and carries the previous month's digest; `sentinel usage-verify file` checks it.

**Invoicing.** The signed usage export is the input to whatever invoicing you run. Sentinel itself does not issue invoices or take payments; a hosted operator builds that on top of the export.

**Value.** The **Value** page shows what automatic resolutions saved: each one is worth the exception's
`effort_minutes` (or the site default) at the site's hourly cost, less the model spend for its cases.
Set the figures in the people configuration:

```yaml
value: {currency: INR, hourly_cost: 400, default_minutes: 8, model_cost_rate: 84}
```

It uses the same rows as the usage export, so the value report and the bill agree. `sentinel value --days 30`.

## Tamper-evident audit trail

Workers seal the audit trail every minute: rows older than five minutes get a chain number and a hash, and
each batch becomes a seal chained to the one before (signed when `SENTINEL_SECRET_AUDIT_KEY` is set).
`sentinel audit verify` recomputes every row, batch and seal and names any row that was edited, deleted or
re-ordered and any seal that was forged. Retention leaves a tombstone with the hash of each audit row it
removes, and DPDP erasure records the original and new hash of each row it rewrites, so both still verify.
`sentinel audit export --out audit.jsonl.gz [--since-seal N]` writes seals and rows for an auditor;
`sentinel audit verify-export audit.jsonl.gz` checks a file offline. Set `SENTINEL_AUDIT_WEBHOOK` to post
each new seal and its rows (signed) to a SIEM or log store; delivery resumes after an outage. Keep the
audit key and a copy of exports off the server: someone with full database access can rebuild an unsigned
chain, but not one signed with a key they do not have, nor one already shipped elsewhere.

## Hosted mode (many customers in one service)

For small customers without their own server, one service can host many tenants. Each gets its own
PostgreSQL schema and connection pool, engine, configuration (an overlay or a packs file), tokens and single
sign-on and secrets: a tenant's configuration can only read variables named
`SENTINEL_SECRET_<TENANT>_...` or `SENTINEL_EDGE_<TENANT>_...`, never another tenant's or the service's own.
Requests reach a tenant by host name or the `/t/<tenant>/` prefix; workers take turns between tenants by
`weight`, so one busy tenant cannot starve the rest. See `sentinel/hosted.py` for the tenants file.

```
sentinel hosted serve  --tenants tenants.yaml --port 8080
sentinel hosted worker --tenants tenants.yaml --threads 8
```

Put PgBouncer in front of PostgreSQL when there are more than a handful of tenants (`pool_per_tenant`
connections each), give each tenant its own database role on its schema if you want the database itself to
enforce the separation, and back up per schema (`sentinel --pg ... --schema t_acme backup`).

## Large sites: monthly partitions (PostgreSQL)

Above a few million audit rows, `sentinel --pg ... partition apply` rewrites `audit` and `model_runs` as
monthly partitions (one transaction; stop the API and workers first on a big table). The maintenance service
then creates the coming months' partitions; anything outside them lands in a default partition.
`sentinel partition status` shows the state. Retention keeps working row by row. `events` stays one table,
because duplicate detection needs one unique key across all months.

## Fleet

Every site answers `GET /v1/fleet/status` for a service token named `fleet` (add it to the site's
`tokens.yaml` as `{kind: service, principal: fleet}`) with its version, health, last backup, last
usage export and published configuration. On KBGrid's own instance set `SENTINEL_FLEET` to a fleet file:

```yaml
sites:
  acme-prod: {url: "https://sentinel.acme.example", token_env: SENTINEL_SECRET_FLEET_ACME}
target_version: "0.13.0"
```

The **Fleet** page (or `sentinel fleet status --sites fleet.yaml`) shows every site and flags the ones that
are unreachable, unhealthy, without a backup, or behind the target version, with the
commands that upgrade them. Upgrades run on the site; the fleet never pushes code.

## Personal data (DPDP)

The **Privacy** page (needs `__privacy__`) answers a person's requests: find every case that mentions their
phone, email or customer id, download what is held, and erase it from closed cases. `--pii-days` on the
maintenance service removes personal fields (the overlay's `pii_keys`) from closed cases after that many
days. The data map, a breach runbook and a data processing agreement template are in
[docs/privacy](privacy/README.md).

## Languages

Give a person a `language` in the people configuration (or the console's person form): `hi` Hindi, `ta`
Tamil, `te` Telugu, `kn` Kannada, `mr` Marathi, `bn` Bengali, `gu` Gujarati, `ml` Malayalam, `pa` Punjabi;
English otherwise. Their cards on WhatsApp, Slack, Teams, email and the phone page use that language's words
for Approve, Close, Suggested and so on. With a model configured, the case's own text (the exception's
description, the reason and the model's rationale) is translated too: route `translate` to a small or local
model in the models configuration to keep it cheap. Personal data is masked before translation and results
are cached. Facts, codes and action names stay as they are. For WhatsApp templates, list the languages the
template is approved in (`template: {name: sentinel_review, language: en, languages: [en, hi, ta]}`); other
readers get the default. Have a native speaker check the words in `sentinel/i18n.py` for your site.

## More edges: Slack, Teams, email, and your own

**WhatsApp through Gupshup or Interakt.** For customers who would rather not set up a WhatsApp Business app
with Meta, edges of kind `gupshup` and `interakt` send the same cards (see `sentinel/wa_providers.py`, or add
them from the Data sources page). Replies come back to `POST /v1/wa/<edge>`: Gupshup's callback URL carries
a shared token (`?token=`), Interakt's webhook is checked with its signing secret. Interakt sends approved
templates only (body: title and reason; quick-reply buttons); Gupshup sends a quick-reply message inside the
24-hour window, or a template when one is configured.

Besides Ask AI (A2UI), WhatsApp and signed webhooks, the connectors configuration can send review cards to:

- **Slack** (`kind: slack`, a bot token and the app's signing secret): a direct message to the person's
  Slack member id (`contact.slack`) or a channel, with Approve / Close buttons. Point the Slack app's
  interactivity request URL at `/v1/slack/<edge>`; presses are signature-checked and matched to people.
- **Teams** (`kind: teams`, a Workflows webhook URL): an Adaptive Card with a link to decide in the console.
- **Email** (`kind: email`, SMTP with STARTTLS): to `contact.email`, with a link to decide.

New kinds plug in without changing Sentinel: an overlay calls `sentinel.edges.register_edge_kind(kind,
settings, build)`, and a pack installed as a Python package registers through the `sentinel.edge_kinds`
entry point. See `sentinel/channels.py` for the settings of each built-in kind.

## Monitoring

`GET /metrics` (Prometheus) and `GET /healthz`.

| Metric | Alert when |
|---|---|
| `sentinel_work_oldest_ready_age_seconds` | > 300 for 5 min (workers down or too few) |
| `sentinel_work_items{status="dead"}` | increases (a job failed all retries; its incident went to a person) |
| `sentinel_open_reviews` | sustained growth (people not keeping up, or edges not delivering) |
| `rate(sentinel_dispositions_total{resolver="auto"}[1h])` | drops to zero for a busy pattern (kill switch or breaker) |
| `sentinel_action_attempts_total{ok="false"}` | spikes (an external system is failing) |
| `sentinel_ingest_seconds` p95 | > 50 ms on async ingest |
| `rate(sentinel_model_fallbacks_total[15m])` | above zero for long (small-model host down: costs rise) |
| `sentinel_gateway_rejected_total{reason="busy"}` | increases (Mac mini saturated: add capacity) |

Workers serve their own `/metrics` with `--metrics-port`; scrape them as well as the API (the bundle's
Prometheus does).

`/healthz` returns `degraded` with reasons when there are dead jobs or the queue lags. Logs are JSON
(`sentinel.engine`, `sentinel.worker`) with incident and review ids; secret-looking keys are redacted in
logs and in the audit trail.

## Backups, restores and retention

The site bundle's `maintenance` service backs up the database every night at `BACKUP_AT`, checks the
backup can be read, keeps the newest `BACKUP_KEEP` and then applies retention. Backups land in
`BACKUP_DIR` on the server (make it writable for the container: `mkdir -p backups && sudo chown 10001
backups`). **Copy that directory off the server every night** (rsync, restic, the cloud provider's
snapshot of the disk) - a backup on the same disk does not survive the disk.

Each backup is a `sentinel-<time>.dump` (PostgreSQL custom format, the Sentinel schema only) with a
`.json` manifest: time, Sentinel version, rows per table, SHA-256.

**Check a backup** (do this monthly, on a copy, not only when you need it):

```
docker compose run --rm maintenance verify-backup /backups/sentinel-20261010T023000Z.dump
```

**Restore** (replaces everything in the Sentinel schema):

```
docker compose stop api worker maintenance
docker compose run --rm maintenance restore /backups/sentinel-20261010T023000Z.dump --yes
docker compose up -d
```

The restore refuses a file that does not match its manifest, runs in one transaction, and compares row
counts with the manifest afterwards. Work queued after the backup was taken is lost; events re-sent by
their sources are taken in again (duplicates are recognised).

**Restore drill on a spare machine**: install the bundle with the same `.env`, `docker compose up -d db`,
then run the restore as above and `docker compose up -d`. Sign in to the console and check the overview.

**Retention.** Closed cases older than `RETENTION_DAYS` (default 365) are written to a gzip JSON-lines
archive in `BACKUP_DIR/archive` and then removed with everything that belongs to them (events, reviews,
deliveries, model calls, audit entries, vectors). Open cases, learned trust, configuration history, access
tokens and audit entries that are not about a case stay. Preview what would go with
`sentinel --pg "$SENTINEL_PG" retention --keep-days 365`. Archives can be queried with DuckDB:
`SELECT * FROM read_json_auto('archive/archive-*.jsonl.gz') WHERE "table" = 'dispositions'`. Keep them as
long as your record-keeping rules say; they are not needed by Sentinel.

**SQLite** (pilots): `sentinel --db sentinel.db backup --out backups` makes an online copy; restore with
`restore <file> --yes` while nothing else uses the file.

## Upgrades

The PostgreSQL schema records its version. A process that finds the schema current starts without running
any DDL; one that finds it older migrates it (under a lock, one process at a time). With several API or
worker processes, set `SENTINEL_AUTO_MIGRATE=0` so they refuse to start on an old schema, and run
`sentinel --pg "$SENTINEL_PG" migrate` once as a step of each upgrade, before starting the new version.
(v0.1 databases gain the `unattended` column and new indexes this way.) For change-controlled environments, apply `sql/postgres_schema.sql` first; it is safe to
re-run. Pattern definitions are versioned: changing what a pattern means (its match rules, playbook or
allowed actions) resets the trust it earned, with a `pattern_changed` audit entry. Cosmetic changes
(description, SLA, owner) do not.

Before an upgrade: take a backup (`docker compose run --rm maintenance backup --out /backups`), then
`git pull`, `docker compose build`, `docker compose up -d`. To go back, deploy the previous version and
restore that backup.

## Performance (measured)

`python examples/loadtest.py` on a 2-core cloud VM, in-memory actions, so these are framework overhead:

| Store | Sync ingest + resolve | Async ingest (queue only) | Async drain, 4 workers |
|---|---|---|---|
| SQLite (file, WAL, synchronous=FULL), 6,000 events | 502 events/s, p50 1.8 ms | 930 events/s, p50 0.95 ms | ~300 incidents/s |
| PostgreSQL 16 on the same VM, 4,000 events | 212 events/s, p50 4.3 ms | 374 events/s, p50 2.5 ms | ~90 incidents/s |

Latency stays flat as history grows: per-event cost depends on the circuit-breaker limit and the last
20 dispositions, never on total history. Real throughput is bounded by your systems' API latency and
LLM latency (seconds), not by the framework.

## Failure behaviour

| Failure | What happens |
|---|---|
| Worker dies mid-job | Lease expires; another worker retakes the job. A step that may have run is never re-run blind: the incident goes to a person to verify. |
| External system down | Action retried within its attempt budget; then the incident goes to a person with the error. |
| Action hangs | `timeout_s` on the action: outcome marked unknown and sent to a person. |
| LLM slow, down or nonsense | Timeout, repair attempt, then a person with whatever diagnosis exists. |
| Edge (webhook) down | Delivery retried with backoff; after max attempts the job is dead-lettered (alert). |
| Too many unattended fixes in an hour | Circuit breaker routes the rest to people. |
| A fix turns out wrong | `reverse` runs compensations, flags what can't be undone, demotes the pattern. |
| A fix didn't hold | Outcome check fails: pattern demoted, and the problem comes back as a new incident. |

## Per-client adoption (ADR-004)

Each client moves to a newer Sentinel under support, recorded in its `SENTINEL_ADOPTION.md` (template:
`docs/templates/SENTINEL_ADOPTION.md`).

**Fleet.** Give each site its own target, and set the support window:

```yaml
support_window: 2                       # current + previous minor release
sites:
  chain-prod: {url: ..., token_env: ..., target_version: "0.16.1",
             adoption: "retail-pos tenants/chain/SENTINEL_ADOPTION.md"}
```

- `sentinel fleet status` flags `behind`, measured against the site's own target (fleet-wide target otherwise).
- It also flags `outside support window` when a site is `support_window` or more minor releases behind the
  newest.

**Dual run** (behavioural or breaking changes):
1. Trace the same events under each pin, read-only: `sentinel dualrun trace --events events.jsonl --out prod.jsonl`
   on the production pin, and again into `candidate.jsonl` on the candidate pin.
2. Compare them: `sentinel dualrun compare prod.jsonl candidate.jsonl`.
   - It lists differences per pattern and returns the trust guard: the patterns that drop one mode on
     switch-over.
   - It exits 1 when anything differs, owner or agent mode included. Copy the report into the adoption record.
   - Events pair by their `idempotency_key`, else an `id` in the file, else their line number. Trace the same
     file on both pins.

