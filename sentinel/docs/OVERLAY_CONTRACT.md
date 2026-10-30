# The overlay contract

An overlay is the project's own package (`examples/quickstart.py` is the smallest reference and `python -m sentinel.demo` a fuller one). The framework calls into it
only through the `Overlay` object returned by its `build_overlay()`; everything else is configuration.
This page is the full list of what an overlay provides and the exact shape of each piece. If code and
this page disagree, the code is right and this page is a bug.

| Field | Shape | Notes |
|---|---|---|
| `name` | `str` | Shown in logs and the console. |
| `fingerprint_rules`, `patterns`, `roles` | from `load_layers([...])` or `load_registry(path)` | The starting registry. Once a registry is published (console or `sentinel config publish`), the published version wins. |
| `actions` | `ActionRegistry` | The only way anything changes. See *Actions*. |
| `tools` | `ToolRegistry` | Read-only lookups for playbooks and the model. |
| `services` | `dict[str, Any]` | Adapters (API clients, DB handles) passed to actions, tools and verifiers. |
| `receivers` | `{source: fn(raw: dict) -> Event | list[Event]}` | Turn a webhook body into events (`POST /v1/hooks/{source}`). |
| `verifiers` | `{name: fn}` | Outcome checks named by a pattern's `outcome_check`. |
| `notifier` | `fn(kind: str, data: dict) -> None` or `None` | Called for promotions, pattern changes, escalations. Must not raise or block. |
| `directory` | `Directory` or `None` | People and authority. Usually loaded from `people.yaml`; `None` = open mode (tests, demos). |
| `edges`, `role_edges`, `default_edges` | `{name: Edge}`, `{role: [edge]}`, `[edge]` | Where review cards go. |
| `pii_keys` | `[str]` | Payload keys masked before a model sees them. |
| `mcp_commands` | `[[argv...]]` | The only stdio MCP servers configuration may start. |
| `capabilities`, `case_defaults` | from the registry document (`doc.capabilities`, `doc.defaults`) | The business capabilities (owner, intent, outcome metrics, automation ceiling, observe mode) and how long cases live. |
| `datasets`, `metrics` | `{name: fn(services, now) -> rows}`, the metrics YAML as a dict | KPIs, monitors and dataset checks, until a metrics configuration is published. |

An overlay is a **domain pack**: it supplies what the business means (capabilities and their intent,
exceptions, methods, KPIs, data checks, authority) as versioned configuration, and code only for the
calculations and integrations configuration cannot express. The framework never learns a business concept
(no MOQ, no settlement, no OTIF in its code); if a pack needs one there, the missing abstraction belongs in
the framework as a general mechanism, not as that concept.

## Actions

```python
@actions.action("hold_order", reversible=True, safe=False, description="...", params={"order": "str", "note?": "str"})
def hold_order(ctx: ActionContext, params: dict) -> ActionResult: ...

@hold_order.compensator
def release_order(ctx: ActionContext, params: dict) -> ActionResult: ...
```

- `ctx` has `incident`, `event`, `actor` (`auto`, `llm` or `human:<id>`), `idempotency_key` and `services`.
  Pass `idempotency_key` to the downstream system; the same key may arrive twice after a crash.
- Return `ActionResult(ok, detail, data, retryable)`. `retryable=False` stops retries at once. Raising is
  treated as a failure with retry.
- `params` declares names and types (`str int float bool list dict any`; a trailing `?` = optional).
  Playbook params and model proposals are checked against it at configuration time and again when the
  step runs. An action that declares nothing accepts anything; declare it.
- `reversible=True` needs a compensator. `safe=True` means idempotent with no business effect (re-sync,
  refresh). Only reversible or safe actions run unattended; any other action waits for a person unless
  the guardrails allow irreversible unattended actions. Unattended limits in `people.yaml` (amounts,
  patterns) apply on top.

Actions can also be defined without code, as HTTP calls in the connectors configuration (`actions:`, see
OPERATIONS.md). They get the same checks, guardrails and approvals; a name the overlay implements in code may
not be redefined there.

## Tools

```python
@tools.tool("stock_level", "stock for a SKU at a location", {"sku": "str", "location?": "str"})
def stock_level(args: dict, services: dict) -> dict | list | str: ...
```

Tools never change anything; the registry refuses one not marked read-only. Results longer than the
model limit are cut. MCP tools (`connectors` configuration) appear as `server.tool` and follow the
same rules.

## Verifiers

```python
def payment_settled(*, incident, disposition, params, services) -> bool | None: ...
```

Called by keyword, some minutes after a resolution (`outcome_check: {verifier, after_minutes, params, codes}`).
A resolution is checked when it ran steps, or when it was closed with one of `codes` (a fix made outside
Sentinel, such as "matched in the books"). The built-in `metric` verifier measures since the fix, or over
the last `params.days` up to the check when given (for KPIs about things already wrong before the fix).
Return `True` (the fix held), `False` (it did not: the pattern loses trust and a person is told) or
`None` (cannot tell yet: checked again, then recorded as unknown).

## Roles: one place

Roles appear in two files, with different jobs:

- `people.yaml` is the source of truth: the role tree, who holds each role, their scope and authority.
  With a directory, every `owner_role` and `escalation_role` must exist there, and publishing a registry
  that names an unknown role is refused. A pattern may name a role slot instead (`owner_slot`,
  `escalation_slot`); the registry's `slot_bindings` turn it into a role, and the same check applies to the
  bound role. An unbound slot refuses publish.
- `roles:` in the registry is only a description per role (for the console and templates). Keep the
  same names; do not invent roles there.

**The org layer (ADR-003 C1, all optional).** `people.yaml` can also say:

```yaml
roles:
  category_buyer: {parent: ops_head, dotted: [internal_audit]}   # audit sees the queue; cannot act on it
scopes:
  store: {rolls_up_to: region, parents: {TVM01: south, COK01: central}}   # a region covers its stores
  category: {parents: {rice: staples, staples: grocery}}                   # a tree inside one fact
stop_at: [ops_head, regional_manager]     # vacancy and escalation never climb past these
vacancy: escalate                          # a vacant role's new reviews go to the nearest held role above
assignments:
- {person_id: priya, role_id: store_manager, scope: {store: TVM01}, valid_from: 2026-10-25, valid_to: 2026-11-08}
```

- A dotted line gives visibility only: no inherited authority, and it is never on the escalation path.
- `valid_from` is inclusive and `valid_to` exclusive. The engine's clock decides what is current, and past
  assignments stay in the file as history.
- An assignment scoped to a higher value covers every value below it.
- `holders(role, facts)` returns the people to route to: the role's own holders in scope, or the nearest role
  above with someone. It stops at a `stop_at` role even when that role is vacant, and it never pages the top.
  When `stop_at` is set, every role must have a stop at or above it. SLA escalation (`sweep`) up the tree also stops at a `stop_at`
  role. A pattern's explicit `escalation_role` is still honoured, because it is a routing choice the pack made.
- A dotted-line person sees the queue in `reviews_for` and the console, but cannot approve from it.
- When someone may not approve a step, `escalate_to` (and a forward) never names a role past the stop list. The
  first stop role on the way up is named instead, and that person takes it further outside Sentinel.
- `vacancy: escalate` is off by default. When it moves a review, the move is audited as `vacancy_escalated`.

A directory that uses none of this behaves exactly as before.

**The authority contract (ADR-003 C2).** A domain core calls `sentinel.org.authorise()` on every write an agent
can trigger, against its synced copy of the people configuration, so the check runs where the write happens
(offline included). Sentinel asks; the core decides.

```python
from sentinel.org import Agent, authorise
dec = authorise(directory, Agent("r06@TVM01", bound_role="store_manager"), "stock.adjust", obj="A1",
                scope={"store": "TVM01"}, amount=3000, done_on_object={"r06@TVM01": ["task.count"]})
if not dec: refuse(dec.reason, dec.escalate_to)
```

An action is allowed only if all of these hold:
- **A person** holds, now and in that scope, a role whose authority approves the action and amount. Limits
  bound an amount's size, so a negative amount is checked as its magnitude.
- **An agent** never exceeds the person holding its bound role in that scope today. If that role is vacant, the
  nearest held role above decides (`holders`). Nobody past the stop list ever decides, and with nobody in
  scope the agent is refused.
- **Segregation of duties:** no pair in `sod:` (people configuration, or passed by the caller) is broken on
  that object.
- **Approvals:** nobody approves their own proposal, and an agent never approves anything (`__approve__`, or any
  action with `proposed_by`).

The result says which role decided (`decided_by_role`), which checks ran, and where to escalate.

**Enforcing it in a domain core, offline (`sentinel.orgsync`).** A core enforces against a signed copy of the
people configuration.
- **Keys.** `sentinel policy keygen --out keys/ --kid site-1` makes the site key pair. `private.pem` stays with
  Sentinel (point `SENTINEL_POLICY_KEY` at it); `keys.json` goes to every core.
- **The policy bundle.** `sentinel policy export --ttl 24` (or `engine.export_policy()`) signs the people
  configuration with a version and an expiry. In the core, `snap = load_policy(token, "keys.json", core="pos")`
  verifies it with the standard library only. Bundles that are tampered with, signed by another key, or whose
  version does not match their content are refused.
  - After `expires_at` the bundle is **stale**. Agents may not write at all; people still may (a till must
    sell), and their receipts are marked stale.
- **Agent assertions.** An unattended action handler calls `ctx.assert_for(action, obj)` for a short-lived
  signed token naming the agent (`template@scope`), its bound role, its mode, the case, the action and the
  object. The core passes it as `snap.authorise(None, action, obj, scope, amount, assertion=token)`.
  - It is accepted only if **every claim matches**:
    - signature, expiry and issue time;
    - site, action and object;
    - every scope fact the core passes is covered by the token's scope, directly or by roll-up (a store token
      covers its region, never another region or an unrelated fact);
    - a caller-named actor is the token's agent (a person never uses an agent's token);
    - the token's mode is ACT, and the bundle the core holds does not put that agent below ACT there.
  - It is also refused if it was already used: one assertion, one write.
  - A core that keeps its own authority and loads no bundle (a Postgres core with its own Limits) uses
    `bind_assertion(token, keys, action=, obj=, scope=, site=, used=, expand=)` in its command layer. It applies
    the same matching rules and the one-use rule, and returns the claims (`bound_role`, scope, case). The core then
    runs its own authority check for that bound role.
  - `load_policy(..., site="r06")` pins the core to its own site's bundles. A bundle issued more than five minutes
    in the core's future is refused, or treated as stale if it is already loaded.
  - With a valid assertion, the agent is still never allowed more than the person holding its bound role.
- **Receipts.** Every `snap.authorise` returns `(decision, receipt)`. The core posts receipts to
  `POST /v1/receipts` with a service token. Sentinel audits each one once (`authority_receipt`, with the posting
  principal as `posted_by`) and flags:
  - unknown bundle versions and stale bundles;
  - agent writes allowed without an assertion;
  - decisions dated after the issued bundle's expiry or before its issue (when the core's clock is wrong);
  - `unknown_assertion`: an assertion id this site never issued;
  - `assertion_mismatch`: the receipt differs from what the assertion was issued for (agent, template, case,
    action, object or scope, where a rolled-up scope still counts as covered). Absent on either side is a
    mismatch;
  - `assertion_reused`: a second allowed write on one assertion, from any core or till. It is also audited and
    notified, because one-use is otherwise only per process.

  Receipts are strict. `at` is an ISO-8601 date-time with a UTC offset or `Z`. Scope facts follow the fact rule
  below. A batch with one bad receipt gets 422, and none of it is recorded.
- **The fact rule (`sentinel.factrule`).** One rule wherever a fact enters: receipts, data trust, console facts and
  the scope an assertion is minted with.
  - A name is non-empty text.
  - A value is non-empty text or a whole number. Text that is only whitespace counts as empty, because
    fingerprints trim it. An unset fact is left out; `null` is refused.
  - Money and quantities travel as `amount`, not as facts.
  - A value that breaks the rule but must still be recorded is kept as its JSON text, the same way on every side.
    That covers what a caller passed to a core's `authorise`, an odd case fact, and a list in a fingerprint field.
  - **Relied-on facts must arrive plain.** Some facts are relied on: people scope dimensions, assignment and agent
    policy scopes, data trust scores, `trust_by` and `claims` (`engine.relied_facts`). If an event's payload value
    for one of them is not plain (a list, an object, a fraction, a boolean or ""), the case goes to a person.
    - The check runs at ingest, before normalising, and is audited `scope_fact_not_plain` with `Incident.odd_facts`.
      `trace` makes the same judgement, so a dry run predicts it.
    - No assertion is minted for that case. That is audited at ingest as `agent_assertion_refused`, and again on
      any later attempt.
    - Otherwise an odd value could match no per-scope control (an OBSERVE row, a data trust cap) and run alone.
  - **The people configuration follows the same rule.**
    - Assignment, agent policy and SCIM grant scopes take non-empty text, whole numbers, or a non-empty list of them.
    - `max_amount` must be a finite number.
    - A row that could never match is refused at publish, not ignored.
  - A fact name that isn't non-empty text, passed by a caller, is kept in a record under a reserved name
    (`(name: "")`) and never overwrites a real fact.

**Data trust caps autonomy per scope.** In the registry's `defaults:`:
`data_trust: {act_min: 0.95, propose_min: 0.80, max_age_hours: 48, unknown: none}`.
- Monitoring posts scores to `POST /v1/data-trust {scope: {store: TVM01}, score: 0.91}` (or calls
  `engine.set_data_trust`).
- Where the lowest fresh score among a case's facts, and the scopes they roll up to, is below `act_min`, agents
  only propose. Below `propose_min` they only observe, whatever trust the template has earned.
- Scores older than `max_age_hours` count as unknown. `unknown: PROPOSE | OBSERVE` makes unknown scores cap too.
- `sources: [monitoring]` lists the service principals that may post scores; any other principal gets 403. Each
  row records who posted it. Without `sources`, any service token may post, and `sentinel validate` warns.
- Band changes are audited as `data_trust_band`. A pattern can opt out with `data_trust_exempt: true`.

**Spot checks and agent incidents (Layer D).**
- **Spot checks.** `spot_check_rate: 0.05` on a pattern samples that share of its unattended decisions
  (deterministically per case) for a person to check: the owner role in scope, or the oversight role
  (`engine.spot_checks`, `spot_check_verdict`, and the console's Agents page).
  - A "wrong" verdict needs a note. The decision is reversed (what can be undone is undone) and the agent's
    trust drops.
  - If the checker lacks `__reverse__`, the trust drops anyway. The result names the roles and people who may
    undo it, and the case waits in their spot-check queue as **"judged wrong: undo needed"**. They undo it, or
    keep it with a reason. However it is finished (Undo, or a plain reverse from the case page), it leaves the
    queue, and one wrong decision lowers trust once. A decision reversed before anyone checked it shows as
    `reversed` and can no longer be marked right.
  - **If nobody active holds `__reverse__`,** the case still has a holder. The first role with active people
    holds it: the template's oversight roles, then its escalation role in scope, then its owner role in scope.
    Failing all of those, the person who judged it holds it. The card says that the undo right must be granted
    in People. Until then the holder can only keep it, with a reason (`can_undo: false`, `held_by` on the
    spot-check row).
- **Agent incident.** `engine.agent_incident(pattern_or_scope, actor, reason, hours=24, undo=False)` is one step,
  for oversight roles only. It stops the agent, lists its unattended decisions in the window, puts every one on
  spot check, optionally undoes the reversible ones, and keeps a record. `close_agent_incident` needs a
  post-mortem, and a closed incident cannot be closed again: its post-mortem stays as written.

**Two agents, one object.** Set `claims: [store, article]` (and `claim_minutes`) on patterns that act on the same
objects.
- Before acting alone, an agent claims the object. Another template finding it claimed goes to a person
  instead, audited as `object_contention`. `trace` says so in advance.
- The same template is not blocked. A case whose facts do not name the object takes no claim. A claim is
  released if the circuit breaker stops the action.

**Agents: identities, modes and grants (ADR-003 C1).** An agent is a template (a pattern, or its capability)
running in a scope. `agents:` in the people configuration sets each agent's mode per scope. Rows can be time-bound.
The most specific row wins, and row order never decides:
1. A pattern id beats its capability, which beats `"*"`.
2. Then the row with more scope keys.
3. Then the row whose keys sit deeper (store below region, rice below staples).
4. On a true tie, the least autonomous mode wins.

```yaml
agents:
- {template: "*", mode: OBSERVE}                                     # everything starts observing
- {template: stock_signal, scope: {store: TVM02}, mode: ACT, grants: {task.shelf_check: EDIT}}
- {template: stock_signal, scope: {region: central}, mode: PROPOSE}
- {template: loss_signal, scope: {store: TVM01}, mode: OFF}
```

| Mode | Effect in that scope |
|---|---|
| OFF | The template takes no cases; its events go to people as unmatched |
| OBSERVE | Shadow: proposals only; a person decides everything |
| PROPOSE | A person approves every proposal; never unattended |
| ACT | Acts alone up to the route it has earned, inside the pattern's ceiling and the unattended limits |

- **Grants** are VIEW or EDIT per action. When an agent has grants, an unattended step on an action without
  EDIT goes to a person, audited as `agent_grant`. APPROVE is never grantable, and configuring it is refused.
- Each case records its agent identity (`provenance.agent`, as `template@scope`) and its mode. The identity
  names the row that decided: its template (the pattern, or the capability when a capability row decided) and
  its scope.
- `trace` shows the agent, its mode and grants, and why it was routed as it was.
- With no `agents:` section, nothing changes.

**Pooled trust (scale).** A template running in many scopes (`trust_by: [store]`) would earn trust too slowly
if every scope learned alone. Set `trust_pool_min: N` on the pattern to pool it:
- Every decision, reversal and outcome check teaches both the scope's own trust and the template's pooled trust.
- A scope uses the pooled route until it has `N` decisions of its own; after that, its own trust decides.
- A reversal anywhere demotes the pool, so every thin scope drops with it.
- A scope lowered by hand (`set_route("pattern@scope", ...)`) or by an oversight stop is **held**. The pooled
  route never lifts it, mature or thin. Raising that scope by hand releases the hold.
- `trace` says when a route is pooled.

**Many open cases (scale).** Two pattern settings keep people's work manageable when a template has many open
cases:
- `money_fact: <fact or payload field>` ranks that template's cases by money at stake: in the console's Reviews
  view ("most money at stake first"), in `engine.ranked_reviews(person)` and in `engine.template_digest(pattern)`.
- `digest_above: N` means that once N of the template's cases are open, a new case gets no card.
  - Each person holding the cases' roles in scope gets one digest every `digest_every_minutes` (default 60).
    It lists their cases ranked by money and points to the console to decide them together (bulk approve or
    close). It is audited as `template_digest_sent`.
  - Escalation still moves such cases up the tree; they stay on the digest.

Sentinel never runs a process per agent instance. An instance is a row: a trust segment, a case's
`provenance.agent`. So hundreds of scopes are configuration, not processes.

**Oversight (Layer D).** The role that watches agents must own none of them:

```yaml
oversight:
- {role: internal_audit, templates: ["*"]}      # pattern ids, capability ids or "*"
```

- An oversight role may not be a covered template's owner or escalation role, nor above one on the solid line.
  The engine refuses to start, and publishing is refused, if it is.
- A person who holds both an oversight role and an owning role gets a warning.
- The lever is `engine.oversee(pattern_or_segment, "stop" | "demote" | "cap", actor, reason, route=...)`. Only an
  oversight-role holder may use it, it needs a reason, and it only lowers autonomy. Each use is audited as
  `oversight_action`.
- Circuit breaker, kill switch, outcome checks and the owner report stay as they are. Oversight adds an
  independent hand on them.

## Edges and delivery

An `Edge` has a `name` and `deliver(card: ReviewCard) -> str`. A card goes to the first edge that exists
in this order: the person's own `edges`, then `role_edges[role]`, then `default_edges`.

Delivery always runs as background work (`deliver` work items), in both modes, so a slow or failing edge
never holds up an incident. With `async_mode=False` (tests, single-process scripts) something must still
call `engine.work(...)` (or run `sentinel worker`) for cards to go out; reviews exist and the console
shows them either way.

## Connectors and other configuration from files

Connectors (MCP servers, sources), people, models and the registry are versioned configuration kinds.
They can be edited in the console or kept in git and published from the command line:

```
sentinel --overlay pkg:build_overlay config check connectors connectors.yaml
sentinel --overlay pkg:build_overlay config publish connectors connectors.yaml --by mohan
```

Secrets are never in these files: they name environment variables (`SENTINEL_SECRET_*`), which the
framework reads only from its allowlist.

## Versioning

Pin the framework to a commit or tag. A change to a pattern's meaning (match, playbook, allowed actions,
codes, `llm_max_steps`, or the fingerprint rules for its event types) resets the trust it earned;
descriptions, SOPs, SLAs and owners do not.
