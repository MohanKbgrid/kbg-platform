# Changelog

## Open-source snapshot (sentinel-v0.24.0 content, published into kbg-platform)

This repository publishes v0.24.0 as a scrubbed snapshot with no private history. Compared with the private
v0.24.0 it differs as follows; older entries below describe the private line and may mention these.

- **Removed:** KBGrid's own invoicing and payment-link code, its CLI command (`sentinel invoice`), its webhook
  (`/v1/billing/...`) and its secret names. Usage metering and the signed usage export stay.
- **Replaced:** a product-specific connector template is now the generic `postgres-outbox` template (the outbox
  reader only; the product-specific finance datasets are not published).
- **Renamed:** customer names in examples, tests and docs are replaced by neutral demo names ("Acme Home").
- **Not published:** internal working notes (`NEXT_SESSION`, `BUILDER_MISSES`, `PARADIGM_OVERHAUL`) and two
  console screenshots that showed a customer name. One test that read `BUILDER_MISSES.md` now checks only the
  public contract and changelog.
- **Licensing:** Apache-2.0 for code, CC BY 4.0 for docs (see the repository root).

Every release from v0.14.3 is classified under ADR-004 (`docs/adr/ADR-004-continuous-evolution-per-client-adoption.md`).
Each release entry carries two lines that a client's support record (`docs/templates/SENTINEL_ADOPTION.md`) is built from:

- **Class:** the highest class of anything in the release.
  - *Compatible*: additive, ships switched off; nothing changes for a client until they enable it.
  - *Behavioural*: same contracts, different outcomes; the entry names the patterns that can be affected,
    and adoption needs a dual run.
  - *Breaking*: a contract changes; the entry carries the migration, and the old form keeps working for at
    least two releases.
- **Adopt:** what a consumer must do to move its pin to this release.

A release is a commit on `main` with the version in `pyproject.toml`; it is never a git tag. Consumers pin by
commit SHA. `tests/test_changelog.py` refuses an entry without both lines. Entries before v0.14.3 are unclassified.

## v0.24.0 (2026-10-20)

**Class:** Compatible (every part is opt-in: a policy key, `data_trust` in defaults, `spot_check_rate`, `claims`.
Without them, nothing changes. `ActionContext` gains an optional `assert_for`).
**Adopt:** move the pin. For domain cores, make a site key (`sentinel policy keygen`), set `SENTINEL_POLICY_KEY`,
ship `keys.json` and the exported bundle to each core, call `snap.authorise` on agent-triggerable writes, and post
receipts back. Turn on `data_trust`, `spot_check_rate` and `claims` per tenant as needed.

Hardening the agentic layer (the next steps after the overhaul, built and tested together):

- **Domain cores enforce offline (`sentinel.orgsync`).**
  - A signed policy bundle (RS256, verified with the standard library) with a version, an expiry and a stale
    rule: agents may not write on a stale bundle; people still may, and are flagged.
  - Signed, short-lived agent assertions minted through `ctx.assert_for(action, obj)`, each bound to action,
    object, scope, site and ACT mode, and usable once.
  - Decision receipts from `snap.authorise`, posted to `POST /v1/receipts`, audited once each and flagged
    (unknown version, stale, agent write without an assertion).
  - CLI: `sentinel policy keygen | export | verify`.
- **Data trust caps autonomy per scope.** `defaults.data_trust` sets the bands. `POST /v1/data-trust` and
  `engine.set_data_trust` record a scope's score. The lowest fresh score among a case's facts and their
  roll-ups caps it at PROPOSE or OBSERVE. Applies to routing, shadow, unattended runs and `trace`; band changes
  are audited, and a pattern can opt out with `data_trust_exempt`.
- **Spot checks.** `spot_check_rate` samples unattended decisions deterministically. A wrong verdict reverses
  the decision and demotes the agent; a checker without reverse rights still demotes, and the result says who
  must undo it.
- **Agent incident playbook.** `engine.agent_incident` stops the agent, lists its recent decisions, puts them
  on spot check, optionally undoes them, and keeps a record. `close_agent_incident` needs a post-mortem.
- **Object contention.** `claims` / `claim_minutes`: a second template finding the object claimed goes to a
  person, audited as `object_contention`. The claim is checked and taken atomically, and released if the
  breaker stops the action.
- **Console (Agents & oversight):** data trust by scope, a spot-check queue with right / wrong verdicts, agent
  incidents with open and close, and spot-check and claim settings per template. Tested in a real browser at
  desktop and phone width, light and dark.

Independent functional test before push (`tests/functional/test_independent_v024.py`, 94 cases in a dairy
cooperative domain, docs only). The first pass found 11 defects (5 Medium), so the builder recorded a method review
(`docs/BUILDER_MISSES.md`, with seven pre-handover checks now standing) and fixed each class in general:
- **Assertions are accepted only if every claim matches.**
  - Every scope fact the core passes must be covered, directly or by roll-up. Before, only shared keys were
    compared.
  - A caller-named actor must be the token's agent, and a person never uses an agent's token.
  - The bundle the core holds can put an agent below ACT even when the token says ACT.
  - A missing assertion id is refused.
- **Time edges.** A bundle issued in the future beyond five minutes is refused or treated as stale.
  `load_policy(site=...)` pins a core to its own site. Receipts are checked against the issued bundle's expiry and
  issue time.
- **No dead ends.** A spot check judged wrong by someone without reverse rights now names the roles and people who
  may undo it. The case waits in their queue as "undo needed", and they undo it or keep it with a reason.
- **Write-once.** A closed agent incident cannot be closed again.
- **Strict inputs.** Bools are refused as numbers (data trust scores, pattern settings), `hours` / `ttl` must be
  finite and in range, and console verdicts and `undo` must be JSON booleans (malformed input gets 422, never 500).
- **The console never shows "null"** for missing facts.
- **`orgsync.bind_assertion`** gives a core that keeps its own authority and loads no bundle (the POS core, Option A
  in its handoff) the same matching and one-use rules, so the two options cannot drift.

The re-verification pass (180 cases) confirmed those fixes and found 8 more defects (2 Medium, 6 Low), in three
classes. Each class is fixed in general, with regression tests in `tests/test_v024_pass2.py` and a browser test:
- **No dead ends: the holder must exist.**
  - A case judged wrong when nobody active holds `__reverse__` now has a holder. The first role with active
    people holds it: oversight, then the escalation role in scope, then the owner role in scope, then the person
    who judged it.
  - The card says the undo right must be granted and offers only Keep.
- **Strict inputs, for every type.**
  - Receipts refuse coerced fields: `actor_kind` must be `person` or `agent`. Ids and versions may not be empty.
    `allowed` and `stale` must be booleans, `amount` a real number, and text fields text.
  - Data trust refuses a score sent as text, and scope values that are booleans or fractions.
  - Every console and API body field is read through `sentinel.inputs`: the wrong JSON type gets 422.
  - Typed request bodies share `inputs.Body`: booleans must be JSON booleans and numbers finite JSON numbers.
    Pydantic's lax "yes" → true and "24" → 24.0 no longer get through.
- **One mistake, one effect.**
  - A wrong decision lowers trust once, whichever paths report it (verdict, undo, reverse, incident undo):
    `Disposition.trust_charged`.
  - A plain reverse of a case waiting as "undo needed" settles it.

The third pass (331 cases) confirmed those fixes and found 5 Low defects, each fixed with its class:
- **Strict inputs reach every exit.** A 422 no longer echoes the input, so a NaN or Infinity literal in a typed body
  gets 422, not 500. A receipt's `at` must be ISO-8601 text. Empty fact values and empty fact names are refused.
- **Binding is total on receipts.** A receipt naming an assertion this site never issued is flagged
  `unknown_assertion`. One whose action, object or case differs from what was issued is flagged
  `assertion_mismatch`. Sentinel records each assertion it mints by its id.
- **A reversal is a "wrong" verdict.**
  - Any reversal (by hand, by Undo, or by an agent incident) settles an open spot check, so an undone decision never
    waits as pending or gets marked right.
  - A decision reversed before anyone checked it shows as `reversed`. A later "wrong" on it is recorded with no
    further effect.
  - A decision undone through "undo needed" refuses a second undo.
- **One assertion, one write, across every core** (fourth pass).
  - Sentinel records the first allowed receipt for each assertion. A second one from any core or till is flagged
    `assertion_reused`, audited and notified.
  - `assertion_mismatch` compares everything the assertion was issued for: agent, template, case, action, object and
    scope (covered directly or by roll-up). Absent on either side counts as a mismatch.
  - A receipt's `at` must be an ISO-8601 date-time with a UTC offset or `Z`, so a core's local time is never read as
    UTC.
- **Receipts are all-or-nothing and as strict as data trust** (fifth pass).
  - A batch is validated in full before any receipt is recorded: a bad receipt gets 422 and nothing in the batch
    half-lands.
  - Receipt scope facts follow the data-trust rule: names are non-empty text; values are non-empty text, whole
    numbers or null.
  - A core's own `authorise` keeps any other value the caller passed as JSON text, so its receipts always validate.
- **One fact rule, and strict settings** (sixth pass).
  - `sentinel.factrule` is the one rule for facts in receipts, data trust, console facts and assertion scopes. An
    unset fact is left out; `null` is refused everywhere.
  - Odd values are kept as JSON text by one normaliser on both sides, so a receipt and its assertion always agree.
    A list or object in a fingerprint field is now normalised to JSON text, not Python text. That affects grouping
    only for such values: an open case holding one gets a new case once after the upgrade.
  - An assertion is not minted when a scope fact the core relies on is not plain; a person decides instead.
  - Registry settings added in v0.18–v0.24 are strict: numbers must be YAML numbers, `data_trust_exempt` a boolean,
    and `claims` / `trust_by` lists of fact names. `defaults.data_trust` numbers must be finite numbers.
- **Odd values in relied-on facts go to a person** (seventh pass).
  - A relied-on scope fact that arrives as a list, object, fraction, boolean or "" makes the case a person's, at
    ingest (`scope_fact_not_plain`, `Incident.odd_facts`). Before, a list became JSON text and slipped past
    per-scope controls.
  - The people configuration follows the fact rule: scopes in assignments, agent policies and SCIM grants, and a
    finite `max_amount`.
  - `money_fact` must name a fact.
  - A record never loses a fact to an empty or odd name.
- **Attack table (ADR-007) and the gaps it found.**
  - Assertion one-use is checked and marked atomically within a process (`PolicySnapshot`, `bind_assertion`).
  - `defaults.data_trust.sources` limits who may post scores (403 otherwise), and each score records its poster.
  - The data trust index is updated under a lock.
  - Receipts record the posting principal (`posted_by`).
- **A whitespace-only value or name breaks the fact rule**, judged as the fingerprint will trim it. Every configured
  fact or parameter name follows one name rule (`factrule.name_problem`): `claims`, `trust_by`, `money_fact`,
  `inhibit_on`, `brief_fields`, fingerprint fields and `group_by`, `amount_param` and `data_trust.sources`.
- **In-process writes are attributed:** a direct `set_data_trust` or `record_receipts` call records `engine` as its
  poster.
- **`trace` predicts the route that ingest takes:** the odd-fact judgement is one function used by both, so dry runs,
  golden cases and dual runs agree with ingest.
- **State and its audit row land together.** Spot-check verdicts, keeps, agent incidents and receipts write their
  state and audit row in one transaction. Receipt de-duplication is checked under a lock, so the same id posted twice
  at once is recorded once and counted once.

## v0.23.0 (2026-10-20)

**Class:** Compatible (opt-in pattern settings and a new console page. The `escalate_to` cap only changes
tenants that set `stop_at`, a v0.16 feature no client has adopted yet).
**Adopt:** move the pin. To use the scale settings, add `money_fact` and `digest_above` to busy templates.

The backlog left after the paradigm overhaul:

- **Digest past a threshold, ranked by money.** New pattern settings: `digest_above`, `digest_every_minutes`
  and `money_fact`.
  - Once a template has N open cases, new cases get no card. Each holder of the cases' roles in scope gets one
    digest, ranked by money at stake, audited as `template_digest_sent`. Escalation still moves the cases.
  - `ReviewTask.digested`, `engine.template_digest()`, `engine.ranked_reviews()` and
    `send_template_digests()` (run by `sweep`) support this. The stores gain `open_reviews_of_pattern` and
    `count_open_reviews_of_pattern` (SQLite and PostgreSQL).
- **`escalate_to` never names a role past the stop list.** Applies to `authorize_steps`, to `authorise` for
  people and agents, and to forwards. See `Directory.cap_escalation()`.
- **Console: Agents & oversight page**, which shows:
  - each template's slots and the roles they are bound to, its ceiling, its trust (pooled or not) and scale
    settings, its open cases and its overseers;
  - the slot bindings and the agent modes;
  - a "which mode applies here?" lookup;
  - the oversight roles, with the stop / demote / cap form (oversight roles only; a reason is required);
  - the domain binding's never-automate list.

  The **Reviews** view can order by money at stake and marks cases sent on a digest. Endpoints:
  `/console/api/agents`, `/agents/effective`, `/oversee`, `/reviews/ranked`. Tested in a real browser at
  desktop and phone width, light and dark.
- **Console layout:** at phone width a wide table scrolls inside its card instead of widening the page (grid
  tracks are `minmax(0, 1fr)`).

Independent functional test before push (`tests/functional/test_independent_backlog.py`, 72 cases in a hospital
claims domain written from the docs alone). It found 5 defects, all fixed in this release and kept as regression
tests. The two Medium ones are one class: a case could reach nobody.
- **A digested case never reaches nobody.** If no digest can be delivered to anyone holding a case's role (no
  text-capable edge, or nobody in scope), that case goes out as a card. The same happens when a template stops
  digesting or is removed, on registry publish and on escalation. `template_digest_sent` records who missed it,
  and `digest_released` records the fallback.
- **An oversight `cap` without a route is refused** and not audited.
- **The console no longer shows a literal "null"** in the mode lookup or on review cards.
- `template_digest()` on an unknown pattern raises a clear `EngineError`.

## v0.22.2 (2026-10-20)

**Class:** Compatible (fixes to v0.19–v0.22 before any client adopted them).
**Adopt:** move the pin; nothing else.

Fixes from the independent functional test of S6–S9 (`tests/functional/test_independent_s6_s9.py`, 76 cases in a
dairy-processor domain written from the docs alone; it found 7 defects, all fixed here and kept as regression
tests).

- **A scope stopped by hand or by oversight stays stopped under pooled trust.** Before, a per-scope kill switch
  or `oversee(..., "stop")` on a pattern with `trust_pool_min` had no effect: thin scopes, and mature ones whose
  sample count the stop reset, fell back to the pooled AUTO route, and the action ran unattended. Such a scope
  now carries a hold (`PatternState.cap`) that the pool never lifts. Raising the scope by hand releases it.
- **A published registry that breaks the domain binding is never applied.** The previous configuration keeps
  running, and the refusal is audited (`config_apply_failed`).
- **An undeclared binding slot is refused even when the registry declares no slots.**
- **`dualrun compare` exits 1 on any difference**, owner and agent mode included, and its verdict says so.
- **Dual-run events without an `idempotency_key` pair by line number** (or an `id` in the file), not by a
  random id.

## v0.22.1 (2026-10-20)

**Class:** Compatible (fixes to v0.17.0 / v0.18.0 before any client adopted them; only tenants with `agents:`
or callers of `sentinel.org.authorise` see a difference).
**Adopt:** move the pin; nothing else.

Fixes from the independent functional test of `authorise()` and agent modes
(`tests/functional/test_independent_agents.py`, 69 cases in a hospital-pharmacy domain written from the docs
alone; it found 4 defects, all fixed here and kept as regression tests).

- **Policy precedence never depends on row order.** A store row now beats a region row: more specific means
  deeper in the roll-up chain or the value tree. On a true tie the least autonomous mode wins. Before, listing
  a region ACT row first let an agent act unattended where a store row said PROPOSE.
- **The agent identity names the row that decided:** the pattern, or the capability when a capability row
  decided. A row matched through a roll-up records its own scope (`region=south`), so instances with different
  modes are distinguishable.
- **Limits bound an amount's size:** `authorise` checks a negative amount as its magnitude.
- **A SoD pair naming the same action twice is refused.**

## v0.22.0 (2026-10-20)

**Class:** Compatible (fleet and CLI additions; a fleet file without the new keys reports as before, plus a
support-window flag computed against the newest release).
**Adopt:** move the pin. In the fleet file, give each site its `target_version` and `adoption` record, and set
`support_window` once Mohan decides it (default 2).

- **Per-client adoption tooling (paradigm overhaul S9, ADR-004).**
  - **Fleet:** `Site.target_version` overrides the fleet-wide target, and `Site.adoption` points at the support
    record. `FleetFile.support_window` / `latest_version` drive the `outside support window` flag, and each
    row reports `minors_behind`. Upgrade commands use the site's own target.
  - **Dual run:** `sentinel.dualrun` with `sentinel dualrun trace` (read-only, one JSON line per event under a
    pin) and `sentinel dualrun compare`. The comparison gives differences per pattern in match, route, outcome,
    proposed actions and owner, plus the trust guard. `compare` exits 1 when anything differs.
- Exemplar: a candidate R06 pin that widens the UOM-error match is caught by the dual run, and the guard names
  `r06_uom_error`.

## v0.21.0 (2026-10-20)

**Class:** Compatible (opt-in: an overlay without `binding` is unchanged).
**Adopt:** move the pin. A pack adds `binding.yaml` and passes it as `Overlay(binding=...)`.

- **Capability catalogue and domain bindings (paradigm overhaul S8, ADR-005).**
  - `sentinel.bindings.CATALOGUE` holds tier-1 capabilities in structural terms: `exception_watch`,
    `reconciliation` and `approval`, each already proven in two or more domains. Demand planning is not
    extracted yet.
  - `DomainBinding` / `load_binding` is tier 2: domain words, slots, and `never_automate`, which is required.
  - `check_binding` refuses engine start and registry publish for an unknown capability, an unmapped or foreign
    structure, a dead pattern glob, an undeclared slot, or a never-automate action that a pattern could run
    unattended. `enforce_never_automate` holds such patterns at a person even when the check is skipped.
  - `relevant()` lists the catalogue rows a domain uses, in its own words.
- Exemplar: the R06 retail binding (`exception_watch` and `reconciliation`).

## v0.20.0 (2026-10-20)

**Class:** Compatible (opt-in `oversight:` section in the people configuration; without it nothing changes).
**Adopt:** move the pin. To separate oversight, add `oversight:` naming a role that owns none of the agents.
For R06 that is internal audit.

- **Oversight separation (paradigm overhaul S7, ADR-003 Layer D, invariant 5).**
  - `oversight:` rows (`OversightRule`) name who oversees which templates.
  - A role that owns a covered template, or sits above its owner on the solid line, is refused at engine start
    and at publish. A person holding both an oversight role and an owning role gets a warning.
  - `Engine.oversee(pattern, "stop" | "demote" | "cap", actor, reason)` is the recorded lever
    (`oversight_action`). It is oversight-role only, needs a reason, and only lowers autonomy, on a template
    or one scope.

## v0.19.0 (2026-10-20)

**Class:** Compatible (opt-in per pattern with `trust_pool_min`. Patterns without it learn exactly as before,
and their definition hash is unchanged).
**Adopt:** move the pin. To pool, add `trust_pool_min: N` to a pattern that has `trust_by`. Doing so changes
that pattern's definition hash, so its trust restarts from its configured route, as for any change of meaning.

- **Pooled trust (paradigm overhaul S6, ADR-003 scale).** For a pattern with `trust_by` and
  `trust_pool_min: N`:
  - Each decision, reversal and outcome check teaches the scope's own state and the template's pooled state.
  - A scope uses the pooled route until it has N decisions of its own.
  - A reversal anywhere demotes the pool.
  - `Engine.trust_states()` / `trusted_state()` expose this, and `trace` says when a route is pooled.
  - The registry check warns on `trust_pool_min` without `trust_by`.
- Runtime at scale needs no change: Sentinel has no per-instance processes, and an agent instance is a row (a
  trust segment, `provenance.agent`). Bulk decisions and digests past a scope threshold remain backlog.

## v0.18.1 (2026-10-20)

**Class:** Compatible (fixes to v0.16.0 org-layer features before any client adopted them. Only tenants using
`stop_at` or `dotted` see a difference).
**Adopt:** move the pin; nothing else.

Fixes from the independent functional test of the org layer (`tests/functional/test_independent_org.py`,
57 cases in a dairy domain written from the docs alone; it found 3 defects from 2 causes, all fixed here and
kept as regression tests).

- **SLA escalation stops at the stop list.** `sweep()` walked up the tree past `stop_at`, and it also undid a
  correct vacancy routing by paging the top on the first sweep. A pattern's explicit `escalation_role` is
  still honoured.
- **A dotted-line person sees the queue in `reviews_for`.** Before, `can_see` said yes but the queue was never
  read. Approval still needs the solid line.

## v0.18.0 (2026-10-20)

**Class:** Compatible (opt-in: with no `agents:` section in the people configuration, matching, shadow, routing
and unattended runs are unchanged).
**Adopt:** move the pin. To use modes, add `agents:` rows to the tenant's people configuration. Start with
`{template: "*", mode: OBSERVE}` and raise scopes one by one.

- **Agent identities, modes and grants (paradigm overhaul S5, ADR-003 C1).**
  - `agents:` rows (`AgentPolicy`) set OFF / OBSERVE / PROPOSE / ACT per template × scope. The most specific
    row wins, and rows can be time-bound.
  - Effects: OFF sends the template's events to people as unmatched. OBSERVE is shadow. PROPOSE caps the
    route at a person. ACT runs within earned trust, the ceiling and limits.
  - **Grants** VIEW / EDIT per action. With grants set, an unattended step without EDIT goes to a person,
    audited as `agent_grant`.
  - **Invariant:** APPROVE is never grantable to an agent (refused at load).
  - Cases carry `provenance.agent` (`template@scope`) and `provenance.agent_mode`. `trace` shows the agent and
    why it was routed.
- Exemplar: R06 with OBSERVE by default, ACT at one store with an EDIT grant, PROPOSE at another, ACT without
  the needed grant, and OFF for loss at one store.

## v0.17.0 (2026-10-20)

**Class:** Compatible (a new module and an optional `sod:` section; nothing existing calls it).
**Adopt:** move the pin. Domain cores adopt by calling `sentinel.org.authorise()` on each agent-triggerable
write. Tenants may add `sod:` pairs to the people configuration.

- **`sentinel.org.authorise(directory, actor, action, obj, scope, amount, ...)`** (paradigm overhaul S4,
  ADR-003 C2): the one authority check a domain core imports. Rules:
  - A **person** needs current authority in scope.
  - An **agent** (`Agent(id, bound_role)`) is capped at the person holding its bound role in that scope today,
    falling back to the nearest held role above when vacant. It is refused when nobody in scope holds that
    role, and never reaches past the stop list.
  - **SoD pairs** are checked on the object.
  - Nobody approves their own proposal, and an agent never approves.
  - The result is a `Decision` (truthy when allowed) with `decided_by_role`, `checks` and `escalate_to`.
- **`sod:`** in the people configuration (`{first, second, description}`). It is validated, round-trips
  through publish, and is kept for SCIM-provisioned people. The people check warns on actions the overlay
  does not provide, and `__approve__` is a known action.
- Exemplar: the R06 chain A org with stock-adjust Limits rows, an agent per store, a vacant store, and
  count/adjust segregation.

## v0.16.1 (2026-10-20)

**Class:** Compatible (fixes to v0.15.0 role slots before any client adopted them; registries without slots
are untouched).
**Adopt:** move the pin. A slotted pattern that also writes `owner_role` / `escalation_role` is now refused:
remove the role line and let `slot_bindings` decide.

Fixes from the independent functional test of role slots (`tests/functional/test_independent_slots.py`,
52 journeys in a hospital domain written from the docs alone; it found 6 defects, all fixed here and kept as
regression tests).

- **An overlay built in code resolves its slots.** The engine binds `Overlay.slots` / `slot_bindings` at start
  and refuses an unbound slot. Before, its cases went silently to the default role `operator`.
- **`conformance()` reports an unbound slot.**
- **A slot plus any role line is refused**, including `operator` and the currently bound role. Before, a
  published text naming the bound role was stored as a role override and blocked every later rebinding.
  Re-resolving already-bound patterns against new bindings still works, and overrides keep unset fields unset.
- **`trace` shows `escalation_slot`, and the case story shows both slots** (`Pattern.slot_info()`).

## v0.16.0 (2026-10-20)

**Class:** Compatible (every feature is opt-in in the people configuration; a directory that uses none of it
matches, sees and authorises exactly as before).
**Adopt:** move the pin; nothing else. To use the org layer, add `dotted`, `scopes`, `stop_at`, `vacancy` or
assignment `valid_from` / `valid_to` to the tenant's people configuration and publish it.

- **Org layer (paradigm overhaul S3, ADR-003 C1).**
  - **Dotted lines** (`Role.dotted`) see a queue without acting on it or sitting on the escalation path.
    `Directory.can_act()` is the solid-line check that approval now uses; `can_see()` adds the dotted lines.
  - **Time-bound assignments** (`valid_from` inclusive, `valid_to` exclusive), read on the engine's clock.
  - **Typed hierarchical scopes** (`scopes:`): a tree within a fact (category) or a roll-up to another fact
    (store → region). An assignment to a higher value covers everything below it.
  - **`holders(role, facts, at)`**: the role's people in scope, else the nearest held role above. It never
    climbs past a `stop_at` role, and every role must have a stop at or above it.
  - **`vacancy: escalate`** (off by default): new reviews for a vacant role go to that nearest held role,
    audited as `vacancy_escalated`.
  - Configuration is validated: unknown or solid-line-duplicating dotted roles, scope cycles, stop list gaps
    and empty windows are refused.
- Exemplar: chain A's org for R06 (`people_chain_a_org.yaml`), with regions over stores, a category tree,
  leave cover by dates, internal audit on a dotted line, and a vacant store routed to its regional manager.

## v0.15.0 (2026-10-20)

**Class:** Compatible (additive and switched off: a registry without slots behaves exactly as before, and
every definition hash is unchanged).
**Adopt:** move the pin; nothing else. To use slots, the pack replaces `owner_role` / `escalation_role` with
`owner_slot` / `escalation_slot` and declares `slots:`; each tenant adds `slot_bindings:` in its own layer
before that pack version is enabled (publish is refused until every slot used is bound).

- **Role slots (paradigm overhaul S2, ADR-003).** A pattern can name the job (`owner_slot`,
  `escalation_slot`) instead of an org role; registries carry `slots:` (declared slots) and `slot_bindings:`
  (slot → this tenant's role), merged across layers. Refused at load and at publish: a used slot that is
  unbound, a slot not declared, a binding to an unknown role, a pattern naming a slot and a different role.
  Registry documents write the slot, not the resolved role, so a rebinding never leaves a stale role; a
  console rebinding is stored as a layer and survives pack upgrades. Rebinding does not reset trust (who owns a
  case is not what it means). `explain` shows the slot.
- **Exemplar:** retail R06 stock integrity as a test pack (`tests/packs/r06_stock_integrity`): one template
  naming slots only, two store chains with different orgs binding it, golden cases, routing to the holders of
  the bound role in scope. A test keeps the exemplar's words out of `sentinel/`.

## v0.14.3 (2026-10-20)

**Class:** Compatible (documentation and process only; no code path changes).
**Adopt:** nothing to change. Start a `SENTINEL_ADOPTION.md` for each client from the new template.

- **ADR-004 discipline adopted (paradigm overhaul S1).** CHANGELOG entries now carry a class and an adoption
  line; `docs/templates/SENTINEL_ADOPTION.md` is the per-client support record (pinned pair, rollback pair,
  changes between pins, pack check, replay, dual run, switch, watch). A test keeps every new entry classified.

## v0.14.2 (2026-10-13)

Framework fixes from the independent functional test of the Acme Home overlay (94 journeys; it found 10
defects, 4 of them in the framework). Each has a regression test that fails without the fix.

- **A malformed value gives a data case, never a failed monitor.** Dataset checks take `types` (boolean,
  integer, number, time, text): a value that does not fit is stored as null and counted, so the dataset is
  untrusted while its metrics still run. An undeclared column mixing text with other values is untrusted
  too. Trust is now decided before a monitor runs its query.
- **The metric verifier honours `params.days`:** it measures the last N days up to the check, so it sees
  what was already wrong before the fix (a bank line 48 h unmatched). Without `days` it measures since the
  fix, as before.
- **A fix made outside Sentinel is verified.** `outcome_check.codes` lists closing codes ("matched in the
  books") that are checked like a fix with steps; unknown codes are refused at start.
- **Authority rules take `inherit` and `needs_proposal`.** `inherit: false` keeps a rule to its own role
  (seniors do not hold it); `needs_proposal: true` approves only what another person proposed, so an
  escalated case or a playbook's proposal cannot be approved alone.

## v0.14.1 (2026-10-13)

Fixes from the first independent functional test (`tests/functional/test_independent.py`, 78 journeys and
probes written by a separate tester from the docs alone; it found 4 defects, all fixed here and kept as
regression tests).

- **A proposer never approves their own forward.** The forwarded proposal now records who proposed it
  (`proposed_by`, carried across repeated forwards); approving or modifying it as one of them is refused
  and audited (`decision_denied`), even after a role change gives that person the approving role.
- **A redelivered "it is fixed" event closes nothing.** Clearing events are checked against the inbox
  before they close cases, so a replayed old recovery cannot close a breach opened since (`duplicate`).
- **Cutting the newest seal and its rows is detected.** `verify` compares the newest audit row with the audit
  table's sequence counter and flags sealed rows whose seal is missing.
- **Prompt-injection check covers payload keys,** not only values.

## v0.14.0 (2026-10-13)

- **Propose, then approve.** A decision by someone who may only propose a step (or is above their amount
  limit) no longer fails: it becomes the proposal of a new review for the role that may approve it, and runs
  only when that person approves (maker-checker on actions: a planner proposes a purchase order, the buyer
  approves it; Accounts proposes a large refund, the Controller approves it). Before, the decision was refused
  with an `escalate_to` hint and nothing moved the case.
- **Derived dataset columns.** `derive:` on any dataset adds columns computed in order from the loaded rows,
  so a business rule (e.g. MOQ-aware replenishment) is configuration, the same for every source.

## v0.13.0 (2026-10-12)

How long a case lives, KPIs that raise and close cases, Ask AI analytics that act, and the platform side of a
domain pack: business capabilities, methods of work recorded on every case, a decision trace, and data that
must pass its checks before anyone acts on it.

- **Datasets from connectors.** Dataset `kind: lookup`: rows through a connector's read-only lookup (login,
  paging, XML) mapped to columns in configuration. Zoho Books and Tally templates ship the standard
  finance datasets (bank lines, cash position, invoices, settlements); `connectors.with_datasets` switches a
  metrics configuration to them, per dataset. New mapping filters; dotted XML element names in paths.
- **Randomised trials of methods.** A candidate method can be tried on a random share of new cases (each
  decided by a person) and compared with the current one on verified outcomes, with a 95% interval; promotion
  from a trial needs it shown better and is refused when shown worse.

- **Learning methods of work.** Candidate methods mined daily from what people keep doing on an exception,
  backtested on recent cases, compared in shadow, promoted by someone with `__configure__` (maker-checker) and
  rolled back; never wider than the exception's allowed actions. Proposed methods on the Capabilities page;
  `/console/api/methods/candidates`, `/methods/propose`, `/methods/candidates/<id>/<shadow|reject|promote|rollback>`.
- **Postgres outbox connector.** Template `postgres-outbox`: reads the application's Sentinel outbox (triggers write order fulfilled / cancelled and sync failed / recovered in the same
  transaction) with a read-only login and a cursor. SQL sources take bound `params`; emit rules take a
  `correlation` id.
- **Fixed: SQL and HTTP datasets could not load** (the dataset reader built a source with no emit rule, which
  is refused). SQL datasets take bound `params`; database numerics load as numbers.

- **Capabilities and methods of work.** Registry `capabilities:` (accountable role, intent, outcome metrics,
  automation ceiling, `mode: observe`); exceptions name their `capability` and `method`. Every case and
  disposition records its provenance (capability, method, definition hash, registry version). The case story
  has a decision trace with its gaps; `GET /console/api/methods` compares method versions on real cases;
  console **Capabilities** page with each capability's stage.
- **Trusted data.** Dataset `checks` (fresh, min_rows, unique, not_null, invalid rules) and `owner`: untrusted
  data stops monitors raising or closing cases and outcome checks judging, and raises `data.untrusted` for its
  owner until `data.trusted`.

- **Metrics, monitors and Ask AI analytics.** Configuration kind `metrics`: datasets (SQL, HTTP, files, the
  overlay, Sentinel's own cases) loaded into a locked-down DuckDB; KPIs with dimensions, targets and owners;
  monitors that raise `kpi.breach` cases, report them again while they last and send `kpi.recovered` when
  they recover. Agents read KPIs (`metrics.query`) and outcome checks measure them (`verifier: metric`).
  Ask AI: `/v1/ask/catalog`, `/v1/ask/metric` (summary, typed widget, A2UI) and `/v1/ask/raise` plus the
  A2UI `sentinel.raise` button. Console **Metrics** page.
- **Escalation ceiling.** `escalation: {stop_at: OPS-07}` (or a list of function heads): a review climbs no
  higher.

- **How long a case lives.** Per exception, with registry `defaults:`: a repeat limit at the top of the role
  tree, then a daily overdue list instead of more cards; `clear_when` events and scheduled lookups that close
  a case as `resolved_in_source`; `expires_after_hours`; pauses while waiting on someone outside
  (`pause_on`), released by time or by a new report; silences for planned work (Silences page,
  `__silence__`). None of these move earned trust; the Value page marks exceptions to tune.

## v0.12.0 (2026-10-11)

Keys entered in the console, WhatsApp through Indian providers, invoice payment links, ready-made sales
channel and warehouse connectors that wait for their keys, and the penetration test scope.

- **Penetration test scope (SEC).** `docs/security/PEN_TEST_SCOPE.md`: rules of engagement, the test site, a checklist per surface and what the firm reports back.
- **Sales channel and warehouse connectors (B1).** Templates for Shopify, Amazon SP-API, Flipkart, Ajio, Myntra
  and a REST warehouse system; each waits for its keys. Keys a template in use lists appear on the Keys page
  even when only the overlay's code reads them.

- **Payment links (F4).** `sentinel invoice --payment-link` creates a Razorpay link and a Pay button on the
  invoice; signed payment-link webhooks are recorded per invoice. Platform keys (audit, usage, bundle, SCIM,
  catalogue, Razorpay) can be entered on the Keys page too.
- **WhatsApp through Gupshup and Interakt (B5).** Edge kinds `gupshup` and `interakt` with cards in the reader's
  language and button replies to `/v1/wa/<edge>` (shared token or signed); ready-made templates.
- **Keys page.** Connector keys entered in the console, encrypted per tenant (`SENTINEL_MASTER_KEY`), never shown
  again, applied to every process at once; connectors and edges wait for missing keys instead of failing;
  `sentinel secret list | set | clear`, `sentinel new-master-key`.

## v0.11.0 (2026-10-11)

The rest of the review backlog and the platform items: a tamper-evident audit, hosted multi-tenant mode,
domain packs and their catalogue, ready-made connectors for Indian systems, billing, environments, SCIM,
security readiness, Indian-language cards and benchmarks.

- **Connector templates (B3/B4).** Shiprocket, Delhivery, Zoho Books, SAP Business One and TallyPrime
  (`sentinel connector list | show | add`, **Add to draft** in the console). Connectors configuration gains
  login tokens (`auth:`), read-only HTTP lookups (`lookups:`), XML polls and bodies, an `xml` filter and
  token-mode webhook signatures.
- **Pack catalogue (G2).** `sentinel pack catalogue build | search | add`: a signed index of packs with
  versions, industries, exceptions, capabilities and file digests; adding resolves dependencies, verifies
  files, grants nothing and keeps settings across upgrades; listed on the console's set-up page.
- **Anonymised benchmarks (E5).** Opt-in monthly snapshots of rates for shared (template and pack)
  exceptions, percentiles across at least k sites per industry, and a comparison on the Value page
  (`sentinel benchmark snapshot | build | compare`). Pack layers are now named `pack:<id>`.
- **Indian languages (A8).** A person's `language` (Hindi, Tamil, Telugu, Kannada, Marathi, Bengali,
  Gujarati, Malayalam, Punjabi) sets the words on their cards across WhatsApp, Slack, Teams, email and the
  phone page; the case's text is translated by the model (`task: translate`), masked and cached; WhatsApp
  templates pick an approved language.
- **Visual playbook builder (C3).** The exception editor builds playbooks step by step: actions and lookups
  chosen from the catalogue with a field per parameter, closing steps with outcomes, conditions per step,
  reordering, and checks for missing parameters before the change is kept. The catalogue now lists
  connector tools too.
- **Security readiness.** Signed release images (Sigstore, keyless) with provenance and a CycloneDX SBOM
  attestation; `scripts/sbom.py` (offline SBOM); weekly and per-push dependency advisories (pip-audit), image
  scan (Trivy) and secret scan (gitleaks); Dependabot; `SECURITY.md` and `docs/security/` (controls map for
  security reviews, access control, secure development, vulnerability management, incident response, support
  access).
- **SCIM 2.0 provisioning with group-to-role mapping.** `/scim/v2` Users and Groups for Entra ID, Okta and
  Google; groups give roles (with scope) through the people configuration's `scim:` section; deactivation
  and removal take effect at once and reach every process.
- **Environments and configuration bundles (C5).** `SENTINEL_ENV` names the site (shown on the console and in
  `/healthz`); `sentinel bundle export | plan | import` moves signed, checked configuration from dev to staging
  to production, refusing bundles from environments a site does not accept.
- **Fix: engines no longer share overlay state.** Publishing on one engine changed the patterns of every other
  engine built from the same overlay object (hosted tenants given an overlay object rather than a factory).
- **Invoices in INR with GST (F4) and the pass-through ledger (F5).** `sentinel invoice` turns a verified,
  final usage export and a plan file into a tax invoice (JSON and HTML) with overage, model and message costs
  at a markup, discounts, and CGST/SGST or IGST.
- **Tamper-evident audit (H14, AU).** Settled audit rows are sealed into a hash chain of signed batches
  without a global write lock; `sentinel audit verify | export | verify-export`; retention tombstones and
  erasure redactions keep the chain valid; optional forwarding to a SIEM (`SENTINEL_AUDIT_WEBHOOK`).
- **Hosted multi-tenant mode (D1).** A schema, pool, engine, tokens, SSO, licence and secrets scope per
  tenant; routing by host or `/t/<tenant>/`; weighted worker turns; `sentinel hosted serve | worker`.
  Configured actions and model calls run with the tenant's secrets scope.
- **Monthly partitions (H13).** Opt-in for `audit` and `model_runs` on PostgreSQL (`sentinel partition`),
  with partitions created ahead by the maintenance service.
- **Operator features.** Bulk decisions (A6), a mobile review page at `/console/m` (A7), model cost and
  quality per exception (E3), the monthly owner report by email / Slack / Teams (E2), and draft patterns
  suggested from unmatched cases (A5).
- **Domain packs (G1), test kit (D8), console layer over packs (D4).** `sentinel-pack.yaml` manifests
  with versions, requirements, namespaced actions and tools, capabilities a site grants, settings and golden
  cases; `sentinel.testing` (conformance, golden cases, `engine_for`); `sentinel pack check`; console
  changes are kept as a layer and re-applied over upgraded packs.
- **Expect sources (D6).** "Did not happen by" exceptions: at a local time each day, an event for every
  expected item that is absent (indents by 05:30, settlements by 21:00, GST due dates).
- **Pluggable edges (D3) and Slack, Teams, email (B5).** Edge kinds come from a registry
  (`register_edge_kind`, `sentinel.edge_kinds` entry points); Slack is two-way (`/v1/slack/<edge>`), Teams
  and email carry a link to the console.
- **Exact circuit breaker (H14).** The unattended-per-hour check and taking the slot happen together under
  a per-pattern transaction lock, and cases in flight count; several workers can no longer overshoot it.

## v0.10.0 (2026-10-10)

The independent review's platform backlog: hardening (below), then the pieces that let a second customer
be set up from configuration instead of a custom build.

**Added**
- **Configuration plane.** Two-person approval for publishing configuration (`config_approval`), replay of
  recent cases through a draft registry before publishing it, a go-live page with a readiness checklist and
  per-exception shadow switch (`shadow: true` in the registry), template layers (`template: <name>`) with
  stub actions, and `sentinel template` / `sentinel config show | check | publish | approve | replay`.
- **Write actions without code.** `actions:` in the connectors configuration: HTTP calls with a parameter
  schema, success checks, an optional undo (`compensate`), idempotency keys and egress checks.
- **Understanding what happened.** A dry-run trace of one event (facts, every candidate exception and the
  clause that failed, grouping, route and why, playbook steps, reviewers), and a case explorer (search, the
  whole story in time order, reverse with a note). CLI: `trace`, `case`.
- **Model and matching.** Multi-step model proposals (`llm_max_steps`), a per-exception switch to skip the
  model's proposal on human cases (`diagnose: false`), `match:` shares the playbook condition language, and
  fingerprint rule changes reset the trust a pattern earned (adopted silently on upgrade). Playbook params
  and lookup args are checked against declared schemas when configuration is published.
- **Commercial and admin.** Signed licences that degrade to human review and never stop the site
  (`sentinel licence keygen | issue | status`), a signed and chained monthly usage export (`sentinel usage`),
  a value report in the site's currency (Value page), Plan & usage, and a fleet view across sites
  (`/v1/fleet/status`, Fleet page, `sentinel fleet status`).
- **Personal data (DPDP).** Access reports, erasure from closed cases, scrubbing personal fields by age
  (`--pii-days`), the `__privacy__` right, a Privacy page, a data map, a breach runbook and a DPA template
  (docs/privacy).
- **Docs.** The overlay contract (docs/OVERLAY_CONTRACT.md).

**Upgrade notes**
- Fingerprint rules are now part of a pattern's meaning: trust stored by 0.9 is adopted, but any later change
  to a pattern's fingerprint rules resets its trust.
- A new index on incidents (`ix_inc_created`); PostgreSQL sites run `sentinel migrate` (or start with
  automatic migration on).

### Hardening from the independent review

**Fixed**
- **H1** A lost database connection never came back: after a PostgreSQL restart the API and workers kept
  running but did nothing. The PostgreSQL store now uses a connection pool (`psycopg-pool`): broken
  connections are replaced, each thread works on its own connection (async drain with 4 threads went from
  136 to 253 incidents/s on 2 cores), and sessions have statement and lock timeouts. Workers exit after 30
  failed loops in a row so their supervisor restarts them; the bundle's workers have a healthcheck.
- **H2** Anyone with the configure right could run programs and read the server's secrets. Now: stdio MCP
  servers only run commands the overlay or the operator allows; configuration reads only variables named
  `SENTINEL_SECRET_*` / `SENTINEL_EDGE_*` / `SENTINEL_GATEWAY_KEY` or listed in `SENTINEL_CONFIG_SECRETS`;
  every request configuration causes (polled and SQL sources, MCP over HTTP, edges, model servers) refuses
  metadata and link-local addresses, needs `SENTINEL_EGRESS_ALLOW` for internal ones, follows no redirects
  and caps response size. **Upgrade note:** rename secrets used by connectors and edges to
  `SENTINEL_SECRET_...` (or list them in `SENTINEL_CONFIG_SECRETS`), and add internal systems to
  `SENTINEL_EGRESS_ALLOW`.
- **H3** Automatic playbooks and the model ignored approval limits (a model posted ₹9,99,999 where people
  were capped at ₹5,000). Unattended steps now respect amount limits: explicit `unattended:` rules in the
  people configuration, otherwise the lowest `max_amount` any person has for that action. Over the limit,
  the case goes to a person with the reason.
- **H4** A model call longer than the job lease (300 s) let a second worker run the case again. Workers now
  renew the lease while a job runs, check they still hold it before acting on a model's answer (a worker
  that lost its job acts on nothing), and in async mode candidate models run as their own `shadow_eval` job
  instead of on the case's critical path.
- **H5** Locks only worked inside one process. Now a review is closed with a conditional update (two API
  replicas cannot both act on it), work on one incident (decisions, reversals, resolving, recovery) is
  serialised across processes with a session advisory lock, and trust is updated under a per-pattern lock so
  concurrent updates are not lost. Recovery re-checks each incident under that lock.
- **H6** Health checks, metrics, the report and the inbox loaded every open review or disposition (200-300 ms
  at 20,000 open reviews, on every health probe). They are now counts and aggregates in the database; the
  inbox is filtered by role in SQL and paged (`limit`, `offset`). New indexes on incidents by state and on
  open reviews by role.
- **H7** Retention would not keep up at about a million cases a year. Added the missing indexes (action and
  model runs by incident, incident events by event, audit and events by time, finished work); retention walks
  closed cases by `(updated_ts, id)` instead of OFFSET and removes loose rows in bounded batches with
  `NOT EXISTS`. Monthly partitions for audit, events, work and model runs come with versioned migrations (H13).
- Schema setup no longer runs DDL in every process at start: the schema records its version and processes
  skip setup when it is current. Before, `CREATE INDEX IF NOT EXISTS` took table locks at start that could
  deadlock with live traffic from other processes (found by the six-process test after H7 added indexes).
- **H8** An edge's shared secret let it answer as any person. Every delivered card now carries a single-use
  answer token bound to its review, person and edge (7 days); answers without it, for someone else, or a
  second time are refused. WhatsApp replies must come from a person the card was sent to. Edges can verify
  answers with their own `answer_secret_env`. Blocking engine calls no longer run on the API's event loop,
  and edge and webhook bodies are capped while being read.
- **H9** Authorisation gaps. Case details are shown only to people in the roles that work the case (or above,
  in scope) and to configurers; people's contact details only to `__configure__` / `__access__` holders, who
  alone may draft people changes; testing an MCP server needs `__configure__`. Single sign-on now checks the
  ID token's RS256 signature against the provider's keys, requires https provider endpoints and a verified
  email, and ties each person to the provider's account id after the first sign-in (reset via the API). The
  API sends security headers (CSP with `frame-ancestors 'none'` for the console, nosniff, no framing).
- **H10** Events could be lost: the duplicate check was global, so the same key from two sources or tenants
  dropped the second event. Keys are now per tenant and source. Cursors can take a unique tie-breaker
  (`cursor.tie`, `{{cursor_tie}}` / `%(cursor_tie)s`) so rows sharing a timestamp across a page boundary are
  not skipped. **Upgrade note:** an event re-sent across the upgrade is not recognised as a duplicate of its
  pre-upgrade copy; drain retries before upgrading.
- **H11** Model cost and prompt injection. `daily_budget` in the models file stops model calls for the day
  once the estimated spend reaches it; `brief_fields` limits the payload a pattern sends; tool results are cut
  at 8,000 characters and a case at 120,000; case text that reads like instructions to a model sends the
  proposal to a person; the system prompt marks all case text as data.
- **H12** Model gateway. Requests may only set known fields and options; context and output length are
  capped (`max_num_ctx`, `max_num_predict`) and the host's own `keep_alive` applies, so one customer cannot
  unload or starve another's model. The gateway waits upstream no longer than the site will (sites send
  `X-Request-Timeout`), stops the model's work when the site disconnects, and writes the usage ledger off the
  event loop. Sites now ask Ollama for an 8k context by default (it used to truncate long briefs silently).
- **H13** Versioned migrations: `sentinel migrate` brings a schema up to date once per upgrade, and with
  `SENTINEL_AUTO_MIGRATE=0` processes refuse to start on an old schema instead of migrating it themselves.
  Monthly partitions for the largest tables are deferred until a site's volume needs them (retention with the
  H7 indexes handles about a million cases a year).
- **H14** Actions without their own timeout get a default (120 s; a timed-out step goes to a person as
  "outcome unknown"); tools the model calls time out after 30 s and the model is told; per-incident locks are
  a fixed set of stripes (memory no longer grows with every case); MCP calls over HTTP run in parallel.
  Still open: a tamper-evident audit chain (planned with the signed audit export) and the circuit breaker's
  small overshoot across workers.

## v0.9.0 (2026-10-10)

Production upkeep. 306 tests (plus 5 for the CrewAI add-on), on SQLite and PostgreSQL (with pgvector),
lint clean; backup, restore drill and nightly maintenance verified in the Docker bundle.

**Added**
- **Backups**: `sentinel backup` (pg_dump of the Sentinel schema, or SQLite's online backup) with a
  manifest (SHA-256, rows per table), `verify-backup`, `restore --yes` (verifies the file first and the row
  counts after), pruning to the newest N.
- **Retention**: `sentinel retention` archives closed cases older than the horizon, with everything that
  belongs to them, to gzip JSON lines (readable by DuckDB) and removes them; preview by default.
- **`sentinel maintain`** and a `maintenance` service in the site bundle: nightly backup, verify, prune,
  retention. The runtime image carries the PostgreSQL 16 client tools.
- **HNSW index** for similar-case search: `sentinel vectors-index --dim N`, used automatically.
- Runbook: backups, restore, restore drill, retention, upgrades (OPERATIONS.md); README and ARCHITECTURE
  brought up to date.

**Fixed**
- `sql/postgres_schema.sql` was missing the tables added since v0.3; it is now generated from the store
  and checked in CI.

## v0.8.0 (2026-10-10)

People. 300 tests (plus 5 for the CrewAI add-on), on SQLite and PostgreSQL, lint clean.

**Added**
- **Access page**: give people and systems tokens from the console (shown once, stored hashed, optional
  expiry, revoke at once), with the new `__access__` right. Token use is recorded (last used).
- **Single sign-on** with OpenID Connect (authorization code with PKCE, standard library only): only active
  people in the people configuration get in, matched on email or id; sessions expire and end on sign-out.
- **Edges from configuration** (connectors `edges:`): A2UI cards for Ask AI and other chat surfaces,
  WhatsApp Business Cloud API (interactive buttons or approved templates; signed replies matched to people
  by number), and signed webhooks. Answers come back through the same approval rules. The connectors page
  lists edges.

## v0.7.0 (2026-10-10)

Know more per case. 288 tests (plus 5 for the CrewAI add-on), on SQLite and PostgreSQL, lint clean.

**Added**
- **Standard operating procedures** per exception (`sop`): in the model brief (the most relevant sections
  when long, never masked), on review cards and in the console editor. The model names the step it
  followed. Editing a procedure keeps earned trust.
- **Trust per segment** (`trust_by: [channel]`): each value earns its own streak, promotions and reversals;
  a reversal demotes only its segment; setting the pattern's route sets every segment (kill switch), and
  each earns its way back. Exceptions page lists segments with their
  promotions; API accepts `pattern@fact=value` ids; configuration check warns about facts events never carry.
- **CrewAI add-on** (`pip install 'kbg-sentinel[crewai]'`): the `crew` model provider. Investigators use
  the case's read-only tools through Sentinel (unmasked, recorded, masked again), a decider answers in the
  usual form, and every model call goes through a named Sentinel model client. Telemetry off.
- **Fact refresh**: repeat events keep an open incident's facts current; a case that now matches a more
  urgent pattern has its review pulled forward.

**Fixed**
- Model calls that hang past their timeout are counted and discarded when they return; no new call queues
  behind them. The Claude client has an SDK-level timeout.

## v0.6.0 (2026-10-10)

Connect without code.

**Added**
- **Connectors** configuration: data sources (signed webhooks at `/v1/hooks/{source}`, polled HTTP APIs with
  cursors, read-only SQL tables) mapped to events by emit rules; MCP servers (stdio, HTTP with JSON or SSE)
  whose allowlisted read-only tools become lookup tools. Console page with payload try-out, fetch now and MCP
  test; checks for unknown filters and operators, secrets in payloads, unset environment variables, event types
  nothing handles.
- **Expressions** for configuration: templates with filters, conditions, list indexes.
- **Branching playbooks**: `lookup`, `when`, `close`, per-step `disposition`.

**Fixed**
- The model brief masked tool and action names along with personal data (any key called `name`). Only the
  case is masked now.


## v0.5.0 (2026-10-10)

Configuration without code, and a console to run it. 250 tests including headless-browser tests of the
console, lint clean.

**Added**
- **Versioned configuration** for the exception registry, people and models: drafts, checks (errors block,
  warnings inform), publish with the `__configure__` right, rollback, diff; applied at once in the publishing
  process and synced by every other API and worker process; set-wise check and publish for changes that
  span registry and people.
- **Templates**: retail fulfilment, dairy distribution, manufacturing (roles, fingerprints, exception
  patterns, people tree and authority), with the actions and verifiers each expects.
- **Console** at `/console` with its API at `/console/api`: overview, reviews (approve, close, do something
  else with parameters pre-filled from the case), exceptions with a form editor, people and roles (role tree,
  scoped assignments, approval authority), models, changes (history, diff, publish, roll back), learning,
  insights (DuckDB), activity, and a set-up wizard from a template. Static HTML/CSS/JS, dark mode, no
  external requests.
- `Store.recent_audit`, `PostgresStore.dsn` (for analytics), `__configure__` meta right.

**Changed**
- Coverage warnings count people in roles above: "no people of its own; only [...] above it see its queue"
  versus "nobody above it either".
- YAML written from running objects normalises numbers (24.0 → 24) so diffs show only real changes.

**Fixed**
- Embedding jobs used wall-clock time instead of the engine clock; a recovery test depended on the time of day.


## v0.4.0 (2026-10-10)

Learning from similar cases, and measuring models before trusting them. 224 tests (all on PostgreSQL with
pgvector, on plain PostgreSQL and on SQLite), lint clean.

**Added**
- **Similar-case search**: masked case text embedded on disposition (background job in async mode), vectors
  in the customer's store - pgvector on PostgreSQL when available, float array otherwise, JSON on SQLite;
  nearest past cases (with reversals and outcome results) in the model brief and on delivered review cards.
- **Embedders**: `OllamaClient.embed`, `OpenAICompatibleClient.embed`, dependency-free `HashingEmbedder`;
  `embedder:` in the models file; `sentinel embed-backfill`.
- **Model evaluation**: `Engine.evaluate` / `sentinel evaluate --candidate <model>` replays known-good past
  decisions (history and similar cases from before each case only), compares with people and the primary
  model, per-pattern verdicts; `sentinel analytics evaluations`.
- CI runs PostgreSQL with pgvector.


## v0.3.0 (2026-10-10)

Open-source, self-hosted stack. 206 tests (204 on SQLite, all on PostgreSQL), lint clean, runtime
dependencies checked for open-source licences in CI, Docker bundle verified end to end.

**Added**
- **Open-model providers**: `OllamaClient` (chat, JSON mode, embeddings) and `OpenAICompatibleClient`
  (vLLM, llama.cpp, LiteLLM, Ollama /v1). Outages (`ModelUnavailable`) are told apart from config errors.
- **Fallback** to a second model with a cool-down after outages; **escalation** of unusable or unsure answers
  to a frontier model; **per-pattern `model_task`** so routine patterns use the small model.
- **Models file** (`load_models`, `--models` / `SENTINEL_MODELS`).
- **Model calls persisted** (`model_runs`): model that answered, provider token counts, cost, latency,
  fallback reason, escalation; never prompts or replies.
- **Model gateway** (`sentinel gateway`): per-customer tokens, model allowlists, rate and concurrency fair
  share, inference-only endpoints, 503 when busy, usage ledger and metrics, no prompt logging.
- **DuckDB analytics** (`sentinel analytics`): automation, weekly, trust, service, models, hotspots;
  Parquet snapshots; read-only over PostgreSQL, SQLite or snapshots.
- **Deploy bundle**: Docker image (DuckDB extensions included for offline sites), site compose with
  PostgreSQL 16 + pgvector, API, worker replicas, Prometheus and a Grafana dashboard; Mac mini install
  script (native Ollama, gateway under launchd).
- Workers serve `/metrics` and `/healthz` (`--metrics-port`); `sentinel new-token`.
- `scripts/check_licences.py` and a CI job building and smoke-testing the image offline.

**Changed**
- Vendor-neutral PostgreSQL naming: `sql/postgres_schema.sql` (was `supabase_migration.sql`).
- Histograms keep bucket counts instead of every sample (memory stays flat).
- PostgreSQL schema creation and migration take an advisory lock, so API and workers can start together.


## v0.2.0 (2026-10-10)

Hardening plus production features. 141 tests, all passing on PostgreSQL (two Postgres-only
multi-process tests skip on SQLite), a chaos suite soaked at 3,000 random scenarios, lint clean.

**Added**
- **RBAC**: role tree, people, scoped assignments, approval authority with amount limits, meta rights
  (promote, set route, kill switch, reverse), two-person rule for promotions to `auto`, escalation up
  the tree, `reviews_for(person)`.
- **Async work queue**: ingest only records and queues; workers lease jobs (`SKIP LOCKED` on Postgres),
  retry with exponential backoff, dead-letter to a person. `Worker` loop with maintenance.
- **Action timeouts**: a timed-out step is marked unknown and never retried blind.
- **Pattern versioning**: trust resets when a pattern's meaning changes, not on cosmetic edits.
- **Layered registry**: `load_layers([trunk, domain, project])` with extend, override and disable.
- **Outcome verification**: scheduled checks after a fix; failures demote the pattern and come back
  as a follow-up incident.
- **Model router**: per-task models, metering (latency, size, estimated cost), candidate models run in
  shadow with agreement scoring.
- **PII masking** around every LLM call, including tool results; real values restored for actions.
- **Edges**: review cards per person and channel through the queue; HMAC-signed webhooks with replay
  protection; answers back through RBAC; delivery on escalation.
- **HTTP API** (FastAPI): bearer tokens (hashed) for services and people, signed edge answers, rate
  limiting, clean error codes. `sentinel serve`, `sentinel worker`, `sentinel token-hash`.
- **Observability**: Prometheus metrics, `/healthz`, JSON logs, secret redaction in audit and logs.
- Payload size and depth limits at ingest; idempotent schema migrations.
- `Engine.coverage()` / `sentinel validate` warnings: patterns whose role nobody can act on.

**Fixed (found by the new tests)**
- SQLite store: rows were fetched outside the lock, which could corrupt reads across threads.
- `recover()` could take an incident a live worker was still executing; it now waits for staleness.
- Escalation at the top of the role tree could move a review back down.
- Circuit breaker and LLM history read the whole disposition history per event (quadratic); now
  bounded and indexed. Synchronous resolution is 3.7× faster on Postgres and flat as history grows.
- Compensations (undo steps) were not audited as side effects.

## v0.1.0 (2026-10-10)

First release: event pipeline, fingerprints, grouping, inhibition, registry, auto/LLM/HITL routing,
guardrails, idempotent actions with compensation, learning with human-approved promotions, SQLite and
PostgreSQL stores, CLI.
