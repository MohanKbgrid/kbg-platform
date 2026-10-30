# ADR-006: Case families, interrupt budgets and the alert-fatigue governor (v0.25.0)

- **Status:** Proposed (design). Build starts after v0.24.0 passes independent verification.
- **Date:** 20 Oct 2026
- **Requested by:** a retail POS (the retail POS `docs/design/SENTINEL_H1_GAPS_REQUEST.md`). Reviewed in
  `SENTINEL_H1_GAPS_REVIEW.md`, with Mohan's decisions D1–D4 (20 Oct).
- **Class:** Compatible. Every part is opt-in per tenant: `families:`, `interrupts:` and `governor:`. Without them,
  nothing changes.

## Context
One consumer raises the same problem from three lanes (live, live against a baseline, overnight). It needs the phone
to buzz rarely, and it needs detectors that are mostly ignored to step out of people's way by rule. Sentinel today:
- dedupes within one pattern (fingerprint plus an open-incident window);
- pushes every review through the edges;
- has digests (`digest_above` and `digest_every_minutes`);
- has pooled trust;
- has no notion of shift, budget or disposition usefulness.

The framework stays generic. Lanes, families, shifts and disposition codes are configuration; no retail words go in
`sentinel/`.

## Decision

### 1. Case families (Gap 1, D1, D2)
```yaml
families:
  stock_integrity:
    key: [store, article, business_date]       # exact match only
    raci: {A: store_owner, R: [stock_controller], C: [loss_prevention], I: [area_manager]}   # slots
    reopen_on: [count_variance]                # evidence kinds that re-open a case closed the same day
    lanes: [LIVE, BASELINE, OVERNIGHT]
patterns:
  - id: phantom_stock_baseline
    family: stock_integrity
    evidence_kind: sales_stopped
```
- **Case key.** The case key is family plus the values of `key`, taken from the event facts. It is computed only when
  every key fact is present and plain (text or a whole number). Otherwise the finding falls back to the pattern's own
  fingerprint, and a `family_key_incomplete` audit row is written. It never matches on a partial key.
- **Attach.** A matching open case gains the event as evidence, plus the lane, the evidence kind and the pattern.
  - Severity and money are raised to the maximum.
  - It re-notifies only when severity or money rose, and then only through the interrupt budget (section 2).
- **Same-day closure holds.** A case closed today for the same key stays closed. A finding of a kind listed in
  `reopen_on` that the case has not seen re-opens it and notifies. Anything else adds a note.
- **Overnight.**
  - An OVERNIGHT finding on an open or closed key marks the case `confirmed`.
  - `family.sweep_done` (facts: family, store, business_date, lane OVERNIGHT) adds the note "not seen overnight"
    to unconfirmed cases in that scope. It never notifies and never closes.
  - Each baseline detector gets an overnight confirmation rate. It is evidence for the governor's retune proposal,
    never a demotion trigger, unless the tenant maps it in explicitly (D2).
- **Restatement.** A finding for a past business date updates that date's case (evidence and money). It never opens
  a second case for the same key.
- **RACI (D1).**
  - A is exactly one slot. A owns the case, closes it and is the escalation root.
  - R works the case and may propose a closure. R may differ per pattern (`raci_override.R` on a pattern).
  - C is asked: a "consulted" entry on the case records their answer.
  - I gets the case in digests only, never an interrupt.
  - Every slot resolves through `holders()` in the case's scope (vacancy walk-up, stop list).
  - An agent may be R, never A or C.
  - Publishing is refused when A is not exactly one slot, a slot is unbound, or the patterns in a family disagree
    on the key.

### 2. Interrupt budgets (Gap 2, D3, D4)
```yaml
interrupts:
  enabled: true
  eligible: {lane: LIVE, act_within_shift: true, money_min: 5000}   # or safety: true on the pattern
  coalesce_minutes: 2
  budgets:
    - {role_slot: store_owner, per_shift: 5}
    - {role_slot: store_owner, scope: {format: hyper}, per_shift: 7}       # most specific row wins
  allocation:                                    # optional (D3); replaces per_shift with an allocated pool
    direction: top_down                          # or bottom_up
    level: region                                # top_down: the pool lives here
    pool_per_shift: 120
    key: sales_share                             # published per scope and period by the consumer
    forecast: forecast_factor
    floor: 1
    ceiling: 12
  safety: {per_shift: 3, escalate: true}         # flat, never sales-weighted
  sessions: {lease_minutes: 15}
```
- **Delivery levels.** Every case is delivered as an interrupt (pushed through the edges), a card (queue), or a
  digest. Without `interrupts.enabled`, every case keeps today's behaviour (pushed).
- **Who is on shift (D4).**
  - The consumer sends `session.start`, `session.heartbeat` and `session.end` with person, role, scope and device.
  - A session can activate only a role the person holds in the org layer for that scope and time. Anything else is
    refused and audited (`session_role_refused`).
  - Holders on shift are the people with a live session whose lease has not lapsed.
  - Shift windows come from `shifts:` per scope (`trading_days`, `windows`).
- **Spend.**
  - A budget key is (person, role, scope, shift window). It is never the session, so a re-login does not reset it.
  - Coalescing: eligible cases for one holder within `coalesce_minutes` go out as one interrupt and spend one unit.
  - A person with several devices gets one interrupt, on the latest active device.
- **Over budget.** The case becomes a card at the top of the queue, marked "would have interrupted". It is never
  dropped or delayed.
- **Safety.**
  - Safety has its own flat budget. When it is spent, the case escalates to the next holder up the tree (never past
  the stop list) and spends that holder's safety budget.
  - At the stop role with its budget spent, the case still interrupts and is audited `safety_over_budget`, so safety
  is never silent.
- **Vacancy.** Nobody on shift for the role means the case goes to the escalated holder and spends their budget.
- **Allocation (D3).**
  - **top_down:** the pool is split across children by `sales_share × forecast_factor`. Rounding uses largest
    remainder, then the floor and ceiling are applied, then the surplus or deficit is redistributed, so the children
    sum exactly to the pool unless the floors alone exceed it. In that case each child gets its floor, and the gap is
    shown in the console and audited.
  - **bottom_up:** store budgets come from per-store rows (or their key share of a base), and parents show the sum.
  - Missing or stale data (older than `max_age_hours`) keeps the last good allocation and opens a data-trust case. It
    never falls to zero.
- **Reporting.** Per role, scope and shift: interrupts sent, budget used, "would have interrupted", and the action
  rate on interrupts. The figures appear in the owner report and on the console's Agents and oversight page.

### 3. Alert-fatigue governor (Gap 3, D2)
```yaml
governor:
  useful: [ACTED]
  not_useful: [NO_ACTION, DUPLICATE, DATA_ERROR, FALSE_POSITIVE]
  window_days: 28
  min_closures: 20
  warn: 0.5
  demote: 0.7
  cool_off_days: 14
  pool_min: 20                  # store rates pool upward until a store has its own minimum (like trust)
```
- **Measure.**
  - Per detector (pattern × scope, pooled as trust is), over the rolling window: the not-useful rate and the median
    time to close.
  - Closures without a mapped code count in neither bucket and are reported as `unmapped`.
- **Warn.** A retune proposal goes to the template's oversight role, with evidence (dispositions, a sample of cases,
  and the overnight confirmation rate). It is never automatic.
- **Demote.**
  - The detector's delivery level drops one step (interrupt → card → digest). The change is governed:
    - recorded as a config change by `governor`;
    - shown in the console;
    - reversible by oversight.
  - It never touches the autonomy route or agent mode.
  - It never disables a detector. Safety patterns never go below card; they are only flagged.
- **Recovery.** A full window below warn makes a restore proposal. Restoring needs a person.
- **Cool-off.** After oversight reverses a demotion, the governor does not demote that detector again for
  `cool_off_days`.

## Attack table (planned rules; "As built" will confirm each cell)

Each row is an object that carries authority. The columns are the ways it could be changed or misread.

| Object | Insert | Update | Delete | Other tenant or store | Clock | Concurrency |
|---|---|---|---|---|---|---|
| Family case (key) | Only from a finding with a full, plain key | Severity and money only rise. Lanes, kinds and evidence are append-only | Never (closing is a state) | The key includes tenant; families never merge | business_date comes from the event facts, never the clock | Lock on the family key: two lanes at once give one case |
| Same-day closure | Set by A's close | A reopen only by a new kind in `reopen_on` | Never | As above | "Same day" is the key's business_date | Same lock |
| Sweep note | Only from `family.sweep_done` for exactly that scope and date | Append-only | Never | Its scope must match the case key | Event time | Idempotent per (family, scope, date) |
| RACI binding | Publish only | Publish only (versioned config) | n/a | Slots resolve in the case scope | `holders(at=)` uses the engine clock | Read at delivery time |
| Session | Only a role the person holds in scope, now | Heartbeat extends the lease; role, person and scope are fixed | `session.end`, or the lease lapses | Scope must be within the person's assignment | Lease uses the engine clock; future heartbeats refused | One live session per person per device; a person counts once |
| Budget spend | One unit per delivered interrupt (coalesced) | Never decremented back | Resets only at the shift boundary | Key includes scope | Shift window from `shifts:` plus the engine clock | Atomic check-and-spend under the budget key lock |
| Allocation | Computed from published share and forecast | Recomputed per period; the last good one kept | n/a | Share must be for the child's own scope | Period from the engine clock; stale beyond max age | Children always sum to the pool (or each sits at its floor, with the gap reported) |
| Safety budget | Flat | As budget spend | As budget spend | As budget spend | As budget spend | Escalates and spends upward; never silent |
| Governor demotion | Only at ≥ demote with ≥ min closures in the window | Reversal by oversight only | n/a | Pooled like trust | Window from the engine clock; cool-off | One change per detector per evaluation (lock) |
| Disposition code | Only from closures | Write-once | Never | n/a | n/a | n/a |

**Who satisfies each new refusal** (the second "One tester pass" rule):

| Refusal | Satisfied by | Why the contract lets them |
|---|---|---|
| A finding without a full plain key never joins a family | The consumer sets the key facts on every event (`lane` and the key facts) | Event facts are free-form |
| Only one A per family | The pack author | The family YAML; refused at publish time |
| A session refused for a role the person doesn't hold | The org sync (people configuration) | Assignments are already published |
| A sweep note only from `sweep_done` | The overnight job | A plain event with four facts |
| Allocation needs share and forecast | The consumer's people-configuration export | New optional keys; fallback is the last good allocation |
| Demotion only with mapped codes | The tenant's `governor.useful` / `not_useful` | Tenant configuration |

## Consequences
- The consumer must send `lane`, the key facts, the session events and `sweep_done`, and must publish `shifts:`,
  `sales_share` and `forecast_factor`. Without them, the features stay off or fall back. They never fail closed on
  people.
- The independent tester's journeys come from the acceptance cases in the request (16 in total) plus the attack
  table.
- v0.26.0 adds the daily money cap and holdout (`holdout_allowed` per template; never for safety).
