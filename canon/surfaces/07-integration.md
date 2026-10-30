# Surface 7 — Integration (code mapping, outbox, and the environment gate)

**Wave 3.** Depends on Config (per-tenant connector settings) and Tenancy.

## Purpose

Every business application eventually talks to a system of record it does not own — an ERP, a
gateway, a government portal. Three things go wrong every time, and this surface exists to make
each of them impossible rather than unlikely:

1. Our codes are not their codes, and someone "fixes" it with a lookup buried in a service.
2. A write fails at 2am and nobody knows whether it happened.
3. **A development environment writes to the client's production system.**

## The contract

### Code mapping
1. **One place maps our key to their code**, per dimension (material, customer, plant, GL account,
   unit, …). One editor, one table, one audit. A mapping in application code is a defect.
2. **The dimension list is a closed contract** — it changes only when the interface does — so it is
   enforced by a database constraint, not by convention.
3. **An unmapped key REFUSES the push and names the gap.** It does not pass our code through hoping
   the far side is lenient, and it does not silently drop the line. The document surfaces which key
   is missing.
4. **Mappings are versioned and NEVER retroactive.** Changing a mapping must not silently re-write
   what was already sent, or reconciliation against the far side becomes impossible.
5. **Some outbound shapes need EXPLOSION** — one of our lines becomes several of theirs (a revenue
   line split across accounts). Explosion is all-or-nothing: a partial explosion is refused, because
   half a split posts an unbalanced document.

### Outbox
6. **Nothing calls an external system from a request handler.** Writes go to an outbox; a dispatcher
   drains it. This is what makes retries, ordering, and "did it happen" answerable.
7. **Idempotent on a natural source key**, so a retry re-drives the same row rather than creating a
   second document at the far side.
8. **States are explicit**: queued · in-flight · confirmed · **held** · failed. Held is not failed —
   it is "deliberately not sent", and the reason is recorded.
9. **The dispatcher is scheduled and observable.** An outbox with no drainer accumulates silently;
   this happened here. Every run writes a job record on success *and* failure.

### ⛔ The environment gate — the one that protects the client
10. **A single, global `integration_mode` decides whether anything actually leaves.** Not per
    connector, not per caller: one gate, checked at the single point where a push becomes a real
    call.
11. **Non-production HOLDS rather than pretends.** Held documents are real rows in a real state that
    can be inspected, counted, and released — not swallowed, and not faked with a stub that returns
    success. A stub that returns success is how a false green reaches production.
12. **The gate is provable three independent ways**: the config says held, the outbox rows say held,
    and no outbound call is recorded. Assert all three; any one alone can be wrong.

## Beyond the minimum: the multi-consumer relay

The outbox above is the **minimum**: one dispatcher, one far side, six states (queued, in-flight,
confirmed, held, failed, dead-letter). `bases/core/outbox.py` is that minimum. Some products must
fan one event out to several consumers, each at its own pace and with its own failures. That needs
four things the minimum does not have, and a product that adds them should add *these*, not invent
its own:

1. **Six outcomes, not two.** A delivery attempt ends in exactly one of: `APPLIED`, `ALREADY_APPLIED`
   (the far side had it: success, not an error), `RETRY`, `REFUSED_PERMANENT` (stop now, dead-letter),
   `TRANSPORT_ERROR` and `INFRA_HOLD` (our side is not allowed or able to send: wait, do not blame the
   delivery). The mapping to attempts is part of the contract: `RETRY` and `TRANSPORT_ERROR` count
   against the maximum; `APPLIED` and `ALREADY_APPLIED` finish; `REFUSED_PERMANENT` fails at once;
   **`INFRA_HOLD` is never counted.**
2. **Per-consumer delivery state.** One delivery row per (event, consumer), with its own state
   (pending, in-flight, done, failed, abandoned), attempts and next-attempt time. One slow consumer
   must not hold up or mark failed another consumer's copy of the same event.
3. **Leases with a fence.** A worker claims a delivery for a bounded time. The result is accepted only
   if the claim is still the live one: a counter that rises on **every** claim (not the attempt
   number, which a release leaves unchanged) is the fence, so a stale worker that reuses a worker id
   cannot overwrite a newer result. A lost claim counts as an attempt only if the call had started.
4. **Ordering.** A delivery is claimable only when no earlier event of the same aggregate has an
   unfinished delivery for that consumer. Without it, a late "cancelled" can overtake an early
   "created".

Dead letters follow the same discipline as the minimum, with one addition: **a committed money, stock
or approval fact can be replayed but never discarded**, and the list of committed types is
insert-only for every role. An empty list fails closed: nothing is then discardable.

## Schema shape

```
code_mapping        company_id · dimension · hub_key · context_key · sap_value · transform
                    · valid_from/to · is_active · version · supersedes_id · superseded_at/by
                    · provenance (jsonb) · note · created_by
                    ↳ dimension is CHECK-constrained; provenance records HOW the mapping was
                      derived (which rule, what evidence, what it agreed with)

outbox              company_id · topic · source_key · payload (jsonb) · state · attempts
                    · last_error · held_reason · created_at · dispatched_at · confirmed_at
                    ↳ UNIQUE (topic, source_key)  — idempotency

integration_mode    global setting: production | uat | dev
job_run             job_name · started/finished · status · rows · summary · detail (jsonb)
```

## Doctrines that bind here

**D1** unmapped refuses · **D2** mappings supersede, never update · **D3** outbox idempotency by
source key · **D5** connector config is data · **D7** never a swallowed error.

## Mapping provenance is not optional

When a mapping is *derived* rather than supplied — matched by name, inferred from transactions — the
row must record which rule fired, what evidence supported it, and what corroborated it. Two reasons.
First, a human must be able to check it. Second, when a derivation later proves wrong, you need to
find every row that rule produced. In this programme a derived mapping was wrong exactly once
(a route assigned to the wrong sales group on 96 lines), and provenance is what made it findable and
retractable rather than permanent.

Give derivation rules a **minimum evidence floor** — a share is meaningless without a denominator —
and a **retraction path**: a mapping the job no longer stands behind is closed on the next run.

## Gate tests

1. **An unmapped key refuses and names itself.** Push a document with an unmapped material; assert
   refusal, and that the response names the dimension and the key.
2. **Explosion is all-or-nothing.** Configure a split where one target is missing; assert the whole
   document refuses rather than posting a partial.
3. **A mapping change is not retroactive.** Send a document, change the mapping, re-read the sent
   document; assert it still shows what was actually sent.
4. **Retry re-drives the same row.** Fail a push, retry; assert one outbox row with attempts=2 —
   not two rows.
5. **⛔ The gate holds, proven three ways.** With mode ≠ production: assert (a) the resolved mode,
   (b) every relevant outbox row in `held`, and (c) that no outbound call was made. Then flip the
   mode in config alone and assert the state changes — proving the gate is live and not merely
   defaulting.
6. **The dispatcher is actually scheduled.** Assert a schedule exists *and* that a run record was
   written recently. A comment describing a schedule is not a schedule — a timer that had never
   fired sat beside such a comment in this programme.
7. **Failures are loud.** Force a far-side error; assert a non-zero result and a recorded failure —
   never a swallowed response.
8. **The first enqueue of a new (topic, source_key) produces exactly one row.** Enqueue once into an
   empty outbox; assert exactly one row exists, not zero and not two. Enqueue the same key again;
   assert the same row, still one. This catches a calling-convention bug that every other gate misses:
   a synchronous caller meeting an asynchronous store sees an un-awaited lookup, which is always
   truthy, so the "row already exists" branch runs on the very first enqueue and nothing is written.
   The outbox looks healthy, the retry gate (4) has nothing to retry, and only a count of rows shows it.
9. **A held row consumes no attempt.** With mode ≠ production, run the dispatcher repeatedly; assert
   every row stays held with `attempts = 0` and can still be re-driven. Flip the mode; assert the same
   rows send, and that `attempts` counts only real calls. (For a relay, the same rule is the
   `INFRA_HOLD` outcome: it stays pending and is never counted.)

## Divergence register

| What | Why | Cost |
|---|---|---|
| _Conforms._ The environment gate is proven three independent ways; unmapped codes refuse and name the gap; mappings are versioned with provenance and a retraction path; the outbox is idempotent on a source key; the state machine is the canon base, vendored. 83/83. | | |
| The dispatcher's state machine is **vendored from `bases/core`**, not re-derived — and the base learned the held-does-not-consume-an-attempt rule *from this project*. | | |
| **Three outbox designs exist in the programme, deliberately not merged into a fourth.** (1) `bases/core/outbox.py`: the minimum, one consumer, outbound. (2) A multi-consumer **relay**: per-consumer deliveries, six outcomes, leases with a fence, per-aggregate ordering (section above). (3) An **inbound hub** for a retail estate: a message envelope with an idempotency table keyed on tenant, source system and change id; statuses accepted / processed / rejected / dead / quarantined; a dead-letter queue (open, replaying, replayed, discarded) where a discard needs a recorded approval and a committed-fact type can never be discarded. | They solve different problems: one outbound consumer; fan-out with ordering; inbound receipt with controls. Each was built under real pressure before the canon said what the shared part is. | Three vocabularies for "stuck": held / INFRA_HOLD / quarantined, and failed / dead_letter / DEAD. A reader must know which design they are in. This spec fixes the shared rules (gates 4, 8, 9, the environment gate, the committed-fact rule); it does not claim the three share code. Do not write a fourth. |
