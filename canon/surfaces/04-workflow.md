# Surface 4 — Workflow and the work queue

**Wave 2.** Depends on RBAC (who may decide) and Tenancy (whose work it is).

## Purpose

Two things that are usually built separately and should not be: **routing a decision to whoever
should make it**, and **presenting a person with everything waiting on them**. Built apart, you get
an approval engine nobody looks at and five "pending" screens that disagree.

The rule that follows from that: **the queue IS the application.** A role's landing screen is its
work queue. Not a dashboard with a queue widget — the queue.

## The contract

### Routing
1. **Applications raise work; they do not know who does it.** The caller names *what* happened and
   *where* (object, value, org unit, route). Which rung, which position, and when it is due are
   read from configuration. A caller that names an approver has hardcoded the org chart.
2. **Route to a position, never a person** (D9). Resolve the person at decision time.
3. **Thresholds walk the org chart.** An approval matrix maps (decision type × value band × org
   level) to the position that decides. Raising an approval limit is a data change.
4. **An unassigned position routes to its parent.** Work never falls into a hole because a seat is
   empty; it escalates and says that it did.
5. **Escalation is time-based and produces a record.** A breach is an event with the elapsed time
   and the position that missed it — not a red flag on a screen that vanishes when someone opens it.
6. **Skip-level and delegated decisions are legal and are LABELLED.** The audit records the bypassed
   level, or the acted-for identity. Making them illegal only produces workarounds outside the
   system.

### The queue
7. **One queue, one component, many mount points.** Every app renders the same queue; scope comes
   from the API's answer, not from a prop the screen passes. A screen that can ask for a wider scope
   than its user is entitled to is an authorisation bug waiting to be written.
8. **Sorted by RISK, not arrival.** Oldest-first is the wrong order for a queue that matters. Rank
   by a stated formula combining escalation, overdue time, value and age — and **echo the formula on
   screen from the same constant the server sorts by**, so a supervisor can see why an item is top.
9. **Sort and filter over the WHOLE matched set, then page.** Limiting before ranking means a
   high-risk item with a distant due date silently disappears at scale. This is a real bug that
   shipped in this programme and was caught by a gate.
10. **Available actions come from the same authority function as the write path** — a disabled
    button and a 403 can never disagree (see RBAC §3).
11. **An item outlives the object that raised it.** Deleting a source row must not orphan a live
    queue entry; teardown *closes* items, it does not delete them. The audit trail is append-only
    and therefore undeletable, which is correct and must be designed for.

## Schema shape

```
workflow_definition   key · name · version · steps (jsonb)
workflow_instance     definition_key · object_type · object_ref · state · company_id
workflow_event        instance_id · step · actor · decision · reason · acted_for
                      · bypassed_level · at            ← APPEND-ONLY (trigger-enforced)
approval_matrix       decision_type · org_level · value_from · value_to · position_code · sla_hours
work_item             company_id · item_type · object_type · object_ref · status · risk_score
                      · due_at · route_id · org_unit_id · value_amount · flags[] · raised_by
work_item_event       work_item_id · event · actor · reason · at    ← APPEND-ONLY
```

## Doctrines that bind here

**D9** route to a position · **D2** append-only audit · **D8** held ≠ blocked · **D5** matrix and
SLAs are data · **D1** an unrouteable decision refuses rather than auto-approving.

## Gate tests

1. **The caller cannot name the approver.** Assert `raise_item` accepts no approver argument, and
   that changing the approval matrix alone re-routes an identical call.
2. **Threshold walks the chart.** Raise an item below a band and above it; assert two different
   positions receive it, with no code change between the two runs.
3. **An empty seat escalates.** Vacate a position; raise work for it; assert the parent receives it
   *and* that the item states why.
4. **SLA breach produces an event.** Advance time past the SLA; assert a breach event exists naming
   the elapsed time and the position — and that it persists after someone views the queue.
5. **Risk sort is server-side and over the whole set.** Seed more items than one page; assert the
   top item by risk appears on page 1 even when its due date would place it last by arrival. Then
   **change one input twice** (raise a value, then set an escalation) and assert the order moved
   both times.
6. **The formula on screen matches the sort.** Assert the displayed explanation derives from the
   same constant the server ranks by — not a re-implementation.
7. **Actions and permissions agree.** For an item the user may not action, assert the availability
   response is disabled-with-reason and the write endpoint 403s with the same reason.
8. **Skip-level is recorded.** Approve past a level; assert the audit names the bypassed level.
9. **Deleting the source object does not corrupt the queue.** Delete a raising object; assert the
   item survives, renders honestly, and can be closed.

## Divergence register

| What | Why | Cost |
|---|---|---|
| `work_item` / `work_item_event` hold **0 rows** | Nothing live raises work yet; the pilot has not run. | The queue's behaviour under real volume — the risk sort in particular — is proven only by fixtures. |
| _Conforms on_ — callers raise without naming an approver, matrix-driven routing (19 rows), risk sort over the whole matched set before paging, availability sharing the write path's authority function, append-only audit. | | |
