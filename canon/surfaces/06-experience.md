# Surface 6 — Experience patterns

**Wave 2.** Cheap to establish early, brutally expensive to retrofit across forty screens.

## Purpose

> *"Even the UI/UX should be similar across the projects going forward. I don't want to reinvent
> every time."* — the product owner, 2026-08-16

This surface is the **visual and behavioural language**, not a component library. Components are
downstream of it. The point is that no project re-argues what an empty state looks like, what a
denied button does, or what happens when a table has 40,000 rows.

## The contract

### The data table
Every list in every app behaves identically:
1. **Server-side sort, filter and page — over the WHOLE matched set, always ranked before limited.**
   Limiting first is a real bug: the highest-priority row silently vanishes at scale.
2. **Column set is per user and persists.** Chosen once, remembered.
3. **Every table exports**, and the export carries provenance (below).
4. **Row density is a setting, not a redesign.** Floor staff and analysts need different densities
   of the same table.

### The eight states people forget
A screen is not done until all eight are designed. Most software ships two.
| State | What it must do |
|---|---|
| **Loading** | Skeleton in the shape of the content, not a spinner over a blank page |
| **Empty — never had data** | Explain what would put data here, and offer the action that does |
| **Empty — filtered to nothing** | Say which filter caused it, and offer to clear that one |
| **Denied** | **Visible, disabled, with the reason and who can do it.** Never hidden |
| **Partial failure** | Show what loaded and name what did not. Never fail the whole page for one widget |
| **Stale / offline** | State when the data is from, and that it may have moved |
| **Too much** | Above a threshold, insist on a filter rather than rendering 40,000 rows |
| **Error** | What happened, what to do, and a reference that support can trace |

### Export and print
5. **Every export carries a provenance sheet**: source, filters applied, generated-at, generated-by,
   row count, and the version of the calculation. An exported number that cannot be traced back is a
   number that will be argued about in a meeting and lose.
6. **Print produces operational artifacts, not screenshots.** A gate pass, a receipt, a day-close
   statement — designed for the paper it lands on, stored as a document, reprints labelled.

### Offline and conflict
7. **Local-first where the user may be offline.** Queue writes, show queue depth **persistently and
   never hidden**, retry with backoff.
8. **Idempotency by client-minted id** (D3) so a flush cannot duplicate.
9. **Conflicts are surfaced to a human with both versions**, never auto-merged on financial data.

### Access and language
10. **Denied is visible with its reason** — stated again here because it is the single most-violated
    rule in this list, and it belongs to Experience as much as to RBAC.
11. **Language is a user setting**, and the floor layer may need a different language from the
    office layer in the same deployment.

### The floor layer is a different persona, same bar
12. Mobile-first, one-handed, possibly outdoors, possibly raining, with someone waiting. **Minimum
    44px targets, no horizontal scrolling, no modal that can trap the user offline, and every screen
    usable without a network.** A click budget of ≤2 to the primary action.

## Doctrines that bind here

**D7** a control that reports falsely either way is worse than none — including UI: a
green "synced" that lies is worse than no indicator · **D8** held ≠ blocked · **D3** idempotency.

## The verification trap

Frontend "it compiles" checks lie. In this programme, the type-check command that *appeared* to pass
was not actually rebuilding. Use the build command that forces a full rebuild
(`tsc -b --force`, not `--noEmit`), and prove a served bundle is current by asserting it contains
something that did not exist before (D6).

## Gate tests

1. **Rank before limit.** Seed more rows than a page; assert the top-ranked row is on page 1 even
   when its natural sort order would place it last.
2. **All eight states render.** One test per state, asserting the *specific* copy — especially that
   denied shows a reason and names who can act.
3. **Export carries provenance.** Export a filtered view; assert the provenance sheet records the
   filters that were actually applied, not the defaults.
4. **A stored artifact is re-served, not re-rendered** (see Documents §3).
5. **Offline flush is idempotent.** Queue captures, go offline, flush three times; assert identical
   counts each time.
6. **The sync indicator cannot lie.** Force a failed flush; assert the indicator shows queued depth
   and does not report synced.
7. **Floor targets meet the minimum.** Assert interactive elements on floor screens meet the 44px
   minimum — a lint or a rendered measurement, not a reviewer's eye.

## Divergence register

| What | Why | Cost |
|---|---|---|
| ⛔ **"Pricing is central" is violated.** The field bill accepts a client-supplied `unit_price`; the pricing engine reads a table with 0 rows and no field path calls it. | Historical: capture was built before the pricing model was settled. | Every downstream number — scheme, discount, tax, margin, incentive — inherits whatever the client sent. **Open and unresolved.** |
| The eight states are **not all distinctly implemented** — a shared `DataState` covers loading/empty/error; denied-with-reason, partial-failure, stale and too-much are not consistently present. | Screens predate the contract. | Denied actions are hidden rather than explained on the older screens. |
| _Conforms on_ — server-side rank-before-page (a real bug fixed), offline idempotency by client-minted id, a sync indicator that cannot report synced with a queue. | | |
