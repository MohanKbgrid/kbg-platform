# KBG Platform Surfaces — the canon

**What this is.** Nine cross-cutting surfaces that every business application KBG builds needs, and
keeps rebuilding badly. Each has a spec here: what it must *do*, what shape its data takes, the
doctrines that make it trustworthy, and the acceptance gates that prove it works. They are written
stack-agnostically. The reference implementation is a production Python/FastAPI + React + Postgres platform, where
every gate below was actually run and passed.

**The thesis:**
> With Claude Code as the engineering team, **code is cheap to port but expensive to trust.**
> The global asset is the **CONTRACT**, not the library.

That is not a preference, it is an observation from this programme. The GL shape has already crossed between two unrelated products successfully, and it crossed as
*schema + contract*, not as code. An agent handed a
contract and a gate will produce something correct for its own codebase. An agent handed a library
will produce something that compiles and hides a semantic mismatch you find in production.

So: read the spec, build against the contract, **run the gate**. Copy code only where it is faster,
never because it is authoritative.

---

## The nine surfaces, in coupling order

**Adopt in this order.** It is not arbitrary — each wave depends on the one before it, and the last
wave depends on decisions the first three force you to make.

| Wave | # | Surface | Why here |
|---|---|---|---|
| **1 — identity & config** | 1 | [Tenancy](surfaces/01-tenancy.md) | Everything else stamps a tenant. Retrofitting it later means touching every table. |
| | 2 | [Config](surfaces/02-config.md) | Credentials and per-tenant settings; RBAC and Integration both read it. |
| | 3 | [RBAC](surfaces/03-rbac.md) | Every write is authorised. Deny-by-default only works if it is there from the first endpoint. |
| **2 — work & evidence** | 4 | [Workflow](surfaces/04-workflow.md) | Routing, approval, escalation, and the queue that *is* the application. |
| | 5 | [Documents](surfaces/05-documents.md) | Required-evidence blocking; workflow steps depend on it. |
| | 6 | [Experience](surfaces/06-experience.md) | The data-table contract, the 8 states, export and print. Cheap early, expensive to retrofit across 40 screens. |
| **3 — the outside world** | 7 | [Integration](surfaces/07-integration.md) | Code mapping, outbox, and the gate that stops a dev box writing to production. |
| | 8 | [Runtime AI](surfaces/08-runtime-ai.md) | Grounded-or-nothing drafting. Needs Documents + Workflow to have somewhere to land. |
| **4 — money, last** | 9 | [Accounting](surfaces/09-accounting.md) | **Deliberately last.** Money semantics want the doctrine decided before any adapter exists, and every surface above it is an input. |

Plus one seam, not a surface: [CRM](surfaces/10-crm-seam.md) — build the boundary now, extract when
the trigger fires.

## How the code travels: **vendor the base, propagate the GATE**

Decided 2026-08-17. There are two reference bases —
[`bases/core`](../bases/core) (primitives) and [`bases/ui-kit`](../bases/ui-kit)
(visual language), both in this repo. **They are bases, not
dependencies.** A project copies one in, owns its copy, and changes it freely. Divergence is
expected and is not propagated back.

That is deliberate, and it follows from the thesis above. A shared library spanning unrelated
products becomes either a lowest-common-denominator that fits none, or a "shared" package carrying
per-project branches — worse than honest copies. Accounting settles it: one product's control
accounts come from a reference finance function, another's from a hospital. No abstraction usefully
covers both.

**What travels instead is this canon: the contracts, and the GATE TESTS.** When a bug in one
project reveals a missing *rule*, the rule goes into that surface's spec and its gate list. Every
project then inherits the *test* while keeping its own implementation. That is what stops the same
bug being rediscovered four times without re-coupling four codebases.

### The line, restated precisely (the product owner 2026-08-17)

> *"UI/UX, Integration and Accounting should only exist as common implementation PATTERNS — the
> implementation itself will be project or tenant specific."*

Correct, and it is the sharpest statement of what this canon is for. **The contract is common; the
binding is project- and tenant-specific.**

| Surface | Common — the pattern | Project / TENANT specific |
|---|---|---|
| Accounting | control accounts + dimensional sub-ledgers · validate before mutate · corrections are new documents · the four SAP-class items | chart of accounts, the dimension list, every posting adapter, GL codes, period policy |
| Integration | outbox keyed by a source id · the environment gate · an unmapped code REFUSES · mappings supersede | connectors, which dimensions exist, interface contracts, the code values themselves |
| UI/UX | the eight states · the table contract · the token ROLES · denied-visible-with-reason | markup, palette values, density, language, layout |

**Tenant, not only project** — Tenancy §1 already says companies are standalone, with different
modules and unique reports. So accounting differs *within* one product between two companies, and a
white-labelled tenant may want its own palette. The Config surface is what carries that; it is not
a fourth mechanism.

⚠️ **A CORRECTION to earlier guidance in this file.** It previously said to keep `tokens.css` in
sync across projects, to protect a "one product family" look. That was wrong under the rule above:
a token sheet *is* an implementation — specific hex values — and different products for different
businesses should not be forced onto one palette. What must not diverge is the **token ROLE
VOCABULARY**: every product defines `--kbg-accent`, `--kbg-ink`, `--kbg-line`, four semantic
colours held separate from the accent, and `--kbg-touch-min`. That vocabulary is what makes a
component portable between products. The values behind it are the product's own.

**Consequence for the two package repos:** encoding a pattern as code is legitimate only where the
pattern is small and genuinely domain-free — `Gap`, `Decision`, `decide()`, the versioned write.
The moment something must know what a control account *is*, or what a connector talks to, it stops
being encodable and becomes a spec.

## Adoption

- **[Greenfield](adoption/greenfield.md)** — a new product, born on the canon. Day-one commit
  already carries tenancy, config, RBAC, workflow, documents, and accounting.
- **[Retrofit](adoption/retrofit.md)** — an existing codebase, surface by surface, without a
  big-bang rewrite. Worked example available on request.

---

## The doctrines

These are cross-surface. They are what make the surfaces trustworthy rather than merely present,
and **every one of them exists because something went wrong in this programme.** They are not
style; violating one produces a specific, observed class of bug.

### D1 — Deny by default
An unlisted permission is denied, not allowed. An unmapped code refuses rather than passing through.
An unconfigured threshold refuses rather than defaulting. Allow-lists shrink safely; deny-lists rot.

### D2 — Append-only on anything financial or evidentiary
There is **no update-in-place** on a posted document, an audit event, or a mapping. A correction is
a new dated record referencing the original. This is what makes an audit trail an audit trail rather
than a table someone can quietly fix.

### D3 — Idempotency by SOURCE id, not by server id
The client mints the id (a UUID from the device, an external system's document number) and it
becomes the primary key. A re-sent capture then collides instead of duplicating — double-insert is
impossible *by construction* rather than by a de-dup pass that someone has to remember to run.

### D4 — Missing data is a FINDING, never a licence to invent
No default shelf life, no assumed price, no "probably 2 days". A surface that cannot answer returns
a named gap with the reason. **A fabricated number that reads correctly is the most expensive kind
of bug, because nobody questions it.** In this programme, seeded synthetic rows once overstated a
month by +45% volume / +74% value before anyone noticed.

### D5 — Config is data, not code
Every threshold, window, tolerance and toggle is a row someone can change without a deploy. If a
business owner would ever plausibly ask "can we make that 300 instead of 200", it is data. And the
gate must **prove the control controls**: change the input, assert the output changed.

### D6 — Prove newness, not liveness
A restart proves itself by an *advanced* timestamp, not by reporting `active`. A deploy proves
itself by serving something that did not exist before. `systemctl enable --now` is a no-op on an
already-running unit and will happily print success over stale code.

### D7 — A control that can report a false result is worse than no control
Both directions. A check that can go green while broken trains people to trust nothing; a check
that can go **red while healthy** burns the time it was meant to save. Verify against the
authoritative state (the catalog, the schema, the ledger), never by inferring from behaviour that
may never be exercised.

### D8 — Held ≠ blocked
Review happens *behind* the user, not in front of them. Capture always succeeds; a flagged document
does not stop the person at the counter. Hard blocks are reserved for the few cases where
proceeding is genuinely unsafe (credit limit, physical stock) and each one is named.

### D9 — Route to a POSITION, never to a person
Approvals, escalations and queues address an org position. People change jobs, go on leave, and
leave the company; a workflow bound to a person's login silently stops routing. The person is
resolved from the position at decision time and recorded on the audit event.

### D10 — Timestamps are capture time, not sync time
A document posts to the day it *happened*. A late sync must never move a transaction into the wrong
period — that is an accounting error introduced by a network outage.

### D11 — One engine, channel-resolved input
When two channels need different rules, vary the *data* they read, not the code that reads it.
Two pricing engines will diverge; one engine reading two price books cannot.

### D12 — State the denominator
Any comparison — price vs price, actual vs target, our number vs theirs — must state the unit and
grain of both sides, or it is not a comparison. This programme twice produced a confident finding
from a mixed-unit denominator, and both times the "discrepancy" was an artefact.

---

## The seven questions to ask of any new requirement

Before building anything, answer these. If you cannot, the requirement is not ready.

1. **Who is allowed to do it, and what happens to someone who is not?** (RBAC — and "the button is
   hidden" is not an answer; a denied action must be *visible with its reason*.)
2. **What does it post, and against which control account and dimensions?** (Accounting)
3. **What evidence must exist before it can complete?** (Documents)
4. **Who approves it, at what threshold, and who does it escalate to?** (Workflow)
5. **What does it send outward, and what stops that in a non-production environment?** (Integration)
6. **What does it look like when there is no data, when it is loading, when it is denied, and when
   it partially failed?** (Experience — the states people forget)
7. **Which tenant owns the row?** (Tenancy)

## Signals the platform is being bypassed

Treat each as a defect, not a shortcut:

- A screen computing its own price, tax, or total instead of asking the engine.
- A second inbox, worklist, or "pending items" table beside the work queue.
- A boolean `is_approved` column on a domain table instead of a workflow instance.
- A role name in an `if` statement.
- An external call made directly from a request handler rather than through the outbox.
- A financial correction done with `UPDATE`.
- A new table without a tenant column.

## Divergence register

A project **may** diverge from a spec. It may not diverge *silently*. Each surface spec ends with a
divergence register: what the project does differently, why, and what it costs. An empty register
means "we follow the canon", and that claim should be true.

## When this canon is wrong

It is derived from one programme's experience. Where a spec conflicts with a real business
requirement, **the business wins** — and that conflict is a defect in the spec, to be fixed here so
the next project inherits the correction. Raise it; do not work around it privately.
