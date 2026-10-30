# Surface 8 — Runtime AI

**Wave 3.** Needs Documents (something to read) and Workflow (somewhere for a draft to land).

## Purpose

AI inside a business application earns its place in exactly one way: **turning something a human
would have to key into something a human only has to check.** Everything else is a demo.

The whole surface therefore reduces to one mechanism — the **grounded draft** — and one
non-negotiable boundary: a draft never becomes a posted document without a named human.

## The contract

1. **Grounded or nothing.** A draft may only assert what is present in its source — a document, an
   image, a record. If the source does not contain a field, the draft leaves it empty and says so.
   It must never fill a gap from world knowledge, and it must never round, tidy, or "correct" a
   value it read. **This is D4 applied to a model, and it is the difference between a useful surface
   and a liability.**
2. **Confidence per field, not per document.** A human checking a draft needs to know *which* field
   to look at. A single document-level score sends them to read everything, which is what they were
   doing before.
3. **A draft is a DRAFT.** It lands in the work queue as something to accept, edit, or reject. There
   is **no code path from draft to posted document that does not pass through a named human**, and
   this is asserted by a test that looks for one.
4. **The human's decision is recorded against the draft**: accepted as-is, edited (with the diff),
   or rejected (with a reason). This is the training signal *and* the audit.
5. **Acceptance rate is measured and visible.** A capability whose drafts are always edited is not
   saving anyone time; the dashboard must be able to say so, per capability, so a bad one can be
   switched off.
6. **Capabilities are configured, not compiled.** Which capability is enabled, its provider, its
   model, its prompt version, and its minimum acceptance rate are config rows.
7. **The provider is labelled, including when it is a stub.** A stubbed provider must announce
   itself in the response (`stub: true`) — an unlabelled stub returning plausible output is the
   purest form of false green.
8. **Every invocation is recorded**: capability, input reference, provider, model, tokens, latency,
   outcome. Cost and quality both become answerable.
9. **Nothing is sent outward that the tenant has not consented to.** Which fields leave, to which
   provider, is per-tenant config — and the environment gate (Integration §10) applies here too.

## Schema shape

```
ai_capability_config  company_id · capability_key · provider · model · prompt_version
                      · is_enabled · min_acceptance_rate · config (jsonb)
ai_draft              company_id · capability_key · object_type · object_ref
                      · source_document_id · fields (jsonb: value + confidence + source_span)
                      · state (draft|accepted|edited|rejected|expired) · expires_at
ai_draft_event        draft_id · actor · decision · field_diffs (jsonb) · reason · at
ai_invocation         capability_key · provider · model · tokens_in/out · latency_ms
                      · outcome · stub (bool) · at
```

## Four layers, kept apart

An agentic system mixes four jobs that must be separable, or each new domain copies and re-cuts the
mix, and the size of the organisation starts to drive the code. Keep them as four layers with
contracts between them. (Worked in Sentinel; `sentinel/docs/adr/ADR-003`. The split is a **logical**
boundary inside one product, not four deployables: both halves run on one spine of events and
cases, and splitting the deployment would duplicate the case engine.)

| Layer | Job | Generic part | A domain or tenant supplies |
|---|---|---|---|
| **A. Business monitoring** | Sense the business | Sources, schedules, monitors, data checks | Detector queries, metrics, thresholds |
| **B. Agent functionality** | Decide and propose | Case engine, routing, playbooks, learning, idempotent execution | Templates with **role slots** (D9) |
| **C1. Org and assignment** | Who holds which role, where, when | Role tree, scopes, time-bound assignments, vacancy and escalation | The people and the bindings |
| **C2. Authority and policy** | What a role may do without an approver | Policy engine: most-specific row wins, hard rows, segregation of duties, the ceiling rule | The vocabulary of limits |
| **D. Agent oversight** | Watch the agents | Agreement, reversals, outcome checks, cost, drift, the stop switch | Nothing: it reports to people |

**Contracts between layers.** A feeds B with canonical events. B asks C1 who holds a role slot in a
scope today, and escalates a vacancy up the tree. B acts through the domain's own core by asking
`authorise(actor, action, object, scope, amount)`; this is the RBAC surface's decision function (see
Surface 3), not a second one. Every proposal, decision, execution and outcome goes to D, and D may
stop, demote or cap an agent.

**Two rules that make the split safe.**
- **The watched must not hold its own keys.** Enforcement lives in each domain's core, which calls
  `authorise()` on every agent-triggerable write. The agent framework asks; the core decides.
- **Derive the tree, never the authority.** Reporting lines can be derived from history. Authority
  cannot: deriving it from observed approvals would turn today's out-of-policy approvals into
  tomorrow's policy.

## Doctrines that bind here

**D4** missing data is a finding — a model may not invent · **D8** a draft never blocks capture ·
**D1** a disabled capability is absent, not silently bypassed · **D7** a stub must be labelled.

## Where it earns its place — and where it does not

**Earns it:** reading a supplier invoice into line items; extracting a meter reading from a photo;
turning a handwritten collection sheet into rows; summarising a long free-text note into a reason
code from the fixed list.

**Does not:** deciding an approval; setting a price; choosing an account to post to; anything where
being wrong is expensive and being right is unverifiable. Those want a rule, and a rule is testable.

## Gate tests

1. **⛔ NEGATIVE: no path from draft to posted document without a human.** The most important test on
   this surface. Enumerate the code paths that create a posted document; assert none accepts a draft
   id without a named actor. Attempt it directly and assert refusal.
2. **Grounded refusal.** Feed a source missing a field; assert the draft leaves it empty with a
   stated reason — and specifically assert it was **not** filled with a plausible value.
3. **Field-level confidence exists** and varies within one draft.
4. **An edit records the diff.** Accept with a change; assert the event stores before and after.
5. **The stub announces itself.** With a stub provider, assert `stub: true` in the response and in
   the invocation record.
6. **A disabled capability is absent.** Disable it; assert the endpoint is unavailable and that no
   fallback quietly produces a draft anyway.
7. **Acceptance rate is computed from real events**, not from a stored counter that could drift.
8. **An expired draft does not leak.** Expire drafts; assert they cannot be accepted, and that any
   work item they raised is handled explicitly rather than orphaned.

For a system that runs agents (the four layers above), these also gate. Each is a test in Sentinel,
inherited by every domain that adopts it:

9. **An agent can never approve.** Assert APPROVE is not grantable to an agent identity.
10. **An agent never exceeds its bound role.** For every action an agent may run on its own, assert
    that a person holding the bound role in that scope today could do the same without an approver.
11. **Every slot is bound.** Publish a template with a slot unbound in the tenant; assert refusal.
12. **The tree resolves.** No dangling parent, no loop, and the stop list matches the tree.
13. **Oversight is independent.** Assert the role that oversees an agent is not the role that owns it.
14. **Trust is pooled** across scopes unless a scope override carries its own minimum evidence.

## Divergence register

| What | Why | Cost |
|---|---|---|
| `ai_draft` may hold no rows; the provider is a labelled stub | No live AI traffic; no provider contracted. | Grounding behaviour is proven against fixtures, not a real model. The stub is labelled, so this is visible rather than a false green. |
| _Conforms on_ — the negative proof that no path exists from draft to posted document without a named human, per-field confidence, acceptance-rate measurement, config-driven capabilities. | | |
