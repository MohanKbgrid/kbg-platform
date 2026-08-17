# Adoption — Greenfield (a new product, born on the canon)

**Audience: the build agent for a new KBG product.** Self-contained. First consumer: a greenfield product.

You are not "adding a platform later". The day-one commit already carries tenancy, config, RBAC,
workflow, documents, and the ledger. That is cheaper than it sounds — most of it is schema and a few
hundred lines of service — and it removes the single most expensive class of rework there is.

## The order, and why deviating costs you

Build in canon wave order. Each wave depends on decisions the previous one forces.

```
Wave 1   Tenancy → Config → RBAC          identity and permission
Wave 2   Workflow → Documents → Experience work, evidence, and the shell
Wave 3   Integration → Runtime AI          the outside world
Wave 4   Accounting                        money, once the inputs are settled
         ─────────────────────────────────
then     the first business module
```

**Do not start with the business module.** It is the tempting move because it is the thing the
client asked for, and it is how you end up with tenancy bolted on across forty tables.

## Day-one checklist

Before the first business feature exists, these must be true:

- [ ] `company` table exists; **every** other table you have created carries `company_id`.
- [ ] Tenant context is resolved from the request and no write reads a tenant from the body.
- [ ] Config surface exists; at least one threshold is a row, and a test proves changing it changes
      behaviour with no deploy.
- [ ] `can(actor, action, object)` exists and **every** endpoint calls it. Deny by default.
- [ ] A denied action returns a *reason*, and the same function drives the UI's disabled state.
- [ ] Workflow can raise an item without naming an approver; the approval matrix is data.
- [ ] The work queue component exists and is the landing screen for at least one role.
- [ ] Document types are declared; one is required and provably blocks a transition.
- [ ] The eight Experience states exist in the shell, not just in a design file.
- [ ] Outbox exists; `integration_mode` gates it; nothing calls outward from a request handler.
- [ ] GL vouchers balance, validate before mutating, and carry currency, doc series, open-item
      groundwork, and reversal linkage — **the four that cannot be retrofitted**.
- [ ] Alembic (or equivalent) is the only schema path. **Never `create_all`.**
- [ ] A test suite runs against a fixture database with a guard that refuses to run anywhere else.

## Starter decisions you must make explicitly

Write the answer down; do not let it emerge.

1. **What is a tenant here?** A legal entity, a franchise, a client? This decides whether masters
   are shared.
2. **What is the operating unit?** Warehouse, branch, clinic, site. It becomes a GL dimension and an
   RBAC scope.
3. **What are the control accounts?** Name them before the first adapter. Sales, receivables, stock,
   cash, and whatever this domain adds.
4. **What are the dimensions?** The list is hard to extend later because every posting path stamps
   them. Be generous now.
5. **Which system of record does this eventually talk to?** Even "none yet" is an answer, but it
   determines whether you need the SAP-class four on day one. If there is *any* chance, the answer
   is yes.
6. **What is the offline story?** If any user is ever offline, capture ids are client-minted from
   the first endpoint, not retrofitted.

## How to work

- **Brief-first.** For each surface, write a task brief that quotes the spec's contract and gates
  verbatim. A rule the agent must go and look up is a rule the agent will skip.
- **Gate every surface before starting the next.** The gates in each spec are the definition of
  done. Run them; do not reason about whether they would pass.
- **Verify evidence, not claims.** When a build reports green, ask what it changed and check the
  negative case. In this programme a stale server process once served a passing test suite.
- **Record divergences** in each spec's register as you make them.

## What you inherit, and what you must not copy

**Inherit:** the contracts, the doctrines, the gate lists, the schema *shapes*.

**Do not copy:** another project's data, names, domain vocabulary, or business rules. A canon
surface describes a mechanism. One product's control accounts, route logic and ERP function
modules are *its* instance of the mechanism, not the mechanism.

## First business module

Only once the waves are gated. Then, for that module, answer the **seven questions** in the canon
README before writing code. If you cannot answer all seven, the requirement is not ready, and
building it will produce something the platform has to be bypassed to use.
