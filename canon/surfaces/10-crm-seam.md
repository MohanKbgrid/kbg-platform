# Seam — CRM (build the boundary now, extract when the trigger fires)

**Not a surface. A seam.** Included in the canon because getting it wrong is expensive and getting
it right early is nearly free.

## The situation

Every business application starts with customers embedded in its transactional core. That is
correct at the start. It stops being correct at a predictable moment, and the cost of the move is
decided entirely by whether you left a seam.

## Why it separates eventually

Customer data grows a second life. It stops being "who to invoice" and becomes prospecting,
onboarding pipeline, visit history, competitor intelligence, credit behaviour, campaign
membership. Those have a different cadence, a different audience, and different volumes than
transactions do. Left in the transactional core, they distort it — a customer table with 40 CRM
columns is one that every transaction join now pays for.

## The trigger to extract

Extract when **any two** of these become true. Not before — premature extraction buys you a
distributed system and no benefit:

1. A non-transactional team (marketing, telesales) needs write access to customer data.
2. Customer-adjacent entities outnumber customers (leads, contacts, activities, campaigns).
3. CRM read patterns start dictating indexes on transactional tables.
4. A CRM feature needs a release cadence the transactional core cannot match.

## Build the seam now — three cheap rules

1. **The golden identity is separate from the CRM attributes.** A minimal identity record
   (id, legal name, tax id, status) that transactions reference, and everything else — segment,
   tier, contacts, activity — in tables that reference *it*. Transactions never join to a CRM
   attribute; they join to the identity.
2. **CRM never writes transactional state.** It may propose (a lead, an onboarding request, a credit
   limit change) but the proposal goes through Workflow and the transactional side accepts it. This
   is what makes later extraction a routing change instead of a rewrite.
3. **The customer lifecycle is explicit and shared:** `Lead → Staged → Approved → Active →
   Suspended`. Both sides read it; only one side advances it.

## The one that bites at go-live

**Seeded customers do not have a lifecycle.** When thousands of customers arrive from an existing
system, they arrive **Active** with their external code already assigned. The `Lead → Staged →
Approved` path applies only to customers *captured in the field* after go-live.

Miss this and the system generates an approval task for every seeded customer on day one. That is
not a hypothetical — it is exactly what the specification had to be amended to prevent here.

## Gate tests

1. **Transactions never join a CRM attribute.** Assert transactional queries reference only the
   identity record.
2. **CRM cannot write transactional state.** Attempt a direct write from the CRM path; assert
   refusal, and that the legitimate route is a workflow proposal.
3. **Seeded customers arrive Active.** Seed a batch; assert zero approval tasks were raised, and
   that a field-captured customer *does* raise one.
4. **The extraction is a routing change.** A test that stands the CRM tables behind an interface and
   asserts the transactional side still passes its own suite unchanged.

## Divergence register

| What | Why | Cost |
|---|---|---|
| Customer still lives in the transactional core with CRM-adjacent columns attached | Correct per the spec — **the extraction trigger has not fired.** No non-transactional team writes customer data, and CRM entities do not outnumber customers. | None yet. Re-assess when either trigger fires. |
| _Conforms on_ — the `Lead → Staged → Approved → Active → Suspended` lifecycle exists, and seeded customers arrive Active rather than generating an approval task each. | | |
