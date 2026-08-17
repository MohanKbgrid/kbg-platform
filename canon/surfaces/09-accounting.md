# Surface 9 — Accounting (the general ledger)

**Wave 4. Deliberately LAST.**

Not because it is least important — it is the most — but because money semantics want the doctrine
decided *before* any adapter exists. Every surface above it is an input to this one, and a GL built
first will encode assumptions the other surfaces then have to fight.

## Purpose

One double-entry ledger that every module posts into, so that "what did the business do" has one
answer. The alternative — each module keeping its own totals and a reporting layer reconciling them
— produces numbers that disagree, and the disagreement surfaces in front of the client.

## The contract

### The control-account doctrine
This is the single most important design decision on this surface, and it comes from a real Finance
head, not from a textbook:

1. **Native postings hit CONTROL accounts.** Not one account per material, per customer, or per
   route — one control account per *kind* of thing (sales, receivables, stock, cash).
2. **The detail rides on the journal line as DIMENSIONS.** Material, customer, route, plant, batch,
   channel — each line carries them. "Sales of product X on route Y" is then a query, not an
   account.
3. **The exploded, account-per-material shape is applied ONLY at the push boundary**, if the far
   system demands it (see Integration §5). It is a projection, never our native model.

Why this matters: a chart of accounts that grows with the product catalogue becomes unmaintainable,
and every new material becomes a finance ticket. With dimensions, a new material needs nothing.

### Posting
4. **Every posting balances, and it is asserted** — not assumed because the code "should" balance.
5. **Validate everything BEFORE mutating anything.** A posting routine that deletes prior lines and
   then validates will, on a validation failure, leave the ledger short. That exact hole existed
   here, at zero callers, and was closed before it had one.
6. **Idempotent on a natural source key** (D3), so a retried post amends rather than duplicates.
7. **A period can be closed**, and a closed period refuses postings — with the period named.
8. **Corrections are new dated documents referencing the original** (D2). There is no
   update-in-place, and no reopening. A reversal links to what it reverses.
9. **Every voucher names its source**: which module, which document, which actor.

### The SAP-class items you cannot retrofit
If the ledger may ever face a real ERP, four things must be present from the first migration.
Retrofitting any of them means rewriting posted history:
- **Currency on every amount** — even in a single-currency business.
- **Document number series per company AND per fiscal year**, allocated atomically.
- **Open-item groundwork** on receivable and payable lines: a clearing reference and status, so an
  invoice can be matched to a receipt later even if you do not build matching yet.
- **Reversal linkage** as a first-class column, not a note in a description field.

### Responsibility accounting
10. **The operating unit is a dimension** (warehouse, plant, branch) and operational roles are bound
    to theirs; leadership is not. Booking level — whether a transaction books to the org or to the
    unit — is a *role capability*, not a screen setting.

## Schema shape

```
chart_of_accounts   company_id · code · name · type · is_control · parent_code · metadata (jsonb)
fiscal_period       company_id · year · period · state (open|closed|certified) · closed_by/at
gl_voucher          company_id · voucher_no · doc_series · fiscal_year · doc_date · posting_date
                    · source_module · source_ref · currency · reverses_voucher_id
                    · created_by · created_at
gl_line             voucher_id · line_no · account_code · debit · credit · currency
                    · dim_product · dim_customer · dim_route · dim_plant · dim_batch · dim_channel
                    · clearing_ref · clearing_status
document_sequence   company_id · series_key · fiscal_year · next_value    ← atomic
```

## Doctrines that bind here

**D2** append-only, corrections are new documents · **D3** idempotent by source key · **D10**
posting date is the date it *happened* · **D1** an unresolvable account refuses.

## Adapters

Each module gets a thin **posting adapter** translating its business event into a balanced voucher.
Adapters are the only place domain vocabulary meets accounts. Two rules:
- **An adapter that cannot represent an event REFUSES and says what it cannot represent.** In this
  programme an invoice adapter could not express a bill-level cash discount, so it refused every
  cash bill — which was correct, loud, and fixed in an hour. A silent approximation would have
  quietly mis-stated revenue for a month.
- **A business event with no adapter is a finding**, not a reason to post something approximate.

## Gate tests

1. **Every voucher balances.** Assert on every posting path, including failure paths.
2. **Validation precedes mutation.** Force a validation failure on a re-post; assert the prior lines
   are **still there**. This is the test that catches delete-before-validate.
3. **Idempotency.** Post the same source key twice; assert one voucher and no doubled amounts.
4. **A closed period refuses**, naming the period. Then assert the seeded period is still open after
   the suite — a test that closes a period and does not restore it poisons every later run.
5. **Dimensions are populated, not null.** Assert each posting path stamps the dimensions its
   business event actually knows. A dimensional ledger with null dimensions is a control-account
   ledger with no detail — the worst of both.
6. **A correction is a new document.** Correct a posted voucher; assert the original is byte-for-byte
   unchanged and the correction references it.
7. **A reversal links.** Reverse; assert `reverses_voucher_id` is set and the pair nets to zero.
8. **Number series are per company and per year, and atomic.** Allocate concurrently; assert no
   duplicates.
9. **The adapter refuses what it cannot represent** — construct an event with an unrepresentable
   element; assert refusal naming it, not a silent approximation.
10. **The ledger ties out to the source.** For a period, assert the sum of postings equals the sum
    of the originating documents. State the denominator (D12) — same grain, same unit, same period.

## Divergence register

| What | Why | Cost |
|---|---|---|
| _Conforms, including all four items that cannot be retrofitted_ — `currency` on the voucher, per-company/per-fiscal-year `document_sequence`, open-item groundwork (`cleared_by_voucher_id` on lines), and `reverses_voucher_id`. Control accounts with dimensional sub-ledgers per the doctrine; validate-before-mutate (a real delete-before-validate hole was closed at zero callers); adapters refuse what they cannot represent. 104/104. | | |
| Period certification is single, not dual (Accounts + MD) | The MD certification step is designed, not built. | A period can be closed without the second signature the spec asks for. |
