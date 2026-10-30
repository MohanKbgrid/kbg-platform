# Personal data in Sentinel (DPDP pack)

India's Digital Personal Data Protection Act, 2023 and the DPDP Rules, 2025 (notified 13 November 2025,
in force in phases; most duties, including breach notification, apply from around May 2027). The customer
running Sentinel is the **Data Fiduciary**; KBGrid, when it operates or supports a site, is a **Data
Processor**. This pack is operational help, not legal advice: confirm every timeline and obligation with
counsel before relying on it.

## What Sentinel holds

| Where | What | Personal? | How long |
|---|---|---|---|
| Events | the payload each source sends (orders, shipments, payments) | often: names, phones, addresses | until retention removes the case (`--retention-days`) |
| Cases | facts read from the first event, the first event itself, proposals | sometimes | as above |
| Decisions, reviews | who decided, notes people wrote | people's ids; notes may mention customers | as above |
| Audit trail | every step, with the data that drove it (secrets redacted) | sometimes | as above |
| Similar-case vectors | numbers derived from case text | derived | removed with the case, or on erasure |
| Model calls | metering only (model, tokens, cost); never prompts or replies | no | as above |
| Archives (retention) | gzip files of removed cases | yes | until you delete them |
| Backups | full database copies | yes | `--keep` days of backups |

Prompts sent to a model are masked first for the payload keys the overlay lists as `pii_keys`.

## Tools

- **Find / access request**: Privacy page, or `sentinel privacy access "<phone or email>" --by <person>`.
  Returns every case that mentions the identifier and what is held, as JSON for the reply.
- **Erasure**: Privacy page, or `sentinel privacy erase "<identifier>" --by <person> --reason "<ref>" --yes`.
  Overwrites the identifier and the overlay's `pii_keys` with `[erased]` in events, facts, decisions,
  reviews and the audit trail of closed cases, and drops their vectors. Open cases are skipped (erase again
  when they close). The audit records a hash of the identifier, never the identifier.
- **Retention by data class**: `sentinel maintain ... --pii-days 90` (or `sentinel privacy scrub --days 90
  --apply`) removes personal fields from closed cases older than 90 days and keeps what happened and how it
  was decided. `--retention-days` then removes whole cases later.
- Needs the `__privacy__` right in the people configuration.

Search finds an identifier in each case's first event and facts. Ask the source system for its own
records too: Sentinel holds only what was sent to it.

See also: [breach runbook](BREACH_RUNBOOK.md) · [data processing agreement template](DPA_TEMPLATE.md).
