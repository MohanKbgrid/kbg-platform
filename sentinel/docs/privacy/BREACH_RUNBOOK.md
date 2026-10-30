# Personal data breach runbook

For a Sentinel site. The Data Fiduciary (the customer) notifies; KBGrid, as processor, tells the customer at
once and helps. Confirm timelines with counsel: under the DPDP Rules, 2025 the Data Protection Board gets an
intimation without delay and a detailed report within 72 hours of becoming aware, and each affected person
gets a plain-language notice without delay.

## 0. Who

| Role | Person | Contact |
|---|---|---|
| Incident lead (customer) | | |
| Privacy / DPO contact (customer) | | |
| KBGrid on call | | |
| Counsel | | |

## 1. First hour: contain

1. Note the time you became aware. Every deadline counts from here.
2. Revoke exposed credentials: person and service tokens (Access page), `SENTINEL_SECRET_*` values at their
   source, the database password, SSO client secret, edge secrets, the usage key.
3. If someone got into the server: stop the API (`docker compose stop api`), keep the database and logs.
4. If the leak is through an outbound edge or a configured action: unpublish that connector (Changes page)
   or turn its exceptions to shadow (Go live page).
5. Keep evidence: `docker compose logs > logs-<date>.txt`, the audit trail (Activity page or
   `sentinel ... show`), a fresh backup (`sentinel backup`).

## 2. Within the day: scope

- Which systems and data: events, cases, archives, backups, model traffic (Sentinel never stores prompts).
- Which people: use `sentinel privacy access "<identifier>"` for known identifiers; for a whole period, the
  Cases page by date and source.
- Since when: audit trail (`config_published`, `meta_denied`, `sso_*`, access token events), proxy and
  database logs.

## 3. Notify (Data Fiduciary)

- **Board, initial intimation (without delay):** what happened, how much, when and where, likely impact.
- **Board, detailed report (within 72 hours of awareness, unless the Board extends it):** updated facts,
  causes if known, what was done to contain and fix it, who was responsible if found, notices sent.
- **Each affected person (without delay):** what happened and when, likely consequences, what you did, what
  they can do to protect themselves, and who to contact. Plain language, in a language they read.
- Keep copies of every notice and the dates sent.

## 4. Fix and learn

- Patch the cause; rotate anything still at risk; check backups and archives were not the route.
- Write a blameless postmortem; update this runbook and the data map.
- Keep this record with the logs for at least a year (confirm the period with counsel).
