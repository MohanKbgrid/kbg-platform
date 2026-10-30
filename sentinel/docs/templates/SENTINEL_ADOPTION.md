# Sentinel adoption record — <client>

_Template from kbg-sentinel `docs/templates/SENTINEL_ADOPTION.md` (ADR-004 §3). Copy it to
`tenants/<client>/SENTINEL_ADOPTION.md` in the client's repository (or the domain pack's tenant folder).
One file per client. Newest adoption on top. Never edit a past entry: add a new one._

## Client

| Field | Value |
|---|---|
| Client | <name, site or tenant id> |
| Deployment | on-premises / dedicated site / hosted (hosted tenants cannot pin; see ADR-004 §6) |
| Domain pack | <repo>, e.g. the retail POS/sentinel |
| Client owner (approves on client side) | <name, role> |
| KBGrid support owner | <name> |
| Support window | current release + previous (ADR-004 §5; confirm when Mohan decides) |

## Current pinned pair

| | Framework (kbg-sentinel) | Domain pack |
|---|---|---|
| Version | v0.x.y | <pack version> |
| Commit SHA | <full SHA> | <full SHA> |
| Adopted on | YYYY-MM-DD | |

**Rollback pair** (the pinned pair before this one): framework `<SHA>` + pack `<SHA>`.
Rollback is a pin change only (migrations are expand-then-contract).

## Adoption log

### YYYY-MM-DD — v<from> → v<to>

**1. Changes between pins** (from the kbg-sentinel CHANGELOG, every release in between):

| Release | Class | Item | Affects this client? | Action |
|---|---|---|---|---|
| v0.x.y | Compatible | <item> | no (switched off) | none / enable later |
| v0.x.y | Behavioural | <item, patterns named> | <pattern ids> | dual run |
| v0.x.y | Breaking | <item> | <contract> | migrate: <steps> |

**2. Pack check.** Golden cases and functional scenarios on the target pair:
- golden cases: <passed>/<total>, run <date>, evidence <link or path>
- client functional scenarios: <passed>/<total>
- independent function test: <who, date, result>

**3. Replay.** Cases replayed: <n> from <date range>.

| Pattern | Match diff | Route diff | Proposal diff | Note |
|---|---|---|---|---|
| | | | | |

**4. Dual run** (needed for any behavioural or breaking item). Shadow pin `<SHA>` beside production
from <date> to <date> (<days>; agreed length: behavioural 1 week / breaking 2 weeks, pending decision).

| Pattern | Production proposals | Shadow proposals | Differences | Trust guard applied |
|---|---|---|---|---|
| | | | | ACT → PROPOSE / none |

**5. Switch.** Pin changed on <date, time> by <who>.
- Client approval: <name, date, reference>
- KBGrid approval: <name, date>
- Settings switched on in this adoption (compatible features): <keys, or none>

**6. Watch** (Layer D, agreed period <days>). Agreement, reversals and outcome checks before vs after:

| Metric | Before | After | Verdict |
|---|---|---|---|
| Agreement rate | | | |
| Reversals | | | |
| Outcome checks failed | | | |

**Result:** adopted / rolled back to <pair> on <date> because <reason>.
