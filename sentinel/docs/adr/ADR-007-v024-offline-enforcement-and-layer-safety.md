# ADR-007: Offline enforcement and Layer-D safety (v0.24.0): As built

- **Status:** As built, written before the final handover (20 Oct 2026).
- **Scope:** v0.24.0. It covers the signed policy bundle, agent assertions, receipts, data trust, spot checks, agent
  incidents and object claims.
- **Why this ADR exists late:** the "One tester pass" rule asks for this table before the first handover. v0.24.0
  went to the tester without one, and seven passes followed (`docs/BUILDER_MISSES.md`). This table is the
  builder's own check. Each cell is a rule (with the test that proves it) or a stated reason. The cells that were
  empty when I wrote it are the **gaps G1–G6** below, fixed in the same change.

## Decision (summary)
Sentinel issues authority; domain cores enforce it offline; Sentinel checks what the cores report.
- **Bundle:** signed people configuration with a version, an issue time, an expiry and a site.
- **Assertion:** a signed, one-use permission for one agent write: actor, template, case, action, object, scope and
  ACT mode.
- **Receipt:** what the core decided, posted back.
- **Layer A caps Layer B:** data trust per scope caps agent mode.
- **Layer D:** samples unattended decisions (spot checks), stops an agent in one step (agent incident), and keeps
  two templates from acting alone on one object (claims).

## Attack table

Columns: **insert**; **update** (of each field); **delete / truncate**; **other tenant / site**; **clock**;
**commit and concurrency**.

### 1. Policy bundle
| Path | Rule or reason |
|---|---|
| Insert (issue) | `sentinel policy export` only (CLI, operator holding the private key). There is no HTTP route. |
| Insert at the core | `load_policy`: RS256 signature against `keys.json` (`kid` must match when present), and the version must equal the hash of the content. The people configuration is parsed under the fact rule; a bad one is refused. |
| Update of any claim | Any change breaks the signature. Re-issuing identical content gives the same version with a later expiry. **Reason:** identical content is identical authority, so Sentinel's expiry check uses the latest issue. A core holding an older copy past its own expiry reports `stale` itself. |
| Delete / truncate at the core | No snapshot means no authorise: the core fails closed (its contract). |
| Other site | `load_policy(site=)` pins the core to its site. Assertions carry `site`; a mismatch is refused. |
| Clock | Expiry is exact. Issued more than `SKEW` (5 min) in the core's future: refused on load, or stale once loaded. Agents never write on a stale bundle; people still may, flagged. |
| Key compromise | **Reason:** rotate by issuing a new key pair and shipping `keys.json`. Cores trust only the keys they hold. There is no in-band revocation list. |

### 2. Agent assertion
| Path | Rule or reason |
|---|---|
| Insert (mint) | Only `engine.agent_assertion` for an incident, called by an action through `ctx.assert_for`. There is no HTTP route. Not minted when a relied-on scope fact is odd (`agent_assertion_refused`). |
| Claims | Allowed only if every claim matches: actor, site, action, object, ACT mode, and every scope fact the core passes (covered directly or by roll-up). Absent on either side is a mismatch. |
| Mode | The bundle the core holds can narrow the token below ACT, never widen it. |
| Amount | Never more than the bound role's holder in scope (`authorise`). |
| One use, one process | **G1, fixed:** check-and-mark is atomic under a lock in `PolicySnapshot` and `bind_assertion`. Two threads can no longer both pass. |
| One use, across cores | Sentinel records the first allowed receipt per assertion; a second is `assertion_reused`, audited and notified. Cores using `bind_assertion` keep `used` in a table with a unique id (the POS does). |
| Clock | TTL is 1 s to 1 h. Valid up to `exp` minus nothing and issued at most `SKEW` ahead. |
| Other site | Refused, and `unknown_assertion` at the other site's Sentinel. |

### 3. Receipt
| Path | Rule or reason |
|---|---|
| Insert | `POST /v1/receipts` (service token) or `engine.record_receipts`. Every field is strict, and scope follows the fact rule. The whole batch is validated before any receipt is recorded. |
| Attribution | **G4, fixed:** the audit row records the posting principal. Before, only the client-supplied `core` text was kept. |
| Update / delete | Write-once by id: a duplicate is counted, never re-audited. There is no update or delete route. |
| Flags | `unknown_bundle_version`, `stale_bundle`, `after_bundle_expiry`, `before_bundle_issue`, `agent_write_without_assertion`, `unknown_assertion`, `assertion_mismatch`, `assertion_reused`. |
| Forged receipt | **Reason:** a receipt authorises nothing. It is evidence, checked against what Sentinel issued. A forged one can only add flagged audit rows, attributed to the principal that posted it. |
| Clock | `at` must carry a UTC offset. Flags are computed against the issued bundle's window. |
| Concurrency | Dedupe and the reuse record run under a lock in one transaction with the audit row. |

### 4. Data trust score
| Path | Rule or reason |
|---|---|
| Insert / update | `POST /v1/data-trust` (service token) or `engine.set_data_trust`. One fact under the fact rule; a finite score in 0..1. |
| In-process callers | **Reason:** a direct `engine.set_data_trust` / `record_receipts` call is the deployment's own code, already inside the trust boundary. It is attributed as `engine`, and the `sources` allowlist applies to service principals over HTTP. |
| Who may set it | **G2, fixed:** `defaults.data_trust.sources` lists the service principals allowed to post scores. When it is set, any other principal gets 403. The row records the posting principal; the client's `source` text is kept only as a label. Without `sources`, any service token may post. That is documented, and `sentinel validate` warns. |
| Token issuance | **Reason:** the allowlist names principals, so whoever holds `__access__` (who issues service tokens) can in effect grant data-trust posting. Grant `__access__` accordingly. |
| Delete / truncate | No route. Scores go stale after `max_age_hours`. Unknown scores follow `unknown` (set `PROPOSE` to fail closed). |
| Index | **G3, fixed:** the index update is locked, so concurrent posts for different scopes never lose an entry. |
| Other tenant | **Reason:** scope ids belong to the engine's people configuration, which is one organisation. Organisations are separated by hosted mode (a schema, engine and tokens each). `Event.tenant` partitions cases inside one organisation and shares its scopes, like the people configuration does. |
| Clock | `at` is the engine clock. Freshness is measured on the engine clock. |
| Escape by odd value | A relied-on fact that arrives as no plain value sends the case to a person at ingest (`scope_fact_not_plain`). |

### 5. Spot check (on a disposition)
| Path | Rule or reason |
|---|---|
| Insert (sample) | Deterministic per case (`spot_check_rate`). An agent incident puts its decisions on check. |
| Verdict | By the owner role in scope or oversight, a JSON boolean, with a note required for "wrong". Write-once: a second verdict is refused. |
| Undo needed | Held by `__reverse__` holders. If there are none, by oversight, then the escalation role, then the owner role, then the checker. A fallback holder can keep it with a reason, never undo. |
| Reversal | Any reversal settles an open check. Trust is charged once per decision (`trust_charged`). |
| Meta rights | **Reason:** `__reverse__` and other meta rights come from unscoped assignments only (`authorize_meta` matches no scope), so a store-scoped person can never undo another store's decision. |
| Concurrency | The state and its audit row are written in one transaction. Trust is charged under the pattern-state lock. |

### 6. Agent incident
| Path | Rule or reason |
|---|---|
| Insert | Oversight roles only. A reason is required, and `hours` is finite in (0, 1 year]. The record and its index are written under a lock in one transaction. |
| Close | Oversight only. A post-mortem is required. Write-once: closing again is refused. |
| Delete | No route. |

### 7. Object claim
| Path | Rule or reason |
|---|---|
| Insert | Checked and taken under a lock in one transaction. Released when the breaker stops the action. Expires after `claim_minutes`. |
| Object identity | Taken from the `claims` facts. An odd value sends the case to a person, so no claim is taken. |
| Other tenant | The same reason as data trust (one organisation per engine). |

### 8. Configuration (registry, defaults, people)
| Path | Rule or reason |
|---|---|
| Publish | Strict: numbers are numbers and flags are booleans. Every configured fact or parameter name (`claims`, `trust_by`, `money_fact`, `inhibit_on`, `brief_fields`, fingerprint fields and `group_by`, `amount_param`, `data_trust.sources`) follows one name rule (`factrule.name_problem`: not empty and not only whitespace). Scopes follow the fact rule. Maker-checker applies as before. |

## Who satisfies each refusal
| Refusal | Satisfied by | Contract |
|---|---|---|
| Agent write without a valid assertion | The action, through `ctx.assert_for` | `ActionContext.assert_for(action, obj)` |
| Scope not covered | The core, passing the scope it enforces | `authorise(scope=...)` / `bind_assertion(scope=...)` |
| Data trust post from an unlisted principal | Monitoring, using a principal named in `data_trust.sources` | Tokens configuration |
| Receipt `at` without an offset | The core: `datetime.now(UTC).isoformat()` | `Receipt.at` |
| Odd relied-on fact | The event source, sending plain ids | Fact rule (`OVERLAY_CONTRACT.md`) |

## Gaps found by this table (fixed in the same change)
- **G1 (Medium).** Assertion one-use within one process could be beaten by two threads. Check-and-mark is now atomic.
- **G2 (Medium).** Any service token could raise a scope's data trust and lift caps, and the `source` attribution was
  client text. Fix: the `sources` allowlist, and the posting principal is recorded.
- **G3 (Low).** The data trust index could lose an entry under concurrent posts. The update is now locked.
- **G4 (Low).** Receipts were not attributed to the posting principal. The principal is now recorded.
- **G5 (Low).** `bind_assertion` mutated the caller's `used` map outside a lock. It now runs under a module lock,
  and the docstring says to use a table in multi-process cores.
- **G6 (Low).** The data trust `sources` setting must itself be strict: a list of non-empty principal ids.
