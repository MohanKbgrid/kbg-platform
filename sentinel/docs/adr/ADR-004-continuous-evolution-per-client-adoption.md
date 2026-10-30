# ADR-004 — Sentinel evolves continuously; each client adopts versions under support control

Status: **Proposed** (20 Oct 2026). From Mohan: "We cannot freeze Sentinel's evolution. A client's adoption of a newer
version of Sentinel needs to be managed at support level for that client."

## Context
- Sentinel is KBGrid's agentic base. It keeps changing as new ideas and past lessons are folded in (v0.2 → v0.14 in weeks).
- Clients run it in production with **earned trust**: patterns that reached ACT after months of shadow and two-person promotion. A framework change that silently alters how a trusted pattern matches, routes or executes would spend that trust without anyone deciding to.
- Mechanics already in place:
  - packs and overlays pin Sentinel by **commit SHA** (no tags, standing rule);
  - versioned schema migrations;
  - a definition hash that resets trust when a pattern's meaning changes;
  - `replay` and `trace` against drafts;
  - shadow mode;
  - golden cases per pack (`testing.py`);
  - a **fleet** view that reports each site's version against a target and lists the upgrade commands. Upgrades run on the site; the fleet never pushes code.

## Decision

### 1. Main never freezes
Development continues on `main`. A **release** is a commit on `main` with a version bump in `pyproject.toml`, a `CHANGELOG`
entry and a **compatibility note**. It is identified by version and SHA, never a git tag.

### 2. Every change is classified in its CHANGELOG entry
| Class | Meaning | Rule |
|---|---|---|
| **Compatible** | Additive: new feature, new config key, new optional field | Ships **switched off** for existing tenants. Behaviour changes only when the client enables it in configuration (new patterns and methods arrive in OBSERVE) |
| **Behavioural** | Same contracts, different outcomes: matching, routing, scoring, learning maths | Must state which patterns can be affected. Adopted only after a **dual run** (§4) |
| **Breaking** | A contract changes: overlay contract, event envelope, config schema, `holders()` / `authorise()`, the store schema in a non-additive way | Needs a migration note, an automated migration where possible, and a **deprecation window**: the old form keeps working for at least two releases |

**Database migrations are expand-then-contract.** A release adds before it removes, so the previous release still runs
on the new schema. That is what makes rollback a pin change, not a restore.

### 3. Each client has a support record
`tenants/<client>/SENTINEL_ADOPTION.md` in the client's own repository (or the pack's tenant folder) holds:
- the **pinned pair**: framework SHA + domain-pack SHA, tested together;
- the date, who approved it on the client side and on KBGrid's side;
- the evidence from the independent test pass and the dual run;
- the **rollback pair** (the previous pinned pair).

The fleet view's `target_version` is set **per client**, from this record, not chain-wide.

### 4. Adoption path for a client (run by KBGrid support)
1. **Read** the CHANGELOG between the client's pin and the target. List compatible, behavioural and breaking items.
2. **Pack check:** the domain pack's golden cases and the client's functional scenarios run green on the target pair.
3. **Replay:** recent client cases are replayed through the target pair. Differences in match, route or proposal are listed per pattern.
4. **Dual run** (behavioural or breaking changes): the target pair runs in **shadow beside production** on live events for an agreed period. Its proposals are compared, never executed.
5. **Trust guard:** any pattern whose outcome differs in the dual run **drops one mode** (ACT → PROPOSE) on switch-over and earns its way back. Patterns with no difference keep their trust.
6. **Switch** the pin with the client's approval. Record it. Keep the rollback pair ready.
7. **Watch:** oversight (Layer D) compares agreement, reversals and outcomes before and after for the agreed period.

### 5. Support window
- KBGrid supports a client on **the current release and the one before it**.
- Fixes, security fixes included, land on `main` only, with **no per-client branches**: back-porting to forked branches is how products stop evolving.
- A client outside the window is upgraded, and the compatibility discipline above is what keeps that cheap.
- Contracts can set a longer window as a paid support tier.

### 6. Hosted mode is different
Hosted tenants share one runtime, so they **cannot pin different versions**. For them, every change rides on **per-tenant
switches** (compatible and behavioural changes off until enabled, after the same replay and dual run on that tenant's data).
Clients who need their own pin run on-premises or as a dedicated site.

## Consequences
- Sentinel keeps evolving at full speed, and no client is moved without evidence.
- Most changes are compatible and opt-in, so upgrades are cheap.
- The cost moves to discipline in each change: classify it, ship it switched off, expand before contract, keep golden cases. The CHANGELOG becomes a support document, not just a history.
- Fleet tooling needs two small additions: a per-client target, and a "behind by N releases, outside support window" flag.

## Open points for Mohan
1. Support window: current + previous (proposed), or a time-based window.
2. Dual-run length by risk: e.g. 1 week for behavioural, 2 weeks for breaking.
