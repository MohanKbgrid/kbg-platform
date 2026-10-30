# ADR-003 — Four layers: business monitoring, agent functionality, org and authority, agent oversight

Status: **Accepted in part** (Mohan, 20 Oct 2026). The four-layer split and the role-slot rule are **accepted** as
**logical boundaries inside Sentinel**. Splitting the layers into separate products or repositories is **not adopted**:
Sentinel is KBGrid's agentic base and evolves as one product (see "Decision on packaging" below and ADR-004).
First proposed 20 Oct 2026. Raised by Mohan: "agentic functionality adoption is one part and role assignment is
another part; segregate them so the layer can be adopted across domains and the scale of the org is not a driver."
This ADR takes that position, records where it holds, where it does not, and the shape that survives the critique.

## Context

The agents-as-roles mandate already built in one domain pack (agents are roles; people are assigned to roles; an agent
never exceeds its human) mixes three concerns in one design and one set of core tables:
- what the agent does;
- who is accountable for it;
- what that person may authorise.

Every new domain (retail POS, hospital, dairy, D2C) would copy and re-cut that mix. Retail also adds scale: 22 stores ×
categories × templates means hundreds of agent instances and thousands of people. The proposal is three separate
layers so a domain adopts the agent functions without inheriting another customer's org, and so org size never
drives code.

## The proposal, tested

| Claim | Holds? | Hole found | Fold-in |
|---|---|---|---|
| Separate agent functionality from role assignment | **Yes** | Templates in the reference pack name human roles directly ("Reports To: Fulfilment Exec"). That binds functionality to one org | Templates declare **role slots** (e.g. `accountable: category_buyer`, `approver: category_head`). Each tenant **binds slots to its own org roles** in configuration. A template never names an org role |
| A "role assignment" layer is enough on the org side | **No** | Two different things hide in it. **Who holds which role** (org tree, assignments, scopes) is domain-agnostic. **What a role may authorise** (Limits keys, money limits, clinical authority) is domain vocabulary. Merge them and the layer is domain-coupled again | Split the org layer into **C1 Org and assignment** (generic) and **C2 Authority policy** (generic engine, domain vocabulary supplied by the pack) |
| "Monitoring" is a layer of its own | **Partly** | The word covers two jobs. (a) **Watching the business**: detectors, monitors, data trust. (b) **Watching the agents**: agreement, reversals, cost, drift, the kill switch. (a) feeds agents. (b) must be **independent of the agents it watches** (the watched must not grade itself) | Two layers. **A Business monitoring** (sensing). **D Agent oversight** (governance), reporting to people, able to stop an agent |
| Monitoring and functionality can be split physically | **No** | Both run on one spine: events → cases → routing → learning. Splitting the deployment duplicates the case engine and breaks grouping and inhibition across them | Split **by contract, not by process**. A emits events; B consumes events and cases. Same Sentinel runtime |
| Org scale stops being a driver | **For code, yes. For operations, no** | (1) **Learning dilutes.** One agent instance per store × category earns trust from too few cases to ever leave OBSERVE. (2) **Process count:** hundreds of always-on processes is unworkable. (3) **Human throughput:** case volume grows with stores; approvers become the bottleneck | (1) Learn at **template level, pooled across scopes**, with per-scope overrides only when evidence differs (Sentinel's `trust_by` with a pooled parent). (2) **One worker per template iterates its scopes** in a set-based run; an instance is a row, not a process. (3) Bulk decisions, digests and ranked-by-money queues are mandatory once a template passes a scope count |
| Org data can be derived from history | **Reporting lines, yes. Authority, no** | Deriving authority from observed approvals would turn today's out-of-policy approvals into tomorrow's policy | **Derive the tree; never derive authority.** Derived reporting lines are proposed and ratified once. Authority comes only from policy (Limits, delegation of authority), never from behaviour |
| One central role service for all domains | **Not at runtime** | Tills, wards and depots must keep working when the network is down. A live dependency on a central role service breaks offline selling (POS ADR-009, INT-08 offline sign-in) | C1/C2 is a **library + replicated store**. Each domain core holds a synced copy and enforces locally. The authority check runs where the write happens |
| Sentinel can enforce its own agents' limits | **No** | The watched must not hold its own keys | Enforcement lives in each **domain core** (`authorise()` called on every agent-triggerable write). Sentinel asks; the core decides |

## Decision (proposed)

Four layers, each with a generic engine and a domain-supplied part. A domain adopts by supplying only the right-hand column.

| Layer | Job | Generic (kbg-sentinel and the shared org library) | Domain pack / tenant supplies |
|---|---|---|---|
| **A. Business monitoring** | Sense the business: detectors, KPI monitors, expect sources, data trust | Sources, schedules, monitors (`kpi.py`), DataChecks, `data.untrusted` | Detector queries, metrics, datasets, thresholds |
| **B. Agent functionality** | Decide and propose: cases, routing, playbooks, planners, methods, learning, idempotent execution | Case engine, registry, executor, method learning, evaluation, pooled trust | **Templates** (with role slots, scope dimensions, needed capabilities), actions, tools, verifiers |
| **C1. Org and assignment** | Who holds which role, where, when; the tree; vacancy and escalation | Role tree (solid and dotted lines), typed hierarchical **scopes**, time-bound assignments, stop list, identity adapters (HR feed, SCIM, derivation from history), agent identities and modes (OFF / OBSERVE / PROPOSE / ACT), grants (VIEW / EDIT, **never APPROVE**) | Scope dimensions (retail: region ⊃ store, category tree; hospital: hospital ⊃ department ⊃ ward, specialty), the tenant's roles, **slot bindings** |
| **C2. Authority policy** | What a role may do without an approver; maker-checker; segregation of duties | Policy engine: most-specific-row-wins thresholds, hard rows, SoD pairs, the ceiling rule | The vocabulary: Limits keys (retail), clinical and financial authority (hospital), credit limits (dairy) |
| **D. Agent oversight** | Watch the agents: agreement, reversals, outcome checks, cost, drift, circuit breaker, kill switch, owner report | Already in kbg-sentinel (§8, §11, §12, §19–24); moved behind its own role so it reports to people, not to the agents | Who receives oversight reports; ceilings per template |

### The contracts between layers
- **A → B:** canonical events (envelope §1; ADR-002 event spine).
- **B → C1:** `holders(role_slot, scope, at)` returns the people to route a case to; vacancy escalates up the tree to the stop list.
- **B → domain core → C2:** `authorise(actor, action, object, scope, amount)`. Allowed only if **all** of these hold:
  - the actor's mode and grant permit the action;
  - a person holding the actor's bound role **in that scope, today**, could do the same without an approver under the domain's policy (nearest held role above if vacant);
  - no SoD pair is violated;
  - the actor is not the approver of its own proposal.
- **B → D:** every proposal, decision, execution and outcome (already in the audit chain).
- **D → B:** stop, demote, or cap an agent template or instance. Recorded, and needs D's own role.

### Invariants (tests in the framework, inherited by every domain)
1. APPROVE is never grantable to an agent identity.
2. No agent action allowed to run on its own exceeds the authority of its bound role in that scope.
3. Every slot used by a template is bound in each tenant that enables it; publish is refused otherwise.
4. The tree resolves (no dangling parent, no loop) and the stop list matches it.
5. Oversight (D) cannot be held by the same role that owns the agent it oversees.
6. A template's trust is pooled across scopes unless a scope override has its own minimum evidence.

## Consequences
- **Mostly re-packaging, not new build.** kbg-sentinel already has A, B and D, and part of C1 (people directory, RBAC, SCIM, scoped assignments). The work:
  1. extract C1/C2 into a shared, replicable org-and-authority module with its own store and sync;
  2. introduce role slots in templates;
  3. add pooled trust;
  4. make each domain core call `authorise()`.
- **The reference pack migrates** by replacing role names in its templates with slots and binding them in its tenant files. Its own core keeps its tables until C1/C2 can replace them, with the same rules.
- **New domains** (retail POS first, hospital next) adopt by supplying templates, scope dimensions, authority vocabulary and slot bindings. No org-specific code.
- **Scale** shows up only as configuration (more scopes, more assignments) and as operating load. Bulk review and digests become mandatory past a scope threshold set in the template.

## Open points for Mohan
1. Confirm the four-layer split and the role-slot rule.
2. Where C1/C2 lives: a package inside kbg-sentinel (simplest) or a separate repository (cleanest for domains that use the org layer without Sentinel).
