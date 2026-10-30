# ADR-005 — Generic capabilities, domain bindings, client configuration

Status: **Accepted as a guiding principle** (Mohan, 20 Oct 2026): "the layer theory is to be generic so that domain
vocabulary and agents' work are consolidated and the relevant rows are checked. Demand planning applies across any domain,
but the form may be different."

## Decision
Agent work is built in three tiers. Only the rows relevant to a domain and client are evaluated.

| Tier | Holds | Checked by |
|---|---|---|
| **1. Generic capability** (framework) | The method and the loop, in **structural** terms: demand series, resource with capacity, supply source with lead time, exception, approval, allocation under constraints, outcome check | Invariant tests in the framework |
| **2. Domain binding** (domain pack) | The domain's words mapped onto those structures; grain; constraints; **what may never be automated** (clinical, statutory, tax, money posting); role slots | A binding check that refuses publish when a required structure is unmapped or a never-automate rule is missing |
| **3. Client configuration** (tenant) | Thresholds (e.g. the Limits table), scopes, slot bindings, switches | Config checks as today (maker-checker publish) |

Worked example, demand planning: one generic loop (forecast → buffer → allocate under constraints → verify → learn). It is bound to:
- retail: item × store, MOQ, shelf life, OTB;
- hospital: beds, OT slots and tests by department, staffing, drug law;
- dairy: products by depot and route, cold chain, vehicle capacity;
- D2C: SKU × channel.

## Guardrails
1. **Generic by structure, not by words.** Users and screens keep the domain's words; only the engine speaks generic. No shared renaming ("order", "return" and "stock" mean different things per domain).
2. **Extract, don't pre-design.** A capability becomes generic after it has worked in two or three domains. Until then it lives in the domain pack.
3. **Domain law stays in the domain.** The generic loop never decides what a domain forbids automating.
4. **Transfer methods, not parameters.** Methods and priors may seed another domain. Learned parameters (elasticities, safety stock, trust) pool only within a domain and client.
5. **A generic change reaches every domain at once**, so ADR-004's classification, ship-switched-off and per-client replay/dual-run rules are mandatory for tier-1 changes.
