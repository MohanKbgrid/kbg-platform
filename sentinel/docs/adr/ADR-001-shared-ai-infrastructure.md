# ADR-001 — Shared AI infrastructure: what Sentinel adopts, and what it deliberately does not

Status: **Accepted** (17 Oct 2026). Source: OSS adoption notes for the AI Gateway, Golden Trunk ERP and ACME (17 Oct).
Licences were checked by the note authors on 17 Oct; re-verify the LICENSE file at the pinned version before use.

## Context

Three adoption notes recommend LiteLLM, Langfuse, Hatchet, CopilotKit/AG-UI and the MCP SDK for the shared AI gateway and
the projects behind it. Sentinel already has, in this repo: an idempotent step executor (`ARCHITECTURE.md` §6), a model
router with fallback, escalation and metering (`providers.py`, `model_runs`, §12), its own gateway, and an audit trail. The
question is where the recommendations add something and where they would duplicate or weaken it.

## Decision

| Component | Decision for Sentinel | Reason |
|---|---|---|
| LiteLLM (MIT, not `enterprise/`) | **Optional backend, not a dependency.** Works today through `OpenAICompatibleClient` (already named in `providers.py`). The shared gateway may run it; Sentinel code never imports it. | Sentinel's router already does fallback, escalation, cool-down and metering. A second router inside it would hide which model answered. |
| Langfuse (MIT, not `ee/`) | **Opt-in export only, off by default.** No change to what `model_runs` stores. | Sentinel stores token counts, latency and cost, **never prompts or replies**, by design. Langfuse traces hold content. A customer who wants traces may switch it on per tenant, with the retention and privacy review that implies. |
| Hatchet (MIT) | **Not adopted in Sentinel.** Stays the engine for the Trunk, gateway and project workflows. | The executor claims a key per step and refuses to re-run an unknown outcome. That rule is stricter than a generic retrying queue and must not be replaced. Hatchet may *call* Sentinel; it does not run its steps. |
| MCP Python SDK | **Adopt** for exposing each overlay's tools. | Matches "agents touch reality only through tools". |
| CopilotKit + AG-UI | **Spike only** (one project, Northwind sales-trend chat). Not part of the platform until the spike reports. | The valuable part is the autonomy-class contract, not the library. |
| Mem0 / Graphiti / Letta | **Deferred.** | Sentinel's similar-cases and learning (§13, §8) cover the need; a second memory store would split the truth. |
| ERPNext/Frappe, Odoo | **Reference only.** Never copy code. | GPL/LGPL. |

## The contract to define first (before any UI shell)

Autonomy classes map onto Sentinel's own approval and trust rules, in one table kept in this repo:

- `auto-execute-with-audit` → an action whose pattern has earned trust, runs through the executor.
- `propose-then-confirm` → a proposal waiting on a human decision (§7).
- `screen-required` → a case that opens the project's transactional screen; Sentinel records the case and the decision, the project owns the write.

Any shell (CopilotKit, assistant-ui, a custom page) renders these three and nothing else.

## Consequences

- No new mandatory service in Sentinel. Observability additions are exporters, not dependencies.
- Overlays follow the same rule: shared infrastructure may sit beside Sentinel, never between it and its audit trail.

## Proof required

The existing independent test pass plus one test that runs Sentinel with the gateway pointed at a LiteLLM proxy and shows `model_runs` still records the model that actually answered.
