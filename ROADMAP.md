# Roadmap

What exists, what is being built, what is next. No dates: this is an order, and it moves when evidence says so.

## Shipped
- **Canon:** nine surfaces and one seam, twelve doctrines, greenfield and retrofit adoption guides.
- **Bases:** a dependency-free Python core and a React UI kit, to copy in and own.
- **Sentinel 0.24:** four layers (monitoring, functionality, org and assignment with authority, oversight), role slots,
  modes OFF / OBSERVE / PROPOSE / ACT, per-client adoption records, DuckDB analytics, A2UI cards, MCP.
- **Open licensing:** Apache-2.0 code, CC BY 4.0 canon and docs. Nothing is paid or gated.

## Being built now
- **The conformance kit (`gates/`):** a runnable gate per canon surface, each proven red first.
- **Bases brought up to date:** denial kinds in `authority`, a sync and async `outbox`, `rbac_shadow`, `job_run`, a
  vendoring check, and domain-free UI components (tables, work queue, audit log, access control, status chips).
- **Open standards in Sentinel, all additive:** CloudEvents in, OpenTelemetry (GenAI conventions) out, JSON Schema for
  every YAML, an AsyncAPI document for events, A2UI v0.9 (v0.8 still accepted), an A2A endpoint beside MCP, and an
  optional Cedar backend for `authorise()`.
- **A five-minute demo** on synthetic data.
- **Release engineering:** PyPI publishing by trusted publishing, signed images, SBOMs, CodeQL, Scorecard.

## Next
- First public Sentinel release on PyPI.
- A documentation site covering every layer.
- Canon: "Distributing master data offline" (versioned deltas, snapshots, urgent set-state changes, multi-source blocking)
  as specs and gates.
- More planted-defect tests for existing gates; `good first issue` labels.

## Later, and only on evidence
- **An integration-hub base (`bases/hub`)**, after it has run in production for one product and at least one other
  product adopts the pattern. Until then it is specified and gated, not shipped as code.
- A second Sentinel store backend, if someone needs it.

## How to influence it
Open an issue describing the failure you hit. The roadmap follows real failures, not feature wishes.
