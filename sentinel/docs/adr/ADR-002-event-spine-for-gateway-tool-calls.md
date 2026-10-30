# ADR-002 — Sentinel as the event spine for gateway and project tool calls

Status: **Proposed** (17 Oct 2026). Needs Mohan's confirmation, because it sets what every project emits.

## Decision

Every project's tool execution through the shared gateway emits a canonical Sentinel event; Sentinel does not poll project tables.

1. **One envelope** (existing, §1). Each event carries an idempotency key that is unique per fact, so replays have one effect.
2. **Project side writes an outbox row in the same transaction as the change** (the `postgres-outbox` connector template reads exactly this). Sentinel reads it with a read-only login and a `(created_at, id)` cursor.
3. **Retry state lives outside the event.** Events are immutable. Delivery attempts, next-attempt time and last error sit in a separate mutable table owned by the reader. This is the same fix made for the retail POS relay (`outbox.delivery`, retail-pos ADR-003), so all projects behave alike.
4. **Severity and approval come from the registry**, not from the gateway. The gateway's autonomy class is an input; the registry decides.
5. **Dead letters are visible exceptions**, not logs: an event that cannot be delivered becomes a case.

## Consequences

The `postgres-outbox` template is the reference. Overlays implement the same reader contract (`OVERLAY_CONTRACT.md`).
