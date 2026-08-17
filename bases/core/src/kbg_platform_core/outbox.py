"""Integration §10 — the environment gate, and D3 idempotency by source key.

⛔ THE FAILURE THIS PREVENTS: a development or UAT environment writing to the client's production
system of record. It has to be one gate at one place, because per-connector or per-caller gating
means the next caller someone adds is ungated.

HELD IS NOT FAILED, AND HELD IS NOT FAKED. A non-production environment produces real rows in a
real `HELD` state that can be listed, counted and released. It must never stub a success — a stub
returning success is how a false green reaches production, and this programme has the scar.

The store is injected. This package does not know your ORM; it knows the state machine.
"""
from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any, Optional, Protocol


class Mode(str, enum.Enum):
    PRODUCTION = "production"
    UAT = "uat"
    DEV = "dev"

    @property
    def may_send(self) -> bool:
        return self is Mode.PRODUCTION


class State(str, enum.Enum):
    QUEUED = "queued"
    IN_FLIGHT = "in_flight"
    CONFIRMED = "confirmed"
    HELD = "held"
    FAILED = "failed"
    DEAD_LETTER = "dead_letter"


@dataclass(frozen=True)
class RetryPolicy:
    """How many times to re-drive before a row stops being retried.

    `max_attempts` is a policy, so it is data (D5) rather than a constant buried in the drain loop.
    """

    max_attempts: int = 5


@dataclass(frozen=True)
class Transition:
    """What the drain loop should do with one row. PURE — it touches no database.

    Returned rather than applied so a project keeps its own persistence and gets the RULES from
    here. That split is what makes this library portable: the decision is universal, the SQL is not.
    """

    state: State
    increment_attempts: bool
    record_response: bool
    counts_as: str            # dispatched | held | failed | dead_letter
    reason: str


def decide(*, result: dict[str, Any], attempts: int,
           policy: Optional[RetryPolicy] = None) -> Transition:
    """The outbox state machine, in one place.

    ⛔ THE RULE THAT IS EASY TO GET WRONG, and the reason this function exists: **a HELD row must
    not increment `attempts`, and must stay re-drivable.** Held means "this environment may not
    send", which is a property of the ENVIRONMENT, not of the message. If holding consumed a retry,
    a long UAT period would dead-letter perfectly good events purely because time passed — and they
    would be discovered only after the switch flipped to production and nothing arrived.

    So a held row keeps its queued state and its attempt count, and the same drain loop re-drives it
    the moment the gate opens. No separate re-drive mechanism is needed, which is the point.

    The response is recorded EITHER WAY. A held row that looks merely unprocessed is a silent
    outcome, and a silent outcome is the false-green shape this whole library is shaped against.
    """
    policy = policy or RetryPolicy()

    if result.get("held"):
        return Transition(
            state=State.QUEUED, increment_attempts=False, record_response=True,
            counts_as="held",
            reason=str(result.get("held_reason")
                       or "environment may not send; re-driven when the gate opens"))

    if result.get("ok"):
        return Transition(State.CONFIRMED, True, True, "dispatched",
                          "the far side accepted it")

    nxt = attempts + 1
    if nxt >= policy.max_attempts:
        return Transition(State.DEAD_LETTER, True, True, "dead_letter",
                          f"failed {nxt} times (max {policy.max_attempts}); stops retrying and "
                          f"needs a human")
    return Transition(State.FAILED, True, True, "failed",
                      str(result.get("error") or f"attempt {nxt} failed; will retry"))


@dataclass
class OutboxRow:
    topic: str
    source_key: str
    payload: dict[str, Any]
    state: State = State.QUEUED
    attempts: int = 0
    held_reason: Optional[str] = None
    last_error: Optional[str] = None
    detail: dict[str, Any] = field(default_factory=dict)


class OutboxStore(Protocol):
    """Implement against your own persistence. `upsert` MUST be idempotent on
    (topic, source_key) — that uniqueness is the idempotency guarantee, and enforcing it in the
    database rather than in Python is what makes a concurrent retry safe."""

    def get(self, topic: str, source_key: str) -> Optional[OutboxRow]: ...
    def upsert(self, row: OutboxRow) -> OutboxRow: ...


class Outbox:
    def __init__(self, mode: Mode, store: OutboxStore) -> None:
        self.mode = mode
        self.store = store

    def enqueue(self, *, topic: str, source_key: str, payload: dict[str, Any]) -> OutboxRow:
        """Queue an outbound document — or HOLD it, if this environment may not send.

        Re-enqueuing the same (topic, source_key) returns the EXISTING row rather than creating a
        second one. A retry after a timeout therefore cannot produce two documents at the far side,
        which is the failure D3 exists to prevent.
        """
        if not source_key:
            raise ValueError(
                "source_key is required: idempotency is by SOURCE key, so an outbound document "
                "without one cannot be safely retried")

        existing = self.store.get(topic, source_key)
        if existing is not None:
            return existing

        row = OutboxRow(topic=topic, source_key=source_key, payload=payload)
        if not self.mode.may_send:
            row.state = State.HELD
            row.held_reason = (
                f"integration_mode={self.mode.value}: outbound writes are held, not sent. "
                f"The row is real and releasable — nothing was faked and nothing was dropped.")
        return self.store.upsert(row)

    def release_check(self) -> dict[str, Any]:
        """What a gate test asserts against. Deliberately returns the MODE rather than a boolean,
        so a test can assert the specific environment and not merely 'something is off'."""
        return {"mode": self.mode.value, "maySend": self.mode.may_send}

    def mark_confirmed(self, row: OutboxRow, detail: Optional[dict] = None) -> OutboxRow:
        row.state = State.CONFIRMED
        row.detail.update(detail or {})
        return self.store.upsert(row)

    def held_result(self) -> dict[str, Any]:
        """What a handler returns when the gate is shut. Shaped so `decide()` reads it, and so a
        reader inspecting a queued row can see it is being HELD rather than merely unprocessed."""
        return {"held": True, "mode": self.mode.value,
                "held_reason": f"integration_mode={self.mode.value}: outbound writes are held, "
                               f"not sent. Nothing was faked and nothing was dropped."}

    def mark_failed(self, row: OutboxRow, error: str) -> OutboxRow:
        """A failure is RECORDED, never swallowed (D7). `error` is required."""
        if not error:
            raise ValueError("a failure must carry its error; a swallowed error is a false green")
        row.state = State.FAILED
        row.attempts += 1
        row.last_error = error
        return self.store.upsert(row)
