# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""Integration §10 — the environment gate, and D3 idempotency by source key.

⛔ THE FAILURE THIS PREVENTS: a development or UAT environment writing to the client's production
system of record. It has to be one gate at one place, because per-connector or per-caller gating
means the next caller someone adds is ungated.

HELD IS NOT FAILED, AND HELD IS NOT FAKED. A non-production environment produces real rows in a
real `HELD` state that can be listed, counted and released. It must never stub a success — a stub
returning success is how a false green reaches production, and this programme has the scar.

The store is injected. This package does not know your ORM; it knows the state machine.

TWO FRONT DOORS, ONE STATE MACHINE. `Outbox` is for a synchronous store, `AsyncOutbox` for an
asynchronous one (an async ORM). Both are thin: the rules live in `decide()` and in the shared
`_OutboxCore`, so the two cannot drift. A product with an async store must use `AsyncOutbox`;
the synchronous `Outbox` REFUSES an async store loudly (see `_refuse_awaitable`) instead of
treating an un-awaited lookup as "the row already exists".
"""
from __future__ import annotations

import enum
import inspect
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


class AsyncOutboxStore(Protocol):
    """The same contract for an asynchronous store. Used by `AsyncOutbox` only."""

    async def get(self, topic: str, source_key: str) -> Optional[OutboxRow]: ...
    async def upsert(self, row: OutboxRow) -> OutboxRow: ...


def _refuse_awaitable(value: Any, what: str) -> None:
    """⛔ R1 (Integration gate 8). A synchronous caller meeting an asynchronous store gets back an
    un-awaited coroutine from `get()`. A coroutine is ALWAYS truthy and never None, so
    `if existing is not None` takes the "row already exists" branch on the very FIRST enqueue,
    returns a coroutine as if it were a row, and nothing is ever written. The outbox then looks
    healthy and only a count of rows shows the loss. Refuse it, loudly, at the point of contact."""
    if inspect.isawaitable(value):
        if inspect.iscoroutine(value):
            value.close()          # silence "coroutine was never awaited"; we are refusing it
        raise TypeError(
            f"outbox store.{what}() returned an awaitable: this is a synchronous Outbox over an "
            f"asynchronous store. Use AsyncOutbox, which awaits every store call. (Reading an "
            f"un-awaited coroutine as 'the row exists' silently drops the first enqueue.)")


class _OutboxCore:
    """Everything that is NOT a store call: validation, the held decision, the gate report, and
    applying a `decide()` transition to a row. Shared by `Outbox` and `AsyncOutbox`."""

    def __init__(self, mode: Mode, store: Any, policy: Optional[RetryPolicy] = None) -> None:
        self.mode = mode
        self.store = store
        self.policy = policy or RetryPolicy()

    @staticmethod
    def _require_key(source_key: str) -> None:
        if not source_key:
            raise ValueError(
                "source_key is required: idempotency is by SOURCE key, so an outbound document "
                "without one cannot be safely retried")

    def _new_row(self, topic: str, source_key: str, payload: dict[str, Any]) -> OutboxRow:
        row = OutboxRow(topic=topic, source_key=source_key, payload=payload)
        if not self.mode.may_send:
            row.state = State.HELD
            row.held_reason = (
                f"integration_mode={self.mode.value}: outbound writes are held, not sent. "
                f"The row is real and releasable — nothing was faked and nothing was dropped.")
        return row

    def release_check(self) -> dict[str, Any]:
        """What a gate test asserts against. Deliberately returns the MODE rather than a boolean,
        so a test can assert the specific environment and not merely 'something is off'."""
        return {"mode": self.mode.value, "maySend": self.mode.may_send}

    def held_result(self) -> dict[str, Any]:
        """What a handler returns when the gate is shut. Shaped so `decide()` reads it, and so a
        reader inspecting a queued row can see it is being HELD rather than merely unprocessed."""
        return {"held": True, "mode": self.mode.value,
                "held_reason": f"integration_mode={self.mode.value}: outbound writes are held, "
                               f"not sent. Nothing was faked and nothing was dropped."}

    def _apply(self, row: OutboxRow, result: dict[str, Any]) -> Transition:
        """Run `decide()` and apply it. The ONLY place a row's state follows from a result.

        A held result changes NOTHING about the attempt count and does not move the row out of
        its HELD/QUEUED state; it only refreshes the reason. Every other outcome follows the
        transition, and a recorded failure always carries its error (D7)."""
        if row.state in (State.CONFIRMED, State.DEAD_LETTER):
            # Terminal. A late or duplicate result for a delivered row must not resurrect it (a retry would then
            # send the document twice); a dead-lettered row waits for a person, not for the next result.
            return Transition(row.state, False, False, "ignored",
                              f"row is {row.state.value}; a further result changes nothing")
        t = decide(result=result, attempts=row.attempts, policy=self.policy)
        if t.counts_as == "held":
            row.held_reason = t.reason
            return t
        row.state = t.state
        row.held_reason = None
        if t.increment_attempts:
            row.attempts += 1
        if t.state in (State.FAILED, State.DEAD_LETTER):
            row.last_error = t.reason
        elif t.state is State.CONFIRMED:
            row.last_error = None
        return t

    def _release(self, row: OutboxRow) -> bool:
        """HELD -> QUEUED, only when the environment may now send. Never touches `attempts`."""
        if row.state is State.HELD and self.mode.may_send:
            row.state = State.QUEUED
            row.held_reason = None
            return True
        return False

    def _fail(self, row: OutboxRow, error: str) -> None:
        if not error:
            raise ValueError("a failure must carry its error; a swallowed error is a false green")
        if row.state in (State.CONFIRMED, State.DEAD_LETTER):
            return                                    # terminal: see _apply
        row.attempts += 1
        row.state = State.DEAD_LETTER if row.attempts >= self.policy.max_attempts else State.FAILED
        row.last_error = error

    @staticmethod
    def _confirm(row: OutboxRow, detail: Optional[dict]) -> None:
        if row.state is State.HELD:
            raise ValueError("a HELD row was never sent: it cannot be confirmed while the gate holds it "
                             "(release it first, then dispatch)")
        row.state = State.CONFIRMED
        row.held_reason = None
        row.detail.update(detail or {})


class Outbox(_OutboxCore):
    """For a SYNCHRONOUS store. Refuses an asynchronous one (R1)."""

    def enqueue(self, *, topic: str, source_key: str, payload: dict[str, Any]) -> OutboxRow:
        """Queue an outbound document — or HOLD it, if this environment may not send.

        Re-enqueuing the same (topic, source_key) returns the EXISTING row rather than creating a
        second one. A retry after a timeout therefore cannot produce two documents at the far side,
        which is the failure D3 exists to prevent.
        """
        self._require_key(source_key)
        existing = self.store.get(topic, source_key)
        _refuse_awaitable(existing, "get")
        if existing is not None:
            return existing
        saved = self.store.upsert(self._new_row(topic, source_key, payload))
        _refuse_awaitable(saved, "upsert")
        return saved

    def settle(self, row: OutboxRow, result: dict[str, Any]) -> OutboxRow:
        """Apply the outcome of one drain attempt (`{"ok":..}`, `{"held":..}`, or an error)."""
        self._apply(row, result)
        saved = self.store.upsert(row)
        _refuse_awaitable(saved, "upsert")
        return saved

    def release_held(self, row: OutboxRow) -> OutboxRow:
        """Re-queue a HELD row once the gate is open. A no-op while the gate is shut."""
        if self._release(row):
            saved = self.store.upsert(row)
            _refuse_awaitable(saved, "upsert")
            return saved
        return row

    def mark_confirmed(self, row: OutboxRow, detail: Optional[dict] = None) -> OutboxRow:
        self._confirm(row, detail)
        saved = self.store.upsert(row)
        _refuse_awaitable(saved, "upsert")
        return saved

    def mark_failed(self, row: OutboxRow, error: str) -> OutboxRow:
        """A failure is RECORDED, never swallowed (D7). `error` is required."""
        self._fail(row, error)
        saved = self.store.upsert(row)
        _refuse_awaitable(saved, "upsert")
        return saved


class AsyncOutbox(_OutboxCore):
    """For an ASYNCHRONOUS store: same rules, every store call awaited."""

    async def enqueue(self, *, topic: str, source_key: str,
                      payload: dict[str, Any]) -> OutboxRow:
        self._require_key(source_key)
        existing = await self.store.get(topic, source_key)
        if existing is not None:
            return existing
        return await self.store.upsert(self._new_row(topic, source_key, payload))

    async def settle(self, row: OutboxRow, result: dict[str, Any]) -> OutboxRow:
        self._apply(row, result)
        return await self.store.upsert(row)

    async def release_held(self, row: OutboxRow) -> OutboxRow:
        if self._release(row):
            return await self.store.upsert(row)
        return row

    async def mark_confirmed(self, row: OutboxRow, detail: Optional[dict] = None) -> OutboxRow:
        self._confirm(row, detail)
        return await self.store.upsert(row)

    async def mark_failed(self, row: OutboxRow, error: str) -> OutboxRow:
        self._fail(row, error)
        return await self.store.upsert(row)
