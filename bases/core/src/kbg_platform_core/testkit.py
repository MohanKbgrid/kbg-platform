"""D5 + D7 — prove the control controls, and never run destructive tests on the wrong database.

Two assertions this programme learned to insist on, because a suite without them can be entirely
green and entirely meaningless.

`assert_control_controls` is the antidote to the commonest false green in configurable systems: a
test that seeds the default threshold and asserts the default outcome. It passes identically
against a hardcoded constant. The only way to prove a threshold is data is to CHANGE it and watch
the outcome move.

`require_fixture_db` is the antidote to the other kind of incident — a teardown running against
production. It fails CLOSED: a database name it does not recognise is refused, including names it
has never heard of.
"""
from __future__ import annotations

from typing import Any, Callable, Iterable, Optional


class ControlNotProven(AssertionError):
    pass


def require_fixture_db(current: str, allowed: Iterable[str],
                       purpose: str = "writes fixture rows and deletes them again") -> str:
    """Refuse to proceed unless `current` is a known fixture database.

    Fail-closed by design: an unrecognised name is refused rather than assumed safe. The cost of a
    false refusal is a one-line config change; the cost of a false permit is a production incident.
    """
    allowed = set(allowed)
    if current in allowed:
        return current
    raise SystemExit(
        f"REFUSED: this suite {purpose}, and {current!r} is not a recognised fixture database "
        f"(allowed: {sorted(allowed)}). If this database really is disposable, add it explicitly — "
        f"never widen the check to 'anything that is not production'."
    )


def assert_control_controls(*, describe: str,
                            run: Callable[[], Any],
                            change: Callable[[], None],
                            restore: Optional[Callable[[], None]] = None,
                            invariant: Optional[Callable[[], Any]] = None) -> tuple[Any, Any]:
    """Prove that a config value actually drives behaviour.

    Runs the observation, changes ONLY the config, runs it again, and asserts the result moved.
    Returns `(before, after)` so the caller can assert the specific transition too.

    `invariant`, if given, is something that must NOT change — typically the underlying
    measurement. That second assertion is what distinguishes "the threshold moved the verdict"
    from "the whole computation changed", and without it a passing test still permits a bug where
    changing config accidentally alters the measurement as well.

    `restore` is run in a finally block. Pass it. A test that leaves a threshold moved poisons
    every test that runs after it, and the failure will appear somewhere unrelated.
    """
    before = run()
    inv_before = invariant() if invariant else None
    try:
        change()
        after = run()
        inv_after = invariant() if invariant else None
    finally:
        if restore is not None:
            restore()

    if before == after:
        raise ControlNotProven(
            f"{describe}: changing the config did NOT change the outcome (both {before!r}). "
            f"Either the value is hardcoded somewhere, or this test did not change the value the "
            f"code actually reads. A test that only asserts the default passes equally well "
            f"against a constant."
        )
    if invariant is not None and inv_before != inv_after:
        raise ControlNotProven(
            f"{describe}: the invariant moved too ({inv_before!r} -> {inv_after!r}). The config "
            f"should change the VERDICT, not the underlying measurement."
        )
    return before, after


def assert_advanced(describe: str, before: Any, after: Any) -> None:
    """D6 — prove NEWNESS, not liveness.

    A restart proves itself by an advanced timestamp; a deploy proves itself by serving something
    that did not exist before. `systemctl enable --now` is a no-op on an already-running unit and
    will happily report success over stale code — which is why 'the service is active' is not
    evidence of anything.
    """
    if not (after > before):
        raise AssertionError(
            f"{describe}: expected the value to ADVANCE, got {before!r} -> {after!r}. "
            f"Reporting 'active' or 'ok' is not evidence that anything new is running."
        )
