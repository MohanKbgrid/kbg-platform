# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""RBAC shadow mode: make the coverage gap MEASURABLE before enforcing it.

The reference code for the strangler in `canon/adoption/retrofit.md` ("Retrofitting RBAC without a
flag day"). A product whose routes are gated by "is logged in" rather than "is allowed" cannot
safely add a permission check everywhere at once: nobody knows which permissions real users need,
because the model has never met live traffic. Shadow mode asks the new question on every request,
RECORDS the answer, and changes nothing. The flip to enforcement, route group by route group, is
then driven by evidence.

WHAT IT NEVER DOES
  * It never denies, raises into the request, or alters a response. A shadow layer that can break
    a request is not a shadow layer. `observe()` therefore never raises: an evaluation error is
    recorded as `error`, and a recorder failure is counted in `recorder_errors` and swallowed.
  * It never reads a missing mapping as "no permission needed". A route with no row in the table
    is `unmapped`, which is the FINDING (D4), not a pass.
  * It never reads an error as an allow. Only an explicit allow answer is recorded `allow`.

OUTCOMES (closed list, `OUTCOMES`)
  allow       mapped, and the actor holds the permission
  would_deny  mapped, and the actor does NOT: under enforcement this request would have failed.
              Each is a permission to grant, or a person doing something they should not
  unmapped    no permission is mapped for this route yet
  error       evaluation raised or returned nothing usable

STORAGE AND FRAMEWORK AGNOSTIC. Nothing here imports a web framework or a database. You inject
  * `evaluate(actor, action, object_type)` -> a Decision-like object with `.allowed` (and optional
    `.reason`), or a plain bool. May be a coroutine function; use `aobserve` for that.
  * `recorder(observation: dict)` -> persist it anywhere (a table, a log line, a list). May be
    omitted; `MemoryRecorder` keeps them in memory for tests and one-off runs.

READ THE RESULT with `coverage_report(observations, table)`. Watch `unmapped` go to zero, then
`wouldDeny` and `errors` go to zero per route group; a group with `ready` true can be enforced.
"""
from __future__ import annotations

import inspect
import re
from dataclasses import dataclass
from typing import Any, Callable, Iterable, Optional

ALLOW = "allow"
WOULD_DENY = "would_deny"
UNMAPPED = "unmapped"
ERROR = "error"
OUTCOMES = (ALLOW, WOULD_DENY, UNMAPPED, ERROR)

_READ_ONLY = re.compile(r"(GET|HEAD|OPTIONS)")


@dataclass(frozen=True)
class RoutePermission:
    """One row of the table: which permission a route SHOULD require.

    `methods` is a regex over the HTTP method (e.g. "GET", "POST|PATCH|PUT"). `object_type` is
    separate from `action` because an authority function asks "may this actor do ACTION to this
    KIND of thing", and merging the two into one string makes every call a guess.
    """

    methods: str
    path_prefix: str
    action: str
    object_type: str

    @property
    def permission(self) -> str:
        return f"{self.object_type}.{self.action}"


def route_table(rows: Iterable[tuple[str, str, str, str]]) -> tuple[RoutePermission, ...]:
    """Build a table from `(methods, path_prefix, action, object_type)` tuples."""
    return tuple(RoutePermission(*r) for r in rows)


def _under(path: str, prefix: str) -> bool:
    """Prefix match on a path-SEGMENT boundary, so '/api/bills' does not claim '/api/billsfoo'."""
    return path == prefix or path.startswith(prefix.rstrip("/") + "/")


def permission_for(table: Iterable[RoutePermission], method: str,
                   path: str) -> Optional[RoutePermission]:
    """The row that governs this route, or None when it is not mapped.

    The LONGEST matching prefix wins, so the result does not depend on the order of the rows (a
    specific route can sit anywhere in the table). None is a real answer; the caller records it as
    `unmapped`.
    """
    best: Optional[RoutePermission] = None
    for row in table:
        if _under(path, row.path_prefix) and re.fullmatch(row.methods, method.upper()):
            if best is None or len(row.path_prefix) > len(best.path_prefix):
                best = row
    return best


class MemoryRecorder:
    """The simplest recorder: keeps every observation in a list."""

    def __init__(self) -> None:
        self.observations: list[dict[str, Any]] = []

    def __call__(self, obs: dict[str, Any]) -> None:
        self.observations.append(obs)


def _actor_name(actor: Any) -> Optional[str]:
    if actor is None:
        return None
    return getattr(actor, "login", None) or getattr(actor, "name", None) or str(actor)


def _read_decision(decision: Any, obs: dict[str, Any]) -> None:
    if decision is None:
        obs["outcome"], obs["reason"] = ERROR, "evaluate returned nothing; not read as an allow"
        return
    allowed = decision if isinstance(decision, bool) else getattr(decision, "allowed", None)
    if not isinstance(allowed, bool):
        obs["outcome"], obs["reason"] = ERROR, "evaluate returned an unusable answer"
        return
    obs["outcome"] = ALLOW if allowed else WOULD_DENY
    obs["reason"] = getattr(decision, "reason", None)
    kind = getattr(decision, "kind", None)
    if kind:
        obs["kind"] = kind


class RbacShadow:
    """Evaluate what the authority WOULD have said, record it, never deny."""

    def __init__(self, table: Iterable[RoutePermission],
                 evaluate: Callable[[Any, str, str], Any],
                 recorder: Optional[Callable[[dict[str, Any]], Any]] = None) -> None:
        self.table = tuple(table)
        self._evaluate = evaluate
        self.recorder = recorder if recorder is not None else MemoryRecorder()
        #: observations the recorder failed to persist: a number, never a silent loss
        self.recorder_errors = 0

    def _begin(self, actor: Any, method: str, path: str) -> tuple[dict[str, Any], Optional[RoutePermission]]:
        row = permission_for(self.table, method, path)
        obs: dict[str, Any] = {
            "method": method.upper(), "path": path,
            "permission": row.permission if row else None,
            "actor": _actor_name(actor),
            "readOnly": bool(_READ_ONLY.fullmatch(method.upper())),
            "outcome": UNMAPPED, "reason": None,
            "shadow": True, "enforced": False,
        }
        if row is None:
            obs["reason"] = ("no permission mapped for this route yet; this is the coverage gap "
                             "being measured, not a pass")
        return obs, row

    def _emit(self, obs: dict[str, Any]) -> dict[str, Any]:
        try:
            result = self.recorder(obs)
            if inspect.iscoroutine(result):
                result.close()
                raise TypeError("recorder is a coroutine function; use aobserve")
        except Exception:  # noqa: BLE001 - observability must not take down what it observes
            self.recorder_errors += 1
        return obs

    def observe(self, actor: Any, method: str, path: str) -> dict[str, Any]:
        """Never raises, never denies. Returns the observation it recorded."""
        obs, row = self._begin(actor, method, path)
        if row is not None:
            try:
                result = self._evaluate(actor, row.action, row.object_type)
                if inspect.isawaitable(result):
                    if inspect.iscoroutine(result):
                        result.close()
                    raise TypeError("evaluate is async; use aobserve")
                _read_decision(result, obs)
            except Exception as e:  # noqa: BLE001 - recorded as `error`, never propagated
                obs["outcome"], obs["reason"] = ERROR, f"{type(e).__name__}: {e}"[:200]
        return self._emit(obs)

    async def aobserve(self, actor: Any, method: str, path: str) -> dict[str, Any]:
        """The same for an async `evaluate` and/or an async recorder."""
        obs, row = self._begin(actor, method, path)
        if row is not None:
            try:
                result = self._evaluate(actor, row.action, row.object_type)
                if inspect.isawaitable(result):
                    result = await result
                _read_decision(result, obs)
            except Exception as e:  # noqa: BLE001
                obs["outcome"], obs["reason"] = ERROR, f"{type(e).__name__}: {e}"[:200]
        try:
            result = self.recorder(obs)
            if inspect.isawaitable(result):
                await result
        except Exception:  # noqa: BLE001
            self.recorder_errors += 1
        return obs


def coverage_report(observations: Iterable[dict[str, Any]],
                    table: Iterable[RoutePermission] = ()) -> dict[str, Any]:
    """What the shadow run has learned: the artefact the flip decision is made from.

    Counts are over `observations` (read them back from wherever your recorder put them). A route
    group is one row of `table`; it is `ready` to enforce only when it was actually observed,
    never would-deny, and never errored. A mapped group nobody has exercised is NOT ready: no
    traffic is not evidence. Unmapped routes are listed by `METHOD path` so the gap is a worklist.
    """
    table = tuple(table)
    counts = {o: 0 for o in OUTCOMES}
    groups: dict[str, dict[str, Any]] = {
        r.permission + " " + r.path_prefix: {
            "permission": r.permission, "pathPrefix": r.path_prefix,
            "observations": 0, "byOutcome": {o: 0 for o in OUTCOMES}, "ready": False}
        for r in table}
    unmapped_routes: dict[str, int] = {}
    total = 0
    for obs in observations:
        outcome = obs.get("outcome")
        if outcome not in counts:
            outcome = ERROR              # a record that is not one of ours is a finding, not data
        total += 1
        counts[outcome] += 1
        if outcome == UNMAPPED:
            key = f"{obs.get('method')} {obs.get('path')}"
            unmapped_routes[key] = unmapped_routes.get(key, 0) + 1
            continue
        row = permission_for(table, str(obs.get("method", "")), str(obs.get("path", "")))
        if row is not None:
            g = groups[row.permission + " " + row.path_prefix]
            g["observations"] += 1
            g["byOutcome"][outcome] += 1
    for g in groups.values():
        b = g["byOutcome"]
        g["ready"] = g["observations"] > 0 and b[WOULD_DENY] == 0 and b[ERROR] == 0
    return {
        "observations": total,
        "byOutcome": counts,
        "unmapped": counts[UNMAPPED],
        "wouldDeny": counts[WOULD_DENY],
        "errors": counts[ERROR],
        "unmappedRoutes": dict(sorted(unmapped_routes.items())),
        "mappedRoutes": len(table),
        "groups": list(groups.values()),
        "readyToEnforce": total > 0 and counts[UNMAPPED] == 0 and counts[WOULD_DENY] == 0
                          and counts[ERROR] == 0,
        "note": ("Shadow mode observes only; nothing was denied. Enforce a route group once it is "
                 "`ready`, and read the deny reasons first: each is either a permission to grant "
                 "or a person doing something they should not."),
    }
