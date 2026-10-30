# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""D1 — deny by default, and ONE function drives both the disabled button and the 403.

The bug this prevents is specific and common: a UI computes whether to show a button, an API
computes whether to allow the call, and the two drift. Users then see enabled buttons that fail,
or — worse — the API is open and only the UI is closed.

So `Authority.check()` is the single question. The screen renders from it, the endpoint enforces
from it, and they cannot disagree because there is only one answer.

Two smaller rules fall out of the canon and are enforced here:
  * a denial carries a REASON, a KIND (a closed list of seven) and, where known, WHO CAN — because
    "hidden" teaches users the feature does not exist, while "requires Plant Manager" teaches them
    how the org works, and because a greyed-out button needs to say WHICH of seven things is wrong
    (canon, RBAC surface, rule 3 and gate 9);
  * every decision is logged, allow AND deny, because a system that only records denials cannot
    answer "who could have done this".
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Optional

#: The closed list of denial kinds (canon: RBAC surface, rule 3). `AUTHORITY` is the default.
AUTHORITY = "AUTHORITY"
STATE_GATE = "STATE_GATE"
CONFIG_GATE = "CONFIG_GATE"
PRECONDITION = "PRECONDITION"
READINESS = "READINESS"
APPROVAL_PENDING = "APPROVAL_PENDING"
COMPLETED = "COMPLETED"
_INVISIBLE = {ord(c): None for c in "\u200b\u200c\u200d\u2060\u2062\u2063\ufeff\u00ad"}
BLOCK_KINDS = (AUTHORITY, STATE_GATE, CONFIG_GATE, PRECONDITION, READINESS, APPROVAL_PENDING,
               COMPLETED)

#: The code carried by the deny-by-default fallback (no rule matched).
NO_RULE = "NO_RULE"


@dataclass(frozen=True)
class Decision:
    """One answer to "may this actor do this?". Build it with `allow()` / `deny()`.

    A denial ALWAYS has a reason and a kind from `BLOCK_KINDS`; both are enforced when the object
    is constructed, so no path (including a bare `Decision(False, ...)`) can produce a silent or
    mis-classified denial. An allow carries no kind. `COMPLETED` is a kind of non-allow that is
    not an error ("already done"); it is still `allowed=False`.

    Field order keeps the original positional layout (allowed, reason, who_can, detail); `kind`
    and `code` are appended so existing positional callers are unaffected.
    """

    allowed: bool
    reason: Optional[str] = None
    who_can: Optional[str] = None
    detail: dict[str, Any] = field(default_factory=dict)
    kind: Optional[str] = None
    code: Optional[str] = None

    def __post_init__(self) -> None:
        if self.allowed:
            if self.kind is not None:
                raise ValueError("an allow does not carry a denial kind")
            return
        reason = self.reason
        if reason is not None and not isinstance(reason, str):
            raise ValueError("a denial reason must be text")
        # None, "", whitespace-only and invisible-character-only (zero-width space etc.) are all "no reason"
        if not (reason or "").translate(_INVISIBLE).strip():
            raise ValueError(
                "a denial must carry a reason - a silently disabled control is the thing this "
                "class exists to prevent")
        if self.kind is None:
            object.__setattr__(self, "kind", AUTHORITY)
        elif self.kind not in BLOCK_KINDS:
            raise ValueError(f"unknown denial kind {self.kind!r}; one of {BLOCK_KINDS}")

    @classmethod
    def allow(cls, reason: Optional[str] = None, **detail: Any) -> "Decision":
        return cls(True, reason, None, detail)

    @classmethod
    def deny(cls, reason: str, who_can: Optional[str] = None, *, kind: str = AUTHORITY,
             code: Optional[str] = None, **detail: Any) -> "Decision":
        return cls(False, reason, who_can, detail, kind, code)

    def as_availability(self) -> dict[str, Any]:
        """What a screen renders. Note it never omits the reason on a denial, and a denial always
        names its kind (None on an allow)."""
        return {"enabled": self.allowed, "reason": self.reason, "whoCan": self.who_can,
                "kind": self.kind, "code": self.code}

    def as_blocked_by(self) -> Optional[dict[str, Any]]:
        """The `{kind, code, reason}` shape some products use on the wire; None on an allow."""
        if self.allowed:
            return None
        return {"kind": self.kind, "code": self.code, "reason": self.reason}


class Authority:
    """Wrap the product's own decision function, or subclass and implement `_evaluate`.

    Pass `authorise(actor, action, obj)` - it returns a `Decision`, or None when no rule matched.
    (A richer policy engine that also takes scope and amount is wrapped in a closure that fills
    those in; this class only fixes the three things every screen and endpoint share.)
    Existing subclasses that override `_evaluate` keep working unchanged. Do not override `check`:
    the logging and the deny-by-default fallback live there on purpose.

    `None` means "no rule matched", which is a DENIAL with code `NO_RULE`. That is the
    deny-by-default doctrine expressed as a language default: forgetting to grant something
    fails closed, which is the correct direction.
    """

    def __init__(self, authorise: Optional[Callable[[Any, str, Any], Optional[Decision]]] = None,
                 log: Optional[Callable[[dict[str, Any]], None]] = None) -> None:
        if authorise is not None and not callable(authorise):
            raise TypeError("authorise must be a callable (actor, action, obj) -> Decision | None")
        self._authorise = authorise
        self._log = log

    def _evaluate(self, actor: Any, action: str, obj: Any = None) -> Optional[Decision]:
        if self._authorise is None:
            raise NotImplementedError(
                "inject an `authorise` callable or override `_evaluate`")
        return self._authorise(actor, action, obj)

    def check(self, actor: Any, action: str, obj: Any = None, *,
              acted_for: Any = None) -> Decision:
        decision = self._evaluate(actor, action, obj)
        if decision is None:
            decision = Decision.deny(
                f"no rule grants {action!r}; unlisted actions are denied by default",
                code=NO_RULE)
        elif not isinstance(decision, Decision):
            raise TypeError(
                f"authorise must return a Decision or None, got {type(decision).__name__}")
        if self._log is not None:
            self._log({
                "actor": getattr(actor, "login", None) or str(actor),
                "action": action,
                "object": getattr(obj, "id", None) or (str(obj) if obj is not None else None),
                "allowed": decision.allowed,
                "kind": decision.kind,
                "code": decision.code,
                "reason": decision.reason,
                "acted_for": (getattr(acted_for, "login", None) or
                              (str(acted_for) if acted_for is not None else None)),
            })
        return decision

    def require(self, actor: Any, action: str, obj: Any = None, *,
                acted_for: Any = None) -> Decision:
        """Enforce. Raises `PermissionDenied` carrying the same reason AND kind the UI showed."""
        d = self.check(actor, action, obj, acted_for=acted_for)
        if not d.allowed:
            raise PermissionDenied(d)
        return d


class PermissionDenied(PermissionError):
    def __init__(self, decision: Decision) -> None:
        super().__init__(decision.reason)
        self.decision = decision
