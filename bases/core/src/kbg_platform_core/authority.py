"""D1 — deny by default, and ONE function drives both the disabled button and the 403.

The bug this prevents is specific and common: a UI computes whether to show a button, an API
computes whether to allow the call, and the two drift. Users then see enabled buttons that fail,
or — worse — the API is open and only the UI is closed.

So `Authority.check()` is the single question. The screen renders from it, the endpoint enforces
from it, and they cannot disagree because there is only one answer.

Two smaller rules fall out of the canon and are enforced here:
  * a denial carries a REASON and, where known, WHO CAN — because "hidden" teaches users the
    feature does not exist, while "requires Plant Manager" teaches them how the org works;
  * every decision is logged, allow AND deny, because a system that only records denials cannot
    answer "who could have done this".
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Optional


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: Optional[str] = None
    who_can: Optional[str] = None
    detail: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def allow(cls, reason: Optional[str] = None, **detail: Any) -> "Decision":
        return cls(True, reason, None, detail)

    @classmethod
    def deny(cls, reason: str, who_can: Optional[str] = None, **detail: Any) -> "Decision":
        if not reason:
            raise ValueError(
                "a denial must carry a reason — a silently disabled control is the thing this "
                "class exists to prevent")
        return cls(False, reason, who_can, detail)

    def as_availability(self) -> dict[str, Any]:
        """What a screen renders. Note it never omits the reason on a denial."""
        return {"enabled": self.allowed, "reason": self.reason, "whoCan": self.who_can}


class Authority:
    """Subclass and implement `_evaluate`. Do not override `check` — the logging and the
    deny-by-default fallback live there on purpose.

    `_evaluate` returning None means "no rule matched", which is a DENIAL. That is the
    deny-by-default doctrine expressed as a language default: forgetting to grant something
    fails closed, which is the correct direction.
    """

    def __init__(self, log: Optional[Callable[[dict[str, Any]], None]] = None) -> None:
        self._log = log

    def _evaluate(self, actor: Any, action: str, obj: Any = None) -> Optional[Decision]:
        raise NotImplementedError

    def check(self, actor: Any, action: str, obj: Any = None, *,
              acted_for: Any = None) -> Decision:
        decision = self._evaluate(actor, action, obj)
        if decision is None:
            decision = Decision.deny(
                f"no rule grants {action!r}; unlisted actions are denied by default")
        if self._log is not None:
            self._log({
                "actor": getattr(actor, "login", None) or str(actor),
                "action": action,
                "object": getattr(obj, "id", None) or (str(obj) if obj is not None else None),
                "allowed": decision.allowed,
                "reason": decision.reason,
                "acted_for": (getattr(acted_for, "login", None) or
                              (str(acted_for) if acted_for is not None else None)),
            })
        return decision

    def require(self, actor: Any, action: str, obj: Any = None, *,
                acted_for: Any = None) -> Decision:
        """Enforce. Raises `PermissionDenied` carrying the same reason the UI showed."""
        d = self.check(actor, action, obj, acted_for=acted_for)
        if not d.allowed:
            raise PermissionDenied(d)
        return d


class PermissionDenied(PermissionError):
    def __init__(self, decision: Decision) -> None:
        super().__init__(decision.reason)
        self.decision = decision
