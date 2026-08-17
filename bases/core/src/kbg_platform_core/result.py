"""D4 — missing data is a FINDING, never a licence to invent.

The doctrine is easy to agree with and easy to violate, because the ordinary way to signal absence
in Python is `None`, and `None` is silently falsy. `price or 0` looks reasonable and quietly
invents a zero. `shelf_life or 2` invents a shelf life that decides when real stock is written off.

So absence is a TYPE here, not a value. A `Gap` carries a machine-readable code and a
human-readable reason, and **reading `.value` on it raises**. A caller cannot accidentally treat
"we do not know" as a number; they have to say what happens when we do not know.

    price = resolve_price(product)
    if price.is_gap:
        return blocked(price.code, price.reason)
    total = qty * price.value
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Generic, Iterable, TypeVar

T = TypeVar("T")


class GapError(RuntimeError):
    """Raised when a caller reads `.value` off a Gap. Deliberately loud: reaching this means a
    code path forgot to handle absence, which is the bug D4 exists to prevent."""


@dataclass(frozen=True)
class Resolved(Generic[T]):
    """A value that is actually known, with optional provenance describing how it was derived."""

    value: T
    provenance: dict[str, Any] = field(default_factory=dict)

    is_gap = False

    def unwrap_or(self, _default: T) -> T:
        return self.value

    def as_dict(self) -> dict[str, Any]:
        return {"resolved": True, "value": self.value, "provenance": self.provenance}


@dataclass(frozen=True)
class Gap:
    """A stated absence. `code` is for machines and reports, `reason` is for the human who has to
    fix it — and it should say what would resolve the gap, not merely that one exists."""

    code: str
    reason: str
    detail: dict[str, Any] = field(default_factory=dict)

    is_gap = True

    @property
    def value(self):  # noqa: D102 - deliberately raises
        raise GapError(
            f"read .value on a Gap({self.code!r}). Absence is not a number. "
            f"Handle it: {self.reason}"
        )

    def unwrap_or(self, default):
        """The ONLY sanctioned way to substitute a value — explicit, at the call site, visible in
        review. If you find yourself writing this for money or safety data, you probably want to
        refuse instead."""
        return default

    def as_dict(self) -> dict[str, Any]:
        return {"resolved": False, "code": self.code, "reason": self.reason,
                "detail": self.detail}


Outcome = Resolved[T] | Gap


def gaps(items: Iterable[Outcome]) -> list[Gap]:
    """Every Gap in a batch — so a document can report ALL of what it could not resolve at once,
    rather than failing on the first and making the user discover the rest one at a time."""
    return [i for i in items if i.is_gap]


def all_resolved(items: Iterable[Outcome]) -> bool:
    return not any(i.is_gap for i in items)
