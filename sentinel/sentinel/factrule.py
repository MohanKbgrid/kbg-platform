# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""One rule for a fact wherever it enters (BUILDER_MISSES check 13): receipts, data trust, the console's facts,
and the scope an agent assertion is minted with.

- A fact name is non-empty text (not only whitespace).
- A fact value is non-empty text (not only whitespace: fingerprints trim it) or a whole number (never a boolean,
  a fraction, a list or an object).
- An unset fact is left out. ``null`` is refused everywhere, so there is one rule.
Money and quantities are not facts: they travel as ``amount``.

``as_fact`` is the one normaliser for a value that breaks the rule but must still be recorded (what a caller passed
to a core's ``authorise``, a case fact copied into an assertion): it becomes its JSON text. Both sides use it, so a
receipt and the assertion it names always describe an odd value the same way.
"""
from __future__ import annotations

import json
from typing import Any


def name_problem(name: Any) -> str | None:
    """The rule for a fact name (or any configured name a fact is looked up by): non-empty, not only whitespace."""
    if not isinstance(name, str) or not name.strip():
        return "fact names must be non-empty text"
    return None


def fact_problem(name: Any, value: Any) -> str | None:
    """Why this fact breaks the rule, or None when it follows it."""
    if (why := name_problem(name)) is not None:
        return why
    if value is None:
        return f"{name} needs a value (leave an unset fact out)"
    if isinstance(value, bool) or not isinstance(value, str | int) or (isinstance(value, str) and not value.strip()):
        return f"{name} must be non-empty text or a whole number"      # judged as the fingerprint will trim it
    return None


def is_plain(name: Any, value: Any) -> bool:
    return fact_problem(name, value) is None


def as_fact(value: Any) -> Any:
    """A value kept as evidence in a shape the rule accepts: plain values as they are, anything else as JSON text."""
    if (isinstance(value, str) and value.strip()) or (isinstance(value, int) and not isinstance(value, bool)):
        return value
    return json.dumps(value, default=str, sort_keys=True)


def as_facts(facts: dict[str, Any]) -> dict[str, Any]:
    """Facts for a record: unset ones left out, odd values as JSON text, and a name that isn't non-empty text kept
    under a reserved name ("(name: ...)") that never overwrites a real fact."""
    out: dict[str, Any] = {}
    odd: list[tuple[Any, Any]] = []
    for k, v in facts.items():
        if v is None:
            continue
        if isinstance(k, str) and k.strip():
            out[k] = as_fact(v)
        else:
            odd.append((k, v))
    for k, v in odd:
        name, n = f"(name: {json.dumps(k, default=str)})", 2
        while name in out:
            name, n = f"(name: {json.dumps(k, default=str)} #{n})", n + 1
        out[name] = as_fact(v)
    return out


def scope_problem(scope: Any, *, lists: bool = False) -> str | None:
    """The fact rule for a configured scope (people configuration). ``lists``: a value may be a non-empty list of
    plain values (an assignment covering several stores)."""
    if not isinstance(scope, dict):
        return "a scope is an object of facts"
    for k, v in scope.items():
        if lists and isinstance(v, list):
            if not v:
                return f"{k}: an empty list matches nothing"
            for x in v:
                if (why := fact_problem(k, x)) is not None:
                    return why
            continue
        if (why := fact_problem(k, v)) is not None:
            return why
    return None
