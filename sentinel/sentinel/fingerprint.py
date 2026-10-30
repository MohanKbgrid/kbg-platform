# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""Deterministic incident signatures (the observability 'fingerprint' idea).

A FingerprintRule picks fields out of an event payload, optionally buckets
numeric values, and turns them into stable facts + a signature string. The
signature is what grouping, the registry and learning all key on.
"""
from __future__ import annotations

import hashlib
from typing import Any

from pydantic import BaseModel, Field

from .models import Event


def dig(data: dict[str, Any], path: str) -> Any:
    """Read 'a.b.c' (or 'a.0.c' for lists) out of nested data. Missing -> None."""
    from .expr import dig as _dig
    return _dig(data, path)


class Bucket(BaseModel):
    """Turn a number into a label, e.g. age_hours -> '>24h'."""

    field: str                              # payload path
    edges: list[float]                      # ascending
    labels: list[str]                       # len(edges) + 1

    def label(self, value: Any) -> str | None:
        if value is None:
            return None
        try:
            v = float(value)
        except (TypeError, ValueError):
            return None
        for edge, lab in zip(self.edges, self.labels, strict=False):
            if v < edge:
                return lab
        return self.labels[-1]


class FingerprintRule(BaseModel):
    event_type: str
    fields: dict[str, str] = Field(default_factory=dict)      # fact name -> payload path
    buckets: dict[str, Bucket] = Field(default_factory=dict)  # fact name -> bucket
    group_by: list[str] = Field(default_factory=list)         # facts forming the signature; default: all

    def model_post_init(self, _ctx: Any) -> None:
        from .factrule import name_problem
        for n in [*self.fields, *self.buckets, *self.group_by]:
            if name_problem(n) is not None:
                raise ValueError(f"fingerprint rule {self.event_type}: fact names must be non-empty text")
        for name, b in self.buckets.items():
            if len(b.labels) != len(b.edges) + 1:
                raise ValueError(f"bucket {name}: need len(labels) == len(edges)+1")
            if b.edges != sorted(b.edges):
                raise ValueError(f"bucket {name}: edges must be ascending")


class Fingerprinter:
    def __init__(self, rules: list[FingerprintRule] | None = None) -> None:
        self._rules: dict[str, FingerprintRule] = {}
        for r in rules or []:
            self.add(r)

    def add(self, rule: FingerprintRule) -> None:
        if rule.event_type in self._rules:
            raise ValueError(f"duplicate fingerprint rule for {rule.event_type}")
        self._rules[rule.event_type] = rule

    def facts(self, event: Event) -> dict[str, Any]:
        rule = self._rules.get(event.type)
        facts: dict[str, Any] = {"event_type": event.type, "source": event.source}
        if rule is None:
            return facts
        for name, path in rule.fields.items():
            facts[name] = _normalise(dig(event.payload, path))
        for name, bucket in rule.buckets.items():
            facts[name] = bucket.label(dig(event.payload, bucket.field))
        return facts

    def raw(self, event: Event) -> dict[str, Any]:
        """The payload values behind each fingerprint field, before normalising (to see which were not plain)."""
        rule = self._rules.get(event.type)
        return {} if rule is None else {name: dig(event.payload, path) for name, path in rule.fields.items()}

    def signature(self, event: Event, facts: dict[str, Any] | None = None) -> str:
        facts = facts if facts is not None else self.facts(event)
        rule = self._rules.get(event.type)
        keys = (rule.group_by if rule and rule.group_by else sorted(k for k in facts if k != "event_type"))
        parts = [event.tenant, event.type] + [f"{k}={facts.get(k)}" for k in keys]
        return "|".join(str(p) for p in parts)

    @staticmethod
    def short(signature: str) -> str:
        return hashlib.sha256(signature.encode()).hexdigest()[:12]


def _normalise(v: Any) -> Any:
    if isinstance(v, str):
        return v.strip()
    if isinstance(v, (int, float, bool)) or v is None:
        return v
    from .factrule import as_fact                 # a list or object: its JSON text, as every other record writes it
    return as_fact(v)
