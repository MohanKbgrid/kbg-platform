# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""A test kit for overlay and pack authors.

    from sentinel.testing import conformance, engine_for, run_golden

    def test_my_overlay_conforms():
        assert conformance(build_overlay()) == []

    def test_golden_cases():
        assert run_golden(engine_for(build_overlay()), "golden/") == []

``conformance`` checks what Sentinel relies on and cannot check at run time: the registry is valid against
the actions and tools; every action describes itself, declares its parameters and, if reversible, can be
undone; tools are read-only; every exception's event types have fingerprint rules and its roles exist;
outcome verifiers exist; pack actions carry their pack's namespace.

Golden cases are YAML files, one case each (or a list), replayed through the read-only trace::

    name: credit limit exceeded holds the order
    event: {type: order.credit_exceeded, payload: {outlet: O-17, amount: 92000}}
    expect: {pattern: credit_limit_exceeded, outcome: automatic, actions: [dairy.place_hold]}

``expect`` may give pattern, route, outcome (automatic | person | model | grouped | suppressed | duplicate)
and actions (the playbook's, in order).
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import yaml

from .models import Event


class FrozenClock:
    def __init__(self, at: datetime | None = None) -> None:
        self.now = at or datetime(2026, 1, 15, 4, 30, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self.now

    def advance(self, **kw: float) -> None:
        self.now += timedelta(**kw)


def engine_for(overlay: Any, **kw: Any) -> Any:
    """An engine on an in-memory database with a frozen clock, for tests."""
    from .engine import Engine
    from .policy import Guardrails
    from .store import SQLiteStore
    kw.setdefault("clock", FrozenClock())
    kw.setdefault("guardrails", Guardrails(allow_irreversible_unattended=True))
    return Engine(overlay, store=SQLiteStore(":memory:"), **kw)


def conformance(overlay: Any) -> list[str]:
    from .registry import Registry
    out: list[str] = []
    try:
        reg = Registry(overlay.patterns)
    except Exception as e:  # noqa: BLE001
        return [f"registry: {e}"]
    out += [f"registry: {m}" for m in reg.validate(overlay.actions, {n: t.params for n, t in
                                                                     overlay.tools.tools.items()})]
    namespaces = {p.manifest.namespace for p in getattr(getattr(overlay, "packs", None), "packs", [])}
    for spec in overlay.actions.specs():
        a = overlay.actions.get(spec.name)
        if not spec.description:
            out.append(f"action {spec.name}: no description (people and the model choose by it)")
        if not spec.params_schema:
            out.append(f"action {spec.name}: declares no params, so nothing it is given can be checked")
        if spec.reversible and a.compensate is None:
            out.append(f"action {spec.name}: marked reversible but has no compensator")
        if namespaces and "." in spec.name and spec.name.split(".")[0] not in namespaces:
            out.append(f"action {spec.name}: not in any pack's namespace {sorted(namespaces)}")
    for t in overlay.tools.tools.values():
        if not getattr(t, "read_only", True):
            out.append(f"tool {t.name}: tools must be read-only")
        if not t.description:
            out.append(f"tool {t.name}: no description")
    if any(p.owner_slot or p.escalation_slot for p in overlay.patterns):
        from .overlay import SlotError, resolve_slots
        try:
            resolve_slots(list(overlay.patterns), getattr(overlay, "slots", {}), getattr(overlay, "slot_bindings", {}),
                          overlay.roles)
        except SlotError as e:
            out.append(f"role slots: {e}")
    fp_types = {r.event_type for r in overlay.fingerprint_rules}
    roles = set(getattr(overlay, "roles", {}) or {})
    for p in overlay.patterns:
        missing = [t for t in p.event_types if t not in fp_types and t != "*"]
        if missing:
            out.append(f"pattern {p.id}: no fingerprint rule for {missing}")
        for r in filter(None, (p.owner_role, p.escalation_role)):
            if roles and r not in roles:
                out.append(f"pattern {p.id}: role {r!r} is not in the registry's roles")
        if p.outcome_check and p.outcome_check.get("verifier") not in (overlay.verifiers or {}):
            out.append(f"pattern {p.id}: outcome verifier {p.outcome_check.get('verifier')!r} is not provided")
        if not p.description:
            out.append(f"pattern {p.id}: no description")
    return out


def golden_cases(path: str | Path) -> list[dict[str, Any]]:
    p = Path(path)
    files = sorted(p.glob("*.yaml")) + sorted(p.glob("*.yml")) if p.is_dir() else [p]
    out = []
    for f in files:
        data = yaml.safe_load(f.read_text(encoding="utf-8")) or []
        for i, case in enumerate(data if isinstance(data, list) else [data]):
            out.append({**case, "_where": f"{f.name}#{i + 1}"})
    return out


def run_golden(engine: Any, path: str | Path, *, run_lookups: bool = True) -> list[str]:
    """Replay golden cases through the read-only trace; returns one line per case that did not go as
    expected (empty: all good)."""
    out = []
    for case in golden_cases(path):
        name = case.get("name") or case["_where"]
        ev = Event.model_validate({"source": "golden", **(case.get("event") or {})})
        t = engine.trace(ev, run_lookups=run_lookups, replay=True)
        exp = case.get("expect") or {}
        got = {"pattern": t["pattern"]["id"], "route": (t.get("route") or {}).get("route"),
               "outcome": t.get("outcome"),
               "actions": [s["action"] for s in ((t.get("playbook") or {}).get("proposal") or {}).get("steps", [])]}
        for k, want in exp.items():
            if got.get(k) != want:
                out.append(f"{name}: {k} expected {want!r}, got {got.get(k)!r} ({'; '.join(t['steps'][-2:])})")
    return out

