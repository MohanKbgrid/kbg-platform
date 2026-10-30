# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""Capabilities and methods of work: what the business does, and the evidence for how each part of it is run.

A **capability** (``capabilities:`` in the registry) is a business responsibility - Inventory & Replenishment,
Finance & MIS - with an accountable role, its intent (what it is for and must never do), the metrics that show
whether it works, a ceiling on how far its exceptions may be automated and a mode: ``act``, or ``observe``
(instrumented and measured; every exception in shadow, so nothing happens without a person). The registry's
exceptions belong to capabilities; a role may own several, and a capability may span several roles.

A **method of work** is how an exception is handled: its playbook, the actions allowed, its limits. Exceptions
name theirs (``method: stock_push@2``); whatever the name says, the exact definition is fingerprinted, and every
case records the capability, method, definition and registry version that decided it (``Provenance``). So the
outcomes of two versions of a method can be compared on real cases, a change can be replayed on past cases
before it is published (``Engine.replay``), run in shadow, published under maker-checker, and rolled back by
publishing the earlier version again. Learning proposes; people with the authority decide.

``overview`` is each capability with its exceptions, outcome metrics, cases and how far it has got
(observed, measured, verified, acting). ``methods`` is the evidence per method version.
"""
from __future__ import annotations

from collections import defaultdict
from datetime import timedelta
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .engine import Engine

NONE = "(no capability)"
BEFORE = "(before methods were recorded)"


def _rate(n: int, d: int) -> float | None:
    return round(n / d, 3) if d else None


def _stats(ds: list[Any]) -> dict[str, Any]:
    real = [d for d in ds if d.resolver != "system"]
    agreed = [d.agreed_with_proposal for d in real if d.agreed_with_proposal is not None]
    held = sum(1 for d in real if d.outcome == "held")
    failed = sum(1 for d in real if d.outcome == "failed")
    return {
        "cases": len(real),
        "shadow": sum(1 for d in real if d.shadow),
        "by_resolver": {r: sum(1 for d in real if d.resolver == r) for r in sorted({d.resolver for d in real})},
        "unattended": sum(1 for d in real if d.resolver in ("auto", "llm") and not d.shadow),
        "agreement": _rate(sum(agreed), len(agreed)),
        "reversed": sum(1 for d in real if d.reversed),
        "outcomes": {"held": held, "failed": failed},
        "held_rate": _rate(held, held + failed),
        "closed_by_system": len(ds) - len(real),
    }


def methods(engine: Engine, *, days: int = 90, capability: str | None = None) -> dict[str, Any]:
    """Evidence per (exception, method, definition): cases, who resolved them, agreement with the proposal,
    reversals and verified outcomes. The version running now is marked ``current``."""
    since = engine.clock() - timedelta(days=days)
    groups: dict[tuple[str, str | None, str | None], list[Any]] = defaultdict(list)
    for d in engine.store.dispositions():
        if d.created_at < since or d.pattern_id == engine.registry.fallback.id:
            continue
        pv = d.provenance
        if capability is not None and (pv.capability if pv else None) != capability:
            continue
        groups[(d.pattern_id, pv.method if pv else BEFORE, pv.definition if pv else None)].append(d)
    current: dict[str, tuple[str | None, str]] = {}
    for p in engine.registry.all():
        current[p.id] = (p.method, p.definition_hash(engine._fingerprint_hash(p)))
    rows = []
    for (pid, method, definition), ds in groups.items():
        cap = next((d.provenance.capability for d in ds if d.provenance), None)
        rows.append({"pattern": pid, "capability": cap, "method": method, "definition": definition,
                     "current": definition is not None and current.get(pid, (None, ""))[1] == definition,
                     "first": min(d.created_at for d in ds).isoformat(),
                     "last": max(d.created_at for d in ds).isoformat(),
                     "configs": sorted({d.provenance.config for d in ds if d.provenance and d.provenance.config}),
                     **_stats(ds)})
    rows.sort(key=lambda r: (r["capability"] or "~", r["pattern"], r["first"]))
    return {"days": days, "methods": rows}


def _stage(c: Any, exceptions: list[dict[str, Any]], outcomes: list[dict[str, Any]],
           stats: dict[str, Any]) -> str:
    """How far a capability has got: planned -> observed -> measured -> verified -> acting."""
    if not exceptions and not outcomes:
        return "planned"
    measured = any(o.get("value") is not None for o in outcomes) or any(e["outcome_check"] for e in exceptions)
    if not measured:
        return "observed"
    if not stats["outcomes"]["held"]:
        return "measured"
    if c is not None and c.mode == "act" and any(e["route_now"] != "hitl" and not e["shadow"]
                                                   for e in exceptions):
        return "acting"
    return "verified"


def overview(engine: Engine, *, days: int = 30, person: str | None = None) -> dict[str, Any]:
    """Every capability with its exceptions, outcome metrics, recent cases and stage; exceptions that belong
    to none are listed under ``(no capability)``."""
    from .kpi import KpiError, can_see
    since = engine.clock() - timedelta(days=days)
    by_cap: dict[str, list[Any]] = defaultdict(list)
    for p in engine.registry.all():
        by_cap[p.capability or NONE].append(p)
    disp: dict[str, list[Any]] = defaultdict(list)
    for d in engine.store.dispositions():
        if d.created_at >= since:
            disp[d.pattern_id].append(d)
    open_count: dict[str, int] = defaultdict(int)
    for inc in engine.store.incidents():
        if not inc.state.terminal:
            open_count[inc.pattern_id] += 1
    ids = list(engine.capabilities) + ([NONE] if NONE in by_cap else [])
    out = []
    for cid in ids:
        c = engine.capabilities.get(cid)
        exc = []
        for p in by_cap.get(cid, []):
            exc.append({"id": p.id, "description": p.description, "method": p.method, "owner_role": p.owner_role,
                        "route_now": engine.effective_route(p).value, "max_route": p.max_route.value,
                        "shadow": engine.is_shadow(p), "playbook": bool(p.playbook),
                        "outcome_check": bool(p.outcome_check), "clears_at_source": p.clear_when is not None,
                        "open": open_count.get(p.id, 0)})
        outcomes = []
        kp = engine.kpi
        for m in (c.outcomes if c else []):
            row: dict[str, Any] = {"metric": m}
            md = kp.doc.metrics.get(m) if kp is not None else None
            if md is None:
                row["error"] = "not a configured metric"
            elif not can_see(engine, person, md):
                continue
            else:
                row.update(title=md.title, target=md.target_text())
                try:
                    res = kp.query(m, days=7)
                    row.update(value=res["total"]["value"], text=res["total"]["text"],
                               target_ok=res["total"]["target_ok"], trusted=res.get("trusted", True))
                except KpiError as e:
                    row["error"] = str(e)
            outcomes.append(row)
        ds = [d for p in by_cap.get(cid, []) for d in disp.get(p.id, [])]
        stats = _stats(ds)
        out.append({"id": cid, "title": c.title if c else "Exceptions not yet assigned to a capability",
                    "owner": c.owner if c else None, "description": c.description if c else "",
                    "intent": list(c.intent) if c else [], "mode": c.mode if c else "act",
                    "max_route": c.max_route.value if c else None, "exceptions": exc, "outcomes": outcomes,
                    "open": sum(e["open"] for e in exc), "stats": stats, "stage": _stage(c, exc, outcomes, stats)})
    return {"days": days, "capabilities": out}
