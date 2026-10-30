# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""Dual run (ADR-004 §4): a candidate pin beside production, compared, never executed.

Two framework versions cannot share one process, so a dual run has two halves:

  1. On each pin (production and candidate, same site data and configuration), trace the same events
     read-only and write one JSON line per event:
         sentinel dualrun trace --events events.jsonl --out prod.jsonl        # under the production pin
         sentinel dualrun trace --events events.jsonl --out candidate.jsonl   # under the candidate pin
  2. Compare them anywhere:
         sentinel dualrun compare prod.jsonl candidate.jsonl
     It lists, per pattern, every event whose match, route, outcome or proposed actions differ, and the
     **trust guard**: patterns whose outcome differs drop one mode (ACT → PROPOSE) on switch-over and earn it
     back. Patterns with no difference keep their trust. The report goes into the client's
     SENTINEL_ADOPTION.md (dual-run table).

Tracing is the engine's read-only ``trace``: nothing is stored, run or sent.
"""
from __future__ import annotations

import json
from collections.abc import Iterable
from pathlib import Path
from typing import Any

FIELDS = ("pattern", "route", "outcome", "actions", "owner_role", "agent_mode")


def summarise(trace: dict[str, Any]) -> dict[str, Any]:
    """What a dual run compares from one trace."""
    pat = trace.get("pattern") or {}
    return {"pattern": pat.get("id"), "owner_role": pat.get("owner_role"),
            "route": (trace.get("route") or {}).get("route"), "outcome": trace.get("outcome"),
            "actions": [s.get("action") for s in ((trace.get("playbook") or {}).get("proposal") or {})
                        .get("steps", [])],
            "agent_mode": (trace.get("agent") or {}).get("mode")}


def trace_events(engine: Any, events: Iterable[Any], *, version: str | None = None) -> list[dict[str, Any]]:
    """One summary line per event, keyed by the event's id (or idempotency key), read-only."""
    from . import __version__
    from .models import Event
    out = []
    for i, ev in enumerate(events):
        given = None if isinstance(ev, Event) else ev.get("id")
        ev = ev if isinstance(ev, Event) else Event.model_validate({"source": "dualrun", **ev})
        # the key must be the same on both pins: the event's own key or id from the file, else its line number
        key = ev.idempotency_key or given or f"#{i}"
        out.append({"key": key, "version": version or __version__,
                    **summarise(engine.trace(ev, replay=True))})
    return out


def compare(production: list[dict[str, Any]], candidate: list[dict[str, Any]]) -> dict[str, Any]:
    """Differences per pattern, and the trust guard (patterns to drop one mode on switch-over)."""
    prod = {r["key"]: r for r in production}
    cand = {r["key"]: r for r in candidate}
    diffs: dict[str, list[dict[str, Any]]] = {}
    missing = sorted(set(prod) ^ set(cand))
    same = 0
    for key in sorted(set(prod) & set(cand)):
        a, b = prod[key], cand[key]
        changed = {f: {"production": a.get(f), "candidate": b.get(f)} for f in FIELDS if a.get(f) != b.get(f)}
        if not changed:
            same += 1
            continue
        for pid in {a.get("pattern"), b.get("pattern")} - {None}:
            diffs.setdefault(pid, []).append({"key": key, "changed": changed})
    outcome_changed = sorted(pid for pid, rows in diffs.items()
                             if any(set(r["changed"]) & {"pattern", "route", "outcome", "actions"} for r in rows))
    versions = {"production": sorted({r.get("version") for r in production} - {None}),
                "candidate": sorted({r.get("version") for r in candidate} - {None})}
    return {"versions": versions, "events": len(set(prod) & set(cand)), "unchanged": same,
            "unpaired": missing, "patterns": {pid: {"differences": len(rows), "examples": rows[:5]}
                                              for pid, rows in sorted(diffs.items())},
            "trust_guard": outcome_changed, "differs": bool(diffs or missing),
            "verdict": ("no differences: adopt with trust kept" if not diffs and not missing else
                        f"{len(outcome_changed)} pattern(s) drop one mode on switch-over" if outcome_changed else
                        "differences in owner or mode only (or unpaired events): review before adopting")}


def read_jsonl(path: str | Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in Path(path).read_text(encoding="utf-8").splitlines() if line.strip()]


def write_jsonl(rows: list[dict[str, Any]], path: str | Path) -> None:
    Path(path).write_text("".join(json.dumps(r, sort_keys=True) + "\n" for r in rows), encoding="utf-8")


__all__ = ["compare", "read_jsonl", "summarise", "trace_events", "write_jsonl"]
