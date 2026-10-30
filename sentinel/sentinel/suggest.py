# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""New exception patterns, drafted from the cases nothing matched.

Unmatched cases of the same event type are grouped by the facts that separate them (facts with few distinct
values; ids and amounts are ignored). For each group with enough cases the draft says how people closed them:
the action most of them took (with its parameters mapped back to the event's fields when they line up) and
the codes they used. The draft starts as human-reviewed (``route: hitl``) and goes into the registry like
any other change, through the console's drafts or ``sentinel config publish``. With a model configured, it
also writes the description and instructions (``task: suggest``); without one the wording is plain.
"""
from __future__ import annotations

import json
import re
from collections import Counter, defaultdict
from datetime import timedelta
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .engine import Engine

UNMATCHED = "__unmatched__"
SKIP = {"event_type", "source"}


def _slug(*parts: Any) -> str:
    s = "_".join(re.sub(r"[^a-z0-9]+", "_", str(p).lower()).strip("_") for p in parts if p not in (None, ""))
    return (s or "new_exception")[:60]


def suggestions(engine: Engine, *, days: int = 30, min_cases: int = 3, limit: int = 2000,
                use_model: bool = True) -> list[dict[str, Any]]:
    since = (engine.clock() - timedelta(days=days)).timestamp()
    cases, cursor = [], None
    while len(cases) < limit:
        page = engine.store.search_incidents(pattern=UNMATCHED, since_ts=since, before=cursor, limit=200)
        if not page:
            break
        cases += page
        cursor = (page[-1].created_at.timestamp(), page[-1].id)
        if len(page) < 200:
            break
    by_type: dict[str, list[Any]] = defaultdict(list)
    for c in cases:
        by_type[c.facts.get("event_type") or c.first_event.get("type") or "?"].append(c)
    known = {p.id for p in engine.registry.all()}
    out = []
    for etype, group in by_type.items():
        keys = {k for c in group for k in c.facts if k not in SKIP}
        distinct = {k: {json.dumps(c.facts.get(k), default=str) for c in group} for k in keys}
        # separating facts: present in most cases, few values (not ids, amounts or timestamps)
        common = {k for k in keys if sum(k in c.facts for c in group) >= 0.8 * len(group)}
        sep = sorted(k for k, vals in distinct.items() if k in common and 1 < len(vals) <= max(3, len(group) // 5))
        clusters: dict[tuple, list[Any]] = defaultdict(list)
        for c in group:
            clusters[tuple((k, c.facts.get(k)) for k in sep)].append(c)
        for sig, members in clusters.items():
            if len(members) < min_cases:
                continue
            out.append(_draft(engine, etype, dict(sig), members, known))
    out.sort(key=lambda x: -x["cases"])
    if use_model and engine.llm is not None:
        for s in out[:10]:
            _word(engine, s)
    return out


def _draft(engine: Engine, etype: str, match: dict[str, Any], members: list[Any], known: set[str]) -> dict[str, Any]:
    codes: Counter = Counter()
    actions: Counter = Counter()
    decided = 0
    steps_seen = []
    for c in members:
        d = engine.store.get_disposition(c.id)
        if d is None:
            continue
        decided += 1
        codes[d.code] += 1
        names = tuple(s.action for s in d.steps if s.action)
        actions[names] += 1
        if names:
            steps_seen.append((c, d.steps))
    pid = _slug(etype, *match.values())
    while pid in known:
        pid += "_2"
    pattern: dict[str, Any] = {"id": pid, "event_types": [etype], "route": "hitl", "owner_role":
                               engine.registry.fallback.owner_role,
                               "disposition_codes": [c for c, _ in codes.most_common(5)] or ["resolved", "no_action"]}
    if match:
        pattern["match"] = match
    common, n = (actions.most_common(1) or [((), 0)])[0]
    if common and n >= 0.6 * max(1, decided):
        pattern["allowed_actions"] = sorted({a for names in actions for a in names})
        params = _map_params(steps_seen, common)
        if params is not None:
            pattern["playbook"] = [{"action": a, "params": p} for a, p in zip(common, params, strict=False)]
            pattern["max_route"] = "auto"
    share = f"{n} of {decided} decided" if decided else "none decided yet"
    where = (" with " + ", ".join(f"{k}={v}" for k, v in match.items())) if match else ""
    pattern["description"] = f"{etype}{where}: {len(members)} unmatched cases"
    fingerprint = None
    if etype not in {r.event_type for r in engine.overlay.fingerprint_rules}:
        payloads = [c.first_event.get("payload") or {} for c in members]
        shared = set.intersection(*[set(p) for p in payloads]) if payloads else set()
        fields = {k: k for k in sorted(shared) if all(isinstance(p[k], str | int | float | bool) for p in payloads)}
        if fields:
            fingerprint = {"event_type": etype, "fields": fields}
    return {"id": pid, "event_type": etype, "match": match, "cases": len(members), "decided": decided,
            "fingerprint": fingerprint, "roles": {pattern["owner_role"]: pattern["owner_role"]},
            "usual_outcome": codes.most_common(1)[0][0] if codes else None,
            "usual_actions": list(common), "usual_share": share,
            "examples": [c.id for c in members[:5]], "pattern": pattern}


def _map_params(seen: list[tuple[Any, list[Any]]], names: tuple[str, ...]) -> list[dict[str, Any]] | None:
    """Template each parameter from the event when every case's value came from the same payload field."""
    rows = [(c, s) for c, s in seen if tuple(x.action for x in s if x.action) == names]
    if not rows:
        return None
    out = []
    for i, _name in enumerate(names):
        keys = set().union(*[set((s[i].params or {}).keys()) for _, s in rows])
        params: dict[str, Any] = {}
        for k in keys:
            vals = [(c.first_event.get("payload") or {}, (s[i].params or {}).get(k)) for c, s in rows]
            fields = None
            for payload, v in vals:
                f = {pk for pk, pv in payload.items() if pv == v}
                fields = f if fields is None else fields & f
            consts = {json.dumps(v, default=str) for _, v in vals}
            if fields:
                params[k] = "{{payload." + sorted(fields)[0] + "}}"
            elif len(consts) == 1:
                params[k] = vals[0][1]
            else:
                return None                            # people chose different values: leave it to them
        out.append(params)
    return out


def _word(engine: Engine, s: dict[str, Any]) -> None:
    """Ask the model for a short description and instructions; keep the plain wording on any failure."""
    prompt = ("Write a JSON object with 'description' (one sentence) and 'llm_instructions' (two or three "
              "sentences for an operations agent) for a new business exception type. Facts: "
              + json.dumps({k: s[k] for k in ("event_type", "match", "cases", "usual_outcome", "usual_actions")},
                           default=str))
    try:
        llm = engine.llm
        client = llm.router.client("suggest") if llm.router is not None else llm.client
        raw = client.complete("You draft configuration. Reply with JSON only.", [{"role": "user", "content": prompt}])
        from .llm import extract_json
        out = extract_json(raw)
        if isinstance(out.get("description"), str):
            s["pattern"]["description"] = out["description"][:300]
        if isinstance(out.get("llm_instructions"), str):
            s["pattern"]["llm_instructions"] = out["llm_instructions"][:1000]
        s["worded_by_model"] = True
    except Exception:  # noqa: BLE001,S110 - plain wording stays
        pass
