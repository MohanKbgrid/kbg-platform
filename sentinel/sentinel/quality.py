# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""Model cost and quality per exception: what the model costs for each kind of case and how good it is.

Per exception and model: calls, errors, escalations to a stronger model, average latency, spend in the site's
currency; and, from the cases themselves, how often people agreed with the model's proposal and how often
the model's own resolutions were reversed.
"""
from __future__ import annotations

import json
from datetime import timedelta
from typing import TYPE_CHECKING, Any

from .retention import _Q

if TYPE_CHECKING:
    from .engine import Engine


def report(engine: Engine, days: int = 30) -> dict[str, Any]:
    from .value import settings
    cfg = settings(engine)
    since = (engine.clock() - timedelta(days=days)).timestamp()
    q = _Q(engine.store)
    runs = q("SELECT i.pattern_id AS pattern_id, m.task AS task, m.model AS model, COUNT(*) AS calls, "
             "SUM(CASE WHEN m.ok THEN 0 ELSE 1 END) AS errors, "
             "SUM(CASE WHEN m.escalated THEN 1 ELSE 0 END) AS escalated, "
             "SUM(CASE WHEN m.shadow THEN 1 ELSE 0 END) AS shadow, AVG(m.latency_ms) AS latency_ms, "
             "COALESCE(SUM(m.est_cost), 0) AS cost FROM {s}.model_runs m LEFT JOIN {s}.incidents i "
             "ON i.id = m.incident_id WHERE m.ts >= ? GROUP BY i.pattern_id, m.task, m.model", (since,))
    per: dict[str, dict[str, Any]] = {}
    for r in runs:
        pid = r["pattern_id"] or "(no case)"
        x = per.setdefault(pid, {"pattern": pid, "models": [], "calls": 0, "errors": 0, "escalated": 0,
                                 "cost": 0.0, "agreed": 0, "disagreed": 0, "model_resolved": 0,
                                 "model_reversed": 0})
        calls = int(r["calls"])
        x["models"].append({"task": r["task"], "model": r["model"], "calls": calls, "errors": int(r["errors"] or 0),
                            "escalated": int(r["escalated"] or 0), "shadow": int(r["shadow"] or 0),
                            "latency_ms": round(float(r["latency_ms"] or 0)),
                            "cost": round(float(r["cost"] or 0) * cfg.model_cost_rate, 2)})
        x["calls"] += calls
        x["errors"] += int(r["errors"] or 0)
        x["escalated"] += int(r["escalated"] or 0)
        x["cost"] += float(r["cost"] or 0) * cfg.model_cost_rate
    for r in q("SELECT pattern_id, body FROM {s}.dispositions WHERE created_ts >= ?", (since,)):
        d = r["body"] if isinstance(r["body"], dict) else json.loads(r["body"])
        if d.get("proposal_source") != "llm" and d.get("resolver") != "llm":
            continue
        x = per.setdefault(r["pattern_id"], {"pattern": r["pattern_id"], "models": [], "calls": 0, "errors": 0,
                                             "escalated": 0, "cost": 0.0, "agreed": 0, "disagreed": 0,
                                             "model_resolved": 0, "model_reversed": 0})
        if d.get("resolver") == "llm" and not d.get("shadow"):
            x["model_resolved"] += 1
            x["model_reversed"] += bool(d.get("reversed"))
        elif d.get("agreed_with_proposal") is True:
            x["agreed"] += 1
        elif d.get("agreed_with_proposal") is False:
            x["disagreed"] += 1
    for x in per.values():
        x["cost"] = round(x["cost"], 2)
        x["error_rate"] = round(x["errors"] / x["calls"], 3) if x["calls"] else None
        x["escalation_rate"] = round(x["escalated"] / x["calls"], 3) if x["calls"] else None
        judged = x["agreed"] + x["disagreed"]
        x["agreement"] = round(x["agreed"] / judged, 3) if judged else None
        x["reversal_rate"] = round(x["model_reversed"] / x["model_resolved"], 3) if x["model_resolved"] else None
        x["cost_per_case"] = round(x["cost"] / max(1, x["agreed"] + x["disagreed"] + x["model_resolved"]), 2)
    rows = sorted(per.values(), key=lambda x: -x["cost"])
    return {"days": days, "currency": cfg.currency, "patterns": rows,
            "total_cost": round(sum(x["cost"] for x in rows), 2), "total_calls": sum(x["calls"] for x in rows)}
