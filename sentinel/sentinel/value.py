# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""The value report: time and money Sentinel saved, per exception, in the site's currency.

  automatic       cases resolved by a playbook or the model, executed, not reversed, outcome not failed
  minutes saved   automatic x the exception's effort_minutes (or the site default)
  money saved     minutes saved / 60 x hourly_cost (people.yaml ``value:``)
  model cost      estimated model spend for the exception's cases, converted with model_cost_rate
  net             money saved - model cost

The same rows as the usage export, so the value report and the bill always agree on what was automatic.
"""
from __future__ import annotations

from datetime import timedelta
from typing import TYPE_CHECKING, Any

from .rbac import ValueSettings

if TYPE_CHECKING:
    from .engine import Engine


def settings(engine: Engine) -> ValueSettings:
    d = engine.directory
    return getattr(d, "value", None) or ValueSettings()


def _period(engine: Engine, since: float, until: float, cfg: ValueSettings) -> dict[str, Any]:
    rows = engine.store.usage_rows(since, until)
    effort = {p.id: (p.effort_minutes or cfg.default_minutes) for p in engine.registry.all()}
    per: dict[str, dict[str, Any]] = {}

    def row(pid: str | None) -> dict[str, Any]:
        pid = pid or "(no case)"
        return per.setdefault(pid, {"pattern": pid, "cases": 0, "automatic": 0, "by_people": 0, "reversed": 0,
                                    "shadow": 0, "model_cost": 0.0, "expired": 0, "cleared_at_source": 0})
    for r in rows["incidents"]:
        row(r["pattern_id"])["cases"] += int(r["n"])
    for r in rows["dispositions"]:
        x = row(r["pattern_id"])
        if r["shadow"]:
            x["shadow"] += 1
        elif r["resolver"] in ("auto", "llm"):
            if r["reversed"]:
                x["reversed"] += 1
            elif r["outcome"] != "failed":
                x["automatic"] += 1
        elif r["resolver"] == "human":
            x["by_people"] += 1
        elif r["resolver"] == "system":
            x["expired" if r.get("code") == "expired" else "cleared_at_source"] += 1
    for r in rows["models"]:
        row(r["pattern_id"])["model_cost"] += float(r["cost"] or 0) * cfg.model_cost_rate
    for pid, x in per.items():
        mins = effort.get(pid, cfg.default_minutes)
        x["effort_minutes"] = mins
        x["minutes_saved"] = round(x["automatic"] * mins, 1)
        x["minutes_by_people"] = round(x["by_people"] * mins, 1)
        x["money_saved"] = round(x["minutes_saved"] / 60 * cfg.hourly_cost, 2)
        x["model_cost"] = round(x["model_cost"], 2)
        x["net"] = round(x["money_saved"] - x["model_cost"], 2)
        decided = x["automatic"] + x["by_people"] + x["reversed"]
        x["automation_rate"] = round(x["automatic"] / decided, 3) if decided else None
        settled = x["expired"] + x["cleared_at_source"]
        # people mostly leave it alone: tune it (a narrower match, a clear_when, or shorter expiry) or drop it
        x["tune"] = x["cases"] >= 5 and settled / x["cases"] >= 0.3
    keys = ("cases", "automatic", "by_people", "reversed", "shadow", "minutes_saved", "minutes_by_people",
            "money_saved", "model_cost", "net", "expired", "cleared_at_source")
    total = {k: round(sum(x[k] for x in per.values()), 2) for k in keys}
    decided = total["automatic"] + total["by_people"] + total["reversed"]
    total["automation_rate"] = round(total["automatic"] / decided, 3) if decided else None
    total["hours_saved"] = round(total["minutes_saved"] / 60, 1)
    return {"patterns": sorted(per.values(), key=lambda x: -x["money_saved"]), "total": total}


def report(engine: Engine, *, days: int = 30, weeks: int = 8) -> dict[str, Any]:
    cfg = settings(engine)
    now = engine.clock()
    until = now.timestamp() + 1                       # include what happened this second
    out = _period(engine, (now - timedelta(days=days)).timestamp(), until, cfg)
    trend = []
    for i in range(weeks, 0, -1):
        a, b = now - timedelta(weeks=i), now - timedelta(weeks=i - 1)
        t = _period(engine, a.timestamp(), b.timestamp() + (1 if i == 1 else 0), cfg)["total"]
        trend.append({"week_starting": a.date().isoformat(), "automatic": t["automatic"],
                      "by_people": t["by_people"], "money_saved": t["money_saved"], "net": t["net"]})
    return {"days": days, "currency": cfg.currency, "settings": cfg.model_dump(mode="json"), **out, "trend": trend}
