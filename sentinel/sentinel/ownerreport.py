# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""The monthly owner report: one short message for the business owner about last month.

Cases handled, how many Sentinel resolved on its own, time and money saved, model spend, reversals, overdue
reviews and escalations, and the exceptions that came up most. Sent to the people named (their email, Slack
or Teams edge) or printed. ``SENTINEL_OWNER_REPORT=hari,hema`` makes the maintenance service send it on the
first of each month.
"""
from __future__ import annotations

from datetime import timedelta
from typing import TYPE_CHECKING, Any

from .retention import _Q
from .usage import month_bounds, previous_month

if TYPE_CHECKING:
    from .engine import Engine


def build(engine: Engine, month: str | None = None) -> dict[str, Any]:
    from .value import _period, settings
    month = month or previous_month(engine.clock())
    start, end = month_bounds(month)
    cfg = settings(engine)
    v = _period(engine, start.timestamp(), end.timestamp(), cfg)
    t = v["total"]
    q = _Q(engine.store)
    escalations = int(q("SELECT COUNT(*) AS n FROM {s}.audit WHERE kind = 'escalated' AND ts >= ? AND ts < ?",
                        (start.timestamp(), end.timestamp()))[0]["n"])
    overdue = engine.store.review_counts(engine.clock())["overdue"]
    top = sorted(v["patterns"], key=lambda x: -x["cases"])[:5]
    sym = "₹" if cfg.currency == "INR" else f"{cfg.currency} "

    def money(x: float) -> str:
        return f"{sym}{round(x):,}"
    lines = [f"Sentinel, {start.strftime('%B %Y')} ({engine.overlay.name})", "",
             f"{t['cases']} cases. {t['automatic']} resolved automatically"
             + (f" ({round(t['automation_rate'] * 100)}% of those decided)" if t["automation_rate"] is not None else "")
             + f", {t['by_people']} by people.",
             f"Saved about {t['hours_saved']} hours of people's time, worth {money(t['money_saved'])}; model spend "
             f"{money(t['model_cost'])}; net {money(t['net'])}.",
             f"Reversed: {t['reversed']}. Escalated: {escalations}. Reviews overdue now: {overdue}.", ""]
    if top:
        lines.append("Most frequent exceptions:")
        lines += [f"  {x['pattern']}: {x['cases']} cases, {x['automatic']} automatic" for x in top if x["cases"]]
    return {"month": month, "text": "\n".join(lines).rstrip() + "\n", "totals": t, "escalations": escalations,
            "overdue_now": overdue, "top": top}


def send(engine: Engine, report: dict[str, Any], people: list[str]) -> dict[str, Any]:
    """Send the report to each person over the first of their edges that can carry text."""
    subject = f"Sentinel: {report['month']}"
    sent, skipped = [], []
    d = engine.directory
    for pid in people:
        p = d.people.get(pid) if d is not None else None
        if p is None:
            skipped.append({"person": pid, "reason": "not in the people configuration"})
            continue
        names = list(p.edges) + [n for n in engine.overlay.edges if n not in p.edges]
        for name in names:
            e = engine.overlay.edges.get(name)
            fn = getattr(e, "send_text", None)
            if fn is None:
                continue
            try:
                fn(p.contact, subject, report["text"])
                sent.append({"person": pid, "edge": name})
                break
            except Exception as err:  # noqa: BLE001 - try the next edge
                skipped.append({"person": pid, "edge": name, "reason": str(err)[:200]})
        else:
            if not any(s["person"] == pid for s in sent):
                skipped.append({"person": pid, "reason": "no email, Slack or Teams edge reached them"})
    engine.store.audit(None, "owner_report_sent", {"month": report["month"], "sent": len(sent)})
    return {"sent": sent, "skipped": skipped}


def due(engine: Engine) -> str | None:
    """The month to send, if the report for last month has not gone yet (first days of a month)."""
    month = previous_month(engine.clock())
    st = engine.store.get_source_state("owner_report") or {}
    if st.get("month") == month or engine.clock().day > 7:
        return None
    return month


def mark_sent(engine: Engine, month: str) -> None:
    engine.store.put_source_state("owner_report", {"month": month, "at": (engine.clock() + timedelta()).isoformat()})
