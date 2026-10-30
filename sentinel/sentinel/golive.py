# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""Going live: is this site ready, pattern by pattern, and the switch that moves a pattern out of shadow.

A site goes live in three moves: connect (sources deliver events, people can receive cards, a model is
set up), watch in shadow (Sentinel proposes, people decide, agreement is measured), then switch patterns
live one at a time once they have enough shadow cases at a high enough agreement. The switch is an ordinary
published registry change (``shadow: true`` / removed), so it is versioned, audited and, with maker-checker,
needs a second person.
"""
from __future__ import annotations

from datetime import datetime, timedelta, UTC
from typing import TYPE_CHECKING, Any

import yaml

from .models import Route
from .registry import ceiling

if TYPE_CHECKING:
    from .engine import Engine

MIN_SHADOW_CASES = 20
MIN_AGREEMENT = 0.9


def readiness(engine: Engine, *, min_cases: int = MIN_SHADOW_CASES,
              min_agreement: float = MIN_AGREEMENT) -> dict[str, Any]:
    now = engine.clock()
    store = engine.store
    checks: list[dict[str, Any]] = []

    def check(area: str, item: str, ok: bool | None, detail: str = "") -> None:
        checks.append({"area": area, "item": item, "ok": ok, "detail": detail})

    # ---- connect -----------------------------------------------------------------------------------
    sources = []
    for name, s in engine.sources.items():
        st = store.get_source_state(name) or {}
        healthy = None if s.kind == "webhook" else (bool(st.get("last_run")) and not st.get("last_error"))
        sources.append({"name": name, "kind": s.kind, "enabled": s.enabled, "ok": healthy,
                        "last_run": st.get("last_run"), "last_error": st.get("last_error"),
                        "events": st.get("total_events", 0)})
    receivers = sorted(engine.overlay.receivers)
    check("connect", "Events can arrive", bool(sources or receivers),
          f"{len(sources)} configured source(s), {len(receivers)} webhook receiver(s) in the overlay")
    broken = [s["name"] for s in sources if s["enabled"] and s["ok"] is False]
    if sources:
        check("connect", "Sources are fetching without errors", not broken,
              f"failing: {broken}" if broken else "every polled source's last fetch worked")
    recent = store.search_incidents(since_ts=(now - timedelta(days=7)).timestamp(), limit=1)
    check("connect", "Cases arrived in the last 7 days", bool(recent),
          "" if recent else "nothing yet: check the sources and the event types the fingerprints expect")
    edges = sorted(engine.overlay.edges)
    check("connect", "Review cards can reach people", bool(edges) or None,
          f"edges: {edges}" if edges else "no edges: people work in the console only (fine for a pilot)")
    model = engine.llm is not None
    budget = getattr(engine.router, "daily_budget", None) if engine.router else None
    check("connect", "A model is set up", model or None,
          ("with a daily budget" if budget else "no daily budget set") if model else "no model: every case goes to "
                                                                                  "a person or a playbook")

    # ---- people -------------------------------------------------------------------------------------
    d = engine.directory
    if d is None:
        check("people", "People and roles are configured", False, "open mode: anyone with a token can do anything")
    else:
        owners = sorted({p.owner_role for p in engine.registry.all()} | {engine.registry.fallback.owner_role})
        empty = [r for r in owners if r in d.roles and not any(
            a.role_id == r and a.person_id in d.people and d.people[a.person_id].active for a in d.assignments)]
        unknown = [r for r in owners if r not in d.roles]
        check("people", "Every exception has someone to decide it", not empty and not unknown,
              f"no active person in {empty}" if empty else f"unknown roles {unknown}" if unknown else
              f"{len(owners)} owner role(s) staffed")
        admins = [p.id for p in d.people.values() if p.active and d.authorize_meta(p.id, "__configure__",
                                                                                     "config:registry").allowed]
        check("people", "At least two people can configure", len(admins) >= 2, f"{admins}")
        check("people", "Configuration changes need a second person", d.config_approval is not None or None,
              "config_approval is on" if d.config_approval else "recommended before go-live (config_approval)")
        if edges:
            unreachable = sorted({a.person_id for a in d.assignments if a.person_id in d.people
                                  and d.people[a.person_id].active and a.role_id in owners
                                  and engine._edge_for(d.people[a.person_id], a.role_id) is None})
            check("people", "Deciders can be reached on an edge", not unreachable or None,
                  f"console only: {unreachable}" if unreachable else "")

    # ---- patterns ------------------------------------------------------------------------------------
    report = engine.report()["patterns"]
    stats = store.disposition_stats()
    patterns = []
    for p in engine.registry.all():
        r = report.get(p.id, {})
        c = stats.get(p.id, {})
        shadow_n = int(c.get("shadow_n", 0) or 0)
        agree = r.get("shadow_agreement")
        shadow = engine.is_shadow(p)
        code_shadow = engine.guardrails.is_shadow(p.id)
        if not shadow:
            state = "live"
        elif shadow_n < min_cases:
            state = "collecting"
        elif agree is not None and agree >= min_agreement:
            state = "ready"
        else:
            state = "below_agreement"
        acts_alone = ceiling(p).level > Route.HITL.level
        patterns.append({"id": p.id, "description": p.description, "state": state, "shadow": shadow,
                         "shadow_in_code": code_shadow, "shadow_cases": shadow_n, "agreement": agree,
                         "route": r.get("route"), "ceiling": ceiling(p).value, "decided": r.get("dispositions", 0),
                         "outcome_check": bool(p.outcome_check), "can_act_alone": acts_alone})
    for x in patterns:
        if x["can_act_alone"] and not x["outcome_check"]:
            check("patterns", f"{x['id']}: fixes are checked afterwards", None,
                  "no outcome_check: a fix that did not hold is noticed only when the problem comes back")
    live = [x["id"] for x in patterns if x["state"] == "live"]
    weak = [x["id"] for x in patterns if x["state"] == "live" and x["shadow_cases"] < min_cases]
    check("patterns", "Live exceptions were proven in shadow first", not weak or None,
          f"went live with fewer than {min_cases} shadow cases: {weak}" if weak else f"{len(live)} live")

    # ---- operations ----------------------------------------------------------------------------------
    backups = store.recent_audit(1, ["backup_made"])
    if backups:
        age_h = (now.timestamp() - float(backups[0]["ts"])) / 3600
        check("operations", "A recent backup exists", age_h < 36, f"last backup {age_h:.0f} hours ago")
    else:
        check("operations", "A recent backup exists", False, "no backup recorded: run the maintenance service")
    counts = store.review_counts(now)
    overdue = counts.get("overdue", 0)
    check("operations", "Reviews are being worked", overdue == 0 or None,
          f"{counts.get('open', 0)} open, {overdue} past their SLA")
    total = sum(v.get("n", 0) for v in stats.values())
    unmatched = stats.get(engine.registry.fallback.id, {}).get("n", 0)
    if total:
        share = unmatched / total
        check("operations", "Most cases match an exception", share <= 0.1 or None,
              f"{share:.0%} unmatched ({unmatched} of {total}): add patterns for the common ones")
    from .retention import _Q
    aq = _Q(store)
    stale = int(aq("SELECT COUNT(*) AS n FROM {s}.audit WHERE chain_no IS NULL AND ts < ?",
                   (now.timestamp() - 3600,))[0]["n"])
    seals = int(aq("SELECT COUNT(*) AS n FROM {s}.audit_seals")[0]["n"])
    check("operations", "The audit trail is sealed", stale == 0 and (seals > 0 or None),
          f"{stale} rows older than an hour are not sealed: is a worker running?" if stale else
          f"{seals} seals" if seals else "nothing sealed yet")
    q = store.queue_stats(now)
    dead = int((q.get("counts") or {}).get("dead", 0))
    check("operations", "No background work has given up", not dead, f"{dead} dead work item(s)" if dead else "")

    blocking = [c for c in checks if c["ok"] is False]
    return {"checked_at": now.astimezone(UTC).isoformat() if isinstance(now, datetime) else str(now),
            "thresholds": {"min_shadow_cases": min_cases, "min_agreement": min_agreement},
            "sources": sources, "patterns": patterns, "checks": checks, "blocking": len(blocking),
            "ready": [x["id"] for x in patterns if x["state"] == "ready"]}


def set_shadow(engine: Engine, pattern_ids: list[str], shadow: bool, actor: str, note: str = "") -> Any:
    """Publish the running registry with these patterns moved into (or out of) shadow. Goes through the
    normal configuration path: checked, versioned, audited, and subject to maker-checker."""
    doc = yaml.safe_load(engine.config_text("registry")) or {}
    known = {p.get("id") for p in doc.get("patterns") or []}
    missing = [i for i in pattern_ids if i not in known]
    if missing:
        from .engine import EngineError
        raise EngineError(f"unknown patterns {missing}")
    for p in doc.get("patterns") or []:
        if p.get("id") in pattern_ids:
            if shadow:
                p["shadow"] = True
            else:
                p.pop("shadow", None)
    from .config import dump_yaml
    verb = "into shadow" if shadow else "live"
    cv, _ = engine.save_config("registry", dump_yaml(doc), actor,
                               note or f"{', '.join(pattern_ids)} {verb}")
    return engine.publish_config(cv.id, actor=actor)
