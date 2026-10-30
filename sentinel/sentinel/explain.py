# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""Read-only views for people who need to understand what Sentinel did or would do.

``trace``  runs one event through fingerprinting, matching, grouping, inhibition, routing and the playbook
           without storing anything, acting, or asking a model: "why did this go where it went?". It can
           trace against a draft registry, so a change can be checked before it is published.
``case``   one incident's whole story in time order: events, decisions, model calls, actions, reviews,
           deliveries, the disposition and its outcome, and whether it can still be reversed.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, UTC
from typing import TYPE_CHECKING, Any

from .expr import ExprError, explain_match, matches, render
from .fingerprint import Fingerprinter
from .models import Event, Incident, IncidentState, Pattern, PlaybookStep, Route
from .registry import Registry, ceiling

if TYPE_CHECKING:
    from .engine import Engine


# ============================================================================ trace
def trace(engine: Engine, event: Event, *, registry_text: str | None = None,
          run_lookups: bool = False, replay: bool = False, _built: Any = None) -> dict[str, Any]:
    """What would happen to this event now. Nothing is written; no action runs; no model is called.
    ``run_lookups`` runs the playbook's read-only lookups (tools never change anything); without it the walk
    stops at the first lookup."""
    out: dict[str, Any] = {"event": {"id": event.id, "type": event.type, "source": event.source,
                                     "tenant": event.tenant}, "steps": []}
    if _built is not None:                               # replay: the draft was checked and built once
        registry, fp, rules = _built
        out["draft"] = True
    elif registry_text is not None:
        doc, problems = engine.check_config("registry", registry_text)
        errors = [p.message for p in problems if p.severity == "error"]
        if doc is None or errors:
            return {**out, "draft": True, "error": "the draft registry has errors", "problems": errors}
        registry, fp, rules = Registry(doc.patterns), Fingerprinter(doc.fingerprints), list(doc.fingerprints)
        out["draft"] = True
    else:
        registry, fp, rules = engine.registry, engine.fp, list(engine.overlay.fingerprint_rules)
        out["draft"] = False
    note = out["steps"].append

    # 1. facts and signature
    rule = next((r for r in rules if r.event_type == event.type), None)
    facts = fp.facts(event)
    sig = fp.signature(event, facts)
    out["facts"] = facts
    out["fingerprint"] = {"signature": sig, "rule": rule.model_dump(mode="json") if rule else None}
    missing = [k for k, v in facts.items() if v is None]
    note(f"facts read with the fingerprint rule for {event.type}" if rule else
         f"no fingerprint rule for {event.type}: only event_type and source are known")
    if missing:
        note(f"facts with no value in this event: {missing}")

    # 2. which patterns match, and why the others do not
    cands = []
    for p in registry.all():
        if event.type not in p.event_types:
            continue
        clauses = explain_match(p.match, facts)
        cands.append({"pattern": p.id, "matches": p.matches(event.type, facts), "priority": p.priority,
                      "clauses": clauses})
    pattern = registry.match(event.type, facts)
    off = engine.agent_policy(pattern, facts)
    if off is not None and off.mode == "OFF":
        note(f"{pattern.id} is OFF for this scope (agent policy): it goes to people as unmatched")
        pattern = registry.fallback
    out["candidates"] = cands
    out["pattern"] = {"id": pattern.id, "description": pattern.description, "owner_role": pattern.owner_role,
                      "layer": pattern.layer, **pattern.slot_info()}
    winners = [c["pattern"] for c in cands if c["matches"]]
    if not cands:
        note(f"no pattern handles {event.type}: it goes to {pattern.id} (a person)")
    elif not winners:
        note(f"{len(cands)} pattern(s) handle {event.type} but none matched these facts: {pattern.id} (a person)")
    elif len(winners) > 1:
        note(f"{len(winners)} patterns matched {winners}; {pattern.id} wins (priority, then the most specific)")
    else:
        note(f"matched {pattern.id}")

    # 3. duplicate, grouping, inhibition (not when replaying history: those depend on what was open then)
    store = engine.store
    if not replay and store.get_event(event.id) is not None:
        out["outcome"] = "duplicate"
        note(f"event {event.id} was already received: it would be ignored")
        return out
    now = engine.clock()
    since = (now - timedelta(minutes=pattern.group_window_minutes) if pattern.group_window_minutes
             else datetime.min.replace(tzinfo=now.tzinfo or UTC))
    existing = None if replay else store.find_open_incident(sig, since)
    if existing is not None:
        out["outcome"] = "grouped"
        out["incident"] = existing.id
        note(f"an open incident with the same signature exists ({existing.id}, {existing.state.value}): the "
             "event would be added to it")
        return out
    inc = Incident(tenant=event.tenant, pattern_id=pattern.id, fingerprint=sig, route=pattern.route,
                   event_ids=[event.id], first_event=event.model_dump(mode="json"), facts=facts,
                   created_at=now, updated_at=now)
    if pattern.inhibited_by and not replay:
        parent = engine._inhibitor(pattern, inc)
        if parent is not None:
            out["outcome"] = "suppressed"
            out["parent"] = parent.id
            note(f"suppressed: {parent.id} ({parent.pattern_id}) is open with the same {pattern.inhibit_on}")
            return out

    # 4. route
    route, why = _route(engine, pattern, facts, rules)
    odd = engine._odd_scope_facts(pattern, event)       # the same judgement ingest makes, on the raw payload
    if odd:
        route, why = Route.HITL, why + f"; scope facts {', '.join(odd)} are not plain values, so a person decides"
        inc.odd_facts = odd
        out["odd_facts"] = odd
    inc.route = route
    shadow = engine.is_shadow(pattern, facts)
    pol = engine.agent_policy(pattern, facts)
    if pol is not None:
        out["agent"] = {"id": engine.agent_identity(pattern, facts), "mode": pol.mode, "grants": dict(pol.grants)}
    out["route"] = {"route": route.value, "ceiling": ceiling(pattern).value,
                    "segment": engine.segment_of(pattern, facts), "shadow": shadow, "why": why}
    note(why)
    if shadow:
        note("shadow mode: whatever is proposed goes to a person; nothing runs")

    # 5. what happens next
    proposal, walk = _walk(engine, pattern, inc, run_lookups)
    out["playbook"] = {"steps": walk, "proposal": proposal}
    if route in (Route.AUTO, Route.LLM) and not shadow and not replay:
        n = store.count_unattended(pattern.id, now - timedelta(hours=1), cap=engine.guardrails.max_unattended_per_hour)
        if n >= engine.guardrails.max_unattended_per_hour:
            out["outcome"] = "person"
            note(f"circuit breaker: {n} unattended resolutions in the last hour; a person decides")
            return {**out, **_who(engine, pattern, facts)}
    if route is Route.AUTO:
        if proposal is None:
            out["outcome"] = "person"
            note("the playbook would not produce a resolution here; a person decides")
        else:
            out["outcome"] = _unattended(engine, pattern, proposal, "auto", note, shadow, facts)
    elif route is Route.LLM:
        out["outcome"] = "model"
        note(f"the model is asked for a proposal ({pattern.model_task or 'diagnose'}); it acts alone only with "
             f"confidence of at least {pattern.llm_min_confidence}, at most {pattern.llm_max_steps} step(s), "
             "reversible or safe actions, and within the unattended limits; otherwise a person decides")
    else:
        out["outcome"] = "person"
        if engine.llm is not None and pattern.allowed_actions and pattern.diagnose:
            note("a person decides; the model prepares a proposal for them first")
        else:
            note("a person decides" + (" with the playbook's proposal" if proposal else ""))
    if out["outcome"] in ("person", "model"):
        out.update(_who(engine, pattern, facts))
    return out


def replay(engine: Engine, registry_text: str, *, days: float = 30, limit: int = 2000,
           examples: int = 50) -> dict[str, Any]:
    """Run recent cases' first events through the running registry and through a draft, and report what the
    draft would change: which exception they go to, the route, and the outcome. Read-only; no lookups run."""
    doc, problems = engine.check_config("registry", registry_text)
    errors = [p.message for p in problems if p.severity == "error"]
    if doc is None or errors:
        return {"error": "the draft registry has errors", "problems": errors}
    built = (Registry(doc.patterns), Fingerprinter(doc.fingerprints), list(doc.fingerprints))
    since = engine.clock().timestamp() - days * 86400
    seen, same, changed, tally = 0, 0, [], {}
    cursor = None
    while seen < limit:
        page = engine.store.search_incidents(since_ts=since, before=cursor, limit=min(200, limit - seen))
        if not page:
            break
        cursor = (page[-1].created_at.timestamp(), page[-1].id)
        for inc in page:
            if not inc.first_event:
                continue
            try:
                ev = Event.model_validate(inc.first_event)
            except ValueError:                      # an event stored by an older version: skip it
                continue
            seen += 1
            now = trace(engine, ev, replay=True)
            new = trace(engine, ev, replay=True, _built=built)
            a, b = _gist(now), _gist(new)
            if a == b:
                same += 1
                continue
            for k in a:
                if a[k] != b[k]:
                    label = f"{k}: {a[k]} -> {b[k]}"
                    tally[label] = tally.get(label, 0) + 1
            if len(changed) < examples:
                changed.append({"incident": inc.id, "created_at": inc.created_at.isoformat(), "now": a, "draft": b,
                                "facts": new.get("facts")})
        if len(page) < 200:
            break
    return {"cases": seen, "unchanged": same, "changed": seen - same, "days": days,
            "changes": dict(sorted(tally.items(), key=lambda kv: -kv[1])), "examples": changed,
            "warnings": [p.message for p in problems if p.severity == "warning"][:20]}


def _gist(t: dict[str, Any]) -> dict[str, Any]:
    prop = (t.get("playbook") or {}).get("proposal")
    return {"pattern": t["pattern"]["id"], "route": (t.get("route") or {}).get("route"), "outcome": t.get("outcome"),
            "actions": " then ".join(s["action"] for s in prop["steps"]) if prop else None}


def _route(engine: Engine, pattern: Pattern, facts: dict[str, Any], rules: list[Any]) -> tuple[Route, str]:
    """The route an incident would get now, read without changing any stored trust."""
    seg = engine.segment_of(pattern, facts)
    key = f"{pattern.id}@{seg}" if seg else pattern.id
    st = engine.store.get_pattern_state(key) or (engine.store.get_pattern_state(pattern.id) if seg else None)
    pooled = False
    if seg and pattern.trust_pool_min:
        own = engine.store.get_pattern_state(key)
        if own is None or own.samples < pattern.trust_pool_min:
            st, pooled = engine.store.get_pattern_state(pattern.id), True
            if st is not None and own is not None and own.cap is not None and own.cap.level < st.route.level:
                st = st.model_copy(update={"route": own.cap})
    fph = _fp_hash(rules, pattern)
    current = pattern.definition_hash(fph)
    if st is None:
        route, why = pattern.route, f"no trust earned yet: starts at {pattern.route.value}"
    elif st.definition_hash not in (None, current, pattern.definition_hash()):
        route, why = pattern.route, (f"the pattern's meaning changed since trust was earned: back to "
                                     f"{pattern.route.value}")
    else:
        route, why = st.route, (f"earned route {st.route.value} (streak {st.streak}, {st.samples} decisions)"
                                + (f"; pooled across scopes until {seg} has {pattern.trust_pool_min} of its own"
                                   if pooled else ""))
    cap = ceiling(pattern)
    if route.level > cap.level:
        route, why = cap, why + f"; capped at {cap.value}" + (" (no playbook)" if pattern.max_route is Route.AUTO
                                                                 else "")
    if route is Route.LLM and engine.llm is None:
        route, why = Route.HITL, why + "; no model configured, so a person"
    pol = engine.agent_policy(pattern, facts)
    if pol is not None and pol.mode == "PROPOSE" and route is not Route.HITL:
        route, why = Route.HITL, why + "; agent mode PROPOSE in this scope, so a person approves"
    cap, cwhy = engine.data_trust_cap(pattern, facts)
    if cap == "PROPOSE" and route is not Route.HITL:
        route, why = Route.HITL, why + f"; {cwhy}, so a person approves"
    elif cap == "OBSERVE":
        why += f"; {cwhy}, so it only observes"
    return route, why


def _fp_hash(rules: list[Any], pattern: Pattern) -> str | None:
    picked = sorted((r.model_dump(mode="json") for r in rules if r.event_type in pattern.event_types),
                    key=lambda r: r["event_type"])
    return hashlib.sha256(json.dumps(picked, sort_keys=True).encode()).hexdigest()[:16] if picked else None


def _walk(engine: Engine, pattern: Pattern, inc: Incident,
          run_lookups: bool) -> tuple[dict[str, Any] | None, list[dict[str, Any]]]:
    """The playbook walk, step by step, without side effects."""
    if not pattern.playbook:
        return None, []
    scope: dict[str, Any] = {"payload": inc.first_event.get("payload", {}), "facts": inc.facts,
                             "incident": inc.model_dump(), "now": engine.clock()}
    walk: list[dict[str, Any]] = []
    steps: list[PlaybookStep] = []
    code, closed = None, False
    for i, st in enumerate(pattern.playbook, 1):
        row: dict[str, Any] = {"step": i, "kind": st.kind, "name": st.action or st.lookup or "close"}
        try:
            if st.when is not None and not matches(st.when, scope):
                walk.append({**row, "result": "skipped: condition does not hold", "when": st.when})
                continue
            if st.kind == "lookup":
                args = render(st.args, scope)
                if not run_lookups:
                    walk.append({**row, "result": "stopped: lookup not run (run read-only lookups to go on)",
                                 "args": args})
                    return None, walk
                try:
                    scope[st.result_name] = engine.tools.call(st.lookup, args, engine.overlay.services)
                except Exception as e:  # noqa: BLE001 - shown to the person tracing
                    walk.append({**row, "result": f"lookup failed: {type(e).__name__}: {e}"})
                    return None, walk
                walk.append({**row, "result": "looked up", "args": args, "value": scope[st.result_name]})
                continue
            if st.kind == "close":
                code, closed = st.disposition, True
                walk.append({**row, "result": f"close as {st.disposition}"})
                break
            params = render(st.params, scope)
            steps.append(PlaybookStep(action=st.action, params=params))
            code = st.disposition or code
            walk.append({**row, "result": "would run", "params": params})
        except ExprError as e:
            walk.append({**row, "result": f"error: {e}"})
            return None, walk
    if not steps and not closed:
        return None, walk
    return {"steps": [s.model_dump(exclude_defaults=True) for s in steps],
            "disposition_code": code or pattern.playbook_disposition}, walk


def _unattended(engine: Engine, pattern: Pattern, proposal: dict[str, Any], resolver: str, note: Any,
                shadow: bool, facts: dict[str, Any] | None = None) -> str:
    if shadow:
        return "person"
    pol = engine.agent_policy(pattern, facts)
    steps = [PlaybookStep(**s) for s in proposal["steps"]]
    irrev = engine._irreversible(steps)
    if irrev and not engine.guardrails.allow_irreversible_unattended:
        note(f"{irrev} cannot be undone and are not declared safe: a person approves")
        return "person"
    cap, cwhy = engine.data_trust_cap(pattern, facts)
    if cap is not None:
        note(f"{cwhy}: a person decides")
        return "person"
    held = engine.object_claim(pattern, facts or {}) if pattern.claims else None
    if held is not None:
        note(f"another agent ({held['pattern']}) is acting on {held['object']} until {held['until']}: a person "
             "decides")
        return "person"
    if pol is not None and pol.mode != "ACT":
        note(f"agent mode {pol.mode} in this scope: a person decides")
        return "person"
    if pol is not None and pol.grants and any(st.action and pol.grants.get(st.action) != "EDIT" for st in steps):
        note("the agent has no EDIT grant for every action: a person approves")
        return "person"
    if engine.directory is not None:
        auth = engine.directory.authorize_unattended(resolver, pattern.id, steps)
        if not auth.allowed:
            note(f"over an unattended limit ({auth.reason}): a person approves")
            return "person"
    names = [s.action for s in steps] or ["no action"]
    note(f"resolved automatically: {' then '.join(names)}, closed as {proposal['disposition_code']}")
    return "automatic"


def _who(engine: Engine, pattern: Pattern, facts: dict[str, Any]) -> dict[str, Any]:
    d = engine.directory
    if d is None:
        return {"reviewers": {"role": pattern.owner_role, "people": None}}
    people = d.people_in(pattern.owner_role, facts)
    return {"reviewers": {"role": pattern.owner_role, "escalation_role": pattern.escalation_role,
                          "people": [{"id": p.id, "edge": engine._edge_for(p, pattern.owner_role)} for p in people]}}


# ============================================================================ case
def case(engine: Engine, incident_id: str, *, max_events: int = 50) -> dict[str, Any] | None:
    store = engine.store
    inc = store.get_incident(incident_id)
    if inc is None:
        return None
    try:
        pattern = engine.registry.get(inc.pattern_id)
        pinfo = {"id": pattern.id, "description": pattern.description, "owner_role": pattern.owner_role,
                 **pattern.slot_info()}
    except KeyError:
        pattern, pinfo = None, {"id": inc.pattern_id, "description": "(no longer in the registry)"}
    event_ids = store.event_ids(inc.id) or inc.event_ids
    events = []
    for eid in event_ids[:max_events]:
        ev = store.get_event(eid)
        if ev is not None:
            events.append({"id": ev.id, "type": ev.type, "source": ev.source,
                           "occurred_at": ev.occurred_at.isoformat(), "payload": ev.payload,
                           "correlation_id": ev.correlation_id, "idempotency_key": ev.idempotency_key})
    timeline: list[dict[str, Any]] = []
    for a in store.audit_log(inc.id):
        timeline.append({"ts": a.get("ts"), "kind": a["kind"], "what": _say(a["kind"], a["data"]),
                         "data": a["data"]})
    for m in store.model_runs_for(inc.id):
        timeline.append({"ts": m["ts"], "kind": "model_call",
                         "what": f"{m['task']} on {m['model']}: {'ok' if m['ok'] else 'failed'}"
                                 + (" (shadow)" if m["shadow"] else "") + f", {round(m['latency_ms'])} ms",
                         "data": {k: m[k] for k in ("task", "model", "ok", "shadow", "escalated", "latency_ms",
                                                     "est_cost", "error") if k in m}})
    for r in store.action_runs_for(inc.id):
        timeline.append({"ts": r["created_ts"], "kind": "action_run",
                         "what": f"{r['action']}: {r['status']}", "data": {"action": r["action"], "status":
                                                                            r["status"], "result": r["result"]}})
    reviews = []
    for rv in store.reviews_for_incident(inc.id):
        dl = [d.model_dump(mode="json") if hasattr(d, "model_dump") else d for d in store.deliveries(rv.id)]
        reviews.append({"id": rv.id, "role": rv.assignee_role, "reason": rv.reason, "open": rv.open,
                        "due": rv.due_at.isoformat(), "escalation_level": rv.escalation_level,
                        "proposal": rv.proposal.model_dump(mode="json") if rv.proposal else None,
                        "deliveries": dl})
    timeline.sort(key=lambda t: (t["ts"] is None, t["ts"] or 0))
    d = store.get_disposition(inc.id)
    disp = d.model_dump(mode="json") if d else None
    can_reverse, why_not = False, "not resolved yet"
    if d is not None:
        if d.reversed:
            why_not = "already reversed"
        elif d.shadow:
            why_not = "shadow: nothing was executed"
        else:
            undo = [s.action for s in d.steps if s.action and engine.actions.has(s.action)
                    and engine.actions.get(s.action).compensate is not None]
            cannot = [s.action for s in d.steps if s.action and s.action not in undo]
            can_reverse = True
            why_not = (f"{cannot} cannot be undone automatically; reversing records the mistake and teaches the "
                       "pattern" if cannot else "")
    trace = _decision_trace(inc, pattern, events, timeline, d, store.action_runs_for(inc.id))
    return {"incident": inc.model_dump(mode="json"), "pattern": pinfo, "events": events, "trace": trace,
            "events_total": len(event_ids), "timeline": timeline, "reviews": reviews, "disposition": disp,
            "parent": inc.parent_id, "children": [c.id for c in store.children(inc.id)],
            "reverse": {"possible": can_reverse, "note": why_not},
            "closed": inc.state is IncidentState.DISPOSITIONED}


def _decision_trace(inc: Any, pattern: Pattern | None, events: list[dict[str, Any]],
                    timeline: list[dict[str, Any]], d: Any, runs: list[dict[str, Any]]) -> dict[str, Any]:
    """The case as one chain: what was observed, which capability and method decided it (and under which
    registry version), how it was resolved and by whom, what was done, and whether the outcome was verified.
    ``gaps`` names any link that is missing."""
    pv = inc.provenance
    decisions = [t["data"] for t in timeline if t["kind"] == "decision"]
    outcome_expected = bool(pattern and pattern.outcome_check and d is not None and not d.shadow
                            and (d.steps or d.code in (pattern.outcome_check.get("codes") or [])))
    chain = {
        "observed": [{k: e.get(k) for k in ("id", "type", "source", "occurred_at", "correlation_id",
                                             "idempotency_key")} for e in events[:10]],
        "capability": pv.capability if pv else None,
        "method": pv.method if pv else None,
        "definition": pv.definition if pv else None,
        "config": pv.config if pv else None,
        "route": inc.route.value, "shadow": inc.shadow,
        "proposal": ({"source": inc.proposal.source, "actions": inc.proposal.actions,
                      "confidence": inc.proposal.confidence} if inc.proposal else None),
        "decisions": [{k: x.get(k) for k in ("actor", "kind", "code") if x.get(k) is not None} for x in decisions],
        "resolved": ({"resolver": d.resolver, "actor": d.actor, "code": d.code,
                      "agreed_with_proposal": d.agreed_with_proposal, "at": d.created_at.isoformat()}
                     if d is not None else None),
        "actions": [{"action": r["action"], "status": r["status"]} for r in runs],
        "outcome": ({"verdict": d.outcome, "detail": d.outcome_detail} if d is not None and d.outcome else None),
    }
    gaps = []
    if not chain["observed"]:
        gaps.append("no source event")
    if pv is None and inc.pattern_id != "__unmatched__":
        gaps.append("no record of the method that decided it (opened before methods were recorded)")
    if pv is not None and pv.capability is None:
        gaps.append("the exception belongs to no capability")
    if d is None:
        gaps.append("not resolved yet")
    elif outcome_expected and not d.outcome:
        gaps.append("outcome not verified yet")
    chain["gaps"] = gaps
    chain["complete"] = not gaps
    return chain


_SAY = {
    "created": lambda d: f"opened as {d.get('pattern')} on route {d.get('route')}"
                         + (" (shadow)" if d.get("shadow") else "") + (f", under {d['parent']}" if d.get("parent")
                                                                       else ""),
    "grouped": lambda d: f"another event grouped in (now {d.get('count')})",
    "facts_changed": lambda d: f"facts changed: {', '.join(d.get('changed', {}))}",
    "llm_proposal": lambda d: "the model proposed a resolution",
    "llm_diagnosis": lambda d: "the model prepared a proposal for a person",
    "llm_failed": lambda d: f"the model could not resolve it: {d.get('error')}",
    "possible_prompt_injection": lambda d: "the case text reads like instructions to a model",
    "unattended_limit": lambda d: f"over an unattended limit: {d.get('reason')}",
    "decision": lambda d: f"{d.get('actor') or 'a person'} decided: {d.get('kind')}"
                          + (f" ({d['code']})" if d.get("code") else ""),
    "decision_denied": lambda d: f"decision refused: {d.get('reason')}",
    "reversed": lambda d: f"reversed by {d.get('actor')}",
    "outcome": lambda d: f"outcome check: {d.get('verdict')}",
    "compensation_attempt": lambda d: f"undo {d.get('action')}: {'ok' if d.get('ok') else 'failed'}",
}


def _say(kind: str, data: dict[str, Any]) -> str:
    f = _SAY.get(kind)
    try:
        return f(data) if f else kind.replace("_", " ")
    except Exception:  # noqa: BLE001 - a label, never worth failing the page for
        return kind.replace("_", " ")
