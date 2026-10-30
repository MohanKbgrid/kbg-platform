# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""Learning methods of work: propose a better way to handle an exception from what people actually did, test
it on the past, watch it in shadow, and let someone with the authority promote it (or roll it back).

The loop, per exception (learning is scoped to one exception and its own cases; nothing else changes):

1. **Propose** (``propose``). Among recent cases people decided, find the resolution they keep choosing: the
   same actions, with parameters that can be read from the case (a fact, a payload field) or are always the
   same. If it differs from the current playbook and enough cases support it, it becomes a candidate
   method, named after the exception's method with the next version (``stock_push@2``). Only actions the
   exception already allows are used: learning never widens what may be done, and cases whose fix was
   reversed or whose outcome failed are not evidence.
2. **Backtest** (part of proposing). Replay it on every recent decided case: how often would it have done
   what people did, against how often the current method did. Outcomes of the cases where people did it are
   kept with it.
3. **Shadow** (``start_shadow``). While a candidate is in shadow, every case of the exception that a person
   (or the current method) resolves is compared with what the candidate would have done. Nothing it
   proposes is executed.
4. **Promote** (``promote``, needs ``__configure__``). Only a candidate with enough shadow cases at a high
   enough agreement; it is published as an ordinary registry version (maker-checker applies), its playbook
   and method name replacing the old ones. The exception's earned trust resets, because it now means
   something else: the new method earns autonomy on its own record.
4a. **Trial** (``start_trial``), for cause rather than agreement. New cases are assigned at random (a fixed
   share, by the case id): half get the candidate's proposal, half the current method's; every trial case goes
   to a person, whatever the exception has earned. Verified outcomes and handling times are compared between
   the two arms with a 95% interval (``trial_report``): *better*, *worse* or *not clear yet*. Because the
   arms are random, a difference is the method's doing, not the cases'. A candidate the trial shows worse
   cannot be promoted.
5. **Roll back** (``rollback``). Puts the exception's previous definition back, leaving any other change to
   the registry in place.

The system proposes and measures; it never approves its own change.
"""
from __future__ import annotations

import re
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, Field

from .models import PlaybookStep, new_id, utcnow

if TYPE_CHECKING:
    from .engine import Engine

STATE = "__method_candidates__"
STATUSES = ("proposed", "shadow", "trial", "awaiting_approval", "promoted", "rejected", "rolled_back")


class MethodLearnError(ValueError):
    pass


class Candidate(BaseModel):
    id: str = Field(default_factory=lambda: new_id("mth"))
    pattern_id: str
    name: str                                     # e.g. stock_push@2
    replaces: str | None = None                   # the method it would replace
    steps: list[dict[str, Any]]                   # playbook steps (templates)
    disposition_code: str
    status: str = "proposed"
    support: dict[str, Any] = Field(default_factory=dict)     # cases, share, held, failed
    backtest: dict[str, Any] = Field(default_factory=dict)    # candidate vs current on past cases
    shadow: dict[str, Any] = Field(default_factory=lambda: {"cases": 0, "agreed": 0, "seen": []})
    trial: dict[str, Any] = Field(default_factory=dict)        # {share, started_at}
    created_at: datetime = Field(default_factory=utcnow)
    history: list[dict[str, Any]] = Field(default_factory=list)   # who did what, when
    config_version: str | None = None              # the registry version that published it
    previous: dict[str, Any] | None = None         # the exception before promotion (for rollback)

    def playbook(self) -> list[PlaybookStep]:
        return [PlaybookStep.model_validate(s) for s in self.steps]

    def view(self) -> dict[str, Any]:
        d = self.model_dump(mode="json", exclude={"previous"})
        d["shadow"] = {k: v for k, v in d["shadow"].items() if k != "seen"}
        sh = self.shadow
        d["shadow"]["agreement"] = round(sh["agreed"] / sh["cases"], 3) if sh.get("cases") else None
        return d


# ------------------------------------------------------------------------------------------- storage
def _load(engine: Engine) -> dict[str, Candidate]:
    raw = engine.store.get_source_state(STATE) or {}
    return {k: Candidate.model_validate(v) for k, v in (raw.get("candidates") or {}).items()}


def _save(engine: Engine, cands: dict[str, Candidate]) -> None:
    engine.store.put_source_state(STATE, {"candidates": {k: c.model_dump(mode="json") for k, c in cands.items()}})


def _get(cands: dict[str, Candidate], cid: str) -> Candidate:
    if cid not in cands:
        raise MethodLearnError(f"unknown candidate method {cid}")
    return cands[cid]


# ---------------------------------------------------------------------------------------- evidence
def _scope(inc: Any) -> dict[str, Any]:
    return {"payload": (inc.first_event or {}).get("payload", {}) or {}, "facts": inc.facts or {}}


def _norm(steps: list[PlaybookStep] | list[dict[str, Any]]) -> list[tuple[str, tuple[tuple[str, str], ...]]]:
    out = []
    for s in steps:
        s = s if isinstance(s, PlaybookStep) else PlaybookStep.model_validate(s)
        if s.kind != "action":
            continue
        out.append((s.action, tuple(sorted((k, "" if v is None else str(v)) for k, v in s.params.items()))))
    return out


def _evidence(engine: Engine, pattern: Any, since: datetime) -> list[tuple[Any, Any]]:
    """(incident, disposition) for recent cases people decided, that held (or are not yet known)."""
    out = []
    for d in engine.store.dispositions(pattern.id):
        if d.created_at < since or d.resolver not in ("human",) or d.reversed or d.outcome == "failed":
            continue
        inc = engine.store.get_incident(d.incident_id)
        if inc is not None:
            out.append((inc, d))
    return out


def _generalise(action: str, examples: list[tuple[dict[str, Any], dict[str, Any]]]) -> dict[str, Any] | None:
    """Parameter templates that reproduce every example (params, case scope), or None."""
    keys = set(examples[0][0])
    if any(set(p) != keys for p, _ in examples):
        return None
    out: dict[str, Any] = {}
    for k in sorted(keys):
        values = [p[k] for p, _ in examples]
        refs: set[str] | None = None
        for v, (_, sc) in zip(values, examples, strict=True):
            here = {f"facts.{f}" for f, fv in sc["facts"].items() if fv is not None and str(fv) == str(v)}
            here |= {f"payload.{f}" for f, fv in sc["payload"].items()
                     if not isinstance(fv, dict | list) and fv is not None and str(fv) == str(v)}
            refs = here if refs is None else refs & here
        if refs:
            out[k] = "{{" + sorted(refs, key=lambda r: (not r.startswith("facts."), r))[0] + "}}"
        elif all(str(v) == str(values[0]) for v in values):
            out[k] = values[0]
        else:
            return None                       # varies with something the case does not carry: a person's call
    return out


def _render(steps: list[dict[str, Any]], scope: dict[str, Any]) -> list[PlaybookStep] | None:
    from .expr import ExprError, render
    try:
        return [PlaybookStep(action=s["action"], params=render(s.get("params") or {}, scope)) for s in steps]
    except ExprError:
        return None


def _current_agreement(engine: Engine, pattern: Any, ev: list[tuple[Any, Any]]) -> dict[str, Any]:
    pure = pattern.playbook and all(s.kind == "action" and s.when is None for s in pattern.playbook)
    if pure:
        steps = [s.plain() for s in pattern.playbook]
        hits = sum(1 for inc, d in ev if (r := _render(steps, _scope(inc))) is not None and _norm(r) == _norm(d.steps))
        return {"agreement": round(hits / len(ev), 3) if ev else None, "basis": "replayed"}
    known = [d.agreed_with_proposal for _, d in ev if d.agreed_with_proposal is not None]
    return {"agreement": round(sum(known) / len(known), 3) if known else None,
            "basis": "recorded proposals" if known else "no proposal to compare"}


def _next_name(pattern: Any, taken: set[str]) -> tuple[str, str | None]:
    base, ver = (pattern.method or f"{pattern.id}@1"), 1
    m = re.fullmatch(r"(.+)@(\d+)", base)
    if m:
        base, ver = m.group(1), int(m.group(2))
    n = ver + 1
    while f"{base}@{n}" in taken:
        n += 1
    return f"{base}@{n}", pattern.method


# ---------------------------------------------------------------------------------------- propose
def propose(engine: Engine, pattern_id: str | None = None, *, days: int = 90, min_cases: int = 5,
            min_share: float = 0.6) -> list[dict[str, Any]]:
    """Candidate methods from what people chose, backtested on recent cases. Returns the new ones."""
    since = engine.clock() - timedelta(days=days)
    cands = _load(engine)
    pats = [engine.registry.get(pattern_id)] if pattern_id else engine.registry.all()
    new: list[Candidate] = []
    for p in pats:
        if p.id == engine.registry.fallback.id:
            continue
        ev = _evidence(engine, p, since)
        if len(ev) < min_cases:
            continue
        groups: dict[tuple[Any, ...], list[tuple[Any, Any]]] = defaultdict(list)
        for inc, d in ev:
            acts = tuple(s.action for s in d.steps if s.kind == "action")
            if acts and all(a in p.allowed_actions for a in acts):
                groups[acts].append((inc, d))
        current = _norm([s.plain() for s in p.playbook]) if p.playbook else []
        existing = {(c.pattern_id, repr(_norm(c.steps))) for c in cands.values()}
        for acts, rows in groups.items():
            share = len(rows) / len(ev)
            if len(rows) < min_cases or share < min_share:
                continue
            steps = []
            for i, a in enumerate(acts):
                tpl = _generalise(a, [([s for s in d.steps if s.kind == "action"][i].params, _scope(inc))
                                      for inc, d in rows])
                if tpl is None:
                    break
                steps.append({"action": a, "params": tpl})
            if len(steps) != len(acts):
                continue
            if (p.id, repr(_norm(steps))) in existing:
                continue
            renders = {inc.id: _render(steps, _scope(inc)) for inc, _ in ev}
            hits = sum(1 for inc, d in ev if renders[inc.id] is not None and _norm(renders[inc.id]) == _norm(d.steps))
            cur = _current_agreement(engine, p, ev)
            # a candidate that is the current playbook in other words is not new
            if current and all(_norm(_render(steps, _scope(inc)) or []) ==
                               _norm(_render([s.plain() for s in p.playbook], _scope(inc)) or []) for inc, _ in ev):
                continue
            codes = Counter(d.code for _, d in rows)
            name, replaces = _next_name(p, {c.name for c in cands.values() if c.pattern_id == p.id})
            c = Candidate(pattern_id=p.id, name=name, replaces=replaces, steps=steps,
                          disposition_code=codes.most_common(1)[0][0],
                          support={"cases": len(rows), "decided": len(ev), "share": round(share, 3),
                                   "held": sum(d.outcome == "held" for _, d in rows),
                                   "failed": 0, "days": days},
                          backtest={"cases": len(ev), "agreement": round(hits / len(ev), 3),
                                    "current": cur},
                          created_at=engine.clock(),
                          history=[{"at": engine.clock().isoformat(), "by": "learning", "did": "proposed"}])
            cands[c.id] = c
            new.append(c)
            engine.store.audit(None, "method_proposed", {"pattern": p.id, "candidate": c.id, "name": c.name,
                                                         "support": c.support, "backtest": c.backtest})
    if new:
        _save(engine, cands)
        engine.notify("method_proposed", {"candidates": [c.id for c in new]})
    return [c.view() for c in new]


# ----------------------------------------------------------------------------------------- shadow
def observe(engine: Engine, inc: Any, d: Any) -> None:
    """A case of an exception with a candidate in shadow was resolved: would the candidate have agreed?"""
    if d.resolver in ("system", "parent"):
        return
    cands = _load(engine)
    changed = False
    for c in cands.values():
        if c.status != "shadow" or c.pattern_id != inc.pattern_id or inc.id in c.shadow.get("seen", []):
            continue
        r = _render(c.steps, _scope(inc))
        agreed = r is not None and _norm(r) == _norm(d.steps) and not d.reversed
        c.shadow["cases"] = int(c.shadow.get("cases", 0)) + 1
        c.shadow["agreed"] = int(c.shadow.get("agreed", 0)) + int(agreed)
        c.shadow["seen"] = [*c.shadow.get("seen", []), inc.id][-500:]
        changed = True
        engine.store.audit(inc.id, "method_shadow", {"candidate": c.id, "agreed": agreed})
    if changed:
        _save(engine, cands)


# ------------------------------------------------------------------------------------- decisions
def _record(c: Candidate, engine: Engine, actor: str, did: str, note: str = "") -> None:
    c.history.append({"at": engine.clock().isoformat(), "by": actor, "did": did, **({"note": note} if note else {})})
    engine.store.audit(None, f"method_{did}", {"candidate": c.id, "pattern": c.pattern_id, "name": c.name,
                                                "by": actor, "note": note})


def start_shadow(engine: Engine, cid: str, actor: str) -> dict[str, Any]:
    engine._authorize_configure(actor, "registry")
    cands = _load(engine)
    c = _get(cands, cid)
    if c.status not in ("proposed", "rolled_back"):
        raise MethodLearnError(f"{c.name} is {c.status}")
    c.status = "shadow"
    _record(c, engine, actor, "shadow_started")
    _save(engine, cands)
    return c.view()


def reject(engine: Engine, cid: str, actor: str, note: str = "") -> dict[str, Any]:
    engine._authorize_configure(actor, "registry")
    cands = _load(engine)
    c = _get(cands, cid)
    if c.status in ("promoted",):
        raise MethodLearnError(f"{c.name} is live: roll it back instead")
    # rejecting a method in trial ends the trial: new cases all get the current method again
    c.status = "rejected"
    _record(c, engine, actor, "rejected", note)
    _save(engine, cands)
    return c.view()


def _registry_with(engine: Engine, pattern_id: str, change: Any) -> tuple[str, dict[str, Any]]:
    import yaml

    from .config import _load_text, dump_yaml
    data = _load_text(engine.config_text("registry")) or {}
    pats = data.get("patterns") or []
    p = next((x for x in pats if x.get("id") == pattern_id), None)
    if p is None:
        raise MethodLearnError(f"{pattern_id} is not in the registry")
    before = yaml.safe_load(yaml.safe_dump(p))
    change(p)
    return dump_yaml(data), before


def _publish(engine: Engine, text: str, actor: str, note: str) -> tuple[Any, bool]:
    """(version, published). With maker-checker, the version waits for someone else's approval."""
    from .config import ApprovalNeeded, ConfigError
    cv, probs = engine.save_config("registry", text, actor, note)
    errors = [p.message for p in probs if p.severity == "error"]
    if errors:
        raise MethodLearnError(f"the registry would be invalid: {errors[0]}")
    try:
        engine.publish_config(cv.id, actor)
    except ApprovalNeeded:
        return cv, False
    except ConfigError as e:
        raise MethodLearnError(str(e)) from None
    return cv, True


def promote(engine: Engine, cid: str, actor: str, *, min_shadow_cases: int = 10,
            min_agreement: float = 0.8) -> dict[str, Any]:
    """Publish the candidate as the exception's method. It must have earned it in shadow (or in a trial)."""
    engine._authorize_configure(actor, "registry")
    cands = _load(engine)
    c = _get(cands, cid)
    if c.status not in ("shadow", "trial"):
        raise MethodLearnError(f"{c.name} is {c.status}; only a method watched in shadow or tried can be promoted")
    if c.status == "trial":
        rep = trial_report(engine, cid)
        if rep["verdict"] == "worse":
            raise MethodLearnError(f"the trial shows {c.name} worse than the current method: {rep['summary']}")
        if rep["verdict"] != "better":
            raise MethodLearnError(f"the trial has not shown {c.name} better yet: {rep['summary']}")
    n, agreed = int(c.shadow.get("cases", 0)), int(c.shadow.get("agreed", 0))
    if c.status == "shadow" and (n < min_shadow_cases or agreed / n < min_agreement):
        raise MethodLearnError(f"{c.name} has {n} shadow case(s) at {agreed / n if n else 0:.0%} agreement; it needs "
                               f"{min_shadow_cases} at {min_agreement:.0%}")
    pattern = engine.registry.get(c.pattern_id)

    def change(p: dict[str, Any]) -> None:
        p["playbook"] = list(c.steps)
        p["method"] = c.name
        if c.disposition_code in pattern.disposition_codes:
            p["playbook_disposition"] = c.disposition_code

    text, before = _registry_with(engine, c.pattern_id, change)
    cv, published = _publish(engine, text, actor, f"method {c.name} for {c.pattern_id} (learned; promoted by {actor})")
    c.previous, c.config_version = before, cv.id
    c.status = "promoted" if published else "awaiting_approval"
    _record(c, engine, actor, "promoted" if published else "promotion_requested")
    _save(engine, cands)
    return c.view()


def start_trial(engine: Engine, cid: str, actor: str, share: float = 0.5) -> dict[str, Any]:
    """Try the candidate on a random share of new cases, each decided by a person, and compare outcomes."""
    engine._authorize_configure(actor, "registry")
    if not 0.05 <= share <= 0.95:
        raise MethodLearnError("the trial share is between 5% and 95% of new cases")
    cands = _load(engine)
    c = _get(cands, cid)
    if c.status != "shadow":
        raise MethodLearnError(f"{c.name} is {c.status}; watch it in shadow before trying it")
    if any(o.status == "trial" and o.pattern_id == c.pattern_id for o in cands.values()):
        raise MethodLearnError(f"{c.pattern_id} already has a method in trial")
    pattern = engine.registry.get(c.pattern_id)
    if not pattern.outcome_check:
        raise MethodLearnError(f"{c.pattern_id} has no outcome check: a trial needs verified outcomes to compare")
    c.status = "trial"
    c.trial = {"share": share, "started_at": engine.clock().isoformat()}
    _record(c, engine, actor, "trial_started", f"{share:.0%} of new cases")
    _save(engine, cands)
    return c.view()


def assign(engine: Engine, pattern_id: str, incident_id: str) -> Candidate | None:
    """The candidate in trial for this exception if this case falls in its arm (fixed by the case id)."""
    import hashlib
    for c in _load(engine).values():
        if c.status == "trial" and c.pattern_id == pattern_id:
            bucket = int(hashlib.sha256(f"{c.id}:{incident_id}".encode()).hexdigest()[:8], 16) / 0xFFFFFFFF
            return c if bucket < float(c.trial.get("share", 0.5)) else None
    return None


def trial_steps(engine: Engine, cid: str) -> list[PlaybookStep] | None:
    c = _load(engine).get(cid)
    return c.playbook() if c is not None else None


def _arm(ds: list[Any], incidents: dict[str, Any]) -> dict[str, Any]:
    held = sum(d.outcome == "held" for d in ds)
    failed = sum(d.outcome == "failed" for d in ds)
    hours = [(d.created_at - incidents[d.incident_id].created_at).total_seconds() / 3600
             for d in ds if d.incident_id in incidents]
    agreed = [d.agreed_with_proposal for d in ds if d.agreed_with_proposal is not None]
    return {"cases": len(ds), "held": held, "failed": failed,
            "held_rate": round(held / (held + failed), 3) if held + failed else None,
            "hours_to_resolve": round(sum(hours) / len(hours), 2) if hours else None,
            "agreement": round(sum(agreed) / len(agreed), 3) if agreed else None,
            "reversed": sum(d.reversed for d in ds)}


def trial_report(engine: Engine, cid: str, *, min_outcomes: int = 10) -> dict[str, Any]:
    """The two arms of a trial since it started, and whether the candidate's verified outcomes are better."""
    import math
    cands = _load(engine)
    c = _get(cands, cid)
    if not c.trial:
        raise MethodLearnError(f"{c.name} has not been tried")
    since = datetime.fromisoformat(c.trial["started_at"])
    trial, control = [], []
    incidents: dict[str, Any] = {}
    for d in engine.store.dispositions(c.pattern_id):
        if d.created_at < since or d.resolver in ("system", "parent"):
            continue
        inc = engine.store.get_incident(d.incident_id)
        if inc is None or inc.created_at < since:
            continue
        incidents[inc.id] = inc
        (trial if inc.provenance and inc.provenance.trial == cid else control).append(d)
    a, b = _arm(trial, incidents), _arm(control, incidents)
    na, nb = a["held"] + a["failed"], b["held"] + b["failed"]
    out: dict[str, Any] = {"candidate": c.id, "name": c.name, "pattern": c.pattern_id, "share": c.trial.get("share"),
                           "since": c.trial["started_at"], "candidate_arm": a, "current_arm": b,
                           "min_outcomes": min_outcomes}
    if na < min_outcomes or nb < min_outcomes:
        out.update(verdict="not clear yet", difference=None, interval=None,
                   summary=f"{na} and {nb} verified outcomes; {min_outcomes} each are needed")
        return out
    pa, pb = a["held"] / na, b["held"] / nb
    diff = pa - pb
    se = math.sqrt(pa * (1 - pa) / na + pb * (1 - pb) / nb) or 1e-9
    lo, hi = diff - 1.96 * se, diff + 1.96 * se
    verdict = "better" if lo > 0 else "worse" if hi < 0 else "not clear yet"
    out.update(verdict=verdict, difference=round(diff, 3), interval=[round(lo, 3), round(hi, 3)],
               summary=f"outcomes held {pa:.0%} with {c.name} against {pb:.0%} now "
                       f"({diff:+.0%}, 95% interval {lo:+.0%} to {hi:+.0%})")
    return out


def rollback(engine: Engine, cid: str, actor: str, note: str = "") -> dict[str, Any]:
    """Put the exception's definition from before the promotion back; other registry changes stay."""
    engine._authorize_configure(actor, "registry")
    cands = _load(engine)
    c = _get(cands, cid)
    if c.status != "promoted" or c.previous is None:
        raise MethodLearnError(f"{c.name} is {c.status}; only a promoted method can be rolled back")
    prev = c.previous

    def change(p: dict[str, Any]) -> None:
        p.clear()
        p.update(prev)

    text, _ = _registry_with(engine, c.pattern_id, change)
    cv, published = _publish(engine, text, actor, f"roll back method {c.name} on {c.pattern_id}: {note}"[:400])
    c.status = "rolled_back" if published else c.status
    _record(c, engine, actor, "rolled_back" if published else "rollback_requested", note)
    _save(engine, cands)
    return c.view()


def candidates(engine: Engine, pattern_id: str | None = None) -> list[dict[str, Any]]:
    """Candidate methods, newest first. A promotion waiting for approval shows as promoted once published."""
    cands = _load(engine)
    changed = False
    for c in cands.values():
        if c.status == "awaiting_approval" and c.config_version:
            cv = engine.store.get_config_version(c.config_version)
            if cv is not None and cv.status in ("published", "superseded"):
                c.status = "promoted"
                c.history.append({"at": engine.clock().isoformat(), "by": "approval", "did": "promoted"})
                changed = True
    if changed:
        _save(engine, cands)
    out = [c.view() for c in cands.values() if pattern_id is None or c.pattern_id == pattern_id]
    return sorted(out, key=lambda x: x["created_at"], reverse=True)
