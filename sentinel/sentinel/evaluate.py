# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""Measure a model on past cases before trusting it: replay decided incidents and compare.

    report = evaluate(engine, small_model, limit=200)
    sentinel --models models.yaml ... evaluate --candidate local --limit 200

For each closed case (newest first) whose outcome is known to be right - decided by a person, not
reversed, not failed by its outcome check - the candidate model gets the same masked brief it would
have had at the time (history and similar cases from *before* that case only) and proposes a
resolution. Compared with what was actually done:

  exact   same actions with the same parameters, and the same disposition code
  action  same actions (parameters may differ)
  code    same disposition code

and, where the primary model (e.g. Claude) proposed something for that case, whether the candidate
agrees with it. Each pattern gets a verdict: **ready** when it has at least `min_cases` cases, exact
agreement >= `threshold` and errors <= `max_error_rate`; otherwise **not yet**, with the reason.

Read-only tools run against today's systems, not the systems as they were, so cases that depend on
fast-changing state (stock levels) can score lower than live use would. Nothing is executed.
"""
from __future__ import annotations

import concurrent.futures as cf
import time
from dataclasses import asdict, dataclass, field
from typing import TYPE_CHECKING, Any

from .llm import LLMResolver
from .models import Proposal
from .routing import MeteredClient, model_name

if TYPE_CHECKING:
    from .engine import Engine


@dataclass
class CaseResult:
    incident_id: str
    pattern_id: str
    truth_code: str
    truth_actions: list[str]
    candidate_code: str | None
    candidate_actions: list[str] | None
    exact: bool
    action_match: bool
    code_match: bool
    agrees_with_primary: bool | None
    confidence: float | None
    error: str | None
    latency_ms: float


@dataclass
class EvalReport:
    model: str
    cases: list[CaseResult] = field(default_factory=list)
    by_pattern: dict[str, dict[str, Any]] = field(default_factory=dict)
    overall: dict[str, Any] = field(default_factory=dict)
    settings: dict[str, Any] = field(default_factory=dict)

    def ready_patterns(self) -> list[str]:
        return [p for p, s in self.by_pattern.items() if s["verdict"] == "ready"]

    def to_dict(self, with_cases: bool = False) -> dict[str, Any]:
        out = {"model": self.model, "overall": self.overall, "by_pattern": self.by_pattern, "settings": self.settings}
        if with_cases:
            out["cases"] = [asdict(c) for c in self.cases]
        return out


def _rate(xs: list[bool]) -> float | None:
    return round(sum(xs) / len(xs), 3) if xs else None


def _summary(rows: list[CaseResult], min_cases: int, threshold: float, max_error_rate: float) -> dict[str, Any]:
    n = len(rows)
    answered = [r for r in rows if r.error is None]
    prim = [r.agrees_with_primary for r in rows if r.agrees_with_primary is not None]
    s = {"cases": n, "errors": n - len(answered),
         "exact": _rate([r.exact for r in rows]), "action": _rate([r.action_match for r in rows]),
         "code": _rate([r.code_match for r in rows]),
         "agrees_with_primary": _rate(prim), "compared_with_primary": len(prim),
         "error_rate": _rate([r.error is not None for r in rows]),
         "avg_ms": round(sum(r.latency_ms for r in rows) / n, 1) if n else None}
    reasons = []
    if n < min_cases:
        reasons.append(f"only {n} cases (need {min_cases})")
    if s["exact"] is not None and s["exact"] < threshold:
        reasons.append(f"exact agreement {s['exact']:.2f} below {threshold:.2f}")
    if s["error_rate"] is not None and s["error_rate"] > max_error_rate:
        reasons.append(f"error rate {s['error_rate']:.2f} above {max_error_rate:.2f}")
    s["verdict"] = "ready" if n and not reasons else "not yet"
    s["reasons"] = reasons
    return s


def _primary_proposal(engine: Engine, incident_id: str) -> Proposal | None:
    """What the primary model proposed for this case at the time (from the audit trail)."""
    for a in reversed(engine.store.audit_log(incident_id)):
        if a["kind"] in ("llm_proposal", "llm_diagnosis") and a["data"].get("proposal"):
            try:
                return Proposal.model_validate(a["data"]["proposal"])
            except ValueError:
                return None
    return None


def evaluate(engine: Engine, candidate: Any, *, patterns: list[str] | None = None, limit: int = 100,
             include_unattended: bool = False, min_cases: int = 20, threshold: float = 0.9,
             max_error_rate: float = 0.05, threads: int = 1, timeout_s: float = 120.0) -> EvalReport:
    """Replay up to `limit` known-good closed cases through `candidate` (anything with .complete)."""
    if limit < 1 or threads < 1:
        raise ValueError("limit and threads must be >= 1")
    known = {p.id: p for p in engine.registry.all()}
    if patterns:
        unknown = [p for p in patterns if p not in known]
        if unknown:
            raise ValueError(f"unknown patterns: {unknown}")
    resolvers = ("human", "auto", "llm") if include_unattended else ("human",)
    picked = []
    for d in sorted(engine.store.dispositions(), key=lambda d: d.created_at, reverse=True):
        if len(picked) >= limit:
            break
        if (d.pattern_id in known and (not patterns or d.pattern_id in patterns) and d.resolver in resolvers
                and not d.reversed and d.outcome != "failed" and known[d.pattern_id].allowed_actions):
            picked.append(d)

    name = model_name(candidate)
    runs: list[Any] = []
    sink = engine.router._record if engine.router is not None else runs.append
    resolver = LLMResolver(candidate, engine.actions, engine.overlay.tools, timeout_s=timeout_s,
                           masker=engine.masker)
    by_pattern_hist: dict[str, list[Any]] = {}

    def history_before(d: Any) -> list[Any]:
        if d.pattern_id not in by_pattern_hist:
            by_pattern_hist[d.pattern_id] = sorted(engine.store.dispositions(d.pattern_id), key=lambda x: x.created_at)
        return [x for x in by_pattern_hist[d.pattern_id] if x.created_at < d.created_at][-20:]

    for d in picked:                      # warm the history cache before threads read it
        history_before(d)

    def one(d: Any) -> CaseResult:
        inc = engine.store.get_incident(d.incident_id)
        pattern = known[d.pattern_id]
        event = engine.store.get_event(inc.event_ids[0]) if inc and inc.event_ids else None
        truth_actions = [s.action for s in d.steps]
        client = MeteredClient(candidate, "eval", sink, shadow=True, prices=engine.router.prices
                               if engine.router is not None else None)
        client.incident_id = d.incident_id
        similar = None
        if engine.embedder is not None and inc is not None:
            try:
                similar = engine.similar_cases(inc, pattern, event, before=d.created_at)
            except Exception:  # noqa: BLE001 - evaluate without similar cases if the embedder is down
                similar = None
        t0 = time.perf_counter()
        out = resolver._run(client, inc, pattern, event, history_before(d), engine.overlay.services, similar)
        ms = (time.perf_counter() - t0) * 1000
        p = out.proposal
        if p is None:
            return CaseResult(d.incident_id, d.pattern_id, d.code, truth_actions, None, None, False, False, False,
                              None, None, out.error or "no proposal", round(ms, 1))
        prim = None
        primary = _primary_proposal(engine, d.incident_id)
        if primary is not None:
            prim = primary.same_as(p.steps, p.disposition_code)
        return CaseResult(d.incident_id, d.pattern_id, d.code, truth_actions, p.disposition_code, p.actions,
                          exact=p.same_as(d.steps, d.code), action_match=p.actions == truth_actions,
                          code_match=p.disposition_code == d.code, agrees_with_primary=prim,
                          confidence=p.confidence, error=None, latency_ms=round(ms, 1))

    if threads == 1:
        results = [one(d) for d in picked]
    else:
        with cf.ThreadPoolExecutor(threads, thread_name_prefix="eval") as ex:
            results = list(ex.map(one, picked))

    report = EvalReport(model=name, cases=results,
                        settings={"limit": limit, "min_cases": min_cases, "threshold": threshold,
                                  "max_error_rate": max_error_rate, "include_unattended": include_unattended,
                                  "patterns": patterns})
    for pid in sorted({r.pattern_id for r in results}):
        report.by_pattern[pid] = _summary([r for r in results if r.pattern_id == pid], min_cases, threshold,
                                          max_error_rate)
    report.overall = _summary(results, min_cases, threshold, max_error_rate)
    report.overall["ready_patterns"] = report.ready_patterns()
    engine.store.audit(None, "model_evaluation", {"model": name, "overall": report.overall,
                                                  "by_pattern": {k: {kk: v[kk] for kk in ("cases", "exact",
                                                                                          "verdict")}
                                                                 for k, v in report.by_pattern.items()}})
    return report
