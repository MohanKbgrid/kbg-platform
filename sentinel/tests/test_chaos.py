# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""Chaos: random interleavings of every feature in async mode, invariants checked after every step.

Operations: events (several patterns), worker batches, lease expiry (simulated crash), decisions by
authorised AND unauthorised people, SLA sweeps with clock jumps, adapter failures, outcome checks,
reversals, promotion attempts. After every step the invariants below must hold; at the end the queue
is drained and nothing may be left stranded.
"""
from __future__ import annotations

from hypothesis import HealthCheck, given, settings, strategies as st

from sentinel import (ActionResult, AuthorizationError, Decision, DecisionKind, Engine, EngineError, Event,
                      Guardrails, IncidentState as S, LearningPolicy, MemoryEdge, Route)
from tests.conftest import Backend, FakeClock, job_event, make_overlay, new_store, stuck_event
from tests.test_rbac import make_directory

PEOPLE = ["asha", "ravi", "lata", "hari", "hema", "mallory", "gone"]

op = st.one_of(
    st.tuples(st.just("job"), st.sampled_from(["TIMEOUT", "AUTH", "DISK"]), st.integers(0, 4)),
    st.tuples(st.just("stuck"), st.sampled_from(["S1", "S2"]), st.integers(0, 40)),
    st.tuples(st.just("down"), st.sampled_from(["S1", "S2"]), st.just(0)),
    st.tuples(st.just("work"), st.just(""), st.integers(1, 5)),
    st.tuples(st.just("crash"), st.just(""), st.just(0)),
    st.tuples(st.just("decide"), st.sampled_from(["approve", "modify", "reject"]), st.integers(0, 50)),
    st.tuples(st.just("tick"), st.just(""), st.integers(1, 400)),
    st.tuples(st.just("sweep"), st.just(""), st.just(0)),
    st.tuples(st.just("fail"), st.sampled_from(["retry", "hold", "notify"]), st.just(0)),
    st.tuples(st.just("reverse"), st.sampled_from(PEOPLE), st.integers(0, 20)),
    st.tuples(st.just("promote"), st.sampled_from(PEOPLE), st.just(0)),
)


def build(shadow: bool, relaxed: bool = False):
    backend, clock = Backend(), FakeClock()
    ov = make_overlay(backend)
    ov.edges["ask_ai"] = MemoryEdge("ask_ai")
    ov.default_edges = ["ask_ai"]
    verdict = {"v": True}
    ov.verifiers["held"] = lambda incident, disposition, params, services: verdict["v"]
    ov.patterns[0] = ov.patterns[0].model_copy(update={"outcome_check": {"verifier": "held", "after_minutes": 10}})
    eng = Engine(ov, store=new_store(), clock=clock, directory=make_directory(), async_mode=True,
                 guardrails=Guardrails(shadow=shadow, allow_irreversible_unattended=relaxed), retry_base_s=1,
                 learning=LearningPolicy(promote_streak={Route.HITL: 2, Route.LLM: 2}))
    return eng, backend, clock, verdict


@settings(max_examples=150, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(st.lists(op, max_size=70), st.booleans(), st.booleans())
def test_chaos(ops, shadow, relaxed):
    eng, backend, clock, verdict = build(shadow, relaxed)
    try:
        for kind, a, b in ops:
            step(eng, backend, clock, verdict, kind, a, b)
            check(eng, backend, shadow, drained=False, relaxed=relaxed)
        for _ in range(60):                       # drain: everything must come to rest
            clock.advance(seconds=3600)
            if not any(eng.work("drain", limit=50).values()):
                break
        check(eng, backend, shadow, drained=True, relaxed=relaxed)
    finally:
        if hasattr(eng.store, "drop"):
            eng.store.drop()
            eng.store.close()


def step(eng, backend, clock, verdict, kind, a, b):
    if kind == "job":
        eng.ingest(job_event(error=a, ref=f"J{b}", system=["billing", "hr"][b % 2]))
    elif kind == "stuck":
        eng.ingest(stuck_event(site=a, age=b, ref=f"I{b % 3}"))
    elif kind == "down":
        eng.ingest(Event(type="site.down", source="mon", payload={"site": a}))
    elif kind == "work":
        eng.work(f"w{b}", limit=b)
    elif kind == "crash":
        eng.store.lease("crashed-worker", clock(), 3, lease_seconds=1)   # took work, then died
    elif kind == "tick":
        clock.advance(seconds=b)
    elif kind == "sweep":
        eng.sweep()
    elif kind == "fail":
        backend.fail_next.setdefault(a, []).append(ActionResult(ok=False, detail="x", retryable=False))
        verdict["v"] = not verdict["v"]
    elif kind == "decide":
        revs = eng.store.open_reviews()
        if not revs:
            return
        rev = revs[b % len(revs)]
        who = PEOPLE[b % len(PEOPLE)]
        pat = eng.registry.get(eng.store.get_incident(rev.incident_id).pattern_id)
        try:
            if a == "approve" and rev.proposal is not None and rev.proposal.steps:
                eng.decide(rev.id, Decision(kind=DecisionKind.APPROVE, actor=who))
            elif a == "modify" and pat.allowed_actions:
                act = pat.allowed_actions[b % len(pat.allowed_actions)]
                params = {"ref": "R"} if act != "notify" else {"ref": "R", "msg": "m"}
                eng.decide(rev.id, Decision(kind=DecisionKind.MODIFY, actor=who, action=act, params=params))
            else:
                eng.decide(rev.id, Decision(kind=DecisionKind.REJECT, actor=who,
                                            disposition_code=pat.disposition_codes[0]))
        except AuthorizationError:
            pass                                   # refusals are expected; invariants check nothing changed
    elif kind == "reverse":
        done = [d for d in eng.store.dispositions() if not d.reversed and not d.shadow and d.steps]
        if done:
            try:
                eng.reverse(done[b % len(done)].incident_id, actor=a)
            except (AuthorizationError, EngineError):
                pass
    elif kind == "promote":
        for pid, r in eng.report()["patterns"].items():
            if r["pending_promotion"]:
                try:
                    eng.approve_promotion(pid, actor=a)
                except (AuthorizationError, EngineError):
                    pass


def check(eng, backend, shadow, drained, relaxed=False):
    d = eng.directory
    for inc in eng.store.incidents():
        disp = eng.store.get_disposition(inc.id)
        rev = eng.store.open_review_for(inc.id)
        if inc.state is S.DISPOSITIONED:
            assert disp is not None and rev is None
        elif inc.state is S.AWAITING_HUMAN:
            assert rev is not None and disp is None
        elif inc.state is S.SUPPRESSED:
            assert inc.parent_id is not None and disp is None
        elif inc.state is S.OPEN:
            assert not drained, f"{inc.id} stranded OPEN after draining"
            assert eng.store.live_work_for(inc.id, "resolve") >= 1, f"{inc.id} OPEN with no job"
        else:
            raise AssertionError(f"{inc.id} in transient state {inc.state}")
        if shadow and disp is not None:
            assert disp.shadow
    if shadow:
        assert backend.calls == [], "shadow mode executed an action"
    # every human-resolved disposition was made by someone authorised for it at the time
    for disp in eng.store.dispositions():
        if disp.resolver == "human" and disp.actor:
            who = disp.actor.split(":", 1)[1]
            inc = eng.store.get_incident(disp.incident_id)
            assert d.people.get(who) is not None and d.people[who].active, f"{who} decided"
            roles = d.roles_of(who, inc.facts)
            assert roles, f"{who} has no role for {inc.facts}"
        if disp.resolver in ("auto", "llm") and not disp.shadow and not relaxed:
            irreversible = [s.action for s in disp.steps
                            if not (eng.actions.get(s.action).spec.reversible or eng.actions.get(s.action).spec.safe)]
            assert irreversible == [], "irreversible action ran unattended"
    # every successful action attempt maps to exactly one external call
    oks = [a for a in eng.store.audit_log()
           if a["kind"] in ("action_attempt", "compensation_attempt") and a["data"]["ok"]]
    assert len(oks) == len(backend.calls), "a side effect happened that the audit log does not show"
    # cards only ever went to people in scope for the role at the time
    for card in eng.overlay.edges["ask_ai"].cards:
        inc = eng.store.get_incident(card.incident_id)
        assert card.recipient_id is None or d.can_see(card.recipient_id, card.assignee_role, inc.facts)
    # promotions to AUTO were approved by two different people
    for a in eng.store.audit_log():
        if a["kind"] == "promotion_approved" and a["data"]["to"] == "auto":
            assert len(set(a["data"]["approvers"])) == 2
    if drained:
        q = eng.store.queue_stats(eng.clock())["counts"]
        assert q.get("queued", 0) == 0 and q.get("leased", 0) == 0, q
