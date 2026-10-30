# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""Hardening: durability across restarts, crash recovery, concurrency, and randomised invariants."""
from __future__ import annotations

import threading

from hypothesis import HealthCheck, given, settings, strategies as st

from sentinel import (Decision, DecisionKind, Engine, Event, Guardrails, IncidentState as S, LearningPolicy,
                      Route, SQLiteStore)
from tests.conftest import new_store, Backend, FakeClock, job_event, make_overlay, stuck_event
from datetime import UTC

# ------------------------------------------------------------------ durability

def test_duplicates_never_reprocess(engine, backend):
    results = [engine.ingest(job_event(key="K1")) for _ in range(5)]
    assert [r.status for r in results] == ["new"] + ["duplicate"] * 4
    assert backend.count("retry") == 1


def test_restart_keeps_reviews_and_learning(tmp_path, backend, clock):
    db = str(tmp_path / "s.db")
    e1 = Engine(make_overlay(backend), store=SQLiteStore(db), clock=clock, guardrails=Guardrails())
    r = e1.ingest(job_event())
    rev_id = e1.store.open_review_for(r.incident_id).id
    e1.store.close()

    e2 = Engine(make_overlay(backend), store=SQLiteStore(db), clock=clock, guardrails=Guardrails())
    assert e2.ingest(job_event()).status == "grouped"       # still open after restart -> grouped into it
    assert e2.ingest(Event(type="job.failed", source="x", idempotency_key=None,
                           id=r.event_id)).status == "duplicate"
    e2.decide(rev_id, Decision(kind=DecisionKind.APPROVE, actor="a"))
    assert e2.store.get_incident(r.incident_id).state is S.DISPOSITIONED
    assert e2.store.get_pattern_state("job_timeout").samples == 1


def _crash_mid_execution(engine, backend, mark_step_done: bool):
    """Simulate: incident moved to RESOLVING, step claimed, process died."""
    from sentinel.models import Proposal, PlaybookStep
    r = engine.ingest(job_event(error="AUTH", ref="J1"))
    inc = engine.store.get_incident(r.incident_id)
    review = engine.store.open_review_for(inc.id)
    review.open = False
    engine.store.put_review(review)
    inc.proposal = Proposal(steps=[PlaybookStep(action="retry", params={"ref": "J1"})], source="human")
    inc.state = S.RESOLVING
    inc.attempts = 1
    engine.store.put_incident(inc)
    key = f"{inc.id}:1:0:retry"
    engine.store.claim_action_run(key, inc.id, "retry")
    if mark_step_done:
        backend.calls.append(("retry", {"ref": "J1"}))
        engine.store.finish_action_run(key, "ok", {"ok": True})
    return inc.id


def test_recover_completes_when_step_known_done(engine, backend):
    inc_id = _crash_mid_execution(engine, backend, mark_step_done=True)
    assert engine.recover(stale_after_s=0) == [inc_id]
    assert engine.store.get_incident(inc_id).state is S.DISPOSITIONED
    assert backend.count("retry") == 1                           # not executed twice
    assert engine.recover(stale_after_s=0) == []                                # idempotent


def test_recover_escalates_when_outcome_unknown(engine, backend):
    inc_id = _crash_mid_execution(engine, backend, mark_step_done=False)
    engine.recover(stale_after_s=0)
    inc = engine.store.get_incident(inc_id)
    assert inc.state is S.AWAITING_HUMAN and backend.count("retry") == 0
    assert "uncertain" in engine.store.open_review_for(inc_id).reason


def test_recover_drives_open_incidents(engine, backend):
    from sentinel.models import Incident
    ev = job_event()
    engine.store.insert_event(ev)
    facts = engine.fp.facts(ev)
    inc = Incident(pattern_id="job_timeout", fingerprint=engine.fp.signature(ev, facts), route=Route.AUTO,
                   event_ids=[ev.id], first_event=ev.model_dump(mode="json"), facts=facts,
                   created_at=engine.clock(), updated_at=engine.clock())   # engine time, not wall-clock time
    engine.store.put_incident(inc)
    engine.recover(stale_after_s=0)
    assert engine.store.get_incident(inc.id).state is S.DISPOSITIONED and backend.count("retry") == 1


def test_transaction_rolls_back(engine):
    import pytest
    with pytest.raises(RuntimeError):
        with engine.store.transaction():
            engine.store.audit(None, "should_vanish")
            raise RuntimeError("boom")
    assert all(a["kind"] != "should_vanish" for a in engine.store.audit_log())

# ------------------------------------------------------------------ concurrency

def _run_threads(n, fn):
    errors = []
    barrier = threading.Barrier(n)

    def wrap(i):
        try:
            barrier.wait()
            fn(i)
        except Exception as e:  # collect, assert later
            errors.append(e)
    ts = [threading.Thread(target=wrap, args=(i,)) for i in range(n)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    return errors


def test_concurrent_duplicates_create_one_incident(engine, backend):
    errors = _run_threads(20, lambda i: engine.ingest(job_event(key="SAME")))
    assert errors == []
    assert len(engine.store.incidents()) == 1 and backend.count("retry") == 1


def test_concurrent_burst_groups_into_one_incident(engine):
    errors = _run_threads(30, lambda i: engine.ingest(job_event(error="AUTH", ref=f"J{i}")))
    assert errors == []
    incs = engine.store.incidents()
    assert len(incs) == 1 and len(engine.store.event_ids(incs[0].id)) == 30


def test_concurrent_decisions_only_one_wins(engine, backend):
    r = engine.ingest(job_event(error="AUTH"))
    rev = engine.store.open_review_for(r.incident_id)
    errors = _run_threads(8, lambda i: engine.decide(rev.id, Decision(
        kind=DecisionKind.MODIFY, actor=f"op{i}", action="retry", params={"ref": "J1"})))
    assert len(errors) == 7 and backend.count("retry") == 1

# ------------------------------------------------------------------ randomised invariants

op = st.one_of(
    st.tuples(st.just("job"), st.sampled_from(["TIMEOUT", "AUTH", "DISK"]), st.integers(0, 3)),
    st.tuples(st.just("stuck"), st.sampled_from(["S1", "S2"]), st.integers(0, 40)),
    st.tuples(st.just("down"), st.sampled_from(["S1", "S2"]), st.just(0)),
    st.tuples(st.just("decide"), st.sampled_from(["approve", "modify", "reject"]), st.integers(0, 5)),
    st.tuples(st.just("tick"), st.just(""), st.integers(1, 300)),
    st.tuples(st.just("fail"), st.sampled_from(["retry", "hold"]), st.just(0)),
    st.tuples(st.just("sweep"), st.just(""), st.just(0)),
)


@settings(max_examples=60, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(st.lists(op, max_size=40), st.booleans(), st.booleans())
def test_invariants_hold_under_random_operations(ops, shadow, strict):
    backend, clock = Backend(), FakeClock()
    store = new_store()
    try:
        _random_run(ops, shadow, strict, backend, clock, store)
    finally:
        if hasattr(store, "drop"):
            store.drop()
            store.close()
            from tests.conftest import _PG_STORES
            if store in _PG_STORES:
                _PG_STORES.remove(store)


def _random_run(ops, shadow, strict, backend, clock, store):
    from sentinel import ActionResult
    eng = Engine(make_overlay(backend), store=store, clock=clock,
                 guardrails=Guardrails(shadow=shadow, allow_irreversible_unattended=not strict),
                 learning=LearningPolicy(promote_streak={Route.HITL: 2, Route.LLM: 2}, auto_promote=True))
    for kind, a, b in ops:
        if kind == "job":
            eng.ingest(job_event(error=a, ref=f"J{b}", system=f"sys{b % 2}"))
        elif kind == "stuck":
            eng.ingest(stuck_event(site=a, age=b, ref=f"I{b % 3}"))
        elif kind == "down":
            eng.ingest(Event(type="site.down", source="mon", payload={"site": a}))
        elif kind == "tick":
            clock.advance(minutes=b)
        elif kind == "fail":
            backend.fail_next.setdefault(a, []).append(ActionResult(ok=False, detail="x", retryable=False))
        elif kind == "sweep":
            eng.sweep()
        else:
            revs = eng.store.open_reviews()
            if not revs:
                continue
            rev = revs[b % len(revs)]
            inc = eng.store.get_incident(rev.incident_id)
            pat = eng.registry.get(inc.pattern_id)
            if a == "approve" and rev.proposal is not None:
                eng.decide(rev.id, Decision(kind=DecisionKind.APPROVE, actor="p"))
            elif a == "modify" and pat.allowed_actions:
                act = pat.allowed_actions[0]
                params = {"ref": "R"} if act != "notify" else {"ref": "R", "msg": "m"}
                eng.decide(rev.id, Decision(kind=DecisionKind.MODIFY, actor="p", action=act, params=params))
            else:
                eng.decide(rev.id, Decision(kind=DecisionKind.REJECT, actor="p",
                                            disposition_code=pat.disposition_codes[0]))
        _check_invariants(eng, backend, shadow, strict)


def _check_invariants(eng, backend, shadow, strict):
    for inc in eng.store.incidents():
        disp = eng.store.get_disposition(inc.id)
        rev = eng.store.open_review_for(inc.id)
        if inc.state is S.DISPOSITIONED:
            assert disp is not None and rev is None
        elif inc.state is S.AWAITING_HUMAN:
            assert rev is not None and disp is None
        elif inc.state is S.SUPPRESSED:
            assert inc.parent_id is not None and disp is None
        else:
            raise AssertionError(f"incident left in transient state {inc.state}")
        if shadow and disp is not None:
            assert disp.shadow
    if shadow:
        assert backend.calls == []
    for d in eng.store.dispositions():
        if strict and d.resolver in ("auto", "llm"):
            irreversible = [s.action for s in d.steps
                            if not (eng.actions.get(s.action).spec.reversible or eng.actions.get(s.action).spec.safe)]
            assert irreversible == [], "irreversible action ran without a human"
        if d.resolver in ("auto", "llm"):
            p = eng.registry.get(d.pattern_id)
            assert all(s.action in p.allowed_actions for s in d.steps)
    # every audit-recorded successful action corresponds to exactly one backend call
    oks = [a for a in eng.store.audit_log() if a["kind"] == "action_attempt" and a["data"]["ok"]]
    assert len(oks) == len(backend.calls)


def test_recover_leaves_fresh_work_alone(engine, backend, clock):
    inc_id = _crash_mid_execution(engine, backend, mark_step_done=True)
    assert engine.recover() == []                                # may still be in a live worker's hands
    clock.advance(seconds=301)
    assert engine.recover() == [inc_id]


def test_v01_database_is_migrated_in_place(tmp_path):
    """A database written by v0.1 (no `unattended` column) opens cleanly and is backfilled."""
    import json as _json
    import sqlite3

    from sentinel.store import SQLiteStore as _S
    db = str(tmp_path / "old.db")
    con = sqlite3.connect(db)
    con.executescript("""
    CREATE TABLE dispositions (id TEXT PRIMARY KEY, incident_id TEXT NOT NULL UNIQUE, pattern_id TEXT NOT NULL,
      body TEXT NOT NULL, created_ts REAL NOT NULL);
    CREATE TABLE reviews (id TEXT PRIMARY KEY, incident_id TEXT NOT NULL, is_open INTEGER NOT NULL,
      due_ts REAL NOT NULL, body TEXT NOT NULL);
    """)
    for i, (res, shadow) in enumerate([("auto", False), ("llm", False), ("human", False), ("auto", True)]):
        body = {"id": f"d{i}", "incident_id": f"i{i}", "pattern_id": "p", "fingerprint": "f", "code": "ok",
                "resolver": res, "shadow": shadow, "created_at": "2026-10-10T09:00:00Z"}
        con.execute("INSERT INTO dispositions VALUES (?,?,?,?,?)", (f"d{i}", f"i{i}", "p", _json.dumps(body), 1e9))
    con.commit()
    con.close()
    st = _S(db)
    from datetime import datetime
    assert st.count_unattended("p", datetime(2000, 1, 1, tzinfo=UTC), cap=100) == 2
    st.close()
    st2 = _S(db)                                  # second open: migration is a no-op
    assert st2.count_unattended("p", datetime(2000, 1, 1, tzinfo=UTC), cap=1) == 1


def test_hung_model_calls_do_not_pile_up(engine_factory):
    import threading as th
    import time as t
    from sentinel import ScriptedLLM
    from sentinel.llm import LLMResolver
    release = th.Event()
    hung = ScriptedLLM(fn=lambda s, m: (release.wait(5), '{"final": {"action": null}}')[1])
    eng = engine_factory(llm=hung, llm_timeout_s=0.05)
    res: LLMResolver = eng.llm
    for i in range(res._pool_size - 1):
        eng.ingest(stuck_event(ref=f"H{i}"))                         # each times out; the call keeps running
    assert res._stuck == res._pool_size - 1
    eng.ingest(stuck_event(ref="H-next"))
    fails = [a["data"]["error"] for a in eng.store.audit_log() if a["kind"] == "llm_failed"]
    assert "still running past their timeout" in fails[-1]           # refused at once, not queued
    release.set()
    for _ in range(100):
        if res._stuck == 0:
            break
        t.sleep(0.02)
    assert res._stuck == 0 and res.late_replies == res._pool_size - 1
