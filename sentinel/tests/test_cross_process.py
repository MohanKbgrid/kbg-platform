# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""Two API replicas (two engines on one database) cannot both act on a review, and trust updates made at the
same time are not lost (review finding H5)."""
from __future__ import annotations

import os
import threading
import uuid

import pytest

from sentinel import Decision, DecisionKind, EngineError, Guardrails, LearningPolicy, Route
from tests.conftest import job_event

PG = os.environ.get("SENTINEL_TEST_PG")
pytestmark = pytest.mark.skipif(not PG, reason="needs SENTINEL_TEST_PG")


@pytest.fixture
def two_engines(engine_factory):
    from sentinel.pg_store import PostgresStore
    schema = f"t_{uuid.uuid4().hex[:12]}"
    a, b = PostgresStore(PG, schema=schema), PostgresStore(PG, schema=schema)
    pol = LearningPolicy(promote_streak={Route.HITL: 1000})
    ea = engine_factory(store=a, guardrails=Guardrails(allow_irreversible_unattended=True), learning=pol)
    eb = engine_factory(store=b, guardrails=Guardrails(allow_irreversible_unattended=True), learning=pol)
    yield ea, eb
    a.drop()
    a.close()
    b.close()


def test_one_review_is_decided_once(two_engines, backend):
    ea, eb = two_engines
    ea.set_route("job_timeout", Route.HITL, actor="setup")
    r = ea.ingest(job_event(ref="J1", key="j1"))
    rev = ea.store.open_review_for(r.incident_id)
    results, start = [], threading.Barrier(2)

    def decide(eng):
        start.wait()
        try:
            eng.decide(rev.id, Decision(kind=DecisionKind.APPROVE, actor="op"))
            results.append("ok")
        except EngineError as e:
            results.append(str(e))
    ts = [threading.Thread(target=decide, args=(e,)) for e in (ea, eb)]
    for t in ts:
        t.start()
    for t in ts:
        t.join(30)
    assert results.count("ok") == 1 and backend.calls == [("retry", {"ref": "J1"})]


def test_trust_updates_are_not_lost(two_engines):
    ea, eb = two_engines
    ea.set_route("job_timeout", Route.HITL, actor="setup")
    reviews = []
    for i in range(16):
        r = ea.ingest(job_event(ref=f"J{i}", system=f"s{i}", key=f"k{i}"))
        reviews.append(ea.store.open_review_for(r.incident_id).id)

    def work(eng, ids):
        for rid in ids:
            eng.decide(rid, Decision(kind=DecisionKind.APPROVE, actor="op"))
    ts = [threading.Thread(target=work, args=(ea, reviews[0::2])), threading.Thread(target=work, args=(eb, reviews[1::2]))]
    for t in ts:
        t.start()
    for t in ts:
        t.join(60)
    assert ea.store.get_pattern_state("job_timeout").streak == 16


def test_circuit_breaker_holds_across_processes(engine_factory, overlay, backend):
    """H14: several workers in several processes cannot overshoot max_unattended_per_hour together."""
    import time

    from sentinel.pg_store import PostgresStore
    orig = backend.do

    def slow(name, params):
        time.sleep(0.15)
        return orig(name, params)
    backend.do = slow
    schema = f"t_{uuid.uuid4().hex[:12]}"
    stores = [PostgresStore(PG, schema=schema) for _ in range(3)]
    g = Guardrails(allow_irreversible_unattended=True, max_unattended_per_hour=3)
    engines = [engine_factory(store=s, guardrails=g, async_mode=True) for s in stores]
    for i in range(12):
        engines[0].ingest(job_event(error="TIMEOUT", ref=f"B{i}", system=f"s{i}", key=f"b{i}"))
    threads = [threading.Thread(target=lambda e=e, n=n: [e.work(f"w{n}{k}", limit=4) for k in range(4)])
               for n, e in enumerate(engines * 2)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    auto = [d for d in stores[0].dispositions("job_timeout") if d.resolver == "auto"]
    assert len(auto) == 3 and len(backend.calls) == 3
    assert len(stores[0].open_reviews()) == 9
    stores[0].drop()
    for s in stores:
        s.close()
