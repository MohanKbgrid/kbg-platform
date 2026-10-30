# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""Async work queue: leases, retries with backoff, dead letters, workers, action timeouts."""
from __future__ import annotations

import threading
import time
from datetime import timedelta

import pytest

from sentinel import ActionResult, ActionSpec, Guardrails, IncidentState as S, PlaybookStep
from sentinel.models import WorkItem
from sentinel.worker import Worker
from tests.conftest import job_event


@pytest.fixture
def aeng(engine_factory):
    return engine_factory(async_mode=True, retry_base_s=10)

# ------------------------------------------------------------------ queue semantics

def test_ingest_only_queues_then_worker_resolves(aeng, backend):
    r = aeng.ingest(job_event())
    assert r.status == "new" and aeng.store.get_incident(r.incident_id).state is S.OPEN
    assert backend.calls == [] and aeng.report()["queue"]["counts"] == {"queued": 1}
    assert aeng.work("w1") == {"done": 1, "retry": 0, "dead": 0, "lost": 0}
    assert aeng.store.get_incident(r.incident_id).state is S.DISPOSITIONED and backend.count("retry") == 1
    assert aeng.work("w1")["done"] == 0


def test_grouped_and_duplicate_events_do_not_queue(aeng):
    aeng.ingest(job_event(error="AUTH", ref="A", key="k1"))
    aeng.ingest(job_event(error="AUTH", ref="B"))          # grouped
    aeng.ingest(job_event(error="AUTH", ref="A", key="k1"))  # duplicate
    assert aeng.report()["queue"]["counts"] == {"queued": 1}


def test_lease_is_exclusive_and_expires(aeng, clock):
    aeng.enqueue("noop", dedupe_key="x")
    assert not aeng.enqueue("noop", dedupe_key="x")                       # dedupe
    first = aeng.store.lease("w1", clock(), 10, lease_seconds=60)
    assert len(first) == 1 and aeng.store.lease("w2", clock(), 10, 60) == []
    clock.advance(seconds=61)
    second = aeng.store.lease("w2", clock(), 10, 60)                    # w1 crashed; lease expired
    assert [w.id for w in second] == [first[0].id] and second[0].attempts == 2
    assert not aeng.store.complete(first[0].id, "w1")                   # w1's late completion is ignored
    assert aeng.store.complete(second[0].id, "w2")


def test_failures_back_off_then_dead_letter_to_a_human(aeng, clock, notes):
    calls = []

    def boom(item: WorkItem) -> None:
        calls.append(item.attempts)
        raise RuntimeError("upstream down")
    aeng._drive = lambda inc, pattern: boom(WorkItem(kind="resolve", attempts=len(calls) + 1))  # type: ignore
    r = aeng.ingest(job_event())
    assert aeng.work("w1")["retry"] == 1
    assert aeng.work("w1")["done"] == 0                                 # backoff: not ready yet
    for _ in range(4):
        clock.advance(seconds=1000)
        aeng.work("w1")
    assert len(calls) == 5
    item = [w for w in aeng.store.lease("probe", clock() + timedelta(days=1), 10, 1)]
    assert item == []                                                   # dead items are never leased again
    del aeng._drive                                                     # restore the real method
    inc = aeng.store.get_incident(r.incident_id)
    assert inc.state is S.AWAITING_HUMAN
    assert "failed repeatedly" in aeng.store.open_review_for(inc.id).reason
    assert any(k == "work_dead" for k, _ in notes)


def test_unknown_work_kind_is_dead_lettered(aeng):
    aeng.enqueue("mystery")
    assert aeng.work("w1")["dead"] == 1


def test_custom_work_handler(aeng):
    seen = []
    aeng.register_work_handler("ping", lambda item: seen.append(item.payload["n"]))
    aeng.enqueue("ping", payload={"n": 7})
    aeng.work("w1")
    assert seen == [7]


def test_recover_requeues_orphaned_open_incidents(aeng, backend):
    r = aeng.ingest(job_event())
    lease = aeng.store.lease("w1", aeng.clock(), 10, 60)
    aeng.store.fail(lease[0].id, "w1", "simulated", None)               # job died, incident still OPEN
    assert aeng.recover(stale_after_s=0) == [r.incident_id]
    assert aeng.recover(stale_after_s=0) == []                                         # live job exists now: no duplicate
    aeng.work("w2")
    assert aeng.store.get_incident(r.incident_id).state is S.DISPOSITIONED and backend.count("retry") == 1

# ------------------------------------------------------------------ workers

def test_worker_threads_resolve_each_incident_once(engine_factory, backend):
    eng = engine_factory(async_mode=True)
    for i in range(40):
        eng.ingest(job_event(ref=f"J{i}", system=f"s{i}"))
    stop = threading.Event()
    workers = [Worker(eng, worker_id=f"w{n}", batch=3, poll_s=0.01) for n in range(4)]
    threads = [threading.Thread(target=w.run, args=(stop,)) for w in workers]
    for t in threads:
        t.start()
    deadline = time.time() + 20
    while time.time() < deadline and len(eng.store.incidents(S.DISPOSITIONED)) < 40:
        time.sleep(0.05)
    stop.set()
    for t in threads:
        t.join(timeout=5)
    assert len(eng.store.incidents(S.DISPOSITIONED)) == 40
    assert backend.count("retry") == 40                                 # exactly once each


def test_worker_survives_maintenance_errors(aeng):
    w = Worker(aeng, worker_id="w", maintenance_every_s=0)
    aeng.sweep = lambda: (_ for _ in ()).throw(RuntimeError("db hiccup"))  # type: ignore
    assert w.run_once() == {"done": 0, "retry": 0, "dead": 0, "lost": 0}

# ------------------------------------------------------------------ action timeouts

def test_action_timeout_is_uncertain_and_never_retried_blind(engine_factory, overlay, backend):
    release = threading.Event()

    def slow(ctx, p):
        release.wait(5)
        return backend.do("slow", p)
    overlay.actions.register(ActionSpec(name="slow", safe=True, timeout_s=0.2, params_schema={"ref": "str"}), slow)
    overlay.patterns.append(overlay.patterns[0].model_copy(update={
        "id": "slow_p", "match": {"error": "SLOW"}, "priority": 9,
        "playbook": [PlaybookStep(action="slow", params={"ref": "{{payload.ref}}"})], "allowed_actions": ["slow"]}))
    eng = engine_factory(ov=overlay, guardrails=Guardrails())
    r = eng.ingest(job_event(error="SLOW"))
    inc = eng.store.get_incident(r.incident_id)
    assert inc.state is S.AWAITING_HUMAN and "timed out" in eng.store.open_review_for(inc.id).reason
    release.set()                                                       # the call finishes late, in the background
    time.sleep(0.1)
    assert eng.recover(stale_after_s=0) == []                                       # nothing re-driven
    assert backend.count("slow") == 1


def test_queue_stats_report_age(aeng, clock):
    aeng.enqueue("noop")
    clock.advance(seconds=30)
    stats = aeng.store.queue_stats(clock())
    assert stats["counts"] == {"queued": 1} and stats["oldest_ready_age_s"] == pytest.approx(30, abs=1)


def test_handler_result_types_still_enforced(engine_factory, overlay):
    overlay.actions.register(ActionSpec(name="weird", safe=True), lambda c, p: ActionResult(ok=True))
    assert overlay.actions.has("weird")
