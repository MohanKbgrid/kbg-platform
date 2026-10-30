# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""Cross-process safety on PostgreSQL (skipped unless SENTINEL_TEST_PG is set).

Six worker processes, each with its own connection, ingest a burst of events for the same
fingerprint plus duplicate deliveries. Advisory locks + unique keys must give exactly one
incident, every event linked once, and the side effect executed once.
"""
from __future__ import annotations

import multiprocessing as mp
import os
import uuid

import pytest

DSN = os.environ.get("SENTINEL_TEST_PG")
pytestmark = pytest.mark.skipif(not DSN, reason="set SENTINEL_TEST_PG to run")


def _worker(schema, worker_id, n, q):
    from sentinel import Engine, Guardrails
    from sentinel.pg_store import PostgresStore
    from tests.conftest import Backend, job_event, make_overlay
    backend = Backend()
    store = PostgresStore(DSN, schema=schema)
    eng = Engine(make_overlay(backend), store=store, guardrails=Guardrails(allow_irreversible_unattended=True))
    statuses = []
    for i in range(n):
        statuses.append(eng.ingest(job_event(error="AUTH", ref=f"w{worker_id}-{i}")).status)   # same fingerprint
        statuses.append(eng.ingest(job_event(key="DUP-1")).status)                              # duplicate delivery
    q.put((statuses, backend.count("retry")))
    store.close()


def test_six_processes_one_incident():
    from sentinel.pg_store import PostgresStore
    schema = f"mp_{uuid.uuid4().hex[:10]}"
    PostgresStore(DSN, schema=schema).close()            # create schema once
    ctx = mp.get_context("spawn")
    q = ctx.Queue()
    procs = [ctx.Process(target=_worker, args=(schema, w, 10, q)) for w in range(6)]
    for p in procs:
        p.start()
    results = [q.get(timeout=120) for _ in procs]
    for p in procs:
        p.join(timeout=60)
    store = PostgresStore(DSN, schema=schema)
    try:
        incs = store.incidents()
        auth = [i for i in incs if i.pattern_id == "job_failed_other"]
        timeout = [i for i in incs if i.pattern_id == "job_timeout"]
        assert len(auth) == 1, "burst for one fingerprint must collapse into one incident"
        assert len(store.event_ids(auth[0].id)) == 60
        assert len(timeout) == 1, "the duplicated delivery must create exactly one incident"
        assert sum(r for _, r in results) == 1, "side effect must run exactly once across all processes"
        assert sum(s.count("duplicate") for s, _ in results) == 59
    finally:
        store.drop()
        store.close()


def _queue_worker(schema, worker_id, q):
    import time as _t
    from sentinel import Engine, Guardrails
    from sentinel.pg_store import PostgresStore
    from tests.conftest import Backend, make_overlay
    backend = Backend()
    store = PostgresStore(DSN, schema=schema)
    eng = Engine(make_overlay(backend), store=store, async_mode=True,
                 guardrails=Guardrails(allow_irreversible_unattended=True, max_unattended_per_hour=1000))
    idle = 0
    while idle < 20:
        stats = eng.work(worker_id, limit=3)
        idle = 0 if any(stats.values()) else idle + 1
        _t.sleep(0.02)
    q.put(backend.count("retry"))
    store.close()


def test_four_processes_share_one_queue():
    """SKIP LOCKED: 4 worker processes drain 60 queued incidents; each is resolved exactly once."""
    from sentinel import Engine, Guardrails
    from sentinel.pg_store import PostgresStore
    from tests.conftest import Backend, job_event, make_overlay
    schema = f"mq_{uuid.uuid4().hex[:10]}"
    store = PostgresStore(DSN, schema=schema)
    producer = Engine(make_overlay(Backend()), store=store, async_mode=True,
                      guardrails=Guardrails(allow_irreversible_unattended=True, max_unattended_per_hour=1000))
    for i in range(60):
        producer.ingest(job_event(ref=f"J{i}", system=f"s{i}"))
    ctx = mp.get_context("spawn")
    q = ctx.Queue()
    procs = [ctx.Process(target=_queue_worker, args=(schema, f"w{n}", q)) for n in range(4)]
    for p in procs:
        p.start()
    total = sum(q.get(timeout=180) for _ in procs)
    for p in procs:
        p.join(timeout=60)
    try:
        from sentinel import IncidentState
        assert total == 60, "every incident's action ran exactly once across processes"
        assert len(store.incidents(IncidentState.DISPOSITIONED)) == 60
        assert store.queue_stats(producer.clock())["counts"] == {"done": 60}
    finally:
        store.drop()
        store.close()
