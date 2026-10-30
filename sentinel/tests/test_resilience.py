# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""Staying up: database connections that are cut are replaced, threads work in parallel, nothing waits
forever, and a worker that keeps failing exits so its supervisor restarts it."""
from __future__ import annotations

import os
import threading
import uuid

import pytest

from sentinel.worker import Worker
from tests.conftest import job_event

PG = os.environ.get("SENTINEL_TEST_PG")
needs_pg = pytest.mark.skipif(not PG, reason="needs SENTINEL_TEST_PG")


def _store(**kw):
    from sentinel.pg_store import PostgresStore
    return PostgresStore(PG, schema=f"t_{uuid.uuid4().hex[:12]}", **kw)


def _kill(schema: str) -> int:
    import psycopg
    with psycopg.connect(PG, autocommit=True) as c:
        return len(c.execute("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE application_name = %s",
                             (f"sentinel:{schema}",)).fetchall())


@needs_pg
def test_cut_connections_are_replaced(engine_factory):
    st = _store()
    try:
        eng = engine_factory(store=st)
        eng.ingest(job_event(ref="A", key="a"))
        assert _kill(st.schema) >= 1                         # e.g. a database restart or failover
        r = eng.ingest(job_event(ref="B", key="b", system="other"))     # works without restarting anything
        assert r.status == "new" and st.ping()
        with st.transaction():                               # and transactions too
            st.lock("x")
        assert len(eng.store.incidents()) == 2
    finally:
        st.drop()
        st.close()


@needs_pg
def test_threads_work_in_parallel(engine_factory):
    st = _store(pool_size=4)
    try:
        eng = engine_factory(store=st)
        errors = []

        def go(n):
            try:
                for i in range(15):
                    eng.ingest(job_event(ref=f"{n}-{i}", system=f"s{n}-{i}", key=f"{n}-{i}"))
            except Exception as e:  # noqa: BLE001
                errors.append(e)
        ts = [threading.Thread(target=go, args=(n,)) for n in range(4)]
        for t in ts:
            t.start()
        for t in ts:
            t.join()
        assert errors == [] and len(eng.store.incidents()) == 60
        assert st.pool_stats().get("pool_size", 0) >= 2               # more than one connection was used
    finally:
        st.drop()
        st.close()


@needs_pg
def test_nothing_waits_forever():
    import psycopg
    st = _store(statement_timeout_ms=200)
    try:
        with pytest.raises(psycopg.errors.QueryCanceled):
            st._x("SELECT pg_sleep(2)")
        assert st.ping()                                     # the connection is fine afterwards
    finally:
        st.drop()
        st.close()


def test_worker_exits_after_repeated_failures():
    class Broken:
        def work(self, *a, **k):
            raise RuntimeError("database unreachable")

    w = Worker(Broken(), poll_s=0.001, max_failures=3)          # type: ignore[arg-type]
    stop = threading.Event()
    w.run(stop)                                                  # returns by itself
    assert w.failed and stop.is_set()


def test_worker_recovers_when_failures_stop():
    calls = {"n": 0}

    class Flaky:
        def work(self, *a, **k):
            calls["n"] += 1
            if calls["n"] <= 2:
                raise RuntimeError("blip")
            if calls["n"] > 6:
                stop.set()
            return {"done": 0}

        def sync_config(self):
            return []

        def schedule_sources(self):
            pass

        def recover(self):
            pass

        def sweep(self):
            pass

    stop = threading.Event()
    w = Worker(Flaky(), poll_s=0.001, max_failures=3)            # type: ignore[arg-type]
    w.run(stop)
    assert not w.failed and calls["n"] > 3


@needs_pg
def test_processes_can_refuse_to_migrate(monkeypatch, capsys):
    from sentinel.cli import main
    from sentinel.pg_store import PostgresStore
    schema = f"t_{uuid.uuid4().hex[:12]}"
    with pytest.raises(RuntimeError, match="sentinel migrate"):
        PostgresStore(PG, schema=schema, migrate=False)            # a fresh schema, and migrating is off
    assert main(["--pg", PG, "--schema", schema, "migrate"]) == 0
    assert "version" in capsys.readouterr().out
    st = PostgresStore(PG, schema=schema, migrate=False)           # now current: starts without DDL
    st.drop()
    st.close()
