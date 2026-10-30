# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""Throughput and latency of the engine on this machine.

    python examples/loadtest.py                 # SQLite file
    python examples/loadtest.py --pg <dsn>      # PostgreSQL

Measures: synchronous ingest+resolve, async ingest (enqueue only), and async drain with N worker threads.
Uses the generic test overlay with an auto-resolving pattern; actions are in-memory, so the numbers are
the framework's own overhead, not your systems'. The circuit breaker (500 unattended/hour here) trips
during the run by design; incidents past it go to people, which is part of what is measured.
"""
from __future__ import annotations

import argparse
import statistics
import sys
import tempfile
import threading
import time
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sentinel import Engine, Guardrails, IncidentState, SQLiteStore  # noqa: E402
from sentinel.worker import Worker  # noqa: E402
from tests.conftest import Backend, job_event, make_overlay  # noqa: E402


def store_for(pg: str | None):
    if pg:
        from sentinel.pg_store import PostgresStore
        return PostgresStore(pg, schema=f"load_{uuid.uuid4().hex[:8]}")
    return SQLiteStore(str(Path(tempfile.mkdtemp()) / "load.db"))


def engine(pg, async_mode):
    return Engine(make_overlay(Backend()), store=store_for(pg), async_mode=async_mode,
                  guardrails=Guardrails(allow_irreversible_unattended=True, max_unattended_per_hour=500))


def pct(xs, p):
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(len(xs) * p))]


def run(n: int, workers: int, pg: str | None) -> None:
    label = "PostgreSQL" if pg else "SQLite (file, WAL)"
    print(f"\n{label}: {n} events, distinct fingerprints, auto-resolving pattern")

    eng = engine(pg, async_mode=False)
    lat = []
    t0 = time.perf_counter()
    for i in range(n):
        s = time.perf_counter()
        eng.ingest(job_event(ref=f"J{i}", system=f"s{i}"))
        lat.append(time.perf_counter() - s)
    dt = time.perf_counter() - t0
    print(f"  sync ingest+resolve : {n / dt:8.0f} events/s   p50 {statistics.median(lat) * 1000:6.2f} ms"
          f"   p95 {pct(lat, .95) * 1000:6.2f} ms")
    _cleanup(eng)

    eng = engine(pg, async_mode=True)
    lat = []
    t0 = time.perf_counter()
    for i in range(n):
        s = time.perf_counter()
        eng.ingest(job_event(ref=f"J{i}", system=f"s{i}"))
        lat.append(time.perf_counter() - s)
    dt = time.perf_counter() - t0
    print(f"  async ingest (queue): {n / dt:8.0f} events/s   p50 {statistics.median(lat) * 1000:6.2f} ms"
          f"   p95 {pct(lat, .95) * 1000:6.2f} ms")
    stop = threading.Event()
    ws = [Worker(eng, worker_id=f"w{i}", batch=20, poll_s=0.005) for i in range(workers)]
    ts = [threading.Thread(target=w.run, args=(stop,)) for w in ws]
    t0 = time.perf_counter()
    for t in ts:
        t.start()
    while eng.store.incidents(IncidentState.OPEN) and time.perf_counter() - t0 < 600:
        time.sleep(0.05)
    dt = time.perf_counter() - t0
    stop.set()
    for t in ts:
        t.join()
    auto = len(eng.store.incidents(IncidentState.DISPOSITIONED))
    print(f"  async drain ({workers} workers): {n / dt:6.0f} incidents/s processed "
          f"({auto} auto-resolved, {n - auto} to people after the circuit breaker tripped)")
    _cleanup(eng)


def _cleanup(eng):
    if hasattr(eng.store, "drop"):
        eng.store.drop()
    eng.store.close()


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("-n", type=int, default=2000)
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--pg", default=None)
    a = ap.parse_args()
    run(a.n, a.workers, a.pg)
