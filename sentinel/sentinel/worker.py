# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""Worker loop: lease background work, run maintenance on a timer.

    worker = Worker(engine, worker_id="w1")
    worker.run(stop_event)          # blocks until stop_event is set

Run several workers (threads or processes) against the same Postgres store; leases with
SKIP LOCKED keep them from taking the same item, and an expired lease is picked up again.
"""
from __future__ import annotations

import logging
import os
import socket
import threading
import time
from dataclasses import dataclass, field

from .engine import Engine

log = logging.getLogger("sentinel.worker")


@dataclass
class Worker:
    engine: Engine
    worker_id: str = field(default_factory=lambda: f"{socket.gethostname()}:{os.getpid()}:{threading.get_ident()}")
    batch: int = 10
    poll_s: float = 1.0
    lease_s: float = 300.0
    maintenance_every_s: float = 60.0
    config_every_s: float = 15.0
    max_failures: int = 30            # consecutive failed loops (e.g. database away) before giving up
    failed: bool = False              # set when the worker gave up, so the process can exit and be restarted
    _last_maintenance: float = 0.0
    _last_config: float = 0.0

    def run_once(self) -> dict[str, int]:
        stats = self.engine.work(self.worker_id, limit=self.batch, lease_seconds=self.lease_s)
        now = time.monotonic()
        if now - self._last_config >= self.config_every_s:
            self._last_config = now
            try:
                applied = self.engine.sync_config()
                if applied:
                    log.info("configuration applied: %s", ", ".join(applied))
                self.engine.schedule_sources()
            except Exception:  # noqa: BLE001
                log.exception("configuration sync failed")
        if now - self._last_maintenance >= self.maintenance_every_s:
            self._last_maintenance = now
            try:
                self.engine.recover()
                self.engine.sweep()
                self.engine.seal_audit()
            except Exception:  # noqa: BLE001 - maintenance must never kill the worker
                log.exception("maintenance failed")
        return stats

    def run(self, stop: threading.Event) -> None:
        log.info("worker %s started", self.worker_id)
        failures = 0
        while not stop.is_set():
            try:
                stats = self.run_once()
                failures = 0
            except Exception:  # noqa: BLE001 - keep the loop alive; the store records item failures
                failures += 1
                log.exception("work loop error (%d in a row)", failures)
                if failures >= self.max_failures:
                    # the database (or something under us) has been failing for a while: stop, so the
                    # process exits and its supervisor (Docker, systemd) starts a fresh one
                    log.critical("worker %s giving up after %d failed loops", self.worker_id, failures)
                    self.failed = True
                    stop.set()
                    break
                stop.wait(min(30.0, self.poll_s * 2 ** min(failures, 5)))   # back off while it is failing
                continue
            if not any(stats.values()):
                stop.wait(self.poll_s)
        log.info("worker %s stopped", self.worker_id)
