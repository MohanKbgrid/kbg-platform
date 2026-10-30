# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""One helper every scheduled job uses to record its run: on success AND on failure.

The rule it enforces (Integration gate 6 and 7): a job that runs leaves ONE record, whatever
happens, and a job that fails fails LOUDLY. A morning report that reads these records can then say
"ran / failed / did not run" instead of guessing. If every job hand-rolls its own insert, the row
shape ends up wrong in some of them and the report silently misses a job.

    with record("nightly_sync", store, expect_every_hours=24) as run:
        n = do_the_work()
        run.rows(n)
        run.summarize(f"synced {n} rows")
        run.detail(per_source={"a": n})

  * The record is written as `running` when the block is ENTERED and updated (the same row, never a
    second one) when it ends. A run in progress is therefore visible, and a run that died leaves
    its `running` row behind as the evidence, rather than leaving no trace at all.
  * An exception inside the block is recorded as `failed`, with the exception in `detail`, and is
    RE-RAISED. The job still fails; nothing is swallowed. `BaseException` (a cancel, Ctrl-C) is
    recorded and re-raised too.
  * `run.partial("why")` marks real-but-incomplete work; `run.failed("why")` marks a failure the
    job detected without raising.
  * Telemetry must not kill the job: if the store cannot be written, a loud `JOB_RUN:` line goes to
    stderr, `run.record_errors` counts it, and the job carries on with its own outcome. The missing
    record is itself what the report shows as "did not run", so a broken recorder cannot mask a
    good run as a bad one, nor a bad run as a good one.
  * `expect_every_hours` is stored in the record's detail, so a new job registers itself for
    absence detection without touching the report. Pass None for an ad-hoc job.

STORE (injected; this module imports only the standard library). Two methods, sync or async:

    open(run)           -> row id (any value), or None. Insert the `running` row.
    close(row_id, run)  -> None. Update that row from `run.snapshot()`. If `row_id` is None (the
                           open failed) insert the whole row instead, so there is still one row.

`run.snapshot()` returns a plain dict: job_name, scope, started_at, finished_at, status,
rows_affected, summary, detail, host. Use `record` with a sync store and `arecord` with an async one.
"""
from __future__ import annotations

import contextlib
import inspect
import socket
import sys
import traceback
from datetime import datetime, timezone
from typing import Any, Callable, Iterator, Optional, Protocol

__all__ = ["record", "arecord", "write", "Run", "JobRunStore", "OK", "FAILED", "PARTIAL",
           "RUNNING", "STATUSES"]

OK = "ok"
FAILED = "failed"
PARTIAL = "partial"
RUNNING = "running"        # in flight: finished_at is None. Never a terminal status.
STATUSES = (OK, FAILED, PARTIAL, RUNNING)


class JobRunStore(Protocol):
    def open(self, run: "Run") -> Any: ...
    def close(self, row_id: Any, run: "Run") -> None: ...


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Run:
    """Mutable handle given to the job body. Everything is optional except being honest."""

    def __init__(self, job_name: str, *, scope: Any = None,
                 expect_every_hours: Optional[float] = 24, host: Optional[str] = None,
                 clock: Callable[[], datetime] = _utcnow) -> None:
        if not job_name:
            raise ValueError("a job run needs a job name")
        self._clock = clock
        self.job_name = job_name
        self.scope = scope                      # tenant / company / whatever your store scopes by
        self.started_at = clock()
        self.finished_at: Optional[datetime] = None
        self.row_id: Any = None
        self.status = OK
        self.rows_affected: Optional[int] = None
        self.summary: Optional[str] = None
        self.host = host or socket.gethostname()
        self.record_errors = 0
        self._detail: dict[str, Any] = {}
        if expect_every_hours is not None:
            self._detail["expect_every_hours"] = expect_every_hours

    # -- the job talks to the run through these --
    def rows(self, n: Optional[int]) -> "Run":
        self.rows_affected = None if n is None else int(n)
        return self

    def summarize(self, line: str) -> "Run":
        """ONE line. A report concatenates summaries verbatim and never parses them."""
        self.summary = " ".join(str(line).split())
        return self

    def detail(self, **kw: Any) -> "Run":
        self._detail.update(kw)
        return self

    def partial(self, why: Optional[str] = None) -> "Run":
        """Real work done, but not all of it (cutoff reached, N of M units failed)."""
        self.status = PARTIAL
        if why:
            self._detail.setdefault("partial_reason", why)
        return self

    def failed(self, why: Optional[str] = None) -> "Run":
        self.status = FAILED
        if why:
            self._detail.setdefault("failure_reason", why)
        return self

    # -- internals --
    def snapshot(self) -> dict[str, Any]:
        return {
            "job_name": self.job_name, "scope": self.scope, "started_at": self.started_at,
            "finished_at": self.finished_at, "status": self.status,
            "rows_affected": self.rows_affected, "summary": self.summary,
            "detail": dict(self._detail), "host": self.host,
        }

    def _opening(self) -> None:
        """The row as it looks at the start: running, nothing counted, nothing claimed."""
        self._final = (self.status, self.rows_affected, self.summary)
        self.status, self.rows_affected, self.summary = RUNNING, None, None

    def _restore_after_open(self) -> None:
        self.status, self.rows_affected, self.summary = self._final

    def _note_exception(self, exc: BaseException) -> None:
        self.status = FAILED
        self._detail["exception"] = {
            "type": type(exc).__name__,
            "message": str(exc)[:2000],
            "traceback": "".join(traceback.format_exception_only(type(exc), exc)).strip()[:500],
        }
        if self.summary is None:
            self.summary = f"FAILED: {type(exc).__name__}: {str(exc)[:180]}"

    def _finish(self) -> None:
        self.finished_at = self._clock()


def _warn(run: Run, exc: BaseException, what: str) -> None:
    run.record_errors += 1
    print(f"JOB_RUN: could not {what} for {run.job_name!r} ({type(exc).__name__}: {exc}); "
          f"the job's own result is unaffected and the report will show it as 'did not run'",
          file=sys.stderr, flush=True)


@contextlib.contextmanager
def record(job_name: str, store: JobRunStore, *, scope: Any = None,
           expect_every_hours: Optional[float] = 24, host: Optional[str] = None,
           clock: Callable[[], datetime] = _utcnow) -> Iterator[Run]:
    """Record a run in a SYNCHRONOUS store. Re-raises whatever the body raises."""
    run = Run(job_name, scope=scope, expect_every_hours=expect_every_hours, host=host, clock=clock)
    run._opening()
    try:
        result = store.open(run)
        if inspect.isawaitable(result):
            if inspect.iscoroutine(result):
                result.close()
            raise TypeError("store.open returned an awaitable; use arecord for an async store")
        run.row_id = result
    except Exception as exc:  # noqa: BLE001 - telemetry must not kill the job
        _warn(run, exc, "open the run record")
        run.row_id = None
    finally:
        run._restore_after_open()
    try:
        yield run
    except BaseException as exc:
        run._note_exception(exc)
        raise
    finally:
        run._finish()
        try:
            result = store.close(run.row_id, run)
            if inspect.isawaitable(result):
                if inspect.iscoroutine(result):
                    result.close()
                raise TypeError("store.close returned an awaitable; use arecord for an async store")
        except Exception as exc:  # noqa: BLE001
            _warn(run, exc, "close the run record")


@contextlib.asynccontextmanager
async def arecord(job_name: str, store: Any, *, scope: Any = None,
                  expect_every_hours: Optional[float] = 24, host: Optional[str] = None,
                  clock: Callable[[], datetime] = _utcnow):
    """The same for an ASYNC store (open/close are coroutines)."""
    run = Run(job_name, scope=scope, expect_every_hours=expect_every_hours, host=host, clock=clock)
    run._opening()
    try:
        result = store.open(run)
        run.row_id = await result if inspect.isawaitable(result) else result
    except Exception as exc:  # noqa: BLE001
        _warn(run, exc, "open the run record")
        run.row_id = None
    finally:
        run._restore_after_open()
    try:
        yield run
    except BaseException as exc:
        run._note_exception(exc)
        raise
    finally:
        run._finish()
        try:
            result = store.close(run.row_id, run)
            if inspect.isawaitable(result):
                await result
        except Exception as exc:  # noqa: BLE001
            _warn(run, exc, "close the run record")


def write(job_name: str, store: JobRunStore, *, status: str = OK, summary: Optional[str] = None,
          rows: Optional[int] = None, scope: Any = None,
          expect_every_hours: Optional[float] = None, **detail: Any) -> Run:
    """One-shot record for a job that already knows its outcome (a wrapper script, a manual run)."""
    if status not in (OK, FAILED, PARTIAL):
        raise ValueError(f"status must be one of {(OK, FAILED, PARTIAL)}, got {status!r}")
    with record(job_name, store, scope=scope, expect_every_hours=expect_every_hours) as run:
        run.rows(rows).detail(**detail)
        if summary:
            run.summarize(summary)
        run.status = status
    return run
