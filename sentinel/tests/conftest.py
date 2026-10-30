# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""Generic, domain-free test overlay. Proves the core works without ACME."""
from __future__ import annotations

import os
import threading
import uuid
from datetime import datetime, timedelta, UTC

import pytest

from sentinel import (ActionRegistry, ActionResult, Bucket, Engine, Event, FingerprintRule, Guardrails,
                      LearningPolicy, Overlay, Pattern, PlaybookStep, Route, SQLiteStore, ToolRegistry)


_PG_STORES: list = []


def new_store():
    """SQLite by default; set SENTINEL_TEST_PG=<dsn> to run the whole suite on PostgreSQL."""
    dsn = os.environ.get("SENTINEL_TEST_PG")
    if not dsn:
        return SQLiteStore()
    from sentinel.pg_store import PostgresStore
    st = PostgresStore(dsn, schema=f"t_{uuid.uuid4().hex[:12]}")
    _PG_STORES.append(st)
    return st


@pytest.fixture(autouse=True)
def _local_test_servers(monkeypatch):
    """Tests talk to fake servers on this machine; production refuses internal addresses unless allowed."""
    if "SENTINEL_EGRESS_ALLOW" not in os.environ:
        monkeypatch.setenv("SENTINEL_EGRESS_ALLOW", "127.0.0.0/8,::1,localhost")


@pytest.fixture(autouse=True)
def _cleanup_pg():
    """Close each test's Postgres stores when the test ends (CI Postgres allows ~100 connections)."""
    before = len(_PG_STORES)
    yield
    while len(_PG_STORES) > before:
        st = _PG_STORES.pop()
        try:
            st.drop()
            st.close()
        except Exception:  # noqa: BLE001 - best-effort cleanup
            pass


class FakeClock:
    def __init__(self) -> None:
        self.now = datetime(2026, 10, 10, 9, 0, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self.now

    def advance(self, **kw) -> None:
        self.now += timedelta(**kw)


class Backend:
    """Stands in for an external system. Records every side effect."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, dict]] = []
        self.lock = threading.Lock()
        self.fail_next: dict[str, list[ActionResult | Exception]] = {}

    def do(self, name: str, params: dict) -> ActionResult:
        with self.lock:
            queue = self.fail_next.get(name)
            if queue:
                nxt = queue.pop(0)
                if isinstance(nxt, Exception):
                    raise nxt
                return nxt
            self.calls.append((name, dict(params)))
        return ActionResult(ok=True, detail=f"{name} done")

    def count(self, name: str) -> int:
        return sum(1 for n, _ in self.calls if n == name)


def make_overlay(backend: Backend, patterns: list[Pattern] | None = None, notes: list | None = None) -> Overlay:
    acts = ActionRegistry()

    @acts.action("retry", reversible=False, params={"ref": "str"}, description="re-run a failed job")
    def retry(ctx, p):
        return backend.do("retry", p)

    @acts.action("hold", reversible=True, params={"ref": "str", "reason?": "str"}, description="put item on hold")
    def hold(ctx, p):
        return backend.do("hold", p)

    @hold.compensator
    def unhold(ctx, p):
        return backend.do("unhold", p)

    @acts.action("cancel", reversible=False, params={"ref": "str"}, description="cancel; cannot be undone",
                 max_attempts=1)
    def cancel(ctx, p):
        return backend.do("cancel", p)

    @acts.action("notify", reversible=False, params={"ref": "str", "msg": "str"})
    def notify(ctx, p):
        return backend.do("notify", p)

    tools = ToolRegistry()

    @tools.tool("lookup", "look up a record by ref", {"ref": "str"})
    def lookup(args, services):
        return {"ref": args.get("ref"), "status": "stuck", "age_h": 30}

    rules = [
        FingerprintRule(event_type="job.failed", fields={"system": "system", "error": "error_code"}),
        FingerprintRule(event_type="item.stuck", fields={"site": "site", "ref": "ref"},
                        buckets={"age": Bucket(field="age_hours", edges=[4, 24], labels=["<4h", "4-24h", ">24h"])},
                        group_by=["site", "age", "ref"]),
        FingerprintRule(event_type="site.down", fields={"site": "site"}),
    ]

    default_patterns = [
        Pattern(id="job_timeout", event_types=["job.failed"], match={"error": "TIMEOUT"}, route=Route.AUTO,
                playbook=[PlaybookStep(action="retry", params={"ref": "{{payload.ref}}"})],
                allowed_actions=["retry", "notify"], owner_role="ops"),
        Pattern(id="job_failed_other", event_types=["job.failed"], match={"system": "*"}, route=Route.HITL,
                allowed_actions=["retry", "cancel", "notify"], owner_role="ops", escalation_role="lead",
                group_window_minutes=60),
        Pattern(id="item_stuck_long", event_types=["item.stuck"], match={"age": ">24h"}, route=Route.LLM,
                allowed_actions=["hold", "cancel", "notify"], owner_role="ops",
                playbook=[PlaybookStep(action="hold", params={"ref": "{{payload.ref}}", "reason": "stuck"})],
                inhibited_by=["site_down"], inhibit_on=["site"], llm_min_confidence=0.8),
        Pattern(id="item_stuck_short", event_types=["item.stuck"], match={"age": ["<4h", "4-24h"]},
                route=Route.HITL, allowed_actions=["hold"], inhibited_by=["site_down"], inhibit_on=["site"]),
        Pattern(id="site_down", event_types=["site.down"], route=Route.HITL, allowed_actions=["notify"],
                owner_role="lead", sla_minutes=30),
    ]
    sink = notes if notes is not None else []
    return Overlay(name="generic", fingerprint_rules=rules, patterns=patterns or default_patterns, actions=acts,
                   tools=tools, services={"backend": backend},
                   receivers={"jobs": lambda raw: Event(type="job.failed", source="jobs", payload=raw,
                                                        idempotency_key=raw.get("id"))},
                   roles={"ops": "operator", "lead": "team lead"},
                   notifier=lambda kind, data: sink.append((kind, data)))


def job_event(error="TIMEOUT", ref="J1", system="billing", key=None, **extra) -> Event:
    return Event(type="job.failed", source="scheduler", idempotency_key=key,
                 payload={"system": system, "error_code": error, "ref": ref, **extra})


def stuck_event(ref="I1", site="S1", age=30, key=None) -> Event:
    return Event(type="item.stuck", source="wms", idempotency_key=key,
                 payload={"ref": ref, "site": site, "age_hours": age})


@pytest.fixture
def clock():
    return FakeClock()


@pytest.fixture
def backend():
    return Backend()


@pytest.fixture
def notes():
    return []


@pytest.fixture
def overlay(backend, notes):
    return make_overlay(backend, notes=notes)


@pytest.fixture
def engine_factory(overlay, clock):
    def make(llm=None, store=None, guardrails=None, learning=None, ov=None, **kw):
        return Engine(ov or overlay, store=store or new_store(), llm=llm, clock=clock,
                      guardrails=guardrails or Guardrails(allow_irreversible_unattended=True),
                      learning=learning or LearningPolicy(), **kw)
    return make


@pytest.fixture
def engine(engine_factory):
    return engine_factory()
