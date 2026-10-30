# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""The Postgres outbox connector: Sentinel reads the application's outbox table (written by database triggers in the same
transaction as the business change) with a read-only login, resuming where it left off. An order fulfilled
in the application closes its "order stuck" case at the source; a sync job that recovers closes its failure case."""
from __future__ import annotations

import json
import os
import uuid
from datetime import UTC, datetime, timedelta

import pytest

from sentinel import FingerprintRule, Guardrails, IncidentState as S, Pattern, Route, connectors
from sentinel.config import dump_yaml
from sentinel.models import ClearEvent, ClearWhen
from sentinel.sources import parse_sources, to_events
from tests.conftest import Backend, make_overlay

TENANT = "11111111-1111-1111-1111-111111111111"


def _rows():
    t = datetime(2026, 10, 12, 9, 0, tzinfo=UTC)
    return [
        {"id": 1, "event_type": "channel.sync_failed", "idempotency_key": "channel.sync_failed:j1",
         "correlation_id": "j1", "created_at": t,
         "payload": {"channel": "amazon", "operation": "orders", "error_code": "RATE_LIMITED", "job_id": "j1"}},
        {"id": 2, "event_type": "order.fulfilled", "idempotency_key": "order.fulfilled:o1", "correlation_id": "403-1",
         "created_at": t, "payload": {"order_id": "403-1", "channel": "amazon", "status": "SHIPPED"}},
        {"id": 3, "event_type": "channel.sync_ok", "idempotency_key": "channel.sync_ok:j2", "correlation_id": "j2",
         "created_at": t + timedelta(minutes=5), "payload": {"channel": "amazon", "operation": "orders"}},
        {"id": 4, "event_type": "something.else", "idempotency_key": "x:1", "correlation_id": None,
         "created_at": t + timedelta(minutes=6), "payload": {}},
    ]


def test_the_template_maps_outbox_rows_to_events():
    tpl = connectors.load("postgres-outbox")
    src = parse_sources(tpl["connectors"]["sources"])["outbox"]
    rows = [{**r, "created_at": r["created_at"].isoformat()} for r in _rows()]
    evs = to_events(src, rows, items=rows)
    assert [e.type for e in evs] == ["channel.sync_failed", "order.fulfilled", "channel.sync_ok"]
    assert evs[1].payload == {"order_id": "403-1", "channel": "amazon", "status": "SHIPPED"}
    assert evs[1].idempotency_key == "outbox:order.fulfilled:o1" and evs[1].correlation_id == "403-1"
    assert evs[0].correlation_id == "j1"


@pytest.fixture
def pg_outbox():
    dsn = os.environ.get("SENTINEL_TEST_PG")
    if not dsn:
        pytest.skip("needs SENTINEL_TEST_PG")
    import psycopg
    schema = f"ng_{uuid.uuid4().hex[:10]}"
    with psycopg.connect(dsn, autocommit=True) as c:
        c.execute(f"CREATE SCHEMA {schema}")
        c.execute(f"""CREATE TABLE {schema}.sentinel_outbox (id bigserial PRIMARY KEY, tenant_id uuid NOT NULL,
            event_type text NOT NULL, idempotency_key text NOT NULL, correlation_id text, payload jsonb NOT NULL,
            occurred_at timestamptz DEFAULT now(), created_at timestamptz NOT NULL)""")
    sep = "&" if "?" in dsn else "?"
    yield f"{dsn}{sep}options=-csearch_path%3D{schema}", schema, dsn
    with psycopg.connect(dsn, autocommit=True) as c:
        c.execute(f"DROP SCHEMA {schema} CASCADE")


def _insert(dsn, schema, rows, tenant=TENANT):
    import psycopg
    with psycopg.connect(dsn, autocommit=True) as c:
        for r in rows:
            c.execute(f"INSERT INTO {schema}.sentinel_outbox (id, tenant_id, event_type, idempotency_key, "
                      "correlation_id, payload, created_at) VALUES (%s,%s,%s,%s,%s,%s,%s)",
                      (r["id"], tenant, r["event_type"], r["idempotency_key"], r["correlation_id"],
                       json.dumps(r["payload"]), r["created_at"]))


def test_reading_the_outbox_closes_cases_at_the_source(engine_factory, pg_outbox, monkeypatch):
    src_dsn, schema, admin = pg_outbox
    monkeypatch.setenv("SENTINEL_SECRET_OUTBOX_DB", src_dsn)
    monkeypatch.setenv("SENTINEL_SECRET_OUTBOX_TENANT", TENANT)
    tpl = connectors.load("postgres-outbox")
    ov = make_overlay(Backend(), patterns=[
        Pattern(id="order_stuck", event_types=["order.unfulfilled"], route=Route.HITL, allowed_actions=["notify"],
                owner_role="ops", clear_when=ClearWhen(events=[ClearEvent(type="order.fulfilled", same=["order"])])),
        Pattern(id="sync_failed", event_types=["channel.sync_failed"], route=Route.HITL, allowed_actions=["retry"],
                owner_role="ops",
                clear_when=ClearWhen(events=[ClearEvent(type="channel.sync_ok", same=["channel", "operation"])]))])
    ov.fingerprint_rules += [FingerprintRule.model_validate(f) for f in tpl["fingerprints"]]
    ov.fingerprint_rules.append(FingerprintRule(event_type="order.unfulfilled",
                                                fields={"order": "order_id", "channel": "channel"}))
    eng = engine_factory(ov=ov, guardrails=Guardrails())
    cv, probs = eng.save_config("connectors", dump_yaml(connectors.merge({}, "postgres-outbox")), "hari")
    assert not [p for p in probs if p.severity == "error"], probs
    eng.publish_config(cv.id, "hari")

    from sentinel import Event
    stuck = eng.ingest(Event(type="order.unfulfilled", source="scan", payload={"order_id": "403-1", "channel": "amazon"}))
    rows = _rows()
    _insert(admin, schema, rows[:2])
    _insert(admin, schema, [{**rows[0], "id": 9, "idempotency_key": "other-tenant"}],
            tenant="22222222-2222-2222-2222-222222222222")               # another business: never read
    out = eng.poll_source("outbox")
    assert out["events"] == 2
    assert eng.store.get_incident(stuck.incident_id).state is S.DISPOSITIONED      # fulfilled in the application
    assert eng.store.get_disposition(stuck.incident_id).code == "resolved_in_source"
    fail = next(i for i in eng.store.incidents() if i.pattern_id == "sync_failed")
    assert fail.facts["error"] == "RATE_LIMITED" and fail.state is not S.DISPOSITIONED

    assert eng.poll_source("outbox")["events"] == 0                       # resumes where it left off
    _insert(admin, schema, rows[2:])
    assert eng.poll_source("outbox")["events"] == 1                       # the unknown type is skipped
    assert eng.store.get_incident(fail.id).state is S.DISPOSITIONED                # the sync recovered
