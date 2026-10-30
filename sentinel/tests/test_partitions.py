# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""H13: opt-in monthly partitions for audit and model_runs on PostgreSQL; everything keeps working."""
from __future__ import annotations

import os
import uuid
from datetime import UTC, datetime

import pytest

from sentinel import Decision, DecisionKind
from tests.conftest import job_event

PG = os.environ.get("SENTINEL_TEST_PG")
pytestmark = pytest.mark.skipif(not PG, reason="needs SENTINEL_TEST_PG")


def test_convert_then_everything_works(engine_factory, clock, tmp_path):
    from sentinel import partitions, retention
    from sentinel.auditchain import seal, verify
    from sentinel.pg_store import PostgresStore
    from sentinel.routing import ModelRun
    st = PostgresStore(PG, schema=f"t_{uuid.uuid4().hex[:12]}")
    eng = engine_factory(store=st)
    for i in range(3):
        r = eng.ingest(job_event(error="AUTH", ref=f"P{i}", system=f"s{i}", key=f"p{i}"))
        eng.decide(st.open_review_for(r.incident_id).id,
                   Decision(kind=DecisionKind.REJECT, actor="op", disposition_code="no_action"))
    seal(st, settle_s=0)
    before = len(st.audit_log())
    out = partitions.convert(st, "audit", now=datetime(2026, 10, 10, tzinfo=UTC))
    partitions.convert(st, "model_runs", now=datetime(2026, 10, 10, tzinfo=UTC))
    assert out["rows"] == before and partitions.convert(st, "audit")["already"]
    info = partitions.status(st)
    assert info["audit"]["partitioned"] and "audit_202610" in info["audit"]["partitions"]
    assert "audit_default" in info["audit"]["partitions"]
    r = eng.ingest(job_event(error="AUTH", ref="P9", system="x", key="p9"))      # new rows go in
    st.put_model_run(ModelRun(id=f"run_{uuid.uuid4().hex[:8]}", ts=clock().timestamp(), task="diagnose", model="m",
                              incident_id=r.incident_id, ok=True, error=None, latency_ms=5, chars_in=1,
                              chars_out=1, est_cost=0.0))
    assert len(st.audit_log()) > before and st.model_runs_for(r.incident_id)
    seal(st, settle_s=0)
    assert verify(st)["ok"]
    made = partitions.maintain(st, now=datetime(2026, 12, 20, tzinfo=UTC))
    assert "audit_202701" in made or "audit_202702" in made
    clock.advance(days=400)
    retention.run(st, clock(), 365, archive_dir=str(tmp_path), apply=True)
    assert verify(st)["ok"]
    st.drop()
    st.close()
