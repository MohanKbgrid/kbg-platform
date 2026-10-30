# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""DPDP pack: access requests, erasure, and scrubbing personal fields by age."""
from __future__ import annotations

import json

import pytest

from sentinel import AuthorizationError, Decision, DecisionKind
from sentinel.rbac import AuthorityRule
from tests.conftest import job_event
from tests.test_rbac import make_directory


@pytest.fixture
def eng(engine_factory, overlay):
    overlay.pii_keys = ["phone", "email"]
    d = make_directory()
    d.rules.append(AuthorityRule(role_id="ops_head", action="__privacy__"))
    return engine_factory(ov=overlay, directory=d)


def _close(eng, r):
    rv = eng.store.open_review_for(r.incident_id)
    if rv is not None:
        eng.decide(rv.id, Decision(kind=DecisionKind.REJECT, actor="hari", disposition_code="no_action",
                                   note="called +91 98400 12345 back"))


def everything(eng, inc_id):
    inc = eng.store.get_incident(inc_id)
    parts = [inc.model_dump_json(), json.dumps(eng.store.audit_log(inc_id), default=str)]
    parts += [eng.store.get_event(e).model_dump_json() for e in eng.store.event_ids(inc_id)]
    d = eng.store.get_disposition(inc_id)
    parts += [d.model_dump_json()] if d else []
    parts += [r.model_dump_json() for r in eng.store.reviews_for_incident(inc_id)]
    return " ".join(parts)


def test_access_and_erasure(eng):
    r = eng.ingest(job_event(error="AUTH", ref="ORD-1", key="p1", phone="+91 98400 12345",
                             email="asha@example.in", customer="Asha +91 98400 12345"))
    _close(eng, r)
    other = eng.ingest(job_event(error="AUTH", ref="ORD-2", system="crm", key="p2", phone="+91 90000 00000"))
    open_one = eng.ingest(job_event(error="AUTH", ref="ORD-3", system="hr", key="p3", phone="+91 98400 12345"))
    with pytest.raises(AuthorizationError):
        eng.privacy_access("+91 98400 12345", "ravi")
    doc = eng.privacy_access("+91 98400 12345", "hari")
    assert {c["case"] for c in doc["cases"]} == {r.incident_id, open_one.incident_id}
    assert "+91 98400 12345" not in json.dumps(eng.store.audit_log()[-1])            # only a hash is audited
    res = eng.privacy_erase("+91 98400 12345", "hari", "request DP-7")
    assert res["erased_cases"] == [r.incident_id] and res["skipped_open"] == [open_one.incident_id]
    text = everything(eng, r.incident_id)
    assert "98400 12345" not in text and "asha@example.in" not in text and "[erased]" in text
    assert "ORD-1" in text                                                            # the business record stays
    assert "+91 90000 00000" in everything(eng, other.incident_id)                    # other people untouched
    assert "98400 12345" in everything(eng, open_one.incident_id)
    assert eng.case(r.incident_id)["disposition"]["note"] == "called [erased] back"
    with pytest.raises(ValueError):
        eng.privacy_erase("ab", "hari")


def test_scrub_by_age_resumes_and_waits_for_open_cases(eng, clock):
    a = eng.ingest(job_event(error="AUTH", ref="S1", key="s1", phone="111-222-333"))
    _close(eng, a)
    b = eng.ingest(job_event(error="AUTH", ref="S2", system="crm", key="s2", phone="444-555-666"))   # stays open
    from sentinel.privacy import scrub
    clock.advance(days=100)
    dry = scrub(eng, 90)
    assert dry["checked"] == 1 and dry["applied"] is False and "111-222-333" in everything(eng, a.incident_id)
    res = scrub(eng, 90, apply=True)
    assert res["scrubbed"] == 1 and "111-222-333" not in everything(eng, a.incident_id)
    assert "S1" in everything(eng, a.incident_id)
    _close(eng, b)                                                                     # closes later
    clock.advance(days=1)
    again = scrub(eng, 90, apply=True)
    assert again["scrubbed"] == 1 and "444-555-666" not in everything(eng, b.incident_id)


def test_console_and_cli(eng, tmp_path, capsys):
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from sentinel.api import Principal, create_app, token_hash
    r = eng.ingest(job_event(error="AUTH", ref="C1", key="c1", phone="777-888-999"))
    _close(eng, r)
    c = TestClient(create_app(eng, {token_hash("h"): Principal("person", "hari"),
                                    token_hash("r"): Principal("person", "ravi")}, config_sync_s=0))
    H, R = {"Authorization": "Bearer h"}, {"Authorization": "Bearer r"}
    assert c.post("/console/api/privacy/find", json={"identifier": "777-888-999"}, headers=R).status_code == 403
    assert [x["id"] for x in c.post("/console/api/privacy/find", json={"identifier": "777-888-999"},
                                    headers=H).json()["cases"]] == [r.incident_id]
    assert c.post("/console/api/privacy/access", json={"identifier": "777-888-999"}, headers=R).status_code == 403
    assert c.post("/console/api/privacy/erase", json={"identifier": "777-888-999"},
                  headers=H).json()["erased_cases"] == [r.incident_id]
    assert c.post("/console/api/privacy/find", json={"identifier": "ab"}, headers=H).status_code == 422
