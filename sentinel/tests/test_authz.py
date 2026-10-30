# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""Who may see what (review finding H9): case details only for the roles that work the case, people's contact
details only for those who manage people or access, and browser security headers on every response."""
from __future__ import annotations

import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from sentinel import Guardrails  # noqa: E402
from sentinel.api import Principal, create_app, token_hash  # noqa: E402
from sentinel.rbac import AuthorityRule  # noqa: E402
from tests.conftest import job_event  # noqa: E402
from tests.test_rbac import make_directory  # noqa: E402


@pytest.fixture
def c(engine_factory):
    d = make_directory()
    d.rules.append(AuthorityRule(role_id="ops_head", action="__configure__"))
    d.people["ravi"].contact["phone"] = "+91 98400 11111"
    eng = engine_factory(directory=d, guardrails=Guardrails())
    toks = {t: Principal("person", t.split("-")[0]) for t in ("ravi-t", "asha-t", "hema-t", "gone-t")}
    app = create_app(eng, {token_hash(k): v for k, v in toks.items()}, config_sync_s=0)
    return eng, TestClient(app)


def auth(t):
    return {"Authorization": f"Bearer {t}"}


def test_case_details_only_for_roles_that_work_it(c):
    eng, cl = c
    r = eng.ingest(job_event(error="AUTH", system="hr"))          # ops queue, hr scope
    assert cl.get(f"/v1/incidents/{r.incident_id}", headers=auth("ravi-t")).status_code == 200   # ops, all scopes
    assert cl.get(f"/v1/incidents/{r.incident_id}", headers=auth("asha-t")).status_code == 404   # ops, billing only
    assert cl.get(f"/v1/incidents/{r.incident_id}", headers=auth("hema-t")).status_code == 200   # head, above ops


def test_contact_details_need_the_right(c):
    eng, cl = c
    seen = cl.get("/console/api/config/people", headers=auth("ravi-t")).json()["text"]
    assert "98400" not in seen and "(hidden)" in seen
    assert "98400" in cl.get("/console/api/config/people", headers=auth("hema-t")).json()["text"]
    assert cl.post("/console/api/config/people/drafts", json={"text": seen}, headers=auth("ravi-t")).status_code == 403


def test_security_headers(c):
    _, cl = c
    r = cl.get("/console")
    assert "frame-ancestors 'none'" in r.headers["content-security-policy"]
    assert r.headers["x-content-type-options"] == "nosniff" and r.headers["x-frame-options"] == "DENY"
    assert cl.get("/healthz").headers["x-content-type-options"] == "nosniff"
