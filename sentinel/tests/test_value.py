# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""E1: value report (time and money saved) and the plan & usage endpoints."""
from __future__ import annotations

import pytest

from sentinel import Decision, DecisionKind
from sentinel.rbac import AuthorityRule, ValueSettings
from tests.conftest import job_event
from tests.test_rbac import make_directory


def test_value_counts_only_real_automatic_work(engine_factory, overlay):
    i = next(n for n, p in enumerate(overlay.patterns) if p.id == "job_timeout")
    overlay.patterns[i] = overlay.patterns[i].model_copy(update={"effort_minutes": 12})
    d = make_directory(value=ValueSettings(hourly_cost=300, default_minutes=6, model_cost_rate=80))
    eng = engine_factory(ov=overlay, directory=d)
    for n in range(3):
        eng.ingest(job_event(error="TIMEOUT", ref=f"V{n}", system=f"s{n}", key=f"v{n}"))
    eng.reverse(eng.store.incidents()[-1].id, actor="hari")
    h = eng.ingest(job_event(error="AUTH", ref="V9", key="v9"))
    eng.decide(eng.store.open_review_for(h.incident_id).id,
               Decision(kind=DecisionKind.REJECT, actor="lata", disposition_code="no_action"))
    v = eng.value(days=30)
    jt = next(x for x in v["patterns"] if x["pattern"] == "job_timeout")
    assert jt["automatic"] == 2 and jt["reversed"] == 1 and jt["minutes_saved"] == 24.0
    assert jt["money_saved"] == 120.0 and jt["net"] == 120.0                     # 24 min at 300/h, no model
    other = next(x for x in v["patterns"] if x["pattern"] == "job_failed_other")
    assert other["by_people"] == 1 and other["minutes_by_people"] == 6.0
    assert v["total"]["automatic"] == 2 and v["currency"] == "INR" and len(v["trend"]) == 8
    assert v["trend"][-1]["automatic"] == 2
    text = eng.config_text("people")
    assert "hourly_cost: 300" in text                                             # round-trips


def test_plan_usage_and_value_endpoints(engine_factory):
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from sentinel.api import Principal, create_app, token_hash
    d = make_directory()
    d.rules.append(AuthorityRule(role_id="ops_head", action="__configure__"))
    eng = engine_factory(directory=d)
    eng.ingest(job_event(error="TIMEOUT", ref="P1", key="p1"))
    c = TestClient(create_app(eng, {token_hash("h"): Principal("person", "hari"),
                                    token_hash("r"): Principal("person", "ravi")}, config_sync_s=0))
    H, R = {"Authorization": "Bearer h"}, {"Authorization": "Bearer r"}
    assert c.get("/console/api/value", headers=R).json()["total"]["automatic"] == 1
    plan = c.get("/console/api/plan", headers=H).json()
    assert plan["enforced"] is False and plan["usage"]["tenants"]["default"]["resolved_automatic"] == 1
    assert c.get("/console/api/plan", headers=R).json()["usage"] is None
    month = eng.clock().strftime("%Y-%m")
    r = c.get(f"/console/api/usage/{month}", headers=H)
    assert r.status_code == 200 and r.json()["month"] == month and "attachment" in r.headers["content-disposition"]
    assert c.get(f"/console/api/usage/{month}", headers=R).status_code == 403
    assert c.get("/console/api/usage/october", headers=H).status_code == 422
