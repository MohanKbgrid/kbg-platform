# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""C2: go-live readiness and the per-pattern shadow switch."""
from __future__ import annotations

import json

import pytest

from sentinel import Decision, DecisionKind, Guardrails
from sentinel.config import ApprovalNeeded
from sentinel.rbac import AuthorityRule, ConfigApproval
from tests.conftest import job_event
from tests.test_rbac import make_directory


@pytest.fixture
def eng(engine_factory):
    d = make_directory()
    d.rules.append(AuthorityRule(role_id="ops_head", action="__configure__"))
    return engine_factory(directory=d, guardrails=Guardrails(allow_irreversible_unattended=True))


def test_shadow_flag_in_the_registry_holds_actions_for_a_person(eng, backend):
    eng.set_shadow(["job_timeout"], True, "hari")
    assert eng.registry.get("job_timeout").shadow is True
    r = eng.ingest(job_event(error="TIMEOUT", ref="S1", key="s1"))
    assert backend.calls == [] and "shadow" in eng.store.open_review_for(r.incident_id).reason
    t = eng.trace(job_event(error="TIMEOUT", ref="S2", system="hr"))
    assert t["route"]["shadow"] is True and t["outcome"] == "person"
    p = eng.registry.get("job_timeout")
    assert p.definition_hash() == p.model_copy(update={"shadow": False}).definition_hash()   # trust is kept
    eng.set_shadow(["job_timeout"], False, "hari")
    eng.ingest(job_event(error="TIMEOUT", ref="S3", system="crm", key="s3"))
    assert backend.calls == [("retry", {"ref": "S3"})]
    with pytest.raises(Exception, match="unknown patterns"):
        eng.set_shadow(["ghost"], True, "hari")


def test_readiness_tracks_shadow_evidence(eng):
    eng.set_shadow(["job_timeout"], True, "hari")
    for i in range(3):
        r = eng.ingest(job_event(error="TIMEOUT", ref=f"E{i}", system=f"s{i}", key=f"e{i}"))
        rv = eng.store.open_review_for(r.incident_id)
        eng.decide(rv.id, Decision(kind=DecisionKind.APPROVE, actor="hari"))
    g = eng.readiness(min_cases=3, min_agreement=0.9)
    jt = next(x for x in g["patterns"] if x["id"] == "job_timeout")
    assert jt["state"] == "ready" and jt["shadow_cases"] == 3 and jt["agreement"] == 1.0
    assert g["ready"] == ["job_timeout"]
    assert next(x for x in g["patterns"] if x["id"] == "site_down")["state"] == "live"
    assert eng.readiness(min_cases=10)["patterns"][0]["state"] in ("collecting", "live")
    items = {c["item"]: c for c in g["checks"]}
    assert items["A recent backup exists"]["ok"] is False
    assert items["Cases arrived in the last 7 days"]["ok"] is True
    assert items["At least two people can configure"]["ok"] is True          # hari and hema
    assert items["Configuration changes need a second person"]["ok"] is None


def test_going_live_waits_for_a_second_person(engine_factory):
    d = make_directory(config_approval=ConfigApproval(approvals=1))
    d.rules.append(AuthorityRule(role_id="ops_head", action="__configure__"))
    eng = engine_factory(directory=d)
    with pytest.raises(ApprovalNeeded) as e:
        eng.set_shadow(["job_timeout"], True, "hari")
    assert eng.registry.get("job_timeout").shadow is False
    eng.approve_config(e.value.versions[0].id, "hema")
    assert eng.registry.get("job_timeout").shadow is True


def test_console_and_cli(eng, tmp_path, capsys):
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from sentinel.api import Principal, create_app, token_hash
    c = TestClient(create_app(eng, {token_hash("h"): Principal("person", "hari"),
                                    token_hash("r"): Principal("person", "ravi")}, config_sync_s=0))
    assert c.get("/console/api/golive", headers={"Authorization": "Bearer r"}).json()["patterns"]
    assert c.post("/console/api/golive/shadow", json={"patterns": ["site_down"]},
                  headers={"Authorization": "Bearer r"}).status_code == 403
    ok = c.post("/console/api/golive/shadow", json={"patterns": ["site_down"]}, headers={"Authorization": "Bearer h"})
    assert ok.status_code == 200 and eng.registry.get("site_down").shadow is True
    assert c.post("/console/api/golive/sideways", json={"patterns": ["x"]},
                  headers={"Authorization": "Bearer h"}).status_code == 404

    from sentinel.cli import main
    base = ["--overlay", "tests.test_templates_cli:_overlay", "--db", str(tmp_path / "g.db")]
    assert main([*base, "golive", "shadow", "site_down", "--by", "mohan"]) == 0
    capsys.readouterr()
    rc = main([*base, "golive", "status"])
    r = json.loads(capsys.readouterr().out)
    assert rc == 1 and r["blocking"] >= 1                                   # open mode, no backup yet
    assert next(x for x in r["patterns"] if x["id"] == "site_down")["state"] == "collecting"
