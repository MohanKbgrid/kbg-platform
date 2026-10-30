# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""Console API: reading the running system, drafting and publishing configuration, templates, rights."""
from __future__ import annotations

import pytest
import yaml

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from sentinel import Guardrails, SQLiteStore  # noqa: E402
from sentinel.api import Principal, create_app, token_hash  # noqa: E402
from sentinel.rbac import AuthorityRule  # noqa: E402
from tests.conftest import job_event, stuck_event  # noqa: E402
from tests.test_rbac import make_directory  # noqa: E402

TOKENS = {"svc": Principal("service", "ingest"), "ravi": Principal("person", "ravi"),
          "hari": Principal("person", "hari"), "ghost": Principal("person", "ghost")}


def H(tok):
    return {"Authorization": f"Bearer {tok}"}


@pytest.fixture
def console(engine_factory, tmp_path):
    d = make_directory()
    d.rules.append(AuthorityRule(role_id="ops_head", action="__configure__"))
    eng = engine_factory(directory=d, guardrails=Guardrails(allow_irreversible_unattended=True),
                         store=SQLiteStore(str(tmp_path / "c.db")))
    app = create_app(eng, {token_hash(k): v for k, v in TOKENS.items()}, config_sync_s=0)
    with TestClient(app) as c:
        yield eng, c


def test_ui_is_served_without_internet(console):
    _, c = console
    assert c.get("/", follow_redirects=False).headers["location"] == "/console"
    page = c.get("/console")
    assert page.status_code == 200 and "/console/static/app.js" in page.text and "http" not in page.text.split(
        "<body>")[1]
    js = c.get("/console/static/app.js")
    assert js.status_code == 200 and "https://" not in js.text and "http://" not in js.text
    assert c.get("/console/static/app.css").status_code == 200


def test_me_and_access(console):
    _, c = console
    assert c.get("/console/api/me").status_code == 401
    assert c.get("/console/api/me", headers=H("svc")).status_code == 403
    hari = c.get("/console/api/me", headers=H("hari")).json()
    assert hari["roles"] == ["ops_head"] and hari["can"]["__configure__"] is True
    ravi = c.get("/console/api/me", headers=H("ravi")).json()
    assert ravi["roles"] == ["ops"] and ravi["can"]["__configure__"] is False
    assert c.get("/console/api/me", headers=H("ghost")).json()["known"] is False


def test_overview_patterns_catalogue_directory(console):
    eng, c = console
    eng.ingest(job_event(ref="J1", key="a"))
    eng.ingest(job_event(error="E1", ref="J2", key="b"))
    o = c.get("/console/api/overview", headers=H("hari")).json()
    assert o["closed"] == 1 and o["unattended"] == 1 and o["patterns"] == 5 and o["people"] == 6
    assert o["config"]["registry"]["active"] is None
    pats = {p["id"]: p for p in c.get("/console/api/patterns", headers=H("ravi")).json()}
    assert pats["job_timeout"]["route"] == "auto" and pats["job_failed_other"]["ceiling"] == "llm"
    cat = c.get("/console/api/catalogue", headers=H("ravi")).json()
    assert {a["name"] for a in cat["actions"]} == {"retry", "hold", "cancel", "notify"}
    assert {a["risk"] for a in cat["actions"]} == {"irreversible", "reversible"}
    d = c.get("/console/api/directory", headers=H("ravi")).json()
    depth = {r["id"]: r["depth"] for r in d["roles"]}
    assert depth == {"ops_head": 0, "lead": 1, "ops": 2, "supervisor": 1, "operator": 2}
    reviews = c.get("/console/api/reviews", headers=H("hari")).json()
    assert len(reviews) == 1 and reviews[0]["pattern_id"] == "job_failed_other"
    assert len(c.get("/console/api/activity?limit=5", headers=H("hari")).json()) == 5


def test_structured_edit_draft_and_publish(console):
    eng, c = console
    doc = c.get("/console/api/config/registry/doc", headers=H("ravi")).json()
    for p in doc["patterns"]:
        if p["id"] == "site_down":
            p["sla_minutes"] = 12
    chk = c.post("/console/api/config/registry/check", json={"doc": doc}, headers=H("ravi")).json()
    assert not [p for p in chk["problems"] if p["severity"] == "error"] and "+  sla_minutes: 12" in chk["diff"]
    saved = c.post("/console/api/config/registry/drafts", json={"doc": doc, "note": "faster"}, headers=H("ravi")).json()
    vid = saved["version"]["id"]
    assert saved["version"]["status"] == "draft" and saved["version"]["author"] == "ravi"
    r = c.post(f"/console/api/config/versions/{vid}/publish", json={}, headers=H("ravi"))
    assert r.status_code == 403
    r = c.post(f"/console/api/config/versions/{vid}/publish", json={}, headers=H("hari"))
    assert r.status_code == 200 and r.json()["version"]["status"] == "published"
    assert eng.registry.get("site_down").sla_minutes == 12
    v = c.get(f"/console/api/config/versions/{vid}", headers=H("ravi")).json()
    assert v["diff"] == "" and "sla_minutes: 12" in v["text"]
    cfg = c.get("/console/api/config/registry", headers=H("ravi")).json()
    assert cfg["active"]["version"] == 1 and len(cfg["versions"]) == 1


def test_publishing_a_broken_version_reports_problems(console):
    _, c = console
    doc = c.get("/console/api/config/registry/doc", headers=H("hari")).json()
    doc["patterns"][0]["allowed_actions"] = ["warp"]
    vid = c.post("/console/api/config/registry/drafts", json={"doc": doc}, headers=H("hari")).json()["version"]["id"]
    r = c.post(f"/console/api/config/versions/{vid}/publish", json={}, headers=H("hari"))
    assert r.status_code == 422 and any("warp" in p["message"] for p in r.json()["problems"])
    assert c.post("/console/api/config/nope/check", json={"text": ""}, headers=H("hari")).status_code == 404
    assert c.post("/console/api/config/registry/check", json={}, headers=H("hari")).status_code == 422


def test_templates_and_switching_domain_as_a_set(console):
    eng, c = console
    names = [t["name"] for t in c.get("/console/api/templates", headers=H("hari")).json()]
    assert names == ["dairy-distribution", "manufacturing", "retail-fulfilment"]
    t = c.get("/console/api/templates/manufacturing", headers=H("hari")).json()
    assert "create_maintenance_ticket" in t["missing"]["actions"] and t["patterns"] == 7
    assert c.get("/console/api/templates/nope", headers=H("hari")).status_code == 404
    # a template that only uses this overlay's actions: roles and patterns change together
    reg = yaml.safe_load(eng.config_text("registry"))
    people = yaml.safe_load(eng.config_text("people"))
    people["roles"]["desk"] = {"name": "Desk", "parent": "ops_head"}
    people["assignments"].append({"person_id": "ravi", "role_id": "desk"})
    for p in reg["patterns"]:
        p["owner_role"] = "desk"
    reg["roles"]["desk"] = "Desk"
    alone = c.post("/console/api/config/registry/check", json={"doc": reg}, headers=H("hari")).json()
    assert any("'desk' is not in the people configuration" in p["message"] for p in alone["problems"])
    items = {"registry": {"doc": reg}, "people": {"doc": people}}
    both = c.post("/console/api/config-set/check", json={"items": items}, headers=H("hari")).json()
    assert not [p for k in both for p in both[k]["problems"] if p["severity"] == "error"]
    saved = c.post("/console/api/config-set/drafts", json={"items": items, "note": "desk"}, headers=H("hari")).json()
    ids = [saved["people"]["version"]["id"], saved["registry"]["version"]["id"]]
    r = c.post("/console/api/config-set/publish", json={"version_ids": ids}, headers=H("hari"))
    assert r.status_code == 200 and len(r.json()["versions"]) == 2
    assert eng.registry.get("job_timeout").owner_role == "desk" and "desk" in eng.directory.roles
    rv = eng.store.open_review_for(eng.ingest(stuck_event(age=2)).incident_id)
    assert rv.assignee_role == "desk"


def test_insights_from_the_console(console):
    pytest.importorskip("duckdb")
    eng, c = console
    eng.ingest(job_event(ref="J1", key="a"))
    rows = c.get("/console/api/analytics/automation", headers=H("ravi")).json()
    assert rows[0]["pattern_id"] == "job_timeout" and rows[0]["auto"] == 1
    assert c.get("/console/api/analytics/nope", headers=H("ravi")).status_code == 404


def test_api_process_syncs_configuration_published_elsewhere(engine_factory, tmp_path):
    import time
    from sentinel import Engine
    from tests.conftest import make_overlay
    path = str(tmp_path / "s.db")
    eng = engine_factory(store=SQLiteStore(path))
    other = Engine(make_overlay(eng.overlay.services["backend"]), store=SQLiteStore(path))
    app = create_app(other, {token_hash("hari"): Principal("person", "hari")}, config_sync_s=0.05)
    with TestClient(app):
        reg = yaml.safe_load(eng.config_text("registry"))
        reg["patterns"][0]["sla_minutes"] = 3
        from sentinel.config import dump_yaml
        eng.publish_config(eng.save_config("registry", dump_yaml(reg), "m")[0].id, actor="m")
        for _ in range(100):
            if other.registry.get(reg["patterns"][0]["id"]).sla_minutes == 3:
                break
            time.sleep(0.02)
        assert other.registry.get(reg["patterns"][0]["id"]).sla_minutes == 3


def test_connectors_from_the_console(console):
    eng, c = console
    from sentinel.config import dump_yaml
    doc = {"sources": {"jobs": {"kind": "webhook", "emit": [{"type": "job.failed", "key": "j:{{body.id}}", "payload": {
        "system": "{{body.sys}}", "error_code": "TIMEOUT", "ref": "{{body.id}}"}}]}}}
    vid = c.post("/console/api/config/connectors/drafts", json={"doc": doc}, headers=H("hari")).json()["version"]["id"]
    assert c.post(f"/console/api/config/versions/{vid}/publish", json={}, headers=H("hari")).status_code == 200
    info = c.get("/console/api/connectors", headers=H("ravi")).json()
    assert info["sources"][0]["name"] == "jobs" and info["sources"][0]["emits"] == ["job.failed"]
    r = c.post("/console/api/sources/jobs/try", json={"body": {"id": "J5", "sys": "billing"}}, headers=H("ravi")).json()
    assert r["events"][0]["pattern"] == "job_timeout" and r["events"][0]["facts"]["system"] == "billing"
    assert eng.store.incidents() == []                                # trying never ingests
    assert c.post("/console/api/sources/nope/try", json={"body": {}}, headers=H("ravi")).status_code == 404
    assert c.post("/console/api/sources/jobs/poll", json={}, headers=H("ravi")).status_code == 403
    assert dump_yaml(doc)
