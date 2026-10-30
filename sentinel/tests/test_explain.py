# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""A3 dry-run trace and A2 case explorer: read-only views of what Sentinel would do and did."""
from __future__ import annotations

import yaml

from sentinel import Decision, DecisionKind, Event
from tests.conftest import job_event, stuck_event
from tests.test_config import edit_pattern, registry_doc


def _counts(eng):
    return (len(eng.store.incidents()), len(eng.store.audit_log()), len(eng.store.model_runs()))


def test_trace_explains_and_writes_nothing(engine_factory, backend):
    eng = engine_factory()
    before = _counts(eng)
    t = eng.trace(job_event(error="TIMEOUT", ref="T1"))
    assert _counts(eng) == before and backend.calls == []
    assert t["pattern"]["id"] == "job_timeout" and t["facts"]["error"] == "TIMEOUT"
    assert t["outcome"] == "automatic" and t["playbook"]["proposal"]["steps"] == [
        {"action": "retry", "params": {"ref": "T1"}}]
    other = next(c for c in t["candidates"] if c["pattern"] == "job_failed_other")
    assert other["matches"] is True                                     # both match; the more specific wins
    assert any("2 patterns matched" in s for s in t["steps"])
    h = eng.trace(job_event(error="AUTH", ref="T2"))
    jt = next(c for c in h["candidates"] if c["pattern"] == "job_timeout")
    assert jt["matches"] is False and jt["clauses"] == [{"fact": "error", "want": "TIMEOUT", "got": "AUTH",
                                                         "present": True, "ok": False}]
    assert h["outcome"] == "person" and h["route"]["route"] == "hitl"
    u = eng.trace(Event(type="nobody.knows", source="x"))
    assert u["pattern"]["id"] == "__unmatched__" and any("no pattern handles" in s for s in u["steps"])


def test_trace_sees_duplicates_grouping_and_suppression(engine_factory):
    eng = engine_factory()
    ev = job_event(error="AUTH", ref="G1")
    eng.ingest(ev)
    assert eng.trace(ev)["outcome"] == "duplicate"
    g = eng.trace(job_event(error="AUTH", ref="G2"))                    # same system + error: same signature
    assert g["outcome"] == "grouped"
    eng.ingest(Event(type="site.down", source="mon", payload={"site": "S9"}))
    s = eng.trace(stuck_event(ref="X", site="S9"))
    assert s["outcome"] == "suppressed" and s["parent"]


def test_trace_against_a_draft_registry(engine_factory):
    eng = engine_factory()
    doc = registry_doc(eng)
    draft = edit_pattern(doc, "job_timeout", match={"error": ["TIMEOUT", "AUTH"]})
    t = eng.trace(job_event(error="AUTH", ref="D1"), registry_text=draft)
    assert t["draft"] is True and t["pattern"]["id"] == "job_timeout"
    assert eng.trace(job_event(error="AUTH", ref="D1"))["pattern"]["id"] == "job_failed_other"
    bad = eng.trace(job_event(), registry_text=yaml.safe_dump({"patterns": [{"id": "x"}]}))
    assert bad["error"] and bad["problems"]


def test_trace_playbook_lookups_only_when_asked(engine_factory, overlay):
    from tests.test_playbooks import branching
    from sentinel import Tool
    i = next(n for n, p in enumerate(overlay.patterns) if p.id == "item_stuck_long")
    overlay.patterns[i] = branching(allowed_actions=["hold", "notify"])
    overlay.tools.register(Tool("stock", "stock", {"ref": "str"}, lambda a, s: {"qty": 2, "where": "W1",
                                                                                "status": "open"}))
    eng = engine_factory(ov=overlay)
    stop = eng.trace(stuck_event(ref="L1"))
    assert stop["pattern"]["id"] == "item_stuck_long" and stop["playbook"]["proposal"] is None
    assert "lookup not run" in stop["playbook"]["steps"][0]["result"]
    run = eng.trace(stuck_event(ref="L1"), run_lookups=True)
    assert [s["result"] for s in run["playbook"]["steps"]][:2] == ["looked up", "skipped: condition does not hold"]
    assert run["playbook"]["proposal"]["steps"][0]["action"] == "hold"


def test_case_story_search_and_reverse_info(engine_factory, backend):
    eng = engine_factory()
    a = eng.ingest(job_event(error="TIMEOUT", ref="C1", key="c1"))       # automatic
    b = eng.ingest(job_event(error="AUTH", ref="ORD-77QX", key="c2"))          # a person
    rid = eng.store.open_review_for(b.incident_id).id
    eng.decide(rid, Decision(kind=DecisionKind.REJECT, actor="lata", disposition_code="no_action"))
    c = eng.case(a.incident_id)
    kinds = [t["kind"] for t in c["timeline"]]
    assert kinds[0] == "created" and "action_run" in kinds
    assert c["events"][0]["payload"]["ref"] == "C1" and c["disposition"]["code"] == "resolved"
    assert c["reverse"]["possible"] is True and c["closed"] is True
    assert all(t["ts"] is not None for t in c["timeline"])
    hc = eng.case(b.incident_id)
    assert any("lata decided: reject" in t["what"] for t in hc["timeline"]) and hc["reviews"][0]["open"] is False
    assert eng.case("inc_nope") is None
    found = eng.search_cases(None, text="ord-77qx")["cases"]
    assert [x["id"] for x in found] == [b.incident_id]
    assert {x["id"] for x in eng.search_cases(None, pattern="job_timeout")["cases"]} == {a.incident_id}
    assert [x["id"] for x in eng.search_cases(None, facts={"error": "AUTH"})["cases"]] == [b.incident_id]
    for i in range(5):
        eng.ingest(job_event(error="TIMEOUT", ref=f"P{i}", system=f"s{i}", key=f"p{i}"))
    page1 = eng.search_cases(None, limit=3)
    page2 = eng.search_cases(None, limit=3, before=tuple(page1["next"].split(":", 1)) and
                             (float(page1["next"].split(":", 1)[0]), page1["next"].split(":", 1)[1]))
    ids = [x["id"] for x in page1["cases"] + page2["cases"]]
    assert len(ids) == len(set(ids)) == 6
    assert eng.search_cases(None, text="50%_")["cases"] == []          # wildcards are literal


def test_trace_and_case_cli(tmp_path, capsys):
    import json

    from sentinel.cli import main
    base = ["--overlay", "tests.test_templates_cli:_overlay", "--db", str(tmp_path / "c.db")]
    f = tmp_path / "e.json"
    f.write_text(json.dumps({"system": "billing", "error_code": "TIMEOUT", "ref": "Z1"}))
    assert main([*base, "trace", str(f), "--type", "job.failed"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["pattern"]["id"] == "job_timeout" and out["outcome"] == "person"      # default guardrails
    assert any("cannot be undone" in s for s in out["steps"])
    assert main([*base, "case", "inc_none"]) == 1


def test_replay_reports_what_a_draft_changes(engine_factory):
    """A4: recent cases through the running registry and a draft; only the draft's effect is reported."""
    eng = engine_factory()
    for i in range(3):
        eng.ingest(job_event(error="AUTH", ref=f"R{i}", system=f"s{i}", key=f"r{i}"))
    eng.ingest(job_event(error="TIMEOUT", ref="R9", system="x", key="r9"))
    doc = registry_doc(eng)
    same = eng.replay(eng.config_text("registry"))
    assert same["cases"] == 4 and same["changed"] == 0
    draft = edit_pattern(doc, "job_timeout", match={"error": ["TIMEOUT", "AUTH"]})
    before = len(eng.store.audit_log())
    r = eng.replay(draft)
    assert len(eng.store.audit_log()) == before                    # read-only
    assert r["cases"] == 4 and r["changed"] == 3 and r["unchanged"] == 1
    assert r["changes"]["pattern: job_failed_other -> job_timeout"] == 3
    assert r["examples"][0]["draft"]["pattern"] == "job_timeout"
    assert eng.replay("patterns: [{id: x}]")["error"]


def test_console_trace_cases_and_replay_rights(engine_factory):
    import pytest
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from sentinel.api import Principal, create_app, token_hash
    from sentinel.rbac import AuthorityRule
    from tests.test_rbac import make_directory
    d = make_directory()
    d.rules.append(AuthorityRule(role_id="ops_head", action="__configure__"))
    eng = engine_factory(directory=d)
    r = eng.ingest(job_event(error="AUTH", ref="Q1", key="q1"))
    c = TestClient(create_app(eng, {token_hash("h"): Principal("person", "hari"),
                                    token_hash("a"): Principal("person", "asha")}, config_sync_s=0))
    H, A = {"Authorization": "Bearer h"}, {"Authorization": "Bearer a"}
    ev = {"type": "job.failed", "payload": {"system": "billing", "error_code": "AUTH", "ref": "Q2"}}
    assert c.post("/console/api/trace", json={"event": ev}, headers=A).json()["pattern"]["id"] == "job_failed_other"
    assert c.post("/console/api/trace", json={"event": ev, "run_lookups": True}, headers=A).status_code == 403
    assert c.post("/console/api/trace", json={"event": {"payload": {}}}, headers=A).status_code == 422
    text = eng.config_text("registry")
    assert c.post("/console/api/config/registry/replay", json={"text": text}, headers=A).status_code == 403
    assert c.post("/console/api/config/registry/replay", json={"text": text}, headers=H).json()["changed"] == 0
    assert c.get("/console/api/cases?text=Q1", headers=H).json()["cases"][0]["id"] == r.incident_id
    assert c.get(f"/console/api/cases/{r.incident_id}", headers=H).status_code == 200
    assert c.get("/console/api/cases/inc_nope", headers=H).status_code == 404
    assert c.get("/console/api/cases?fact=bad", headers=H).status_code == 422
    assert c.get("/console/api/cases?fact=a%20b=1", headers=H).status_code == 422       # bad fact name
