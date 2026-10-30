# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""Capabilities, methods of work and the decision trace; data that must be trusted before anyone acts on it.

The loop being proved: event -> case (stamped with capability, method, definition and registry version) ->
routing -> decision -> verified outcome, every link recorded; a new method version is compared with the old on
real cases; data that fails its checks stops monitors acting and asks its owner to fix it."""
from __future__ import annotations

from datetime import timedelta

import pytest
import yaml

from sentinel import Capability, Decision, DecisionKind, Event, FingerprintRule, Guardrails, Pattern, PlaybookStep
from sentinel import IncidentState as S, Route, load_layers
from sentinel.config import dump_yaml
from sentinel.models import ClearEvent, ClearWhen
from sentinel.overlay import parse_registry
from sentinel.rbac import AuthorityRule
from tests.conftest import Backend, job_event, make_overlay
from tests.test_rbac import make_directory

CAPS = {
    "jobs": Capability(title="Batch jobs", owner="ops", intent=["Every scheduled job runs to completion"],
                       outcomes=["failed_jobs"]),
    "stock": Capability(title="Stock", owner="lead", mode="observe", max_route=Route.LLM),
}


def _patterns() -> list[Pattern]:
    return [
        Pattern(id="job_timeout", event_types=["job.failed"], match={"error": "TIMEOUT"}, route=Route.AUTO,
                playbook=[PlaybookStep(action="retry", params={"ref": "{{payload.ref}}"})],
                allowed_actions=["retry", "notify"], owner_role="ops", capability="jobs", method="retry_once@1",
                outcome_check={"verifier": "job_ok", "after_minutes": 10}),
        Pattern(id="job_failed_other", event_types=["job.failed"], match={"system": "*"}, route=Route.HITL,
                allowed_actions=["retry", "cancel", "notify"], owner_role="ops", capability="jobs",
                method="look@1"),
        Pattern(id="item_stuck_long", event_types=["item.stuck"], match={"age": ">24h"}, route=Route.LLM,
                max_route=Route.LLM, allowed_actions=["hold"], owner_role="ops", capability="stock",
                playbook=[PlaybookStep(action="hold", params={"ref": "{{payload.ref}}"})]),
    ]


@pytest.fixture
def eng(engine_factory):
    ov = make_overlay(Backend(), patterns=_patterns())
    ov.capabilities = dict(CAPS)
    ov.verifiers = {"job_ok": lambda **kw: True}
    return engine_factory(ov=ov, directory=_directory(), guardrails=Guardrails(allow_irreversible_unattended=True))


def _directory():
    d = make_directory()
    d.rules.append(AuthorityRule(role_id="ops_head", action="__configure__"))
    return d


# ------------------------------------------------------------------------------------------ registry
def test_capabilities_are_validated():
    base = {"roles": {"ops": "x", "lead": "y"}, "patterns": [
        {"id": "a", "event_types": ["e"], "capability": "jobs", "max_route": "auto", "owner_role": "ops"}]}
    doc = parse_registry({**base, "capabilities": {"jobs": {"title": "Jobs", "owner": "ops"}}})
    assert doc.capabilities["jobs"].owner == "ops"
    with pytest.raises(ValueError, match="unknown capability"):
        parse_registry({**base, "capabilities": {}})
    with pytest.raises(ValueError, match="above capability jobs"):
        parse_registry({**base, "capabilities": {"jobs": {"title": "Jobs", "max_route": "hitl"}}})
    with pytest.raises(ValueError, match="not a known role"):
        parse_registry({**base, "capabilities": {"jobs": {"title": "Jobs", "owner": "ghost"}}})
    with pytest.raises(ValueError, match="mode"):
        parse_registry({**base, "capabilities": {"jobs": {"title": "Jobs", "mode": "maybe"}}})


def test_layers_merge_capabilities_and_the_console_keeps_them(tmp_path, eng):
    (tmp_path / "trunk.yaml").write_text(yaml.safe_dump({
        "roles": {"ops": "x"}, "capabilities": {"jobs": {"title": "Jobs"}},
        "patterns": [{"id": "a", "event_types": ["e"], "capability": "jobs", "owner_role": "ops"}]}))
    (tmp_path / "site.yaml").write_text(yaml.safe_dump({"capabilities": {"jobs": {"title": "Jobs here", "mode": "observe"}}}))
    doc = load_layers([tmp_path / "trunk.yaml", tmp_path / "site.yaml"])
    assert doc.capabilities["jobs"].title == "Jobs here" and doc.capabilities["jobs"].mode == "observe"
    text = eng.config_text("registry")
    assert "capabilities:" in text and "retry_once@1" in text
    data = yaml.safe_load(text)
    data["capabilities"]["jobs"]["intent"].append("No job is cancelled without a person")
    cv, probs = eng.save_config("registry", dump_yaml(data), "hari")
    assert not [p for p in probs if p.severity == "error"], probs
    eng.publish_config(cv.id, "hari")
    assert "No job is cancelled without a person" in eng.capabilities["jobs"].intent


def test_an_observe_only_capability_acts_on_nothing(eng):
    r = eng.ingest(Event(type="item.stuck", source="wms", payload={"ref": "I1", "site": "S1", "age_hours": 40}))
    inc = eng.store.get_incident(r.incident_id)
    assert inc.shadow and inc.provenance.capability == "stock"


# ------------------------------------------------------------------------------- provenance and methods
def test_every_case_records_what_decided_it_and_methods_are_compared(eng, clock):
    r = eng.ingest(job_event(ref="J1"))
    inc = eng.store.get_incident(r.incident_id)
    pv = inc.provenance
    assert (pv.capability, pv.method, pv.config) == ("jobs", "retry_once@1", None) and len(pv.definition) == 16
    d1 = eng.store.get_disposition(inc.id)
    assert d1.resolver == "auto" and d1.provenance == pv

    # a new version of the method: published through the console, so the case also records the registry version
    data = yaml.safe_load(eng.config_text("registry"))
    p = next(x for x in data["patterns"] if x["id"] == "job_timeout")
    p["method"] = "retry_then_notify@2"
    p["playbook"].append({"action": "notify", "params": {"ref": "{{payload.ref}}", "msg": "retried"}})
    cv, _ = eng.save_config("registry", dump_yaml(data), "hari")
    eng.publish_config(cv.id, "hari")
    clock.advance(minutes=1)
    r2 = eng.ingest(job_event(ref="J2"))
    pv2 = eng.store.get_incident(r2.incident_id).provenance
    assert pv2.method == "retry_then_notify@2" and pv2.definition != pv.definition
    assert pv2.config == f"v{cv.version}"

    clock.advance(minutes=11)
    eng.work("w")                                       # outcome checks
    ev = eng.method_evidence()
    rows = {(m["pattern"], m["method"]): m for m in ev["methods"]}
    old, new = rows[("job_timeout", "retry_once@1")], rows[("job_timeout", "retry_then_notify@2")]
    assert old["current"] is False and new["current"] is True
    assert old["cases"] == new["cases"] == 1 and old["unattended"] == 1 and old["outcomes"]["held"] == 1
    assert new["configs"] == [f"v{cv.version}"]
    assert eng.method_evidence(capability="stock")["methods"] == []


def test_the_case_story_is_one_decision_trace(eng, clock):
    r = eng.ingest(Event(type="job.failed", source="scheduler", correlation_id="batch-42",
                         payload={"system": "billing", "error_code": "TIMEOUT", "ref": "J9"}))
    clock.advance(minutes=11)
    eng.work("w")
    t = eng.case(r.incident_id)["trace"]
    assert t["observed"][0]["correlation_id"] == "batch-42"
    assert (t["capability"], t["method"]) == ("jobs", "retry_once@1")
    assert t["resolved"]["resolver"] == "auto" and t["actions"][0]["action"] == "retry"
    assert t["outcome"]["verdict"] == "held" and t["complete"] and t["gaps"] == []

    r2 = eng.ingest(job_event(error="AUTH", ref="J10"))            # a person has to decide this one
    t2 = eng.case(r2.incident_id)["trace"]
    assert not t2["complete"] and "not resolved yet" in t2["gaps"]
    rev = eng.store.open_review_for(r2.incident_id)
    eng.decide(rev.id, Decision(kind=DecisionKind.MODIFY, actor="ravi", action="notify",
                                params={"ref": "J10", "msg": "credentials expired"}))
    t2 = eng.case(r2.incident_id)["trace"]
    assert t2["complete"] and t2["decisions"][0]["actor"] == "ravi" and t2["resolved"]["actor"] == "human:ravi"


def test_capability_overview(eng, clock):
    eng.ingest(job_event(ref="J1"))
    clock.advance(minutes=11)
    eng.work("w")
    caps = {c["id"]: c for c in eng.capability_overview()["capabilities"]}
    jobs = caps["jobs"]
    assert jobs["owner"] == "ops" and {e["id"] for e in jobs["exceptions"]} == {"job_timeout", "job_failed_other"}
    assert jobs["outcomes"][0]["error"] == "not a configured metric"     # no metrics configured here
    assert jobs["stats"]["outcomes"]["held"] == 1 and jobs["stage"] == "acting"
    assert caps["stock"]["mode"] == "observe" and caps["stock"]["exceptions"][0]["shadow"] is True
    assert caps["stock"]["stage"] == "observed"


def test_configuration_warns_about_loose_ends(eng):
    data = yaml.safe_load(eng.config_text("registry"))
    data["capabilities"]["empty"] = {"title": "Nothing yet", "outcomes": ["nope"]}
    data["patterns"][1].pop("capability")
    _, probs = eng.check_config("registry", dump_yaml(data))
    msgs = [p.message for p in probs]
    assert any("exceptions with no capability" in m and "job_failed_other" in m for m in msgs)


# ----------------------------------------------------------------------------------- data trust

BANK: dict[str, list[dict]] = {"rows": []}


def _bank(services, now):
    return list(BANK["rows"])


def _lines(now, n=30, dup=False, stale=False):
    base = now - timedelta(days=3 if stale else 0, hours=1)
    rows = [{"line_id": f"L{i}", "account": "HDFC-01", "amount": 100.0 + i, "booked_at": (base - timedelta(hours=i)).isoformat(),
             "matched": i % 10 != 0} for i in range(n)]
    if dup:
        rows.append(dict(rows[0]))
    return rows


TRUST_METRICS = {
    "datasets": {"bank_lines": {"kind": "overlay", "name": "bank_lines", "refresh_minutes": 1, "owner": "lead",
                                "checks": {"fresh": "booked_at", "max_age_hours": 26, "min_rows": 10,
                                           "unique": ["line_id"], "not_null": ["amount"],
                                           "invalid": {"no_account": "account is null or account = ''"}}}},
    "metrics": {"unmatched": {"title": "Unmatched bank lines", "dataset": "bank_lines", "time": "booked_at",
                              "value": "sum(case when matched then 0 else 1 end)", "dimensions": ["account"],
                              "target": {"lte": 0}, "owner": "ops"}},
    "monitors": {"unmatched_by_account": {"metric": "unmatched", "by": ["account"], "window_days": 7,
                                          "every_minutes": 60}},
}


@pytest.fixture
def teng(engine_factory, clock):
    pytest.importorskip("duckdb")
    ov = make_overlay(Backend(), patterns=[
        Pattern(id="recon_break", event_types=["kpi.breach"], match={"metric": "unmatched"}, route=Route.HITL,
                allowed_actions=["notify"], owner_role="ops",
                clear_when=ClearWhen(events=[ClearEvent(type="kpi.recovered", same=["metric", "account"])]),
                outcome_check={"verifier": "metric", "after_minutes": 60,
                               "params": {"metric": "unmatched", "facts": ["account"]}}),
        Pattern(id="data_untrusted", event_types=["data.untrusted"], route=Route.HITL, max_route=Route.HITL,
                allowed_actions=[], owner_role="lead",
                clear_when=ClearWhen(events=[ClearEvent(type="data.trusted", same=["dataset"])]))])
    ov.fingerprint_rules += [
        FingerprintRule(event_type="kpi.breach", fields={"metric": "metric", "account": "account"},
                        group_by=["metric", "account"]),
        FingerprintRule(event_type="kpi.recovered", fields={"metric": "metric", "account": "account"}),
        FingerprintRule(event_type="kpi.raised", fields={"metric": "metric"}),
        FingerprintRule(event_type="data.untrusted", fields={"dataset": "dataset"}, group_by=["dataset"]),
        FingerprintRule(event_type="data.trusted", fields={"dataset": "dataset"})]
    ov.datasets = {"bank_lines": _bank}
    BANK["rows"] = _lines(clock())
    e = engine_factory(ov=ov, directory=_directory(), guardrails=Guardrails())
    cv, probs = e.save_config("metrics", yaml.safe_dump(TRUST_METRICS), author="hari")
    assert not [p for p in probs if p.severity == "error"], probs
    assert not [p for p in probs if "data" in p.message], probs
    e.publish_config(cv.id, actor="hari")
    return e


def test_trusted_data_lets_the_monitor_act(teng):
    res = teng.kpi.query("unmatched", days=7)
    assert res["trusted"] is True and res["total"]["value"] == 3
    assert teng.run_monitor("unmatched_by_account")["raised"] == ["account=HDFC-01"]


@pytest.mark.parametrize("bad, problem", [
    (lambda now: _lines(now, dup=True), "duplicate line_id"),
    (lambda now: _lines(now, stale=True), "stale"),
    (lambda now: _lines(now, n=5), "at least 10"),
    (lambda now: [{**r, "account": None} if i == 3 else r for i, r in enumerate(_lines(now))], "no_account"),
])
def test_untrusted_data_stops_monitors_and_asks_its_owner(teng, clock, bad, problem):
    BANK["rows"] = bad(clock())
    out = teng.run_monitor("unmatched_by_account")
    assert out["raised"] == [] and problem in out["skipped"]
    res = teng.kpi.query("unmatched", days=7)
    assert res["trusted"] is False and any(problem in p for p in res["trust_problems"])
    inc = next(i for i in teng.store.incidents() if i.pattern_id == "data_untrusted")
    assert teng.store.open_review_for(inc.id).assignee_role == "lead" and inc.facts["dataset"] == "bank_lines"
    clock.advance(minutes=61)
    teng.run_monitor("unmatched_by_account")                         # still bad: the same case, reported again
    assert len([i for i in teng.store.incidents() if i.pattern_id == "data_untrusted"]) == 1
    BANK["rows"] = _lines(clock())                                    # the owner fixed the data
    clock.advance(minutes=2)
    assert teng.run_monitor("unmatched_by_account")["raised"] == ["account=HDFC-01"]
    assert teng.store.get_incident(inc.id).state is S.DISPOSITIONED
    assert teng.store.get_disposition(inc.id).code == "resolved_in_source"


def test_an_open_breach_is_neither_raised_nor_closed_on_untrusted_data(teng, clock):
    teng.run_monitor("unmatched_by_account")
    brk = next(i for i in teng.store.incidents() if i.pattern_id == "recon_break")
    rows = [{**r, "matched": True} for r in _lines(clock())]
    rows.append(dict(rows[0]))                                        # looks fixed, but the data is not trusted
    BANK["rows"] = rows
    clock.advance(minutes=2)
    assert teng.run_monitor("unmatched_by_account")["recovered"] == []
    assert teng.store.get_incident(brk.id).state is not S.DISPOSITIONED
    rev = teng.store.open_review_for(brk.id)
    teng.decide(rev.id, Decision(kind=DecisionKind.MODIFY, actor="ravi", action="notify",
                                 params={"ref": "HDFC-01", "msg": "matched by hand"}))
    clock.advance(minutes=61)
    teng.work("w")
    assert teng.store.get_disposition(brk.id).outcome != "held"       # no verdict on untrusted data


# ---- v0.14.2: malformed values, the verifier's window, checking a fix made outside Sentinel --------------
def _typed(teng):
    doc = {**TRUST_METRICS, "datasets": {"bank_lines": {**TRUST_METRICS["datasets"]["bank_lines"],
           "checks": {**TRUST_METRICS["datasets"]["bank_lines"]["checks"],
                      "types": {"matched": "boolean", "booked_at": "time", "amount": "number"}}}}}
    cv, probs = teng.save_config("metrics", yaml.safe_dump(doc), author="hari")
    assert not [p for p in probs if p.severity == "error"], probs
    teng.publish_config(cv.id, actor="hari")


@pytest.mark.parametrize("typed", [True, False])
@pytest.mark.parametrize("bad, problem", [
    ({"matched": "yes"}, "matched"),
    ({"booked_at": "13/10/2026"}, "booked_at"),
])
def test_a_malformed_value_makes_the_data_untrusted_and_never_fails_the_monitor(teng, clock, typed, bad, problem):
    if typed:
        _typed(teng)
    rows = _lines(clock())
    rows[1] = {**rows[1], **bad}
    BANK["rows"] = rows
    clock.advance(minutes=2)
    out = teng.run_monitor("unmatched_by_account")                    # never raises
    assert out["raised"] == [] and problem in out["skipped"], out
    inc = next(i for i in teng.store.incidents() if i.pattern_id == "data_untrusted")
    assert teng.store.open_review_for(inc.id).assignee_role == "lead"
    if typed:                                                         # the metric still runs on typed data
        res = teng.kpi.query("unmatched", days=7)
        assert res["trusted"] is False and res["total"]["value"] is not None


def test_typed_columns_load_good_data_unchanged(teng, clock):
    _typed(teng)
    clock.advance(minutes=2)
    assert teng.run_monitor("unmatched_by_account")["raised"] == ["account=HDFC-01"]
    assert teng.kpi.query("unmatched", days=7)["total"]["value"] == 3


def test_the_metric_verifier_with_days_sees_what_was_wrong_before_the_fix(teng, clock):
    teng.registry.get("recon_break").outcome_check["params"]["days"] = 7
    teng.run_monitor("unmatched_by_account")
    brk = next(i for i in teng.store.incidents() if i.pattern_id == "recon_break")
    rev = teng.store.open_review_for(brk.id)
    teng.decide(rev.id, Decision(kind=DecisionKind.MODIFY, actor="ravi", action="notify",
                                 params={"ref": "HDFC-01", "msg": "chased"}))
    clock.advance(minutes=61)
    BANK["rows"] = _lines(clock() - timedelta(minutes=61))          # nothing changed in the books
    teng.work("w")
    assert teng.store.get_disposition(brk.id).outcome == "failed"


def test_a_close_with_an_outcome_code_is_verified_and_other_closes_are_not(teng, clock):
    teng.registry.get("recon_break").outcome_check.update(codes=["resolved"])
    teng.registry.get("recon_break").outcome_check["params"]["days"] = 7
    teng.run_monitor("unmatched_by_account")
    brk = next(i for i in teng.store.incidents() if i.pattern_id == "recon_break")
    teng.decide(teng.store.open_review_for(brk.id).id,
                Decision(kind=DecisionKind.REJECT, actor="ravi", disposition_code="resolved"))
    BANK["rows"] = [{**r, "matched": True} for r in _lines(clock())]     # it really was fixed in the books
    clock.advance(minutes=61)
    teng.work("w")
    assert teng.store.get_disposition(brk.id).outcome == "held"
    # a false positive is not a fix: nothing to verify
    BANK["rows"] = _lines(clock())
    clock.advance(minutes=61)
    teng.run_monitor("unmatched_by_account")
    brk2 = next(i for i in teng.store.incidents() if i.pattern_id == "recon_break" and i.id != brk.id)
    teng.decide(teng.store.open_review_for(brk2.id).id,
                Decision(kind=DecisionKind.REJECT, actor="ravi", disposition_code="false_positive"))
    clock.advance(minutes=61)
    teng.work("w")
    assert teng.store.get_disposition(brk2.id).outcome is None


def test_outcome_codes_must_be_the_patterns_codes(engine_factory):
    from sentinel import EngineError
    ov = make_overlay(Backend(), patterns=[
        Pattern(id="x", event_types=["job.failed"], route=Route.HITL, allowed_actions=["notify"], owner_role="ops",
                outcome_check={"verifier": "metric", "codes": ["nope"]})])
    with pytest.raises(EngineError, match="not disposition codes"):
        engine_factory(ov=ov, directory=_directory(), guardrails=Guardrails())
