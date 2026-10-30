# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""How long a case lives: repeat limits, closing at the source, expiry, pauses, silences and defaults."""
from __future__ import annotations

import pytest

from sentinel import Event, Guardrails, IncidentState as S, Pattern, PlaybookStep, Route
from sentinel.engine import AuthorizationError, EngineError
from sentinel.models import ClearEvent, ClearLookup, ClearWhen, EscalationRule
from tests.conftest import Backend, job_event, make_overlay
from tests.test_rbac import make_directory

STATUS = {"value": "stuck"}


def _overlay(backend, notes, **over):
    base = dict(id="job_failed_other", event_types=["job.failed"], match={"system": "*"}, route=Route.HITL,
                allowed_actions=["retry", "notify"], owner_role="ops", escalation_role="lead", sla_minutes=240)
    base.update(over)
    pats = [Pattern(**base),
            Pattern(id="job_timeout", event_types=["job.failed"], match={"error": "TIMEOUT"}, route=Route.AUTO,
                    playbook=[PlaybookStep(action="retry", params={"ref": "{{payload.ref}}"})],
                    allowed_actions=["retry"], owner_role="ops", priority=5)]
    ov = make_overlay(backend, patterns=pats, notes=notes)

    @ov.tools.tool("job_status", "the job's status now", {"ref": "str"})
    def job_status(args, services):
        return {"ref": args["ref"], "status": STATUS["value"]}
    return ov


@pytest.fixture
def make(engine_factory, notes):
    def mk(**over):
        STATUS["value"] = "stuck"
        d = make_directory()
        return engine_factory(ov=_overlay(Backend(), notes, **over), directory=d,
                              guardrails=Guardrails(allow_irreversible_unattended=True))
    return mk


def _case(eng, ref="J1", system="hr", error="AUTH"):
    r = eng.ingest(job_event(error=error, ref=ref, system=system))
    return r.incident_id, eng.store.open_review_for(r.incident_id)


def test_escalation_stops_at_the_top_and_goes_on_the_daily_list(make, clock, notes):
    eng = make(escalation=EscalationRule(repeat=1))
    inc, rev = _case(eng)
    roles = []
    for _ in range(6):
        clock.advance(minutes=241)
        eng.sweep()
        r = eng.store.get_review(rev.id)
        roles.append((r.assignee_role, r.escalation_level, r.quiet))
    # owner ops -> lead (escalation role) -> ops_head (top) -> once more at the top -> quiet, and stays quiet
    assert roles[:4] == [("lead", 1, False), ("ops_head", 2, False), ("ops_head", 3, False), ("ops_head", 3, True)]
    assert roles[4:] == [("ops_head", 3, True)] * 2
    kinds = [a["kind"] for a in eng.store.recent_audit(100) if a.get("incident_id") == inc]
    assert kinds.count("escalation_stopped") == 1 and kinds.count("escalated") == 3
    assert eng.store.review_counts(clock())["overdue"] == 1                  # still overdue on the console
    clock.now = clock.now.replace(hour=10) if clock.now.hour < 9 else clock.now
    eng.sweep()
    assert any(k == "overdue_digest" for k, _ in notes)
    sent = len([1 for k, _ in notes if k == "overdue_digest"])
    eng.sweep()                                                               # once a day
    assert len([1 for k, _ in notes if k == "overdue_digest"]) == sent


def test_unlimited_without_a_rule(make, clock):
    eng = make()
    _, rev = _case(eng)
    for _ in range(6):
        clock.advance(minutes=241)
        eng.sweep()
    r = eng.store.get_review(rev.id)
    assert not r.quiet and r.escalation_level == 6 and r.top_repeats == 4


def test_closes_when_the_source_says_it_is_fixed(make):
    eng = make(clear_when=ClearWhen(events=[ClearEvent(type="job.recovered", same=["system"])]))
    inc, rev = _case(eng, system="hr")
    other, _ = _case(eng, system="payroll", ref="J2")
    res = eng.ingest(Event(type="job.recovered", source="scheduler", payload={"system": "hr"}))
    assert res.status == "cleared" and res.incident_id == inc
    d = eng.store.get_disposition(inc)
    assert d.code == "resolved_in_source" and d.resolver == "system"
    assert not eng.store.get_review(rev.id).open
    assert eng.store.get_incident(other).state is S.AWAITING_HUMAN             # another system: untouched
    st = eng.store.get_pattern_state("job_failed_other")
    assert st is None or st.samples == 0                                       # teaches nothing
    again = eng.ingest(Event(type="job.recovered", source="scheduler", payload={"system": "billing"}))
    assert again.status == "no_case" and again.incident_id is None             # not an unmatched case
    assert not [i for i in eng.store.incidents() if i.pattern_id == "__unmatched__"]


def test_closes_when_a_lookup_shows_it_is_fixed(make, clock):
    eng = make(clear_when=ClearWhen(lookup=ClearLookup(tool="job_status", args={"ref": "{{payload.ref}}"},
                                                       condition={"result.status": "done"}, every_minutes=30)))
    inc, _ = _case(eng)
    clock.advance(minutes=31)
    eng.work("w")
    assert eng.store.get_incident(inc).state is S.AWAITING_HUMAN               # still stuck: asked again later
    STATUS["value"] = "done"
    clock.advance(minutes=31)
    eng.work("w")
    assert eng.store.get_disposition(inc).code == "resolved_in_source"
    clock.advance(minutes=31)
    assert eng.work("w")["done"] == 0                                          # no more checks once closed


def test_untouched_cases_expire_unless_the_source_reports_again(make, clock):
    eng = make(expires_after_hours=24)
    a, _ = _case(eng, ref="A", system="hr")
    b, _ = _case(eng, ref="B", system="payroll")
    clock.advance(hours=20)
    eng.ingest(job_event(error="AUTH", ref="B", system="payroll"))             # b is still happening
    clock.advance(hours=5)
    assert eng.expire_cases() == [a]
    assert eng.store.get_disposition(a).code == "expired"
    assert eng.store.get_incident(b).state is S.AWAITING_HUMAN
    clock.advance(hours=20)
    assert eng.expire_cases() == [b]
    row = next(x for x in eng.value(days=30)["patterns"] if x["pattern"] == "job_failed_other")
    assert row["expired"] == 2 and row["by_people"] == 0


def test_pause_stops_the_clock_and_comes_back(make, clock):
    eng = make(pause_on=["awaiting_customer"])
    inc, rev = _case(eng)
    clock.advance(minutes=60)
    with pytest.raises(EngineError, match="can be paused for"):
        eng.pause_review(rev.id, "ravi", "lunch")
    with pytest.raises(AuthorizationError):
        eng.pause_review(rev.id, "asha", "awaiting_customer")                  # asha only sees billing
    eng.pause_review(rev.id, "ravi", "awaiting_customer", hours=10)
    clock.advance(hours=5)
    eng.sweep()
    r = eng.store.get_review(rev.id)
    assert r.escalation_level == 0 and r.hold.kind == "pause"                  # SLA passed while paused: no escalation
    assert eng.expire_cases() == []
    clock.advance(hours=5, minutes=1)
    eng.sweep()
    r = eng.store.get_review(rev.id)
    assert r.hold is None and r.rounds == 1
    assert 179 <= (r.due_at - clock()).total_seconds() / 60 <= 181              # the 3 hours that were left
    # paused again, then the source reports the problem again: back to a person at once
    eng.pause_review(rev.id, "ravi", "awaiting_customer")
    eng.ingest(job_event(error="AUTH", ref="J1", system="hr"))
    assert eng.store.get_review(rev.id).hold is None
    eng.pause_review(rev.id, "ravi", "awaiting_customer")
    eng.resume_review(rev.id, "lata")
    with pytest.raises(EngineError, match="not paused"):
        eng.resume_review(rev.id, "lata")


def test_silence_holds_cases_and_nothing_runs_on_its_own(make, clock):
    eng = make()
    with pytest.raises(AuthorizationError):
        eng.add_silence("ravi", reason="stock count", hours=2, facts={"system": "hr"})
    s = eng.add_silence("lata", reason="stock count tonight", hours=2, facts={"system": "hr"})
    inc, rev = _case(eng, error="TIMEOUT", system="hr")                        # would retry automatically
    assert eng.store.get_incident(inc).state is S.AWAITING_HUMAN
    assert rev.hold.kind == "silence" and "stock count" in rev.reason
    assert eng.overlay.services["backend"].count("retry") == 0
    other, _ = _case(eng, error="TIMEOUT", system="billing", ref="J9")         # not covered: runs as usual
    assert eng.store.get_disposition(other).resolver == "auto"
    clock.advance(hours=1)
    eng.sweep()
    assert eng.store.get_review(rev.id).hold is not None                        # still held
    clock.advance(hours=1, minutes=1)
    eng.sweep()
    r = eng.store.get_review(rev.id)
    assert r.hold is None and r.rounds == 1 and r.escalation_level == 0
    s2 = eng.add_silence("lata", reason="warehouse move", hours=5, pattern="job_failed_other")
    inc2, rev2 = _case(eng, ref="J3")
    assert rev2.hold.silence_id == s2.id
    eng.end_silence(s2.id, "lata")
    eng.sweep()
    assert eng.store.get_review(rev2.id).hold is None
    assert [x.id for x in eng.silences.active()] == []
    assert {x.id for x in eng.silences.all()} == {s.id, s2.id}


def test_registry_defaults(engine_factory, notes):
    import yaml
    from sentinel.rbac import AuthorityRule
    d = make_directory()
    d.rules.append(AuthorityRule(role_id="ops_head", action="__configure__"))
    eng = engine_factory(ov=_overlay(Backend(), notes), directory=d, guardrails=Guardrails())
    doc = yaml.safe_load(eng.config_text("registry"))
    doc["defaults"] = {"escalation": {"repeat": 0}, "expires_after_hours": 48, "pause_on": ["awaiting_vendor"],
                       "digest_hour": 10, "timezone": "Asia/Kolkata"}
    cv, probs = eng.save_config("registry", yaml.safe_dump(doc), author="hari")
    assert not [p for p in probs if p.severity == "error"], probs
    eng.publish_config(cv.id, actor="hari")
    assert eng.case_defaults.expires_after_hours == 48 and eng.case_defaults.timezone == "Asia/Kolkata"
    assert "defaults" in yaml.safe_load(eng.config_text("registry"))
    _, rev = _case(eng)
    eng.pause_review(rev.id, "ravi", "awaiting_vendor")                         # the default reason applies
    bad = dict(doc, defaults={"expires_after_hours": -1})
    _, probs = eng.check_config("registry", yaml.safe_dump(bad))
    assert any(p.severity == "error" and "defaults" in p.message for p in probs)
    doc["patterns"][0]["clear_when"] = {"events": [{"type": "job.done", "same": ["nope"]}],
                                        "lookup": {"tool": "nope", "condition": {"result.ok": True}}}
    _, probs = eng.check_config("registry", yaml.safe_dump(doc))
    msgs = [(p.severity, p.message) for p in probs]
    assert any(s == "error" and "lookup tool 'nope'" in m for s, m in msgs)
    assert any(s == "warning" and "never close them" in m for s, m in msgs)


def test_escalation_stops_at_the_named_role(make, clock):
    eng = make(escalation=EscalationRule(repeat=0, stop_at="lead"))
    _, rev = _case(eng)
    seen = []
    for _ in range(3):
        clock.advance(minutes=241)
        eng.sweep()
        r = eng.store.get_review(rev.id)
        seen.append((r.assignee_role, r.quiet))
    assert seen == [("lead", False), ("lead", True), ("lead", True)]     # never reaches ops_head
