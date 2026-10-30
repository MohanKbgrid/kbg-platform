# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""RBAC: roles, scopes, approval authority, two-person promotion, kill switch, escalation up the tree."""
from __future__ import annotations

import pytest

from sentinel import (Assignment, AuthorityRule, AuthorizationError, Decision, DecisionKind, Directory, EngineError,
                      Guardrails, IncidentState as S, LearningPolicy, Person, PlaybookStep, Role, Route,
                      load_directory)
from sentinel.rbac import DirectoryError
from tests.conftest import job_event


def make_directory(rules_override=None, **kw) -> Directory:
    roles = [Role(id="ops_head"), Role(id="lead", parent="ops_head"), Role(id="ops", parent="lead"),
             Role(id="supervisor", parent="ops_head"), Role(id="operator", parent="lead")]
    people = [Person(id="asha"), Person(id="ravi"), Person(id="lata"), Person(id="hari"), Person(id="hema"),
              Person(id="gone", active=False)]
    assignments = [Assignment(person_id="asha", role_id="ops", scope={"system": "billing"}),
                   Assignment(person_id="ravi", role_id="ops"),
                   Assignment(person_id="lata", role_id="lead"),
                   Assignment(person_id="hari", role_id="ops_head"),
                   Assignment(person_id="hema", role_id="ops_head"),
                   Assignment(person_id="gone", role_id="ops")]
    rules = [AuthorityRule(role_id="ops", action="retry"), AuthorityRule(role_id="ops", action="notify"),
             AuthorityRule(role_id="ops", action="hold"), AuthorityRule(role_id="ops", action="cancel", level="propose"),
             AuthorityRule(role_id="lead", action="cancel"), AuthorityRule(role_id="lead", action="__kill_switch__"),
             AuthorityRule(role_id="ops_head", action="__promote__"),
             AuthorityRule(role_id="ops_head", action="__set_route__"),
             AuthorityRule(role_id="ops_head", action="__reverse__"),
             AuthorityRule(role_id="lead", action="refund", max_amount=10000),
             AuthorityRule(role_id="ops_head", action="refund")]
    if rules_override is not None:
        rules = rules_override(rules)
    return Directory(roles, people, assignments, rules, **kw)


@pytest.fixture
def rbac_engine(engine_factory):
    return engine_factory(directory=make_directory(), guardrails=Guardrails())


def open_review(eng, **kw):
    r = eng.ingest(job_event(**kw))
    return r.incident_id, eng.store.open_review_for(r.incident_id)

# ------------------------------------------------------------------ directory structure

def test_directory_validation():
    with pytest.raises(DirectoryError, match="unknown parent"):
        Directory([Role(id="a", parent="ghost")])
    with pytest.raises(DirectoryError, match="cycle"):
        Directory([Role(id="a", parent="b"), Role(id="b", parent="a")])
    with pytest.raises(DirectoryError, match="unknown role"):
        Directory([Role(id="a")], [Person(id="p")], [Assignment(person_id="p", role_id="zzz")])
    with pytest.raises(DirectoryError, match="unknown person"):
        Directory([Role(id="a")], [], [Assignment(person_id="p", role_id="a")])
    with pytest.raises(DirectoryError, match="duplicate role"):
        Directory([Role(id="a"), Role(id="a")])
    with pytest.raises(ValueError):
        AuthorityRule(role_id="a", action="x", level="maybe")


def test_hierarchy_queries():
    d = make_directory()
    assert d.ancestors("ops") == ["lead", "ops_head"]
    assert d.descendants("ops_head") == {"lead", "ops", "supervisor", "operator"}
    assert d.roles_of("asha", {"system": "billing"}) == {"ops"}
    assert d.roles_of("asha", {"system": "hr"}) == set()
    assert d.roles_of("gone") == set()
    assert d.can_see("lata", "ops") and not d.can_see("ravi", "lead")
    assert [p.id for p in d.people_in("ops", {"system": "billing"})] == ["asha", "ravi"]


def test_amount_limits():
    d = make_directory()
    small = PlaybookStep(action="refund", params={"amount": 4999.0})
    big = PlaybookStep(action="refund", params={"amount": 25000.0})
    missing = PlaybookStep(action="refund", params={})
    assert d.authorize_steps("lata", "p", "lead", [small], {}).allowed
    denied = d.authorize_steps("lata", "p", "lead", [big], {})
    assert not denied.allowed and "limit" in denied.reason and denied.escalate_to == "ops_head"
    assert not d.authorize_steps("lata", "p", "lead", [missing], {}).allowed      # unknown amount: refuse
    assert d.authorize_steps("hari", "p", "lead", [big], {}).allowed               # head: no limit


def test_engine_refuses_directory_missing_pattern_roles(engine_factory):
    d = Directory([Role(id="ops")])
    with pytest.raises(EngineError, match="missing from the directory"):
        engine_factory(directory=d)

# ------------------------------------------------------------------ decisions

def test_unknown_and_inactive_people_are_refused(rbac_engine):
    _, rev = open_review(rbac_engine, error="AUTH")
    for who in ("mallory", "gone"):
        with pytest.raises(AuthorizationError):
            rbac_engine.decide(rev.id, Decision(kind=DecisionKind.REJECT, actor=who, disposition_code="no_action"))
    denials = [a for a in rbac_engine.store.audit_log() if a["kind"] == "decision_denied"]
    assert len(denials) == 2


def test_propose_only_escalates_and_senior_inherits(rbac_engine, backend):
    inc_id, rev = open_review(rbac_engine, error="AUTH")
    # ravi may only propose a cancel: his decision goes to the lead as a proposal, and nothing runs yet
    rbac_engine.decide(rev.id, Decision(kind=DecisionKind.MODIFY, actor="ravi", action="cancel",
                                        params={"ref": "J1"}, note="customer asked"))
    assert backend.calls == [] and rbac_engine.store.get_incident(inc_id).state is S.AWAITING_HUMAN
    fwd = rbac_engine.store.open_review_for(inc_id)
    assert fwd.id != rev.id and fwd.assignee_role == "lead"
    assert fwd.proposal.steps[0].action == "cancel" and fwd.proposal.rationale == "proposed by ravi: customer asked"
    assert any(a["kind"] == "proposal_forwarded" for a in rbac_engine.store.audit_log())
    with pytest.raises(AuthorizationError):                                    # not his own forward
        rbac_engine.decide(fwd.id, Decision(kind=DecisionKind.APPROVE, actor="ravi"))
    rbac_engine.decide(fwd.id, Decision(kind=DecisionKind.APPROVE, actor="lata"))
    assert backend.calls == [("cancel", {"ref": "J1"})]


def _buyer_rules(rules):
    """cancel as a purchase order: ops proposes, only the lead approves, and only on someone's proposal."""
    out = [r for r in rules if not (r.role_id == "lead" and r.action == "cancel")]
    return [*out, AuthorityRule(role_id="lead", action="cancel", inherit=False, needs_proposal=True)]


@pytest.mark.parametrize("senior", ["hari", "hema"])
def test_a_rule_that_is_not_inherited_is_not_held_by_seniors(engine_factory, backend, senior):
    eng = engine_factory(directory=make_directory(_buyer_rules), guardrails=Guardrails())
    inc_id, rev = open_review(eng, error="AUTH")
    # the head holds cancel only as the propose rule inherited from ops: it goes to the lead, nothing runs
    eng.decide(rev.id, Decision(kind=DecisionKind.MODIFY, actor=senior, action="cancel", params={"ref": "J1"}))
    assert backend.calls == []
    fwd = eng.store.open_review_for(inc_id)
    assert fwd.assignee_role == "lead"
    eng.decide(fwd.id, Decision(kind=DecisionKind.APPROVE, actor="lata"))     # on the head's proposal: fine
    assert backend.calls == [("cancel", {"ref": "J1"})]


def test_a_rule_that_needs_a_proposal_refuses_to_act_alone(engine_factory, backend):
    eng = engine_factory(directory=make_directory(_buyer_rules), guardrails=Guardrails())
    inc_id, rev = open_review(eng, error="AUTH")
    with pytest.raises(AuthorizationError, match="needs a proposal"):
        eng.decide(rev.id, Decision(kind=DecisionKind.MODIFY, actor="lata", action="cancel", params={"ref": "J1"}))
    assert backend.calls == []
    eng.decide(rev.id, Decision(kind=DecisionKind.MODIFY, actor="ravi", action="cancel", params={"ref": "J1"}))
    fwd = eng.store.open_review_for(inc_id)
    eng.decide(fwd.id, Decision(kind=DecisionKind.APPROVE, actor="lata"))
    assert backend.calls == [("cancel", {"ref": "J1"})]


def test_a_rule_without_inherit_still_reaches_its_own_role_only():
    d = make_directory(_buyer_rules)
    st = [PlaybookStep(action="cancel", params={"ref": "J1"})]
    assert d.authorize_steps("lata", "p", "lead", st, {}, proposed_by=["ravi"]).allowed
    assert not d.authorize_steps("lata", "p", "lead", st, {}, proposed_by=["lata"]).allowed   # own proposal
    assert not d.authorize_steps("hari", "p", "ops_head", st, {}, proposed_by=["ravi"]).allowed


def test_a_step_with_no_authority_is_refused_not_forwarded():
    d = make_directory()
    none = d.authorize_steps("ravi", "p", "ops", [PlaybookStep(action="refund", params={"amount": 10.0})], {})
    assert not none.allowed and not none.proposable                 # nothing to propose: refused as before
    prop = d.authorize_steps("ravi", "p", "ops", [PlaybookStep(action="cancel", params={"ref": "J1"})], {})
    assert not prop.allowed and prop.proposable and prop.escalate_to == "lead"
    over = d.authorize_steps("lata", "p", "lead", [PlaybookStep(action="refund", params={"amount": 25000.0})], {})
    assert over.proposable and over.escalate_to == "ops_head"       # above the limit: goes up


def test_lead_inherits_ops_authority(rbac_engine, backend):
    _, rev = open_review(rbac_engine, error="AUTH")
    rbac_engine.decide(rev.id, Decision(kind=DecisionKind.MODIFY, actor="lata", action="retry", params={"ref": "J1"}))
    assert backend.calls == [("retry", {"ref": "J1"})]


def test_scope_limits_what_a_person_can_act_on(rbac_engine, backend):
    _, rev = open_review(rbac_engine, error="AUTH", system="hr")
    with pytest.raises(AuthorizationError, match="not in role"):
        rbac_engine.decide(rev.id, Decision(kind=DecisionKind.MODIFY, actor="asha", action="retry",
                                            params={"ref": "J1"}))
    _, rev2 = open_review(rbac_engine, error="AUTH", system="billing", ref="J2")
    rbac_engine.decide(rev2.id, Decision(kind=DecisionKind.MODIFY, actor="asha", action="retry",
                                         params={"ref": "J2"}))
    assert backend.calls == [("retry", {"ref": "J2"})]


def test_reviews_for_respects_role_tree_and_scope(rbac_engine):
    open_review(rbac_engine, error="AUTH", system="billing", ref="B1")
    open_review(rbac_engine, error="AUTH", system="hr", ref="H1")
    assert len(rbac_engine.reviews_for("asha")) == 1          # billing only
    assert len(rbac_engine.reviews_for("ravi")) == 2          # unscoped ops
    assert len(rbac_engine.reviews_for("lata")) == 2          # lead sees the ops queue
    assert rbac_engine.reviews_for("mallory") == []

# ------------------------------------------------------------------ control surface

def test_auto_promotion_needs_two_different_approvers(engine_factory):
    eng = engine_factory(directory=make_directory(), guardrails=Guardrails(),
                         learning=LearningPolicy(promote_streak={Route.HITL: 1}))
    eng.set_route("job_timeout", Route.HITL, actor="hari")
    _, rev = open_review(eng)
    eng.decide(rev.id, Decision(kind=DecisionKind.APPROVE, actor="ravi"))
    assert eng.store.get_pattern_state("job_timeout").pending_promotion is Route.AUTO
    with pytest.raises(AuthorizationError):
        eng.approve_promotion("job_timeout", actor="ravi")               # ops cannot promote
    st = eng.approve_promotion("job_timeout", actor="hari")
    assert st.route is Route.HITL and st.promotion_approvals == ["hari"]
    with pytest.raises(EngineError, match="different approver"):
        eng.approve_promotion("job_timeout", actor="hari")
    st = eng.approve_promotion("job_timeout", actor="hema")
    assert st.route is Route.AUTO and st.pending_promotion is None
    approved = [a for a in eng.store.audit_log() if a["kind"] == "promotion_approved"]
    assert approved[0]["data"]["approvers"] == ["hari", "hema"]


def test_single_approver_mode(engine_factory):
    eng = engine_factory(directory=make_directory(two_person_auto_promotion=False), guardrails=Guardrails(),
                         learning=LearningPolicy(promote_streak={Route.HITL: 1}))
    eng.set_route("job_timeout", Route.HITL, actor="hari")
    _, rev = open_review(eng)
    eng.decide(rev.id, Decision(kind=DecisionKind.APPROVE, actor="ravi"))
    assert eng.approve_promotion("job_timeout", actor="hari").route is Route.AUTO


def test_kill_switch_vs_raising_autonomy(rbac_engine):
    st = rbac_engine.set_route("job_timeout", Route.HITL, actor="lata")         # lead: kill switch allowed
    assert st.route is Route.HITL
    with pytest.raises(AuthorizationError):
        rbac_engine.set_route("job_timeout", Route.AUTO, actor="lata")          # raising needs __set_route__
    with pytest.raises(AuthorizationError):
        rbac_engine.set_route("job_timeout", Route.HITL, actor="ravi")
    assert rbac_engine.set_route("job_timeout", Route.AUTO, actor="hari").route is Route.AUTO


def test_reverse_requires_authority(engine_factory, backend):
    eng = engine_factory(directory=make_directory())        # irreversible allowed unattended -> auto resolves
    r = eng.ingest(job_event())
    with pytest.raises(AuthorizationError):
        eng.reverse(r.incident_id, actor="ravi")
    assert eng.reverse(r.incident_id, actor="hari").reversed


def test_escalation_walks_up_the_tree(rbac_engine, clock):
    _, rev = open_review(rbac_engine, error="AUTH")                   # owner ops, escalation_role lead
    clock.advance(minutes=241)
    assert rbac_engine.sweep()[0].assignee_role == "lead"             # first: the pattern's escalation role
    clock.advance(minutes=241)
    assert rbac_engine.sweep()[0].assignee_role == "ops_head"         # then up the tree
    clock.advance(minutes=241)
    top = rbac_engine.sweep()[0]
    assert top.assignee_role == "ops_head" and top.escalation_level == 3   # top of the tree stays


def test_load_directory_yaml(tmp_path):
    f = tmp_path / "people.yaml"
    f.write_text("""
roles:
  head: {name: Head}
  exec: {name: Executive, parent: head}
people:
  - {id: priya, name: Priya, edges: [ask_ai, whatsapp]}
assignments:
  - {person_id: priya, role_id: exec, scope: {location: [WH_CHN, STORE_FLG]}}
authority:
  - {role_id: exec, action: reallocate_order}
""")
    d = load_directory(f)
    assert d.ancestors("exec") == ["head"]
    assert d.roles_of("priya", {"location": "STORE_FLG"}) == {"exec"}
    assert d.roles_of("priya", {"location": "BLR"}) == set()
    bad = tmp_path / "bad.yaml"
    bad.write_text("rolez: {}\n")
    with pytest.raises(DirectoryError, match="unknown top-level"):
        load_directory(bad)


def test_coverage_warns_when_nobody_can_act(engine_factory):
    from sentinel import Assignment, Directory
    d = make_directory()                                   # the fixture never staffed 'operator'
    assert engine_factory(directory=d).coverage() == [
        "item_stuck_short: role 'operator' has no people of its own; only ['lead', 'ops_head'] above it see its queue"]
    nobody = Directory(list(d.roles.values()), list(d.people.values()),
                       [a for a in d.assignments if a.role_id in ("ops", "supervisor")], d.rules)
    assert "item_stuck_short: role 'operator' has no active people, and nobody above it either" in engine_factory(
        directory=nobody).coverage()
    staffed = Directory(list(d.roles.values()), list(d.people.values()),
                        d.assignments + [Assignment(person_id="ravi", role_id="operator")], d.rules)
    assert engine_factory(directory=staffed).coverage() == []
    mis_scoped = Directory(list(d.roles.values()), list(d.people.values()),
                           [Assignment(person_id="ravi", role_id="operator", scope={"warehouse": "W1"})]
                           + [a for a in d.assignments], d.rules)
    assert any("scoped on ['warehouse']" in w for w in engine_factory(directory=mis_scoped).coverage())
