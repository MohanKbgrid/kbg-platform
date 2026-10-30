# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""Independent black-box journeys for the authority contract (v0.17.0, ``sentinel.org.authorise``, ``sod:``) and
agent identities, modes and grants (v0.18.0, ``agents:``), written from CHANGELOG, OVERLAY_CONTRACT ("The org
layer", "The authority contract", "Agents: identities, modes and grants"), ADR-003 and public signatures only.

Domain: a hospital pharmacy. Wards roll up to sites (W1, W2 -> A; W3, W4 -> B). Pharmacy technicians count
stock, ward pharmacists adjust it (up to 5,000) and own the pharmacy exceptions, the site manager adjusts up to
50,000, the chief pharmacist without limit. Count and adjust are segregated. Internal audit sits on a dotted line
to the ward pharmacist. W2 has no ward pharmacist (vacant); site B has no site manager; a locum covers W3 from
25 Oct.

Tests that expose a framework defect carry ``# FIXED v0.22.1 (was DEFECT):`` with expected vs actual and are left failing.
"""
from __future__ import annotations

import copy
from datetime import UTC, date, datetime
from typing import Any

import pytest
import yaml

from sentinel import (ActionRegistry, ActionResult, AuthorizationError, Decision, DecisionKind, Event, Guardrails,
                      IncidentState, Overlay)
from sentinel.org import Agent, SodRule, authorise
from sentinel.overlay import parse_registry
from sentinel.rbac import parse_directory
from sentinel.testing import FrozenClock, engine_for

TODAY = datetime(2026, 10, 20, 9, 0, tzinfo=UTC)
IN_LOCUM = datetime(2026, 10, 26, 9, 0, tzinfo=UTC)

PEOPLE: dict[str, Any] = {
    "roles": {
        "chief_pharmacist": {"name": "Chief pharmacist"},
        "site_manager": {"parent": "chief_pharmacist"},
        "ward_pharmacist": {"parent": "site_manager", "dotted": ["audit"]},
        "pharmacy_tech": {"parent": "ward_pharmacist"},
        "audit": {"parent": "chief_pharmacist"},
        "supervisor": {"parent": "chief_pharmacist"},
    },
    "scopes": {"ward": {"rolls_up_to": "site", "parents": {"W1": "A", "W2": "A", "W3": "B", "W4": "B"}}},
    "stop_at": ["site_manager", "chief_pharmacist"],
    "people": [{"id": p} for p in ("tina", "wes", "mia", "cy", "aud", "lena")],
    "assignments": [
        {"person_id": "tina", "role_id": "pharmacy_tech", "scope": {"ward": "W1"}},
        {"person_id": "wes", "role_id": "ward_pharmacist", "scope": {"ward": "W1"}},
        {"person_id": "lena", "role_id": "ward_pharmacist", "scope": {"ward": "W3"},
         "valid_from": date(2026, 10, 25), "valid_to": date(2026, 11, 8)},
        {"person_id": "mia", "role_id": "site_manager", "scope": {"site": "A"}},
        {"person_id": "cy", "role_id": "chief_pharmacist"},
        {"person_id": "cy", "role_id": "supervisor"},
        {"person_id": "aud", "role_id": "audit"},
    ],
    "authority": [
        {"role_id": "pharmacy_tech", "action": "stock.count"},
        {"role_id": "ward_pharmacist", "action": "stock.adjust", "max_amount": 5000},
        {"role_id": "site_manager", "action": "stock.adjust", "max_amount": 50000},
        {"role_id": "chief_pharmacist", "action": "stock.adjust"},
        {"role_id": "ward_pharmacist", "action": "dispense.release"},
        {"role_id": "ward_pharmacist", "action": "reorder"},
        {"role_id": "ward_pharmacist", "action": "quarantine"},
        {"role_id": "ward_pharmacist", "action": "write_off", "max_amount": 5000},
        {"role_id": "site_manager", "action": "write_off", "max_amount": 50000},
        {"role_id": "chief_pharmacist", "action": "__configure__"},
    ],
    "sod": [{"first": "stock.count", "second": "stock.adjust", "description": "who counts does not adjust"}],
}

REGISTRY: dict[str, Any] = {
    "capabilities": {
        "inventory": {"title": "Pharmacy inventory", "owner": "ward_pharmacist"},
        "quality": {"title": "Medicines quality", "owner": "ward_pharmacist"},
    },
    "fingerprints": [
        {"event_type": "ph.low_stock", "fields": {"ward": "ward", "drug": "drug"}, "group_by": ["ward", "drug"]},
        {"event_type": "ph.expiring", "fields": {"ward": "ward", "drug": "drug"}, "group_by": ["ward", "drug"]},
        {"event_type": "ph.cold_chain", "fields": {"ward": "ward", "drug": "drug"}, "group_by": ["ward", "drug"]},
    ],
    "patterns": [
        {"id": "low_stock", "description": "Ward stock below par", "capability": "inventory",
         "event_types": ["ph.low_stock"], "route": "auto",
         "playbook": [{"action": "reorder", "params": {"drug": "{{payload.drug}}"}}],
         "allowed_actions": ["reorder"], "owner_role": "ward_pharmacist"},
        {"id": "expiring", "description": "Stock expiring on the ward", "capability": "inventory",
         "event_types": ["ph.expiring"], "route": "auto",
         "playbook": [{"action": "write_off", "params": {"drug": "{{payload.drug}}",
                                                         "amount": "{{payload.amount|float}}"}}],
         "allowed_actions": ["write_off"], "owner_role": "ward_pharmacist"},
        {"id": "cold_chain", "description": "Fridge excursion", "capability": "quality",
         "event_types": ["ph.cold_chain"], "route": "auto",
         "playbook": [{"action": "quarantine", "params": {"drug": "{{payload.drug}}"}}],
         "allowed_actions": ["quarantine"], "owner_role": "ward_pharmacist"},
    ],
}


def people(agents: list[dict] | None = None, **changes: Any) -> dict[str, Any]:
    p = copy.deepcopy(PEOPLE)
    if agents is not None:
        p["agents"] = copy.deepcopy(agents)
    for k, v in changes.items():
        if v is None:
            p.pop(k, None)
        else:
            p[k] = v
    return p


def directory(**kw: Any):
    return parse_directory(people(**kw))


class Rig:
    def __init__(self, agents: list[dict] | None = None, *, at: datetime = TODAY, reg: dict | None = None,
                 guardrails: Guardrails | None = None, people_doc: dict | None = None) -> None:
        self.calls: list[tuple[str, dict]] = []
        acts = ActionRegistry()
        for name in ("reorder", "quarantine", "write_off"):
            self._action(acts, name)
        doc = parse_registry(copy.deepcopy(reg or REGISTRY))
        ov = Overlay(name="pharmacy", fingerprint_rules=doc.fingerprints, patterns=doc.patterns, roles=doc.roles,
                     capabilities=doc.capabilities, actions=acts,
                     directory=parse_directory(people_doc or people(agents)))
        self.clock = FrozenClock(at)
        kw: dict[str, Any] = {"clock": self.clock}
        if guardrails is not None:
            kw["guardrails"] = guardrails
        self.eng = engine_for(ov, **kw)
        self.n = 0

    def _action(self, acts: ActionRegistry, name: str) -> None:
        params = {"drug": "str", "amount?": "float"}

        @acts.action(name, reversible=True, params=params, description=f"{name} a drug")
        def run(ctx, p):
            self.calls.append((name, dict(p)))
            return ActionResult(ok=True)

        @run.compensator
        def undo(ctx, p):
            return ActionResult(ok=True)

    def event(self, kind: str = "ph.low_stock", ward: str = "W1", **payload: Any) -> Event:
        self.n += 1
        body = {"ward": ward, "drug": payload.pop("drug", f"drug{self.n}"), **payload}
        if ward is None:
            body.pop("ward")
        return Event(type=kind, source="his", idempotency_key=f"k{self.n}", payload=body)

    def ingest(self, ev: Event):
        r = self.eng.ingest(ev)
        return self.eng.store.get_incident(r.incident_id)

    def ran(self, inc) -> bool:
        return inc.state == IncidentState.DISPOSITIONED and any(a["kind"] == "action_attempt"
                                                               for a in self.eng.store.audit_log(inc.id))

    def kinds(self, inc=None) -> list[str]:
        return [a["kind"] for a in self.eng.store.audit_log(inc.id if inc else None)]


def errors(problems) -> list[str]:
    return [p.message for p in problems if p.severity == "error"]


def bot(scope: str = "W1", role: str = "ward_pharmacist") -> Agent:
    return Agent(f"stock_bot@{scope}", bound_role=role)


# ============================================================================== 1. authorise: persons
class TestAuthorisePerson:
    def test_person_within_limit_in_scope(self):
        dec = authorise(directory(), "wes", "stock.adjust", obj="INS-1", scope={"ward": "W1"}, amount=4000)
        assert dec and dec.allowed and dec.decided_by_role == "ward_pharmacist"

    def test_person_over_limit_is_refused_with_escalation(self):
        dec = authorise(directory(), "wes", "stock.adjust", obj="INS-1", scope={"ward": "W1"}, amount=7000)
        assert not dec and "limit" in dec.reason
        assert dec.escalate_to == "site_manager"

    def test_person_out_of_scope_is_refused(self):
        assert not authorise(directory(), "wes", "stock.adjust", obj="X", scope={"ward": "W2"}, amount=10)
        assert not authorise(directory(), "mia", "stock.adjust", obj="X", scope={"ward": "W3"}, amount=10)

    def test_person_covers_lower_scope_via_roll_up(self):
        dec = authorise(directory(), "mia", "stock.adjust", obj="X", scope={"ward": "W2"}, amount=40000)
        assert dec and dec.decided_by_role == "site_manager"

    def test_time_bound_person_only_inside_window(self):
        d = directory()
        assert not authorise(d, "lena", "stock.adjust", obj="X", scope={"ward": "W3"}, amount=10, at=TODAY)
        assert authorise(d, "lena", "stock.adjust", obj="X", scope={"ward": "W3"}, amount=10, at=IN_LOCUM)

    def test_dotted_line_person_cannot_authorise(self):
        d = directory()
        assert d.can_see("aud", "ward_pharmacist", {"ward": "W1"})
        assert not authorise(d, "aud", "stock.adjust", obj="X", scope={"ward": "W1"}, amount=10)
        assert not authorise(d, "aud", "dispense.release", obj="X", scope={"ward": "W1"})

    def test_inactive_person_cannot_authorise(self):
        p = people()
        p["people"] = [dict(x, active=False) if x["id"] == "wes" else x for x in p["people"]]
        assert not authorise(parse_directory(p), "wes", "stock.adjust", obj="X", scope={"ward": "W1"}, amount=10)


# ============================================================================== 2. authorise: agents
class TestAuthoriseAgent:
    def test_agent_capped_at_its_bound_roles_limit_not_its_seniors(self):
        d = directory()
        ok = authorise(d, bot("W1"), "stock.adjust", obj="X", scope={"ward": "W1"}, amount=5000)
        assert ok and ok.decided_by_role == "ward_pharmacist"
        no = authorise(d, bot("W1"), "stock.adjust", obj="X", scope={"ward": "W1"}, amount=5001)
        assert not no and no.decided_by_role == "ward_pharmacist"

    def test_agent_negative_amount_is_held_to_the_limit(self):
        # DEFECT (judgement call): docs: "An agent never exceeds the person holding its bound role" with amount
        # limits (ward pharmacist: 5,000). Expected: an adjustment of -100,000 (a write-down 20x the limit) is
        # refused, as +100,000 is (limit on magnitude, or negative amounts refused). Actual: allowed, decided by
        # ward_pharmacist -- any signed quantity below zero passes every max_amount.
        d = directory()
        assert not authorise(d, bot("W1"), "stock.adjust", obj="X", scope={"ward": "W1"}, amount=100000)
        assert not authorise(d, bot("W1"), "stock.adjust", obj="X", scope={"ward": "W1"}, amount=-100000)

    def test_agent_with_unknown_amount_is_refused(self):
        assert not authorise(directory(), bot("W1"), "stock.adjust", obj="X", scope={"ward": "W1"})

    def test_agent_bound_to_a_role_without_the_action_is_refused(self):
        # the technician may count but not adjust, even though the people above may
        d = directory()
        assert authorise(d, bot("W1", "pharmacy_tech"), "stock.count", obj="X", scope={"ward": "W1"})
        assert not authorise(d, bot("W1", "pharmacy_tech"), "stock.adjust", obj="X", scope={"ward": "W1"},
                             amount=1)

    def test_vacant_bound_role_falls_to_nearest_held_role_above(self):
        d = directory()
        dec = authorise(d, bot("W2"), "stock.adjust", obj="X", scope={"ward": "W2"}, amount=6000)
        assert dec and dec.decided_by_role == "site_manager"
        assert not authorise(d, bot("W2"), "stock.adjust", obj="X", scope={"ward": "W2"}, amount=60000)

    def test_vacant_up_to_the_stop_list_is_refused_never_the_chief(self):
        # W4: no ward pharmacist, no site manager for B; chief is past the stop list
        dec = authorise(directory(), bot("W4"), "stock.adjust", obj="X", scope={"ward": "W4"}, amount=1)
        assert not dec
        assert dec.decided_by_role != "chief_pharmacist"

    def test_inactive_holder_counts_as_vacant_for_the_agent(self):
        p = people()
        p["people"] = [dict(x, active=False) if x["id"] == "wes" else x for x in p["people"]]
        dec = authorise(parse_directory(p), bot("W1"), "stock.adjust", obj="X", scope={"ward": "W1"}, amount=6000)
        assert dec and dec.decided_by_role == "site_manager"

    def test_agent_follows_todays_holder(self):
        d = directory()
        assert not authorise(d, bot("W3"), "stock.adjust", obj="X", scope={"ward": "W3"}, amount=10, at=TODAY)
        dec = authorise(d, bot("W3"), "stock.adjust", obj="X", scope={"ward": "W3"}, amount=10, at=IN_LOCUM)
        assert dec and dec.decided_by_role == "ward_pharmacist"

    def test_agent_with_no_scope_does_not_borrow_an_unscoped_senior(self):
        # every ward pharmacist and site manager is scoped; the chief is past the stop list
        assert not authorise(directory(), bot("any"), "stock.adjust", obj="X", scope={}, amount=10)

    def test_agent_bound_to_unknown_role_is_refused(self):
        assert not authorise(directory(), bot("W1", "ghost"), "stock.count", obj="X", scope={"ward": "W1"})

    def test_agent_bound_to_dotted_role_cannot_act_in_that_queue(self):
        assert not authorise(directory(), bot("W1", "audit"), "stock.adjust", obj="X", scope={"ward": "W1"},
                             amount=1)


# ============================================================================== 3. approvals and SoD
class TestApprovalsAndSod:
    def test_agent_never_approves(self):
        d = directory()
        assert not authorise(d, bot("W1"), "__approve__", obj="X", scope={"ward": "W1"})
        dec = authorise(d, bot("W1"), "stock.adjust", obj="X", scope={"ward": "W1"}, amount=10,
                        proposed_by=["tina"])
        assert not dec

    def test_self_approval_refused_other_proposer_allowed(self):
        d = directory()
        assert not authorise(d, "wes", "stock.adjust", obj="X", scope={"ward": "W1"}, amount=10, proposed_by=["wes"])
        assert authorise(d, "wes", "stock.adjust", obj="X", scope={"ward": "W1"}, amount=10, proposed_by=["tina"])

    def test_agent_self_approval_refused(self):
        a = bot("W1")
        assert not authorise(directory(), a, "__approve__", obj="X", scope={"ward": "W1"}, proposed_by=[a.id])

    @pytest.mark.parametrize("done, doing, who", [
        ("stock.count", "stock.adjust", "wes"),
        ("stock.adjust", "stock.count", "tina"),
    ])
    def test_sod_from_config_in_either_order_for_people(self, done, doing, who):
        d = directory()
        p = people()
        p["assignments"].append({"person_id": "tina", "role_id": "ward_pharmacist", "scope": {"ward": "W1"}})
        p["assignments"].append({"person_id": "wes", "role_id": "pharmacy_tech", "scope": {"ward": "W1"}})
        d = parse_directory(p)
        amount = 10 if doing == "stock.adjust" else None
        clean = authorise(d, who, doing, obj="INS-1", scope={"ward": "W1"}, amount=amount)
        assert clean
        dec = authorise(d, who, doing, obj="INS-1", scope={"ward": "W1"}, amount=amount,
                        done_on_object={who: [done]})
        assert not dec and any(c.startswith("sod") for c in dec.checks)

    def test_sod_for_agents_in_either_order(self):
        d = directory()
        a = bot("W1")
        assert not authorise(d, a, "stock.adjust", obj="INS-1", scope={"ward": "W1"}, amount=10,
                             done_on_object={a.id: ["stock.count"]})
        t = bot("W1", "pharmacy_tech")
        assert not authorise(d, t, "stock.count", obj="INS-1", scope={"ward": "W1"},
                             done_on_object={t.id: ["stock.adjust"]})

    def test_sod_is_per_actor_on_the_object(self):
        # tina counted INS-1; wes adjusting it is the point of the pair
        assert authorise(directory(), "wes", "stock.adjust", obj="INS-1", scope={"ward": "W1"}, amount=10,
                         done_on_object={"tina": ["stock.count"]})

    def test_sod_from_the_caller(self):
        d = directory()
        rule = SodRule(first="dispense.release", second="stock.adjust")
        assert authorise(d, "wes", "stock.adjust", obj="INS-1", scope={"ward": "W1"}, amount=10,
                         done_on_object={"wes": ["dispense.release"]})
        assert not authorise(d, "wes", "stock.adjust", obj="INS-1", scope={"ward": "W1"}, amount=10,
                             done_on_object={"wes": ["dispense.release"]}, sod=[rule])
        assert not authorise(d, "wes", "dispense.release", obj="INS-1", scope={"ward": "W1"},
                             done_on_object={"wes": ["stock.adjust"]}, sod=[rule])

    def test_sod_config_is_validated(self):
        with pytest.raises(ValueError):
            directory(sod=[{"first": "stock.count"}])


# ============================================================================== 4. modes in the engine
class TestModes:
    def test_without_agents_nothing_changes(self):
        rig = Rig()
        inc = rig.ingest(rig.event())
        assert rig.ran(inc) and not inc.shadow
        assert inc.provenance.agent is None and inc.provenance.agent_mode is None
        t = rig.eng.trace(rig.event())
        assert not t.get("agent") and t["outcome"] == "automatic"

    def test_star_observe_is_shadow(self):
        rig = Rig([{"template": "*", "mode": "OBSERVE"}])
        inc = rig.ingest(rig.event())
        assert not rig.ran(inc) and inc.shadow and rig.calls == []
        assert rig.eng.store.open_review_for(inc.id) is not None
        assert inc.provenance.agent_mode == "OBSERVE"

    def test_act_in_one_ward_does_not_leak_to_another(self):
        rig = Rig([{"template": "*", "mode": "OBSERVE"},
                   {"template": "low_stock", "scope": {"ward": "W1"}, "mode": "ACT"}])
        w1 = rig.ingest(rig.event(ward="W1"))
        w2 = rig.ingest(rig.event(ward="W2"))
        assert rig.ran(w1) and w1.provenance.agent_mode == "ACT" and "W1" in w1.provenance.agent
        assert not rig.ran(w2) and w2.provenance.agent_mode == "OBSERVE"

    def test_list_valued_policy_scope(self):
        rig = Rig([{"template": "*", "mode": "OBSERVE"},
                   {"template": "low_stock", "scope": {"ward": ["W1", "W3"]}, "mode": "ACT"}])
        got = {w: rig.ran(rig.ingest(rig.event(ward=w))) for w in ("W1", "W2", "W3")}
        assert got == {"W1": True, "W2": False, "W3": True}

    def test_agent_identity_tells_two_site_agents_apart(self):
        # FIXED v0.22.1 (was DEFECT): docs: "Each case records its agent identity (provenance.agent, as template@scope)" and "An
        # instance is a row: a trust segment, a case's provenance.agent". Expected: the site A agent (ACT) and the
        # site B agent (PROPOSE) of low_stock have different identities, naming their scope (site=A / site=B).
        # Actual: both are 'inventory@*' -- a policy matched through a scope roll-up records no scope at all, so
        # two instances with different modes are indistinguishable in provenance, trace and oversight.
        rig = Rig([{"template": "low_stock", "scope": {"site": "A"}, "mode": "ACT"},
                   {"template": "low_stock", "scope": {"site": "B"}, "mode": "PROPOSE"}])
        a = rig.ingest(rig.event(ward="W1"))
        b = rig.ingest(rig.event(ward="W3"))
        assert (a.provenance.agent_mode, b.provenance.agent_mode) == ("ACT", "PROPOSE")
        assert a.provenance.agent != b.provenance.agent, a.provenance.agent
        assert "*" not in a.provenance.agent

    def test_agent_identity_tells_two_templates_apart(self):
        # FIXED v0.22.1 (was DEFECT): docs: "An agent is a template (a pattern, or its capability) running in a scope" and the most
        # specific row wins, a pattern id beating its capability. Expected: when pattern rows decide (low_stock
        # PROPOSE, expiring ACT), the identities differ (e.g. 'low_stock@*' vs 'expiring@*'). Actual: both cases
        # record 'inventory@*' (the capability), so a PROPOSE agent and an ACT agent share one identity.
        rig = Rig([{"template": "low_stock", "mode": "PROPOSE"}, {"template": "expiring", "mode": "ACT"}])
        low = rig.ingest(rig.event(ward="W1"))
        exp = rig.ingest(rig.event("ph.expiring", ward="W1", amount=10))
        assert (low.provenance.agent_mode, exp.provenance.agent_mode) == ("PROPOSE", "ACT")
        assert low.provenance.agent != exp.provenance.agent, low.provenance.agent

    def test_most_specific_row_does_not_depend_on_row_order(self):
        # FIXED v0.22.1 (was DEFECT): docs: "The most specific row wins ... then the row with more scope keys." A ward is below its
        # site, so a ward=W2 row is more specific than a site=A row (both have one key). Expected: the same mode
        # for W2 whatever order the rows are listed in (ward row: PROPOSE). Actual: listing order decides --
        # [ward, site] gives PROPOSE, [site, ward] gives ACT and the case runs unattended.
        ward = {"template": "low_stock", "scope": {"ward": "W2"}, "mode": "PROPOSE"}
        site = {"template": "low_stock", "scope": {"site": "A"}, "mode": "ACT"}
        modes = []
        for rows in ([ward, site], [site, ward]):
            rig = Rig(rows)
            modes.append(rig.ingest(rig.event(ward="W2")).provenance.agent_mode)
        assert modes == ["PROPOSE", "PROPOSE"], modes

    def test_act_does_not_leak_to_other_templates(self):
        rig = Rig([{"template": "*", "mode": "OBSERVE"},
                   {"template": "low_stock", "scope": {"ward": "W1"}, "mode": "ACT"}])
        inc = rig.ingest(rig.event("ph.cold_chain", ward="W1"))
        assert not rig.ran(inc) and inc.provenance.agent_mode == "OBSERVE"

    def test_site_scoped_policy_via_roll_up(self):
        rig = Rig([{"template": "*", "mode": "OBSERVE"},
                   {"template": "low_stock", "scope": {"site": "A"}, "mode": "ACT"}])
        got = {w: rig.ran(rig.ingest(rig.event(ward=w))) for w in ("W1", "W2", "W3")}
        assert got == {"W1": True, "W2": True, "W3": False}

    def test_event_without_the_scoped_fact_gets_no_scoped_policy(self):
        rig = Rig([{"template": "*", "mode": "OBSERVE"},
                   {"template": "low_stock", "scope": {"ward": "W1"}, "mode": "ACT"}])
        inc = rig.ingest(rig.event(ward=None))
        assert not rig.ran(inc) and inc.provenance.agent_mode == "OBSERVE"

    def test_pattern_id_beats_capability_even_with_fewer_scope_keys(self):
        rig = Rig([{"template": "inventory", "scope": {"site": "A"}, "mode": "ACT"},
                   {"template": "low_stock", "mode": "PROPOSE"}])
        low = rig.ingest(rig.event(ward="W1"))
        exp = rig.ingest(rig.event("ph.expiring", ward="W1", amount=10))
        assert not rig.ran(low) and low.provenance.agent_mode == "PROPOSE"
        assert rig.ran(exp) and exp.provenance.agent_mode == "ACT"

    def test_capability_beats_star(self):
        rig = Rig([{"template": "*", "mode": "ACT"}, {"template": "quality", "mode": "OBSERVE"}])
        assert rig.ran(rig.ingest(rig.event("ph.low_stock")))
        cold = rig.ingest(rig.event("ph.cold_chain"))
        assert not rig.ran(cold) and cold.provenance.agent_mode == "OBSERVE"

    def test_more_scope_keys_wins_within_a_template(self):
        rig = Rig([{"template": "low_stock", "scope": {"ward": "W1"}, "mode": "ACT"},
                   {"template": "low_stock", "scope": {"ward": "W1", "drug": "insulin"}, "mode": "OFF"}])
        ins = rig.ingest(rig.event(ward="W1", drug="insulin"))
        para = rig.ingest(rig.event(ward="W1", drug="paracetamol"))
        assert ins.pattern_id == "__unmatched__"
        assert para.pattern_id == "low_stock" and rig.ran(para)

    def test_off_sends_events_to_unmatched(self):
        rig = Rig([{"template": "*", "mode": "ACT"},
                   {"template": "low_stock", "scope": {"ward": "W1"}, "mode": "OFF"}])
        ev = rig.event(ward="W1")
        t = rig.eng.trace(ev)
        inc = rig.ingest(ev)
        assert t["pattern"]["id"] == inc.pattern_id == "__unmatched__"
        assert rig.calls == [] and rig.eng.store.open_review_for(inc.id).assignee_role == "supervisor"
        assert any("OFF" in s for s in t["steps"])
        assert rig.ingest(rig.event(ward="W2")).pattern_id == "low_stock"

    def test_propose_never_runs_unattended_even_with_auto_route(self):
        rig = Rig([{"template": "low_stock", "mode": "PROPOSE"}])
        for _ in range(3):
            inc = rig.ingest(rig.event(ward="W1"))
            rev = rig.eng.store.open_review_for(inc.id)
            assert not rig.ran(inc) and rev is not None
            before = len(rig.calls)
            rig.eng.decide(rev.id, Decision(kind=DecisionKind.APPROVE, actor="wes", disposition_code="resolved"))
            assert len(rig.calls) == before + 1          # a person's approval runs it
        t = rig.eng.trace(rig.event(ward="W1"))
        assert t["outcome"] == "person"
        assert not rig.ran(rig.ingest(rig.event(ward="W1")))

    def test_propose_review_cannot_be_approved_by_the_dotted_line(self):
        rig = Rig([{"template": "low_stock", "mode": "PROPOSE"}])
        inc = rig.ingest(rig.event(ward="W1"))
        rev = rig.eng.store.open_review_for(inc.id)
        with pytest.raises(AuthorizationError):
            rig.eng.decide(rev.id, Decision(kind=DecisionKind.APPROVE, actor="aud", disposition_code="resolved"))
        assert rig.calls == []

    def test_time_bound_policy(self):
        rows = [{"template": "*", "mode": "OBSERVE"},
                {"template": "low_stock", "scope": {"ward": "W1"}, "mode": "ACT",
                 "valid_from": date(2026, 10, 25), "valid_to": date(2026, 11, 1)}]
        before = Rig(rows, at=TODAY)
        assert not before.ran(before.ingest(before.event()))
        during = Rig(rows, at=IN_LOCUM)
        assert during.ran(during.ingest(during.event()))
        end = Rig(rows, at=datetime(2026, 11, 1, 0, 0, tzinfo=UTC))
        assert not end.ran(end.ingest(end.event()))

    def test_time_bound_policy_follows_the_engine_clock(self):
        rows = [{"template": "*", "mode": "OBSERVE"},
                {"template": "low_stock", "mode": "ACT", "valid_to": datetime(2026, 10, 20, 12, 0, tzinfo=UTC)}]
        rig = Rig(rows)
        assert rig.ran(rig.ingest(rig.event()))
        rig.clock.advance(hours=3)
        assert not rig.ran(rig.ingest(rig.event()))


# ============================================================================== 5. ACT limits and grants
class TestActLimits:
    def test_act_with_edit_grant_runs(self):
        rig = Rig([{"template": "low_stock", "mode": "ACT", "grants": {"reorder": "EDIT"}}])
        inc = rig.ingest(rig.event())
        assert rig.ran(inc) and "agent_grant" not in rig.kinds(inc)

    def test_act_with_view_only_goes_to_a_person(self):
        rig = Rig([{"template": "low_stock", "mode": "ACT", "grants": {"reorder": "VIEW"}}])
        inc = rig.ingest(rig.event())
        assert not rig.ran(inc) and rig.calls == []
        assert rig.eng.store.open_review_for(inc.id) is not None
        assert "agent_grant" in rig.kinds(inc)

    def test_act_with_grants_missing_the_action_goes_to_a_person(self):
        rig = Rig([{"template": "low_stock", "mode": "ACT", "grants": {"quarantine": "EDIT"}}])
        inc = rig.ingest(rig.event())
        assert not rig.ran(inc) and "agent_grant" in rig.kinds(inc)

    def test_trace_agrees_with_ingest_on_grants(self):
        rig = Rig([{"template": "low_stock", "mode": "ACT", "grants": {"reorder": "VIEW"}}])
        ev = rig.event()
        t = rig.eng.trace(ev)
        inc = rig.ingest(ev)
        assert (t["outcome"] == "automatic") == rig.ran(inc)
        assert t["agent"]["grants"] == {"reorder": "VIEW"} and t["agent"]["mode"] == "ACT"

    def test_act_without_grants_runs(self):
        rig = Rig([{"template": "low_stock", "mode": "ACT"}])
        assert rig.ran(rig.ingest(rig.event()))

    def test_act_stays_inside_unattended_amount_limits(self):
        rig = Rig([{"template": "expiring", "mode": "ACT", "grants": {"write_off": "EDIT"}}])
        small = rig.ingest(rig.event("ph.expiring", amount=3000))
        big = rig.ingest(rig.event("ph.expiring", amount=9000))
        assert rig.ran(small) and not rig.ran(big)
        assert "unattended_limit" in rig.kinds(big)

    def test_act_stays_inside_the_patterns_ceiling(self):
        reg = copy.deepcopy(REGISTRY)
        reg["patterns"][0].update(route="hitl", max_route="hitl")
        rig = Rig([{"template": "low_stock", "mode": "ACT", "grants": {"reorder": "EDIT"}}], reg=reg)
        inc = rig.ingest(rig.event())
        assert not rig.ran(inc) and rig.calls == []

    def test_act_does_not_override_a_capability_in_observe(self):
        reg = copy.deepcopy(REGISTRY)
        reg["capabilities"]["inventory"]["mode"] = "observe"
        rig = Rig([{"template": "low_stock", "mode": "ACT"}], reg=reg)
        inc = rig.ingest(rig.event())
        assert not rig.ran(inc) and inc.shadow

    def test_act_does_not_override_a_shadow_pattern(self):
        reg = copy.deepcopy(REGISTRY)
        reg["patterns"][0]["shadow"] = True
        rig = Rig([{"template": "low_stock", "mode": "ACT"}], reg=reg)
        assert not rig.ran(rig.ingest(rig.event()))

    def test_act_does_not_run_irreversible_under_strict_guardrails(self):
        rig = Rig([{"template": "low_stock", "mode": "ACT", "grants": {"reorder": "EDIT"}}],
                  guardrails=Guardrails())
        # reorder is reversible, so it may run; the point is the agent mode adds nothing beyond guardrails
        assert rig.ran(rig.ingest(rig.event()))

    @pytest.mark.parametrize("rows", [
        [{"template": "*", "mode": "OBSERVE"}],
        [{"template": "low_stock", "mode": "PROPOSE"}],
        [{"template": "low_stock", "mode": "ACT"}],
        [{"template": "low_stock", "mode": "ACT", "grants": {"reorder": "VIEW"}}],
        [{"template": "low_stock", "mode": "OFF"}],
        [{"template": "low_stock", "scope": {"site": "B"}, "mode": "ACT"}, {"template": "*", "mode": "PROPOSE"}],
    ])
    def test_trace_shows_agent_and_agrees_with_ingest(self, rows):
        rig = Rig(rows)
        ev = rig.event(ward="W1")
        t = rig.eng.trace(ev)
        inc = rig.ingest(ev)
        assert t["pattern"]["id"] == inc.pattern_id
        assert (t["outcome"] == "automatic") == rig.ran(inc)
        if inc.pattern_id != "__unmatched__":
            assert t["agent"]["id"] == inc.provenance.agent
            assert t["agent"]["mode"] == inc.provenance.agent_mode
            assert any(t["agent"]["mode"] in s or "shadow" in s or "agent" in s for s in t["steps"]) or \
                t["outcome"] == "automatic"


# ============================================================================== 6. configuration
class TestConfig:
    ROWS = [{"template": "*", "mode": "OBSERVE"},
            {"template": "low_stock", "scope": {"ward": "W1"}, "mode": "ACT", "grants": {"reorder": "EDIT"}},
            {"template": "cold_chain", "scope": {"site": "A"}, "mode": "OFF",
             "valid_from": date(2026, 10, 1), "valid_to": date(2026, 12, 1)}]

    @pytest.mark.parametrize("grant", ["APPROVE", "approve"])
    def test_approve_grant_refused_at_load(self, grant):
        rows = copy.deepcopy(self.ROWS)
        rows[1]["grants"] = {"reorder": grant}
        with pytest.raises(ValueError, match="APPROVE"):
            directory(agents=rows)

    @pytest.mark.parametrize("bad", [{"mode": "AUTO"}, {"grants": {"reorder": "ADMIN"}}])
    def test_bad_mode_or_grant_refused(self, bad):
        rows = copy.deepcopy(self.ROWS)
        rows[1].update(bad)
        with pytest.raises(ValueError):
            directory(agents=rows)

    def test_publish_round_trip_keeps_sod_and_agents(self):
        rig = Rig(self.ROWS)
        text = rig.eng.config_text("people")
        data = yaml.safe_load(text)
        assert data["sod"] == [{"first": "stock.count", "second": "stock.adjust",
                                "description": "who counts does not adjust"}]
        assert len(data["agents"]) == 3 and data["agents"][1]["grants"] == {"reorder": "EDIT"}
        assert errors(rig.eng.check_config("people", text)[1]) == []
        cv, _ = rig.eng.save_config("people", text, author="cy")
        rig.eng.publish_config(cv.id, "cy")
        assert yaml.safe_load(rig.eng.config_text("people")) == data
        assert rig.ran(rig.ingest(rig.event(ward="W1")))
        assert not rig.ran(rig.ingest(rig.event(ward="W2")))
        assert rig.ingest(rig.event("ph.cold_chain", ward="W2")).pattern_id == "__unmatched__"
        assert not authorise(rig.eng.directory, "wes", "stock.adjust", obj="X", scope={"ward": "W1"}, amount=1,
                             done_on_object={"wes": ["stock.count"]})

    def test_publish_refuses_an_approve_grant(self):
        rig = Rig(self.ROWS)
        text = rig.eng.config_text("people").replace("EDIT", "APPROVE")
        assert any("APPROVE" in m for m in errors(rig.eng.check_config("people", text)[1]))
        cv, _ = rig.eng.save_config("people", text, author="cy")
        with pytest.raises(Exception):
            rig.eng.publish_config(cv.id, "cy")
        assert rig.ran(rig.ingest(rig.event(ward="W1")))        # the live policy is untouched

    def test_publishing_off_takes_effect_on_the_next_event(self):
        rig = Rig(self.ROWS)
        assert rig.ran(rig.ingest(rig.event(ward="W1")))
        data = yaml.safe_load(rig.eng.config_text("people"))
        data["agents"][1]["mode"] = "OFF"
        cv, _ = rig.eng.save_config("people", yaml.safe_dump(data), author="cy")
        rig.eng.publish_config(cv.id, "cy")
        inc = rig.ingest(rig.event(ward="W1"))
        assert inc.pattern_id == "__unmatched__" and len(rig.calls) == 1

    def test_plain_people_config_has_no_agents_or_sod(self):
        rig = Rig(people_doc=people(sod=None))
        data = yaml.safe_load(rig.eng.config_text("people"))
        assert not data.get("agents") and not data.get("sod")
        assert errors(rig.eng.check_config("people", rig.eng.config_text("people"))[1]) == []
        assert rig.ran(rig.ingest(rig.event()))
