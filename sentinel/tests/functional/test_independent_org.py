# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""Independent black-box journeys for the org layer (v0.16.0, ADR-003 C1), written from CHANGELOG,
OVERLAY_CONTRACT ("The org layer", "Roles: one place"), ADR-003 and public signatures only.

Domain: a dairy distributor. Depots roll up to zones, zones to regions; products form a tree
(paneer, curd -> fresh -> dairy; ghee -> dairy). Depot managers own "stock expiring" cases; internal audit
sits on a dotted line to the depot manager. Leave cover is a dated assignment.

Tests that expose a framework defect carry ``# DEFECT:`` with expected vs actual and are left failing.
"""
from __future__ import annotations

import copy
from datetime import UTC, date, datetime
from typing import Any

import pytest
import yaml

from sentinel import (ActionRegistry, ActionResult, AuthorizationError, Decision, DecisionKind, Event, Guardrails,
                      MemoryEdge, Overlay)
from sentinel.overlay import parse_registry
from sentinel.rbac import DirectoryError, parse_directory
from sentinel.testing import FrozenClock, engine_for

REFUSED = (DirectoryError, ValueError)

# ============================================================================== org under test
BASE_ROLES = {
    "md": {"name": "Managing director"},
    "regional_manager": {"parent": "md"},
    "zone_manager": {"parent": "regional_manager"},
    "depot_manager": {"parent": "zone_manager", "dotted": ["internal_audit"]},
    "internal_audit": {"parent": "md"},
    "supervisor": {"parent": "md"},
}

ORG = {
    "roles": BASE_ROLES,
    "scopes": {
        "depot": {"rolls_up_to": "zone", "parents": {"D1": "Z1", "D2": "Z1", "D3": "Z2"}},
        "zone": {"rolls_up_to": "region", "parents": {"Z1": "north", "Z2": "south"}},
        "product": {"parents": {"paneer": "fresh", "curd": "fresh", "fresh": "dairy", "ghee": "dairy"}},
    },
    "stop_at": ["regional_manager", "md"],
    "people": [{"id": p} for p in ("ravi", "dev", "zara", "zed", "rena", "aud", "mo", "gone")]
              + [{"id": "lapsed", "active": False}],
    "assignments": [
        {"person_id": "ravi", "role_id": "depot_manager", "scope": {"depot": "D1"}},
        # leave cover for D2: 25 Oct (inclusive) to 8 Nov (exclusive)
        {"person_id": "dev", "role_id": "depot_manager", "scope": {"depot": "D2"},
         "valid_from": date(2026, 10, 25), "valid_to": date(2026, 11, 8)},
        # a past assignment kept as history
        {"person_id": "gone", "role_id": "depot_manager", "scope": {"depot": "D3"},
         "valid_from": date(2026, 1, 1), "valid_to": date(2026, 6, 1)},
        {"person_id": "zara", "role_id": "zone_manager", "scope": {"zone": "Z1"}},
        {"person_id": "zed", "role_id": "zone_manager", "scope": {"zone": "Z2"}},
        {"person_id": "rena", "role_id": "regional_manager", "scope": {"region": "north"}},
        {"person_id": "aud", "role_id": "internal_audit"},
        {"person_id": "mo", "role_id": "md"},
        {"person_id": "mo", "role_id": "supervisor"},
        {"person_id": "lapsed", "role_id": "zone_manager", "scope": {"zone": "Z2"}},
    ],
    "authority": [
        {"role_id": "depot_manager", "action": "write_off"},
        {"role_id": "md", "action": "__configure__"},
    ],
}

REGISTRY = {
    "roles": {k: k for k in BASE_ROLES},
    "fingerprints": [{"event_type": "stock.expiring",
                      "fields": {"depot": "depot", "product": "product", "batch": "batch"}, "group_by": ["batch"]}],
    "patterns": [{"id": "expiring", "description": "Stock close to expiry", "event_types": ["stock.expiring"],
                  "route": "hitl", "max_route": "hitl",
                  "playbook": [{"action": "write_off", "params": {"batch": "{{payload.batch}}"}}],
                  "allowed_actions": ["write_off"], "disposition_codes": ["written_off", "no_action"],
                  "owner_role": "depot_manager", "sla_minutes": 30}],
}

TODAY = datetime(2026, 10, 20, 9, 0, tzinfo=UTC)          # before dev's cover starts
IN_COVER = datetime(2026, 10, 26, 9, 0, tzinfo=UTC)
AFTER_COVER = datetime(2026, 11, 9, 9, 0, tzinfo=UTC)


def org(**changes: Any) -> dict[str, Any]:
    d = copy.deepcopy(ORG)
    for k, v in changes.items():
        if v is None:
            d.pop(k, None)
        else:
            d[k] = v
    return d


def directory(**changes: Any):
    return parse_directory(org(**changes))


def make_engine(people: dict | None = None, at: datetime = TODAY, edge: MemoryEdge | None = None):
    acts = ActionRegistry()

    @acts.action("write_off", reversible=False, params={"batch": "str"}, description="write off a batch")
    def write_off(ctx, p):
        return ActionResult(ok=True, detail="written off")

    doc = parse_registry(copy.deepcopy(REGISTRY))
    kw: dict[str, Any] = {}
    if edge is not None:
        kw = {"edges": {edge.name: edge}, "default_edges": [edge.name]}
    ov = Overlay(name="dairy", fingerprint_rules=doc.fingerprints, patterns=doc.patterns, roles=doc.roles,
                 actions=acts, directory=parse_directory(copy.deepcopy(people or ORG)), **kw)
    clock = FrozenClock(at)
    return engine_for(ov, clock=clock, guardrails=Guardrails()), clock


_n = [0]


def expiring(eng, depot: str = "D1", product: str = "paneer"):
    _n[0] += 1
    r = eng.ingest(Event(type="stock.expiring", source="erp", idempotency_key=f"exp-{_n[0]}",
                         payload={"depot": depot, "product": product, "batch": f"B{_n[0]}"}))
    return r.incident_id, eng.store.open_review_for(r.incident_id)


def approve(eng, rev, who: str):
    return eng.decide(rev.id, Decision(kind=DecisionKind.APPROVE, actor=who, disposition_code="written_off"))


def kinds(eng) -> list[str]:
    return [a["kind"] for a in eng.store.audit_log()]


def errors(problems) -> list[str]:
    return [p.message for p in problems if p.severity == "error"]


# ============================================================================== 1. dotted lines
class TestDotted:
    def test_dotted_line_sees_but_cannot_act(self):
        d = directory()
        f = {"depot": "D1", "product": "paneer"}
        assert d.can_see("aud", "depot_manager", f) and not d.can_act("aud", "depot_manager", f)
        assert d.can_act("ravi", "depot_manager", f) and d.can_act("zara", "depot_manager", f)

    def test_dotted_line_has_no_authority_in_authorize_steps(self):
        from sentinel import PlaybookStep
        d = directory()
        a = d.authorize_steps("aud", "expiring", "depot_manager",
                              [PlaybookStep(action="write_off", params={"batch": "B1"})], {"depot": "D1"})
        assert not a.allowed

    def test_dotted_line_cannot_approve_through_the_engine(self):
        eng, _ = make_engine()
        _, rev = expiring(eng, "D1")
        with pytest.raises(AuthorizationError):
            approve(eng, rev, "aud")
        assert "decision_denied" in kinds(eng)
        assert eng.store.open_review_for(rev.incident_id).id == rev.id    # still open, nothing ran

    def test_dotted_line_sees_the_queue_in_reviews_for(self):
        # FIXED v0.18.1 (was DEFECT): docs: "audit sees the queue; cannot act on it" and can_see() "adds the dotted lines".
        # Expected: engine.reviews_for('aud') lists the open depot_manager review (it is the queue a person
        # sees). Actual: [] -- reviews_for only reads roles the person holds and the roles below them, so a
        # dotted-line role's queue is never fetched even though can_see() says True.
        eng, _ = make_engine()
        expiring(eng, "D1")
        assert eng.directory.can_see("aud", "depot_manager", {"depot": "D1"})
        assert len(eng.reviews_for("aud")) == 1

    def test_dotted_line_does_not_reach_other_queues(self):
        d = directory()
        assert not d.can_see("aud", "zone_manager", {"zone": "Z1"})
        assert not d.can_act("aud", "zone_manager", {"zone": "Z1"})

    def test_dotted_role_is_never_a_holder_when_vacant(self):
        d = directory()
        role, people = d.holders("depot_manager", {"depot": "D2"}, TODAY)      # D2 vacant before the cover
        assert role != "internal_audit" and "aud" not in [p.id for p in people]
        assert role == "zone_manager" and [p.id for p in people] == ["zara"]

    def test_sweep_never_escalates_onto_the_dotted_line(self):
        eng, clock = make_engine()
        inc, _ = expiring(eng, "D1")
        seen = []
        for _ in range(4):
            clock.advance(minutes=31)
            eng.sweep()
            seen.append(eng.store.open_review_for(inc).assignee_role)
        assert "internal_audit" not in seen
        assert seen[0] == "zone_manager"

    @pytest.mark.parametrize("dotted, needle", [(["ghost"], "ghost"), (["zone_manager"], "zone_manager"),
                                                (["md"], "md")])
    def test_unknown_or_solid_line_duplicating_dotted_refused(self, dotted, needle):
        roles = copy.deepcopy(BASE_ROLES)
        roles["depot_manager"]["dotted"] = dotted
        with pytest.raises(REFUSED, match=needle):
            directory(roles=roles)


# ============================================================================== 2. time-bound assignments
class TestTime:
    def test_valid_from_is_inclusive_and_valid_to_exclusive(self):
        d = directory()
        f = {"depot": "D2"}
        assert d.roles_of("dev", f, datetime(2026, 10, 24, 23, 59, tzinfo=UTC)) == set()
        assert d.roles_of("dev", f, datetime(2026, 10, 25, 0, 0, tzinfo=UTC)) == {"depot_manager"}
        assert d.roles_of("dev", f, datetime(2026, 11, 7, 23, 59, tzinfo=UTC)) == {"depot_manager"}
        assert d.roles_of("dev", f, datetime(2026, 11, 8, 0, 0, tzinfo=UTC)) == set()

    def test_datetime_windows(self):
        a = copy.deepcopy(ORG["assignments"])
        a.append({"person_id": "zed", "role_id": "depot_manager", "scope": {"depot": "D1"},
                  "valid_from": datetime(2026, 10, 20, 14, 0, tzinfo=UTC),
                  "valid_to": datetime(2026, 10, 20, 22, 0, tzinfo=UTC)})
        d = directory(assignments=a)
        f = {"depot": "D1"}
        assert "depot_manager" not in d.roles_of("zed", f, datetime(2026, 10, 20, 13, 59, tzinfo=UTC))
        assert "depot_manager" in d.roles_of("zed", f, datetime(2026, 10, 20, 14, 0, tzinfo=UTC))
        assert "depot_manager" not in d.roles_of("zed", f, datetime(2026, 10, 20, 22, 0, tzinfo=UTC))

    def test_datetime_window_with_offset_from_yaml(self):
        text = yaml.safe_dump(org(assignments=[]))
        text = text.replace("assignments: []", """assignments:
- {person_id: zed, role_id: depot_manager, scope: {depot: D1}, valid_from: '2026-10-20T14:00:00+05:30', valid_to: '2026-10-20T22:00:00+05:30'}
- {person_id: mo, role_id: md}
- {person_id: mo, role_id: supervisor}""")
        d = parse_directory(yaml.safe_load(text))
        f = {"depot": "D1"}
        assert "depot_manager" not in d.roles_of("zed", f, datetime(2026, 10, 20, 8, 29, tzinfo=UTC))
        assert "depot_manager" in d.roles_of("zed", f, datetime(2026, 10, 20, 8, 30, tzinfo=UTC))
        assert "depot_manager" not in d.roles_of("zed", f, datetime(2026, 10, 20, 16, 30, tzinfo=UTC))

    @pytest.mark.parametrize("frm, to", [(date(2026, 11, 8), date(2026, 11, 8)),
                                         (date(2026, 11, 8), date(2026, 10, 25))])
    def test_empty_window_refused(self, frm, to):
        a = copy.deepcopy(ORG["assignments"])
        a[1].update(valid_from=frm, valid_to=to)
        with pytest.raises(REFUSED):
            directory(assignments=a)

    def test_engine_clock_decides_who_gets_the_case_and_can_approve(self):
        before, _ = make_engine(at=TODAY)
        _, rev = expiring(before, "D2")
        assert before.reviews_for("dev") == []
        with pytest.raises(AuthorizationError):
            approve(before, rev, "dev")
        during, _ = make_engine(at=IN_COVER)                 # wall clock is still 20 Oct
        _, rev2 = expiring(during, "D2")
        assert rev2.assignee_role == "depot_manager"
        assert [r.id for r in during.reviews_for("dev")] == [rev2.id]
        approve(during, rev2, "dev")

    def test_expired_cover_gets_no_queue_or_authority(self):
        eng, _ = make_engine(at=AFTER_COVER)
        _, rev = expiring(eng, "D2")
        assert eng.reviews_for("dev") == []
        with pytest.raises(AuthorizationError):
            approve(eng, rev, "dev")

    def test_window_ending_while_case_is_open_removes_authority(self):
        eng, clock = make_engine(at=datetime(2026, 11, 7, 23, 0, tzinfo=UTC))
        _, rev = expiring(eng, "D2")
        assert [r.id for r in eng.reviews_for("dev")] == [rev.id]
        clock.advance(minutes=61)                            # now 8 Nov 00:01: cover over
        assert eng.reviews_for("dev") == []
        with pytest.raises(AuthorizationError):
            approve(eng, rev, "dev")

    def test_cards_go_only_to_people_current_on_the_engine_clock(self):
        edge = MemoryEdge()
        eng, _ = make_engine(at=AFTER_COVER, edge=edge)
        a = copy.deepcopy(ORG["assignments"])
        expiring(eng, "D1")
        eng.work("w")
        assert [c.recipient_id for c in edge.cards] == ["ravi"]
        edge2 = MemoryEdge()
        p = org()
        p["vacancy"] = "off"
        eng2, _ = make_engine(people=p, at=AFTER_COVER, edge=edge2)
        expiring(eng2, "D2")                                  # vacant role keeps the case; no current people
        eng2.work("w")
        assert "dev" not in [c.recipient_id for c in edge2.cards]
        assert a  # unchanged fixture

    def test_past_assignments_stay_as_history(self):
        d = directory()
        assert any(a.person_id == "gone" for a in d.assignments)
        assert d.roles_of("gone", {"depot": "D3"}, datetime(2026, 3, 1, tzinfo=UTC)) == {"depot_manager"}
        assert d.roles_of("gone", {"depot": "D3"}, TODAY) == set()
        eng, _ = make_engine()
        assert "gone" in eng.config_text("people")


# ============================================================================== 3. typed hierarchical scopes
class TestScopes:
    def test_tree_within_a_fact(self):
        a = copy.deepcopy(ORG["assignments"]) + [
            {"person_id": "zed", "role_id": "depot_manager", "scope": {"product": "fresh"}},
            {"person_id": "rena", "role_id": "depot_manager", "scope": {"product": "dairy"}}]
        d = directory(assignments=a)
        assert "depot_manager" in d.roles_of("zed", {"product": "paneer"}, TODAY)
        assert "depot_manager" in d.roles_of("zed", {"product": "fresh"}, TODAY)
        assert "depot_manager" not in d.roles_of("zed", {"product": "ghee"}, TODAY)
        assert "depot_manager" in d.roles_of("rena", {"product": "paneer"}, TODAY)     # two levels down
        assert "depot_manager" in d.roles_of("rena", {"product": "ghee"}, TODAY)

    def test_lower_value_does_not_cover_higher(self):
        a = copy.deepcopy(ORG["assignments"]) + [
            {"person_id": "zed", "role_id": "depot_manager", "scope": {"product": "paneer"}}]
        d = directory(assignments=a)
        assert "depot_manager" not in d.roles_of("zed", {"product": "fresh"}, TODAY)
        assert "depot_manager" not in d.roles_of("zed", {"product": "curd"}, TODAY)

    def test_roll_up_across_facts(self):
        d = directory()
        assert d.roles_of("zara", {"depot": "D1"}, TODAY) == {"zone_manager"}
        assert d.roles_of("zara", {"depot": "D2"}, TODAY) == {"zone_manager"}
        assert d.roles_of("zara", {"depot": "D3"}, TODAY) == set()
        assert d.roles_of("zed", {"depot": "D3"}, TODAY) == {"zone_manager"}

    def test_chain_of_roll_ups(self):
        d = directory()
        assert d.roles_of("rena", {"depot": "D1"}, TODAY) == {"regional_manager"}    # depot->zone->region
        assert d.roles_of("rena", {"zone": "Z1"}, TODAY) == {"regional_manager"}
        assert d.roles_of("rena", {"depot": "D3"}, TODAY) == set()

    def test_list_valued_assignment_scopes(self):
        a = copy.deepcopy(ORG["assignments"]) + [
            {"person_id": "zed", "role_id": "depot_manager", "scope": {"depot": ["D1", "D3"]}},
            {"person_id": "aud", "role_id": "regional_manager", "scope": {"region": ["north", "south"]}},
            {"person_id": "ravi", "role_id": "zone_manager", "scope": {"zone": ["Z2"]}}]
        d = directory(assignments=a)
        assert "depot_manager" in d.roles_of("zed", {"depot": "D3"}, TODAY)
        assert "depot_manager" not in d.roles_of("zed", {"depot": "D2"}, TODAY)
        assert "regional_manager" in d.roles_of("aud", {"depot": "D3"}, TODAY)
        assert "zone_manager" in d.roles_of("ravi", {"depot": "D3"}, TODAY)
        assert "zone_manager" not in d.roles_of("ravi", {"depot": "D1"}, TODAY)

    def test_values_not_in_the_tree(self):
        a = copy.deepcopy(ORG["assignments"]) + [
            {"person_id": "zed", "role_id": "depot_manager", "scope": {"depot": "D9"}},
            {"person_id": "zed", "role_id": "depot_manager", "scope": {"product": "dairy"}}]
        d = directory(assignments=a)
        assert d.roles_of("zara", {"depot": "D9"}, TODAY) == set()       # D9 belongs to no zone
        assert d.roles_of("rena", {"depot": "D9"}, TODAY) == set()
        assert "depot_manager" in d.roles_of("zed", {"depot": "D9"}, TODAY)  # exact match still works
        assert "depot_manager" not in d.roles_of("zed", {"product": "butter"}, TODAY)
        assert d.roles_of("mo", {"depot": "D9"}, TODAY) == {"md", "supervisor"}   # unscoped covers all

    def test_two_dimensions_must_both_match(self):
        a = copy.deepcopy(ORG["assignments"]) + [
            {"person_id": "zed", "role_id": "depot_manager", "scope": {"zone": "Z1", "product": "fresh"}}]
        d = directory(assignments=a)
        assert "depot_manager" in d.roles_of("zed", {"depot": "D1", "product": "curd"}, TODAY)
        assert "depot_manager" not in d.roles_of("zed", {"depot": "D1", "product": "ghee"}, TODAY)
        assert "depot_manager" not in d.roles_of("zed", {"depot": "D3", "product": "curd"}, TODAY)

    def test_out_of_scope_person_gets_no_queue_or_authority(self):
        eng, clock = make_engine()
        inc, rev = expiring(eng, "D1")
        assert eng.reviews_for("zed") == [] and eng.reviews_for("rena") != []
        clock.advance(minutes=31)
        eng.sweep()
        rev = eng.store.open_review_for(inc)
        assert rev.assignee_role == "zone_manager"
        assert eng.reviews_for("zed") == []
        with pytest.raises(AuthorizationError):
            approve(eng, rev, "zed")                         # Z2 manager, D1 is in Z1
        approve(eng, rev, "zara")

    @pytest.mark.parametrize("scopes", [
        {"depot": {"rolls_up_to": "zone", "parents": {}}, "zone": {"rolls_up_to": "depot", "parents": {}}},
        {"product": {"parents": {"paneer": "fresh", "fresh": "paneer"}}},
        {"product": {"parents": {"paneer": "paneer"}}},
        {"depot": {"rolls_up_to": "depot", "parents": {"D1": "D1"}}},
    ])
    def test_scope_cycles_refused(self, scopes):
        with pytest.raises(REFUSED, match="cycle|itself"):
            directory(scopes=scopes)


# ============================================================================== 4. holders and stop_at
class TestHolders:
    def test_own_people_in_scope(self):
        d = directory()
        role, people = d.holders("depot_manager", {"depot": "D1"}, TODAY)
        assert role == "depot_manager" and [p.id for p in people] == ["ravi"]

    def test_vacant_goes_to_nearest_held_role_in_scope(self):
        d = directory()
        assert [p.id for p in d.holders("depot_manager", {"depot": "D2"}, TODAY)[1]] == ["zara"]
        assert d.holders("depot_manager", {"depot": "D2"}, IN_COVER)[0] == "depot_manager"

    def test_inactive_holder_counts_as_vacant(self):
        d = directory()
        # D3: depot vacant (gone expired); Z2 has zed (active) and lapsed (inactive)
        role, people = d.holders("depot_manager", {"depot": "D3"}, TODAY)
        assert role == "zone_manager" and [p.id for p in people] == ["zed"]

    def test_stops_at_vacant_stop_role_and_never_pages_the_top(self):
        a = [x for x in ORG["assignments"] if x["person_id"] != "zed"]
        d = directory(assignments=a)
        role, people = d.holders("depot_manager", {"depot": "D3"}, TODAY)   # south region is vacant
        assert role == "regional_manager" and people == []

    def test_stop_role_asked_directly_returns_itself_when_vacant(self):
        d = directory()
        assert d.holders("regional_manager", {"depot": "D3"}, TODAY) == ("regional_manager", [])

    def test_holders_reads_time(self):
        d = directory()
        assert d.holders("depot_manager", {"depot": "D2"}, AFTER_COVER)[0] == "zone_manager"

    def test_every_role_needs_a_stop_at_or_above(self):
        with pytest.raises(REFUSED, match="stop"):
            directory(stop_at=["regional_manager"])          # md, internal_audit, supervisor have no stop

    def test_unknown_stop_role_refused(self):
        with pytest.raises(REFUSED, match="ghost"):
            directory(stop_at=["regional_manager", "md", "ghost"])

    def test_a_dotted_role_cannot_bridge_a_stop_gap(self):
        # internal_audit sits under md; take md out of stop_at but leave it on a dotted line only
        with pytest.raises(REFUSED, match="stop"):
            directory(stop_at=["regional_manager", "internal_audit", "supervisor"])


# ============================================================================== 5. vacancy
class TestVacancy:
    def test_vacancy_is_off_by_default(self):
        eng, _ = make_engine()
        _, rev = expiring(eng, "D2")
        assert rev.assignee_role == "depot_manager"
        assert "vacancy_escalated" not in kinds(eng)

    def test_vacancy_escalate_routes_to_nearest_held_role_and_audits(self):
        eng, _ = make_engine(people=org(vacancy="escalate"))
        inc, rev = expiring(eng, "D2")
        assert rev.assignee_role == "zone_manager"
        ev = [a for a in eng.store.audit_log() if a["kind"] == "vacancy_escalated"]
        assert len(ev) == 1 and ev[0]["data"]["role"] == "depot_manager" and ev[0]["data"]["to"] == "zone_manager"
        assert [r.id for r in eng.reviews_for("zara")] == [rev.id]
        assert eng.reviews_for("zed") == []

    def test_vacancy_escalate_with_cover_present_does_not_move(self):
        eng, _ = make_engine(people=org(vacancy="escalate"), at=IN_COVER)
        _, rev = expiring(eng, "D2")
        assert rev.assignee_role == "depot_manager" and "vacancy_escalated" not in kinds(eng)

    def test_vacancy_stops_at_stop_role_even_when_vacant(self):
        a = [x for x in ORG["assignments"] if x["person_id"] != "zed"]
        eng, _ = make_engine(people=org(vacancy="escalate", assignments=a))
        _, rev = expiring(eng, "D3")
        assert rev.assignee_role == "regional_manager"       # not md
        assert eng.reviews_for("rena") == []                 # north's manager does not get south's case

    def test_sweep_after_vacancy_escalation_stays_at_the_stop(self):
        # FIXED v0.18.1 (was DEFECT): same rule. A south case lands on the vacant stop role regional_manager (correct, nobody is
        # paged), but the first sweep moves it to md. Expected: stays regional_manager. Actual: 'md'.
        a = [x for x in ORG["assignments"] if x["person_id"] != "zed"]
        eng, clock = make_engine(people=org(vacancy="escalate", assignments=a))
        inc, rev = expiring(eng, "D3")
        assert rev.assignee_role == "regional_manager"
        clock.advance(minutes=31)
        eng.sweep()
        assert eng.store.open_review_for(inc).assignee_role == "regional_manager"

    def test_bad_vacancy_value_refused(self):
        with pytest.raises(REFUSED):
            directory(vacancy="sometimes")

    def test_sweep_never_escalates_past_the_stop_list(self):
        # FIXED v0.18.1 (was DEFECT): docs: "stop_at: [...] # vacancy and escalation never climb past these" and the dotted/stop
        # rules apply to "escalation via sweep". Expected: once the review reaches regional_manager (a stop
        # role) later sweeps keep it there. Actual: ['zone_manager', 'regional_manager', 'md', 'md', 'md'] --
        # sweep() walks directory.parent_of() to md, ignoring stop_at.
        eng, clock = make_engine()
        inc, _ = expiring(eng, "D1")
        roles = []
        for _ in range(5):
            clock.advance(minutes=31)
            eng.sweep()
            roles.append(eng.store.open_review_for(inc).assignee_role)
        assert roles[:2] == ["zone_manager", "regional_manager"]
        assert "md" not in roles, roles


# ============================================================================== 6. config publish and SCIM
class TestConfig:
    def test_people_config_round_trip_keeps_the_org_layer(self):
        eng, _ = make_engine(people=org(vacancy="escalate"))
        text = eng.config_text("people")
        data = yaml.safe_load(text)
        assert data["roles"]["depot_manager"]["dotted"] == ["internal_audit"]
        assert data["scopes"]["depot"]["rolls_up_to"] == "zone"
        assert set(data["stop_at"]) == {"regional_manager", "md"}
        assert data["vacancy"] == "escalate"
        dev = [a for a in data["assignments"] if a["person_id"] == "dev"][0]
        assert str(dev["valid_from"]).startswith("2026-10-25") and str(dev["valid_to"]).startswith("2026-11-08")
        assert errors(eng.check_config("people", text)[1]) == []
        cv, _ = eng.save_config("people", text, author="mo")
        eng.publish_config(cv.id, "mo")
        d = eng.directory
        assert d.holders("depot_manager", {"depot": "D2"}, TODAY)[0] == "zone_manager"
        assert d.can_see("aud", "depot_manager", {"depot": "D1"}) and not d.can_act("aud", "depot_manager",
                                                                                     {"depot": "D1"})
        assert d.roles_of("dev", {"depot": "D2"}, IN_COVER) == {"depot_manager"}
        assert d.roles_of("dev", {"depot": "D2"}, AFTER_COVER) == set()
        assert d.roles_of("rena", {"depot": "D1"}, TODAY) == {"regional_manager"}
        _, rev = expiring(eng, "D2")
        assert rev.assignee_role == "zone_manager"           # vacancy survives publish
        assert yaml.safe_load(eng.config_text("people")) == data

    @pytest.mark.parametrize("mutate, needle", [
        (lambda p: p["roles"]["depot_manager"].update(dotted=["ghost"]), "ghost"),
        (lambda p: p["scopes"]["product"]["parents"].update(dairy="paneer"), "cycle"),
        (lambda p: p.update(stop_at=["regional_manager"]), "stop"),
        (lambda p: p["assignments"][1].update(valid_to=date(2026, 10, 1)), ""),
    ])
    def test_publish_refuses_bad_org(self, mutate, needle):
        eng, _ = make_engine()
        p = yaml.safe_load(eng.config_text("people"))
        mutate(p)
        text = yaml.safe_dump(p)
        errs = errors(eng.check_config("people", text)[1])
        assert errs and any(needle in m for m in errs)
        cv, _ = eng.save_config("people", text, author="mo")
        with pytest.raises(Exception):
            eng.publish_config(cv.id, "mo")

    def test_scim_people_keep_the_org_layer(self, monkeypatch):
        pytest.importorskip("fastapi")
        from fastapi.testclient import TestClient
        from sentinel.api import create_app
        from sentinel.rbac import ScimSettings
        monkeypatch.setenv("SENTINEL_SECRET_SCIM_TOKEN", "scim-secret")
        monkeypatch.setenv("SENTINEL_EGRESS_ALLOW", "127.0.0.0/8,::1,localhost")
        eng, _ = make_engine(people=org(vacancy="escalate"))
        eng.directory.scim = ScimSettings(group_roles={
            "Zone North": [{"role": "zone_manager", "scope": {"zone": "Z1"}}],
            "Audit": ["internal_audit"]})
        c = TestClient(create_app(eng, {}, console=False))
        h = {"Authorization": "Bearer scim-secret"}
        u = c.post("/scim/v2/Users", headers=h, json={"userName": "nila@dairy.in"})
        assert u.status_code == 201, u.text
        uid = u.json()["id"]
        pid = u.json()["sentinelPersonId"]
        c.post("/scim/v2/Groups", headers=h, json={"displayName": "Zone North", "members": [{"value": uid}]})
        c.post("/scim/v2/Groups", headers=h, json={"displayName": "Audit", "members": [{"value": uid}]})
        d = eng.directory
        assert "zone_manager" in d.roles_of(pid, {"depot": "D2"}, TODAY)            # roll-up still applies
        assert "zone_manager" not in d.roles_of(pid, {"depot": "D3"}, TODAY)
        assert d.can_see(pid, "depot_manager", {"depot": "D3"})                     # dotted via audit group
        assert d.can_act(pid, "depot_manager", {"depot": "D1"})                     # via Z1 zone_manager
        assert not d.can_act(pid, "depot_manager", {"depot": "D3"})                 # dotted only for D3
        assert d.vacancy == "escalate" and set(d.stop_at) == {"regional_manager", "md"}
        assert d.holders("depot_manager", {"depot": "D2"}, TODAY)[0] == "zone_manager"
        assert sorted(p.id for p in d.holders("depot_manager", {"depot": "D2"}, TODAY)[1]) == sorted(
            [pid, "zara"])
        assert d.roles_of("dev", {"depot": "D2"}, IN_COVER) == {"depot_manager"}    # windows kept
        assert d.roles_of("dev", {"depot": "D2"}, AFTER_COVER) == set()
        _, rev = expiring(eng, "D3")
        assert rev.assignee_role == "zone_manager"
        with pytest.raises(AuthorizationError):
            approve(eng, rev, pid)                                                  # Z1 person, Z2 case


# ============================================================================== 7. no org layer: as before
class TestPlainDirectory:
    PLAIN = {
        "roles": {"md": {}, "zone_manager": {"parent": "md"}, "depot_manager": {"parent": "zone_manager"},
                  "supervisor": {"parent": "md"}, "internal_audit": {"parent": "md"},
                  "regional_manager": {"parent": "md"}},
        "people": [{"id": p} for p in ("ravi", "zara", "mo")],
        "assignments": [{"person_id": "ravi", "role_id": "depot_manager", "scope": {"depot": "D1"}},
                        {"person_id": "zara", "role_id": "zone_manager", "scope": {"zone": "Z1"}},
                        {"person_id": "mo", "role_id": "md"}],
        "authority": [{"role_id": "depot_manager", "action": "write_off"}, {"role_id": "md", "action": "__configure__"}],
    }

    def test_plain_directory_matches_as_before(self):
        d = parse_directory(copy.deepcopy(self.PLAIN))
        assert d.roles_of("ravi", {"depot": "D1"}) == {"depot_manager"}
        assert d.roles_of("zara", {"depot": "D1"}) == set()        # no roll-up without scopes
        assert d.roles_of("zara", {"zone": "Z1"}) == {"zone_manager"}
        for who, role in [("ravi", "depot_manager"), ("zara", "depot_manager"), ("mo", "depot_manager")]:
            f = {"depot": "D1", "zone": "Z1"}
            assert d.can_see(who, role, f) == d.can_act(who, role, f)
        assert d.vacancy == "off"

    def test_plain_engine_routes_and_escalates_as_before(self):
        eng, clock = make_engine(people=copy.deepcopy(self.PLAIN))
        inc, rev = expiring(eng, "D2")
        assert rev.assignee_role == "depot_manager"            # vacant, but no vacancy rule
        assert "vacancy_escalated" not in kinds(eng)
        roles = []
        for _ in range(3):
            clock.advance(minutes=31)
            eng.sweep()
            roles.append(eng.store.open_review_for(inc).assignee_role)
        assert roles == ["zone_manager", "md", "md"]           # walks up and stays at the top
        _, rev2 = expiring(eng, "D1")
        approve(eng, rev2, "ravi")

    def test_plain_config_text_has_no_org_keys(self):
        eng, _ = make_engine(people=copy.deepcopy(self.PLAIN))
        data = yaml.safe_load(eng.config_text("people"))
        for k in ("scopes", "stop_at"):
            assert not data.get(k)
        assert data.get("vacancy") in (None, "off")
        assert all("valid_from" not in a and "valid_to" not in a for a in data["assignments"])
        assert errors(eng.check_config("people", eng.config_text("people"))[1]) == []
