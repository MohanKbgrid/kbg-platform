# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""S3 (ADR-003 C1): dotted lines, time-bound assignments, typed hierarchical scopes, vacancy, stop list.

Proved on the R06 exemplar's chain A org (tests/packs/r06_stock_integrity/people_chain_a_org.yaml)."""
from __future__ import annotations

from datetime import UTC, date, datetime
from pathlib import Path

import pytest
import yaml

from sentinel import Assignment, Directory, Person, Role
from sentinel.config import directory_doc, dump_yaml
from sentinel.models import Event, PlaybookStep
from sentinel.rbac import DirectoryError, ScopeDimension, load_directory, parse_directory
from sentinel.testing import FrozenClock, engine_for
from tests.test_role_slots import _overlay

PACK = Path(__file__).parent / "packs" / "r06_stock_integrity"
ORG = PACK / "people_chain_a_org.yaml"


def at(y, m, d):
    return datetime(y, m, d, 9, 0, tzinfo=UTC)


def org(**changes):
    data = yaml.safe_load(ORG.read_text(encoding="utf-8"))
    data.update(changes)
    return parse_directory({k: v for k, v in data.items() if v is not None})


# ---- time-bound assignments --------------------------------------------------------------------------

def test_cover_while_on_leave_follows_the_dates():
    d = org()
    tvm01 = {"store": "TVM01"}
    assert [p.id for p in d.people_in("store_manager", tvm01, at(2026, 10, 20))] == ["meena"]
    assert [p.id for p in d.people_in("store_manager", tvm01, at(2026, 10, 30))] == ["priya"]
    assert [p.id for p in d.people_in("store_manager", tvm01, at(2026, 11, 10))] == ["meena"]
    assert d.roles_of("priya", tvm01, at(2026, 10, 20)) == set()
    assert d.roles_of("priya", tvm01, at(2026, 10, 25)) == {"store_manager"}      # valid_from is inclusive
    assert d.roles_of("priya", tvm01, at(2026, 11, 8)) == set()                   # valid_to is exclusive


def test_engine_tells_assignment_time_by_its_own_clock():
    clock = FrozenClock(at(2026, 10, 30))
    eng = engine_for(_overlay("chain_a", org()), clock=clock)
    r = eng.ingest(Event(type="inv.sales_stopped", source="pos",
                         payload={"store": "TVM01", "article": "A1", "book_qty": 4}))
    assert r.incident_id in [t.incident_id for t in eng.reviews_for("priya")]
    assert eng.reviews_for("meena") == []
    clock.now = at(2026, 11, 10)                                      # meena is back
    assert r.incident_id in [t.incident_id for t in eng.reviews_for("meena")]
    assert eng.reviews_for("priya") == []


def test_bad_window_is_refused():
    with pytest.raises(ValueError, match="valid_to must be after valid_from"):
        Assignment(person_id="p", role_id="r", valid_from=date(2026, 5, 1), valid_to=date(2026, 5, 1))


# ---- typed hierarchical scopes -----------------------------------------------------------------------

def test_region_assignment_covers_its_stores():
    d = org()
    assert [p.id for p in d.people_in("regional_manager", {"store": "TVM03"})] == ["suresh"]
    assert [p.id for p in d.people_in("regional_manager", {"store": "COK01"})] == ["lakshmi"]
    assert d.people_in("regional_manager", {"store": "NEW99"}) == []              # store not in the tree
    assert d.roles_of("suresh", {"region": "south"}) == {"regional_manager"}
    assert d.roles_of("suresh", {"store": "COK01"}) == set()


def test_category_tree_covers_children_not_siblings():
    d = org()
    assert d.roles_of("ravi", {"category": "rice"}) == {"category_buyer"}
    assert d.roles_of("ravi", {"category": "staples"}) == {"category_buyer"}
    assert d.roles_of("ravi", {"category": "grocery"}) == set()                   # above the assignment
    assert d.roles_of("ravi", {"category": "soap"}) == set()


def test_scopes_are_validated():
    roles = [Role(id="a")]
    with pytest.raises(DirectoryError, match="value tree has a cycle"):
        Directory(roles, scopes={"c": ScopeDimension(parents={"x": "y", "y": "x"})})
    with pytest.raises(DirectoryError, match="rolls_up_to itself"):
        Directory(roles, scopes={"c": ScopeDimension(rolls_up_to="c")})
    with pytest.raises(DirectoryError, match="rolls up in a cycle"):
        Directory(roles, scopes={"a": ScopeDimension(rolls_up_to="b"), "b": ScopeDimension(rolls_up_to="a")})


def test_without_scopes_matching_is_exact_as_before():
    d = Directory([Role(id="r")], [Person(id="p")], [Assignment(person_id="p", role_id="r", scope={"store": "S"})])
    assert d.roles_of("p", {"store": "S"}) == {"r"} and d.roles_of("p", {"store": "T"}) == set()
    assert d.roles_of("p", {}) == set()


# ---- dotted lines ------------------------------------------------------------------------------------

def test_dotted_line_sees_the_queue_but_cannot_act():
    d = org()
    rice = {"category": "rice"}
    assert d.can_see("ganesh", "category_buyer", rice)
    assert not d.can_act("ganesh", "category_buyer", rice)
    assert "internal_audit" not in d.ancestors("category_buyer")             # not on the escalation path
    auth = d.authorize_steps("ganesh", "p", "category_buyer",
                             [PlaybookStep(action="task.count", params={"store": "TVM01", "article": "A"})], rice)
    assert not auth.allowed
    assert d.authorize_steps("ravi", "p", "category_buyer",
                             [PlaybookStep(action="task.count", params={"store": "TVM01", "article": "A"})],
                             rice).allowed


def test_dotted_lines_are_validated():
    with pytest.raises(DirectoryError, match="unknown dotted-line role"):
        Directory([Role(id="a", dotted=["ghost"])])
    with pytest.raises(DirectoryError, match="duplicates the solid line"):
        Directory([Role(id="top"), Role(id="a", parent="top", dotted=["top"])])


# ---- vacancy and the stop list -----------------------------------------------------------------------

def test_holders_climb_to_the_nearest_held_role_and_stop_at_the_stop_list():
    d = org()
    assert d.holders("store_manager", {"store": "TVM02"})[0] == "store_manager"
    role, people = d.holders("store_manager", {"store": "TVM03"})           # vacant store
    assert (role, [p.id for p in people]) == ("regional_manager", ["suresh"])
    role, people = d.holders("store_manager", {"store": "NEW99"})           # nobody, region unknown
    assert (role, people) == ("regional_manager", [])                       # stops; ops_head is not paged


def test_vacant_role_review_goes_to_the_nearest_held_role():
    eng = engine_for(_overlay("chain_a", org()), clock=FrozenClock(at(2026, 10, 20)))
    r = eng.ingest(Event(type="inv.sales_stopped", source="pos",
                         payload={"store": "TVM03", "article": "A1", "book_qty": 4}))
    review = eng.store.open_review_for(r.incident_id)
    assert review.assignee_role == "regional_manager"
    assert r.incident_id in [t.incident_id for t in eng.reviews_for("suresh")]
    assert r.incident_id not in [t.incident_id for t in eng.reviews_for("lakshmi")]
    trail = [a for a in eng.store.audit_log(r.incident_id) if a["kind"] == "vacancy_escalated"]
    assert trail, eng.store.audit_log(r.incident_id)
    data = trail[0].get("data") or trail[0]
    assert data["role"] == "store_manager" and data["to"] == "regional_manager" and data["people"] == ["suresh"]


def test_vacancy_escalation_is_off_by_default():
    eng = engine_for(_overlay("chain_a", org(vacancy=None)), clock=FrozenClock(at(2026, 10, 20)))
    r = eng.ingest(Event(type="inv.sales_stopped", source="pos",
                         payload={"store": "TVM03", "article": "A1", "book_qty": 4}))
    assert eng.store.open_review_for(r.incident_id).assignee_role == "store_manager"


def test_stop_list_is_validated():
    with pytest.raises(DirectoryError, match="unknown role 'ghost'"):
        Directory([Role(id="a")], stop_at=["ghost"])
    with pytest.raises(DirectoryError, match="no stop role at or above it"):
        Directory([Role(id="top"), Role(id="a", parent="top"), Role(id="b")], stop_at=["top"])
    with pytest.raises(DirectoryError, match="vacancy must be"):
        Directory([Role(id="a")], vacancy="sometimes")


# ---- configuration -----------------------------------------------------------------------------------

def test_people_document_round_trips_the_org_features():
    d = load_directory(ORG)
    again = parse_directory(yaml.safe_load(dump_yaml(directory_doc(d))))
    assert again.stop_at == d.stop_at and again.vacancy == "escalate"
    assert again.scopes["store"].rolls_up_to == "region"
    assert again.roles["category_buyer"].dotted == ["internal_audit"]
    assert [p.id for p in again.people_in("store_manager", {"store": "TVM01"}, at(2026, 10, 30))] == ["priya"]
    plain = directory_doc(Directory([Role(id="a")]))
    assert set(plain) == {"roles", "people", "assignments", "authority"} and plain["roles"] == {"a": {}}
