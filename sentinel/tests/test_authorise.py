# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""S4 (ADR-003 C2): the authorise() contract domain cores import, segregation of duties, the agent ceiling.

Proved on the R06 exemplar's chain A org, with a stock-adjust Limits row added."""
from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest
import yaml

from sentinel.config import directory_doc, dump_yaml
from sentinel.org import APPROVE, Agent, Person, SodRule, authorise
from sentinel.rbac import DirectoryError, parse_directory

ORG = Path(__file__).parent / "packs" / "r06_stock_integrity" / "people_chain_a_org.yaml"
NOW = datetime(2026, 10, 20, 9, 0, tzinfo=UTC)
TVM01, TVM02, TVM03 = {"store": "TVM01"}, {"store": "TVM02"}, {"store": "TVM03"}


def org(**changes):
    data = yaml.safe_load(ORG.read_text(encoding="utf-8"))
    data["authority"] += [
        {"role_id": "store_manager", "action": "stock.adjust", "max_amount": 5000},
        {"role_id": "regional_manager", "action": "stock.adjust", "max_amount": 50000},
        {"role_id": "regional_manager", "action": APPROVE},
        {"role_id": "ops_head", "action": "*"},
    ]
    data["sod"] = [{"first": "task.count", "second": "stock.adjust",
                    "description": "who counts does not post the adjustment"}]
    data.update(changes)
    d = parse_directory(data)
    d.clock = lambda: NOW
    return d


# ---- people ------------------------------------------------------------------------------------------

def test_a_person_acts_only_in_scope_and_in_their_window():
    d = org()
    assert authorise(d, "meena", "task.count", "A1", TVM01)
    no = authorise(d, "arun", "task.count", "A1", TVM01)
    assert not no and "no role in this scope" in no.reason
    assert not authorise(d, "priya", "task.count", "A1", TVM01)                       # cover starts 25 Oct
    assert authorise(d, "priya", "task.count", "A1", TVM01, at=datetime(2026, 10, 30, tzinfo=UTC))


def test_amount_limits_and_where_to_escalate():
    d = org()
    assert authorise(d, "meena", "stock.adjust", "A1", TVM01, 3000)
    over = authorise(d, "meena", "stock.adjust", "A1", TVM01, 8000)
    assert not over and over.escalate_to == "regional_manager"
    assert authorise(d, "suresh", "stock.adjust", "A1", TVM01, 8000)                   # region covers the store
    assert not authorise(d, "lakshmi", "stock.adjust", "A1", TVM01, 8000)              # other region


def test_a_dotted_line_cannot_authorise():
    d = org()
    assert not authorise(d, "ganesh", "task.count", "A1", {"category": "rice", **TVM01})


# ---- agents: never above their human -----------------------------------------------------------------

def test_an_agent_never_exceeds_the_person_holding_its_bound_role_in_scope():
    d = org()
    agent = Agent("r06@TVM01", bound_role="store_manager", on_behalf_of="r06_stock_integrity")
    ok = authorise(d, agent, "task.count", "A1", TVM01)
    assert ok and ok.decided_by_role == "store_manager"
    assert authorise(d, agent, "stock.adjust", "A1", TVM01, 3000)
    over = authorise(d, agent, "stock.adjust", "A1", TVM01, 8000)
    assert not over and over.escalate_to == "regional_manager"


def test_a_vacant_scope_uses_the_nearest_held_role_and_never_the_top():
    d = org()
    agent = Agent("r06@TVM03", bound_role="store_manager")
    dec = authorise(d, agent, "stock.adjust", "A1", TVM03, 8000)
    assert dec and dec.decided_by_role == "regional_manager"                             # suresh holds the region
    nobody = authorise(d, Agent("r06@NEW99", bound_role="store_manager"), "task.count", "A1", {"store": "NEW99"})
    assert not nobody and "has no human" in nobody.reason                                # not ops_head's "*"


@pytest.mark.parametrize("role", ["store_manager", "regional_manager", "ops_head"])
def test_approve_is_never_granted_to_an_agent(role):
    d = org()
    agent = Agent("x", bound_role=role)
    assert not authorise(d, agent, APPROVE, "PO1", TVM01)
    assert not authorise(d, agent, "stock.adjust", "A1", TVM01, 10, proposed_by=["meena"])


# ---- segregation of duties and self-approval ---------------------------------------------------------

def test_nobody_approves_their_own_proposal():
    d = org()
    assert not authorise(d, "suresh", APPROVE, "ADJ1", TVM01, proposed_by=["suresh"])
    assert authorise(d, "suresh", APPROVE, "ADJ1", TVM01, proposed_by=["meena"])
    assert not authorise(d, "meena", APPROVE, "ADJ1", TVM01, proposed_by=["arun"])      # no approve right


def test_sod_pair_on_the_same_object():
    d = org()
    counted = {"meena": ["task.count"], "kavya": ["task.count"]}
    sod = authorise(d, "meena", "stock.adjust", "A1", TVM01, 100, done_on_object=counted)
    assert not sod and "who counts does not post" in sod.reason and "sod:task.count/stock.adjust" in sod.checks
    assert authorise(d, "meena", "stock.adjust", "A1", TVM01, 100, done_on_object={"kavya": ["task.count"]})
    agent = Agent("r06@TVM01", bound_role="store_manager")
    assert not authorise(d, agent, "stock.adjust", "A1", TVM01, 100, done_on_object={"r06@TVM01": ["task.count"]})
    assert authorise(d, "meena", "stock.adjust", "A1", TVM01, 100, done_on_object=counted, sod=[])   # caller's rules


def test_sod_rules_in_the_people_configuration():
    d = org()
    assert d.sod == [SodRule(first="task.count", second="stock.adjust",
                             description="who counts does not post the adjustment")]
    again = parse_directory(yaml.safe_load(dump_yaml(directory_doc(d))))
    assert again.sod == d.sod
    with pytest.raises(DirectoryError, match="sod: a list"):
        org(sod={"first": "a"})
    assert parse_directory({"roles": {"a": None}}).sod == []


def test_an_unknown_or_inactive_person_is_refused():
    d = org()
    assert not authorise(d, Person("ghost"), "task.count", "A1", TVM01)
    assert not authorise(d, Agent("a", bound_role="no_such_role"), "task.count", "A1", TVM01)


def test_limits_bound_the_size_of_an_amount_and_sod_pairs_differ():
    d = org()
    assert not authorise(d, Agent("a", bound_role="store_manager"), "stock.adjust", "A1", TVM01, -8000)
    assert authorise(d, "meena", "stock.adjust", "A1", TVM01, -3000)
    with pytest.raises(ValueError, match="paired with itself"):
        SodRule(first="x", second="x")
