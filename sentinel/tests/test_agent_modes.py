# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""S5 (ADR-003 C1): agent identities, modes OFF / OBSERVE / PROPOSE / ACT per template x scope, grants,
and the invariant that APPROVE is never grantable to an agent. Proved on the R06 exemplar."""
from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest
import yaml

from sentinel import IncidentState as S
from sentinel import Overlay, load_layers
from sentinel.config import directory_doc, dump_yaml
from sentinel.models import Event
from sentinel.rbac import AgentPolicy, parse_directory
from sentinel.testing import FrozenClock, engine_for
from tests.test_role_slots import _actions

PACK = Path(__file__).parent / "packs" / "r06_stock_integrity"
NOW = datetime(2026, 10, 20, 9, 0, tzinfo=UTC)
LIVE = ("live", {"overrides": [{"id": "r06_phantom_stock", "set": {"shadow": False, "route": "auto"}}]})
AGENTS = [
    {"template": "*", "mode": "OBSERVE"},                                                      # default: observe
    {"template": "r06_phantom_stock", "scope": {"store": "TVM02"}, "mode": "ACT",
     "grants": {"task.shelf_check": "EDIT", "task.count": "VIEW"}},
    {"template": "r06_phantom_stock", "scope": {"store": "TVM03"}, "mode": "PROPOSE"},
    {"template": "r06_phantom_stock", "scope": {"store": "TVM04"}, "mode": "ACT", "grants": {"task.count": "EDIT"}},
    {"template": "r06_phantom_stock", "scope": {"store": "TVM05"}, "mode": "ACT"},                # no grants list
    {"template": "r06_unrecorded_loss", "scope": {"store": "TVM01"}, "mode": "OFF"},
]


def directory(agents=AGENTS):
    data = yaml.safe_load((PACK / "people_chain_a_org.yaml").read_text(encoding="utf-8"))
    data["agents"] = agents
    data.pop("vacancy")
    return parse_directory(data)


def engine(agents=AGENTS):
    doc = load_layers([PACK / "template.yaml", PACK / "tenant_chain_a.yaml", LIVE])
    ov = Overlay(name="r06", fingerprint_rules=doc.fingerprints, patterns=doc.patterns, roles=doc.roles,
                 actions=_actions(), directory=directory(agents), slots=doc.slots, slot_bindings=doc.slot_bindings)
    return engine_for(ov, clock=FrozenClock(NOW))


def stopped(store):
    return Event(type="inv.sales_stopped", source="pos", payload={"store": store, "article": "A1", "book_qty": 5})


def test_act_with_an_edit_grant_runs_unattended():
    eng = engine()
    r = eng.ingest(stopped("TVM02"))
    inc = eng.store.get_incident(r.incident_id)
    assert inc.state is S.DISPOSITIONED, [a["kind"] for a in eng.store.audit_log(r.incident_id)]
    assert inc.provenance.agent == "r06_phantom_stock@store=TVM02" and inc.provenance.agent_mode == "ACT"


def test_observe_is_shadow_and_propose_needs_a_person():
    eng = engine()
    obs = eng.store.get_incident(eng.ingest(stopped("TVM01")).incident_id)       # "*" default: OBSERVE
    assert obs.shadow and obs.state is S.AWAITING_HUMAN and obs.provenance.agent_mode == "OBSERVE"
    pro = eng.store.get_incident(eng.ingest(stopped("TVM03")).incident_id)
    assert not pro.shadow and pro.route.value == "hitl" and pro.state is S.AWAITING_HUMAN
    assert pro.proposal is not None and [s.action for s in pro.proposal.steps] == ["task.shelf_check"]


def test_act_without_the_edit_grant_goes_to_a_person_and_is_audited():
    eng = engine()
    r = eng.ingest(stopped("TVM04"))
    assert eng.store.get_incident(r.incident_id).state is S.AWAITING_HUMAN
    grant = [a for a in eng.store.audit_log(r.incident_id) if a["kind"] == "agent_grant"]
    assert grant and (grant[0].get("data") or grant[0])["missing_edit"] == ["task.shelf_check"]
    free = eng.store.get_incident(eng.ingest(stopped("TVM05")).incident_id)      # ACT, no grants list: limits only
    assert free.state is S.DISPOSITIONED


def test_off_sends_the_template_s_events_to_people_as_unmatched():
    eng = engine()
    loss = Event(type="inv.depletion_without_sales", source="pos", payload={"store": "TVM01", "article": "A",
                                                                             "units": 3})
    inc = eng.store.get_incident(eng.ingest(loss).incident_id)
    assert inc.pattern_id == eng.registry.fallback.id
    other = Event(type="inv.depletion_without_sales", source="pos", payload={"store": "TVM02", "article": "A",
                                                                              "units": 3})
    assert eng.store.get_incident(eng.ingest(other).incident_id).pattern_id == "r06_unrecorded_loss"


def test_trace_shows_the_agent_and_why():
    eng = engine()
    t = eng.trace(stopped("TVM03"))
    assert t["agent"] == {"id": "r06_phantom_stock@store=TVM03", "mode": "PROPOSE", "grants": {}}
    assert "PROPOSE" in t["route"]["why"]
    t2 = eng.trace(Event(type="inv.depletion_without_sales", source="pos",
                         payload={"store": "TVM01", "article": "A", "units": 3}))
    assert t2["pattern"]["id"] == eng.registry.fallback.id and any("OFF" in s for s in t2["steps"])
    assert eng.trace(stopped("TVM04"))["outcome"] == "person"
    assert eng.trace(stopped("TVM02"))["outcome"] != "person"


def test_most_specific_policy_wins():
    d = directory()
    assert d.agent_policy("r06_phantom_stock", None, {"store": "TVM02"}).mode == "ACT"
    assert d.agent_policy("r06_phantom_stock", None, {"store": "TVM09"}).mode == "OBSERVE"
    assert d.agent_policy("r06_phantom_stock", "stock", {"store": "TVM02"}).mode == "ACT"
    cap = directory([{"template": "stock", "mode": "PROPOSE"}, {"template": "*", "mode": "ACT"}])
    assert cap.agent_policy("r06_x", "stock", {}).mode == "PROPOSE"
    assert cap.agent_policy("r06_x", None, {}).mode == "ACT"
    assert directory([]).agent_policy("r06_phantom_stock", None, {}) is None


def test_region_scoped_and_time_bound_policies():
    d = directory([{"template": "*", "scope": {"region": "south"}, "mode": "ACT",
                    "valid_from": "2026-11-01"}, {"template": "*", "mode": "OBSERVE"}])
    assert d.agent_policy("p", None, {"store": "TVM01"}, at=NOW).mode == "OBSERVE"
    assert d.agent_policy("p", None, {"store": "TVM01"}, at=datetime(2026, 11, 2, tzinfo=UTC)).mode == "ACT"
    assert d.agent_policy("p", None, {"store": "COK01"}, at=datetime(2026, 11, 2, tzinfo=UTC)).mode == "OBSERVE"


@pytest.mark.parametrize("grants", [{"task.count": "APPROVE"}, {"__approve__": "EDIT"}, {"__approve__": "VIEW"},
                                    {"x": "approve"}])
def test_invariant_approve_is_never_grantable_to_an_agent(grants):
    with pytest.raises(ValueError, match="never grantable"):
        AgentPolicy(template="*", mode="ACT", grants=grants)


def test_policies_are_validated_and_round_trip():
    with pytest.raises(ValueError, match="agent mode"):
        AgentPolicy(mode="SOMETIMES")
    with pytest.raises(ValueError, match="VIEW or EDIT"):
        AgentPolicy(mode="ACT", grants={"x": "DELETE"})
    assert AgentPolicy(mode="act").mode == "ACT"
    d = directory()
    again = parse_directory(yaml.safe_load(dump_yaml(directory_doc(d))))
    assert [a.model_dump() for a in again.agents] == [a.model_dump() for a in d.agents]


def test_no_policies_means_no_change():
    eng = engine(agents=[])
    inc = eng.store.get_incident(eng.ingest(stopped("TVM01")).incident_id)
    assert inc.provenance.agent is None and inc.state is S.DISPOSITIONED              # route auto, not shadow


@pytest.mark.parametrize("order", [1, -1])
def test_precedence_never_depends_on_row_order(order):
    rows = [{"template": "r06_phantom_stock", "scope": {"region": "south"}, "mode": "ACT"},
            {"template": "r06_phantom_stock", "scope": {"store": "TVM01"}, "mode": "PROPOSE"}][::order]
    assert directory(rows).agent_policy("r06_phantom_stock", None, {"store": "TVM01"}).mode == "PROPOSE"
    tie = [{"template": "*", "scope": {"store": "TVM01"}, "mode": "ACT"},
           {"template": "*", "scope": {"store": "TVM01"}, "mode": "OBSERVE"}][::order]
    assert directory(tie).agent_policy("p", None, {"store": "TVM01"}).mode == "OBSERVE"   # least autonomous


def test_identity_names_the_row_that_decided():
    eng = engine([{"template": "*", "scope": {"region": "south"}, "mode": "OBSERVE"}])
    t = eng.trace(stopped("TVM01"))
    assert t["agent"]["id"] == "r06_phantom_stock@region=south"
