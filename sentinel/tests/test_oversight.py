# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""S7 (ADR-003 Layer D): oversight is held by a role that owns none of the agents it oversees, and its lever
(stop / demote / cap) is recorded. Proved on the R06 exemplar with internal audit as the oversight role."""
from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest
import yaml

from sentinel import EngineError, Overlay, Route, load_layers
from sentinel.config import check, directory_doc, dump_yaml
from sentinel.engine import AuthorizationError
from sentinel.rbac import DirectoryError, parse_directory
from sentinel.testing import FrozenClock, engine_for
from tests.test_role_slots import _actions

PACK = Path(__file__).parent / "packs" / "r06_stock_integrity"


def directory(oversight, extra_assign=()):
    data = yaml.safe_load((PACK / "people_chain_a_org.yaml").read_text(encoding="utf-8"))
    data["oversight"] = oversight
    data["assignments"] += list(extra_assign)
    data["authority"].append({"role_id": "ops_head", "action": "__set_route__"})
    return parse_directory(data)


def engine(oversight=({"role": "internal_audit"},), **kw):
    doc = load_layers([PACK / "template.yaml", PACK / "tenant_chain_a.yaml"])
    ov = Overlay(name="r06", fingerprint_rules=doc.fingerprints, patterns=doc.patterns, roles=doc.roles,
                 actions=_actions(), directory=directory(list(oversight), **kw), slots=doc.slots,
                 slot_bindings=doc.slot_bindings)
    return engine_for(ov, clock=FrozenClock(datetime(2026, 10, 20, 9, tzinfo=UTC)))


def test_an_independent_role_may_oversee():
    eng = engine()
    assert eng.directory.overseers("r06_phantom_stock") == ["internal_audit"]


@pytest.mark.parametrize("role,why", [("store_manager", "owns it"), ("regional_manager", "owns it"),
                                      ("ops_head", "above its owner")])
def test_an_owning_role_may_not_oversee(role, why):
    with pytest.raises(EngineError, match=why):
        engine(oversight=[{"role": role, "templates": ["r06_phantom_stock"]}])


def test_publishing_people_with_owning_oversight_is_refused_and_overlaps_are_warned():
    eng = engine()
    data = yaml.safe_load(dump_yaml(directory_doc(eng.directory)))
    data["oversight"] = [{"role": "slp_officer", "templates": ["r06_unrecorded_loss"]}]
    _, probs = check("people", dump_yaml(data), eng._config_context())
    assert any(p.severity == "error" and "slp_officer" in p.message and "owns it" in p.message for p in probs)
    data["oversight"] = [{"role": "internal_audit"}]
    data["assignments"].append({"person_id": "ganesh", "role_id": "store_manager", "scope": {"store": "TVM09"}})
    _, probs = check("people", dump_yaml(data), eng._config_context())
    assert not [p for p in probs if p.severity == "error"]
    assert any(p.severity == "warning" and "ganesh holds oversight" in p.message for p in probs)


def test_oversight_stops_and_demotes_and_is_recorded():
    eng = engine()
    eng.set_route("r06_phantom_stock", Route.AUTO, actor="devi")
    eng.oversee("r06_phantom_stock", "demote", actor="ganesh", reason="reversals rising at TVM01")
    assert eng.store.get_pattern_state("r06_phantom_stock").route is Route.LLM
    eng.oversee("r06_phantom_stock", "stop", actor="ganesh", reason="count tasks look wrong")
    assert eng.store.get_pattern_state("r06_phantom_stock").route is Route.HITL
    acts = [a for a in eng.store.recent_audit(50, kinds=["oversight_action"])]
    assert [(a.get("data") or a)["action"] for a in acts][:2] in (["stop", "demote"], ["demote", "stop"])
    assert all((a.get("data") or a)["actor"] == "ganesh" and (a.get("data") or a)["reason"] for a in acts)


def test_cap_only_lowers():
    eng = engine()
    eng.set_route("r06_phantom_stock", Route.LLM, actor="devi")
    eng.oversee("r06_phantom_stock", "cap", actor="ganesh", reason="cap while we review", route=Route.AUTO)
    assert eng.store.get_pattern_state("r06_phantom_stock").route is Route.LLM          # never raises
    eng.oversee("r06_phantom_stock", "cap", actor="ganesh", reason="cap", route=Route.HITL)
    assert eng.store.get_pattern_state("r06_phantom_stock").route is Route.HITL


def test_only_the_oversight_role_may_use_the_lever():
    eng = engine()
    with pytest.raises(AuthorizationError, match="no oversight role"):
        eng.oversee("r06_phantom_stock", "stop", actor="meena", reason="I own it")            # the owner
    with pytest.raises(EngineError, match="needs a reason"):
        eng.oversee("r06_phantom_stock", "stop", actor="ganesh", reason=" ")
    with pytest.raises(EngineError, match="must be one of"):
        eng.oversee("r06_phantom_stock", "delete", actor="ganesh", reason="x")
    scoped = engine(oversight=[{"role": "internal_audit", "templates": ["r06_daily_triangle_gap"]}])
    with pytest.raises(EngineError, match="no oversight role is configured"):
        scoped.oversee("r06_phantom_stock", "stop", actor="ganesh", reason="x")


def test_oversight_config_is_validated_and_round_trips():
    with pytest.raises(DirectoryError, match="oversight: unknown role"):
        directory([{"role": "ghost"}])
    d = directory([{"role": "internal_audit", "templates": ["r06_phantom_stock"]}])
    again = parse_directory(yaml.safe_load(dump_yaml(directory_doc(d))))
    assert [o.model_dump() for o in again.oversight] == [o.model_dump() for o in d.oversight]


def test_cap_without_a_route_is_refused_and_not_audited():
    eng = engine()
    with pytest.raises(EngineError, match="cap needs the route"):
        eng.oversee("r06_phantom_stock", "cap", actor="ganesh", reason="x")
    assert eng.store.recent_audit(20, kinds=["oversight_action"]) == []
