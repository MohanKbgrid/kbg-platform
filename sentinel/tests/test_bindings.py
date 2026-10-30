# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""S8 (ADR-005): generic capabilities in structural terms, domain bindings, and the binding check that refuses
publish (unmapped structure, missing never-automate rule, a never-automate action that could run unattended)."""
from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from sentinel import EngineError, Overlay, Route, load_layers
from sentinel.bindings import (CATALOGUE, Bind, DomainBinding, check_binding, enforce_never_automate,
                               load_binding, relevant)
from sentinel.config import check, dump_yaml, registry_doc
from sentinel.testing import engine_for
from tests.test_role_slots import _actions

PACK = Path(__file__).parent / "packs" / "r06_stock_integrity"


def r06():
    return load_layers([PACK / "template.yaml", PACK / "tenant_chain_a.yaml"])


def test_the_r06_binding_is_clean():
    doc = r06()
    b = load_binding(PACK / "binding.yaml")
    assert check_binding(b, doc.patterns, doc.slots) == []
    assert relevant(b) == {"exception_watch": {"title": CATALOGUE["exception_watch"].title,
                                               "words": {"subject": "article", "scope": "store", "batch": "batch"}},
                           "reconciliation": {"title": CATALOGUE["reconciliation"].title,
                                              "words": {"side_a": "sales_at_retail", "side_b": "tender_received",
                                                        "period": "business_date", "scope": "store"}}}


def test_never_automate_must_be_stated(tmp_path):
    raw = yaml.safe_load((PACK / "binding.yaml").read_text(encoding="utf-8"))
    del raw["never_automate"]
    f = tmp_path / "b.yaml"
    f.write_text(yaml.safe_dump(raw))
    with pytest.raises(ValueError, match="never_automate is required"):
        load_binding(f)
    with pytest.raises(ValueError):
        DomainBinding(domain="x")                                       # not even in code


def test_binding_problems_are_reported():
    doc = r06()
    b = DomainBinding(domain="retail", never_automate=[], slots=["accountable", "auditor"], binds=[
        Bind(capability="exception_watch", map={"subject": "article", "colour": "red"}, patterns=["r06_*"]),
        Bind(capability="demand_planning", map={}),
        Bind(capability="approval", map={"request": "po", "amount": "value", "approver_slot": "x"},
             patterns=["po_*"])])
    probs = check_binding(b, doc.patterns, doc.slots)
    text = "\n".join(probs)
    assert "structures ['scope'] are not mapped" in text
    assert "['colour'] are not structures" in text
    assert "unknown capability 'demand_planning'" in text                 # not extracted yet: not in the catalogue
    assert "'po_*' matches nothing" in text
    assert "slot 'auditor' is not declared" in text


def test_a_never_automate_action_can_never_run_unattended():
    doc = r06()
    b = DomainBinding(domain="retail", never_automate=["task.count"], binds=[])
    probs = check_binding(b, doc.patterns, doc.slots)
    assert any("r06_unrecorded_loss" in p and "task.count" in p for p in probs)
    held = {p.id: p for p in enforce_never_automate(b, doc.patterns)}
    assert held["r06_unrecorded_loss"].max_route is Route.HITL
    assert held["r06_phantom_stock"].max_route is Route.HITL               # allows task.count too
    assert held["r06_fefo_breach"].max_route is Route.AUTO                 # shelf task only: untouched


def test_engine_refuses_a_binding_violation_and_holds_patterns_otherwise():
    doc = r06()
    bad = DomainBinding(domain="retail", never_automate=["task.count"], binds=[])

    def overlay(binding):
        return Overlay(name="r06", fingerprint_rules=doc.fingerprints, patterns=doc.patterns, roles=doc.roles,
                       actions=_actions(), slots=doc.slots, slot_bindings=doc.slot_bindings, binding=binding)
    with pytest.raises(EngineError, match="domain binding"):
        engine_for(overlay(bad))
    eng = engine_for(overlay(bad), raise_on_invalid=False)
    assert eng.registry.get("r06_unrecorded_loss").max_route is Route.HITL
    ok = engine_for(overlay(load_binding(PACK / "binding.yaml")))
    assert ok.registry.get("r06_fefo_breach").max_route is Route.AUTO


def test_publishing_a_registry_that_breaks_the_binding_is_refused():
    doc = r06()
    eng = engine_for(Overlay(name="r06", fingerprint_rules=doc.fingerprints, patterns=doc.patterns, roles=doc.roles,
                             actions=_actions(), slots=doc.slots, slot_bindings=doc.slot_bindings,
                             binding=DomainBinding(domain="retail", never_automate=["stock.write_off"], binds=[])))
    data = registry_doc(doc.roles, doc.fingerprints, doc.patterns, doc.defaults, doc.capabilities, doc.slots,
                        doc.slot_bindings)
    _, probs = check("registry", dump_yaml(data), eng._config_context())
    assert not [p for p in probs if p.severity == "error"]
    data["patterns"][0]["allowed_actions"].append("stock.write_off")
    _, probs = check("registry", dump_yaml(data), eng._config_context())
    assert any(p.severity == "error" and "never automates" in p.message for p in probs)


def test_the_catalogue_is_structural_and_extracted_not_pre_designed():
    domain_words = {"article", "store", "sku", "ward", "patient", "depot", "route", "bed", "invoice", "po"}
    for cid, spec in CATALOGUE.items():
        assert len(spec.proven_in) >= 2, cid                              # worked in two domains before extraction
        assert not domain_words & {*spec.structures, *spec.optional}, cid
    assert "demand_planning" not in CATALOGUE
