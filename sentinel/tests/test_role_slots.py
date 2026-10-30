# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""S2 (ADR-003): templates name role slots; each tenant binds them to its own roles.

Proved on the R06 stock-integrity exemplar (tests/packs/r06_stock_integrity): one template, two store chains
with different orgs, no retail words in sentinel/."""
from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from sentinel import ActionRegistry, ActionResult, LayerError, Overlay, load_layers
from sentinel import templates
from sentinel.config import Context, apply_layer, check, doc_checksum, dump_yaml, registry_doc, registry_layer
from sentinel.models import Event
from sentinel.overlay import SlotError, parse_registry, resolve_slots
from sentinel.rbac import load_directory
from sentinel.testing import engine_for, run_golden

PACK = Path(__file__).parent / "packs" / "r06_stock_integrity"
TEMPLATE = PACK / "template.yaml"


def _actions() -> ActionRegistry:
    acts = ActionRegistry()

    @acts.action("task.shelf_check", reversible=False, params={"store": "str", "article": "str", "kind?": "str"},
                 description="ask the store to check the shelf for an article")
    def shelf(ctx, p):
        return ActionResult(ok=True, detail="shelf check task raised")

    @acts.action("task.count", reversible=False, params={"store": "str", "article": "str"},
                 description="ask the store to count an article")
    def count(ctx, p):
        return ActionResult(ok=True, detail="count task raised")

    return acts


def _overlay(tenant: str, directory=None) -> Overlay:
    doc = load_layers([TEMPLATE, PACK / f"tenant_{tenant}.yaml"])
    return Overlay(name=f"r06-{tenant}", fingerprint_rules=doc.fingerprints, patterns=doc.patterns, roles=doc.roles,
                   actions=_actions(), directory=directory, slots=doc.slots, slot_bindings=doc.slot_bindings)


# ---- the template names slots only ------------------------------------------------------------------

def test_template_names_slots_never_roles():
    raw = yaml.safe_load(TEMPLATE.read_text(encoding="utf-8"))
    assert "roles" not in raw and "slot_bindings" not in raw
    for p in raw["patterns"]:
        assert "owner_role" not in p and "escalation_role" not in p, p["id"]
        assert p["owner_slot"] in raw["slots"]


def test_no_retail_words_in_the_framework():
    words = ("shelf_check", "phantom", "fefo", "slp_officer", "r06_", "triangle_gap")   # the exemplar's own terms
    root = Path(__file__).resolve().parent.parent / "sentinel"
    for f in root.rglob("*.py"):
        text = f.read_text(encoding="utf-8").lower()
        for w in words:
            assert w not in text, f"{f.name} mentions {w!r}"


# ---- binding per tenant ------------------------------------------------------------------------------

def test_two_tenants_bind_the_same_template_to_their_own_orgs():
    a = {p.id: p for p in load_layers([TEMPLATE, PACK / "tenant_chain_a.yaml"]).patterns}
    b = {p.id: p for p in load_layers([TEMPLATE, PACK / "tenant_chain_b.yaml"]).patterns}
    assert a["r06_phantom_stock"].owner_role == "store_manager"
    assert a["r06_phantom_stock"].escalation_role == "regional_manager"
    assert a["r06_unrecorded_loss"].owner_role == "slp_officer"
    assert b["r06_phantom_stock"].owner_role == "branch_head"
    assert b["r06_unrecorded_loss"].owner_role == "branch_head"
    assert b["r06_phantom_stock"].escalation_role == "area_manager"
    assert a["r06_phantom_stock"].owner_slot == b["r06_phantom_stock"].owner_slot == "accountable"
    # who owns a case is not what the case means: rebinding never resets earned trust
    for pid in a:
        assert a[pid].definition_hash() == b[pid].definition_hash(), pid


def test_publish_is_refused_while_a_slot_is_unbound():
    with pytest.raises(LayerError, match="not bound in slot_bindings"):
        load_layers([TEMPLATE])
    partial = ("layer", {"roles": {"store_manager": "x", "rm": "y"},
                         "slot_bindings": {"accountable": "store_manager", "escalation": "rm"}})
    with pytest.raises(LayerError, match="shrink_owner"):
        load_layers([TEMPLATE, partial])


def test_bindings_are_checked():
    tpl = yaml.safe_load(TEMPLATE.read_text(encoding="utf-8"))
    tpl.pop("layer")
    roles = {"sm": "x", "lp": "y", "rm": "z"}
    good = {"accountable": "sm", "shrink_owner": "lp", "escalation": "rm"}
    with pytest.raises(LayerError, match="unknown role 'nobody'"):
        load_layers([TEMPLATE, ("t", {"roles": roles, "slot_bindings": {**good, "accountable": "nobody"}})])
    with pytest.raises(LayerError, match="not a declared slot"):
        load_layers([TEMPLATE, ("t", {"roles": roles, "slot_bindings": {**good, "auditor": "sm"}})])
    doc = parse_registry({**tpl, "roles": roles, "slot_bindings": good})
    assert {p.owner_role for p in doc.patterns} == {"sm", "lp"}
    undeclared = {**tpl, "roles": roles, "slot_bindings": good,
                  "patterns": [{**tpl["patterns"][0], "owner_slot": "auditor"}]}
    with pytest.raises(SlotError, match="'auditor' is not a declared slot"):
        parse_registry(undeclared)
    both = {**tpl, "roles": roles, "slot_bindings": good,
            "patterns": [{**tpl["patterns"][0], "owner_role": "rm"}]}
    with pytest.raises(SlotError, match="a slot or a role, not both"):
        parse_registry(both)
    for named in ("sm", "operator"):     # even the bound role or the default: a stale line would block rebinding
        same = {**tpl, "roles": roles, "slot_bindings": good,
                "patterns": [{**tpl["patterns"][0], "owner_role": named}]}
        with pytest.raises(SlotError, match="a slot or a role, not both"):
            parse_registry(same)


def test_override_cannot_smuggle_a_role_onto_a_slotted_pattern():
    with pytest.raises(LayerError, match="a slot or a role, not both"):
        load_layers([TEMPLATE, PACK / "tenant_chain_a.yaml",
                     ("site", {"overrides": [{"id": "r06_phantom_stock", "set": {"owner_role": "ops_head"}}]})])
    # moving a pattern back to a named role is explicit: clear the slot in the same override
    doc = load_layers([TEMPLATE, PACK / "tenant_chain_a.yaml",
                       ("site", {"overrides": [{"id": "r06_phantom_stock",
                                                "set": {"owner_slot": None, "owner_role": "ops_head"}}]})])
    assert {p.id: p for p in doc.patterns}["r06_phantom_stock"].owner_role == "ops_head"


# ---- compatible: role ids keep working ---------------------------------------------------------------

@pytest.mark.parametrize("name", templates.names())
def test_registries_without_slots_are_unchanged(name):
    reg = templates.load(name)["registry"]
    plain = parse_registry(reg)
    assert not plain.slots and not plain.slot_bindings
    with_unused = parse_registry({**reg, "slots": {"accountable": "unused"}, "slot_bindings": {}})
    for p, q in zip(plain.patterns, with_unused.patterns, strict=True):
        assert (p.owner_role, p.escalation_role, p.definition_hash()) == \
               (q.owner_role, q.escalation_role, q.definition_hash())
    doc = registry_doc(plain.roles, plain.fingerprints, plain.patterns, plain.defaults, plain.capabilities)
    assert "slots" not in doc and "slot_bindings" not in doc


def test_resolve_slots_returns_unslotted_patterns_untouched():
    pats = parse_registry(templates.load("manufacturing")["registry"]).patterns
    assert all(a is b for a, b in zip(pats, resolve_slots(pats, {}, {}, {}), strict=True))


# ---- configuration: round trip, console rebinding, publish check -------------------------------------

def test_registry_document_round_trips_and_carries_bindings():
    doc = load_layers([TEMPLATE, PACK / "tenant_chain_a.yaml"])
    d = registry_doc(doc.roles, doc.fingerprints, doc.patterns, doc.defaults, doc.capabilities,
                     doc.slots, doc.slot_bindings)
    assert d["slot_bindings"] == {"accountable": "store_manager", "shrink_owner": "slp_officer",
                                  "escalation": "regional_manager"}
    assert all("owner_role" not in p for p in d["patterns"])          # the slot is written, never a stale role
    again = parse_registry(yaml.safe_load(dump_yaml(d)))
    assert [(p.id, p.owner_role, p.escalation_role) for p in again.patterns] == \
           [(p.id, p.owner_role, p.escalation_role) for p in doc.patterns]
    # without the bindings passed in, they are rebuilt from the resolved patterns
    d2 = registry_doc(doc.roles, doc.fingerprints, doc.patterns, doc.defaults, doc.capabilities)
    assert d2["slot_bindings"] == d["slot_bindings"]


def test_a_console_rebinding_is_a_layer_kept_across_pack_upgrades():
    doc = load_layers([TEMPLATE, PACK / "tenant_chain_a.yaml"])
    base = registry_doc(doc.roles, doc.fingerprints, doc.patterns, doc.defaults, doc.capabilities,
                        doc.slots, doc.slot_bindings)
    new = yaml.safe_load(dump_yaml(base))
    new["slot_bindings"]["shrink_owner"] = "regional_manager"        # tenant has no LP team this quarter
    layer = registry_layer(base, new)
    assert layer["slot_bindings"] == {"shrink_owner": "regional_manager"}
    assert "overrides" not in layer                                  # no pattern changed
    upgraded = yaml.safe_load(dump_yaml(base))                       # the pack ships a new pattern
    upgraded["patterns"].append({**upgraded["patterns"][0], "id": "r06_new_signal",
                                 "event_types": ["inv.new_signal"]})
    merged = {p.id: p for p in apply_layer(upgraded, layer).patterns}
    assert merged["r06_unrecorded_loss"].owner_role == "regional_manager"
    assert merged["r06_new_signal"].owner_role == "store_manager"
    assert doc_checksum(base) != doc_checksum(new)


def test_config_check_refuses_publishing_an_unbound_slot():
    eng = engine_for(_overlay("chain_a", load_directory(PACK / "people_chain_a.yaml")))
    text = eng.config_text("registry") if hasattr(eng, "config_text") else None
    if text is None:
        doc = load_layers([TEMPLATE, PACK / "tenant_chain_a.yaml"])
        text = dump_yaml(registry_doc(doc.roles, doc.fingerprints, doc.patterns, doc.defaults, doc.capabilities,
                                      doc.slots, doc.slot_bindings))
    data = yaml.safe_load(text)
    ctx: Context = eng._config_context()
    _, ok = check("registry", dump_yaml(data), ctx)
    assert not [p for p in ok if p.severity == "error"], ok
    del data["slot_bindings"]["shrink_owner"]
    _, bad = check("registry", dump_yaml(data), ctx)
    assert any(p.severity == "error" and "shrink_owner" in p.message for p in bad)
    data["slot_bindings"]["shrink_owner"] = "store_manager"           # bound, but people config must know it
    data["slot_bindings"]["escalation"] = "ghost_role"
    data["roles"]["ghost_role"] = "declared in the registry only"
    _, ghost = check("registry", dump_yaml(data), ctx)
    assert any(p.severity == "error" and "ghost_role" in p.message for p in ghost)


# ---- R06 running: golden cases and routing to the bound role's holders in scope -----------------------

def test_r06_golden_cases():
    eng = engine_for(_overlay("chain_a", load_directory(PACK / "people_chain_a.yaml")))
    assert run_golden(eng, PACK / "golden.yaml") == []


def test_r06_cases_route_to_the_people_holding_the_bound_role_in_scope():
    eng = engine_for(_overlay("chain_a", load_directory(PACK / "people_chain_a.yaml")))
    r = eng.ingest(Event(type="inv.sales_stopped", source="pos",
                         payload={"store": "TVM01", "article": "A100", "book_qty": 14}))
    review = eng.store.open_review_for(r.incident_id)
    assert review is not None and review.assignee_role == "store_manager"
    assert [t.incident_id for t in eng.reviews_for("meena")] == [r.incident_id]   # TVM01's manager
    assert eng.reviews_for("arun") == []                                          # TVM02's manager
    loss = eng.ingest(Event(type="inv.depletion_without_sales", source="pos",
                            payload={"store": "TVM02", "article": "A200", "units": 9}))
    assert eng.store.open_review_for(loss.incident_id).assignee_role == "slp_officer"
    assert loss.incident_id in [t.incident_id for t in eng.reviews_for("kavya")]
    inc = eng.store.get_incident(r.incident_id)
    assert inc.route.value == "hitl"                                 # OBSERVE: a person approves everything


def test_r06_explain_names_the_slot():
    eng = engine_for(_overlay("chain_b"))
    t = eng.trace(Event(type="inv.sales_stopped", source="pos",
                        payload={"store": "B7", "article": "A1", "book_qty": 3}))
    assert t["pattern"]["owner_role"] == "branch_head"
    assert t["pattern"]["owner_slot"] == "accountable"
