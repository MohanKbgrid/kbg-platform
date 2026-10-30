# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""Independent black-box journeys for role slots (v0.15.0, ADR-003), written from CHANGELOG, EXTENDING
("Role slots", "Roles: one place"), OVERLAY_CONTRACT and ADR-003 only.

Domain: a hospital deterioration desk. A clinical pack names the jobs (slots ``accountable`` and
``escalation``); each hospital binds them to its own roles in a tenant layer. People hold roles per ward.

Tests that exposed a product defect carry a ``# FIXED v0.16.1 (was DEFECT):`` comment; all pass now.
"""
from __future__ import annotations

import copy
from typing import Any

import pytest
import yaml

from sentinel import (Engine, Event, FingerprintRule, LayerError, MemoryEdge, Overlay, Pattern, Route,
                      SQLiteStore, SlotError, load_layers, load_registry)
from sentinel.config import ConfigError
from sentinel.overlay import parse_registry
from sentinel.rbac import parse_directory
from sentinel.testing import FrozenClock, conformance

REFUSED = (LayerError, SlotError, ValueError)

# ============================================================================== the pack and the tenants
PACK = {
    "layer": "clinical_pack",
    "roles": {"staff_nurse": "Staff nurse", "charge_nurse": "Charge nurse", "registrar": "Registrar",
              "consultant": "Consultant", "matron": "Matron", "supervisor": "Unmatched cases"},
    "slots": {"accountable": "Accountable for the ward", "escalation": "Above the accountable one"},
    "fingerprints": [
        {"event_type": "vitals.news2_high", "fields": {"ward": "ward", "bed": "bed"}, "group_by": ["bed"]},
        {"event_type": "meds.missed_dose", "fields": {"ward": "ward", "bed": "bed"}, "group_by": ["bed"]},
        {"event_type": "bed.blocked", "fields": {"ward": "ward"}, "group_by": ["ward"]},
    ],
    "patterns": [
        {"id": "news2_high", "description": "Deteriorating patient", "event_types": ["vitals.news2_high"],
         "owner_slot": "accountable", "escalation_slot": "escalation", "sla_minutes": 15,
         "disposition_codes": ["reviewed", "no_action"]},
        {"id": "missed_dose", "description": "A dose was missed", "event_types": ["meds.missed_dose"],
         "owner_slot": "accountable", "sla_minutes": 60, "disposition_codes": ["given", "no_action"]},
        {"id": "bed_blocked", "description": "Bed blocked (role-based, no slots)",
         "event_types": ["bed.blocked"], "owner_role": "matron", "disposition_codes": ["cleared"]},
    ],
}

# St Anne's: nurse-led wards
ST_ANNE = {"layer": "st_anne", "slot_bindings": {"accountable": "charge_nurse", "escalation": "consultant"}}
# Riverside: doctor-led
RIVERSIDE = {"layer": "riverside", "slot_bindings": {"accountable": "registrar", "escalation": "consultant"}}

PEOPLE = {
    "roles": {
        "matron": {"name": "Matron"},
        "consultant": {"name": "Consultant", "parent": "matron"},
        "registrar": {"name": "Registrar", "parent": "consultant"},
        "charge_nurse": {"name": "Charge nurse", "parent": "consultant"},
        "staff_nurse": {"name": "Staff nurse", "parent": "charge_nurse"},
        "supervisor": {"name": "Supervisor"},
    },
    "people": [{"id": p} for p in ("cara", "colm", "rhea", "sid", "dr_kay", "mona", "sup", "nell")],
    "assignments": [
        {"person_id": "cara", "role_id": "charge_nurse", "scope": {"ward": ["W1"]}},
        {"person_id": "colm", "role_id": "charge_nurse", "scope": {"ward": ["W2"]}},
        {"person_id": "rhea", "role_id": "registrar", "scope": {"ward": ["W1", "W2"]}},
        {"person_id": "sid", "role_id": "staff_nurse", "scope": {"ward": ["W1"]}},
        {"person_id": "dr_kay", "role_id": "consultant"},
        {"person_id": "mona", "role_id": "matron"},
        {"person_id": "sup", "role_id": "supervisor"},
    ],
    "authority": [
        {"role_id": "matron", "action": "__configure__"},
        {"role_id": "matron", "action": "__set_route__"},
    ],
}


def layers(*extra: dict[str, Any], pack: dict[str, Any] | None = None) -> list[tuple[str, dict[str, Any]]]:
    out = [("clinical_pack", copy.deepcopy(pack or PACK))]
    for i, x in enumerate(extra):
        out.append((x.get("layer", f"extra{i}"), copy.deepcopy(x)))
    return out


def make_engine(*extra: dict[str, Any], pack: dict[str, Any] | None = None, store: Any = None,
                clock: Any = None, people: dict | None = None, edge: MemoryEdge | None = None) -> Engine:
    doc = load_layers(layers(*extra, pack=pack))
    kw: dict[str, Any] = {}
    if edge is not None:
        kw = {"edges": {edge.name: edge}, "default_edges": [edge.name]}
    ov = Overlay(name="hospital", fingerprint_rules=doc.fingerprints, patterns=doc.patterns, roles=doc.roles,
                 case_defaults=doc.defaults, slots=doc.slots, slot_bindings=doc.slot_bindings,
                 directory=parse_directory(copy.deepcopy(people or PEOPLE)), **kw)
    return Engine(ov, store=store or SQLiteStore(":memory:"), clock=clock or FrozenClock(), licence=False)


def news2(ward: str = "W1", bed: str = "B1", key: str | None = None) -> Event:
    return Event(type="vitals.news2_high", source="ews", idempotency_key=key or f"n2:{ward}:{bed}",
                 payload={"ward": ward, "bed": bed, "score": 7})


def owner(engine: Engine, incident_id: str) -> str:
    rev = engine.store.open_review_for(incident_id)
    assert rev is not None
    return rev.assignee_role


def errors(problems: list[Any]) -> list[str]:
    return [p.message for p in problems if p.severity == "error"]


def publish(engine: Engine, text: str, by: str = "mona") -> Any:
    cv, _ = engine.save_config("registry", text, author="author")
    return engine.publish_config(cv.id, by)


# ============================================================================== 1. load: binding and merging
class TestLoad:
    def test_slots_resolve_to_tenant_roles_per_hospital(self):
        a = {p.id: p for p in load_layers(layers(ST_ANNE)).patterns}
        b = {p.id: p for p in load_layers(layers(RIVERSIDE)).patterns}
        assert a["news2_high"].owner_role == "charge_nurse" and b["news2_high"].owner_role == "registrar"
        assert a["news2_high"].escalation_role == b["news2_high"].escalation_role == "consultant"
        assert a["news2_high"].owner_slot == "accountable" and a["news2_high"].escalation_slot == "escalation"
        assert a["bed_blocked"].owner_role == "matron" and a["bed_blocked"].owner_slot is None

    def test_doc_carries_merged_slots_and_bindings(self):
        doc = load_layers(layers(ST_ANNE))
        assert set(doc.slots) == {"accountable", "escalation"}
        assert doc.slot_bindings == {"accountable": "charge_nurse", "escalation": "consultant"}

    def test_later_layer_rebinds(self):
        doc = load_layers(layers(ST_ANNE, {"layer": "w_reorg", "slot_bindings": {"accountable": "staff_nurse"}}))
        p = {p.id: p for p in doc.patterns}["news2_high"]
        assert p.owner_role == "staff_nurse" and p.escalation_role == "consultant"   # other binding kept

    def test_unbound_slot_refused(self):
        with pytest.raises(REFUSED, match="not bound"):
            load_layers(layers())

    def test_partially_bound_refused(self):
        with pytest.raises(REFUSED, match="escalation"):
            load_layers(layers({"slot_bindings": {"accountable": "charge_nurse"}}))

    @pytest.mark.parametrize("bindings", [{}, None])
    def test_empty_or_null_bindings_refused(self, bindings):
        with pytest.raises(REFUSED):
            load_layers(layers({"slot_bindings": bindings}))

    @pytest.mark.parametrize("value", [None, "", 5, ["charge_nurse"]])
    def test_bad_binding_values_refused(self, value):
        with pytest.raises(REFUSED):
            load_layers(layers({"slot_bindings": {"accountable": value, "escalation": "consultant"}}))

    def test_later_layer_cannot_unbind_with_null(self):
        with pytest.raises(REFUSED):
            load_layers(layers(ST_ANNE, {"slot_bindings": {"accountable": None}}))

    def test_binding_to_unknown_role_refused(self):
        with pytest.raises(REFUSED, match="unknown role"):
            load_layers(layers({"slot_bindings": {"accountable": "ward_clerk", "escalation": "consultant"}}))

    def test_binding_an_undeclared_slot_refused(self):
        with pytest.raises(REFUSED, match="not a declared slot"):
            load_layers(layers({"slot_bindings": {**ST_ANNE["slot_bindings"], "pharmacist": "registrar"}}))

    def test_pattern_using_undeclared_slot_refused(self):
        extra = {"patterns": [{"id": "fall", "event_types": ["bed.blocked"], "owner_slot": "porter"}],
                 "slot_bindings": {**ST_ANNE["slot_bindings"]}}
        with pytest.raises(REFUSED, match="not a declared slot"):
            load_layers(layers(extra))

    def test_slot_declared_in_a_later_layer_is_fine(self):
        extra = {"slots": {"porter": "Moves patients"}, "slot_bindings": {**ST_ANNE["slot_bindings"],
                                                                          "porter": "staff_nurse"},
                 "patterns": [{"id": "transfer", "event_types": ["bed.blocked"], "owner_slot": "porter"}]}
        p = {p.id: p for p in load_layers(layers(extra)).patterns}["transfer"]
        assert p.owner_role == "staff_nurse"

    def test_slot_and_different_role_refused(self):
        pack = copy.deepcopy(PACK)
        pack["patterns"][0]["owner_role"] = "matron"
        with pytest.raises(REFUSED, match="not both"):
            load_layers(layers(ST_ANNE, pack=pack))

    def test_slot_and_same_role_refused(self):
        # Changed in v0.16.1 to fix the "stale role blocks rebinding" defect: a slot plus ANY role line is
        # refused, even the currently bound one, so the binding is the only place the role is decided.
        pack = copy.deepcopy(PACK)
        pack["patterns"][0]["owner_role"] = "charge_nurse"
        with pytest.raises(REFUSED, match="not both"):
            load_layers(layers(ST_ANNE, pack=pack))

    def test_slot_and_role_named_operator_is_also_refused(self):
        # FIXED v0.16.1 (was DEFECT): docs: "a pattern may not name a slot and a different role for the same job". A pattern that
        # explicitly says owner_role: operator next to owner_slot: accountable (bound to charge_nurse) names a
        # different role and must be refused. Actual: accepted silently, because 'operator' is the field
        # default and is treated as "no role given"; the slot wins without a word.
        reg = {**{k: v for k, v in PACK.items() if k != "layer"}, "roles": {**PACK["roles"], "operator": "Ops"},
               **{"slot_bindings": ST_ANNE["slot_bindings"]}}
        reg["patterns"] = [{**PACK["patterns"][1], "owner_role": "operator"}]
        with pytest.raises(REFUSED, match="not both"):
            parse_registry(copy.deepcopy(reg))

    def test_override_setting_a_different_owner_role_on_slotted_pattern_refused(self):
        with pytest.raises(REFUSED, match="not both"):
            load_layers(layers(ST_ANNE, {"overrides": [{"id": "news2_high", "set": {"owner_role": "matron"}}]}))

    def test_override_setting_a_different_escalation_role_refused(self):
        with pytest.raises(REFUSED, match="not both"):
            load_layers(layers(ST_ANNE, {"overrides": [{"id": "news2_high",
                                                         "set": {"escalation_role": "matron"}}]}))

    def test_override_switching_from_slot_to_role_is_allowed(self):
        doc = load_layers(layers(ST_ANNE, {"overrides": [{"id": "news2_high",
                                                          "set": {"owner_slot": None, "owner_role": "matron"}}]}))
        p = {p.id: p for p in doc.patterns}["news2_high"]
        assert p.owner_role == "matron" and p.owner_slot is None

    def test_override_clearing_slot_without_role_does_not_silently_fall_to_operator(self):
        # The pack has no 'operator' role: clearing the slot must not leave the case with a role nobody holds.
        with pytest.raises(REFUSED):
            load_layers(layers(ST_ANNE, {"overrides": [{"id": "news2_high", "set": {"owner_slot": None}}]}))

    def test_slot_on_escalation_only(self):
        pack = copy.deepcopy(PACK)
        pack["patterns"][0].pop("owner_slot")
        pack["patterns"][0]["owner_role"] = "staff_nurse"
        pack["patterns"].pop(1)                                             # missed_dose uses accountable
        doc = load_layers(layers({"slot_bindings": {"escalation": "registrar"}}, pack=pack))
        p = {p.id: p for p in doc.patterns}["news2_high"]
        assert p.owner_role == "staff_nurse" and p.escalation_role == "registrar"

    def test_load_registry_from_a_single_file(self, tmp_path):
        reg = {k: v for k, v in PACK.items() if k != "layer"}
        reg["slot_bindings"] = RIVERSIDE["slot_bindings"]
        f = tmp_path / "registry.yaml"
        f.write_text(yaml.safe_dump(reg), encoding="utf-8")
        p = {p.id: p for p in load_registry(f).patterns}["news2_high"]
        assert p.owner_role == "registrar"
        f.write_text(yaml.safe_dump({k: v for k, v in reg.items() if k != "slot_bindings"}), encoding="utf-8")
        with pytest.raises(REFUSED):
            load_registry(f)


# ============================================================================== 2. compatibility
class TestCompatibility:
    def test_registry_without_slots_unchanged(self):
        reg = {"roles": {"matron": "M"}, "fingerprints": [{"event_type": "bed.blocked", "fields": {"ward": "ward"}}],
               "patterns": [{"id": "bed_blocked", "event_types": ["bed.blocked"], "owner_role": "matron"}]}
        p = parse_registry(reg).patterns[0]
        plain = Pattern(id="bed_blocked", event_types=["bed.blocked"], owner_role="matron")
        assert p.owner_role == "matron" and p.owner_slot is None
        assert p.definition_hash() == plain.definition_hash()

    def test_moving_from_role_to_slot_keeps_definition_hash(self):
        slotted = {p.id: p for p in load_layers(layers(ST_ANNE)).patterns}["news2_high"]
        role_pack = copy.deepcopy(PACK)
        role_pack.pop("slots")
        pat = role_pack["patterns"][0]
        pat.pop("owner_slot"), pat.pop("escalation_slot")
        pat["owner_role"], pat["escalation_role"] = "charge_nurse", "consultant"
        role_pack["patterns"] = [pat, role_pack["patterns"][2]]
        plain = {p.id: p for p in load_layers([("p", role_pack)]).patterns}["news2_high"]
        assert slotted.definition_hash() == plain.definition_hash()

    def test_registry_without_slots_writes_no_slot_keys(self):
        reg = {"roles": {"matron": "M", "supervisor": "S"},
               "fingerprints": [{"event_type": "bed.blocked", "fields": {"ward": "ward"}}],
               "patterns": [{"id": "bed_blocked", "event_types": ["bed.blocked"], "owner_role": "matron"}]}
        doc = parse_registry(reg)
        eng = Engine(Overlay(name="x", fingerprint_rules=doc.fingerprints, patterns=doc.patterns, roles=doc.roles,
                             directory=parse_directory(copy.deepcopy(PEOPLE))), store=SQLiteStore(":memory:"),
                     licence=False)
        text = eng.config_text("registry")
        assert "slot" not in text and "owner_role: matron" in text


# ============================================================================== 3. routing and escalation
class TestRouting:
    def test_case_goes_to_bound_role_and_to_holders_in_scope(self):
        edge = MemoryEdge()
        eng = make_engine(ST_ANNE, edge=edge)
        r = eng.ingest(news2("W1"))
        assert owner(eng, r.incident_id) == "charge_nurse"
        eng.work("w")
        assert [c.recipient_id for c in edge.cards] == ["cara"]            # not colm (W2)
        r2 = eng.ingest(news2("W2", bed="B9"))
        eng.work("w")
        assert owner(eng, r2.incident_id) == "charge_nurse"
        assert [c.recipient_id for c in edge.cards] == ["cara", "colm"]

    def test_same_pack_other_hospital_routes_to_its_own_role(self):
        edge = MemoryEdge()
        eng = make_engine(RIVERSIDE, edge=edge)
        r = eng.ingest(news2("W2"))
        assert owner(eng, r.incident_id) == "registrar"
        eng.work("w")
        assert [c.recipient_id for c in edge.cards] == ["rhea"]

    def test_escalation_goes_to_escalation_slot_role(self):
        clock = FrozenClock()
        eng = make_engine(ST_ANNE, clock=clock)
        r = eng.ingest(news2())
        clock.advance(minutes=16)
        eng.sweep()
        assert owner(eng, r.incident_id) == "consultant"

    def test_pattern_without_escalation_slot_climbs_the_tree(self):
        clock = FrozenClock()
        eng = make_engine(ST_ANNE, clock=clock)
        r = eng.ingest(Event(type="meds.missed_dose", source="emar", payload={"ward": "W1", "bed": "B3"}))
        assert owner(eng, r.incident_id) == "charge_nurse"
        clock.advance(minutes=61)
        eng.sweep()
        assert owner(eng, r.incident_id) == "consultant"                    # parent of charge_nurse


# ============================================================================== 4. publish (console)
class TestPublish:
    def test_published_text_round_trips_and_writes_slots_not_roles(self):
        eng = make_engine(ST_ANNE)
        text = eng.config_text("registry")
        data = yaml.safe_load(text)
        p = {p["id"]: p for p in data["patterns"]}["news2_high"]
        assert p["owner_slot"] == "accountable" and "owner_role" not in p
        assert data["slot_bindings"] == ST_ANNE["slot_bindings"]
        assert errors(eng.check_config("registry", text)[1]) == []
        publish(eng, text)
        assert errors(eng.check_config("registry", eng.config_text("registry"))[1]) == []

    def test_console_rebinding_routes_new_cases_and_keeps_old_ones(self):
        eng = make_engine(ST_ANNE)
        old = eng.ingest(news2(bed="B1"))
        text = eng.config_text("registry").replace("accountable: charge_nurse", "accountable: registrar")
        publish(eng, text)
        new = eng.ingest(news2(bed="B2"))
        assert owner(eng, new.incident_id) == "registrar"
        assert owner(eng, old.incident_id) == "charge_nurse"

    def test_console_rebinding_is_stored_as_a_layer(self):
        eng = make_engine(ST_ANNE)
        text = eng.config_text("registry").replace("accountable: charge_nurse", "accountable: registrar")
        cv, problems = eng.save_config("registry", text, author="author")
        assert errors(problems) == []
        assert cv.layer and cv.layer.get("slot_bindings") == {"accountable": "registrar"}

    def test_console_rebinding_survives_pack_upgrade(self):
        store, clock = SQLiteStore(":memory:"), FrozenClock()
        eng = make_engine(ST_ANNE, store=store, clock=clock)
        publish(eng, eng.config_text("registry").replace("accountable: charge_nurse", "accountable: registrar"))
        pack2 = copy.deepcopy(PACK)
        pack2["fingerprints"].append({"event_type": "meds.allergy", "fields": {"ward": "ward"}})
        pack2["patterns"].append({"id": "allergy", "description": "Allergy clash", "event_types": ["meds.allergy"],
                                  "owner_slot": "accountable"})
        eng2 = make_engine(ST_ANNE, pack=pack2, store=store, clock=clock)
        roles = {p.id: p.owner_role for p in eng2.registry.all()}
        assert roles["news2_high"] == roles["allergy"] == "registrar"
        assert "registry_rebased" in [a["kind"] for a in store.audit_log()]

    @pytest.mark.parametrize("replace,needle", [
        ("slot_bindings: {accountable: charge_nurse, escalation: consultant}", "not bound"),     # removed
        ("accountable: charge_nurse", "unknown role"),                                            # unknown role
    ])
    def test_publish_refuses_bad_bindings(self, replace, needle):
        eng = make_engine(ST_ANNE)
        text = eng.config_text("registry")
        bad = text.replace(replace, "" if needle == "not bound" else "accountable: ward_clerk")
        assert bad != text
        assert any(needle in m for m in errors(eng.check_config("registry", bad)[1]))
        with pytest.raises(ConfigError):
            publish(eng, bad)
        assert owner(eng, eng.ingest(news2()).incident_id) == "charge_nurse"   # still running the old one

    def test_publish_refuses_null_binding(self):
        eng = make_engine(ST_ANNE)
        bad = eng.config_text("registry").replace("accountable: charge_nurse", "accountable: null")
        with pytest.raises(ConfigError):
            publish(eng, bad)

    def test_publish_refuses_undeclared_slot_binding(self):
        eng = make_engine(ST_ANNE)
        bad = eng.config_text("registry").replace("escalation: consultant}", "escalation: consultant, x: matron}")
        assert errors(eng.check_config("registry", bad)[1])

    def test_publish_refuses_slot_and_different_role(self):
        eng = make_engine(ST_ANNE)
        bad = eng.config_text("registry").replace("owner_slot: accountable\n  escalation_slot",
                                                  "owner_slot: accountable\n  owner_role: matron\n  escalation_slot")
        assert any("not both" in m for m in errors(eng.check_config("registry", bad)[1]))

    def test_rebinding_to_a_role_the_people_directory_lacks_is_refused(self):
        eng = make_engine(ST_ANNE)
        text = eng.config_text("registry")
        text = text.replace("roles: {", "roles: {ward_clerk: Ward clerk, ").replace(
            "accountable: charge_nurse", "accountable: ward_clerk")
        assert any("ward_clerk" in m for m in errors(eng.check_config("registry", text)[1]))
        with pytest.raises(ConfigError):
            publish(eng, text)

    def test_people_publish_removing_the_bound_role_is_refused(self):
        eng = make_engine(ST_ANNE)
        people = copy.deepcopy(PEOPLE)
        del people["roles"]["charge_nurse"]
        people["roles"]["staff_nurse"]["parent"] = "consultant"
        people["assignments"] = [a for a in people["assignments"] if a["role_id"] != "charge_nurse"]
        cv, problems = eng.save_config("people", yaml.safe_dump(people), author="author")
        assert errors(problems)
        with pytest.raises(ConfigError):
            eng.publish_config(cv.id, "mona")

    def test_rebinding_keeps_trust(self):
        eng = make_engine(ST_ANNE)
        p0 = eng.registry.get("news2_high")
        eng.set_route("news2_high", Route.LLM, actor="mona")
        publish(eng, eng.config_text("registry").replace("accountable: charge_nurse", "accountable: registrar"))
        p1 = eng.registry.get("news2_high")
        assert p1.owner_role == "registrar" and p1.definition_hash() == p0.definition_hash()
        assert eng.store.get_pattern_state("news2_high").route is Route.LLM
        assert "pattern_changed" not in [a["kind"] for a in eng.store.audit_log()]

    def test_console_rebinding_of_escalation_slot_drives_sweep(self):
        clock = FrozenClock()
        eng = make_engine(ST_ANNE, clock=clock)
        publish(eng, eng.config_text("registry").replace("escalation: consultant", "escalation: matron"))
        r = eng.ingest(news2())
        clock.advance(minutes=16)
        eng.sweep()
        assert owner(eng, r.incident_id) == "matron"

    def test_writing_slot_plus_same_role_must_not_block_a_later_rebinding(self):
        # FIXED v0.16.1 (was DEFECT): CHANGELOG: "Registry documents write the slot, not the resolved role, so a rebinding never
        # leaves a stale role." Publishing a console text whose pattern names owner_slot AND the currently
        # bound role (owner_role: charge_nurse) is accepted and stored as a layer override
        # {owner_role: charge_nurse}; from then on the running registry text carries the resolved role, and
        # the next console rebinding of the slot is refused ("names owner_slot and owner_role ... not both").
        # Expected: either the first publish is refused/normalised (role dropped), or the rebinding succeeds
        # and routes to the new role.
        eng = make_engine(ST_ANNE)
        pinned = eng.config_text("registry").replace(
            "owner_slot: accountable\n  escalation_slot", "owner_slot: accountable\n  owner_role: charge_nurse\n"
            "  escalation_slot")
        try:
            publish(eng, pinned)
        except ConfigError:
            return                                                          # refused up front: fine
        rebound = eng.config_text("registry").replace("accountable: charge_nurse", "accountable: registrar")
        assert errors(eng.check_config("registry", rebound)[1]) == []
        publish(eng, rebound)
        assert owner(eng, eng.ingest(news2()).incident_id) == "registrar"

    def test_draft_trace_shows_a_rebinding_before_publish(self):
        eng = make_engine(ST_ANNE)
        draft = eng.config_text("registry").replace("accountable: charge_nurse", "accountable: registrar")
        t = eng.trace(news2("W2"), registry_text=draft)
        assert t["pattern"]["owner_role"] == "registrar" and t["pattern"]["owner_slot"] == "accountable"
        assert [p["id"] for p in t["reviewers"]["people"]] == ["rhea"]
        assert owner(eng, eng.ingest(news2()).incident_id) == "charge_nurse"   # nothing published


# ============================================================================== 5. explain / trace
class TestExplain:
    def test_trace_shows_owner_slot(self):
        eng = make_engine(ST_ANNE)
        t = eng.trace(news2())
        assert t["pattern"]["owner_slot"] == "accountable" and t["pattern"]["owner_role"] == "charge_nurse"

    def test_trace_shows_escalation_slot(self):
        # FIXED v0.16.1 (was DEFECT): CHANGELOG: "`explain` shows the slot." trace() reports owner_slot but never escalation_slot,
        # so a pattern with a slot on escalation only shows no slot at all in its trace (pattern section has
        # no slot key; reviewers has escalation_role but not where it came from).
        pack = copy.deepcopy(PACK)
        pack["patterns"][0].pop("owner_slot")
        pack["patterns"][0]["owner_role"] = "staff_nurse"
        eng = make_engine(ST_ANNE, pack=pack)
        t = eng.trace(news2())
        assert t["reviewers"]["escalation_role"] == "consultant"
        shown = {**t["pattern"], **t["reviewers"]}
        assert shown.get("escalation_slot") == "escalation"

    def test_case_story_shows_the_slot(self):
        # FIXED v0.16.1 (was DEFECT): CHANGELOG: "`explain` shows the slot." The case story (engine.case / `sentinel case`, the other
        # half of sentinel.explain) lists the pattern's owner_role only; owner_slot is missing, so a reader
        # cannot tell the owner came from the tenant's binding.
        eng = make_engine(ST_ANNE)
        r = eng.ingest(news2())
        story = eng.case(r.incident_id)
        assert story["pattern"]["owner_role"] == "charge_nurse"
        assert story["pattern"].get("owner_slot") == "accountable"


# ============================================================================== 6. overlays built in code
class TestCodeOverlay:
    def test_engine_refuses_an_unresolved_slotted_pattern(self):
        # FIXED v0.16.1 (was DEFECT): ADR-003 invariant 3 / changelog: a used slot that is unbound must be refused. An overlay built
        # in code (Overlay(patterns=[Pattern(owner_slot=...)], slots=..., slot_bindings=...)), as
        # OVERLAY_CONTRACT allows, is accepted by Engine even with NO binding, and every case is silently
        # owned by the default role 'operator'. Even WITH slot_bindings on the Overlay the slot is never
        # resolved: cases still go to 'operator' instead of the bound role.
        fp = [FingerprintRule(event_type="vitals.news2_high", fields={"ward": "ward"})]
        roles = {"registrar": "R", "operator": "O"}
        bound = Overlay(name="code", fingerprint_rules=fp, roles=roles, slots={"accountable": "A"},
                        slot_bindings={"accountable": "registrar"},
                        patterns=[Pattern(id="n", description="d", event_types=["vitals.news2_high"],
                                          owner_slot="accountable")])
        eng = Engine(bound, store=SQLiteStore(":memory:"), licence=False)
        r = eng.ingest(news2())
        assert owner(eng, r.incident_id) == "registrar"

    def test_conformance_reports_unbound_slot(self):
        # FIXED v0.16.1 (was DEFECT): sentinel.testing.conformance "checks what Sentinel relies on ... its roles exist". A pattern
        # with owner_slot and no binding anywhere passes conformance with [] (and then routes to 'operator').
        fp = [FingerprintRule(event_type="vitals.news2_high", fields={"ward": "ward"})]
        ov = Overlay(name="code", fingerprint_rules=fp, roles={"registrar": "R", "operator": "O"},
                     patterns=[Pattern(id="n", description="d", event_types=["vitals.news2_high"],
                                       owner_slot="accountable")])
        assert conformance(ov) != []
