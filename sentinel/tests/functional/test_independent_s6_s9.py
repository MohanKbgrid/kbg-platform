# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""Independent black-box journeys for v0.19.0 pooled trust, v0.20.0 oversight separation, v0.21.0 capability
catalogue and domain bindings, and v0.22.0 per-client fleet targets and dual-run tooling. Written from CHANGELOG,
OVERLAY_CONTRACT ("Pooled trust", "Oversight (Layer D)"), EXTENDING ("Domain bindings (ADR-005)"), OPERATIONS
("Per-client adoption (ADR-004)"), ADR-003/004/005 and public signatures/docstrings only.

Domain: a dairy processor. Chiller excursions are watched per plant (P1..P9) by one template that pools trust; a
lab failure on a batch may never be released unattended (``dairy.release_batch`` is never automated). Plant QA
owns the agents, the plant head is escalation, the MD sits above both, internal audit oversees.

Tests that expose a framework defect carry ``# FIXED v0.22.2 (was DEFECT):`` with expected vs actual and are left failing.
"""
from __future__ import annotations

import copy
import json
import sys
from typing import Any

import pytest
import yaml

from sentinel import (ActionRegistry, ActionResult, AuthorizationError, Capability, Decision, DecisionKind, Engine,
                      EngineError, Event, FingerprintRule, Guardrails, IncidentState, LearningPolicy, Overlay,
                      Pattern, PlaybookStep, Route, ScriptedLLM, SQLiteStore, cli, dualrun, egress, fleet)
from sentinel.bindings import CATALOGUE, DomainBinding, check_binding, enforce_never_automate, relevant
from sentinel.config import ConfigError
from sentinel.rbac import parse_directory
from sentinel.testing import FrozenClock, engine_for

# ============================================================================== the dairy rig
FP = [FingerprintRule(event_type="chiller.warm", fields={"plant": "plant", "batch": "batch", "temp": "temp"}),
      FingerprintRule(event_type="lab.fail", fields={"plant": "plant", "batch": "batch"})]

PEOPLE: dict[str, Any] = {
    "roles": {"md": {}, "plant_head": {"parent": "md"}, "plant_qa": {"parent": "plant_head"},
              "audit": {"parent": "md"}, "supervisor": {"parent": "md"},
              "qa_director": {"parent": "md"}, "regional_qa": {"parent": "qa_director"}},
    "people": [{"id": x} for x in ("qa1", "ph", "mdx", "aud", "qd")],
    "assignments": [{"person_id": "qa1", "role_id": "plant_qa"}, {"person_id": "ph", "role_id": "plant_head"},
                    {"person_id": "mdx", "role_id": "md"}, {"person_id": "mdx", "role_id": "supervisor"},
                    {"person_id": "aud", "role_id": "audit"}, {"person_id": "qd", "role_id": "qa_director"}],
    "authority": [{"role_id": "md", "action": "__configure__"}, {"role_id": "md", "action": "__set_route__"}],
    "oversight": [{"role": "audit", "templates": ["*"]}],
}

BINDING: dict[str, Any] = {
    "domain": "dairy",
    "binds": [{"capability": "exception_watch", "map": {"subject": "batch", "scope": "plant"},
               "patterns": ["dairy_*"]}],
    "never_automate": ["dairy.release_batch"],
}


class Plant:
    """Actions record every side effect; a verifier answers outcome checks."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []
        self.verdict: bool | None = True
        self.acts = ActionRegistry()
        for name in ("dairy.divert", "dairy.hold", "dairy.release_batch"):
            self._action(name)

    def _action(self, name: str) -> None:
        @self.acts.action(name, reversible=True, params={"batch": "str"}, description=name)
        def run(ctx, p):
            self.calls.append((name, p["batch"]))
            return ActionResult(ok=True)

        @run.compensator
        def undo(ctx, p):
            return ActionResult(ok=True)

    def ran(self, name: str = "dairy.divert") -> list[str]:
        return [b for n, b in self.calls if n == name]


def chiller(**over: Any) -> Pattern:
    base: dict[str, Any] = dict(
        id="dairy_chiller", description="Chiller above 7C", event_types=["chiller.warm"], route=Route.HITL,
        playbook=[PlaybookStep(action="dairy.divert", params={"batch": "{{payload.batch}}"})],
        allowed_actions=["dairy.divert", "dairy.hold"], owner_role="plant_qa", escalation_role="plant_head",
        trust_by=["plant"], trust_pool_min=3)
    base.update(over)
    return Pattern(**base)


def lab_fail(**over: Any) -> Pattern:
    base: dict[str, Any] = dict(
        id="dairy_lab_fail", description="Batch failed the lab", event_types=["lab.fail"], route=Route.HITL,
        max_route=Route.HITL, allowed_actions=["dairy.release_batch", "dairy.hold"], owner_role="plant_qa")
    base.update(over)
    return Pattern(**base)


ROLES = {k: k for k in PEOPLE["roles"]}


def overlay(plant: Plant, patterns: list[Pattern], *, people: dict | None = None, binding: dict | None = None,
            **kw: Any) -> Overlay:
    return Overlay(name="dairy", fingerprint_rules=FP, patterns=patterns, actions=plant.acts, roles=dict(ROLES),
                   verifiers={"chiller_ok": lambda **k: plant.verdict},
                   directory=parse_directory(copy.deepcopy(people)) if people else None,
                   binding=DomainBinding.model_validate(copy.deepcopy(binding)) if binding else None, **kw)


def engine(plant: Plant, patterns: list[Pattern], streak: int = 2, **kw: Any) -> Engine:
    ekw = {k: kw.pop(k) for k in ("llm", "raise_on_invalid", "store") if k in kw}
    ov = overlay(plant, patterns, **kw)
    learning = LearningPolicy(promote_streak={Route.HITL: streak, Route.LLM: streak})
    if "store" in ekw:
        return Engine(ov, store=ekw.pop("store"), clock=FrozenClock(), licence=False, learning=learning,
                      guardrails=Guardrails(allow_irreversible_unattended=True), **ekw)
    return engine_for(ov, learning=learning, **ekw)


class Feed:
    def __init__(self) -> None:
        self.n = 0

    def warm(self, plant: str = "P1", temp: float = 9.0, key: bool = True) -> Event:
        self.n += 1
        return Event(type="chiller.warm", source="scada", idempotency_key=f"c{self.n}" if key else None,
                     payload={"plant": plant, "batch": f"{plant}-{self.n}", "temp": temp})

    def lab(self, plant: str = "P1") -> Event:
        self.n += 1
        return Event(type="lab.fail", source="lims", idempotency_key=f"l{self.n}",
                     payload={"plant": plant, "batch": f"L{self.n}"})


def approve_all(eng: Engine) -> None:
    for r in eng.store.open_reviews():
        eng.decide(r.id, Decision(kind=DecisionKind.APPROVE, actor="qa1"))


def kinds(eng: Engine) -> list[str]:
    return [a["kind"] for a in eng.store.audit_log()]


def messages(problems: list[Any], severity: str = "error") -> list[str]:
    return [p.message for p in problems if p.severity == severity]


@pytest.fixture
def plant() -> Plant:
    return Plant()


@pytest.fixture
def feed() -> Feed:
    return Feed()


# ============================================================================== 1. pooled trust (v0.19.0)
class TestPooledTrust:
    def test_thin_plants_learn_together_and_a_new_plant_inherits_the_pool(self, plant, feed):
        eng = engine(plant, [chiller()])
        p = eng.registry.get("dairy_chiller")
        for pl in ("P1", "P2"):
            eng.ingest(feed.warm(pl))
            approve_all(eng)
        pool = eng.store.get_pattern_state("dairy_chiller")
        assert pool is not None and pool.samples == 2 and pool.pending_promotion is Route.AUTO
        assert eng.trusted_state(p, {"plant": "P3"}).pattern_id == "dairy_chiller"
        eng.approve_promotion("dairy_chiller", actor="mdx")
        assert eng.effective_route(p, {"plant": "P3"}) is Route.AUTO
        plant.calls.clear()
        eng.ingest(feed.warm("P3"))
        assert plant.ran() == ["P3-3"]

    def test_each_decision_teaches_both_scope_and_pool(self, plant, feed):
        eng = engine(plant, [chiller()])
        p = eng.registry.get("dairy_chiller")
        eng.ingest(feed.warm("P1"))
        approve_all(eng)
        ids = [s.pattern_id for s in eng.trust_states(p, {"plant": "P1"})]
        assert set(ids) == {"dairy_chiller@plant=P1", "dairy_chiller"}
        assert eng.store.get_pattern_state("dairy_chiller@plant=P1").samples == 1
        assert eng.store.get_pattern_state("dairy_chiller").samples == 1

    def test_scope_switches_to_its_own_trust_at_exactly_n_decisions(self, plant, feed):
        eng = engine(plant, [chiller()], streak=50)
        p = eng.registry.get("dairy_chiller")
        seen = []
        for _ in range(4):
            eng.ingest(feed.warm("P1"))
            approve_all(eng)
            seen.append(eng.trusted_state(p, {"plant": "P1"}).pattern_id)
        assert seen == ["dairy_chiller", "dairy_chiller", "dairy_chiller@plant=P1", "dairy_chiller@plant=P1"]

    def test_trace_says_the_route_is_pooled_and_then_stops_saying_it(self, plant, feed):
        eng = engine(plant, [chiller()], streak=50)
        eng.ingest(feed.warm("P1"))
        approve_all(eng)
        t = eng.trace(feed.warm("P4"))
        assert "pooled" in t["route"]["why"] and t["route"]["segment"] == "plant=P4"
        for _ in range(3):
            eng.ingest(feed.warm("P4"))
            approve_all(eng)
        assert "pooled" not in eng.trace(feed.warm("P4"))["route"]["why"]

    def test_trace_of_a_pooled_route_stores_nothing(self, plant, feed):
        eng = engine(plant, [chiller(route=Route.AUTO)])
        before = len(eng.store.audit_log())
        t = eng.trace(feed.warm("P2"))
        assert t["outcome"] == "automatic" and plant.calls == [] and len(eng.store.audit_log()) == before
        assert eng.store.open_reviews() == []

    def test_reversal_in_a_thin_plant_demotes_every_thin_plant(self, plant, feed):
        eng = engine(plant, [chiller()])
        p = eng.registry.get("dairy_chiller")
        eng.set_route("dairy_chiller", Route.AUTO, actor="mdx")
        r = eng.ingest(feed.warm("P2"))
        eng.reverse(r.incident_id, actor="qa1", note="product was fine")
        assert eng.store.get_pattern_state("dairy_chiller").route is Route.LLM
        assert eng.effective_route(p, {"plant": "P7"}) is not Route.AUTO
        plant.calls.clear()
        eng.ingest(feed.warm("P7"))
        assert plant.ran() == []

    def test_reversal_in_a_mature_plant_also_demotes_the_pool(self, plant, feed):
        eng = engine(plant, [chiller(route=Route.AUTO)])
        ids = [eng.ingest(feed.warm("P1")).incident_id for _ in range(3)]
        p = eng.registry.get("dairy_chiller")
        assert eng.trusted_state(p, {"plant": "P1"}).pattern_id == "dairy_chiller@plant=P1"
        eng.reverse(ids[-1], actor="qa1")
        assert eng.store.get_pattern_state("dairy_chiller").route is Route.LLM
        assert eng.effective_route(p, {"plant": "P5"}) is not Route.AUTO

    def test_failed_outcome_check_demotes_the_pool(self, plant, feed):
        eng = engine(plant, [chiller(outcome_check={"verifier": "chiller_ok", "after_minutes": 10})])
        eng.set_route("dairy_chiller", Route.AUTO, actor="mdx")
        plant.verdict = False
        r = eng.ingest(feed.warm("P2"))
        eng.clock.advance(minutes=11)
        eng.work("w")
        assert eng.store.get_disposition(r.incident_id).outcome == "failed"
        assert eng.store.get_pattern_state("dairy_chiller").route is Route.LLM
        assert eng.effective_route(eng.registry.get("dairy_chiller"), {"plant": "P8"}) is not Route.AUTO

    def test_without_trust_pool_min_the_base_state_never_learns(self, plant, feed):
        eng = engine(plant, [chiller(trust_pool_min=None)])
        p = eng.registry.get("dairy_chiller")
        for _ in range(2):
            eng.ingest(feed.warm("P1"))
            approve_all(eng)
        assert eng.store.get_pattern_state("dairy_chiller") is None
        assert [s.pattern_id for s in eng.trust_states(p, {"plant": "P1"})] == ["dairy_chiller@plant=P1"]
        assert "pooled" not in eng.trace(feed.warm("P2"))["route"]["why"]

    def test_hash_unchanged_without_pooling_and_changed_with_it(self):
        plain = chiller(trust_pool_min=None)
        assert "trust_pool_min" not in json.dumps(plain.model_dump(mode="json", exclude_defaults=True))
        assert plain.definition_hash() != chiller().definition_hash()
        assert chiller(trust_pool_min=3).definition_hash() != chiller(trust_pool_min=4).definition_hash()

    def test_trust_pool_min_must_be_positive(self):
        with pytest.raises(ValueError):
            chiller(trust_pool_min=0)

    def test_trust_pool_min_without_trust_by_warns_on_check(self, plant):
        eng = engine(plant, [chiller(trust_by=[], trust_pool_min=None)])
        text = eng.config_text("registry").replace("owner_role: plant_qa", "owner_role: plant_qa\n  trust_pool_min: 2",
                                                   1)
        _, probs = eng.check_config("registry", text)
        assert any("trust_pool_min" in m for m in messages(probs, "warning"))

    def test_template_kill_switch_stops_mature_and_thin_plants(self, plant, feed):
        eng = engine(plant, [chiller(route=Route.AUTO)])
        for _ in range(3):
            eng.ingest(feed.warm("P1"))
        eng.set_route("dairy_chiller", Route.HITL, actor="mdx")
        plant.calls.clear()
        eng.ingest(feed.warm("P1"))
        eng.ingest(feed.warm("P2"))
        assert plant.ran() == []

    def test_scope_kill_switch_on_a_thin_pooled_plant_holds_it(self, plant, feed):
        # FIXED v0.22.2 (was DEFECT): set_route docstring: '"pattern@segment" sets one segment's route' (the per-scope kill switch).
        # Expected: after set_route("dairy_chiller@plant=P7", HITL) a P7 event goes to a person.
        # Actual: P7 has fewer than trust_pool_min decisions, so the pooled AUTO route still applies and the
        # divert runs unattended; the kill switch is silently ignored. Repro: pooled pattern at AUTO, set one
        # thin segment to HITL, ingest an event for it -> action runs, effective_route is AUTO.
        eng = engine(plant, [chiller(route=Route.AUTO)])
        eng.set_route("dairy_chiller@plant=P7", Route.HITL, actor="mdx")
        plant.calls.clear()
        eng.ingest(feed.warm("P7"))
        assert eng.effective_route(eng.registry.get("dairy_chiller"), {"plant": "P7"}) is Route.HITL
        assert plant.ran() == []

    def test_scope_kill_switch_on_a_mature_pooled_plant_holds_it(self, plant, feed):
        # FIXED v0.22.2 (was DEFECT): Expected: a mature plant (>= trust_pool_min own decisions) set to HITL goes to a person.
        # Actual: set_route resets that segment's samples to 0, so it falls back to the pooled route (AUTO) and
        # keeps acting unattended. Repro: 3 AUTO cases on P1 (own trust), set_route("...@plant=P1", HITL),
        # trusted_state -> "dairy_chiller", next P1 event runs the divert.
        eng = engine(plant, [chiller(route=Route.AUTO)])
        for _ in range(3):
            eng.ingest(feed.warm("P1"))
        eng.set_route("dairy_chiller@plant=P1", Route.HITL, actor="mdx")
        plant.calls.clear()
        eng.ingest(feed.warm("P1"))
        assert plant.ran() == []


# ============================================================================== 2. oversight (v0.20.0)
class TestOversight:
    @pytest.mark.parametrize("role,why", [("plant_qa", "owns"), ("plant_head", "owns"), ("md", "above")])
    def test_owning_roles_refused_at_engine_start(self, plant, role, why):
        people = copy.deepcopy(PEOPLE)
        people["oversight"] = [{"role": role, "templates": ["*"]}]
        with pytest.raises(EngineError, match=why):
            engine(plant, [chiller()], people=people)

    def test_role_above_the_escalation_role_is_refused(self, plant):
        people = copy.deepcopy(PEOPLE)
        people["oversight"] = [{"role": "qa_director", "templates": ["dairy_chiller"]}]
        with pytest.raises(EngineError, match="above"):
            engine(plant, [chiller(escalation_role="regional_qa")], people=people)

    def test_capability_scoped_oversight_by_its_owner_is_refused(self, plant):
        people = copy.deepcopy(PEOPLE)
        people["oversight"] = [{"role": "plant_head", "templates": ["cold_chain"]}]
        caps = {"cold_chain": Capability(title="Cold chain")}
        with pytest.raises(EngineError, match="owns"):
            engine(plant, [chiller(capability="cold_chain")], people=people, capabilities=caps)

    def test_unknown_oversight_role_refused(self):
        people = copy.deepcopy(PEOPLE)
        people["oversight"] = [{"role": "ghost", "templates": ["*"]}]
        with pytest.raises(ValueError, match="ghost"):
            parse_directory(people)

    def test_people_publish_making_the_owner_its_overseer_is_refused(self, plant):
        eng = engine(plant, [chiller()], people=PEOPLE)
        people = copy.deepcopy(PEOPLE)
        people["oversight"] = [{"role": "plant_qa", "templates": ["dairy_chiller"]}]
        cv, probs = eng.save_config("people", yaml.safe_dump(people), author="mdx")
        assert any("owns" in m for m in messages(probs))
        with pytest.raises(ConfigError):
            eng.publish_config(cv.id, "mdx")

    def test_registry_publish_making_the_overseer_an_owner_is_refused(self, plant):
        eng = engine(plant, [chiller()], people=PEOPLE)
        text = eng.config_text("registry").replace("owner_role: plant_qa", "owner_role: audit")
        _, probs = eng.check_config("registry", text)
        assert any("audit" in m and "owns" in m for m in messages(probs))
        cv, _ = eng.save_config("registry", text, author="mdx")
        with pytest.raises(ConfigError):
            eng.publish_config(cv.id, "mdx")

    def test_person_holding_both_gets_a_warning(self, plant):
        eng = engine(plant, [chiller()], people=PEOPLE)
        people = copy.deepcopy(PEOPLE)
        people["assignments"].append({"person_id": "qa1", "role_id": "audit"})
        _, probs = eng.check_config("people", yaml.safe_dump(people))
        assert messages(probs) == [] and any("qa1" in m for m in messages(probs, "warning"))

    def test_oversee_is_oversight_role_only(self, plant):
        eng = engine(plant, [chiller(route=Route.AUTO)], people=PEOPLE)
        for actor in ("qa1", "ph", "mdx"):
            with pytest.raises(AuthorizationError):
                eng.oversee("dairy_chiller", "stop", actor, "trying to grade myself")
        assert "oversight_action" not in kinds(eng)

    @pytest.mark.parametrize("reason", ["", "   "])
    def test_oversee_needs_a_reason(self, plant, reason):
        eng = engine(plant, [chiller(route=Route.AUTO)], people=PEOPLE)
        with pytest.raises(EngineError):
            eng.oversee("dairy_chiller", "stop", "aud", reason)

    def test_oversee_cannot_raise(self, plant):
        eng = engine(plant, [chiller(route=Route.HITL, trust_pool_min=None)], people=PEOPLE)
        with pytest.raises(EngineError):
            eng.oversee("dairy_chiller", "promote", "aud", "looks good")
        eng.oversee("dairy_chiller", "cap", "aud", "ceiling", route=Route.AUTO)
        assert eng.effective_route(eng.registry.get("dairy_chiller"), {"plant": "P1"}) is Route.HITL

    def test_stop_demote_cap_are_audited(self, plant, feed):
        eng = engine(plant, [chiller(route=Route.AUTO, trust_pool_min=None)], people=PEOPLE)
        eng.oversee("dairy_chiller", "demote", "aud", "drift in agreement")
        assert eng.store.get_pattern_state("dairy_chiller").route is Route.LLM
        eng.oversee("dairy_chiller", "stop", "aud", "regulator visit")
        rows = [a for a in eng.store.audit_log() if a["kind"] == "oversight_action"]
        assert [r["data"]["action"] for r in rows] == ["demote", "stop"]
        assert all(r["data"]["actor"] == "aud" and r["data"]["reason"] for r in rows)
        plant.calls.clear()
        eng.ingest(feed.warm("P1"))
        assert plant.ran() == []

    def test_stop_on_one_plant_leaves_others_unpooled(self, plant, feed):
        eng = engine(plant, [chiller(route=Route.AUTO, trust_pool_min=None)], people=PEOPLE)
        eng.oversee("dairy_chiller@plant=P2", "stop", "aud", "P2 probe faulty")
        plant.calls.clear()
        eng.ingest(feed.warm("P2"))
        eng.ingest(feed.warm("P3"))
        assert plant.ran() == ["P3-2"]

    def test_stop_on_one_pooled_plant_stops_it(self, plant, feed):
        # FIXED v0.22.2 (was DEFECT): OVERLAY_CONTRACT: oversee(pattern_or_segment, "stop", ...) works on "a template or one scope".
        # Expected: after oversee("dairy_chiller@plant=P5", "stop") a P5 chiller excursion goes to a person.
        # Actual: on a pattern with trust_pool_min, P5 (thin) keeps using the pooled AUTO route; the stop is
        # recorded as oversight_action but the divert still runs unattended. Repro: chiller(route=AUTO,
        # trust_by=[plant], trust_pool_min=3), oversee("dairy_chiller@plant=P5","stop","aud","x"), ingest P5.
        eng = engine(plant, [chiller(route=Route.AUTO)], people=PEOPLE)
        eng.oversee("dairy_chiller@plant=P5", "stop", "aud", "P5 sensor faulty")
        plant.calls.clear()
        eng.ingest(feed.warm("P5"))
        assert plant.ran() == []

    def test_oversight_scoped_to_other_templates_cannot_touch_this_one(self, plant):
        people = copy.deepcopy(PEOPLE)
        people["oversight"] = [{"role": "audit", "templates": ["dairy_lab_fail"]}]
        eng = engine(plant, [chiller(), lab_fail()], people=people)
        with pytest.raises((AuthorizationError, EngineError)):
            eng.oversee("dairy_chiller", "stop", "aud", "not mine")
        eng.oversee("dairy_lab_fail", "stop", "aud", "mine")

    def test_no_oversight_section_means_no_lever(self, plant):
        people = copy.deepcopy(PEOPLE)
        people.pop("oversight")
        eng = engine(plant, [chiller()], people=people)
        with pytest.raises((AuthorizationError, EngineError)):
            eng.oversee("dairy_chiller", "stop", "mdx", "md wants it off")


# ============================================================================== 3. bindings (v0.21.0)
def binding(**changes: Any) -> DomainBinding:
    d = copy.deepcopy(BINDING)
    for k, v in changes.items():
        if v is None:
            d.pop(k, None)
        else:
            d[k] = v
    return DomainBinding.model_validate(d)


def bound(**kw: Any) -> dict[str, Any]:
    b = copy.deepcopy(BINDING["binds"][0])
    b.update(kw)
    return b


class TestBindings:
    def test_catalogue_is_structural(self):
        assert {"exception_watch", "reconciliation", "approval"} <= set(CATALOGUE)
        assert "demand_planning" not in CATALOGUE
        words = json.dumps({k: v.structures + v.optional for k, v in CATALOGUE.items()})
        for domain_word in ("milk", "store", "sku", "ward", "plant", "article", "depot"):
            assert domain_word not in words
        assert all(len(v.proven_in) >= 2 for v in CATALOGUE.values())

    def test_never_automate_is_required_but_may_be_empty(self):
        with pytest.raises(ValueError):
            binding(never_automate=None)
        assert check_binding(binding(never_automate=[]), [chiller(), lab_fail()]) == []

    @pytest.mark.parametrize("change,needle", [
        ({"binds": [bound(capability="demand_planning")]}, "unknown capability"),
        ({"binds": [bound(map={"subject": "batch"})]}, "not mapped"),
        ({"binds": [bound(map={"subject": "batch", "scope": "plant", "vehicle": "tanker"})]}, "not structures"),
        ({"binds": [bound(patterns=["dairy_*", "milk_*"])]}, "matches nothing"),
    ])
    def test_check_refuses_bad_bindings(self, change, needle):
        probs = check_binding(binding(**change), [chiller(), lab_fail()])
        assert any(needle in p for p in probs)

    def test_relevant_lists_rows_in_domain_words(self):
        rel = relevant(binding())
        assert set(rel) == {"exception_watch"} and rel["exception_watch"]["words"] == {"subject": "batch",
                                                                                      "scope": "plant"}

    @pytest.mark.parametrize("over", [
        {"max_route": Route.LLM},
        {"max_route": Route.AUTO},
        {"max_route": Route.AUTO, "route": Route.AUTO, "allowed_actions": [],
         "playbook": [PlaybookStep(action="dairy.release_batch", params={"batch": "{{payload.batch}}"})]},
        {"max_route": Route.AUTO, "allowed_actions": [],
         "playbook": [PlaybookStep(action="dairy.release_batch", params={"batch": "x"}, when={"plant": "P9"})]},
    ])
    def test_never_automate_reachable_unattended_is_refused(self, plant, over):
        assert any("never automates" in p for p in check_binding(binding(), [chiller(), lab_fail(**over)]))
        with pytest.raises(EngineError, match="never automates"):
            engine(plant, [chiller(), lab_fail(**over)], binding=BINDING)

    def test_unbound_pattern_using_never_automate_action_is_also_refused(self, plant):
        rogue = Pattern(id="qa_quick_release", description="x", event_types=["lab.fail"], route=Route.AUTO,
                        priority=5, allowed_actions=["dairy.release_batch"],
                        playbook=[PlaybookStep(action="dairy.release_batch", params={"batch": "{{payload.batch}}"})])
        with pytest.raises(EngineError, match="qa_quick_release"):
            engine(plant, [chiller(), lab_fail(), rogue], binding=BINDING)

    def test_held_at_a_person_when_the_check_is_skipped(self, plant, feed):
        bad = lab_fail(route=Route.AUTO, max_route=Route.AUTO, allowed_actions=["dairy.release_batch"],
                       playbook=[PlaybookStep(action="dairy.release_batch", params={"batch": "{{payload.batch}}"})])
        held = {p.id: p for p in enforce_never_automate(binding(), [chiller(), bad])}
        assert held["dairy_lab_fail"].max_route is Route.HITL and held["dairy_chiller"] == chiller()
        eng = engine(plant, [chiller(), bad], binding=BINDING, raise_on_invalid=False)
        r = eng.ingest(feed.lab())
        assert plant.ran("dairy.release_batch") == []
        assert eng.store.get_incident(r.incident_id).state is IncidentState.AWAITING_HUMAN
        with pytest.raises(EngineError):
            eng.set_route("dairy_lab_fail", Route.AUTO, actor="mdx")

    def test_model_proposing_a_never_automate_action_waits_for_a_person(self, plant, feed):
        llm = ScriptedLLM([{"final": {"action": "dairy.release_batch", "params": {"batch": "L1"},
                                      "disposition_code": "resolved", "confidence": 0.99, "rationale": "ok"}}])
        pats = [chiller(), lab_fail(route=Route.LLM, max_route=Route.LLM, allowed_actions=["dairy.hold"])]
        eng = engine(plant, pats, binding=BINDING, llm=llm)
        r = eng.ingest(feed.lab())
        assert plant.ran("dairy.release_batch") == []
        assert eng.store.get_incident(r.incident_id).state is IncidentState.AWAITING_HUMAN

    @pytest.mark.parametrize("edit", ["raise", "new_pattern"])
    def test_published_registry_cannot_reintroduce_it(self, plant, feed, edit):
        eng = engine(plant, [chiller(), lab_fail()], binding=BINDING)
        text = eng.config_text("registry")
        if edit == "raise":
            bad = text.replace("  max_route: hitl\n", "  max_route: auto\n")
        else:
            bad = text.replace("patterns:\n", "patterns:\n- id: sneaky\n  description: d\n  event_types: [lab.fail]\n"
                               "  route: auto\n  priority: 9\n  owner_role: plant_qa\n"
                               "  allowed_actions: [dairy.release_batch]\n  playbook:\n"
                               "  - action: dairy.release_batch\n    params: {batch: '{{payload.batch}}'}\n", 1)
        assert bad != text
        assert any("never automates" in m for m in messages(eng.check_config("registry", bad)[1]))
        cv, _ = eng.save_config("registry", bad, author="qa1")
        with pytest.raises(ConfigError):
            eng.publish_config(cv.id, "mdx")
        eng.ingest(feed.lab())
        assert plant.ran("dairy.release_batch") == []

    def test_engine_start_refuses_a_stored_registry_that_breaks_the_binding(self, plant, feed):
        # FIXED v0.22.2 (was DEFECT): a registry published before the binding existed, with an AUTO release_batch
        # pattern, was applied silently. Now it is never applied (the code / packs registry keeps running, like
        # any published configuration that fails to apply) and the refusal is audited as config_apply_failed.
        store = SQLiteStore(":memory:")
        first = engine(plant, [chiller(), lab_fail()], store=store)
        bad = first.config_text("registry").replace(
            "patterns:\n", "patterns:\n- id: sneaky\n  description: d\n  event_types: [lab.fail]\n  route: auto\n"
            "  priority: 9\n  owner_role: plant_qa\n  allowed_actions: [dairy.release_batch]\n  playbook:\n"
            "  - action: dairy.release_batch\n"
            "    params: {batch: '{{payload.batch}}'}\n", 1)
        cv, _ = first.save_config("registry", bad, author="qa1")
        first.publish_config(cv.id, "mdx")
        eng = engine(plant, [chiller(), lab_fail()], store=store, binding=BINDING)
        assert "sneaky" not in {p.id for p in eng.registry.all()}
        failed = eng.store.recent_audit(20, kinds=["config_apply_failed"])
        assert failed and "domain binding" in str(failed[0])
        eng.ingest(feed.lab())
        assert plant.ran("dairy.release_batch") == []

    def test_undeclared_slot_refused_at_start(self, plant):
        b = copy.deepcopy(BINDING)
        b["slots"] = ["accountable"]
        with pytest.raises(EngineError, match="slot"):
            engine(plant, [chiller(), lab_fail()], binding=b, slots={"other": "x"},
                   slot_bindings={"other": "plant_qa"})

    def test_binding_slot_refused_when_registry_declares_no_slots(self, plant):
        # FIXED v0.22.2 (was DEFECT): EXTENDING: engine start is refused for "an undeclared slot". Expected: a binding declaring
        # slots [accountable] on a registry that declares no slots at all is refused. Actual: accepted, because
        # the slot check only runs when the registry declares some slots. Repro: Overlay(binding with
        # slots=[accountable], no slots=) -> Engine starts; check_config("registry", config_text) -> no errors.
        b = copy.deepcopy(BINDING)
        b["slots"] = ["accountable"]
        with pytest.raises(EngineError, match="slot"):
            engine(plant, [chiller(), lab_fail()], binding=b)

    def test_overlay_without_binding_is_unchanged(self, plant, feed):
        pats = [chiller(trust_pool_min=None), lab_fail(max_route=Route.AUTO, route=Route.AUTO,
                                                      playbook=[PlaybookStep(action="dairy.release_batch",
                                                                             params={"batch": "{{payload.batch}}"})])]
        eng = engine(plant, pats)
        eng.ingest(feed.lab())
        assert plant.ran("dairy.release_batch") == ["L1"]


# ============================================================================== 4. fleet (v0.22.0)
@pytest.fixture
def sites(monkeypatch):
    versions: dict[str, str] = {}

    def fake_open(req, timeout, base_opener=None):
        host = req.full_url.split("//")[1].split(".")[0]
        body = {"version": versions[host], "health": "ok", "last_backup": "2026-10-19T00:00:00Z",
                "open_reviews": 0}
        return 200, {}, json.dumps(body).encode()

    monkeypatch.setattr(egress, "open_url", fake_open)
    monkeypatch.setenv("SENTINEL_SECRET_FLEET_DAIRY", "tok")
    return versions


def site(name: str, **kw: Any) -> fleet.Site:
    return fleet.Site(url=f"https://{name}.example", token_env="SENTINEL_SECRET_FLEET_DAIRY", **kw)


def rows(f: fleet.FleetFile) -> dict[str, dict]:
    return {r["name"]: r for r in fleet.collect(f, timeout_s=1)["sites"]}


class TestFleet:
    def test_site_target_overrides_fleet_target(self, sites):
        sites.update(a="0.20.0", b="0.20.0")
        f = fleet.FleetFile(target_version="0.22.0", latest_version="0.22.1",
                            sites={"a": site("a", target_version="0.20.0", adoption="dairy/SENTINEL_ADOPTION.md"),
                                   "b": site("b")})
        r = rows(f)
        assert "behind" not in r["a"]["flags"] and "behind" in r["b"]["flags"]
        assert r["a"]["target_version"] == "0.20.0" and r["a"]["adoption"] == "dairy/SENTINEL_ADOPTION.md"

    def test_behind_own_target_and_upgrade_uses_site_target(self, sites):
        sites.update(a="0.21.0")
        f = fleet.FleetFile(target_version="0.20.0", latest_version="0.22.1",
                            sites={"a": site("a", target_version="0.22.1")})
        r = rows(f)["a"]
        assert "behind" in r["flags"] and r["minors_behind"] == 1
        assert any("kbg-sentinel:0.22.1" in c for c in r["upgrade"])
        assert not any("0.20.0" in c for c in r["upgrade"])

    @pytest.mark.parametrize("version,window,outside", [
        ("0.22.0", 2, False), ("0.21.9", 2, False), ("0.20.5", 2, True), ("0.19.0", 2, True),
        ("0.21.0", 1, True), ("1.0.0", 2, True), ("0.23.0", 2, False)])
    def test_support_window(self, sites, version, window, outside):
        sites.update(a=version)
        f = fleet.FleetFile(latest_version="0.22.1", support_window=window, sites={"a": site("a")})
        assert ("outside support window" in rows(f)["a"]["flags"]) is outside

    def test_minors_behind(self):
        assert fleet.minors_behind("0.20.3", "0.22.1") == 2
        assert fleet.minors_behind("0.22.0", "0.22.1") == 0
        assert fleet.minors_behind("1.2.0", "0.22.1") >= 2

    def test_fleet_file_from_yaml(self, tmp_path, sites):
        sites.update(dairy="0.21.0")
        p = tmp_path / "fleet.yaml"
        p.write_text(yaml.safe_dump({"support_window": 2, "target_version": "0.22.1", "sites": {
            "dairy": {"url": "https://dairy.example", "token_env": "SENTINEL_SECRET_FLEET_DAIRY",
                      "target_version": "0.21.0", "adoption": "t/SENTINEL_ADOPTION.md"}}}), encoding="utf-8")
        f = fleet.load(str(p))
        assert f.sites["dairy"].target_version == "0.21.0" and f.support_window == 2
        assert "behind" not in rows(f)["dairy"]["flags"]
        assert any("0.21.0" in c for c in fleet.upgrade_commands(f, {"name": "dairy", "version": "0.20.0"}))


# ============================================================================== 5. dual run (v0.22.0)
def dual_engine(plant: Plant, *, match: dict | None = None, route: Route = Route.AUTO, action: str = "dairy.divert",
                owner: str = "plant_qa") -> Engine:
    warm = chiller(route=route, match=match or {"temp": {"gt": 7}}, owner_role=owner, trust_by=[],
                   trust_pool_min=None, escalation_role=None,
                   playbook=[PlaybookStep(action=action, params={"batch": "{{payload.batch}}"})])
    rest = Pattern(id="dairy_chiller_other", description="other", event_types=["chiller.warm"], priority=-1,
                   owner_role="plant_qa")
    return engine(plant, [warm, rest])


EVENTS_TEMPS = [9.0, 6.0, 8.0]


class TestDualRun:
    def events(self, feed: Feed) -> list[Event]:
        return [feed.warm("P1", t) for t in EVENTS_TEMPS]

    def test_trace_is_read_only(self, plant, feed):
        eng = dual_engine(plant)
        before = len(eng.store.audit_log())
        out = dualrun.trace_events(eng, self.events(feed), version="prod")
        assert [r["outcome"] for r in out] == ["automatic", "person", "automatic"]
        assert plant.calls == [] and len(eng.store.audit_log()) == before and eng.store.open_reviews() == []
        assert eng.store.incidents() == []

    def test_identical_pins_compare_clean(self, plant, feed):
        evs = self.events(feed)
        c = dualrun.compare(dualrun.trace_events(dual_engine(plant), evs),
                            dualrun.trace_events(dual_engine(plant), evs))
        assert c["patterns"] == {} and c["trust_guard"] == [] and c["unpaired"] == []

    @pytest.mark.parametrize("kw,field", [({"match": {"temp": {"gt": 5}}}, "pattern"),
                                          ({"route": Route.HITL}, "route"),
                                          ({"action": "dairy.hold"}, "actions"),
                                          ({"owner": "plant_head"}, "owner_role")])
    def test_compare_finds_each_kind_of_difference(self, plant, feed, kw, field):
        evs = self.events(feed)
        c = dualrun.compare(dualrun.trace_events(dual_engine(plant), evs),
                            dualrun.trace_events(dual_engine(plant, **kw), evs))
        changed = [e["changed"] for p in c["patterns"].values() for e in p["examples"]]
        assert changed and all(field in ch for ch in changed)

    def test_trust_guard_names_patterns_whose_outcome_differs(self, plant, feed):
        evs = self.events(feed)
        c = dualrun.compare(dualrun.trace_events(dual_engine(plant), evs),
                            dualrun.trace_events(dual_engine(plant, route=Route.HITL), evs))
        assert c["trust_guard"] == ["dairy_chiller"]
        widened = dualrun.compare(dualrun.trace_events(dual_engine(plant), evs),
                                  dualrun.trace_events(dual_engine(plant, match={"temp": {"gt": 5}}), evs))
        assert "dairy_chiller" in widened["trust_guard"]

    def test_unpaired_events_are_reported(self, plant, feed):
        prod = dualrun.trace_events(dual_engine(plant), self.events(feed))
        assert dualrun.compare(prod, prod[:2])["unpaired"] == [prod[2]["key"]]

    def _write(self, tmp_path, name: str, rows_: list[dict]) -> str:
        path = tmp_path / name
        dualrun.write_jsonl(rows_, path)
        return str(path)

    def test_cli_compare_exit_codes(self, plant, feed, tmp_path, capsys):
        evs = self.events(feed)
        prod = self._write(tmp_path, "p.jsonl", dualrun.trace_events(dual_engine(plant), evs))
        same = self._write(tmp_path, "s.jsonl", dualrun.trace_events(dual_engine(plant), evs))
        diff = self._write(tmp_path, "d.jsonl", dualrun.trace_events(dual_engine(plant, action="dairy.hold"), evs))
        assert cli.main(["dualrun", "compare", prod, same]) == 0
        assert cli.main(["dualrun", "compare", prod, diff]) == 1
        capsys.readouterr()

    def test_cli_compare_exits_1_when_only_the_owner_differs(self, plant, feed, tmp_path, capsys):
        # FIXED v0.22.2 (was DEFECT): CHANGELOG v0.22.0: the comparison gives differences "in match, route, outcome, proposed actions
        # and owner", and "`compare` exits 1 when anything differs". Expected: exit 1 when the candidate pin
        # routes cases to a different owner role. Actual: the owner difference is listed under "patterns" but
        # the exit code is 0, so an adoption script would treat a changed owner as "no differences".
        # Repro: two JSONL lines identical except owner_role -> `sentinel dualrun compare a b` returns 0.
        evs = self.events(feed)
        prod = self._write(tmp_path, "p.jsonl", dualrun.trace_events(dual_engine(plant), evs))
        cand = self._write(tmp_path, "c.jsonl", dualrun.trace_events(dual_engine(plant, owner="plant_head"), evs))
        assert cli.main(["dualrun", "compare", prod, cand]) == 1
        capsys.readouterr()

    def test_cli_trace_is_read_only(self, plant, tmp_path, monkeypatch, capsys):
        mod = tmp_path / "dairy_dual_overlay.py"
        mod.write_text(
            "from sentinel import ActionRegistry, ActionResult, FingerprintRule, Overlay, Pattern, PlaybookStep, Route\n"
            "RAN = []\n"
            "def build_overlay():\n"
            "    acts = ActionRegistry()\n"
            "    @acts.action('dairy.divert', reversible=True, params={'batch': 'str'}, description='d')\n"
            "    def f(ctx, p):\n"
            "        RAN.append(p)\n"
            "        return ActionResult(ok=True)\n"
            "    @f.compensator\n"
            "    def u(ctx, p):\n"
            "        return ActionResult(ok=True)\n"
            "    fp = [FingerprintRule(event_type='chiller.warm', fields={'plant': 'plant', 'batch': 'batch'})]\n"
            "    p = Pattern(id='dairy_chiller', description='d', event_types=['chiller.warm'], route=Route.AUTO,\n"
            "                allowed_actions=['dairy.divert'],\n"
            "                playbook=[PlaybookStep(action='dairy.divert', params={'batch': '{{payload.batch}}'})])\n"
            "    return Overlay(name='d', fingerprint_rules=fp, patterns=[p], actions=acts)\n", encoding="utf-8")
        monkeypatch.syspath_prepend(str(tmp_path))
        events = tmp_path / "events.jsonl"
        events.write_text("\n".join(json.dumps({"type": "chiller.warm", "source": "scada", "idempotency_key": k,
                                                "payload": {"plant": "P1", "batch": k}}) for k in ("b1", "b2")),
                          encoding="utf-8")
        db = tmp_path / "site.db"
        base = ["--overlay", "dairy_dual_overlay:build_overlay", "--db", str(db)]
        assert cli.main(base + ["dualrun", "trace", "--events", str(events), "--out", str(tmp_path / "o.jsonl")]) == 0
        out = dualrun.read_jsonl(tmp_path / "o.jsonl")
        assert [r["key"] for r in out] == ["b1", "b2"] and all(r["actions"] == ["dairy.divert"] for r in out)
        assert sys.modules["dairy_dual_overlay"].RAN == []
        st = SQLiteStore(str(db))
        assert st.incidents() == [] and st.audit_log() == []
        capsys.readouterr()

    def test_events_without_keys_pair_across_two_trace_runs(self, plant, feed):
        # FIXED v0.22.2 (was DEFECT): OPERATIONS: trace "the same events under each pin" and compare them. The documented events file
        # is {type, source, payload, idempotency_key}; for an event without idempotency_key the trace keys the line
        # by a random Event.id, so the same events.jsonl traced twice never pairs: everything is "unpaired", the
        # per-pattern differences are empty, and a real route change hides behind the unpaired list. Expected:
        # lines pair (e.g. by line number) and compare reports the route change. Actual: unpaired == all keys.
        raw = [{"type": "chiller.warm", "source": "scada", "payload": {"plant": "P1", "batch": f"B{i}", "temp": 9}}
               for i in range(2)]
        prod = dualrun.trace_events(dual_engine(plant), [Event.model_validate(r) for r in raw])
        cand = dualrun.trace_events(dual_engine(plant, route=Route.HITL), [Event.model_validate(r) for r in raw])
        c = dualrun.compare(prod, cand)
        assert c["unpaired"] == [] and c["trust_guard"] == ["dairy_chiller"]
