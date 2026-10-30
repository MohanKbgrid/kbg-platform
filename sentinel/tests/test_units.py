# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""Unit tests: fingerprinting, registry, actions, lifecycle, YAML loading."""
from __future__ import annotations

import pytest
from hypothesis import given, settings, strategies as st

from sentinel import (ActionRegistry, ActionResult, ActionSpec, Bucket, Event, FingerprintRule, Fingerprinter,
                      ParamError, Pattern, PlaybookStep, Registry, Route, load_registry)
from sentinel.actions import render
from sentinel.lifecycle import ALLOWED, IllegalTransition, can, transition
from sentinel.models import Incident, IncidentState as S
from sentinel.registry import RegistryError, ceiling

# ---------------------------------------------------------------- fingerprint

def test_facts_and_buckets():
    fp = Fingerprinter([FingerprintRule(event_type="x", fields={"site": "a.site"},
                                        buckets={"age": Bucket(field="age", edges=[4, 24],
                                                               labels=["<4h", "4-24h", ">24h"])})])
    e = Event(type="x", source="s", payload={"a": {"site": " S1 "}, "age": 30})
    f = fp.facts(e)
    assert f["site"] == "S1" and f["age"] == ">24h"
    assert fp.facts(Event(type="x", source="s", payload={"age": "bad"}))["age"] is None
    assert fp.facts(Event(type="x", source="s", payload={"age": 4}))["age"] == "4-24h"  # edge is exclusive upper


def test_unknown_event_type_still_fingerprints():
    fp = Fingerprinter()
    e = Event(type="nobody.knows", source="s", payload={"z": 1})
    assert fp.signature(e).startswith("default|nobody.knows")


def test_bucket_validation():
    with pytest.raises(ValueError):
        FingerprintRule(event_type="x", buckets={"a": Bucket(field="a", edges=[1, 2], labels=["x", "y"])})
    with pytest.raises(ValueError):
        FingerprintRule(event_type="x", buckets={"a": Bucket(field="a", edges=[2, 1], labels=["x", "y", "z"])})
    with pytest.raises(ValueError):
        Fingerprinter([FingerprintRule(event_type="x"), FingerprintRule(event_type="x")])


def test_blank_event_type_rejected():
    with pytest.raises(ValueError):
        Event(type="  ", source="s")


@settings(max_examples=60)
@given(st.dictionaries(st.text(min_size=1, max_size=6), st.integers() | st.text(max_size=8), max_size=6))
def test_signature_independent_of_key_order(payload):
    fp = Fingerprinter([FingerprintRule(event_type="x", fields={k: k for k in payload})])
    a = Event(type="x", source="s", payload=payload)
    b = Event(type="x", source="s", payload=dict(reversed(list(payload.items()))))
    assert fp.signature(a) == fp.signature(b)


def test_tenants_never_share_signatures():
    fp = Fingerprinter([FingerprintRule(event_type="x", fields={"k": "k"})])
    a = Event(type="x", source="s", tenant="t1", payload={"k": 1})
    b = Event(type="x", source="s", tenant="t2", payload={"k": 1})
    assert fp.signature(a) != fp.signature(b)

# ---------------------------------------------------------------- registry

def _p(**kw):
    base = dict(id="p", event_types=["e"])
    base.update(kw)
    return Pattern(**base)


def test_match_specificity_priority_and_fallback():
    reg = Registry([_p(id="any", match={"a": "*"}), _p(id="specific", match={"a": 1, "b": 2}),
                    _p(id="prio", match={"c": 1}, priority=5)])
    assert reg.match("e", {"a": 1, "b": 2}).id == "specific"
    assert reg.match("e", {"a": 9}).id == "any"
    assert reg.match("e", {"a": 1, "b": 2, "c": 1}).id == "prio"
    assert reg.match("e", {}).id == "__unmatched__"
    assert reg.match("other", {"a": 1}).id == "__unmatched__"


def test_registry_rejects_bad_patterns():
    with pytest.raises(RegistryError):
        Registry([_p(route=Route.AUTO)])                          # auto without playbook
    with pytest.raises(RegistryError):
        Registry([_p(route=Route.LLM, max_route=Route.HITL)])     # route above ceiling
    with pytest.raises(RegistryError):
        Registry([_p(), _p()])                                    # duplicate
    with pytest.raises(RegistryError):
        Registry([_p(llm_min_confidence=1.5)])
    with pytest.raises(RegistryError):
        Registry([_p(sla_minutes=0)])


def test_registry_validate_against_actions():
    acts = ActionRegistry()
    acts.register(ActionSpec(name="a"), lambda c, p: ActionResult(ok=True))
    reg = Registry([_p(allowed_actions=["a", "ghost"], playbook=[PlaybookStep(action="b")], inhibited_by=["nope"])])
    problems = reg.validate(acts)
    assert any("ghost" in x for x in problems)
    assert any("'b'" in x for x in problems)
    assert any("nope" in x for x in problems)


def test_ceiling_caps_auto_without_playbook():
    assert ceiling(_p()) is Route.LLM
    assert ceiling(_p(playbook=[PlaybookStep(action="a")])) is Route.AUTO
    assert ceiling(_p(max_route=Route.HITL)) is Route.HITL

# ---------------------------------------------------------------- actions

def test_param_validation():
    acts = ActionRegistry()
    acts.register(ActionSpec(name="a", params_schema={"ref": "str", "qty": "int", "note?": "str"}),
                  lambda c, p: ActionResult(ok=True))
    assert acts.validate_params("a", {"ref": "x", "qty": 2}) == {"ref": "x", "qty": 2}
    assert acts.validate_params("a", {"ref": "x", "qty": 2, "note": None}) == {"ref": "x", "qty": 2}
    for bad in ({"qty": 1}, {"ref": "x", "qty": "2"}, {"ref": "x", "qty": True},
                {"ref": "x", "qty": 1, "extra": 1}, "not-a-dict"):
        with pytest.raises(ParamError):
            acts.validate_params("a", bad)  # type: ignore[arg-type]


def test_reversible_requires_compensator():
    acts = ActionRegistry()
    with pytest.raises(ValueError):
        acts.register(ActionSpec(name="r", reversible=True), lambda c, p: ActionResult(ok=True))
    acts.register(ActionSpec(name="x"), lambda c, p: ActionResult(ok=True))
    with pytest.raises(ValueError):
        acts.register(ActionSpec(name="x"), lambda c, p: ActionResult(ok=True))
    with pytest.raises(KeyError):
        acts.get("missing")


def test_render_templates_keep_types():
    scope = {"payload": {"id": 7, "name": "A", "nested": {"x": [1]}}}
    assert render("{{payload.id}}", scope) == 7
    assert render("order {{payload.name}}-{{payload.missing}}", scope) == "order A-"
    assert render({"a": ["{{payload.nested.x}}"]}, scope) == {"a": [[1]]}

# ---------------------------------------------------------------- lifecycle

def test_terminal_state_has_no_exits():
    assert ALLOWED[S.DISPOSITIONED] == set()
    inc = Incident(pattern_id="p", fingerprint="f", route=Route.HITL, state=S.DISPOSITIONED)
    with pytest.raises(IllegalTransition):
        transition(inc, S.OPEN)


@settings(max_examples=200)
@given(st.lists(st.sampled_from(list(S)), max_size=12))
def test_random_walks_respect_graph(steps):
    inc = Incident(pattern_id="p", fingerprint="f", route=Route.HITL)
    for dst in steps:
        before = inc.state
        if can(before, dst):
            transition(inc, dst)
            assert inc.state is dst
        else:
            with pytest.raises(IllegalTransition):
                transition(inc, dst)
            assert inc.state is before

# ---------------------------------------------------------------- yaml

def test_load_registry_validates(tmp_path):
    good = tmp_path / "r.yaml"
    good.write_text("""
roles: {ops: operator}
fingerprints:
  - event_type: e
    fields: {k: k}
patterns:
  - id: p
    event_types: [e]
    owner_role: ops
""")
    doc = load_registry(good)
    assert doc.patterns[0].id == "p" and doc.fingerprints[0].event_type == "e"
    bad_role = tmp_path / "b.yaml"
    bad_role.write_text("roles: {ops: x}\npatterns:\n  - {id: p, event_types: [e], owner_role: ghost}\n")
    with pytest.raises(ValueError, match="unknown role"):
        load_registry(bad_role)
    bad_key = tmp_path / "c.yaml"
    bad_key.write_text("patternz: []\n")
    with pytest.raises(ValueError, match="unknown top-level"):
        load_registry(bad_key)
