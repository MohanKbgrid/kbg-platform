# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""Branching playbooks: read-only lookups, conditions, close steps, per-branch dispositions."""
from __future__ import annotations

import hashlib
import json

import pytest
import yaml

from sentinel import Pattern, PlaybookStep, Route, Tool
from sentinel.registry import Registry, ceiling
from tests.conftest import make_overlay, stuck_event


def branching(**over):
    base = dict(id="item_stuck_long", event_types=["item.stuck"], match={"age": ">24h"}, route=Route.AUTO,
                allowed_actions=["hold", "notify"], owner_role="ops",
                disposition_codes=["resolved", "customer_told", "false_positive"],
                playbook=[
                    PlaybookStep(lookup="stock", args={"ref": "{{payload.ref}}"}, **{"as": "stock"}),
                    PlaybookStep(close=True, disposition="false_positive", when={"stock.status": "shipped"}),
                    PlaybookStep(action="hold", params={"ref": "{{payload.ref}}", "reason": "{{stock.where}}"},
                                 when={"stock.qty": {"gt": 0}}),
                    PlaybookStep(action="notify", params={"ref": "{{payload.ref}}", "msg": "delayed"},
                                 when={"stock.qty": {"lte": 0}}, disposition="customer_told"),
                ])
    base.update(over)
    return Pattern(**base)


@pytest.fixture
def stock():
    return {}


@pytest.fixture
def ov(backend, stock):
    o = make_overlay(backend, patterns=[branching()])

    def look(args, services):
        if stock.get("fail"):
            raise RuntimeError("WMS down")
        return stock.get(args["ref"], {"qty": 0, "where": "none", "status": "open"})
    o.tools.register(Tool("stock", "stock for an item", {"ref": "str"}, look))
    return o


def test_branch_on_a_lookup(engine_factory, ov, backend, stock):
    eng = engine_factory(ov=ov)
    stock["A"] = {"qty": 3, "where": "STORE_FLG", "status": "open"}
    eng.ingest(stuck_event(ref="A"))
    eng.ingest(stuck_event(ref="B"))                                        # no stock -> tell the customer
    assert backend.calls == [("hold", {"ref": "A", "reason": "STORE_FLG"}), ("notify", {"ref": "B", "msg": "delayed"})]
    codes = sorted(d.code for d in eng.store.dispositions("item_stuck_long"))
    assert codes == ["customer_told", "resolved"]


def test_close_step_closes_without_action(engine_factory, ov, backend, stock):
    eng = engine_factory(ov=ov)
    stock["C"] = {"qty": 5, "where": "x", "status": "shipped"}
    r = eng.ingest(stuck_event(ref="C"))
    assert backend.calls == [] and eng.store.get_disposition(r.incident_id).code == "false_positive"


def test_no_branch_or_failed_lookup_goes_to_a_person(engine_factory, ov, backend, stock):
    eng = engine_factory(ov=ov)
    stock["D"] = {"qty": None, "where": "?", "status": "open"}                # neither gt 0 nor lte 0
    r = eng.ingest(stuck_event(ref="D"))
    assert backend.calls == [] and eng.store.open_review_for(r.incident_id) is not None
    assert "playbook_no_branch" in [a["kind"] for a in eng.store.audit_log(r.incident_id)]
    stock["fail"] = True
    r2 = eng.ingest(stuck_event(ref="E"))
    assert "playbook did not apply" in eng.store.open_review_for(r2.incident_id).reason
    assert any(a["kind"] == "playbook_lookup_failed" and "WMS down" in a["data"]["error"]
               for a in eng.store.audit_log(r2.incident_id))


def test_validation(ov):
    bad = branching(playbook=[PlaybookStep(lookup="nope", **{"as": "x"}),
                              PlaybookStep(action="hold", params={"ref": "{{x.a|zap}}"}, when={"x.q": {"gt": 1, "zz": 0}}),
                              PlaybookStep(close=True, disposition="vanished")])
    probs = Registry([bad]).validate(ov.actions, set(ov.tools.tools))
    assert any("lookup tool 'nope' is not available" in p for p in probs)
    assert any("unknown filter 'zap'" in p for p in probs) and any("unknown operators" in p for p in probs)
    assert any("disposition 'vanished'" in p for p in probs)
    with pytest.raises(ValueError):
        PlaybookStep(action="hold", lookup="stock")
    with pytest.raises(ValueError):
        PlaybookStep(close=True)
    lookup_only = branching(route=Route.HITL, playbook=[PlaybookStep(lookup="stock")])
    assert ceiling(lookup_only) is Route.LLM
    with pytest.raises(Exception, match="AUTO route requires"):
        Registry([branching(playbook=[PlaybookStep(lookup="stock")])])


def test_action_only_playbooks_keep_their_hash():
    p = Pattern(id="x", event_types=["e"], route=Route.AUTO, allowed_actions=["a"],
                playbook=[PlaybookStep(action="a", params={"k": "{{payload.k}}"})])
    data = p.model_dump(mode="json", include=set(p._BEHAVIOUR_FIELDS))
    data["playbook"] = [{"action": "a", "params": {"k": "{{payload.k}}"}}]          # the v0.5 form
    old = hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()[:16]
    assert p.definition_hash() == old


def test_round_trip_through_configuration(engine_factory, ov):
    eng = engine_factory(ov=ov)
    text = eng.config_text("registry")
    doc = yaml.safe_load(text)
    steps = next(p for p in doc["patterns"] if p["id"] == "item_stuck_long")["playbook"]
    assert steps[0] == {"lookup": "stock", "args": {"ref": "{{payload.ref}}"}, "as": "stock"}
    assert steps[1] == {"close": True, "when": {"stock.status": "shipped"}, "disposition": "false_positive"}
    parsed, probs = eng.check_config("registry", text)
    assert not [p for p in probs if p.severity == "error"]
    assert parsed.patterns[0].definition_hash() == eng.registry.get("item_stuck_long").definition_hash()


def test_params_checked_against_declared_schemas():
    """D9: a playbook that could never run as written is refused when it is configured, not when a case hits it."""
    from sentinel.actions import ActionRegistry, schema_problems
    from sentinel.models import ActionSpec
    acts = ActionRegistry()
    acts.register(ActionSpec(name="hold", params_schema={"ref": "str", "days": "int", "note?": "str"}),
                  lambda *a: None)
    acts.register(ActionSpec(name="notify"), lambda *a: None)              # declares nothing: anything goes
    tools = {"stock": {"ref": "string", "depth?": "integer"}}
    p = branching(playbook=[
        PlaybookStep(lookup="stock", args={"ref": "{{payload.ref}}", "deep": True}, **{"as": "stock"}),
        PlaybookStep(action="hold", params={"ref": "{{payload.ref}}", "days": "three"}, when={"stock.qty": {"gt": 0}}),
        PlaybookStep(action="hold", params={"days": "{{payload.days}}", "note": 5}, when={"stock.qty": {"lt": 0}}),
        PlaybookStep(action="notify", params={"whatever": 1}, disposition="customer_told")])
    probs = Registry([p]).validate(acts, tools)
    assert any("step 1: stock: unexpected params ['deep']" in m for m in probs)
    assert any("step 2: hold: days must be int, got str 'three'" in m for m in probs)
    assert any("step 3: hold: missing param 'ref'" in m for m in probs)
    assert any("step 3: hold: note must be str" in m for m in probs)
    assert not any("step 3: hold: days" in m for m in probs)               # a whole template is checked at run time
    assert not any("notify" in m for m in probs)
    assert schema_problems("hold", {"n": "int"}, {"n": True}) == ["hold: n must be int, got bool"]
    assert schema_problems("t", {"n": "number"}, {"n": 2}) == []
    assert schema_problems("t", {"s": "str"}, {"s": "id-{{payload.x}}"}) == []
