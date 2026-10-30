# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""Data trust caps autonomy per scope; spot checks keep ACT honest; an agent incident is one step; two agents never
act alone on the same object. Proved on the R06 exemplar."""
from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest
import yaml

from sentinel import ActionRegistry, ActionResult, AuthorizationError, EngineError, Overlay, Route, load_layers
from sentinel import IncidentState as S
from sentinel.models import Event
from sentinel.rbac import parse_directory
from sentinel.testing import FrozenClock, engine_for

PACK = Path(__file__).parent / "packs" / "r06_stock_integrity"
NOW = datetime(2026, 10, 20, 9, 0, tzinfo=UTC)


class Store:
    def __init__(self):
        self.calls, self.undone = [], []


def actions(world):
    acts = ActionRegistry()

    @acts.action("task.shelf_check", reversible=True, params={"store": "str", "article": "str", "kind?": "str"},
                 description="raise a shelf-check task")
    def shelf(ctx, p):
        world.calls.append(("shelf", p["store"], p["article"]))
        return ActionResult(ok=True)

    @shelf.compensator
    def unshelf(ctx, p):
        world.undone.append(("shelf", p["store"], p["article"]))
        return ActionResult(ok=True)

    @acts.action("task.count", reversible=False, params={"store": "str", "article": "str"},
                 description="raise a count task")
    def count(ctx, p):
        world.calls.append(("count", p["store"], p["article"]))
        return ActionResult(ok=True)
    return acts


def directory():
    data = yaml.safe_load((PACK / "people_chain_a_org.yaml").read_text(encoding="utf-8"))
    data.pop("vacancy")
    data["oversight"] = [{"role": "internal_audit"}]
    data["authority"] += [{"role_id": "ops_head", "action": "__reverse__"},
                          {"role_id": "internal_audit", "action": "__reverse__"}]
    return parse_directory(data)


def engine(*layers, defaults=None):
    world = Store()
    live = {"overrides": [{"id": "r06_phantom_stock", "set": {"shadow": False, "route": "auto"}},
                          {"id": "r06_unrecorded_loss", "set": {"shadow": False, "route": "auto"}}]}
    if defaults:
        live["defaults"] = defaults
    doc = load_layers([PACK / "template.yaml", PACK / "tenant_chain_a.yaml", ("live", live), *layers])
    ov = Overlay(name="r06", fingerprint_rules=doc.fingerprints, patterns=doc.patterns, roles=doc.roles,
                 actions=actions(world), directory=directory(), slots=doc.slots, slot_bindings=doc.slot_bindings,
                 case_defaults=doc.defaults)
    clock = FrozenClock(NOW)
    return engine_for(ov, clock=clock), world, clock


def stopped(store, article="A1"):
    return Event(type="inv.sales_stopped", source="pos", payload={"store": store, "article": article, "book_qty": 4})


# ---- data trust ceilings -----------------------------------------------------------------------------

DT = {"data_trust": {"act_min": 0.95, "propose_min": 0.8, "max_age_hours": 24}}


def test_scope_data_trust_caps_the_mode():
    eng, world, _ = engine(defaults=DT)
    eng.set_data_trust({"store": "TVM01"}, 0.97, source="ira")
    eng.set_data_trust({"store": "TVM02"}, 0.90, source="ira")
    eng.set_data_trust({"store": "TVM03"}, 0.50, source="ira")
    a = eng.store.get_incident(eng.ingest(stopped("TVM01")).incident_id)
    b = eng.store.get_incident(eng.ingest(stopped("TVM02")).incident_id)
    c = eng.store.get_incident(eng.ingest(stopped("TVM03")).incident_id)
    assert a.state is S.DISPOSITIONED                                     # good data: acts
    assert b.state is S.AWAITING_HUMAN and b.route is Route.HITL and not b.shadow     # PROPOSE
    assert c.state is S.AWAITING_HUMAN and c.shadow                          # OBSERVE
    assert world.calls == [("shelf", "TVM01", "A1")]
    assert "act_min" in eng.trace(stopped("TVM02", "A9"))["route"]["why"]


def test_region_score_rolls_down_and_the_worst_score_wins():
    eng, _, _ = engine(defaults=DT)
    eng.set_data_trust({"region": "south"}, 0.85)
    eng.set_data_trust({"store": "TVM01"}, 0.99)
    cap, why = eng.data_trust_cap(eng.registry.get("r06_phantom_stock"), {"store": "TVM01"})
    assert cap == "PROPOSE" and "region=south" in why
    assert eng.data_trust_cap(eng.registry.get("r06_phantom_stock"), {"store": "COK01"}) == (None, "")


def test_stale_and_unknown_scores():
    eng, _, clock = engine(defaults={"data_trust": {**DT["data_trust"], "unknown": "propose"}})
    p = eng.registry.get("r06_phantom_stock")
    assert eng.data_trust_cap(p, {"store": "NEW"})[0] == "PROPOSE"        # unknown counts as PROPOSE here
    eng.set_data_trust({"store": "NEW"}, 0.99)
    assert eng.data_trust_cap(p, {"store": "NEW"})[0] is None
    clock.advance(hours=25)                                               # older than max_age_hours
    assert eng.data_trust_cap(p, {"store": "NEW"})[0] == "PROPOSE"


def test_band_changes_are_audited_and_input_is_checked():
    eng, _, _ = engine(defaults=DT)
    eng.set_data_trust({"store": "TVM01"}, 0.99)
    eng.set_data_trust({"store": "TVM01"}, 0.98)                          # same band: no row
    eng.set_data_trust({"store": "TVM01"}, 0.70)
    bands = [a["data"]["band"] for a in eng.store.recent_audit(20, kinds=["data_trust_band"])]
    assert sorted(bands) == ["ACT", "OBSERVE"]
    for bad in ({}, {"store": "A", "region": "B"}, {"store": {"x": 1}}):
        with pytest.raises(EngineError):
            eng.set_data_trust(bad, 0.9)
    for score in (-0.1, 1.5, float("nan"), "high"):
        with pytest.raises(EngineError):
            eng.set_data_trust({"store": "TVM01"}, score)
    assert {r["scope"]["store"]: r["band"] for r in eng.data_trust_scores()} == {"TVM01": "OBSERVE"}


def test_no_data_trust_configured_means_no_cap_and_exempt_patterns():
    eng, world, _ = engine()
    eng.set_data_trust({"store": "TVM01"}, 0.1)
    assert eng.store.get_incident(eng.ingest(stopped("TVM01")).incident_id).state is S.DISPOSITIONED
    eng2, _, _ = engine(("ex", {"overrides": [{"id": "r06_phantom_stock", "set": {"data_trust_exempt": True}}]}),
                        defaults=DT)
    eng2.set_data_trust({"store": "TVM01"}, 0.1)
    assert eng2.data_trust_cap(eng2.registry.get("r06_phantom_stock"), {"store": "TVM01"}) == (None, "")
    with pytest.raises(ValueError):
        engine(defaults={"data_trust": {"act_min": 0.5, "propose_min": 0.9}})


# ---- spot checks -------------------------------------------------------------------------------------

SPOT = ("spot", {"overrides": [{"id": "r06_phantom_stock", "set": {"spot_check_rate": 1.0}}]})


def test_unattended_decisions_are_sampled_for_a_person():
    eng, _, _ = engine(SPOT)
    inc = eng.ingest(stopped("TVM01")).incident_id
    assert eng.store.get_disposition(inc).spot_check == "pending"
    assert [r["incident"] for r in eng.spot_checks("meena")] == [inc]          # owner in scope
    assert [r["incident"] for r in eng.spot_checks("ganesh")] == [inc]         # oversight
    assert eng.spot_checks("arun") == []                                       # other store
    assert eng.spot_check_verdict(inc, "meena", True)["verdict"] == "passed"
    with pytest.raises(EngineError, match="already checked"):
        eng.spot_check_verdict(inc, "meena", True)


def test_a_failed_spot_check_undoes_and_demotes():
    eng, world, _ = engine(SPOT)
    inc = eng.ingest(stopped("TVM01")).incident_id
    with pytest.raises(EngineError, match="say what was wrong"):
        eng.spot_check_verdict(inc, "ganesh", False)
    res = eng.spot_check_verdict(inc, "ganesh", False, "the shelf was full; book stock was right")
    assert res["reversed"] and world.undone == [("shelf", "TVM01", "A1")]
    assert eng.effective_route(eng.registry.get("r06_phantom_stock"), {"store": "TVM01"}) is not Route.AUTO


def test_a_checker_without_reverse_still_demotes():
    eng, world, _ = engine(SPOT)
    inc = eng.ingest(stopped("TVM01")).incident_id
    res = eng.spot_check_verdict(inc, "meena", False, "wrong article")      # meena lacks __reverse__
    assert res["reversed"] is False and world.undone == []
    assert res["undo_by"] == {"roles": ["internal_audit", "ops_head"], "people": ["devi", "ganesh"], "can_undo": True,
                              "fallback": None}
    assert eng.store.get_disposition(inc).spot_check == "undo_pending"         # never a dead end
    assert [c["incident"] for c in eng.spot_checks("ganesh") if c["status"] == "undo_pending"] == [inc]
    assert eng.spot_checks("meena") == [] or all(c["incident"] != inc for c in eng.spot_checks("meena"))
    with pytest.raises(AuthorizationError):
        eng.spot_check_verdict(inc, "meena", False, "again")
    done = eng.spot_check_verdict(inc, "ganesh", False, "undo it")
    assert done["reversed"] and world.undone == [("shelf", "TVM01", "A1")]
    assert eng.effective_route(eng.registry.get("r06_phantom_stock"), {"store": "TVM01"}) is not Route.AUTO
    assert eng.store.get_disposition(inc).spot_check == "failed"
    other = eng.ingest(stopped("TVM02", "B2")).incident_id               # TVM02's trust is its own: still acts
    assert eng.store.get_disposition(other).spot_check == "pending"
    with pytest.raises(AuthorizationError):
        eng.spot_check_verdict(other, "meena", True)                      # not her store


def test_sampling_is_deterministic_and_off_by_default():
    eng, _, _ = engine(("half", {"overrides": [{"id": "r06_phantom_stock", "set": {"spot_check_rate": 0.5}}]}))
    p = eng.registry.get("r06_phantom_stock")
    picks = [eng._sampled(p, f"inc_{i}") for i in range(400)]
    assert picks == [eng._sampled(p, f"inc_{i}") for i in range(400)] and 120 < sum(picks) < 280
    plain, _, _ = engine()
    inc = plain.ingest(stopped("TVM01")).incident_id
    assert plain.store.get_disposition(inc).spot_check is None


# ---- agent incident ----------------------------------------------------------------------------------

def test_agent_incident_stops_lists_reviews_and_undoes():
    eng, world, clock = engine()
    ids = [eng.ingest(stopped(s, a)).incident_id for s, a in (("TVM01", "A1"), ("TVM02", "A2"), ("TVM01", "A3"))]
    with pytest.raises(AuthorizationError):
        eng.agent_incident("r06_phantom_stock", "meena", "bad tasks")          # owner may not
    rec = eng.agent_incident("r06_phantom_stock", "ganesh", "shelf tasks raised for full shelves", undo=True)
    assert {d["incident"] for d in rec["decisions"]} == set(ids) and set(rec["undone"]) == set(ids)
    assert len(world.undone) == 3 and rec["status"] == "open"
    assert eng.store.get_pattern_state("r06_phantom_stock").route is Route.HITL
    assert all(eng.store.get_disposition(i).spot_check == "reversed" for i in ids)    # undone: the check is settled
    assert eng.agent_incidents()[0]["id"] == rec["id"]
    with pytest.raises(EngineError, match="post-mortem"):
        eng.close_agent_incident(rec["id"], "ganesh", " ")
    closed = eng.close_agent_incident(rec["id"], "ganesh", "book stock feed lagged 6h; fixed the feed")
    assert closed["status"] == "closed" and closed["closed_by"] == "ganesh"


def test_agent_incident_on_one_scope_only():
    eng, world, _ = engine()
    a = eng.ingest(stopped("TVM01", "A1")).incident_id
    b = eng.ingest(stopped("TVM02", "A2")).incident_id
    assert eng.registry.get("r06_phantom_stock").trust_by == ["store"]
    rec = eng.agent_incident("r06_phantom_stock@store=TVM01", "ganesh", "TVM01 only")
    assert [d["incident"] for d in rec["decisions"]] == [a] and b not in rec["undone"]


# ---- object contention -------------------------------------------------------------------------------

CLAIMS = ("claims", {"overrides": [{"id": "r06_phantom_stock", "set": {"claims": ["store", "article"]}},
                                   {"id": "r06_unrecorded_loss", "set": {"claims": ["store", "article"],
                                                                         "claim_minutes": 30}}]})


def loss(store, article):
    return Event(type="inv.depletion_without_sales", source="pos", payload={"store": store, "article": article,
                                                                             "units": 3})


def test_a_second_template_on_the_same_object_goes_to_a_person():
    eng, world, clock = engine(CLAIMS)
    first = eng.store.get_incident(eng.ingest(stopped("TVM01", "A1")).incident_id)
    t = eng.trace(loss("TVM01", "A1"))                                    # trace agrees before it happens
    assert t["outcome"] == "person" and any("acting on" in s for s in t["steps"])
    second = eng.store.get_incident(eng.ingest(loss("TVM01", "A1")).incident_id)
    assert first.state is S.DISPOSITIONED and second.state is S.AWAITING_HUMAN
    assert "is acting on article=A1|store=TVM01" in eng.store.open_review_for(second.id).reason
    assert [a for a in eng.store.audit_log(second.id) if a["kind"] == "object_contention"]
    other = eng.store.get_incident(eng.ingest(loss("TVM01", "A2")).incident_id)      # another article: free
    assert other.state is S.DISPOSITIONED
    clock.advance(minutes=61)                                             # the claim lapses
    assert eng.object_claim(eng.registry.get("r06_unrecorded_loss"), {"store": "TVM01", "article": "A1"}) is None


def test_the_same_template_and_unidentified_objects_are_not_blocked():
    eng, world, _ = engine(CLAIMS)
    eng.ingest(stopped("TVM01", "A1"))
    eng.ingest(Event(type="inv.sales_stopped", source="pos", payload={"store": "TVM01", "article": "A9",
                                                                       "book_qty": 2}))
    assert eng.object_claim(eng.registry.get("r06_phantom_stock"), {"store": "TVM01", "article": "A1"}) is None
    assert eng.object_key(eng.registry.get("r06_phantom_stock"), {"store": "TVM01"}) is None
    no_claims, _, _ = engine()
    a = no_claims.store.get_incident(no_claims.ingest(stopped("TVM01", "A1")).incident_id)
    b = no_claims.store.get_incident(no_claims.ingest(loss("TVM01", "A1")).incident_id)
    assert a.state is S.DISPOSITIONED and b.state is S.DISPOSITIONED       # off unless claims are set


def test_a_wrong_verdict_on_an_already_reversed_case_does_not_demote_twice():
    eng, world, _ = engine(SPOT)
    inc = eng.ingest(stopped("TVM01")).incident_id
    eng.reverse(inc, "ganesh", "wrong")
    before = eng.store.get_pattern_state("r06_phantom_stock@store=TVM01").model_dump()
    res = eng.spot_check_verdict(inc, "ganesh", False, "wrong")
    assert res["already"] and eng.store.get_pattern_state("r06_phantom_stock@store=TVM01").model_dump() == before


def test_a_breaker_stop_releases_the_object_claim():
    from sentinel import Guardrails
    eng, world, _ = engine(CLAIMS)
    eng.guardrails = Guardrails(allow_irreversible_unattended=True, max_unattended_per_hour=0)
    inc = eng.store.get_incident(eng.ingest(stopped("TVM01", "A1")).incident_id)
    assert inc.state is S.AWAITING_HUMAN
    assert eng.object_claim(eng.registry.get("r06_unrecorded_loss"), {"store": "TVM01", "article": "A1"}) is None


def test_write_once_and_strict_inputs():
    """v0.24.0 tester defects 5, 8, 9, 10: closed incidents stay closed; bools and NaN are refused."""
    eng, _, _ = engine()
    eng.ingest(stopped("TVM01"))
    rec = eng.agent_incident("r06_phantom_stock", "ganesh", "x")
    eng.close_agent_incident(rec["id"], "ganesh", "first post-mortem")
    with pytest.raises(EngineError, match="already closed"):
        eng.close_agent_incident(rec["id"], "ganesh", "rewritten")
    assert eng.agent_incidents()[0]["postmortem"] == "first post-mortem"
    with pytest.raises(EngineError):
        eng.set_data_trust({"store": "TVM01"}, True)
    for h in (float("nan"), 1e12, 0, -1, True, "24"):
        with pytest.raises(EngineError):
            eng.agent_incident("r06_phantom_stock", "ganesh", "x", hours=h)
    inc = eng.ingest(stopped("TVM01", "Z9")).incident_id
    with pytest.raises(EngineError, match="true .* or false"):
        eng.spot_check_verdict(inc, "ganesh", "false")

