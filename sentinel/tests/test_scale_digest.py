# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""Backlog after the overhaul: past a scope threshold a template goes out as one digest ranked by money at stake
instead of a card per case; the queue ranks by money; escalate_to never names a role past the stop list."""
from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import yaml

from sentinel import Overlay, load_layers
from sentinel.models import Event, PlaybookStep
from sentinel.org import Agent, authorise
from sentinel.rbac import parse_directory
from sentinel.testing import FrozenClock, engine_for
from tests.test_role_slots import _actions

PACK = Path(__file__).parent / "packs" / "r06_stock_integrity"
NOW = datetime(2026, 10, 20, 9, 0, tzinfo=UTC)


class Mailbox:
    def __init__(self):
        self.sent = []

    def send_text(self, contact, subject, text):
        self.sent.append((contact.get("email"), subject, text))


def directory():
    data = yaml.safe_load((PACK / "people_chain_a_org.yaml").read_text(encoding="utf-8"))
    for p in data["people"]:
        p["contact"] = {"email": f"{p['id']}@chain.example"}
        p["edges"] = ["mail"]
    data["authority"] += [{"role_id": "store_manager", "action": "stock.adjust", "max_amount": 5000},
                          {"role_id": "ops_head", "action": "stock.adjust"}]
    data.pop("vacancy")
    d = parse_directory(data)
    d.clock = lambda: NOW          # the fixture has dated cover periods: ask at the frozen date, never the wall clock
    return d


def engine(threshold=2, money="value"):
    over = {"digest_above": threshold, "money_fact": money, "digest_every_minutes": 60,
            "pause_on": ["waiting_on_store"]}
    doc = load_layers([PACK / "template.yaml", PACK / "tenant_chain_a.yaml",
                       ("scale", {"overrides": [{"id": "r06_unrecorded_loss", "set": over}],
                                  "fingerprints": [{"event_type": "inv.depletion_without_sales",
                                                    "fields": {"store": "store", "article": "article",
                                                               "units": "units", "value": "value"},
                                                    "group_by": ["store", "article"]}]})])
    box = Mailbox()
    clock = FrozenClock(NOW)
    ov = Overlay(name="r06", fingerprint_rules=doc.fingerprints, patterns=doc.patterns, roles=doc.roles,
                 actions=_actions(), directory=directory(), slots=doc.slots, slot_bindings=doc.slot_bindings,
                 edges={"mail": box}, default_edges=["mail"])
    return engine_for(ov, clock=clock), box, clock


def loss(article, value, store="TVM01"):
    return Event(type="inv.depletion_without_sales", source="pos",
                 payload={"store": store, "article": article, "units": 3, "value": value})


def test_cards_until_the_threshold_then_the_digest():
    eng, box, _ = engine(threshold=2)
    ids = [eng.ingest(loss(f"A{i}", v)).incident_id for i, v in enumerate([100, 9000, 450, 3000])]
    reviews = [eng.store.open_review_for(i) for i in ids]
    assert [r.digested for r in reviews] == [False, False, True, True]
    assert [eng.store.live_work_for(i, "deliver") > 0 for i in ids] == [True, True, False, False]   # no cards
    assert any(a["data"].get("digested") for a in eng.store.audit_log(ids[2]) if a["kind"] == "review_opened")


def test_the_digest_is_ranked_by_money_and_goes_to_the_holders_in_scope():
    eng, box, clock = engine(threshold=1)
    for i, v in enumerate([100, 9000, 450]):
        eng.ingest(loss(f"A{i}", v))
    eng.ingest(loss("B1", 70000, store="TVM02"))
    box.sent.clear()
    sent = eng.send_template_digests()
    assert sent and sent[0]["pattern"] == "r06_unrecorded_loss" and sent[0]["cases"] == 3   # first case was a card
    to_kavya = [m for m in box.sent if m[0] == "kavya@chain.example"]
    assert len(to_kavya) == 1
    subject, text = to_kavya[0][1], to_kavya[0][2]
    assert "3 open r06_unrecorded_loss" in subject and "79,450 at stake" in subject
    lines = [x for x in text.splitlines() if x[:2] in ("1.", "2.", "3.")]
    assert "70,000" in lines[0] and "9,000" in lines[1] and "450" in lines[2]
    assert eng.send_template_digests() == []                     # not again within the hour
    clock.advance(minutes=61)
    assert eng.send_template_digests()


def test_template_digest_view_and_ranked_queue():
    eng, _, _ = engine(threshold=1)
    for i, v in enumerate([100, 9000, "n/a"]):
        eng.ingest(loss(f"A{i}", v))
    dig = eng.template_digest("r06_unrecorded_loss")
    assert [c["money"] for c in dig["cases"]] == [9000, 100, 0] and dig["money_total"] == 9100
    ranked = eng.ranked_reviews("kavya")
    assert [r["money"] for r in ranked] == [9000, 100, 0]
    assert ranked[0]["digested"] and ranked[0]["pattern"] == "r06_unrecorded_loss"
    assert eng.ranked_reviews("meena") == []                       # not her queue


def test_digested_cases_can_be_decided_in_bulk():
    eng, _, _ = engine(threshold=1)
    for i in range(4):
        eng.ingest(loss(f"A{i}", 100 * i))
    ids = [r["review"] for r in eng.ranked_reviews("kavya")]
    res = eng.decide_many(ids, "approve", actor="kavya")
    assert len(res["decided"]) == 4 and not res["refused"]


def test_no_threshold_means_no_change():
    eng, _, _ = engine(threshold=None, money=None)
    ids = [eng.ingest(loss(f"A{i}", 10)).incident_id for i in range(5)]
    assert not any(eng.store.open_review_for(i).digested for i in ids)
    assert eng.send_template_digests() == []
    assert all(r["money"] == 0 for r in eng.ranked_reviews("kavya"))


def test_escalation_still_happens_and_a_digested_case_stays_on_the_digest():
    eng, _, clock = engine(threshold=1)
    ids = [eng.ingest(loss(f"A{i}", 10)).incident_id for i in range(3)]
    clock.advance(minutes=300)                                 # past the 240-minute SLA
    eng.sweep()
    after = [eng.store.open_review_for(i) for i in ids]
    assert all(r.escalation_level == 1 and r.assignee_role == "regional_manager" for r in after)
    assert [r.digested for r in after] == [False, True, True]
    assert [eng.store.live_work_for(i, "deliver") > 0 for i in ids[1:]] == [False, False]


# ---- escalate_to never past the stop list ------------------------------------------------------------

def test_escalate_to_is_capped_at_the_stop_list():
    d = directory()
    big = [PlaybookStep(action="stock.adjust", params={"amount": 20000})]
    auth = d.authorize_steps("meena", "p", "store_manager", big, {"store": "TVM01"})
    assert not auth.allowed and auth.escalate_to == "regional_manager"       # ops_head could, but is past the stop
    dec = authorise(d, Agent("a", bound_role="store_manager"), "stock.adjust", "A", {"store": "TVM01"}, 20000)
    assert not dec and dec.escalate_to == "regional_manager"
    person = authorise(d, "meena", "stock.adjust", "A", {"store": "TVM01"}, 20000)
    assert not person and person.escalate_to == "regional_manager"
    assert d.cap_escalation("store_manager", "ops_head") == "regional_manager"
    assert d.cap_escalation("store_manager", "regional_manager") == "regional_manager"
    assert d.cap_escalation("slp_officer", "ops_head") == "slp_officer"       # its own role is a stop
    assert d.cap_escalation("store_manager", "category_buyer") == "category_buyer"   # not above it: unchanged


def test_without_a_stop_list_escalate_to_is_unchanged():
    data = yaml.safe_load((PACK / "people_chain_a.yaml").read_text(encoding="utf-8"))
    data["authority"] += [{"role_id": "ops_head", "action": "stock.adjust"}]
    d = parse_directory(data)
    auth = d.authorize_steps("meena", "p", "store_manager", [PlaybookStep(action="stock.adjust",
                                                                          params={"amount": 1})], {"store": "TVM01"})
    assert auth.escalate_to == "ops_head"
    assert d.cap_escalation("store_manager", "ops_head") == "ops_head"


def test_a_stop_role_holder_is_not_pointed_back_at_their_own_role():
    d = directory()
    big = [PlaybookStep(action="stock.adjust", params={"amount": 20000})]
    auth = d.authorize_steps("suresh", "p", "store_manager", big, {"store": "TVM01"})   # suresh: regional (a stop)
    assert not auth.allowed and auth.escalate_to is None and "past the stop list" in auth.reason
    dec = authorise(d, "suresh", "stock.adjust", "A", {"store": "TVM01"}, 20000)
    assert not dec and dec.escalate_to is None and "past the stop list" in dec.reason
    ag = authorise(d, Agent("a", bound_role="regional_manager"), "stock.adjust", "A", {"store": "TVM01"}, 20000)
    assert not ag and ag.escalate_to is None


def test_digests_skip_held_quiet_and_odd_money():
    eng, box, clock = engine(threshold=1)
    ids = [eng.ingest(loss(f"A{i}", v)).incident_id for i, v in enumerate([5, "nan", "inf", 700])]
    assert [c["money"] for c in eng.template_digest("r06_unrecorded_loss")["cases"]] == [700, 5, 0, 0]
    held = eng.store.open_review_for(ids[3])
    eng.pause_review(held.id, "kavya", "waiting_on_store")
    quiet = eng.store.open_review_for(ids[1])
    quiet.quiet = True
    eng.store.put_review(quiet)
    sent = eng.send_template_digests(force=True)
    assert sent and sent[0]["cases"] == 1                         # only ids[2]: ids[0] was a card


def test_a_digested_case_never_reaches_nobody():
    class CardOnly:                                           # an edge that can deliver cards but not text
        def __init__(self):
            self.cards = []

        def send(self, *a, **k):
            self.cards.append(a)
    eng, box, _ = engine(threshold=1)
    eng.overlay.edges["mail"] = CardOnly()
    ids = [eng.ingest(loss(f"A{i}", 10)).incident_id for i in range(3)]
    res = eng.send_template_digests(force=True)
    assert res[0]["sent"] == [] and res[0]["released_to_cards"] == 2 and res[0]["missed"]
    assert not any(eng.store.open_review_for(i).digested for i in ids)
    assert all(eng.store.live_work_for(i, "deliver") > 0 for i in ids)


def test_removing_the_setting_releases_digested_cases_to_cards():
    eng, _, clock = engine(threshold=1)
    ids = [eng.ingest(loss(f"A{i}", 10)).incident_id for i in range(3)]
    assert [eng.store.open_review_for(i).digested for i in ids] == [False, True, True]
    from sentinel.config import dump_yaml
    doc = yaml.safe_load(eng.config_text("registry"))
    for p in doc["patterns"]:
        p.pop("digest_above", None)
    cv, _ = eng.save_config("registry", dump_yaml(doc), author="devi")
    eng.publish_config(cv.id, "devi")
    assert not any(eng.store.open_review_for(i).digested for i in ids)
    assert all(eng.store.live_work_for(i, "deliver") > 0 for i in ids)


def test_unknown_template_digest_is_a_clear_error():
    import pytest as _pt

    from sentinel import EngineError
    eng, _, _ = engine()
    with _pt.raises(EngineError, match="unknown pattern"):
        eng.template_digest("ghost")
