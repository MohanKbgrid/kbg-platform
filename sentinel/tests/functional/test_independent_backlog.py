# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""Independent black-box journeys for v0.23.0: digests past a threshold ranked by money (``digest_above``,
``digest_every_minutes``, ``money_fact``), ``escalate_to`` capped at the stop list, and the console's Agents &
oversight page with money ordering on Reviews. Written from CHANGELOG, OVERLAY_CONTRACT ("Many open cases",
"The org layer", "The authority contract", "Agents", "Oversight") and public signatures/docstrings only.

Domain: hospital revenue cycle. Insurance claim denials are worked per unit; units roll up to hospitals (U1, U2 ->
H1; U3 -> H2). Billing executives own denials, the billing manager covers H1, the finance head and the CFO sit
above (both on the stop list), internal audit oversees every agent. Bed-block alerts are a second template.

Tests that expose a framework defect carry ``# FIXED v0.23.0 before push (was DEFECT):`` with expected vs actual and are left failing.
"""
from __future__ import annotations

import copy
import socket
import threading
import time
from datetime import UTC, date, datetime
from typing import Any

import pytest
import yaml

from sentinel import (ActionRegistry, ActionResult, Decision, DecisionKind, Engine, Event, Guardrails, MemoryEdge,
                      Overlay, Pattern, PlaybookStep, SQLiteStore)
from sentinel.org import Agent, authorise
from sentinel.overlay import parse_registry
from sentinel.rbac import parse_directory
from sentinel.testing import FrozenClock, engine_for

NOW = datetime(2026, 10, 20, 9, 0, tzinfo=UTC)

PEOPLE: dict[str, Any] = {
    "roles": {"cfo": {}, "finance_head": {"parent": "cfo"}, "billing_manager": {"parent": "finance_head"},
              "billing_exec": {"parent": "billing_manager", "dotted": ["audit"]},
              "audit": {"parent": "cfo"}, "supervisor": {"parent": "cfo"}},
    "scopes": {"unit": {"rolls_up_to": "hospital", "parents": {"U1": "H1", "U2": "H1", "U3": "H2"}}},
    "stop_at": ["finance_head", "cfo"],
    "people": [{"id": "bea", "contact": {"email": "bea@hosp.in"}, "edges": ["mail"]},
               {"id": "ben", "contact": {"email": "ben@hosp.in"}},
               {"id": "mgr", "contact": {"email": "mgr@hosp.in"}},
               {"id": "fh", "contact": {"email": "fh@hosp.in"}},
               {"id": "cfo1", "contact": {"email": "cfo@hosp.in"}},
               {"id": "aud", "contact": {"email": "aud@hosp.in"}},
               {"id": "old", "active": False, "contact": {"email": "old@hosp.in"}},
               {"id": "loc", "contact": {"email": "loc@hosp.in"}}],
    "assignments": [
        {"person_id": "bea", "role_id": "billing_exec", "scope": {"unit": "U1"}},
        {"person_id": "ben", "role_id": "billing_exec", "scope": {"unit": "U3"}},
        {"person_id": "old", "role_id": "billing_exec", "scope": {"unit": "U1"}},
        {"person_id": "loc", "role_id": "billing_exec", "scope": {"unit": "U1"}, "valid_from": date(2026, 10, 25)},
        {"person_id": "mgr", "role_id": "billing_manager", "scope": {"hospital": "H1"}},
        {"person_id": "fh", "role_id": "finance_head"},
        {"person_id": "cfo1", "role_id": "cfo"}, {"person_id": "cfo1", "role_id": "supervisor"},
        {"person_id": "aud", "role_id": "audit"}],
    "authority": [
        {"role_id": "billing_exec", "action": "resubmit", "max_amount": 1000},
        {"role_id": "billing_manager", "action": "resubmit", "max_amount": 5000},
        {"role_id": "finance_head", "action": "resubmit", "max_amount": 20000},
        {"role_id": "cfo", "action": "resubmit"},
        {"role_id": "billing_exec", "action": "release_bed"},
        {"role_id": "cfo", "action": "__configure__"}, {"role_id": "cfo", "action": "__silence__"}],
    "oversight": [{"role": "audit", "templates": ["*"]}],
}

REG: dict[str, Any] = {
    "fingerprints": [
        {"event_type": "claim.denied", "fields": {"unit": "unit", "claim": "claim", "amount": "amount"},
         "group_by": ["claim"]},
        {"event_type": "bed.blocked", "fields": {"unit": "unit", "bed": "bed"}, "group_by": ["bed"]}],
    "patterns": [
        {"id": "claim_denied", "description": "Insurance claim denied", "event_types": ["claim.denied"],
         "route": "hitl", "max_route": "hitl", "sla_minutes": 30, "pause_on": ["awaiting_payer"],
         "playbook": [{"action": "resubmit", "params": {"claim": "{{payload.claim}}"}}],
         "allowed_actions": ["resubmit"], "owner_role": "billing_exec",
         "digest_above": 3, "money_fact": "amount"},
        {"id": "bed_blocked", "description": "Bed blocked", "event_types": ["bed.blocked"], "route": "hitl",
         "max_route": "hitl", "allowed_actions": ["release_bed"], "owner_role": "billing_exec", "sla_minutes": 30}],
}


class Mail:
    """A text-capable edge: cards and digests are both recorded."""
    name = "mail"

    def __init__(self) -> None:
        self.cards: list[Any] = []
        self.texts: list[tuple[dict, str, str]] = []

    def deliver(self, card: Any) -> str:
        self.cards.append(card)
        return "ok"

    def send_text(self, contact: dict, subject: str, text: str) -> None:
        self.texts.append((contact, subject, text))


def _actions() -> ActionRegistry:
    acts = ActionRegistry()

    @acts.action("resubmit", reversible=False, params={"claim": "str", "amount?": "float"}, description="resubmit")
    def resubmit(ctx, p):
        return ActionResult(ok=True)

    @acts.action("release_bed", reversible=False, params={"bed": "str"}, description="release a bed")
    def release(ctx, p):
        return ActionResult(ok=True)
    return acts


def reg(**pattern_changes: Any) -> dict[str, Any]:
    r = copy.deepcopy(REG)
    for k, v in pattern_changes.items():
        if v is None:
            r["patterns"][0].pop(k, None)
        else:
            r["patterns"][0][k] = v
    return r


def people(**changes: Any) -> dict[str, Any]:
    p = copy.deepcopy(PEOPLE)
    for k, v in changes.items():
        if v is None:
            p.pop(k, None)
        else:
            p[k] = v
    return p


def overlay(registry: dict | None = None, ppl: dict | None = None, edge: Any = None) -> Overlay:
    doc = parse_registry(copy.deepcopy(registry or REG))
    edge = edge if edge is not None else Mail()
    return Overlay(name="hospital", fingerprint_rules=doc.fingerprints, patterns=doc.patterns, roles=doc.roles,
                   actions=_actions(), directory=parse_directory(copy.deepcopy(ppl or PEOPLE)),
                   edges={edge.name: edge}, default_edges=[edge.name])


def rig(registry: dict | None = None, ppl: dict | None = None, edge: Any = None):
    ov = overlay(registry, ppl, edge)
    clock = FrozenClock(NOW)
    eng = engine_for(ov, clock=clock, guardrails=Guardrails())
    return eng, ov.edges[next(iter(ov.edges))], clock


_n = [0]


def claim(eng, unit: str = "U1", amount: Any = 100, **extra: Any):
    _n[0] += 1
    r = eng.ingest(Event(type="claim.denied", source="his", idempotency_key=f"c{_n[0]}",
                         payload={"unit": unit, "claim": f"CL{_n[0]}", "amount": amount, **extra}))
    return eng.store.open_review_for(r.incident_id)


def bed(eng, unit: str = "U1"):
    _n[0] += 1
    r = eng.ingest(Event(type="bed.blocked", source="his", idempotency_key=f"b{_n[0]}",
                         payload={"unit": unit, "bed": f"B{_n[0]}"}))
    return eng.store.open_review_for(r.incident_id)


def carded(edge: Any) -> set[str]:
    return {c.review_id for c in edge.cards}


def kinds(eng) -> list[str]:
    return [a["kind"] for a in eng.store.audit_log()]


def sent_to(out: list[dict]) -> dict[str, int]:
    return {s["person"]: s["cases"] for o in out for s in o["sent"]}


# ============================================================================== 1. threshold
class TestThreshold:
    def test_cards_stop_exactly_past_the_threshold(self):
        eng, mail, _ = rig()
        rs = [claim(eng, amount=a) for a in (10, 20, 30, 40, 50)]
        eng.work("w", limit=100)
        assert [r.digested for r in rs] == [False, False, False, True, True]
        assert carded(mail) == {r.id for r in rs[:3]}

    def test_threshold_of_one(self):
        eng, mail, _ = rig(reg(digest_above=1))
        a, b = claim(eng), claim(eng)
        eng.work("w", limit=100)
        assert (a.digested, b.digested) == (False, True) and carded(mail) == {a.id}

    def test_other_templates_do_not_count(self):
        eng, mail, _ = rig()
        beds = [bed(eng) for _ in range(6)]
        rs = [claim(eng) for _ in range(3)]
        assert not any(r.digested for r in rs + beds)
        assert claim(eng).digested

    def test_closed_cases_do_not_count(self):
        eng, mail, _ = rig()
        rs = [claim(eng) for _ in range(3)]
        for r in rs[:2]:
            eng.decide(r.id, Decision(kind=DecisionKind.REJECT, actor="bea", disposition_code="no_action"))
        assert not claim(eng).digested                    # 1 open + this one: below the threshold again

    def test_no_settings_no_change(self):
        eng, mail, _ = rig(reg(digest_above=None, money_fact=None))
        rs = [claim(eng) for _ in range(8)]
        eng.work("w", limit=100)
        assert carded(mail) == {r.id for r in rs} and not any(r.digested for r in rs)
        assert eng.send_template_digests(force=True) == []
        assert "template_digest_sent" not in kinds(eng)

    def test_settings_validated(self):
        with pytest.raises(ValueError):
            Pattern(id="x", event_types=["a"], digest_above=0)
        with pytest.raises(ValueError):
            Pattern(id="x", event_types=["a"], digest_every_minutes=1)


# ============================================================================== 2. digest content and money
class TestMoney:
    def test_digest_ranked_by_money_and_audited(self):
        eng, mail, _ = rig()
        for a in (1, 2, 3, 400, 9000, 75):
            claim(eng, amount=a)
        out = eng.send_template_digests()
        assert sent_to(out) == {"bea": 3}
        (contact, subject, text) = mail.texts[0]
        assert contact["email"] == "bea@hosp.in" and "9,475" in subject and "claim_denied" in subject
        assert text.index("9,000") < text.index("400") < text.index("75")
        assert "console" in text
        row = [a for a in eng.store.audit_log() if a["kind"] == "template_digest_sent"][0]["data"]
        assert row["pattern"] == "claim_denied" and row["cases"] == 3

    def test_template_digest_order_and_flags(self):
        eng, _, _ = rig()
        for a in (5, 900, 70, 30000, 1):
            claim(eng, amount=a)
        d = eng.template_digest("claim_denied")
        assert d["open"] == 5 and d["threshold"] == 3
        assert [c["money"] for c in d["cases"]] == [30000, 900, 70, 5, 1]
        assert [c["digested"] for c in d["cases"]] == [True, False, False, False, True]
        assert d["money_total"] == 30976

    @pytest.mark.parametrize("bad", [None, "abc", "NaN", "inf", "-Infinity", "1e400", float("nan"), float("inf"),
                                     True, {"x": 1}])
    def test_unusable_money_ranks_last_as_zero(self, bad):
        eng, _, _ = rig()
        claim(eng, amount=10)
        claim(eng, amount=bad)
        claim(eng, amount=5)
        cases = eng.template_digest("claim_denied")["cases"]
        assert [c["money"] for c in cases] == [10, 5, 0]
        assert eng.template_digest("claim_denied")["money_total"] == 15

    def test_negative_money_is_its_size_and_numeric_strings_parse(self):
        eng, _, _ = rig()
        claim(eng, amount=-5000)
        claim(eng, amount="700")
        claim(eng, amount=900)
        assert [c["money"] for c in eng.template_digest("claim_denied")["cases"]] == [5000, 900, 700]

    def test_money_from_fact_beats_payload_and_payload_field_works(self):
        r = reg(money_fact="net")
        r["fingerprints"][0]["fields"] = {"unit": "unit", "claim": "claim", "net": "billed"}
        eng, _, _ = rig(r)
        claim(eng, amount=1, billed=50, net=99999)          # fact "net" comes from payload.billed
        claim(eng, amount=1, billed=800)
        assert [c["money"] for c in eng.template_digest("claim_denied")["cases"]] == [800, 50]
        eng2, _, _ = rig(reg(money_fact="billed"))           # not a fact: read from the payload
        claim(eng2, billed=3)
        claim(eng2, billed=30)
        assert [c["money"] for c in eng2.template_digest("claim_denied")["cases"]] == [30, 3]

    def test_ranked_reviews_by_person_and_pattern(self):
        eng, _, _ = rig()
        for a in (10, 300, 20):
            claim(eng, amount=a)
        bed(eng)
        claim(eng, unit="U3", amount=99999)
        mine = eng.ranked_reviews("bea")
        assert [r["money"] for r in mine if r["pattern"] == "claim_denied"] == [300, 20, 10]
        assert {r["pattern"] for r in mine} == {"claim_denied", "bed_blocked"}
        assert all(r["pattern"] == "claim_denied" for r in eng.ranked_reviews("bea", pattern_id="claim_denied"))
        assert all(r["facts"]["unit"] != "U3" for r in mine)          # out of scope
        assert [r["money"] for r in eng.ranked_reviews("ben")] == [99999]
        assert eng.ranked_reviews("aud", pattern_id="claim_denied") != []   # dotted line sees the queue

    def test_without_money_fact_the_digest_still_goes(self):
        eng, mail, _ = rig(reg(money_fact=None))
        for _ in range(5):
            claim(eng, amount=1)
        assert sent_to(eng.send_template_digests()) == {"bea": 2}
        assert all(c["money"] == 0 for c in eng.template_digest("claim_denied")["cases"])


# ============================================================================== 3. recipients
class TestRecipients:
    def test_only_current_active_holders_in_scope(self):
        eng, mail, _ = rig()
        for _ in range(3):
            claim(eng)
        claim(eng, amount=7)
        claim(eng, unit="U3", amount=8)
        out = eng.send_template_digests()
        assert sent_to(out) == {"bea": 1, "ben": 1}             # not old (inactive), loc (future), aud (dotted)
        assert {t[0]["email"] for t in mail.texts} == {"bea@hosp.in", "ben@hosp.in"}

    def test_future_cover_receives_once_current(self):
        eng, mail, clock = rig()
        for _ in range(4):
            claim(eng)
        clock.now = datetime(2026, 10, 26, 9, 0, tzinfo=UTC)
        assert "loc" in sent_to(eng.send_template_digests(force=True))

    def test_vacancy_escalate_digest_goes_to_roll_up_holder(self):
        eng, _, _ = rig(ppl=people(vacancy="escalate"))
        for _ in range(3):
            claim(eng)
        v = claim(eng, unit="U2", amount=500)
        assert v.digested and v.assignee_role == "billing_manager"
        assert sent_to(eng.send_template_digests()) == {"mgr": 1}

    def test_edge_without_text_leaves_a_case_neither_carded_nor_digested(self):
        # FIXED v0.23.0 before push (was DEFECT): OVERLAY_CONTRACT: past digest_above "each person holding the cases' roles in scope gets one
        # digest". Expected: bea is told about her digested cases (a card fallback, or at least the audit names
        # her as skipped). Actual: with only a card edge (MemoryEdge, no send_text) the digest reports
        # sent=[] , no card goes either, and template_digest_sent records nothing about who missed it: cases 4
        # and 5 silently reach nobody. Repro: Overlay(edges={"memory": MemoryEdge()}, default_edges=["memory"]),
        # people without `edges`, digest_above=3, ingest 5 claims, send_template_digests(force=True).
        ppl = people()
        for p in ppl["people"]:
            p.pop("edges", None)
        edge = MemoryEdge()
        eng, _, _ = rig(ppl=ppl, edge=edge)
        rs = [claim(eng) for _ in range(5)]
        eng.work("w", limit=100)
        out = eng.send_template_digests(force=True)
        eng.work("w", limit=100)
        reached = carded(edge) | ({r.id for r in rs[3:]} if sent_to(out).get("bea") else set())
        row = [a for a in eng.store.audit_log() if a["kind"] == "template_digest_sent"][-1]["data"]
        assert {r.id for r in rs} <= reached or "bea" in str(row.get("skipped", "")), (out, row)


# ============================================================================== 4. frequency and exclusions
class TestFrequency:
    def test_not_twice_within_the_interval_then_again(self):
        eng, mail, clock = rig()
        for _ in range(5):
            claim(eng)
        assert eng.send_template_digests() != []
        assert eng.send_template_digests() == []
        clock.advance(minutes=59)
        assert eng.send_template_digests() == []
        clock.advance(minutes=2)
        assert sent_to(eng.send_template_digests()) == {"bea": 2}
        assert sent_to(eng.send_template_digests(force=True)) == {"bea": 2}
        assert len(mail.texts) == 3

    def test_custom_interval(self):
        eng, _, clock = rig(reg(digest_every_minutes=15))
        for _ in range(5):
            claim(eng)
        eng.send_template_digests()
        clock.advance(minutes=14)
        assert eng.send_template_digests() == []
        clock.advance(minutes=2)
        assert eng.send_template_digests() != []

    def test_sweep_sends_the_digest(self):
        eng, mail, clock = rig()
        for _ in range(5):
            claim(eng)
        clock.advance(minutes=1)
        eng.sweep()
        assert "template_digest_sent" in kinds(eng) and mail.texts

    def test_paused_silenced_and_quiet_cases_left_out(self):
        eng, mail, _ = rig()
        for _ in range(3):
            claim(eng)
        a = claim(eng, amount=600)
        p = claim(eng, amount=500)
        eng.pause_review(p.id, "bea", "awaiting_payer", hours=5)
        eng.add_silence("cfo1", reason="payer portal down", hours=4, pattern="claim_denied", facts={"unit": "U1"})
        s = claim(eng, amount=700)
        assert s.digested
        cases = {c["review"]: c for c in eng.template_digest("claim_denied")["cases"]}
        assert cases[p.id]["held"] and cases[s.id]["held"]
        eng.send_template_digests(force=True)
        text = mail.texts[-1][2]
        assert "600" in text and "500" not in text and "700" not in text
        assert a.id

    def test_quiet_cases_left_out(self):
        eng, _, clock = rig(reg(escalation={"repeat": 0}))
        for _ in range(5):
            claim(eng)
        for _ in range(8):
            clock.advance(minutes=31)
            eng.sweep()
        assert all(r.quiet for r in eng.store.open_reviews())
        assert eng.send_template_digests(force=True) == []      # they are on the daily overdue list instead


# ============================================================================== 5. escalation and bulk
class TestEscalationAndBulk:
    def test_escalation_moves_digested_cases_without_cards(self):
        eng, mail, clock = rig()
        rs = [claim(eng) for _ in range(5)]
        eng.work("w", limit=100)
        clock.advance(minutes=31)
        eng.sweep()
        eng.work("w", limit=100)
        now = {r.id: r for r in eng.store.open_reviews()}
        assert all(now[r.id].assignee_role == "billing_manager" for r in rs)
        assert now[rs[3].id].digested and now[rs[4].id].digested
        assert not ({rs[3].id, rs[4].id} & carded(mail))
        assert {c.review_id for c in mail.cards if c.recipient_id == "mgr"} == {r.id for r in rs[:3]}
        assert sent_to(eng.send_template_digests(force=True)) == {"mgr": 2}   # they stay on the digest

    def test_escalation_stops_at_the_stop_list(self):
        eng, _, clock = rig()
        rs = [claim(eng) for _ in range(5)]
        for _ in range(6):
            clock.advance(minutes=31)
            eng.sweep()
        assert {eng.store.open_review_for(r.incident_id).assignee_role for r in rs} == {"finance_head"}

    def test_removing_the_setting_gives_digested_cases_cards_again(self):
        # FIXED v0.23.0 before push (was DEFECT): "no settings = no change": once digest_above is removed (published), the template sends no
        # digests at all, so its digested cases must get cards again, at least on their next escalation.
        # Expected: the two digested cases are carded to mgr when the sweep escalates them. Actual: they move to
        # billing_manager but stay digested=True; mgr gets cards only for the three earlier cases and no digest
        # ever goes (send_template_digests(force=True) == []), so those cases reach nobody.
        eng, mail, clock = rig()
        rs = [claim(eng) for _ in range(5)]
        eng.work("w", limit=100)
        doc = yaml.safe_load(eng.config_text("registry"))
        doc["patterns"][[p["id"] for p in doc["patterns"]].index("claim_denied")].pop("digest_above")
        cv, _ = eng.save_config("registry", yaml.safe_dump(doc), author="cfo1")
        eng.publish_config(cv.id, "cfo1")
        assert eng.registry.get("claim_denied").digest_above is None
        clock.advance(minutes=31)
        eng.sweep()
        eng.work("w", limit=100)
        assert eng.send_template_digests(force=True) == []
        assert {rs[3].id, rs[4].id} <= {c.review_id for c in mail.cards if c.recipient_id == "mgr"}

    def test_bulk_decide_ranked_and_digested(self):
        r = reg()
        r["patterns"][0]["playbook"][0]["params"]["amount"] = "{{payload.amount|float}}"
        eng, _, _ = rig(r)
        for a in (1, 2, 3, 4, 5):
            claim(eng, amount=a)
        ids = [r["review"] for r in eng.ranked_reviews("bea", pattern_id="claim_denied")]
        out = eng.decide_many(ids, "approve", "bea")
        assert len(out["decided"]) == 5 and out["refused"] == []
        assert eng.template_digest("claim_denied")["open"] == 0

    def test_bulk_refuses_out_of_scope_and_keeps_going(self):
        eng, _, _ = rig()
        for _ in range(4):
            claim(eng)
        far = claim(eng, unit="U3")
        ids = [c["review"] for c in eng.template_digest("claim_denied")["cases"]]
        out = eng.decide_many(ids, "reject", "bea", disposition_code="no_action")
        assert len(out["decided"]) == 4 and [r["review"] for r in out["refused"]] == [far.id]


# ============================================================================== 6. escalate_to and the stop list
LADDER = [PlaybookStep(action="resubmit", params={"claim": "CL", "amount": 90000})]


class TestEscalateTo:
    def d(self, **kw: Any):
        return parse_directory(people(**kw))

    def test_cap_escalation_rules(self):
        d = self.d()
        assert d.cap_escalation("billing_exec", "cfo") == "finance_head"
        assert d.cap_escalation("billing_manager", "cfo") == "finance_head"
        assert d.cap_escalation("billing_exec", "finance_head") == "finance_head"
        assert d.cap_escalation("billing_exec", "billing_manager") == "billing_manager"
        assert d.cap_escalation("finance_head", "cfo") == "finance_head"
        assert d.cap_escalation("billing_exec", None) is None
        assert self.d(stop_at=None).cap_escalation("billing_exec", "cfo") == "cfo"

    def test_authorise_person_capped(self):
        d = self.d()
        assert authorise(d, "bea", "resubmit", obj="x", scope={"unit": "U1"}, amount=3000).escalate_to == \
            "billing_manager"
        for who in ("bea", "mgr"):
            assert authorise(d, who, "resubmit", obj="x", scope={"unit": "U1"}, amount=90000).escalate_to == \
                "finance_head"
        assert authorise(self.d(stop_at=None), "bea", "resubmit", obj="x", scope={"unit": "U1"},
                         amount=90000).escalate_to == "cfo"

    def test_stop_role_holder_not_pointed_at_itself(self):
        d = self.d()
        dec = authorise(d, "fh", "resubmit", obj="x", scope={"unit": "U1"}, amount=90000)
        assert not dec and dec.escalate_to is None
        low = self.d(stop_at=["billing_manager", "finance_head", "cfo"])
        assert authorise(low, "mgr", "resubmit", obj="x", scope={"unit": "U1"}, amount=90000).escalate_to is None
        assert authorise(low, "bea", "resubmit", obj="x", scope={"unit": "U1"}, amount=90000).escalate_to == \
            "billing_manager"

    def test_agents_capped(self):
        d = self.d()
        for role in ("billing_exec", "billing_manager"):
            dec = authorise(d, Agent("denial_bot@U1", bound_role=role), "resubmit", obj="x", scope={"unit": "U1"},
                            amount=90000)
            assert not dec and dec.escalate_to == "finance_head"
        dec = authorise(d, Agent("denial_bot@U1", bound_role="finance_head"), "resubmit", obj="x",
                        scope={"unit": "U1"}, amount=90000)
        assert not dec and dec.escalate_to is None

    def test_authorize_steps_capped(self):
        d = self.d()
        assert d.authorize_steps("bea", "claim_denied", "billing_exec", LADDER, {"unit": "U1"}).escalate_to == \
            "finance_head"
        a = d.authorize_steps("fh", "claim_denied", "billing_exec", LADDER, {"unit": "U1"})
        assert not a.allowed and a.escalate_to is None

    def test_forward_stops_at_the_stop_role_and_nobody_past_it_is_paged(self):
        r = reg()
        r["patterns"][0]["playbook"][0]["params"]["amount"] = "{{payload.amount|float}}"
        eng, mail, clock = rig(r)
        rv = claim(eng, amount=90000)
        inc = eng.decide(rv.id, Decision(kind=DecisionKind.APPROVE, actor="bea", disposition_code="resolved"))
        fwd = eng.store.open_review_for(inc.id)
        assert fwd.assignee_role == "finance_head" and "proposed by bea" in fwd.reason
        for _ in range(4):
            clock.advance(minutes=31)
            eng.sweep()
        eng.work("w", limit=100)
        assert "cfo1" not in {c.recipient_id for c in mail.cards}
        assert eng.store.open_review_for(inc.id).assignee_role == "finance_head"


# ============================================================================== 7. console API
AGENTS = [{"template": "*", "mode": "OBSERVE"},
          {"template": "claim_denied", "scope": {"unit": "U1"}, "mode": "PROPOSE"},
          {"template": "claim_denied", "scope": {"hospital": "H2"}, "mode": "ACT"}]


@pytest.fixture
def api():
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from sentinel.api import Principal, create_app, token_hash
    eng, mail, clock = rig(ppl=people(agents=AGENTS))
    for a in (5, 900, 70, 30000, 1):
        claim(eng, amount=a)
    toks = {token_hash(f"{p}-t"): Principal("person", p) for p in ("bea", "aud", "cfo1", "fh")}
    toks[token_hash("svc-t")] = Principal("service", "svc")
    c = TestClient(create_app(eng, toks, config_sync_s=0))
    return eng, c, (lambda who: {"Authorization": f"Bearer {who}-t"})


class TestConsoleApi:
    def test_agents_lists_templates_modes_oversight(self, api):
        eng, c, h = api
        j = c.get("/console/api/agents", headers=h("aud")).json()
        t = {x["id"]: x for x in j["templates"]}["claim_denied"]
        assert t["owner_role"] == "billing_exec" and t["digest_above"] == 3 and t["money_fact"] == "amount"
        assert t["open"] == 5 and t["overseers"] == ["audit"]
        assert [a["mode"] for a in j["agents"]] == ["OBSERVE", "PROPOSE", "ACT"]
        assert j["can_oversee"] is True and j["stop_at"] == ["finance_head", "cfo"]
        assert c.get("/console/api/agents", headers=h("bea")).json()["can_oversee"] is False

    @pytest.mark.parametrize("unit", ["U1", "U2", "U3"])
    def test_lookup_agrees_with_ingest(self, api, unit):
        eng, c, h = api
        j = c.post("/console/api/agents/effective", headers=h("bea"),
                   json={"pattern": "claim_denied", "facts": {"unit": unit}}).json()
        rv = claim(eng, unit=unit)
        prov = eng.store.get_incident(rv.incident_id).provenance
        assert (j["agent"], j["mode"]) == (prov.agent, prov.agent_mode)

    def test_lookup_bad_input(self, api):
        _, c, h = api
        assert c.post("/console/api/agents/effective", headers=h("aud"), json={"pattern": "ghost"}).status_code \
            in (404, 422)
        assert c.post("/console/api/agents/effective", headers=h("aud"),
                      json={"pattern": "claim_denied", "facts": "x"}).status_code == 422

    @pytest.mark.parametrize("who", ["bea", "cfo1", "fh"])
    def test_oversee_refuses_non_overseers(self, api, who):
        eng, c, h = api
        r = c.post("/console/api/oversee", headers=h(who),
                   json={"pattern": "claim_denied", "action": "stop", "reason": "x"})
        assert r.status_code == 403 and "oversight_action" not in kinds(eng)

    def test_oversee_service_token_and_no_token_refused(self, api):
        eng, c, _ = api
        body = {"pattern": "claim_denied", "action": "stop", "reason": "x"}
        assert c.post("/console/api/oversee", headers={"Authorization": "Bearer svc-t"}, json=body).status_code \
            == 403
        assert c.post("/console/api/oversee", json=body).status_code == 401
        assert "oversight_action" not in kinds(eng)

    @pytest.mark.parametrize("body", [
        {"pattern": "claim_denied", "action": "stop", "reason": ""},
        {"pattern": "claim_denied", "action": "stop", "reason": "   "},
        {"pattern": "claim_denied", "action": "promote", "reason": "x"},
        {"pattern": "nope", "action": "stop", "reason": "x"},
        {"action": "stop", "reason": "x"},
        {"pattern": "claim_denied", "action": "cap", "reason": "x", "route": "bogus"}])
    def test_oversee_bad_input(self, api, body):
        eng, c, h = api
        r = c.post("/console/api/oversee", headers=h("aud"), json=body)
        assert 400 <= r.status_code < 500 and "oversight_action" not in kinds(eng)

    def test_oversee_cap_without_route_is_bad_input(self, api):
        # FIXED v0.23.0 before push (was DEFECT): "cap" means cap at a route; without one there is nothing to apply. Expected: refused (4xx) and
        # not audited. Actual: 200 {"states":[{"route":"hitl","cap":null}]} and an `oversight_action` row is
        # written for a lever that changed nothing (same for engine.oversee("claim_denied","cap","aud","why")).
        eng, c, h = api
        r = c.post("/console/api/oversee", headers=h("aud"),
                   json={"pattern": "claim_denied", "action": "cap", "reason": "x"})
        assert 400 <= r.status_code < 500 and "oversight_action" not in kinds(eng), r.text

    def test_oversee_stop_scope_audited_and_routes_to_person(self, api):
        eng, c, h = api
        r = c.post("/console/api/oversee", headers=h("aud"),
                   json={"pattern": "claim_denied@unit=U1", "action": "stop", "reason": "payer audit"})
        assert r.status_code == 200
        rows = [a for a in eng.store.audit_log() if a["kind"] == "oversight_action"]
        assert len(rows) == 1 and "payer audit" in str(rows[0]["data"])

    def test_ranked_endpoint(self, api):
        _, c, h = api
        j = c.get("/console/api/reviews/ranked", headers=h("bea")).json()
        assert [x["money"] for x in j] == [30000, 900, 70, 5, 1]
        assert [x["digested"] for x in j] == [True, False, False, False, True]
        assert c.get("/console/api/reviews/ranked", headers=h("ben")).status_code == 401


# ============================================================================== 8. console in a browser
@pytest.fixture
def served(tmp_path):
    pytest.importorskip("fastapi")
    pytest.importorskip("playwright.sync_api")
    import uvicorn

    from sentinel.api import Principal, create_app, token_hash
    ov = overlay(ppl=people(agents=AGENTS))
    eng = Engine(ov, store=SQLiteStore(str(tmp_path / "h.db")), clock=FrozenClock(NOW),
                 guardrails=Guardrails())
    for a in (5, 900, 70, 30000, 1):
        claim(eng, amount=a)
    app = create_app(eng, {token_hash(f"{p}-t"): Principal("person", p) for p in ("bea", "aud", "cfo1")},
                     config_sync_s=0)
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_config=None, access_log=False))
    t = threading.Thread(target=server.run, daemon=True)
    t.start()
    for _ in range(200):
        if server.started:
            break
        time.sleep(0.02)
    yield eng, f"http://127.0.0.1:{port}"
    server.should_exit = True
    t.join(5)


def browse(base: str, who: str, width: int, scheme: str, fn):
    from playwright.sync_api import sync_playwright
    with sync_playwright() as p:
        try:
            browser = p.chromium.launch()
        except Exception as e:  # noqa: BLE001
            pytest.skip(f"no Chromium: {e}")
        pg = browser.new_page(viewport={"width": width, "height": 900}, color_scheme=scheme)
        errors: list[str] = []
        pg.on("pageerror", lambda e: errors.append(str(e)))
        pg.on("console", lambda m: m.type == "error" and errors.append(m.text))
        pg.goto(base + "/console")
        pg.fill("#token", f"{who}-t")
        pg.click("#signin")
        pg.wait_for_selector(".topbar h1")
        try:
            fn(pg)
        finally:
            browser.close()
        assert errors == []


def no_hscroll(pg) -> bool:
    w = pg.evaluate("[document.documentElement.scrollWidth, window.innerWidth]")
    return w[0] <= w[1]


VIEWS = [(1400, "light"), (1400, "dark"), (390, "light"), (390, "dark")]


class TestConsoleBrowser:
    @pytest.mark.parametrize("width, scheme", VIEWS)
    def test_agents_page_for_overseer(self, served, width, scheme):
        eng, base = served

        def run(pg):
            pg.goto(base + "/console#/agents")
            pg.wait_for_selector("text=AGENT MODES", timeout=10000)
            body = pg.inner_text("body")
            for needle in ("claim_denied", "billing_exec", "digest past 3", "OBSERVE", "PROPOSE", "ACT",
                           "finance_head, cfo"):
                assert needle in body, needle
            assert no_hscroll(pg)
            pg.fill("input[placeholder^='store=']", "unit=U3")
            pg.click("button:text-is('Look up')")
            pg.wait_for_selector("text=claim_denied@hospital=H2")
            pg.click("button:text-is('Apply')")
            pg.wait_for_selector(".toast")
            assert "oversight_action" not in kinds(eng)             # no reason, no pattern: refused
            pg.fill("input[placeholder^='template, or']", "claim_denied@unit=U1")
            pg.fill("input[placeholder^='Why']", "denials spiking")
            pg.click("button:text-is('Apply')")
            for _ in range(50):
                if "oversight_action" in kinds(eng):
                    break
                time.sleep(0.1)
            assert "oversight_action" in kinds(eng)
        browse(base, "aud", width, scheme, run)

    @pytest.mark.parametrize("who", ["bea", "cfo1"])
    def test_no_oversight_form_for_others(self, served, who):
        _, base = served

        def run(pg):
            pg.goto(base + "/console#/agents")
            pg.wait_for_selector("text=AGENT MODES", timeout=10000)
            assert pg.locator("input[placeholder^='Why']").count() == 0
            assert pg.locator("button:text-is('Apply')").count() == 0
        browse(base, who, 1400, "light", run)

    def test_lookup_result_has_no_null_text(self, served):
        # FIXED v0.23.0 before push (was DEFECT): the "which mode applies here?" result renders a literal "null": for unit=U3 it reads
        # "claim_denied@hospital=H2 · ACT · route personnull" (the empty segment printed as null).
        # Expected: no "null" in the result. Actual: "...route personnull".
        _, base = served

        def run(pg):
            pg.goto(base + "/console#/agents")
            pg.wait_for_selector("text=AGENT MODES", timeout=10000)
            pg.fill("input[placeholder^='store=']", "unit=U3")
            pg.click("button:text-is('Look up')")
            pg.wait_for_selector("text=claim_denied@hospital=H2")
            assert "null" not in pg.locator(".card", has_text="WHICH MODE").inner_text()
        browse(base, "aud", 1400, "light", run)

    @pytest.mark.parametrize("width, scheme", VIEWS)
    def test_reviews_money_order_and_digest_badges(self, served, width, scheme):
        _, base = served

        def run(pg):
            pg.goto(base + "/console#/reviews")
            pg.wait_for_selector("text=most money at stake first", state="attached", timeout=10000)
            pg.locator("select", has_text="most money at stake first").select_option(
                label="most money at stake first")
            pg.wait_for_timeout(500)
            assert pg.locator("text=/at stake$/").all_inner_texts() == [
                "30,000 at stake", "900 at stake", "70 at stake", "5 at stake", "1 at stake"]
            assert pg.locator("text=on digest").count() == 2
            assert no_hscroll(pg)
            pg.click("text=Select all shown")
            pg.click("text=Close selected")
            pg.wait_for_selector(".toast")
        browse(base, "bea", width, scheme, run)

    def test_reviews_show_no_null_badge(self, served):
        # FIXED v0.23.0 before push (was DEFECT): on Reviews each case that is NOT on a digest shows a literal "null" where the "on digest" badge
        # goes (e.g. "900 at stake null"). Expected: nothing. Actual: the text "null" next to the money badge
        # on 3 of 5 cards (bea, 5 claims, digest_above=3).
        _, base = served

        def run(pg):
            pg.goto(base + "/console#/reviews")
            pg.wait_for_selector("text=/at stake$/", timeout=10000)
            html = pg.locator("text=900 at stake").locator("xpath=..").inner_html()
            assert not html.rstrip().endswith("null"), html[-120:]
        browse(base, "bea", 1400, "light", run)
