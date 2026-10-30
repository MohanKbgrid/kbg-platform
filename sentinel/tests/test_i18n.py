# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""A8: review cards in the reader's language."""
from __future__ import annotations

import json

from sentinel import Guardrails, ScriptedLLM
from sentinel.channels import SlackEdge
from sentinel.edges import WhatsAppEdge
from sentinel.i18n import STRINGS, norm, t, translate
from sentinel.rbac import Person
from tests.conftest import job_event
from tests.test_rbac import make_directory


def _engine(engine_factory, llm=None):
    d = make_directory()
    d.people["ravi"] = Person(id="ravi", language="hi", contact={"whatsapp": "+91 98400 11111", "slack": "U1"})
    d.people["asha"] = Person(id="asha", language="ta-IN", contact={"whatsapp": "+91 98400 22222"})
    return engine_factory(directory=d, guardrails=Guardrails(), llm=llm)


def test_table_is_complete_and_lookups_fall_back():
    for lang, table in STRINGS.items():
        assert set(table) == set(STRINGS["en"]), lang
        assert "{n}" in table["sure"] and "{code}" in table["close_as"] and "{n}" in table["waiting"]
    assert norm("ta-IN") == "ta" and norm("xx") == "en" and norm(None) == "en"
    assert t("hi", "sure", n=90) == "90% निश्चित" and t("zz", "approve") == "Approve"


def test_cards_use_the_readers_words(engine_factory):
    eng = _engine(engine_factory)
    rid = eng.ingest(job_event(error="AUTH", system="hr", ref="I1")).incident_id
    review = eng.store.open_review_for(rid)
    card = eng.build_card(review, "ravi")
    assert card.language == "hi"
    m = WhatsAppEdge("wa", "1", "t", "s", "v").message(card)
    titles = [b["reply"]["title"] for b in m["interactive"]["action"]["buttons"]] if m["type"] == "interactive" else []
    assert any(x.startswith("बंद करें") for x in titles)
    tm = WhatsAppEdge("wa", "1", "t", "s", "v", template={"name": "rv", "language": "en",
                                                         "languages": ["en", "hi"]}).message(card)
    assert tm["template"]["language"]["code"] == "hi"
    other = eng.build_card(review, "asha")
    assert WhatsAppEdge("wa", "1", "t", "s", "v", template={"name": "rv", "languages": ["en", "hi"]}).message(
        other)["template"]["language"]["code"] == "en"                       # no Tamil template approved
    blocks = SlackEdge("sl", "xoxb", "sig").message(card)["blocks"]
    labels = [e["text"]["text"] for b in blocks if b["type"] == "actions" for e in b["elements"]]
    assert labels and all(x.startswith("बंद करें") or x == "स्वीकार करें" for x in labels)
    assert eng.build_card(review, "hari").language == "en"


def test_model_translates_free_text_masked_and_cached(engine_factory):
    calls = []

    def fn(system, messages):
        body = messages[0]["content"]
        calls.append(body)
        src = json.loads(body[body.index("{"):])
        return json.dumps({k: f"[hi] {v}" for k, v in src.items()}, ensure_ascii=False)
    from sentinel.routing import ModelRouter
    routes = {"translate": ScriptedLLM(fn=fn), "diagnose": ScriptedLLM(fn=lambda s, m: "no")}
    eng = _engine(engine_factory, llm=ModelRouter(routes=routes, prices={}))
    out = translate(eng, ["Payment failed for priya@acme.in", "", "Order stuck"], "hi")
    assert out == ["[hi] Payment failed for priya@acme.in", "", "[hi] Order stuck"]
    assert "priya@acme.in" not in calls[0] and "[PII_1]" in calls[0]          # personal data never sent
    assert translate(eng, ["Order stuck"], "hi") == ["[hi] Order stuck"] and len(calls) == 1   # cached
    rid = eng.ingest(job_event(error="AUTH", system="hr", ref="I2")).incident_id
    card = eng.build_card(eng.store.open_review_for(rid), "ravi", localise=True)
    assert card.title.startswith("[hi] ")
    assert card.facts == eng.store.get_incident(rid).facts                     # facts are never translated


def test_without_a_model_text_stays_english(engine_factory):
    eng = _engine(engine_factory)
    assert translate(eng, ["Order stuck"], "ta") == ["Order stuck"]
