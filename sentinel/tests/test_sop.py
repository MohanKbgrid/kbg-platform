# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""Standard operating procedures: in the brief (relevant sections when long), on review cards, never masked,
editing them keeps trust."""
from __future__ import annotations

import json

from sentinel import ScriptedLLM
from sentinel.sop import excerpt, sections
from tests.conftest import make_overlay, stuck_event

SOP = """# Items stuck in the warehouse
Applies to every site. Call the customer only after checking stock.

## Site S1 (Chennai)
1. Hold the item and ask the floor lead to look in returns bay R2.
2. If not found within 2 hours, raise a cycle count.

## Site S2 (Bengaluru)
1. Check the cross-dock lane first; S2 often mis-scans there.
2. Hold the item with reason "cross-dock".
"""


def test_sections_and_excerpt():
    secs = sections(SOP, size=200)
    assert secs[0].startswith("# Items stuck") and any(s.startswith("## Site S2") for s in secs)
    assert excerpt(SOP, "anything") == SOP.strip()                            # short: all of it
    long = SOP + "\n\n" + "\n\n".join(f"## Site S{i}\nFiller text about site {i} " * 20 for i in range(3, 12))
    ex = excerpt(long, json.dumps({"facts": {"site": "S2"}, "event": {"note": "cross-dock lane"}}), max_chars=900)
    assert "# Items stuck" in ex and "cross-dock" in ex and len(ex) < 1000 and "omitted" in ex


def test_procedure_reaches_the_model_unmasked_and_people_see_it(engine_factory, backend):
    ov = make_overlay(backend)
    ov.patterns = [p.model_copy(update={"sop": SOP}) if p.id in ("item_stuck_long", "item_stuck_short") else p
                   for p in ov.patterns]
    seen = []

    def fn(system, messages):
        seen.append((system, json.loads(messages[0]["content"])))
        return json.dumps({"final": {"action": "hold", "params": {"ref": "I1"}, "disposition_code": "resolved",
                                     "confidence": 0.9, "rationale": "Followed S2 step 2"}})
    eng = engine_factory(llm=ScriptedLLM(fn=fn), ov=ov)
    ev = stuck_event(ref="I1", site="S2")
    eng.ingest(ev.model_copy(update={"payload": {**ev.payload, "name": "Asha"}}))
    system, brief = seen[0]
    assert "standard_operating_procedure" in system and brief["standard_operating_procedure"] == SOP.strip()
    assert "Asha" not in json.dumps(brief["event"])                        # the case is masked...
    assert "Hold the item" in brief["standard_operating_procedure"]        # ...the procedure is not
    r = eng.ingest(stuck_event(ref="I2", age=2))                            # short stuck: a person reviews
    card = eng.build_card(eng.store.open_review_for(r.incident_id))
    assert card.sop.startswith("# Items stuck")


def test_editing_the_procedure_keeps_trust():
    from sentinel import Pattern, Route
    p = Pattern(id="x", event_types=["e"], route=Route.HITL)
    assert p.definition_hash() == p.model_copy(update={"sop": "new procedure"}).definition_hash()
