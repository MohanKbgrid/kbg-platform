# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""Health, metrics, the report and the inbox are answered by the database, not by loading every row
(review finding H6)."""
from __future__ import annotations

from sentinel import Decision, DecisionKind, Guardrails, Route
from tests.conftest import job_event
from tests.test_rbac import make_directory


def test_inbox_is_paged_and_scoped(engine_factory, clock):
    eng = engine_factory(directory=make_directory(), guardrails=Guardrails())
    for i in range(120):
        eng.ingest(job_event(error="AUTH", ref=f"J{i}", system="billing" if i % 2 else "hr", key=f"k{i}"))
        clock.advance(minutes=61)                             # past the grouping window: a new case each time
    first = eng.reviews_for("ravi", limit=50)                 # ops, everywhere
    assert len(first) == 50 and [r.due_at for r in first] == sorted(r.due_at for r in first)
    rest = eng.reviews_for("ravi", limit=50, offset=50)
    assert len(rest) == 50 and not {r.id for r in first} & {r.id for r in rest}
    asha = eng.reviews_for("asha", limit=500)                 # ops, billing only
    assert len(asha) == 60
    assert eng.reviews_for("nobody") == []
    h = eng.health()
    overdue = sum(1 for r in eng.store.open_reviews() if r.due_at < clock())
    assert h["open_reviews"] == 120 and h["overdue_reviews"] == overdue


def test_report_counts_match_the_dispositions(engine_factory):
    eng = engine_factory(guardrails=Guardrails(allow_irreversible_unattended=True))
    for i in range(5):
        eng.ingest(job_event(ref=f"A{i}", system=f"s{i}", key=f"a{i}"))            # auto
    eng.set_route("job_timeout", Route.HITL, actor="setup")
    for i in range(3):
        r = eng.ingest(job_event(ref=f"H{i}", system=f"h{i}", key=f"h{i}"))
        eng.decide(eng.store.open_review_for(r.incident_id).id, Decision(kind=DecisionKind.APPROVE, actor="op"))
    rep = eng.report()["patterns"]["job_timeout"]
    ds = eng.store.dispositions("job_timeout")
    assert rep["dispositions"] == len(ds) == 8
    assert rep["by_resolver"]["auto"] == 5 and rep["by_resolver"]["human"] == 3
    assert rep["automation_rate"] == round(5 / 8, 3)
