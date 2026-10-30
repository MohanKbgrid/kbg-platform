# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""Automatic playbooks and the model never do more alone than a person could approve (review finding H3)."""
from __future__ import annotations

import json

import yaml

from sentinel import ActionResult, Pattern, PlaybookStep, Route, ScriptedLLM
from sentinel.config import directory_doc
from sentinel.rbac import UnattendedRule, parse_directory
from tests.conftest import job_event, make_overlay
from tests.test_rbac import make_directory


def overlay_with_refund(backend):
    pat = Pattern(id="job_timeout", event_types=["job.failed"], match={"error": "TIMEOUT"}, route=Route.AUTO,
                  playbook=[PlaybookStep(action="refund", params={"ref": "{{payload.ref}}",
                                                                  "amount": "{{payload.amount|float}}"})],
                  allowed_actions=["refund"], owner_role="ops")
    ov = make_overlay(backend, patterns=[pat])

    @ov.actions.action("refund", reversible=True, params={"ref": "str", "amount": "float"})
    def refund(ctx, p):
        backend.calls.append(("refund", dict(p)))
        return ActionResult(ok=True)

    @refund.compensator
    def unrefund(ctx, p):
        return ActionResult(ok=True)
    return ov


def test_the_lowest_person_limit_applies_by_default(engine_factory, backend):
    d = make_directory()                            # lead may refund up to 10,000; ops_head without limit
    eng = engine_factory(ov=overlay_with_refund(backend), directory=d)
    eng.ingest(job_event(ref="R1", amount=500, key="r1"))
    assert backend.calls == [("refund", {"ref": "R1", "amount": 500.0})]
    r = eng.ingest(job_event(ref="R2", amount=999999, system="other", key="r2"))
    assert len(backend.calls) == 1                                       # not run unattended
    rev = eng.store.open_review_for(r.incident_id)
    assert rev is not None and "above what auto may do alone" in rev.reason and "10000" in rev.reason
    assert any(a["kind"] == "unattended_limit" for a in eng.store.audit_log(r.incident_id))


def test_explicit_unattended_rules(engine_factory, backend):
    d = make_directory(unattended=[UnattendedRule(resolver="auto", action="refund", max_amount=100)])
    eng = engine_factory(ov=overlay_with_refund(backend), directory=d)
    r = eng.ingest(job_event(ref="R3", amount=500, key="r3"))
    assert backend.calls == [] and "100" in eng.store.open_review_for(r.incident_id).reason
    d2 = make_directory(unattended=[UnattendedRule(action="refund")])     # explicitly unlimited
    eng2 = engine_factory(ov=overlay_with_refund(backend), directory=d2)
    eng2.ingest(job_event(ref="R4", amount=5_000_000, key="r4"))
    assert backend.calls == [("refund", {"ref": "R4", "amount": 5_000_000.0})]


def test_model_route_is_limited_too(engine_factory, backend):
    ov = overlay_with_refund(backend)
    ov.patterns[0] = ov.patterns[0].model_copy(update={"route": Route.LLM})

    def fn(system, messages):
        return json.dumps({"final": {"action": "refund", "params": {"ref": "R5", "amount": 50_000},
                                     "disposition_code": "resolved", "confidence": 0.99, "rationale": "x"}})
    eng = engine_factory(ov=ov, directory=make_directory(), llm=ScriptedLLM(fn=fn))
    r = eng.ingest(job_event(ref="R5", amount=50_000, key="r5"))
    assert backend.calls == [] and "llm may do alone" in eng.store.open_review_for(r.incident_id).reason


def test_people_configuration_round_trip():
    d = make_directory(unattended=[UnattendedRule(resolver="llm", action="refund", max_amount=500)])
    doc = directory_doc(d)
    assert doc["unattended"] == [{"resolver": "llm", "action": "refund", "max_amount": 500.0}]
    again = parse_directory(yaml.safe_load(yaml.safe_dump(doc)))
    assert again.unattended_limit("llm", "p", "refund")[0] == 500
    assert again.unattended_limit("auto", "p", "refund")[0] == 10000          # falls back to the lowest person
