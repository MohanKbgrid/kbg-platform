# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""Long jobs keep their lease, a worker that lost its job acts on nothing, and candidate models run as their
own jobs (review finding H4)."""
from __future__ import annotations

import json
import threading
import time

from sentinel import ModelRouter, ScriptedLLM
from tests.conftest import stuck_event


def _final(ref):
    return json.dumps({"final": {"action": "hold", "params": {"ref": ref}, "disposition_code": "resolved",
                                 "confidence": 0.95, "rationale": "r"}})


def slow_llm(gate):
    def fn(system, messages):
        gate.wait(10)
        return _final(json.loads(messages[0]["content"])["incident"]["facts"]["ref"])
    return ScriptedLLM(fn=fn)


def test_a_long_model_call_keeps_its_lease(engine_factory, clock, backend):
    gate = threading.Event()
    eng = engine_factory(llm=slow_llm(gate), async_mode=True)
    eng.ingest(stuck_event(ref="I1"))
    out = {}
    a = threading.Thread(target=lambda: out.update(eng.work("A", lease_seconds=3)))
    a.start()
    time.sleep(0.3)
    clock.advance(seconds=2.5)
    time.sleep(1.5)                                      # the heartbeat renews from the moved clock
    clock.advance(seconds=1.5)                           # past the first lease, inside the renewed one
    assert eng.work("B", lease_seconds=3) == {"done": 0, "retry": 0, "dead": 0, "lost": 0}   # nothing to steal
    gate.set()
    a.join(10)
    assert out["done"] == 1 and backend.calls == [("hold", {"ref": "I1"})]


def test_a_worker_that_lost_its_job_acts_on_nothing(engine_factory, backend):
    gate = threading.Event()
    eng = engine_factory(llm=slow_llm(gate), async_mode=True)
    r = eng.ingest(stuck_event(ref="I2"))
    out = {}
    a = threading.Thread(target=lambda: out.update(eng.work("A", lease_seconds=300)))
    a.start()
    time.sleep(0.3)
    from sentinel.retention import _Q
    _Q(eng.store)("UPDATE {s}.work_items SET leased_by='B'")   # as if the lease expired and worker B took it
    gate.set()
    a.join(10)
    assert out["lost"] == 1 and backend.calls == []       # A stopped before acting
    assert eng.store.get_disposition(r.incident_id) is None and eng.store.open_review_for(r.incident_id) is None
    assert any(x["kind"] == "work_lease_lost" for x in eng.store.audit_log(r.incident_id))


def test_candidate_models_run_as_their_own_job(engine_factory, backend):
    primary = ScriptedLLM(fn=lambda s, m: _final(json.loads(m[0]["content"])["incident"]["facts"]["ref"]))
    primary.model = "claude"
    candidate = ScriptedLLM(fn=lambda s, m: _final("WRONG"))
    candidate.model = "slm"
    eng = engine_factory(llm=ModelRouter(default=primary, candidates={"diagnose": candidate}), async_mode=True)
    r = eng.ingest(stuck_event(ref="I3"))
    first = eng.work("w")
    assert first["done"] == 1 and backend.calls == [("hold", {"ref": "I3"})] and candidate.calls == []
    assert eng.work("w")["done"] >= 1                    # the shadow job
    shadows = [a["data"] for a in eng.store.audit_log(r.incident_id) if a["kind"] == "model_shadow"]
    assert shadows and shadows[0]["agreed"] is False and shadows[0]["model"] == "slm"
