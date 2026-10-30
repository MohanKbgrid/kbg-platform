# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""Nothing an overlay or a tool does can hang a case forever (review finding H14)."""
from __future__ import annotations

import json
import time

from sentinel import ActionResult, ScriptedLLM, Tool
from tests.conftest import job_event, stuck_event


def test_actions_without_their_own_timeout_get_the_default(engine_factory, overlay):
    @overlay.actions.action("slow_retry", reversible=False, params={"ref": "str"})
    def slow(ctx, p):
        time.sleep(2)
        return ActionResult(ok=True)
    p = next(x for x in overlay.patterns if x.id == "job_timeout")
    p.playbook[0].action = "slow_retry"
    p.allowed_actions.append("slow_retry")
    eng = engine_factory(ov=overlay, default_action_timeout_s=0.3)
    r = eng.ingest(job_event(ref="S1"))
    rev = eng.store.open_review_for(r.incident_id)
    assert rev is not None and "timed out" in rev.reason


def test_a_hanging_tool_does_not_hang_the_model(engine_factory, overlay):
    overlay.tools.register(Tool("hang", "never answers", {}, lambda a, s: time.sleep(5)))
    calls = []

    def fn(s, m):
        calls.append(m[-1]["content"])
        if len(calls) == 1:
            return json.dumps({"tool": "hang", "args": {}})
        return json.dumps({"final": {"action": None, "disposition_code": "no_action", "confidence": 0.2,
                                     "rationale": "tool down"}})
    eng = engine_factory(ov=overlay, llm=ScriptedLLM(fn=fn), tool_timeout_s=0.3)
    t0 = time.perf_counter()
    eng.ingest(stuck_event(ref="T1"))
    assert time.perf_counter() - t0 < 3 and "did not answer" in calls[1]
