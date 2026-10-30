# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""The CrewAI add-on: a crew investigates with the case's read-only tools and answers as a model."""
from __future__ import annotations

import json

import pytest

from sentinel import ScriptedLLM
from sentinel.providers import load_models
from tests.conftest import stuck_event

crewai = pytest.importorskip("crewai")

from sentinel.crew import CrewClient, _to_ours  # noqa: E402


class Inner:
    """Plays the investigator (one tool call), then the decider."""

    def __init__(self, final=None):
        self.calls = []
        self.final = final

    def complete(self, system, messages):
        self.calls.append((system, messages))
        text = system + "\n" + "\n".join(m["content"] for m in messages)
        if "Resolver" in system:
            return "Thought: I now know the final answer\nFinal Answer: " + json.dumps(self.final or {
                "final": {"action": "hold", "params": {"ref": "I1", "reason": "stock at STORE_FLG"},
                          "disposition_code": "resolved", "confidence": 0.92, "rationale": "SOP step 2"}})
        if "Observation:" in messages[-1]["content"] or len([m for m in messages if m["role"] == "assistant"]):
            return "Thought: I now know the final answer\nFinal Answer: qty 3 at STORE_FLG for I1"
        assert "lookup" in text
        return ('Thought: check the record\nAction: lookup\nAction Input: {"ref": "I1"}\n'
                "Observation: (made up, must be cut)")


def test_messages_conversion():
    sysm, msgs = _to_ours([{"role": "system", "content": "s"}, {"role": "assistant", "content": "a"},
                           {"role": "user", "content": "u1"}, {"role": "user", "content": "u2"}])
    assert sysm == "s" and msgs[0]["role"] == "user" and msgs[-1] == {"role": "user", "content": "u1\n\nu2"}


def test_crew_resolves_a_case_through_the_engine(engine_factory, backend):
    inner = Inner()
    router = load_models({"models": {"brain": {"provider": "anthropic", "model": "x"},
                                     "crew": {"provider": "crew", "llm": "brain", "max_iter": 4}},
                          "routes": {"diagnose": "crew"}, "default": "diagnose"},
                         factory=lambda spec: inner)
    eng = engine_factory(llm=router)
    r = eng.ingest(stuck_event(ref="I1"))
    assert backend.calls == [("hold", {"ref": "I1", "reason": "stock at STORE_FLG"})]
    d = eng.store.get_disposition(r.incident_id)
    assert d.resolver == "llm" and d.code == "resolved"
    # the investigator saw the result of Sentinel's lookup tool (status "stuck", age_h 30)
    assert any('"age_h": 30' in m["content"] for _, ms in inner.calls for m in ms)


def test_crew_tool_calls_are_recorded_and_masked(engine_factory):
    from sentinel.llm import CASE_TOOLS, CaseTools, LLMResolver
    inner = Inner()
    crew = CrewClient(inner, max_iter=4)
    eng = engine_factory(llm=ScriptedLLM(fn=lambda s, m: "{}"))
    res: LLMResolver = eng.llm
    transcript = []
    token = CASE_TOOLS.set(CaseTools(res, eng.overlay.services, None, transcript))
    try:
        out = crew.complete("rules", [{"role": "user", "content": "item I1 stuck; tools: lookup"}])
    finally:
        CASE_TOOLS.reset(token)
    assert json.loads(out)["final"]["action"] == "hold"
    assert transcript == [{"role": "tool", "name": "lookup", "by": "crew",
                           "result": {"ref": "I1", "status": "stuck", "age_h": 30}}]


def test_repair_goes_to_the_inner_model():
    inner = ScriptedLLM(fn=lambda s, m: '{"final": {}}')
    crew = CrewClient(inner)
    assert crew.complete("s", [{"role": "user", "content": "a"}, {"role": "assistant", "content": "bad"},
                               {"role": "user", "content": "fix"}]) == '{"final": {}}'


def test_spec_validation():
    with pytest.raises(ValueError, match="'llm' must name"):
        load_models({"models": {"c": {"provider": "crew", "llm": "nope"}}, "default": "c"},
                    factory=lambda s: Inner())
    with pytest.raises(ValueError, match="unknown settings"):
        load_models({"models": {"b": {"provider": "anthropic", "model": "x"},
                                "c": {"provider": "crew", "llm": "b", "temp": 1}}, "default": "c"},
                    factory=lambda s: Inner())
    with pytest.raises(ValueError, match="role and a goal"):
        CrewClient(Inner(), [{"role": "x"}])
