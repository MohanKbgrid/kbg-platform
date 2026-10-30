# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""Open-model providers (Ollama, OpenAI-compatible), fallback to a frontier model, escalation, models file."""
from __future__ import annotations

import json
import socket

import pytest

from sentinel import (FallbackClient, ModelRouter, ModelUnavailable, OllamaClient, OpenAICompatibleClient,
                      Pattern, PlaybookStep, Route, ScriptedLLM, load_models)
from sentinel.llm import LLMError
from tests.conftest import make_overlay, stuck_event
from tests.fake_model_server import FakeModelServer

MSGS = [{"role": "user", "content": "hello"}]


def _final(ref="I1", conf=0.95, action="hold"):
    return json.dumps({"final": {"action": action, "params": {"ref": ref}, "disposition_code": "resolved",
                                 "confidence": conf, "rationale": "r"}})


@pytest.fixture
def server():
    s = FakeModelServer(reply=lambda body: _final())
    yield s
    s.close()


def _free_port_url() -> str:
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return f"http://127.0.0.1:{port}"


# ------------------------------------------------------------------ Ollama

def test_ollama_sends_system_messages_json_mode_and_reads_usage(server):
    c = OllamaClient("qwen2.5:7b-instruct", server.url, api_key="k-123", trust_env=False, num_ctx=8192)
    out = c.complete("SYS", MSGS)
    assert json.loads(out)["final"]["action"] == "hold"
    req = server.requests[-1]
    assert req["path"] == "/api/chat" and req["headers"]["Authorization"] == "Bearer k-123"
    body = req["body"]
    assert body["messages"][0] == {"role": "system", "content": "SYS"} and body["messages"][1:] == MSGS
    assert body["format"] == "json" and body["stream"] is False and body["keep_alive"] == "30m"
    assert body["options"] == {"temperature": 0.0, "num_ctx": 8192}
    assert c.last_usage == {"prompt_tokens": 120, "completion_tokens": 30}


def test_ollama_embed(server):
    c = OllamaClient("nomic-embed-text", server.url, trust_env=False)
    assert c.embed(["ab", "abcd"]) == [[2.0, 1.0, 0.0], [4.0, 1.0, 0.0]]


@pytest.mark.parametrize("code,exc", [(503, ModelUnavailable), (429, ModelUnavailable), (500, ModelUnavailable),
                                      (400, LLMError), (401, LLMError)])
def test_http_errors_are_classified(server, code, exc):
    server.fail_with = code
    with pytest.raises(exc) as ei:
        OllamaClient("qwen2.5:7b-instruct", server.url, trust_env=False).complete("s", MSGS)
    assert str(code) in str(ei.value)
    if exc is LLMError:
        assert not isinstance(ei.value, ModelUnavailable)


def test_unknown_model_is_a_config_error_not_an_outage(server):
    with pytest.raises(LLMError) as ei:
        OllamaClient("no-such-model", server.url, trust_env=False).complete("s", MSGS)
    assert not isinstance(ei.value, ModelUnavailable) and "not found" in str(ei.value)


def test_unreachable_and_timeout_are_outages(server):
    with pytest.raises(ModelUnavailable):
        OllamaClient("qwen2.5:7b-instruct", _free_port_url(), trust_env=False, timeout_s=2).complete("s", MSGS)
    server.fail_with, server.slow_s = "slow", 1.5
    with pytest.raises(ModelUnavailable):
        OllamaClient("qwen2.5:7b-instruct", server.url, trust_env=False, timeout_s=0.3).complete("s", MSGS)


def test_rejects_non_http_urls():
    with pytest.raises(ValueError):
        OllamaClient("m", "file:///etc/passwd")


# ------------------------------------------------------------------ OpenAI-compatible

def test_openai_compatible_client(server):
    c = OpenAICompatibleClient("qwen2.5:7b-instruct", server.url + "/v1", json_mode=True, trust_env=False)
    assert json.loads(c.complete("SYS", MSGS))["final"]["confidence"] == 0.95
    body = server.requests[-1]["body"]
    assert server.requests[-1]["path"] == "/v1/chat/completions"
    assert body["response_format"] == {"type": "json_object"} and body["messages"][0]["role"] == "system"
    assert c.last_usage == {"prompt_tokens": 100, "completion_tokens": 20}


# ------------------------------------------------------------------ fallback

class Clock:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t


def test_fallback_on_outage_with_cooldown(server):
    clock = Clock()
    claude = ScriptedLLM(fn=lambda s, m: "from-claude")
    claude.model = "claude"
    fb = FallbackClient(OllamaClient("qwen2.5:7b-instruct", server.url, trust_env=False), claude,
                        cooldown_s=60, clock=clock)
    assert json.loads(fb.complete("s", MSGS)) and fb.last_model == "qwen2.5:7b-instruct"
    server.fail_with = 503
    assert fb.complete("s", MSGS) == "from-claude" and fb.last_model == "claude"
    assert "503" in fb.last_fallback_reason
    n = len(server.requests)
    clock.t = 30                                    # in cool-down: the Mac mini is not even tried
    assert fb.complete("s", MSGS) == "from-claude" and len(server.requests) == n
    assert fb.last_fallback_reason == "primary in cool-down after an outage"
    server.fail_with = None
    clock.t = 61                                    # cool-down over: back to the local model
    fb.complete("s", MSGS)
    assert fb.last_model == "qwen2.5:7b-instruct" and len(server.requests) == n + 1
    assert fb.stats == {"primary": 2, "fallback": 2, "primary_errors": 1}


def test_fallback_on_config_error_has_no_cooldown(server):
    clock = Clock()
    fb = FallbackClient(OllamaClient("missing", server.url, trust_env=False),
                        ScriptedLLM(fn=lambda s, m: "fb"), clock=clock)
    assert fb.complete("s", MSGS) == "fb"
    assert fb.primary_available()           # a bad model name is not an outage; it keeps being tried (and seen)


def test_fallback_failure_surfaces_the_fallback_error():
    fb = FallbackClient(ScriptedLLM([ModelUnavailable("down")]), ScriptedLLM([RuntimeError("also down")]))
    with pytest.raises(RuntimeError, match="also down"):
        fb.complete("s", MSGS)


# ------------------------------------------------------------------ in the engine

def _overlay(backend):
    ov = make_overlay(backend)
    pats = []
    for p in ov.patterns:
        if p.id == "item_stuck_long":
            p = p.model_copy(update={"model_task": "triage"})
        pats.append(p)
    ov.patterns = pats
    return ov


def test_routine_pattern_goes_to_local_model_and_meters_tokens(engine_factory, backend, server):
    local = OllamaClient("qwen2.5:7b-instruct", server.url, trust_env=False)
    claude = ScriptedLLM(fn=lambda s, m: _final())
    claude.model = "claude"
    eng = engine_factory(llm=ModelRouter(routes={"triage": local}, default=claude), ov=_overlay(backend))
    eng.ingest(stuck_event(ref="I1"))
    assert backend.calls == [("hold", {"ref": "I1"})] and claude.calls == []
    runs = eng.store.model_runs()
    assert len(runs) == 1 and runs[0]["model"] == "qwen2.5:7b-instruct" and runs[0]["task"] == "triage"
    assert runs[0]["prompt_tokens"] == 120 and runs[0]["completion_tokens"] == 30
    assert "model_calls_total" in eng.metrics.render()


def test_unsure_local_answer_escalates_to_claude(engine_factory, backend, server):
    server.reply = lambda body: _final(conf=0.4)
    local = OllamaClient("qwen2.5:7b-instruct", server.url, trust_env=False)
    claude = ScriptedLLM(fn=lambda s, m: _final(conf=0.97))
    claude.model = "claude"
    router = ModelRouter(routes={"triage": local}, default=claude, escalations={"triage": claude},
                         escalate_below=0.75, prices={"claude": (3.0, 15.0)})
    eng = engine_factory(llm=router, ov=_overlay(backend))
    eng.ingest(stuck_event(ref="I1"))
    assert backend.calls == [("hold", {"ref": "I1"})] and len(claude.calls) == 1
    esc = [a["data"] for a in eng.store.audit_log() if a["kind"] == "model_escalated"]
    assert esc == [{"task": "triage", "from": "qwen2.5:7b-instruct", "to": "claude",
                    "reason": "confidence 0.40 below 0.75", "error": None}]
    runs = eng.store.model_runs()
    assert [(r["model"], bool(r["escalated"])) for r in runs] == [("qwen2.5:7b-instruct", False), ("claude", True)]
    assert runs[1]["est_cost"] > 0
    inc = eng.store.incidents()[0]
    assert inc.proposal.confidence == 0.97


def test_garbage_from_local_model_escalates(engine_factory, backend, server):
    server.reply = lambda body: "I think you should hold it"
    claude = ScriptedLLM(fn=lambda s, m: _final())
    claude.model = "claude"
    eng = engine_factory(llm=ModelRouter(routes={"triage": OllamaClient("qwen2.5:7b-instruct", server.url,
                                                                        trust_env=False)},
                                         escalations={"triage": claude}, escalate_below=0.5), ov=_overlay(backend))
    eng.ingest(stuck_event(ref="I1"))
    assert backend.calls == [("hold", {"ref": "I1"})]
    reason = [a["data"]["reason"] for a in eng.store.audit_log() if a["kind"] == "model_escalated"][0]
    assert "unusable model output" in reason


def test_mac_mini_down_falls_back_and_is_recorded(engine_factory, backend, server):
    server.fail_with = "drop"
    claude = ScriptedLLM(fn=lambda s, m: _final(ref=json.loads(m[0]["content"])["incident"]["facts"]["ref"]))
    claude.model = "claude"
    triage = FallbackClient(OllamaClient("qwen2.5:7b-instruct", server.url, trust_env=False, timeout_s=2), claude)
    eng = engine_factory(llm=ModelRouter(routes={"triage": triage}), ov=_overlay(backend))
    eng.ingest(stuck_event(ref="I1"))
    eng.ingest(stuck_event(ref="I2"))
    assert backend.calls == [("hold", {"ref": "I1"}), ("hold", {"ref": "I2"})]
    runs = eng.store.model_runs()
    assert [r["model"] for r in runs] == ["claude", "claude"]
    assert runs[0]["fallback_reason"].startswith("ModelUnavailable") and "cool-down" in runs[1]["fallback_reason"]
    assert "model_fallbacks_total" in eng.metrics.render()
    assert len(server.requests) == 1                  # second incident did not wait on the dead Mac mini


def test_customer_data_is_masked_before_the_local_model_too(engine_factory, backend, server):
    eng = engine_factory(llm=ModelRouter(routes={"triage": OllamaClient("qwen2.5:7b-instruct", server.url,
                                                                        trust_env=False)}), ov=_overlay(backend))
    ev = stuck_event()
    eng.ingest(ev.model_copy(update={"payload": {**ev.payload, "customer": "Asha Krishnan",
                                                 "note": "call 98450 12345"}}))
    wire = json.dumps([r["body"] for r in server.requests])
    assert "Asha Krishnan" not in wire and "98450 12345" not in wire


# ------------------------------------------------------------------ models file

def _fake_factory(spec):
    c = ScriptedLLM(fn=lambda s, m: _final())
    c.model = spec["model"]
    c.spec = spec
    return c


def test_load_models_builds_routes_fallbacks_escalation_candidates():
    r = load_models({
        "models": {"local": {"provider": "ollama", "model": "qwen"}, "claude": {"provider": "anthropic",
                                                                              "model": "claude-x"}},
        "routes": {"triage": {"model": "local", "fallback": "claude", "cooldown_s": 5}, "diagnose": "claude"},
        "default": "diagnose", "escalate": {"triage": "claude"}, "escalate_below": 0.7,
        "candidates": {"diagnose": "local"}, "prices": {"claude-x": [3, 15]},
    }, factory=_fake_factory)
    assert isinstance(r.routes["triage"], FallbackClient) and r.routes["triage"].cooldown_s == 5
    assert r.default is r.routes["diagnose"] and r.default.model == "claude-x"
    assert r.escalations["triage"].model == "claude-x" and r.escalate_below == 0.7
    assert r.candidates["diagnose"].model == "qwen" and r.prices == {"claude-x": (3.0, 15.0)}


@pytest.mark.parametrize("cfg,msg", [
    ({}, "models"),
    ({"models": {"a": {"provider": "ollama", "model": "m"}}, "routes": {"t": "b"}}, "unknown model"),
    ({"models": {"a": {"provider": "ollama", "model": "m"}}}, "routes"),
    ({"models": {"a": {"provider": "ollama", "model": "m"}}, "default": "a", "escalate_below": 2}, "escalate_below"),
])
def test_load_models_rejects_bad_config(cfg, msg):
    with pytest.raises(ValueError, match=msg):
        load_models(cfg, factory=_fake_factory)


def test_build_client_validates_provider_settings_and_keys(monkeypatch, tmp_path):
    from sentinel.providers import build_client
    with pytest.raises(ValueError, match="provider"):
        build_client({"provider": "magic", "model": "m"})
    with pytest.raises(ValueError, match="unknown settings"):
        build_client({"provider": "ollama", "model": "m", "colour": "blue"})
    with pytest.raises(ValueError, match="SENTINEL_SECRET_GW_KEY"):
        build_client({"provider": "ollama", "model": "m", "api_key_env": "SENTINEL_SECRET_GW_KEY"})
    monkeypatch.setenv("SENTINEL_SECRET_GW_KEY", "secret-key")
    c = build_client({"provider": "ollama", "model": "m", "api_key_env": "SENTINEL_SECRET_GW_KEY",
                      "base_url": "http://macmini:8090", "num_ctx": 4096})
    assert isinstance(c, OllamaClient) and c.api_key == "secret-key" and c.options["num_ctx"] == 4096
    f = tmp_path / "models.yaml"
    f.write_text("models:\n  local: {provider: openai_compatible, model: m, base_url: 'http://x:8000/v1'}\n"
                 "default: local\n")
    assert isinstance(load_models(f).default, OpenAICompatibleClient)


def test_pattern_model_task_does_not_reset_trust():
    p = Pattern(id="x", event_types=["e"], route=Route.AUTO, playbook=[PlaybookStep(action="a")])
    assert p.definition_hash() == p.model_copy(update={"model_task": "triage"}).definition_hash()
