# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""OpenTelemetry traces with the GenAI semantic conventions: off by default, no prompts unless opted in,
and nothing breaks when the optional extra is absent."""
from __future__ import annotations

import json
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from sentinel import ModelRouter, ScriptedLLM, otel
from sentinel.routing import MeteredClient
from tests.conftest import stuck_event

ROOT = Path(__file__).resolve().parent.parent
SECRET_PROMPT = "customer Asha Krishnan owes 4500"


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    monkeypatch.delenv("SENTINEL_OTEL", raising=False)
    monkeypatch.delenv("SENTINEL_OTEL_CAPTURE_CONTENT", raising=False)
    otel.reset()
    yield
    otel.reset()


@pytest.fixture
def spans():
    pytest.importorskip("opentelemetry.sdk.trace")
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
    exp = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exp))
    return provider, exp


class Reporting(ScriptedLLM):
    """A client that reports provider token counts, as the real ones do."""
    model = "claude-demo"
    last_usage = {"prompt_tokens": 123, "completion_tokens": 45}


def _final(ref="I1"):
    return json.dumps({"final": {"action": "hold", "params": {"ref": ref}, "disposition_code": "resolved",
                                 "confidence": 0.95, "rationale": "r"}})


def test_off_unless_configured(spans):
    provider, exp = spans
    assert not otel.enabled()
    router = ModelRouter(default=Reporting(["ok"]))
    assert router.client("diagnose").complete("s", [{"role": "user", "content": "u"}]) == "ok"
    with otel.span("x") as sp:
        sp.set(a=1)
    assert exp.get_finished_spans() == ()


def test_model_call_span_uses_genai_conventions(spans):
    provider, exp = spans
    otel.configure(tracer_provider=provider)
    router = ModelRouter(default=Reporting(["answer"]))
    router.client("diagnose").complete("sys", [{"role": "user", "content": "hello"}])
    (s,) = exp.get_finished_spans()
    a = dict(s.attributes)
    assert s.name == "chat claude-demo"
    assert a["gen_ai.operation.name"] == "chat" and a["gen_ai.request.model"] == "claude-demo"
    assert a["gen_ai.system"] == "_OTHER" and a["gen_ai.response.model"] == "claude-demo"
    assert a["gen_ai.usage.input_tokens"] == 123 and a["gen_ai.usage.output_tokens"] == 45
    assert a["sentinel.task"] == "diagnose"


def test_provider_names():
    from sentinel.providers import OllamaClient
    assert otel.provider_of(OllamaClient("m", base_url="http://localhost:11434")) == "ollama"
    assert otel.provider_of(object()) == "_OTHER"


def test_failed_call_is_an_error_span(spans):
    provider, exp = spans
    otel.configure(tracer_provider=provider)
    router = ModelRouter(default=ScriptedLLM([RuntimeError("503 overloaded")]))
    with pytest.raises(RuntimeError):
        router.client("diagnose").complete("s", [])
    (s,) = exp.get_finished_spans()
    assert s.status.status_code.name == "ERROR" and s.attributes["error.type"] == "RuntimeError"


def test_prompts_and_replies_are_not_in_spans_by_default(spans):
    provider, exp = spans
    otel.configure(tracer_provider=provider)
    c = MeteredClient(ScriptedLLM([f"reply about {SECRET_PROMPT}"]), "diagnose", lambda run: None)
    c.complete(f"system: {SECRET_PROMPT}", [{"role": "user", "content": SECRET_PROMPT}])
    (s,) = exp.get_finished_spans()
    blob = json.dumps({k: str(v) for k, v in s.attributes.items()}) + json.dumps([e.name for e in s.events])
    assert "Asha" not in blob and not s.events
    assert not any(k in s.attributes for k in ("gen_ai.input.messages", "gen_ai.output.messages",
                                               "gen_ai.system_instructions"))


def test_content_only_with_the_explicit_opt_in(spans):
    provider, exp = spans
    otel.configure(tracer_provider=provider, capture_content=True)
    c = MeteredClient(ScriptedLLM([f"reply {SECRET_PROMPT}"]), "diagnose", lambda run: None)
    c.complete("sys", [{"role": "user", "content": SECRET_PROMPT}])
    (s,) = exp.get_finished_spans()
    assert SECRET_PROMPT in s.attributes["gen_ai.input.messages"]
    assert SECRET_PROMPT in s.attributes["gen_ai.output.messages"]


def test_content_opt_in_from_the_environment(spans, monkeypatch):
    provider, exp = spans
    monkeypatch.setenv("SENTINEL_OTEL", "1")
    monkeypatch.setenv("SENTINEL_OTEL_CAPTURE_CONTENT", "1")
    otel.configure(tracer_provider=provider)            # capture left to the environment
    MeteredClient(ScriptedLLM(["r"]), "t", lambda run: None).complete("s", [{"role": "user", "content": "q"}])
    assert "gen_ai.input.messages" in exp.get_finished_spans()[0].attributes


def test_case_span_with_the_model_call_as_its_child(engine_factory, backend, spans):
    provider, exp = spans
    otel.configure(tracer_provider=provider)
    llm = Reporting(fn=lambda s, m: _final())
    eng = engine_factory(llm=ModelRouter(default=llm))
    eng.ingest(stuck_event(ref="I1"))
    assert backend.calls == [("hold", {"ref": "I1"})]
    finished = exp.get_finished_spans()
    case = [s for s in finished if s.name == "sentinel.case.handle"]
    chat = [s for s in finished if s.name.startswith("chat ")]
    assert len(case) == 1 and len(chat) == 1
    assert chat[0].parent.span_id == case[0].context.span_id            # nested, also across the model's thread
    assert chat[0].context.trace_id == case[0].context.trace_id
    a = case[0].attributes
    assert a["sentinel.incident_id"].startswith("inc_") and a["sentinel.route"] == "llm"
    assert a["sentinel.state"] and a["sentinel.tenant"] == "default"
    assert not any("Asha" in str(v) for s in finished for v in s.attributes.values())


def test_case_span_without_a_model(engine_factory, spans):
    provider, exp = spans
    otel.configure(tracer_provider=provider)
    eng = engine_factory()
    eng.ingest(stuck_event(ref="I9"))
    assert [s.name for s in exp.get_finished_spans()] == ["sentinel.case.handle"]


def test_tracing_does_not_change_the_outcome(engine_factory, backend, spans):
    provider, _ = spans
    eng = engine_factory(llm=ModelRouter(default=ScriptedLLM(fn=lambda s, m: _final("I3"))))
    eng.ingest(stuck_event(ref="I3"))
    plain = list(backend.calls)
    backend.calls.clear()
    otel.configure(tracer_provider=provider)
    eng2 = engine_factory(llm=ModelRouter(default=ScriptedLLM(fn=lambda s, m: _final("I3"))))
    eng2.ingest(stuck_event(ref="I3"))
    assert backend.calls == plain


def test_a_broken_tracer_never_breaks_a_case(engine_factory, backend, monkeypatch):
    pytest.importorskip("opentelemetry")
    otel.configure()
    monkeypatch.setattr(otel, "_tracer", lambda: (_ for _ in ()).throw(RuntimeError("exporter down")))
    eng = engine_factory(llm=ModelRouter(default=ScriptedLLM(fn=lambda s, m: _final())))
    eng.ingest(stuck_event(ref="I1"))
    assert backend.calls == [("hold", {"ref": "I1"})]


def test_env_switch_without_the_extra_warns_and_works(engine_factory, backend, monkeypatch, caplog):
    monkeypatch.setenv("SENTINEL_OTEL", "1")
    monkeypatch.setattr(otel, "_api", lambda: None)
    eng = engine_factory(llm=ModelRouter(default=ScriptedLLM(fn=lambda s, m: _final())))
    eng.ingest(stuck_event(ref="I1"))
    assert backend.calls == [("hold", {"ref": "I1"})]
    assert not otel.enabled()
    with pytest.raises(ImportError, match=r"kbg-sentinel\[otel\]"):
        otel.configure()


def test_really_absent_extra_in_a_fresh_interpreter():
    """The import is blocked outright (not mocked): Sentinel must run, with the switch on, and never import it."""
    code = textwrap.dedent("""
        import sys
        for m in ("opentelemetry", "opentelemetry.trace", "opentelemetry.sdk"):
            sys.modules[m] = None                       # any import of it raises ImportError
        import os
        os.environ["SENTINEL_OTEL"] = "1"
        from sentinel import ModelRouter, ScriptedLLM, otel
        from sentinel.routing import MeteredClient
        r = ModelRouter(default=ScriptedLLM(["fine"]))
        assert r.client("t").complete("s", []) == "fine"
        with otel.span("x") as sp:
            sp.set(a=1)
        assert otel.enabled() is False
        print("OK")
    """)
    r = subprocess.run([sys.executable, "-c", code], cwd=ROOT, capture_output=True, text=True, timeout=120)
    assert r.returncode == 0 and "OK" in r.stdout, r.stderr[-800:]


def test_importing_sentinel_does_not_import_opentelemetry():
    code = "import sys, sentinel, sentinel.engine, sentinel.routing; print('opentelemetry' in sys.modules)"
    r = subprocess.run([sys.executable, "-c", code], cwd=ROOT, capture_output=True, text=True, timeout=120)
    assert r.stdout.strip() == "False", r.stderr[-500:]
