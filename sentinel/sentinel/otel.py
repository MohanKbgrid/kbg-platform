# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""OpenTelemetry traces beside the Prometheus metrics. Optional (`pip install "kbg-sentinel[otel]"`) and OFF.

Switched on by `SENTINEL_OTEL=1` in the environment, or by `configure()` from code that embeds Sentinel. Off, every
function here does nothing and `opentelemetry` is never imported; on but not installed, Sentinel logs one warning
and carries on without traces. Spans are created through the OpenTelemetry API on the global tracer provider (or the
one passed to `configure`), so the operator chooses the exporter the usual way (the SDK, `opentelemetry-instrument`,
OTEL_* variables); Sentinel does not ship or pick one.

Spans:

    sentinel.case.handle        one per case handled (a worker picking it up, or inline); sentinel.* attributes
      chat <model>              one per model call, as a child; the GenAI semantic conventions:
                                gen_ai.operation.name, gen_ai.system, gen_ai.provider.name, gen_ai.request.model,
                                gen_ai.response.model, gen_ai.usage.input_tokens, gen_ai.usage.output_tokens,
                                error.type (on failure), sentinel.task, sentinel.shadow

Privacy: prompts and replies are never logged by Sentinel and are NOT put in spans. Only with the explicit opt-in
`SENTINEL_OTEL_CAPTURE_CONTENT=1` (or `configure(capture_content=True)`) the model span also carries
gen_ai.system_instructions, gen_ai.input.messages and gen_ai.output.messages, which can hold personal data and
business facts: send those only to a backend you would trust with the cases themselves.
"""
from __future__ import annotations

import contextlib
import json
import logging
import os
import threading
from collections.abc import Iterator
from typing import Any

log = logging.getLogger("sentinel.otel")

_TRUE = {"1", "true", "yes", "on"}
_lock = threading.Lock()
_state: dict[str, Any] = {"on": False, "provider": None, "capture": None, "warned": False}


def _truthy(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in _TRUE


def _api() -> Any:
    try:
        from opentelemetry import trace
        return trace
    except ImportError:
        return None


def configure(*, tracer_provider: Any = None, capture_content: bool | None = None) -> None:
    """Turn tracing on from code. `tracer_provider` defaults to the global one. Raises ImportError when the
    `otel` extra is not installed (an explicit request that cannot be met is an error; the environment switch
    only warns)."""
    if _api() is None:
        raise ImportError('OpenTelemetry is not installed: pip install "kbg-sentinel[otel]"')
    with _lock:
        _state.update(on=True, provider=tracer_provider, capture=capture_content)


def reset() -> None:
    """Back to the default (off unless SENTINEL_OTEL is set). For tests and embedders."""
    with _lock:
        _state.update(on=False, provider=None, capture=None, warned=False)


def enabled() -> bool:
    if not (_state["on"] or _truthy("SENTINEL_OTEL")):
        return False
    if _api() is None:
        if not _state["warned"]:
            _state["warned"] = True
            log.warning('SENTINEL_OTEL is set but OpenTelemetry is not installed (pip install "kbg-sentinel[otel]"); '
                        "no traces are produced")
        return False
    return True


def capture_content() -> bool:
    """Prompts and replies go into spans only on this explicit opt-in."""
    if not enabled():
        return False
    c = _state["capture"]
    return bool(c) if c is not None else _truthy("SENTINEL_OTEL_CAPTURE_CONTENT")


def _tracer() -> Any:
    from . import __version__
    trace = _api()
    return trace.get_tracer("sentinel", __version__, tracer_provider=_state["provider"])


def _clean(attrs: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in attrs.items() if v is not None}


class _NoSpan:
    def set(self, **attrs: Any) -> None:
        return None


class _Live:
    def __init__(self, span: Any) -> None:
        self._s = span

    def set(self, **attrs: Any) -> None:
        for k, v in _clean(attrs).items():
            self._s.set_attribute(k, v)


_NOSPAN = _NoSpan()


@contextlib.contextmanager
def span(name: str, attributes: dict[str, Any] | None = None, *,
         ignore: tuple[type[BaseException], ...] = ()) -> Iterator[Any]:
    """A span that is current inside the block. An exception marks it as an error, except those in `ignore`
    (control flow, such as a lease lost). A tracing failure never reaches the caller."""
    if not enabled():
        yield _NOSPAN
        return
    try:
        cm = _tracer().start_as_current_span(name, attributes=_clean(attributes or {}), record_exception=False,
                                             set_status_on_exception=False)
        s = cm.__enter__()
    except Exception:  # noqa: BLE001 - observability must not break a case
        log.debug("could not start span %s", name, exc_info=True)
        yield _NOSPAN
        return
    live = _Live(s)
    try:
        yield live
    except BaseException as e:
        if not isinstance(e, ignore):
            _fail(s, e)
        _leave(cm)
        raise
    else:
        _leave(cm)


def _fail(s: Any, e: BaseException) -> None:
    try:
        from opentelemetry.trace import Status, StatusCode
        s.set_attribute("error.type", type(e).__qualname__)
        s.set_status(Status(StatusCode.ERROR, str(e)[:200]))
    except Exception:  # noqa: BLE001,S110 - best effort
        pass


def _leave(cm: Any) -> None:
    try:
        cm.__exit__(None, None, None)
    except Exception:  # noqa: BLE001,S110 - best effort
        pass


# ---- model calls (GenAI semantic conventions) ---------------------------------------------------------------

_PROVIDERS = {"AnthropicClient": "anthropic", "OllamaClient": "ollama", "OpenAICompatibleClient": "openai",
              "CrewClient": "sentinel.crew"}


def provider_of(client: Any) -> str:
    inner = getattr(client, "primary", client)            # a FallbackClient reports its primary
    return _PROVIDERS.get(type(inner).__name__, "_OTHER")


class ModelCall:
    """One model call's span. Created before the call, `finish`ed after; a no-op when tracing is off."""

    def __init__(self, span_: Any = None, capture: bool = False) -> None:
        self._s, self._capture = span_, capture

    def finish(self, *, answered_by: str | None = None, input_tokens: int | None = None,
               output_tokens: int | None = None, error: str | None = None, reply: str | None = None) -> None:
        s = self._s
        if s is None:
            return
        try:
            _Live(s).set(**{"gen_ai.response.model": answered_by, "gen_ai.usage.input_tokens": input_tokens,
                            "gen_ai.usage.output_tokens": output_tokens})
            if self._capture and reply is not None:
                s.set_attribute("gen_ai.output.messages",
                                json.dumps([{"role": "assistant", "content": reply}], default=str))
            if error is not None:
                from opentelemetry.trace import Status, StatusCode
                s.set_attribute("error.type", error.split(":", 1)[0] or "error")
                s.set_status(Status(StatusCode.ERROR, error[:200]))
        except Exception:  # noqa: BLE001,S110 - best effort
            pass
        finally:
            try:
                s.end()
            except Exception:  # noqa: BLE001,S110
                pass


_NOCALL = ModelCall()


def model_call(model: str, provider: str, *, task: str | None = None, shadow: bool = False, system: str = "",
               messages: list[dict[str, str]] | None = None) -> ModelCall:
    """Start the span for a chat call to `model`. A child of the case being handled, if there is one."""
    if not enabled():
        return _NOCALL
    try:
        cap = capture_content()
        s = _tracer().start_span(f"chat {model}", attributes=_clean({
            "gen_ai.operation.name": "chat", "gen_ai.system": provider, "gen_ai.provider.name": provider,
            "gen_ai.request.model": model, "sentinel.task": task, "sentinel.shadow": shadow or None}))
        if cap:
            s.set_attribute("gen_ai.system_instructions", json.dumps([{"type": "text", "content": system}]))
            s.set_attribute("gen_ai.input.messages", json.dumps(messages or [], default=str))
        return ModelCall(s, cap)
    except Exception:  # noqa: BLE001 - observability must not break a model call
        log.debug("could not start model span", exc_info=True)
        return _NOCALL
