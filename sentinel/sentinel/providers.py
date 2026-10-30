# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""Model providers and the models file.

Every client has one method, ``complete(system, messages) -> str``, so the engine never knows which
provider answered.

* ``OllamaClient``           - Ollama's native chat API (a local small model, e.g. on the office Mac mini,
                               usually reached through ``sentinel gateway``).
* ``OpenAICompatibleClient`` - any server speaking the OpenAI chat-completions format: vLLM, llama.cpp
                               server, LiteLLM, LM Studio, Ollama's /v1.
* ``AnthropicClient``        - Claude (in ``sentinel.llm``).
* ``FallbackClient``         - try a primary model, answer from a fallback when it fails; after an outage
                               the primary is skipped for a cool-down so every call does not wait on it.

``load_models(path_or_dict)`` builds a ``ModelRouter`` from YAML, so changing models is configuration::

    models:
      local:  {provider: ollama, model: "qwen2.5:7b-instruct", base_url: "http://macmini:8090",
               api_key_env: SENTINEL_GATEWAY_KEY}
      claude: {provider: anthropic, model: claude-sonnet-5-5}
    routes:
      triage:   {model: local, fallback: claude}   # routine patterns (model_task: triage)
      diagnose: claude                             # everything else
    default: diagnose
    escalate: {triage: claude}                     # re-ask Claude when the small model is unsure
    escalate_below: 0.75
    candidates: {diagnose: local}                  # shadow-test the small model on Claude's work
    embedder: local-embed                          # similar-case search (a model with .embed)
    prices: {claude-sonnet-5-5: [0.003, 0.015]}    # per 1k tokens (in, out), for cost estimates

Only the standard library is used for HTTP, so the core install stays small.
"""
from __future__ import annotations

import json
import os
import threading
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from pathlib import Path
from typing import Any

from .llm import LLMError
from .routing import Completer, ModelRouter

_RETRYABLE_HTTP = {408, 409, 425, 429, 500, 502, 503, 504}


class ModelUnavailable(LLMError):
    """The provider could not be reached or is overloaded (connection refused, timeout, 429, 5xx)."""


class _HTTPClient:
    """Shared JSON-over-HTTP plumbing. Never logs or echoes request bodies."""

    def __init__(self, base_url: str, *, timeout_s: float, api_key: str | None, trust_env: bool,
                 headers: dict[str, str] | None = None) -> None:
        if not base_url.startswith(("http://", "https://")):
            raise ValueError(f"base_url must be http(s): {base_url!r}")
        self.base_url = base_url.rstrip("/")
        self.timeout_s = timeout_s
        self.api_key = api_key
        self.headers = dict(headers or {})
        handlers: list[Any] = [] if trust_env else [urllib.request.ProxyHandler({})]
        self._opener = urllib.request.build_opener(*handlers)
        self._local = threading.local()

    @property
    def last_usage(self) -> dict[str, int]:
        return getattr(self._local, "usage", {})

    def _post(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        body = json.dumps(payload).encode()
        req = urllib.request.Request(self.base_url + path, data=body, method="POST",  # noqa: S310 - http(s) only
                                     headers={"Content-Type": "application/json",
                                              "X-Request-Timeout": str(int(self.timeout_s)), **self.headers})
        if self.api_key:
            req.add_header("Authorization", f"Bearer {self.api_key}")
        from . import egress
        try:
            _, _, raw = egress.open_url(req, self.timeout_s, base_opener=self._opener)
        except egress.EgressError as e:
            raise LLMError(f"{self.base_url}: {e}") from None
        except urllib.error.HTTPError as e:
            detail = ""
            try:
                detail = e.read(300).decode("utf-8", "replace").strip()
            except Exception:  # noqa: BLE001,S110 - the detail is best effort
                pass
            msg = f"{self.base_url}{path} returned HTTP {e.code}" + (f": {detail}" if detail else "")
            raise (ModelUnavailable if e.code in _RETRYABLE_HTTP else LLMError)(msg) from None
        except (urllib.error.URLError, TimeoutError, ConnectionError, OSError) as e:
            reason = getattr(e, "reason", e)
            raise ModelUnavailable(f"{self.base_url} unreachable: {reason}") from None
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            raise LLMError(f"{self.base_url}{path} returned non-JSON") from None
        if not isinstance(data, dict):
            raise LLMError(f"{self.base_url}{path} returned a non-object")
        return data


class OllamaClient(_HTTPClient):
    """Ollama native chat API (``POST /api/chat``), non-streaming.

    ``json_mode`` asks Ollama to constrain output to JSON, which makes small models far more reliable
    for the resolver's JSON protocol. ``keep_alive`` keeps the model loaded between calls.
    """

    def __init__(self, model: str, base_url: str = "http://localhost:11434", *, timeout_s: float = 60.0,
                 api_key: str | None = None, json_mode: bool = True, temperature: float = 0.0,
                 num_ctx: int | None = 8192, keep_alive: str | None = "30m", trust_env: bool = True,
                 headers: dict[str, str] | None = None) -> None:
        super().__init__(base_url, timeout_s=timeout_s, api_key=api_key, trust_env=trust_env, headers=headers)
        self.model = model
        self.json_mode = json_mode
        self.options: dict[str, Any] = {"temperature": temperature}
        if num_ctx:
            self.options["num_ctx"] = num_ctx
        self.keep_alive = keep_alive

    def complete(self, system: str, messages: list[dict[str, str]]) -> str:
        payload: dict[str, Any] = {"model": self.model, "stream": False, "options": self.options,
                                   "messages": [{"role": "system", "content": system}, *messages]}
        if self.json_mode:
            payload["format"] = "json"
        if self.keep_alive is not None:
            payload["keep_alive"] = self.keep_alive
        data = self._post("/api/chat", payload)
        if data.get("error"):
            raise LLMError(f"ollama: {data['error']}")
        msg = data.get("message")
        if not isinstance(msg, dict) or not isinstance(msg.get("content"), str):
            raise LLMError("ollama reply has no message content")
        self._local.usage = {"prompt_tokens": int(data.get("prompt_eval_count") or 0),
                             "completion_tokens": int(data.get("eval_count") or 0)}
        return msg["content"]

    def embed(self, texts: list[str]) -> list[list[float]]:
        """Embedding vectors (``POST /api/embed``), for similar-case search."""
        data = self._post("/api/embed", {"model": self.model, "input": texts,
                                         **({"keep_alive": self.keep_alive} if self.keep_alive else {})})
        vecs = data.get("embeddings")
        if not isinstance(vecs, list) or len(vecs) != len(texts):
            raise LLMError("ollama embed reply has no embeddings")
        return vecs


class OpenAICompatibleClient(_HTTPClient):
    """``POST {base_url}/chat/completions``; base_url usually ends in ``/v1``."""

    def __init__(self, model: str, base_url: str = "http://localhost:11434/v1", *, timeout_s: float = 60.0,
                 api_key: str | None = None, json_mode: bool = False, temperature: float = 0.0,
                 max_tokens: int = 1024, trust_env: bool = True, headers: dict[str, str] | None = None) -> None:
        super().__init__(base_url, timeout_s=timeout_s, api_key=api_key, trust_env=trust_env, headers=headers)
        self.model = model
        self.json_mode = json_mode
        self.temperature = temperature
        self.max_tokens = max_tokens

    def complete(self, system: str, messages: list[dict[str, str]]) -> str:
        payload: dict[str, Any] = {"model": self.model, "temperature": self.temperature,
                                   "max_tokens": self.max_tokens, "stream": False,
                                   "messages": [{"role": "system", "content": system}, *messages]}
        if self.json_mode:
            payload["response_format"] = {"type": "json_object"}
        data = self._post("/chat/completions", payload)
        try:
            content = data["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError):
            raise LLMError("chat-completions reply has no choices[0].message.content") from None
        if not isinstance(content, str):
            raise LLMError("chat-completions content is not text")
        usage = data.get("usage") or {}
        self._local.usage = {"prompt_tokens": int(usage.get("prompt_tokens") or 0),
                             "completion_tokens": int(usage.get("completion_tokens") or 0)}
        return content

    def embed(self, texts: list[str]) -> list[list[float]]:
        """``POST {base_url}/embeddings``."""
        data = self._post("/embeddings", {"model": self.model, "input": texts})
        rows = data.get("data")
        if not isinstance(rows, list) or len(rows) != len(texts):
            raise LLMError("embeddings reply has no data")
        rows = sorted(rows, key=lambda r: r.get("index", 0)) if all("index" in r for r in rows) else rows
        return [r["embedding"] for r in rows]


def _name(client: Any) -> str:
    return str(getattr(client, "model", None) or type(client).__name__)


class FallbackClient:
    """Primary first, fallback on failure.

    Any primary error falls back for that call. A *ModelUnavailable* error (unreachable, overloaded) also
    opens a cool-down during which the primary is skipped, so an office power cut costs one timeout,
    not one per incident. ``last_model`` (per thread) says which model actually answered.
    """

    def __init__(self, primary: Completer, fallback: Completer, *, cooldown_s: float = 60.0,
                 clock: Callable[[], float] = time.monotonic) -> None:
        self.primary, self.fallback = primary, fallback
        self.cooldown_s = cooldown_s
        self.clock = clock
        self.model = _name(primary)
        self._skip_until = 0.0
        self._guard = threading.Lock()
        self._local = threading.local()
        self.stats = {"primary": 0, "fallback": 0, "primary_errors": 0}

    @property
    def last_model(self) -> str | None:
        return getattr(self._local, "model", None)

    @property
    def last_fallback_reason(self) -> str | None:
        return getattr(self._local, "reason", None)

    def primary_available(self) -> bool:
        with self._guard:
            return self.clock() >= self._skip_until

    def complete(self, system: str, messages: list[dict[str, str]]) -> str:
        reason = None
        if self.primary_available():
            try:
                out = self.primary.complete(system, messages)
                with self._guard:
                    self.stats["primary"] += 1
                self._local.model, self._local.reason = _name(self.primary), None
                return out
            except Exception as e:  # noqa: BLE001 - any primary failure falls back
                reason = f"{type(e).__name__}: {e}"
                with self._guard:
                    self.stats["primary_errors"] += 1
                    if isinstance(e, ModelUnavailable):
                        self._skip_until = self.clock() + self.cooldown_s
        else:
            reason = "primary in cool-down after an outage"
        out = self.fallback.complete(system, messages)
        with self._guard:
            self.stats["fallback"] += 1
        self._local.model, self._local.reason = _name(self.fallback), reason
        return out


# ---- models file ------------------------------------------------------------

_PROVIDERS = ("ollama", "openai_compatible", "anthropic", "hashing", "crew")


def build_client(spec: dict[str, Any]) -> Completer:
    """One model from its spec: {provider, model, base_url?, api_key_env?, timeout_s?, ...}."""
    spec = dict(spec)
    provider = spec.pop("provider", None)
    if provider not in _PROVIDERS:
        raise ValueError(f"provider must be one of {_PROVIDERS}, got {provider!r}")
    if provider == "hashing":          # lexical embedder, no model needed
        from .similarity import HashingEmbedder
        unknown = set(spec) - {"dim"}
        if unknown:
            raise ValueError(f"hashing: unknown settings {sorted(unknown)}")
        return HashingEmbedder(int(spec.get("dim", 256)))  # type: ignore[return-value]
    model = spec.pop("model", None)
    if not model:
        raise ValueError(f"{provider}: 'model' is required")
    key_env = spec.pop("api_key_env", None)
    if key_env and provider != "anthropic":       # a key sent to a configurable URL must be one meant for it
        from .envsecrets import require_allowed
        require_allowed(key_env, f"{provider}/{model}")
    api_key = os.environ.get(key_env) if key_env else None
    if key_env and not api_key:
        raise ValueError(f"{provider}/{model}: environment variable {key_env} is not set")
    if provider == "anthropic":
        from .llm import AnthropicClient
        allowed = {k: spec[k] for k in ("max_tokens", "timeout_s") if k in spec}
        return AnthropicClient(model=model, api_key=api_key, **allowed)
    cls = OllamaClient if provider == "ollama" else OpenAICompatibleClient
    known = {"base_url", "timeout_s", "json_mode", "temperature", "trust_env", "headers"} | (
        {"num_ctx", "keep_alive"} if provider == "ollama" else {"max_tokens"})
    unknown = set(spec) - known
    if unknown:
        raise ValueError(f"{provider}/{model}: unknown settings {sorted(unknown)}")
    return cls(model, api_key=api_key, **spec)


def load_models(source: str | Path | dict[str, Any], *,
                factory: Callable[[dict[str, Any]], Completer] = build_client) -> ModelRouter:
    """Build a ModelRouter from a models file (see module docstring). ``factory`` is replaceable for tests."""
    if isinstance(source, dict):
        cfg = source
    else:
        import yaml
        cfg = yaml.safe_load(Path(source).read_text(encoding="utf-8")) or {}
    specs = cfg.get("models") or {}
    if not isinstance(specs, dict) or not specs:
        raise ValueError("models file needs a 'models' section")
    crews = {n: s for n, s in specs.items() if isinstance(s, dict) and s.get("provider") == "crew"}
    built = {name: factory(spec) for name, spec in specs.items() if name not in crews}
    for name, spec in crews.items():                 # a crew thinks with another model in this file
        from .crew import crew_from_spec
        inner = spec.get("llm")
        if inner not in built:
            raise ValueError(f"models.{name}: 'llm' must name another (non-crew) model in this file, got {inner!r}")
        built[name] = crew_from_spec(name, spec, built[inner])

    def ref(value: Any, where: str) -> Completer:
        if isinstance(value, str):
            if value not in built:
                raise ValueError(f"{where}: unknown model {value!r} (known: {sorted(built)})")
            return built[value]
        if isinstance(value, dict) and "model" in value:
            primary = ref(value["model"], where)
            if value.get("fallback"):
                return FallbackClient(primary, ref(value["fallback"], where + ".fallback"),
                                      cooldown_s=float(value.get("cooldown_s", 60)))
            return primary
        raise ValueError(f"{where}: expected a model name or {{model, fallback}}")

    routes = {task: ref(v, f"routes.{task}") for task, v in (cfg.get("routes") or {}).items()}
    default = None
    if cfg.get("default") is not None:
        d = cfg["default"]
        default = routes[d] if d in routes else ref(d, "default")
    escalations = {task: ref(v, f"escalate.{task}") for task, v in (cfg.get("escalate") or {}).items()}
    candidates = {task: ref(v, f"candidates.{task}") for task, v in (cfg.get("candidates") or {}).items()}
    prices = {str(k): (float(v[0]), float(v[1])) for k, v in (cfg.get("prices") or {}).items()}
    below = float(cfg.get("escalate_below", 0.0))
    if not 0 <= below <= 1:
        raise ValueError("escalate_below must be within [0,1]")
    embedder = None
    if cfg.get("embedder") is not None:
        embedder = ref(cfg["embedder"], "embedder")
        if not callable(getattr(embedder, "embed", None)):
            raise ValueError("embedder: that model cannot make embeddings (use ollama, openai_compatible or hashing)")
    for where, c in [*(("routes." + t, c) for t, c in routes.items()), ("default", default),
                     *(("escalate." + t, c) for t, c in escalations.items()),
                     *(("candidates." + t, c) for t, c in candidates.items())]:
        if c is not None and not callable(getattr(c, "complete", None)):
            raise ValueError(f"{where}: that model cannot answer prompts (embedding-only)")
    if not routes and default is None:
        raise ValueError("models file needs 'routes' or a 'default'")
    budget = cfg.get("daily_budget")
    if budget is not None and float(budget) < 0:
        raise ValueError("daily_budget must be >= 0")
    router = ModelRouter(routes=routes, default=default, candidates=candidates, prices=prices,
                         daily_budget=float(budget) if budget is not None else None,
                         escalations=escalations, escalate_below=below, embedder=embedder)
    router.named = dict(built)
    router.source = cfg
    return router
