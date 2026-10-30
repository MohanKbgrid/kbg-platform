# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""Model gateway: one shared small-model host (e.g. the office Mac mini running Ollama) serving many customers.

    sentinel gateway --config gateway.yaml --port 8090         # pip install "kbg-sentinel[api]"

Ollama itself has no accounts, limits or metering, so it listens only on 127.0.0.1 and this gateway is
the one door in. Per request the gateway:

* authenticates the customer by bearer token (only SHA-256 hashes are configured);
* allows only inference endpoints (chat, generate, embeddings; never pull / delete / create / push) and
  only the models that customer is allowed;
* applies a per-customer request rate and a per-customer cap on simultaneous requests, inside a global
  cap that protects the machine, so one busy customer cannot starve the others;
* forwards to Ollama and records usage (customer, model, tokens, latency, status) for billing:
  metrics, `GET /usage`, and a monthly JSON-lines ledger.

Prompts and replies are never logged or stored. Streaming is refused (Sentinel never streams).

gateway.yaml::

    upstream: http://127.0.0.1:11434
    max_concurrent: 4          # whole machine
    queue_timeout_s: 30        # wait for a slot this long, then 503 (the client falls back to Claude)
    upstream_timeout_s: 300
    usage_dir: /var/lib/sentinel-gateway
    public_metrics: false      # true lets Prometheus scrape /metrics without the admin token
    admins:  [{sha256: 4f2a...}]
    tenants:
      - {name: acme, sha256: 9c1e..., max_concurrent: 2, per_minute: 120,
         models: ["qwen2.5:7b-instruct", "nomic-embed-text"]}
"""
from __future__ import annotations

import asyncio
import json
import logging
import threading
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, PlainTextResponse

from .api import RateLimiter, token_hash
from .observe import Metrics

log = logging.getLogger("sentinel.gateway")

CHAT_PATHS = {"/api/chat", "/api/generate", "/v1/chat/completions", "/v1/completions"}
EMBED_PATHS = {"/api/embed", "/api/embeddings", "/v1/embeddings"}
INFERENCE_PATHS = CHAT_PATHS | EMBED_PATHS
# what a tenant may set; everything else is dropped (keep_alive, other tenants' model settings ...)
ALLOWED_FIELDS = {"model", "messages", "prompt", "system", "stream", "format", "options", "input", "max_tokens",
                  "temperature", "top_p", "seed", "stop", "response_format", "n"}
ALLOWED_OPTIONS = {"temperature", "top_p", "top_k", "seed", "stop", "num_predict", "num_ctx", "repeat_penalty"}


def clamp_body(body: dict[str, Any], cfg: Any) -> dict[str, Any]:
    """Only the fields a request may set, with the host's limits applied, so one tenant cannot unload or
    starve another's model (huge contexts, endless generation, its own keep_alive)."""
    out = {k: v for k, v in body.items() if k in ALLOWED_FIELDS}
    if isinstance(out.get("options"), dict):
        opts = {k: v for k, v in out["options"].items() if k in ALLOWED_OPTIONS}
        if isinstance(opts.get("num_ctx"), (int, float)):
            opts["num_ctx"] = int(min(opts["num_ctx"], cfg.max_num_ctx))
        if isinstance(opts.get("num_predict"), (int, float)):
            opts["num_predict"] = int(min(opts["num_predict"], cfg.max_num_predict))
        out["options"] = opts
    elif "options" in out:
        del out["options"]
    if isinstance(out.get("max_tokens"), (int, float)):
        out["max_tokens"] = int(min(out["max_tokens"], cfg.max_num_predict))
    if cfg.keep_alive is not None:
        out["keep_alive"] = cfg.keep_alive
    return out


@dataclass(frozen=True)
class Tenant:
    name: str
    max_concurrent: int = 2
    per_minute: int = 120
    models: frozenset[str] | None = None          # None: every model on the host

    def allows(self, model: str) -> bool:
        if self.models is None:
            return True
        return model in self.models or model.split(":")[0] in self.models


@dataclass
class GatewayConfig:
    upstream: str = "http://127.0.0.1:11434"
    tenants: dict[str, Tenant] = field(default_factory=dict)       # sha256(token) -> tenant
    admins: set[str] = field(default_factory=set)                  # sha256(token)
    max_concurrent: int = 4
    queue_timeout_s: float = 30.0
    upstream_timeout_s: float = 120.0     # never longer than a client may wait (clients send their own limit)
    max_body_bytes: int = 2_000_000
    max_num_ctx: int = 16384
    max_num_predict: int = 2048
    keep_alive: str | None = "30m"        # the host decides how long models stay loaded
    usage_dir: str | None = None
    public_metrics: bool = False

    def __post_init__(self) -> None:
        if not self.upstream.startswith(("http://", "https://")):
            raise ValueError("upstream must be http(s)")
        if self.max_concurrent < 1:
            raise ValueError("max_concurrent must be >= 1")
        names = [t.name for t in self.tenants.values()]
        if len(names) != len(set(names)):
            raise ValueError("tenant names must be unique")
        for t in self.tenants.values():
            if t.max_concurrent < 1 or t.per_minute < 1:
                raise ValueError(f"tenant {t.name}: limits must be >= 1")


def load_gateway_config(source: str | Path | dict[str, Any]) -> GatewayConfig:
    if isinstance(source, dict):
        cfg = source
    else:
        import yaml
        cfg = yaml.safe_load(Path(source).read_text(encoding="utf-8")) or {}
    tenants: dict[str, Tenant] = {}
    for t in cfg.get("tenants") or []:
        h = str(t["sha256"]).lower()
        if len(h) != 64:
            raise ValueError(f"tenant {t.get('name')}: sha256 must be 64 hex characters")
        if h in tenants:
            raise ValueError(f"tenant {t.get('name')}: token hash already used by {tenants[h].name}")
        models = t.get("models")
        tenants[h] = Tenant(name=str(t["name"]), max_concurrent=int(t.get("max_concurrent", 2)),
                            per_minute=int(t.get("per_minute", 120)),
                            models=frozenset(models) if models is not None else None)
    admins = {str(a["sha256"]).lower() for a in cfg.get("admins") or []}
    keys = ("upstream", "max_concurrent", "queue_timeout_s", "upstream_timeout_s", "max_body_bytes", "usage_dir",
            "public_metrics", "max_num_ctx", "max_num_predict", "keep_alive")
    extra = {k: cfg[k] for k in keys if k in cfg}
    if extra.get("usage_dir"):
        extra["usage_dir"] = str(Path(extra["usage_dir"]).expanduser())
    return GatewayConfig(tenants=tenants, admins=admins, **extra)


class UsageLedger:
    """Usage counters plus an append-only monthly JSON-lines file. No prompt or reply content, ever."""

    def __init__(self, directory: str | None) -> None:
        self.dir = Path(directory) if directory else None
        if self.dir is not None:
            self.dir.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self.totals: dict[tuple[str, str], dict[str, float]] = {}

    def record(self, tenant: str, model: str, path: str, status: int, prompt_tokens: int, completion_tokens: int,
               latency_ms: float) -> None:
        now = datetime.now(UTC)
        with self._lock:
            t = self.totals.setdefault((tenant, model), {"requests": 0, "errors": 0, "prompt_tokens": 0,
                                                          "completion_tokens": 0, "busy_ms": 0.0})
            t["requests"] += 1
            t["errors"] += 0 if status < 400 else 1
            t["prompt_tokens"] += prompt_tokens
            t["completion_tokens"] += completion_tokens
            t["busy_ms"] += latency_ms
            if self.dir is not None:
                line = json.dumps({"ts": now.isoformat(timespec="seconds"), "tenant": tenant, "model": model,
                                   "path": path, "status": status, "prompt_tokens": prompt_tokens,
                                   "completion_tokens": completion_tokens, "latency_ms": round(latency_ms, 1)})
                with open(self.dir / f"usage-{now:%Y-%m}.jsonl", "a", encoding="utf-8") as f:
                    f.write(line + "\n")

    def summary(self) -> dict[str, dict[str, dict[str, float]]]:
        with self._lock:
            out: dict[str, dict[str, dict[str, float]]] = {}
            for (tenant, model), t in sorted(self.totals.items()):
                out.setdefault(tenant, {})[model] = {**t, "busy_ms": round(t["busy_ms"], 1)}
            return out


def _usage_of(path: str, data: Any) -> tuple[int, int]:
    if not isinstance(data, dict):
        return 0, 0
    if isinstance(data.get("usage"), dict):                      # OpenAI format
        u = data["usage"]
        return int(u.get("prompt_tokens") or 0), int(u.get("completion_tokens") or 0)
    return int(data.get("prompt_eval_count") or 0), int(data.get("eval_count") or 0)     # Ollama format


def _err(status: int, message: str, headers: dict[str, str] | None = None) -> JSONResponse:
    return JSONResponse({"error": message}, status_code=status, headers=headers)


def create_gateway(cfg: GatewayConfig, *, transport: httpx.AsyncBaseTransport | None = None) -> FastAPI:
    state: dict[str, Any] = {"client": None, "global": None, "tenant": {}, "in_flight": {}, "waiting": 0}

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        yield
        if state["client"] is not None:
            await state["client"].aclose()

    app = FastAPI(title="Sentinel model gateway", docs_url=None, redoc_url=None, openapi_url=None,
                  lifespan=lifespan)
    metrics = Metrics(prefix="sentinel_gateway")
    ledger = UsageLedger(cfg.usage_dir)
    limiters = {h: RateLimiter(t.per_minute) for h, t in cfg.tenants.items()}

    def _sems() -> tuple[asyncio.Semaphore, dict[str, asyncio.Semaphore]]:
        # created lazily inside the running loop
        if state["global"] is None:
            state["global"] = asyncio.Semaphore(cfg.max_concurrent)
            state["tenant"] = {t.name: asyncio.Semaphore(t.max_concurrent) for t in cfg.tenants.values()}
        return state["global"], state["tenant"]

    def _client() -> httpx.AsyncClient:
        if state["client"] is None:
            state["client"] = httpx.AsyncClient(base_url=cfg.upstream, transport=transport, trust_env=False,
                                                timeout=httpx.Timeout(cfg.upstream_timeout_s, connect=5.0))
        return state["client"]

    metrics.gauge("in_flight", lambda: {(("tenant", k),): float(v) for k, v in state["in_flight"].items()},
                  "Requests being processed upstream, per tenant")
    metrics.gauge("waiting", lambda: float(state["waiting"]), "Requests waiting for a slot")

    def _bearer(request: Request) -> str | None:
        auth = request.headers.get("authorization", "")
        return token_hash(auth[7:].strip()) if auth.lower().startswith("bearer ") and len(auth) > 7 else None

    def _tenant(request: Request) -> tuple[str, Tenant] | None:
        h = _bearer(request)
        return (h, cfg.tenants[h]) if h in cfg.tenants else None

    def _is_admin(request: Request) -> bool:
        return _bearer(request) in cfg.admins

    @app.get("/healthz")
    async def healthz() -> JSONResponse:
        try:
            r = await _client().get("/api/version", timeout=3.0)
            up = r.status_code == 200
        except httpx.HTTPError:
            up = False
        return JSONResponse({"status": "ok" if up else "degraded", "upstream": "up" if up else "down"},
                            status_code=200 if up else 503)

    @app.get("/metrics")
    async def metrics_endpoint(request: Request) -> PlainTextResponse:
        if not cfg.public_metrics and not _is_admin(request):
            return PlainTextResponse("unauthorised\n", status_code=401)
        return PlainTextResponse(metrics.render(), media_type="text/plain; version=0.0.4")

    @app.get("/usage")
    async def usage(request: Request) -> JSONResponse:
        if not _is_admin(request):
            return _err(401, "admin token required")
        return JSONResponse(ledger.summary())

    @app.get("/api/tags")
    async def tags(request: Request) -> JSONResponse:
        who = _tenant(request)
        if who is None:
            return _err(401, "invalid or missing token")
        try:
            r = await _client().get("/api/tags")
            models = r.json().get("models", []) if r.status_code == 200 else []
        except (httpx.HTTPError, ValueError):
            return _err(502, "model host unreachable")
        return JSONResponse({"models": [m for m in models if who[1].allows(str(m.get("name", "")))]})

    @app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD"])
    async def forward(path: str, request: Request) -> JSONResponse:
        path = "/" + path
        who = _tenant(request)
        if who is None:
            return _err(401, "invalid or missing token")
        h, tenant = who
        if request.method != "POST" or path not in INFERENCE_PATHS:
            metrics.inc("rejected_total", tenant=tenant.name, reason="endpoint")
            return _err(403, f"{request.method} {path} is not available through the gateway")
        raw = await request.body()
        if len(raw) > cfg.max_body_bytes:
            metrics.inc("rejected_total", tenant=tenant.name, reason="too_large")
            return _err(413, "request too large")
        try:
            body = json.loads(raw)
        except json.JSONDecodeError:
            return _err(400, "body must be JSON")
        if not isinstance(body, dict) or not isinstance(body.get("model"), str) or not body["model"]:
            return _err(400, "'model' is required")
        model = body["model"]
        if body.get("stream") is True:
            return _err(400, "streaming is not supported by the gateway; send stream=false")
        if not tenant.allows(model):
            metrics.inc("rejected_total", tenant=tenant.name, reason="model")
            return _err(403, f"model {model!r} is not enabled for {tenant.name}")
        if not limiters[h].allow(tenant.name):
            metrics.inc("rejected_total", tenant=tenant.name, reason="rate")
            return _err(429, "rate limit exceeded", headers={"Retry-After": "5"})
        if path in CHAT_PATHS and "stream" not in body:
            body["stream"] = False                 # Ollama streams by default; Sentinel never wants it
        body = clamp_body(body, cfg)
        try:                                       # the client says how long it will wait; never work longer
            client_wait = float(request.headers.get("x-request-timeout") or cfg.upstream_timeout_s)
        except ValueError:
            client_wait = cfg.upstream_timeout_s
        upstream_wait = max(1.0, min(cfg.upstream_timeout_s, client_wait))
        gsem, tsems = _sems()
        tsem = tsems[tenant.name]
        t_wait = time.perf_counter()
        state["waiting"] += 1
        try:
            await asyncio.wait_for(tsem.acquire(), cfg.queue_timeout_s)
            try:
                remaining = max(0.01, cfg.queue_timeout_s - (time.perf_counter() - t_wait))
                await asyncio.wait_for(gsem.acquire(), remaining)
            except BaseException:
                tsem.release()
                raise
        except TimeoutError:
            metrics.inc("rejected_total", tenant=tenant.name, reason="busy")
            return _err(503, "model host busy, try again", headers={"Retry-After": "2"})
        finally:
            state["waiting"] -= 1
        metrics.observe("queue_wait_seconds", time.perf_counter() - t_wait, "Time waiting for a slot",
                        tenant=tenant.name)
        state["in_flight"][tenant.name] = state["in_flight"].get(tenant.name, 0) + 1
        t0 = time.perf_counter()
        status, data = 502, {"error": "model host unreachable"}
        try:
            call = asyncio.ensure_future(_client().post(path, json=body, timeout=httpx.Timeout(upstream_wait,
                                                                                                connect=5.0)))
            try:
                while not call.done():             # stop the model's work as soon as the caller has gone
                    await asyncio.wait({call}, timeout=0.5)
                    if not call.done() and await request.is_disconnected():
                        call.cancel()
                        metrics.inc("rejected_total", tenant=tenant.name, reason="client_gone")
                        break
                r = await call
                status = r.status_code
                try:
                    data = r.json()
                except ValueError:
                    status, data = 502, {"error": "model host returned non-JSON"}
            except asyncio.CancelledError:
                status, data = 499, {"error": "client went away"}
            except httpx.TimeoutException:
                status, data = 504, {"error": "model host timed out"}
            except httpx.HTTPError:
                status, data = 502, {"error": "model host unreachable"}
        finally:
            state["in_flight"][tenant.name] -= 1
            gsem.release()
            tsem.release()
        ms = (time.perf_counter() - t0) * 1000
        p_tok, c_tok = _usage_of(path, data) if status < 400 else (0, 0)
        await asyncio.to_thread(ledger.record, tenant.name, model, path, status, p_tok, c_tok, ms)
        metrics.inc("requests_total", tenant=tenant.name, model=model, status=str(status))
        metrics.inc("tokens_total", float(p_tok), tenant=tenant.name, model=model, kind="prompt")
        metrics.inc("tokens_total", float(c_tok), tenant=tenant.name, model=model, kind="completion")
        metrics.observe("upstream_seconds", ms / 1000, "Model host time per request", tenant=tenant.name,
                        model=model)
        log.info("gateway request", extra={"tenant": tenant.name, "model": model, "path": path,
                                           "status": status, "prompt_tokens": p_tok, "completion_tokens": c_tok,
                                           "latency_ms": round(ms, 1)})
        return JSONResponse(data, status_code=status)

    app.state.metrics = metrics
    app.state.ledger = ledger
    app.state.config = cfg
    return app
