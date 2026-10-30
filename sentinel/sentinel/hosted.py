# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""Hosted mode: many customers (tenants) in one service, each fully separate.

Each tenant gets its own database schema and connection pool, its own engine and configuration (an overlay
or a packs file), its own tokens and single sign-on, its own licence and its own secrets: a tenant's
configuration can only read environment variables named ``SENTINEL_SECRET_<TENANT>_...`` (or
``SENTINEL_EDGE_<TENANT>_...``). Requests reach a tenant by host name or by the ``/t/<tenant>/`` prefix;
workers take turns between tenants by weight, so one busy tenant cannot starve the others.

    dsn_env: SENTINEL_PG               # one PostgreSQL; a schema per tenant (PgBouncer in front for many)
    pool_per_tenant: 3
    tenants:
      acme:
        schema: t_acme
        overlay: acme_sentinel:build_overlay        # or  packs: tenants/acme/packs.yaml
        tokens: tenants/acme/tokens.yaml
        hosts: [acme.sentinel.example.in]
        ingest_per_minute: 600
        weight: 2                                   # share of worker turns
        licence: tenants/acme/licence.txt           # optional, with licence_keys
"""
from __future__ import annotations

import importlib
import os
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field

from .envsecrets import TENANT

_NAME = __import__("re").compile(r"^[a-z][a-z0-9-]{1,30}$")


class TenantSpec(BaseModel):
    schema_name: str = Field(alias="schema")
    overlay: str | None = None
    packs: str | None = None
    tokens: str
    hosts: list[str] = Field(default_factory=list)
    ingest_per_minute: int = 600
    weight: int = Field(default=1, ge=1, le=20)
    licence: str | None = None
    licence_keys: str | None = None


class HostedSpec(BaseModel):
    dsn_env: str = "SENTINEL_PG"
    pool_per_tenant: int = Field(default=3, ge=1, le=20)
    tenants: dict[str, TenantSpec]


def load_spec(path: str | Path) -> tuple[HostedSpec, Path]:
    p = Path(path)
    spec = HostedSpec.model_validate(yaml.safe_load(p.read_text(encoding="utf-8")) or {})
    for name, t in spec.tenants.items():
        if not _NAME.match(name):
            raise ValueError(f"tenant {name!r}: lowercase letters, digits and - only")
        if bool(t.overlay) == bool(t.packs):
            raise ValueError(f"tenant {name}: give exactly one of overlay or packs")
    schemas = [t.schema_name for t in spec.tenants.values()]
    if len(set(schemas)) != len(schemas):
        raise ValueError("two tenants share a schema")
    return spec, p.parent


def load_tokens(path: str | Path) -> tuple[dict[str, Any], dict[str, str], Any]:
    """(token hash -> principal, edge secrets, SSO config) from a tokens file."""
    from .api import Principal
    cfg = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    tokens = {}
    for t in cfg.get("tokens") or []:
        kind = "service" if "service" in t else "person"
        tokens[t["sha256"]] = Principal(kind, t.get("service") or t["person"])
    secrets = {e: os.environ[v] for e, v in (cfg.get("edge_secrets_env") or {}).items() if v in os.environ}
    sso = None
    if cfg.get("sso"):
        from .sso import SSOConfig
        sso = SSOConfig.model_validate(cfg["sso"])
    return tokens, secrets, sso


@dataclass
class Tenant:
    name: str
    spec: TenantSpec
    engine: Any
    worker: Any = None
    app: Any = None
    turns: int = 0


@dataclass
class Hosted:
    tenants: dict[str, Tenant] = field(default_factory=dict)

    def by_host(self, host: str) -> Tenant | None:
        h = (host or "").split(":")[0].lower()
        for t in self.tenants.values():
            if h in (x.lower() for x in t.spec.hosts):
                return t
        return None


def build(path: str | Path, *, async_mode: bool = True, store_factory: Any = None) -> Hosted:
    spec, base = load_spec(path)
    dsn = os.environ.get(spec.dsn_env)
    if not dsn and store_factory is None:
        raise ValueError(f"set {spec.dsn_env} to the PostgreSQL DSN")
    from .engine import Engine
    from .licence import LicenceGuard, load_keys, load_token
    hosted = Hosted()
    for name, t in spec.tenants.items():
        token = TENANT.set(name)
        try:
            if store_factory is not None:
                store = store_factory(name, t.schema_name)
            else:
                from .pg_store import PostgresStore
                store = PostgresStore(dsn, schema=t.schema_name, pool_size=spec.pool_per_tenant)
            if t.packs:
                from .packs import build_overlay
                overlay = build_overlay(base / t.packs, name=name)
            else:
                mod, _, attr = (t.overlay or "").partition(":")
                obj = getattr(importlib.import_module(mod), attr or "build_overlay")
                overlay = obj() if callable(obj) else obj
            lic: Any = False
            if t.licence:
                lic = LicenceGuard(load_token(str(base / t.licence)),
                                   load_keys(str(base / t.licence_keys)) if t.licence_keys else [], site=name)
            eng = Engine(overlay, store=store, async_mode=async_mode, licence=lic)
            hosted.tenants[name] = Tenant(name, t, eng)
        finally:
            TENANT.reset(token)
    return hosted


def asgi_app(hosted: Hosted, base: Path | None = None) -> Any:
    """One ASGI app that hands each request to its tenant's app, by host name or /t/<tenant>/ prefix."""
    from .api import create_app
    for t in hosted.tenants.values():
        tokens, secrets, sso = load_tokens(t.spec.tokens if base is None else base / t.spec.tokens)
        # config_sync_s=0: the tenant's own sync thread would run without the tenant set (threads do not
        # inherit context), so configuration is synced below, per tenant, with its secrets scope
        t.app = create_app(t.engine, tokens, edge_secrets=secrets, sso=sso, config_sync_s=0,
                           ingest_per_minute=t.spec.ingest_per_minute, title=f"Sentinel ({t.name})")
    stop = threading.Event()

    def sync_loop() -> None:
        while not stop.wait(15.0):
            for t in hosted.tenants.values():
                token = TENANT.set(t.name)
                try:
                    t.engine.sync_config()
                except Exception:  # noqa: BLE001,S110 - logged by the engine; keep serving
                    pass
                finally:
                    TENANT.reset(token)

    async def app(scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope["type"] == "lifespan":
            msg = await receive()
            while msg["type"] != "lifespan.shutdown":
                if msg["type"] == "lifespan.startup":
                    threading.Thread(target=sync_loop, daemon=True, name="hosted-config-sync").start()
                    await send({"type": "lifespan.startup.complete"})
                msg = await receive()
            stop.set()
            await send({"type": "lifespan.shutdown.complete"})
            return
        tenant = None
        path = scope.get("path", "")
        if path.startswith("/t/"):
            name, _, rest = path[3:].partition("/")
            tenant = hosted.tenants.get(name)
            if tenant is not None:
                scope = {**scope, "path": "/" + rest, "root_path": scope.get("root_path", "") + f"/t/{name}"}
        if tenant is None:
            host = next((v.decode() for k, v in scope.get("headers", []) if k == b"host"), "")
            tenant = hosted.by_host(host)
        if tenant is None:
            if scope["type"] == "http":
                await send({"type": "http.response.start", "status": 404,
                            "headers": [(b"content-type", b"application/json")]})
                await send({"type": "http.response.body", "body": b'{"detail": "unknown tenant"}'})
            return
        token = TENANT.set(tenant.name)
        try:
            await tenant.app(scope, receive, send)
        finally:
            TENANT.reset(token)
    return app


def run_workers(hosted: Hosted, stop: threading.Event, *, threads: int = 4, batch: int = 10,
                idle_s: float = 0.5) -> None:
    """Worker threads that take turns between tenants by weight; each turn runs as that tenant."""
    from .worker import Worker
    order: list[Tenant] = []
    for t in hosted.tenants.values():
        t.worker = Worker(t.engine, batch=batch)
        order += [t] * t.spec.weight
    lock = threading.Lock()
    pos = {"i": 0}

    def next_tenant() -> Tenant:
        with lock:
            t = order[pos["i"] % len(order)]
            pos["i"] += 1
            return t

    def loop() -> None:
        quiet = 0
        while not stop.is_set():
            t = next_tenant()
            token = TENANT.set(t.name)
            try:
                stats = t.worker.run_once()
                t.turns += 1
                quiet = quiet + 1 if not any(stats.values()) else 0
            except Exception:  # noqa: BLE001 - one tenant's trouble must not stop the others
                quiet += 1
            finally:
                TENANT.reset(token)
            if quiet >= len(order):
                time.sleep(idle_s)
                quiet = 0
    ts = [threading.Thread(target=loop, daemon=True, name=f"hosted-worker-{i}") for i in range(threads)]
    for x in ts:
        x.start()
    for x in ts:
        x.join()
