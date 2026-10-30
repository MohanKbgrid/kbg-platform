# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""Which environment variables configuration may use.

Configuration (data sources, MCP servers, edges, models) refers to secrets by the name of an environment
variable. Because configuration can be published from the console, it may only name variables that were
put there for it - never the database password, the Claude key or anything else in the process:

* names starting ``SENTINEL_SECRET_`` or ``SENTINEL_EDGE_``,
* ``SENTINEL_GATEWAY_KEY`` (the office model gateway),
* names listed in ``SENTINEL_CONFIG_SECRETS`` (comma-separated), for variables you cannot rename.
"""
from __future__ import annotations

import contextvars
import os

PREFIXES = ("SENTINEL_SECRET_", "SENTINEL_EDGE_")
NAMES = {"SENTINEL_GATEWAY_KEY"}

# Hosted mode: the tenant whose configuration is being used. Its configuration may then only read variables
# carrying its own name (SENTINEL_SECRET_<TENANT>_..., SENTINEL_EDGE_<TENANT>_...), never another tenant's.
TENANT: contextvars.ContextVar[str | None] = contextvars.ContextVar("sentinel_tenant", default=None)


def tenant_prefixes(tenant: str) -> tuple[str, str]:
    t = tenant.upper().replace("-", "_")
    return (f"SENTINEL_SECRET_{t}_", f"SENTINEL_EDGE_{t}_")


class SecretNameError(ValueError):
    pass


def allowed(name: str) -> bool:
    tenant = TENANT.get()
    if tenant:
        return name.startswith(tenant_prefixes(tenant))
    extra = {n.strip() for n in (os.environ.get("SENTINEL_CONFIG_SECRETS") or "").split(",") if n.strip()}
    return name.startswith(PREFIXES) or name in NAMES or name in extra


def require_allowed(name: str, where: str) -> None:
    if not allowed(name):
        tenant = TENANT.get()
        if tenant:
            raise SecretNameError(f"{where}: {name} cannot be used by tenant {tenant}'s configuration; name the "
                                  f"variable {tenant_prefixes(tenant)[0]}...")
        raise SecretNameError(f"{where}: {name} cannot be used by configuration; name the variable "
                              f"SENTINEL_SECRET_... or list it in SENTINEL_CONFIG_SECRETS")


# Keys entered in the console (sentinel.secretstore), per tenant; they take precedence over the environment.
_STORED: dict[str | None, dict[str, str]] = {}


def use_stored(values: dict[str, str]) -> None:
    """Make these console-entered keys visible to configuration (for the current tenant)."""
    _STORED[TENANT.get()] = dict(values)


def lookup(name: str) -> str | None:
    """A key's value: entered in the console, else the environment (no allowlist check)."""
    v = (_STORED.get(TENANT.get()) or {}).get(name)
    return v if v else os.environ.get(name)


def source(name: str) -> str:
    if (_STORED.get(TENANT.get()) or {}).get(name):
        return "console"
    return "environment" if os.environ.get(name) else "missing"


def get(name: str, where: str) -> str | None:
    require_allowed(name, where)
    return lookup(name)


def scope() -> dict[str, str]:
    """The variables `{{env.X}}` may read in configuration."""
    out = {k: v for k, v in os.environ.items() if allowed(k)}
    out.update({k: v for k, v in (_STORED.get(TENANT.get()) or {}).items() if allowed(k) and v})
    return out
