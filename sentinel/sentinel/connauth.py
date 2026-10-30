# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""Login tokens for connectors whose APIs hand out a short-lived token (Shiprocket, Zoho, SAP Business One).

In the connectors configuration::

    auth:
      shiprocket:
        url: https://apiv2.shiprocket.in/v1/external/auth/login
        body: {email: "{{env.SENTINEL_SECRET_SHIPROCKET_EMAIL}}",
               password: "{{env.SENTINEL_SECRET_SHIPROCKET_PASSWORD}}"}
        token: body.token                 # where the token is in the reply
        ttl_s: 777600                     # 9 days (Shiprocket tokens last 10)
      zoho:
        url: "https://accounts.zoho.in/oauth/v2/token?refresh_token={{env.SENTINEL_SECRET_ZOHO_REFRESH_TOKEN}}&client_id=...&grant_type=refresh_token"
        token: body.access_token
        ttl_from: body.expires_in         # seconds, from the reply

and then ``{{auth.shiprocket}}`` in the url or headers of a source, lookup or action. A token is fetched when
first used, kept in memory per process (and per tenant in hosted mode) until a minute before it expires, and
fetched again after a 401. Login calls go through the outbound-address checks; their bodies may use
``{{env.SENTINEL_SECRET_...}}`` (a login necessarily sends a secret), unlike other request bodies.
"""
from __future__ import annotations

import json
import threading
import time
import urllib.error
import urllib.request  # noqa: F401 - Request is used below
from typing import Any, Literal

from pydantic import BaseModel, Field

_SPECS: dict[str | None, dict[str, AuthSpec]] = {}
_CACHE: dict[tuple[str | None, str], tuple[str, float]] = {}
_LOCK = threading.Lock()


class AuthError(RuntimeError):
    pass


class AuthSpec(BaseModel):
    name: str
    url: str
    method: Literal["GET", "POST"] = "POST"
    headers: dict[str, str] = Field(default_factory=dict)
    body: Any = None
    form: bool = False                     # send the body as form fields instead of JSON
    token: str = "body.token"  # noqa: S105 - a path in the reply, not a secret in {body, headers}; "headers.Set-Cookie" style also works
    token_regex: str | None = None         # e.g. "B1SESSION=([^;]+)" to cut a cookie
    ttl_s: int = Field(default=3000, ge=60)
    ttl_from: str | None = None            # path to "expires in N seconds" in the reply
    timeout_s: float = Field(default=20.0, gt=0, le=60)


def parse(data: dict[str, Any] | None) -> dict[str, AuthSpec]:
    return {n: AuthSpec.model_validate({**(v or {}), "name": n}) for n, v in (data or {}).items()}


def _tenant() -> str | None:
    from .envsecrets import TENANT
    return TENANT.get()


def configure(specs: dict[str, AuthSpec]) -> None:
    """Make these login specs the ones ``{{auth.X}}`` uses (for the current tenant)."""
    t = _tenant()
    with _LOCK:
        _SPECS[t] = dict(specs)
        for k in [k for k in _CACHE if k[0] == t and k[1] not in specs]:
            del _CACHE[k]


def invalidate(name: str | None = None) -> None:
    t = _tenant()
    with _LOCK:
        for k in [k for k in _CACHE if k[0] == t and (name is None or k[1] == name)]:
            del _CACHE[k]


def _fetch(spec: AuthSpec, opener: Any = None) -> tuple[str, float]:
    import re
    import urllib.parse

    from . import egress
    from .envsecrets import scope as secret_scope
    from .expr import dig, render
    scope = {"env": secret_scope()}
    url = str(render(spec.url, scope))
    headers = {k: str(render(v, scope)) for k, v in spec.headers.items()}
    body = render(spec.body, scope) if spec.body is not None else None
    if body is None:
        data = None
    elif spec.form:
        data = urllib.parse.urlencode(body).encode()
        headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
    else:
        data = json.dumps(body).encode()
        headers.setdefault("Content-Type", "application/json")
    req = urllib.request.Request(url, data=data, method=spec.method,  # noqa: S310 - checked by egress
                                 headers={"Accept": "application/json", "User-Agent": "sentinel", **headers})
    try:
        status, resp_headers, raw = egress.open_url(req, spec.timeout_s, base_opener=opener)
    except urllib.error.HTTPError as e:
        raise AuthError(f"auth {spec.name}: login refused (HTTP {e.code})") from None
    except (egress.EgressError, urllib.error.URLError, OSError, TimeoutError) as e:
        raise AuthError(f"auth {spec.name}: {getattr(e, 'reason', e)}") from None
    try:
        reply: Any = json.loads(raw) if raw else None
    except ValueError:
        reply = raw.decode("utf-8", "replace")
    hdrs = {k: v for k, v in (resp_headers.items() if resp_headers is not None else [])}
    tok = dig({"body": reply, "headers": hdrs}, spec.token)
    if tok is not None and spec.token_regex:
        m = re.search(spec.token_regex, str(tok))
        tok = m.group(1) if m else None
    if not tok:
        raise AuthError(f"auth {spec.name}: no token at {spec.token} in the login reply (HTTP {status})")
    ttl = spec.ttl_s
    if spec.ttl_from:
        try:
            ttl = int(float(dig({"body": reply, "headers": hdrs}, spec.ttl_from)))
        except (TypeError, ValueError):
            pass
    return str(tok), time.time() + max(60, ttl) - 60


def token(name: str, *, opener: Any = None) -> str:
    t = _tenant()
    with _LOCK:
        spec = (_SPECS.get(t) or {}).get(name)
        hit = _CACHE.get((t, name))
    if spec is None:
        raise AuthError(f"auth {name!r} is not configured (add it under auth: in the connectors configuration)")
    if hit and hit[1] > time.time():
        return hit[0]
    value = _fetch(spec, opener)
    with _LOCK:
        _CACHE[(t, name)] = value
    return value[0]


class Tokens(dict):
    """``{{auth.X}}``: fetched only when a template reads it."""

    def __init__(self, opener: Any = None) -> None:
        super().__init__()
        self._opener = opener

    def __contains__(self, key: object) -> bool:
        return isinstance(key, str) and key in (_SPECS.get(_tenant()) or {})

    def __getitem__(self, key: str) -> str:
        return token(key, opener=self._opener)


def uses(text: Any) -> list[str]:
    import re
    return re.findall(r"\{\{\s*auth\.([A-Za-z_][A-Za-z0-9_]*)", json.dumps(text, default=str))
