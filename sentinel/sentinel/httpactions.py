# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""Write actions defined in configuration: an HTTP call to a customer's system, with a parameter schema, an
optional undo, and honest flags. They live in the connectors configuration next to sources and MCP servers:

    actions:
      shopify_hold_order:
        description: Put a Shopify order on hold
        params: {order_id: str, reason?: str}
        request:
          method: POST
          url: "https://{{env.SENTINEL_SECRET_SHOPIFY_SHOP}}.myshopify.com/admin/api/2024-07/fulfillment_orders/{{params.order_id}}/hold.json"
          headers: {X-Shopify-Access-Token: "{{env.SENTINEL_SECRET_SHOPIFY_TOKEN}}"}
          body: {fulfillment_hold: {reason: other, reason_notes: "{{params.reason|default:Sentinel}}"}}
        compensate:                       # makes the action reversible
          method: POST
          url: "https://.../fulfillment_orders/{{params.order_id}}/release_hold.json"
          headers: {X-Shopify-Access-Token: "{{env.SENTINEL_SECRET_SHOPIFY_TOKEN}}"}
        ok_status: [200, 201]             # default: any 2xx
        ok_when: {body.fulfillment_order.status: on_hold}   # optional check of the reply
        safe: false                       # true only for idempotent calls with no business effect
        timeout_s: 20

Templates see ``params``, ``incident`` (id, pattern, facts), ``payload`` (the first event) and, in the URL and
headers only, ``env`` (allowlisted secrets). Every call carries the step's idempotency key (header
``Idempotency-Key`` by default) and goes through the outbound-address checks. 429 and 5xx replies are retried;
other failures are not. An action named here may not replace one the overlay implements in code.
"""
from __future__ import annotations

import json
import re
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator

from .actions import ActionRegistry
from .expr import check_condition, check_template, dig, matches, render
from .models import ActionResult, ActionSpec

_NAME = re.compile(r"^[a-z][a-z0-9_.]{1,63}$")
_ENV = re.compile(r"\{\{\s*env\.([A-Za-z_][A-Za-z0-9_]*)")
_TYPES = {"str", "int", "float", "bool", "list", "dict", "any"}


class HttpActionError(ValueError):
    pass


class HttpRequest(BaseModel):
    method: Literal["GET", "POST", "PUT", "PATCH", "DELETE"] = "POST"
    url: str
    headers: dict[str, str] = Field(default_factory=dict)
    body: Any = None
    timeout_s: float = Field(default=20.0, gt=0, le=120)

    @field_validator("url")
    @classmethod
    def _url(cls, v: str) -> str:
        if not v.startswith(("https://", "http://")) and not v.startswith("{{"):
            raise ValueError("url must be http(s)")
        return v


class HttpAction(BaseModel):
    name: str
    description: str = ""
    params: dict[str, str] = Field(default_factory=dict)
    request: HttpRequest
    compensate: HttpRequest | None = None
    ok_status: list[int] = Field(default_factory=list)       # empty: any 2xx
    ok_when: dict[str, Any] | None = None                     # condition on {status, body}
    safe: bool = False
    max_attempts: int = Field(default=3, ge=1, le=10)
    timeout_s: float | None = None                            # whole step, as for code actions
    idempotency_header: str | None = "Idempotency-Key"

    def model_post_init(self, _ctx: Any) -> None:
        if not _NAME.match(self.name):
            raise ValueError(f"action {self.name!r}: lowercase letters, digits, _ and . only")
        bad = [t for t in self.params.values() if t not in _TYPES and t not in
               ("string", "integer", "number", "boolean", "array", "object")]
        if bad:
            raise ValueError(f"action {self.name}: unknown param types {bad}")

    def spec(self) -> ActionSpec:
        return ActionSpec(name=self.name, description=self.description or f"HTTP {self.request.method}",
                          reversible=self.compensate is not None, safe=self.safe, max_attempts=self.max_attempts,
                          timeout_s=self.timeout_s, params_schema=dict(self.params))


def parse_actions(data: dict[str, Any] | None) -> dict[str, HttpAction]:
    out = {}
    for name, spec in (data or {}).items():
        if not isinstance(spec, dict):
            raise HttpActionError(f"action {name}: must be a mapping")
        out[name] = HttpAction.model_validate({**spec, "name": name})
    return out


def check_actions(actions: dict[str, HttpAction], code_actions: set[str]) -> list[tuple[str, str]]:
    """(severity, message) problems beyond the schema."""
    import os

    from .envsecrets import allowed
    probs: list[tuple[str, str]] = []
    for a in actions.values():
        if a.name in code_actions:
            probs.append(("error", f"action {a.name}: the overlay implements an action of that name in code"))
        for which, req in (("request", a.request), ("compensate", a.compensate)):
            if req is None:
                continue
            where = f"action {a.name} {which}"
            for m in check_template(req.url) + check_template(req.headers) + check_template(req.body):
                probs.append(("error", f"{where}: {m}"))
            if "env." in json.dumps(req.body, default=str):
                probs.append(("error", f"{where}: the body may not read environment variables; put secrets in "
                                       "headers or the URL"))
            for text in [req.url, *req.headers.values()]:
                for env in _ENV.findall(text):
                    if not allowed(env):
                        probs.append(("error", f"{where}: {env} cannot be used by configuration; name the variable "
                                               "SENTINEL_SECRET_... or list it in SENTINEL_CONFIG_SECRETS"))
                    elif not os.environ.get(env):
                        probs.append(("warning", f"{where}: {env} is not set in this process"))
            used = set(re.findall(r"\{\{\s*params\.([A-Za-z_][A-Za-z0-9_]*)", json.dumps(req.model_dump())))
            known = {k.rstrip("?") for k in a.params}
            if a.params and used - known:
                probs.append(("error", f"{where}: uses params {sorted(used - known)} it does not declare"))
        probs += [("error", f"action {a.name} ok_when: {m}") for m in check_condition(a.ok_when)]
        if not a.params:
            probs.append(("warning", f"action {a.name}: declares no params, so nothing it is given is checked"))
        if a.safe and a.request.method != "GET":
            probs.append(("warning", f"action {a.name}: marked safe but sends {a.request.method}; safe actions may "
                                     "run unattended - be sure it changes nothing that matters"))
        if a.request.method == "POST" and not a.idempotency_header:
            probs.append(("warning", f"action {a.name}: no idempotency header; a retried call may act twice"))
    return probs


def _scope(ctx: Any, params: dict[str, Any], with_env: bool) -> dict[str, Any]:
    inc = getattr(ctx, "incident", None)
    ev = getattr(ctx, "event", None)
    out: dict[str, Any] = {"params": params,
                           "incident": {"id": inc.id, "pattern": inc.pattern_id, "facts": inc.facts} if inc else {},
                           "payload": ev.payload if ev is not None else {}}
    if with_env:
        from .connauth import Tokens
        from .envsecrets import scope as secret_scope
        out["env"] = secret_scope()
        out["auth"] = Tokens()
    return out


def encode_body(body: Any, headers: dict[str, str]) -> bytes | None:
    """JSON for structures; a string is sent as it is (XML for Tally, form text), with its own Content-Type."""
    if body is None:
        return None
    if isinstance(body, str):
        if not any(k.lower() == "content-type" for k in headers):
            headers["Content-Type"] = "text/xml; charset=utf-8" if body.lstrip().startswith("<") else "text/plain"
        return body.encode()
    if not any(k.lower() == "content-type" for k in headers):
        headers["Content-Type"] = "application/json"
    return json.dumps(body).encode()


def decode_reply(raw: bytes) -> Any:
    """JSON, or XML as nested dicts (Tally, SOAP), or the text."""
    if not raw:
        return None
    try:
        return json.loads(raw)
    except ValueError:
        pass
    text = raw.decode("utf-8", "replace").strip()
    if text.startswith("<"):
        try:
            return xml_to_dict(text)
        except Exception:  # noqa: BLE001,S110 - fall back to text
            pass
    return text[:4000]


def xml_to_dict(text: str) -> Any:
    """A small XML reader: elements become keys, repeated elements lists, attributes '_NAME', text '_text'.
    DOCTYPE and entity declarations are refused (no entity expansion)."""
    import xml.etree.ElementTree as ET  # noqa: S405 - DOCTYPE/ENTITY refused below
    if "<!DOCTYPE" in text.upper() or "<!ENTITY" in text.upper():
        raise ValueError("XML with DOCTYPE or ENTITY declarations is not accepted")
    root = ET.fromstring(text)  # noqa: S314

    def conv(el: Any) -> Any:
        kids = list(el)
        if not kids and not el.attrib:
            return (el.text or "").strip()
        out: dict[str, Any] = {f"_{k}": v for k, v in el.attrib.items()}
        for k in kids:
            tag = k.tag.split("}")[-1]
            v = conv(k)
            if tag in out:
                out[tag] = out[tag] if isinstance(out[tag], list) else [out[tag]]
                out[tag].append(v)
            else:
                out[tag] = v
        if (el.text or "").strip():
            out["_text"] = el.text.strip()
        return out
    return {root.tag.split("}")[-1]: conv(root)}


def call(action: HttpAction, req: HttpRequest, ctx: Any, params: dict[str, Any], *,
         opener: Any = None, undo: bool = False) -> ActionResult:
    from . import egress
    plain = _scope(ctx, params, with_env=False)
    secret = _scope(ctx, params, with_env=True)
    body = render(req.body, plain) if req.body is not None else None
    key = getattr(ctx, "idempotency_key", None)
    from .connauth import AuthError
    try:
        status, raw = send(req, secret, body, opener=opener,
                           extra={action.idempotency_header: f"{key}:undo" if undo else key}
                           if action.idempotency_header and key else None)
    except AuthError as e:
        return ActionResult(ok=False, retryable=True, detail=f"{action.name}: {e}")
    except egress.EgressError as e:
        return ActionResult(ok=False, retryable=False, detail=f"{action.name}: {e}")
    except (urllib.error.URLError, OSError, TimeoutError) as e:
        return ActionResult(ok=False, retryable=True, detail=f"{action.name}: {getattr(e, 'reason', e)}")
    reply = decode_reply(raw)
    ok = (status in action.ok_status) if action.ok_status else 200 <= status < 300
    if ok and action.ok_when and not undo:
        ok = matches(action.ok_when, {"status": status, "body": reply})
        if not ok:
            return ActionResult(ok=False, retryable=False, data={"status": status, "body": _short(reply)},
                                detail=f"{action.name}: HTTP {status} but the reply does not show success")
    if ok:
        return ActionResult(ok=True, detail=f"{action.name}: HTTP {status}", data={"status": status,
                                                                                 "body": _short(reply)})
    retry = status == 429 or status >= 500
    hint = dig({"b": reply}, "b.errors") or dig({"b": reply}, "b.error") or dig({"b": reply}, "b.message")
    return ActionResult(ok=False, retryable=retry, data={"status": status, "body": _short(reply)},
                        detail=f"{action.name}: HTTP {status}" + (f": {str(hint)[:300]}" if hint else ""))


def send(req: HttpRequest, secret_scope: dict[str, Any], body: Any, *, opener: Any = None,
         extra: dict[str, str] | None = None) -> tuple[int, bytes]:
    """Render url and headers (with env and auth), send, and after a 401 fetch the login token again once."""
    from . import connauth, egress
    url_scope = {**secret_scope, "params": {k: urllib.parse.quote(str(v), safe="") for k, v in
                                            (secret_scope.get("params") or {}).items()}}
    names = connauth.uses([req.url, req.headers])
    for attempt in (1, 2):
        url = str(render(req.url, url_scope))
        headers = {k: str(render(v, secret_scope)) for k, v in req.headers.items()}
        headers.update(extra or {})
        data = encode_body(body, headers)
        r = urllib.request.Request(url, data=data, method=req.method,  # noqa: S310 - checked by egress
                                   headers={"Accept": "application/json", "User-Agent": "sentinel", **headers})
        try:
            status, _, raw = egress.open_url(r, req.timeout_s, base_opener=opener)
            return status, raw
        except urllib.error.HTTPError as e:
            if e.code == 401 and names and attempt == 1:
                for n in names:
                    connauth.invalidate(n)
                continue
            return e.code, (e.read() or b"")[:4000]
    raise AssertionError("unreachable")  # pragma: no cover


def _short(v: Any) -> Any:
    s = json.dumps(v, default=str)
    return v if len(s) <= 4000 else s[:4000] + "..."


def registry_from(actions: dict[str, HttpAction], *, opener: Any = None) -> ActionRegistry:
    reg = ActionRegistry()
    for a in actions.values():
        def handler(ctx: Any, params: dict[str, Any], _a: HttpAction = a) -> ActionResult:
            return call(_a, _a.request, ctx, params, opener=opener)
        undo = None
        if a.compensate is not None:
            def undo(ctx: Any, params: dict[str, Any], _a: HttpAction = a) -> ActionResult:
                return call(_a, _a.compensate, ctx, params, opener=opener, undo=True)  # type: ignore[arg-type]
        reg.register(a.spec(), handler, undo)
    return reg



# ---- read-only lookups from configuration -------------------------------------------------------------------
class HttpLookup(BaseModel):
    """A read-only tool the model and playbooks may call: an HTTP GET (or a read-only query sent as POST, e.g.
    Tally's XML export or a GraphQL query, declared with ``reads_only: true``).

        lookups:
          shiprocket.track:
            description: Where a shipment is, by AWB
            params: {awb: str}
            request: {method: GET, url: "https://apiv2.shiprocket.in/v1/external/courier/track/awb/{{params.awb}}",
                      headers: {Authorization: "Bearer {{auth.shiprocket}}"}}
            result: body.tracking_data          # only this part goes back (keeps the model's view small)
    """
    name: str
    description: str = ""
    params: dict[str, str] = Field(default_factory=dict)
    request: HttpRequest
    result: str | None = None
    reads_only: bool = False
    max_chars: int = Field(default=6000, ge=200, le=50000)

    def model_post_init(self, _ctx: Any) -> None:
        if not _NAME.match(self.name):
            raise ValueError(f"lookup {self.name!r}: lowercase letters, digits, _ and . only")
        if self.request.method != "GET" and not self.reads_only:
            raise ValueError(f"lookup {self.name}: {self.request.method} needs reads_only: true (a lookup may "
                             "never change anything; use an action for that)")
        if self.request.method in ("PUT", "PATCH", "DELETE"):
            raise ValueError(f"lookup {self.name}: {self.request.method} is never read-only; use an action")


def parse_lookups(data: dict[str, Any] | None) -> dict[str, HttpLookup]:
    out = {}
    for name, spec in (data or {}).items():
        if not isinstance(spec, dict):
            raise HttpActionError(f"lookup {name}: must be a mapping")
        out[name] = HttpLookup.model_validate({**spec, "name": name})
    return out


def check_lookups(lookups: dict[str, HttpLookup], code_tools: set[str]) -> list[tuple[str, str]]:
    import os

    from .envsecrets import allowed
    probs: list[tuple[str, str]] = []
    for lk in lookups.values():
        where = f"lookup {lk.name}"
        if lk.name in code_tools:
            probs.append(("error", f"{where}: the overlay has a tool of that name"))
        req = lk.request
        for m in check_template(req.url) + check_template(req.headers) + check_template(req.body):
            probs.append(("error", f"{where}: {m}"))
        if "env." in json.dumps(req.body, default=str) or "auth." in json.dumps(req.body, default=str):
            probs.append(("error", f"{where}: the body may not read secrets; put them in headers or the URL"))
        for text in [req.url, *req.headers.values()]:
            for env in _ENV.findall(text):
                if not allowed(env):
                    probs.append(("error", f"{where}: {env} cannot be used by configuration"))
                elif not os.environ.get(env):
                    probs.append(("warning", f"{where}: {env} is not set in this process"))
        used = set(re.findall(r"\{\{\s*params\.([A-Za-z_][A-Za-z0-9_]*)", json.dumps(req.model_dump())))
        known = {k.rstrip("?") for k in lk.params}
        if used - known:
            probs.append(("error", f"{where}: uses params {sorted(used - known)} it does not declare"))
    return probs


def lookup_tools(lookups: dict[str, HttpLookup], *, opener: Any = None) -> list[Any]:
    from .tools import Tool
    out = []
    for lk in lookups.values():
        def full(args: dict[str, Any], services: dict[str, Any], _l: HttpLookup = lk) -> Any:
            from . import egress
            from .connauth import AuthError
            plain = {"params": args}
            secret = {**_scope(None, args, with_env=True), "params": args}
            body = render(_l.request.body, plain) if _l.request.body is not None else None
            try:
                status, raw = send(_l.request, secret, body, opener=opener)
            except (AuthError, egress.EgressError, urllib.error.URLError, OSError, TimeoutError) as e:
                return {"error": f"{_l.name}: {getattr(e, 'reason', e)}"}
            reply = decode_reply(raw)
            if not 200 <= status < 300:
                return {"error": f"{_l.name}: HTTP {status}", "body": _short(reply)}
            return dig({"body": reply}, _l.result) if _l.result else reply

        def fn(args: dict[str, Any], services: dict[str, Any], _l: HttpLookup = lk, _full: Any = full) -> Any:
            data = _full(args, services)
            text = json.dumps(data, default=str)
            return data if len(text) <= _l.max_chars else {"truncated": True, "data": text[:_l.max_chars]}
        out.append(Tool(name=lk.name, description=lk.description or f"HTTP {lk.request.method}",
                        params=dict(lk.params), fn=fn, full=full))
    return out
