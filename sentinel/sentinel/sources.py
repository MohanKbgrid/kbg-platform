# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""Data sources from configuration: turn webhooks, polled APIs and database tables into events, no code.

    sources:
      shopify_orders:                       # POST /v1/hooks/shopify_orders (signed) or /v1/sources/... (token)
        kind: webhook
        signature: {header: X-Shopify-Hmac-Sha256, secret_env: SENTINEL_SECRET_SHOPIFY_WEBHOOK, encoding: base64}
        emit:
          - type: order.unfulfilled
            when: {body.financial_status: paid, body.fulfillment_status: {exists: false}}
            key: "shopify:{{body.id}}:{{body.updated_at}}"
            payload:
              order_id: "{{body.name}}"
              channel: shopify
              location: "{{body.location_id|default:WH_CHN}}"
              hours_since_paid: "{{body.processed_at|hours_since}}"

      wms_stock:                            # fetched every 5 minutes by the workers
        kind: poll
        every_s: 300
        url: "https://wms.example.in/api/stock?changed_since={{cursor}}"
        headers: {Authorization: "Bearer {{env.SENTINEL_SECRET_WMS_TOKEN}}"}
        items: body.rows                    # where the list is in the response
        cursor: {field: item.updated_at, initial: "2026-01-01T00:00:00Z"}
        emit:
          - type: inventory.mismatch
            when: {item.delta: {ne: 0}}
            key: "wms:{{item.sku}}:{{item.updated_at}}"
            payload: {sku: "{{item.sku}}", location: "{{item.loc}}", abs_delta: "{{item.delta|abs}}"}

      erp_outbox:                           # new rows of a table (an outbox or a change log)
        kind: sql
        every_s: 60
        dsn_env: SENTINEL_SECRET_ERP_DSN
        query: "SELECT * FROM ops_outbox WHERE id > %(cursor)s ORDER BY id LIMIT 500"
        cursor: {field: item.id, initial: 0}
        emit: [{type: "{{item.event_type}}", key: "erp:{{item.id}}", payload: "{{item.body}}"}]

Templates see ``body`` (the webhook body or poll response), ``item`` (one entry of ``items`` / ``each``)
and ``now``. Secrets are read with ``{{env.NAME}}`` only in a poll's url and headers - never in payloads.
``each`` on an emit rule fans one payload out into one event per list entry.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import os
import urllib.error
import urllib.parse
import urllib.request
from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator

from .expr import ExprError, check_condition, check_template, dig, matches, render
from .models import Event


class SourceError(ValueError):
    pass


class Signature(BaseModel):
    """hmac: the header carries an HMAC of the body (Shopify). token: the header carries a shared
    token as it is (Shiprocket's x-api-key, a Delhivery or Zoho custom header)."""
    header: str
    secret_env: str
    mode: Literal["hmac", "token"] = "hmac"
    encoding: Literal["hex", "base64"] = "hex"
    algorithm: Literal["sha256", "sha1"] = "sha256"
    prefix: str = ""                       # e.g. "sha256=" (GitHub style)


class Emit(BaseModel):
    type: str                              # event type (may be a template)
    when: dict[str, Any] | None = None
    each: str | None = None                # path to a list: one event per entry, exposed as `item`
    key: str | None = None                 # idempotency key template; strongly recommended
    payload: dict[str, Any] | str = Field(default_factory=dict)
    tenant: str | None = None
    correlation: str | None = None         # correlation id template (an order, a batch, a job)


class Cursor(BaseModel):
    """Where reading resumes. With only `field`, use ">=" in the query (rows that share the last value are
    read again and recognised as duplicates by their keys). With `tie` (a unique field such as the row id)
    the position is (field, tie): query ``WHERE (updated_at, id) > (%(cursor)s, %(cursor_tie)s)`` and no row
    sharing a timestamp across a page boundary is skipped."""
    field: str                             # path in each item, e.g. item.updated_at
    initial: Any = None
    tie: str | None = None                 # path to a unique tie-breaker, e.g. item.id
    tie_initial: Any = None


class Present(BaseModel):
    """What an expect source reads to see what has happened: an API (url) or a read-only table query."""
    url: str | None = None
    method: Literal["GET", "POST"] = "GET"
    headers: dict[str, str] = Field(default_factory=dict)
    body: dict[str, Any] | None = None
    items: str | None = None
    dsn_env: str | None = None
    query: str | None = None
    timeout_s: float = 30.0


class Source(BaseModel):
    name: str
    kind: Literal["webhook", "poll", "sql", "expect"]
    emit: list[Emit]
    description: str = ""
    tenant: str = "default"
    enabled: bool = True
    signature: Signature | None = None     # webhook
    every_s: int = 300                     # poll / sql
    url: str | None = None                 # poll
    method: Literal["GET", "POST"] = "GET"
    headers: dict[str, str] = Field(default_factory=dict)
    body: dict[str, Any] | str | None = None   # poll POST body (a string is sent as it is: Tally XML)
    items: str | None = None               # poll / sql: where the list is (sql rows are the list)
    cursor: Cursor | None = None
    timeout_s: float = 30.0
    format: Literal["json", "xml"] = "json"   # poll: how to read the reply (xml: Tally, SOAP)
    dsn_env: str | None = None             # sql
    query: str | None = None
    params: dict[str, str] = Field(default_factory=dict)   # sql: named %(x)s values, may be {{env.X}} templates
    # expect: "did not happen by" - at a time each day, raise an event for every expected item that is absent
    at: str | None = None                  # "05:30", local time in `tz`
    tz: str = "Asia/Kolkata"
    days: list[Literal["mon", "tue", "wed", "thu", "fri", "sat", "sun"]] | None = None   # default: every day
    expected: list[dict[str, Any]] | None = None   # what should be there (none: "anything at all")
    present: Present | None = None         # how to see what is there
    match_on: str | None = None            # template giving an item's key, e.g. "{{item.route}}"

    @field_validator("every_s")
    @classmethod
    def _every(cls, v: int) -> int:
        if v < 10:
            raise ValueError("every_s must be at least 10 seconds")
        return v

    def model_post_init(self, _ctx: Any) -> None:
        if not self.emit:
            raise ValueError(f"source {self.name}: needs at least one emit rule")
        if self.kind == "poll" and not self.url:
            raise ValueError(f"source {self.name}: a poll source needs a url")
        if self.kind == "sql" and not (self.dsn_env and self.query):
            raise ValueError(f"source {self.name}: a sql source needs dsn_env and query")
        if self.url and not self.url.startswith(("http://", "https://", "{{env.", "{{ env.")):
            raise ValueError(f"source {self.name}: url must be http(s) (or start with an {{{{env.}}}} base URL)")
        if self.kind == "expect":
            if not self.at or not re.match(r"^([01]\d|2[0-3]):[0-5]\d$", self.at):
                raise ValueError(f"source {self.name}: an expect source needs at: \"HH:MM\"")
            p = self.present
            if p is None or not (p.url or (p.dsn_env and p.query)):
                raise ValueError(f"source {self.name}: an expect source needs present: {{url}} or {{dsn_env, query}}")
            if p.url and not p.url.startswith(("http://", "https://", "{{env.", "{{ env.")):
                raise ValueError(f"source {self.name}: present.url must be http(s)")
            if self.expected and not self.match_on:
                raise ValueError(f"source {self.name}: with expected items, say how to match them (match_on)")
            local_zone(self.tz)


def local_zone(tz: str) -> Any:
    """A time zone by name ("Asia/Kolkata") or fixed offset ("+05:30")."""
    from datetime import timedelta, timezone
    m = re.match(r"^([+-])(\d{2}):(\d{2})$", tz or "")
    if m:
        sign = 1 if m.group(1) == "+" else -1
        return timezone(sign * timedelta(hours=int(m.group(2)), minutes=int(m.group(3))))
    try:
        from zoneinfo import ZoneInfo
        return ZoneInfo(tz)
    except Exception:  # noqa: BLE001 - no tz database in a slim image: India is the common case
        if tz == "Asia/Kolkata":
            return timezone(timedelta(hours=5, minutes=30))
        raise ValueError(f"unknown time zone {tz!r} (use a name like Asia/Kolkata or an offset like +05:30)") from None


def expect_due(s: Source, now: datetime) -> tuple[bool, str, datetime]:
    """(due now?, the local date it is for, the deadline) for an expect source."""
    zone = local_zone(s.tz)
    local = now.astimezone(zone)
    hh, mm = (int(x) for x in (s.at or "00:00").split(":"))
    deadline = local.replace(hour=hh, minute=mm, second=0, microsecond=0)
    day = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")[local.weekday()]
    due = local >= deadline and (not s.days or day in s.days)
    return due, local.date().isoformat(), deadline


def parse_sources(data: dict[str, Any]) -> dict[str, Source]:
    out = {}
    for name, spec in (data or {}).items():
        if not isinstance(spec, dict):
            raise SourceError(f"source {name}: must be a mapping")
        out[name] = Source.model_validate({**spec, "name": name})
    return out


def check_source(s: Source) -> list[tuple[str, str]]:
    """(severity, message) problems beyond the schema."""
    probs: list[tuple[str, str]] = []
    for i, e in enumerate(s.emit):
        where = f"source {s.name} emit[{i}]"
        for m in check_template(e.payload) + check_template(e.key or "") + check_template(e.type):
            probs.append(("error", f"{where}: {m}"))
        for m in check_condition(e.when):
            probs.append(("error", f"{where}: {m}"))
        if not e.key:
            probs.append(("warning", f"{where}: no key - a resent webhook or a re-read row becomes a second event"))
        if "env." in json.dumps(e.payload) or "env." in (e.key or ""):
            probs.append(("error", f"{where}: payloads may not read environment variables (secrets)"))
    from .envsecrets import allowed
    for env in _envs(s):
        if not allowed(env):
            probs.append(("error", f"source {s.name}: {env} cannot be used by configuration; name the variable "
                                   "SENTINEL_SECRET_... or list it in SENTINEL_CONFIG_SECRETS"))
        elif not os.environ.get(env):
            probs.append(("warning", f"source {s.name}: {env} is not set in this process"))
    if s.kind == "webhook" and s.signature is None:
        probs.append(("warning", f"source {s.name}: unsigned - it can only be posted with a service token"))
    if s.kind == "expect" and not any(e.key for e in s.emit):
        probs.append(("warning", f"source {s.name}: give the emit a key with the date (e.g. "
                                 "\"{{item.route}}:{{item.date}}\") so a re-run does not raise it twice"))
    if s.kind in ("poll", "sql") and s.cursor is None:
        probs.append(("warning", f"source {s.name}: no cursor - every run reads everything again (keys dedupe it)"))
    return probs


def _envs(s: Source) -> list[str]:
    names = []
    if s.signature:
        names.append(s.signature.secret_env)
    if s.dsn_env:
        names.append(s.dsn_env)
    if s.present and s.present.dsn_env:
        names.append(s.present.dsn_env)
    extra = [s.present.url or "", *s.present.headers.values()] if s.present else []
    for text in [s.url or "", *s.headers.values(), *extra]:
        names += re.findall(r"\{\{\s*env\.([A-Za-z_][A-Za-z0-9_]*)", text)
    return names


# ---- signatures --------------------------------------------------------------------------

def verify_signature(s: Source, body: bytes, headers: dict[str, str]) -> bool:
    sig = s.signature
    if sig is None:
        return False
    from .envsecrets import SecretNameError, get
    try:
        secret = get(sig.secret_env, f"source {s.name}")
    except SecretNameError:
        return False
    if not secret:
        return False
    given = next((v for k, v in headers.items() if k.lower() == sig.header.lower()), None)
    if not given:
        return False
    if sig.prefix:
        if not given.startswith(sig.prefix):
            return False
        given = given[len(sig.prefix):]
    if sig.mode == "token":
        return hmac.compare_digest(secret.strip().encode(), given.strip().encode())
    digest = hmac.new(secret.encode(), body, getattr(hashlib, sig.algorithm)).digest()
    want = base64.b64encode(digest).decode() if sig.encoding == "base64" else digest.hex()
    return hmac.compare_digest(want.strip(), given.strip())


# ---- mapping -------------------------------------------------------------------------------

def to_events(s: Source, body: Any, items: list[Any] | None = None, now: datetime | None = None) -> list[Event]:
    """Map a webhook body (or each polled item) to events with the source's emit rules."""
    now = now or datetime.now(UTC)
    contexts = [{"body": body, "item": it, "now": now} for it in items] if items is not None else [
        {"body": body, "item": None, "now": now}]
    out: list[Event] = []
    for ctx in contexts:
        for rule in s.emit:
            subs = [ctx]
            if rule.each:
                lst = dig(ctx, rule.each)
                subs = [{**ctx, "item": it, "parent": ctx.get("item")} for it in (lst if isinstance(lst, list) else [])]
            for sc in subs:
                try:
                    if not matches(rule.when, sc):
                        continue
                    etype = render(rule.type, sc)
                    payload = render(rule.payload, sc)
                    key = render(rule.key, sc) if rule.key else None
                    corr = render(rule.correlation, sc) if rule.correlation else None
                except ExprError as e:
                    raise SourceError(f"source {s.name}: {e}") from None
                if isinstance(payload, str):
                    try:
                        payload = json.loads(payload)
                    except json.JSONDecodeError:
                        payload = {"value": payload}
                if not isinstance(payload, dict):
                    payload = {"value": payload}
                if not etype:
                    raise SourceError(f"source {s.name}: event type rendered empty")
                out.append(Event(type=str(etype), source=s.name, tenant=rule.tenant or s.tenant,
                                 idempotency_key=str(key) if key else None,
                                 correlation_id=str(corr) if corr not in (None, "") else None, payload=payload))
    return out


# ---- polling and table reading ---------------------------------------------------------------

def _cursor_of(s: Source, items: list[Any], current: Any, current_tie: Any = None) -> tuple[Any, Any]:
    """The furthest (value, tie) position in this batch."""
    if s.cursor is None:
        return current, current_tie
    best, best_tie = current, current_tie
    for it in items:
        v = dig({"item": it}, s.cursor.field)
        if v is None:
            continue
        t = dig({"item": it}, s.cursor.tie) if s.cursor.tie else None
        try:
            ahead = best is None or v > best or (s.cursor.tie is not None and v == best and
                                                  (best_tie is None or (t is not None and t > best_tie)))
        except TypeError:
            ahead = True
        if ahead:
            best, best_tie = v, t
    return best, best_tie


def fetch(s: Source, cursor: Any, *, opener: Any = None, cursor_tie: Any = None) -> tuple[Any, list[Any]]:
    """Run one poll or table read. Returns (raw body, items)."""
    if s.kind == "poll":
        from . import connauth, egress
        from .envsecrets import scope as secret_scope
        from .httpactions import decode_reply, encode_body
        scope = {"env": secret_scope(), "auth": connauth.Tokens(opener), "cursor": "" if cursor is None else cursor,
                 "cursor_tie": "" if cursor_tie is None else cursor_tie}
        url = render(s.url, {**scope, "cursor": urllib.parse.quote(str(scope["cursor"]), safe=""),
                             "cursor_tie": urllib.parse.quote(str(scope["cursor_tie"]), safe="")})
        body_scope = {"env": scope["env"], "cursor": scope["cursor"], "cursor_tie": scope["cursor_tie"]}
        raw = b""
        for attempt in (1, 2):
            try:
                headers = {k: str(render(v, scope)) for k, v in s.headers.items()}
            except connauth.AuthError as e:
                raise SourceError(f"source {s.name}: {e}") from None
            data = encode_body(render(s.body, body_scope), headers) if s.body is not None else None
            req = urllib.request.Request(url, data=data, method=s.method,  # noqa: S310 - http(s) validated
                                         headers={"Accept": "application/json", **headers})
            try:
                _, _, raw = egress.open_url(req, s.timeout_s, base_opener=opener)
                break
            except egress.EgressError as e:
                raise SourceError(f"source {s.name}: {e}") from None
            except urllib.error.HTTPError as e:
                names = connauth.uses([s.url, s.headers])
                if e.code == 401 and names and attempt == 1:
                    for n in names:
                        connauth.invalidate(n)
                    continue
                raise
        body = decode_reply(raw) if s.format == "xml" else json.loads(raw or b"null")
        items = dig({"body": body}, s.items) if s.items else body
        return body, items if isinstance(items, list) else []
    if s.kind == "sql":
        try:
            import psycopg
            from psycopg.rows import dict_row
        except ImportError as e:  # pragma: no cover
            raise SourceError('sql sources need "psycopg[binary]"') from e
        from . import egress
        from .envsecrets import SecretNameError, get
        from .envsecrets import scope as secret_scope
        try:
            dsn = get(s.dsn_env or "", f"source {s.name}")
        except SecretNameError as e:
            raise SourceError(str(e)) from None
        if not dsn:
            raise SourceError(f"source {s.name}: {s.dsn_env} is not set")
        from psycopg.conninfo import conninfo_to_dict
        info = conninfo_to_dict(dsn)
        for host in str(info.get("host") or "").split(","):
            if host and not host.startswith("/"):
                try:
                    egress.check_host(host, int(str(info.get("port") or 5432).split(",")[0]))
                except egress.EgressError as e:
                    raise SourceError(f"source {s.name}: {e}") from None
        with psycopg.connect(dsn, row_factory=dict_row, autocommit=True, connect_timeout=15) as conn:
            conn.execute("SET default_transaction_read_only = on")
            conn.execute(f"SET statement_timeout = {int(s.timeout_s * 1000)}")
            # extra values are always bound as parameters, never pasted into the query text
            extra = {k: str(render(v, {"env": secret_scope()})) for k, v in s.params.items()}
            rows = conn.execute(s.query, {**extra, "cursor": cursor, "cursor_tie": cursor_tie}).fetchall()
        rows = [{k: (v.isoformat() if isinstance(v, datetime) else v) for k, v in r.items()} for r in rows]
        return rows, rows
    raise SourceError(f"source {s.name}: {s.kind} sources are pushed, not fetched")


def run_once(s: Source, state: dict[str, Any], *, now: datetime | None = None,
             opener: Any = None) -> tuple[list[Event], dict[str, Any]]:
    """Fetch, map and advance the cursor. Returns (events, new state)."""
    if s.kind == "expect":
        return _run_expect(s, state, now=now or datetime.now(UTC), opener=opener)
    cursor = state.get("cursor", s.cursor.initial if s.cursor else None)
    tie = state.get("cursor_tie", s.cursor.tie_initial if s.cursor else None)
    body, items = fetch(s, cursor, opener=opener, cursor_tie=tie)
    events = to_events(s, body, items, now=now)
    new, new_tie = _cursor_of(s, items, cursor, tie)
    out = {**state, "cursor": new, "last_count": len(items)}
    if s.cursor and s.cursor.tie:
        out["cursor_tie"] = new_tie
    return events, out


def _run_expect(s: Source, state: dict[str, Any], *, now: datetime, opener: Any = None) -> tuple[list[Event],
                                                                                                 dict[str, Any]]:
    """What should be there and is not: one event per missing expected item (or one, when nothing at all
    arrived and no items are listed). Each item gets ``date`` (local) and ``deadline`` for the emit rules."""
    p = s.present
    assert p is not None
    inner = Source(name=s.name, kind="poll" if p.url else "sql", emit=s.emit, url=p.url, method=p.method,
                   headers=p.headers, body=p.body, items=p.items, dsn_env=p.dsn_env, query=p.query,
                   timeout_s=p.timeout_s, tenant=s.tenant)
    _, items = fetch(inner, None, opener=opener)
    _, day, deadline = expect_due(s, now)
    extra = {"date": day, "deadline": deadline.isoformat()}
    if s.expected:
        try:
            have = {str(render(s.match_on, {"item": it})) for it in items}
            missing = [{**e, **extra} for e in s.expected if str(render(s.match_on, {"item": e})) not in have]
        except ExprError as e:
            raise SourceError(f"source {s.name}: {e}") from None
    else:
        missing = [] if items else [dict(extra)]
    events = to_events(s, {"expected": len(s.expected or []), "present": len(items)}, missing, now=now)
    return events, {**state, "last_run_for": day, "last_missing": len(missing), "last_present": len(items)}
