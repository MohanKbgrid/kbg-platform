# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""CloudEvents 1.0 on the way in: an HTTP request in either mode becomes Sentinel's canonical Event.

    structured   Content-Type: application/cloudevents+json     the whole event is the JSON body
    binary       ce-id, ce-type, ce-source, ce-specversion ...   headers carry the attributes, the body is the data

Mapping into the canonical envelope (`sentinel.models.Event`):

    id            -> idempotency_key   (duplicates are recognised per tenant and source, as for every receiver)
    source        -> source
    type          -> type
    time          -> occurred_at       (RFC 3339, must carry an offset; absent: now)
    subject       -> payload["ce_subject"]
    data          -> payload           (a JSON object as is; any other JSON value as {"value": ...})
    tenant        -> tenant            (extension attribute, optional)
    correlationid -> correlation_id    (extension attribute, optional)

Other extension attributes are ignored, not stored: the envelope is Sentinel's, not the sender's. This module
only parses and validates; authentication, the size cap, rate limiting and idempotency are the receiver's, so
they are exactly those of the other receivers. Anything malformed raises `CloudEventError` carrying the HTTP
status to answer with (400 malformed, 415 a content type or mode not supported).
"""
from __future__ import annotations

import base64
import binascii
import json
from collections.abc import Mapping
from datetime import datetime
from typing import Any
from urllib.parse import unquote

from .models import Event

SPECVERSION = "1.0"
STRUCTURED = "application/cloudevents+json"
BATCH = "application/cloudevents-batch+json"
MAX_ATTR_LEN = 1024            # id, source, type, subject: a key or a label, never a document


class CloudEventError(ValueError):
    def __init__(self, message: str, status: int = 400) -> None:
        super().__init__(message)
        self.status = status


def _media_type(content_type: str) -> str:
    return content_type.split(";", 1)[0].strip().lower()


def _is_json(media: str) -> bool:
    return media == "application/json" or media.endswith("+json")


def _text(attrs: Mapping[str, Any], name: str, *, required: bool) -> str | None:
    v = attrs.get(name)
    if v is None:
        if required:
            raise CloudEventError(f"missing required CloudEvents attribute {name!r}")
        return None
    if not isinstance(v, str):
        raise CloudEventError(f"CloudEvents attribute {name!r} must be a string")
    if not v.strip():
        if required:
            raise CloudEventError(f"CloudEvents attribute {name!r} must not be empty")
        return None
    if len(v) > MAX_ATTR_LEN:
        raise CloudEventError(f"CloudEvents attribute {name!r} is longer than {MAX_ATTR_LEN} characters")
    return v


def _time(v: str | None) -> datetime | None:
    if v is None:
        return None
    try:
        t = datetime.fromisoformat(v)
    except ValueError:
        raise CloudEventError("CloudEvents attribute 'time' is not an RFC 3339 timestamp") from None
    if t.tzinfo is None:
        raise CloudEventError("CloudEvents attribute 'time' must carry a UTC offset (RFC 3339)")
    return t


def _payload(data: Any, subject: str | None) -> dict[str, Any]:
    if data is None:
        out: dict[str, Any] = {}
    elif isinstance(data, dict):
        out = dict(data)
    else:
        out = {"value": data}
    if subject is not None:
        out["ce_subject"] = subject
    return out


def _event(attrs: Mapping[str, Any], data: Any) -> Event:
    if attrs.get("specversion") != SPECVERSION:
        raise CloudEventError(f"unsupported CloudEvents specversion {attrs.get('specversion')!r}; only "
                              f"{SPECVERSION!r} is accepted")
    eid = _text(attrs, "id", required=True)
    source = _text(attrs, "source", required=True)
    etype = _text(attrs, "type", required=True)
    subject = _text(attrs, "subject", required=False)
    when = _time(_text(attrs, "time", required=False))
    tenant = _text(attrs, "tenant", required=False)
    corr = _text(attrs, "correlationid", required=False)
    extra: dict[str, Any] = {}
    if when is not None:
        extra["occurred_at"] = when
    if tenant is not None:
        extra["tenant"] = tenant
    return Event(type=etype, source=source, idempotency_key=eid, correlation_id=corr,
                 payload=_payload(data, subject), **extra)


def from_structured(body: bytes) -> Event:
    try:
        doc = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise CloudEventError("structured CloudEvent: the body must be UTF-8 JSON") from None
    if not isinstance(doc, dict):
        raise CloudEventError("structured CloudEvent: the body must be a JSON object "
                              "(batches are not supported)")
    if "data" in doc and "data_base64" in doc:
        raise CloudEventError("structured CloudEvent: 'data' and 'data_base64' are mutually exclusive")
    data = doc.get("data")
    if "data_base64" in doc:
        try:
            raw = base64.b64decode(str(doc["data_base64"]), validate=True)
            data = json.loads(raw.decode("utf-8"))
        except (binascii.Error, UnicodeDecodeError, json.JSONDecodeError, ValueError):
            raise CloudEventError("structured CloudEvent: 'data_base64' must be base64 of a JSON document") from None
    return _event(doc, data)


def from_binary(headers: Mapping[str, str], body: bytes) -> Event:
    h = {k.lower(): v for k, v in headers.items()}
    attrs = {k[3:]: unquote(v) for k, v in h.items() if k.startswith("ce-")}
    media = _media_type(h.get("content-type", ""))
    data: Any = None
    if body:
        if _is_json(media) or not media:
            try:
                data = json.loads(body.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                raise CloudEventError("binary CloudEvent: the body must be UTF-8 JSON") from None
        elif media.startswith("text/"):
            try:
                data = body.decode("utf-8")
            except UnicodeDecodeError:
                raise CloudEventError("binary CloudEvent: text data must be UTF-8") from None
        else:
            raise CloudEventError(f"binary CloudEvent: data of type {media!r} is not supported "
                                  "(JSON or text)", status=415)
    return _event(attrs, data)


def parse(headers: Mapping[str, str], body: bytes) -> Event:
    """The canonical Event for a CloudEvents HTTP request (either mode), or `CloudEventError`."""
    h = {k.lower(): v for k, v in headers.items()}
    media = _media_type(h.get("content-type", ""))
    if media == BATCH:
        raise CloudEventError("CloudEvents batch mode is not supported: send one event per request", status=415)
    if media == STRUCTURED:
        return from_structured(body)
    if media.startswith("application/cloudevents"):
        raise CloudEventError(f"CloudEvents format {media!r} is not supported (use application/cloudevents+json)",
                              status=415)
    if any(k.startswith("ce-") for k in h):
        return from_binary(h, body)
    raise CloudEventError("not a CloudEvent: send Content-Type application/cloudevents+json (structured) "
                          "or ce-* headers (binary)", status=415)
