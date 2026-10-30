# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""WhatsApp through an Indian business service provider: Gupshup or Interakt, for customers who would rather
not register a WhatsApp Business app with Meta themselves.

    edges:
      wa_gupshup:  {kind: gupshup, source: "919840011111", app_name: AcmeOps, api_key_env: SENTINEL_SECRET_GUPSHUP_KEY,
                    inbound_token_env: SENTINEL_SECRET_GUPSHUP_INBOUND,
                    template: {id: "a1b2c3...", languages: [en]}}         # optional: outside the 24-hour window
      wa_interakt: {kind: interakt, api_key_env: SENTINEL_SECRET_INTERAKT_KEY, template: {name: sentinel_review,
                    language: en, languages: [en, hi, ta]}, signing_secret_env: SENTINEL_SECRET_INTERAKT_WEBHOOK}

Cards carry Approve and Close buttons whose reply payload is ``sentinel:<review>:<decision>[:<code>]``,
exactly like the Meta edge. Replies come back to ``POST /v1/wa/<edge>``: Gupshup's callback URL is given a
shared token (``?token=`` or an ``X-Sentinel-Token`` header, the value of ``inbound_token_env``); Interakt's
webhook is checked with its signing secret (HMAC-SHA256 of the body in the ``Interakt-Signature`` header) or
the same shared token. The sender is matched to a person by their WhatsApp number, as for Meta.

Interakt sends approved templates only (bodyValues: title, reason; one quick-reply button payload per
button). Gupshup sends a quick-reply message inside the 24-hour customer-service window, or the template when
one is configured. Endpoint and field names follow the providers' public APIs; check them against the
customer's account before going live.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from .edges import EdgeError, ReviewCard, WhatsAppEdge, _close_codes, digits
from .i18n import t


def _post(url: str, data: bytes, headers: dict[str, str], timeout_s: float, who: str) -> Any:
    from . import egress
    req = urllib.request.Request(url, data=data, method="POST", headers=headers)  # noqa: S310 - egress
    try:
        _, _, raw = egress.open_url(req, timeout_s)
    except egress.EgressError as e:
        raise EdgeError(f"{who}: {e}") from None
    except urllib.error.HTTPError as e:
        raise EdgeError(f"{who}: HTTP {e.code}") from None
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        raise EdgeError(f"{who}: {type(e).__name__}: {e}") from None
    try:
        return json.loads(raw or b"null")
    except ValueError:
        return raw.decode("utf-8", "replace")[:500]


def _text(card: ReviewCard) -> str:
    lang = card.language
    lines = [f"*{card.title}*", card.reason]
    facts = ", ".join(f"{k}: {v}" for k, v in card.facts.items() if k not in ("event_type", "source"))
    if facts:
        lines.append(facts)
    if card.proposal_steps:
        conf = (f" ({t(lang, 'sure', n=round(card.proposal_confidence * 100))})"
                if card.proposal_confidence is not None else "")
        lines.append(t(lang, "suggested") + ": " + "; ".join(s.action for s in card.proposal_steps) + conf)
    if card.link:
        lines.append(card.link)
    return "\n".join(lines)[:1000]


def _buttons(card: ReviewCard) -> list[tuple[str, str]]:
    """(title, payload) for Approve and the first close code."""
    out = []
    if card.proposal_steps and "approve" in card.answer_options:
        out.append((t(card.language, "approve")[:20], WhatsAppEdge.reply_id(card.review_id, "approve")))
    close = _close_codes(card, 1)
    if close:
        out.append((t(card.language, "close_as", code=close[0].replace("_", " "))[:20],
                    WhatsAppEdge.reply_id(card.review_id, "reject", close[0])))
    return out


def _decision(payload: str) -> tuple[str, dict[str, Any]] | None:
    parts = str(payload).split(":")
    if len(parts) < 3 or parts[0] != "sentinel" or parts[2] not in ("approve", "reject"):
        return None
    dec: dict[str, Any] = {"kind": parts[2]}
    if parts[2] == "reject":
        dec["disposition_code"] = parts[3] if len(parts) > 3 else None
        dec["note"] = "closed on WhatsApp"
    return parts[1], dec


def _payloads(obj: Any) -> list[str]:
    """Every string in a webhook body that is a Sentinel reply payload (providers nest it differently)."""
    found: list[str] = []
    if isinstance(obj, dict):
        for v in obj.values():
            found += _payloads(v)
    elif isinstance(obj, list):
        for v in obj:
            found += _payloads(v)
    elif isinstance(obj, str) and obj.startswith("sentinel:"):
        found.append(obj)
    return found


class _ProviderEdge:
    kind = "provider"
    inbound_token: str | None = None
    signing_secret: str | None = None
    signature_header = "Interakt-Signature"

    def check_request(self, body: bytes, headers: dict[str, str], query: dict[str, str]) -> bool:
        h = {k.lower(): v for k, v in headers.items()}
        if self.signing_secret:
            given = h.get(self.signature_header.lower(), "")
            given = given.split("=", 1)[1] if given.startswith("sha256=") else given
            want = hmac.new(self.signing_secret.encode(), body, hashlib.sha256).hexdigest()
            if given and hmac.compare_digest(want, given.strip()):
                return True
        if self.inbound_token:
            given = query.get("token") or h.get("x-sentinel-token", "")
            return bool(given) and hmac.compare_digest(self.inbound_token, given)
        return False

    def number_of(self, payload: dict[str, Any]) -> str:
        raise NotImplementedError

    def replies(self, payload: dict[str, Any]) -> list[tuple[str, str, dict[str, Any]]]:
        number = digits(self.number_of(payload) or "")
        out = []
        for p in dict.fromkeys(_payloads(payload)):          # each payload once, in order
            d = _decision(p)
            if d:
                out.append((number, d[0], d[1]))
        return out[:1]                                        # one tap answers one review


class GupshupEdge(_ProviderEdge):
    kind = "gupshup"

    def __init__(self, name: str, source: str, app_name: str, api_key: str, *, inbound_token: str | None = None,
                 template: dict[str, Any] | None = None, base_url: str = "https://api.gupshup.io/wa/api/v1",
                 timeout_s: float = 10.0) -> None:
        if not source or not app_name:
            raise ValueError(f"gupshup {name}: source (the business number) and app_name are required")
        self.name, self.source, self.app_name, self.api_key = name, digits(source), app_name, api_key
        self.inbound_token, self.template = inbound_token, template
        self.base_url, self.timeout_s = base_url.rstrip("/"), timeout_s

    def message(self, card: ReviewCard) -> tuple[str, dict[str, str]]:
        to = digits(card.recipient_contact.get("whatsapp") or card.recipient_contact.get("phone") or "")
        if not to:
            raise EdgeError(f"{self.name}: {card.recipient_id or 'recipient'} has no WhatsApp number")
        buttons = _buttons(card)
        base = {"channel": "whatsapp", "source": self.source, "destination": to, "src.name": self.app_name}
        if self.template:
            langs = self.template.get("languages") or []
            form = {**base, "template": json.dumps({"id": self.template["id"],
                                                    "params": [card.title[:200], card.reason[:500]]}),
                    "postbackTexts": json.dumps([{"index": i, "text": p} for i, (_, p) in enumerate(buttons)])}
            if langs and card.language in langs and self.template.get("ids", {}).get(card.language):
                form["template"] = json.dumps({"id": self.template["ids"][card.language],
                                               "params": [card.title[:200], card.reason[:500]]})
            return f"{self.base_url}/template/msg", form
        body = _text(card)
        if buttons:
            msg = {"type": "quick_reply", "msgid": card.review_id,
                   "content": {"type": "text", "text": body},
                   "options": [{"type": "text", "title": title, "postbackText": p} for title, p in buttons]}
        else:
            msg = {"type": "text", "text": body}
        return f"{self.base_url}/msg", {**base, "message": json.dumps(msg, ensure_ascii=False)}

    def deliver(self, card: ReviewCard) -> str:
        url, form = self.message(card)
        reply = _post(url, urllib.parse.urlencode(form).encode(),
                      {"apikey": self.api_key, "Content-Type": "application/x-www-form-urlencoded",
                       "Accept": "application/json"}, self.timeout_s, self.name)
        if isinstance(reply, dict) and str(reply.get("status", "")).lower() in ("error", "failed"):
            raise EdgeError(f"{self.name}: {reply.get('message') or reply}")
        return str((reply or {}).get("messageId") if isinstance(reply, dict) else card.card_id)

    def number_of(self, payload: dict[str, Any]) -> str:
        p = payload.get("payload") or {}
        return str(p.get("source") or (p.get("sender") or {}).get("phone") or payload.get("mobile") or "")


class InteraktEdge(_ProviderEdge):
    kind = "interakt"

    def __init__(self, name: str, api_key: str, template: dict[str, Any], *, signing_secret: str | None = None,
                 inbound_token: str | None = None, base_url: str = "https://api.interakt.ai/v1/public",
                 country_code: str = "+91", timeout_s: float = 10.0) -> None:
        if not template or not template.get("name"):
            raise ValueError(f"interakt {name}: template.name is required (Interakt sends approved templates)")
        self.name, self.api_key, self.template = name, api_key, template
        self.signing_secret, self.inbound_token = signing_secret, inbound_token
        self.base_url, self.country_code, self.timeout_s = base_url.rstrip("/"), country_code, timeout_s

    def message(self, card: ReviewCard) -> dict[str, Any]:
        number = digits(card.recipient_contact.get("whatsapp") or card.recipient_contact.get("phone") or "")
        if not number:
            raise EdgeError(f"{self.name}: {card.recipient_id or 'recipient'} has no WhatsApp number")
        cc = digits(self.country_code)
        local = number[len(cc):] if number.startswith(cc) and len(number) > 10 else number
        langs = self.template.get("languages") or []
        lang = card.language if card.language in langs else self.template.get("language", "en")
        return {"countryCode": f"+{cc}", "phoneNumber": local, "callbackData": card.review_id, "type": "Template",
                "template": {"name": self.template["name"], "languageCode": lang,
                             "bodyValues": [card.title[:200], card.reason[:500]],
                             "buttonValues": {str(i): [p] for i, (_, p) in enumerate(_buttons(card))}}}

    def deliver(self, card: ReviewCard) -> str:
        body = json.dumps(self.message(card), ensure_ascii=False).encode()
        reply = _post(f"{self.base_url}/message/", body,
                      {"Authorization": f"Basic {self.api_key}", "Content-Type": "application/json",
                       "Accept": "application/json"}, self.timeout_s, self.name)
        if isinstance(reply, dict) and reply.get("result") is False:
            raise EdgeError(f"{self.name}: {reply.get('message') or reply}")
        return str((reply or {}).get("id") if isinstance(reply, dict) else card.card_id)

    def number_of(self, payload: dict[str, Any]) -> str:
        c = (payload.get("data") or {}).get("customer") or {}
        return f"{c.get('country_code', '')}{c.get('phone_number', '')}"


def register() -> None:
    from .edges import register_edge_kind
    register_edge_kind("gupshup", {"source", "app_name", "api_key_env", "inbound_token_env", "template", "base_url"},
                       lambda n, c, secret: GupshupEdge(
                           n, str(c.get("source") or ""), str(c.get("app_name") or ""), secret("api_key_env"),
                           inbound_token=secret("inbound_token_env") if c.get("inbound_token_env") else None,
                           template=c.get("template"),
                           base_url=c.get("base_url", "https://api.gupshup.io/wa/api/v1"),
                           timeout_s=float(c.get("timeout_s", 10))))
    register_edge_kind("interakt", {"api_key_env", "template", "signing_secret_env", "inbound_token_env",
                                    "base_url", "country_code"},
                       lambda n, c, secret: InteraktEdge(
                           n, secret("api_key_env"), dict(c.get("template") or {}),
                           signing_secret=secret("signing_secret_env") if c.get("signing_secret_env") else None,
                           inbound_token=secret("inbound_token_env") if c.get("inbound_token_env") else None,
                           base_url=c.get("base_url", "https://api.interakt.ai/v1/public"),
                           country_code=str(c.get("country_code", "+91")),
                           timeout_s=float(c.get("timeout_s", 10))))
