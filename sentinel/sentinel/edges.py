# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""Edges: where review cards go and how people's answers come back.

An edge is a delivery channel (Ask AI gateway, A2UI, WhatsApp via a BSP, email, Slack). The framework
builds a `ReviewCard` per recipient and hands it to the edge through the work queue, so a failed delivery
is retried with backoff instead of lost. Answers come back through `Engine.answer`, which applies the
same RBAC as any other decision.

`WebhookEdge` is the general-purpose edge: it POSTs the card as JSON, signed with HMAC-SHA256 over
"<timestamp>.<body>" so the receiving side can verify it, and the same scheme verifies answers posted back.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import time
import urllib.error
import urllib.request
from datetime import datetime
from collections.abc import Callable
from typing import Any, Protocol

from pydantic import BaseModel, Field

from .models import new_id, utcnow


class CardStep(BaseModel):
    action: str
    params: dict[str, Any] = Field(default_factory=dict)


class ReviewCard(BaseModel):
    card_id: str = Field(default_factory=lambda: new_id("card"))
    review_id: str
    incident_id: str
    pattern_id: str
    title: str
    severity: str
    reason: str
    facts: dict[str, Any]
    assignee_role: str
    escalation_level: int
    due_at: datetime
    proposal_steps: list[CardStep] = Field(default_factory=list)
    proposal_code: str | None = None
    proposal_confidence: float | None = None
    proposal_rationale: str = ""
    allowed_actions: list[dict[str, Any]] = Field(default_factory=list)
    disposition_codes: list[str] = Field(default_factory=list)
    recipient_id: str | None = None
    recipient_name: str | None = None
    recipient_contact: dict[str, str] = Field(default_factory=dict)
    link: str | None = None
    answer_options: list[str] = Field(default_factory=lambda: ["approve", "modify", "reject"])
    similar_cases: list[dict[str, Any]] = Field(default_factory=list)   # how the nearest past cases ended
    sop: str = ""                                                        # the procedure for this exception
    language: str = "en"                                                 # the reader's (see sentinel.i18n)
    answer_token: str | None = None      # single-use; send it back with the answer (binds review, person, edge)
    hold: dict[str, Any] | None = None   # paused or silenced: kind, reason, until
    quiet: bool = False                  # past every escalation: no longer sent, on the daily overdue list
    pause_reasons: list[str] = Field(default_factory=list)


class Delivery(BaseModel):
    id: str = Field(default_factory=lambda: new_id("dlv"))
    review_id: str
    person_id: str | None
    edge: str
    status: str = "sent"            # sent | answered
    ref: str = ""
    created_at: datetime = Field(default_factory=utcnow)
    answered_at: datetime | None = None
    answer_token_hash: str | None = None          # the card's single-use answer token (sha256)
    answer_expires_at: datetime | None = None


class Edge(Protocol):
    name: str

    def deliver(self, card: ReviewCard) -> str: ...


class MemoryEdge:
    """Keeps cards in memory. For tests, demos, and pull-style UIs that poll for cards."""

    def __init__(self, name: str = "memory") -> None:
        self.name = name
        self.cards: list[ReviewCard] = []

    def deliver(self, card: ReviewCard) -> str:
        self.cards.append(card)
        return card.card_id


def sign(secret: str, body: bytes, ts: int | None = None) -> tuple[str, str]:
    ts_s = str(int(time.time()) if ts is None else ts)
    mac = hmac.new(secret.encode(), ts_s.encode() + b"." + body, hashlib.sha256).hexdigest()
    return ts_s, f"sha256={mac}"


def verify(secret: str, body: bytes, ts: str, signature: str, max_skew_s: int = 300,
           now: float | None = None) -> bool:
    try:
        t = int(ts)
    except (TypeError, ValueError):
        return False
    if abs((now if now is not None else time.time()) - t) > max_skew_s:
        return False                      # stale or future-dated: replay protection
    _, expected = sign(secret, body, t)
    return hmac.compare_digest(expected, signature or "")


class EdgeError(RuntimeError):
    pass


class WebhookEdge:
    """POST the card as JSON with X-Sentinel-Timestamp and X-Sentinel-Signature headers."""

    def __init__(self, name: str, url: str, secret: str, timeout_s: float = 10.0,
                 headers: dict[str, str] | None = None, answer_secret: str | None = None) -> None:
        if not secret or len(secret) < 16:
            raise ValueError("webhook secret must be at least 16 characters")
        if not url.lower().startswith(("https://", "http://")):
            raise ValueError("webhook url must be http(s)")
        self.name, self.url, self.secret, self.timeout_s = name, url, secret, timeout_s
        self.answer_secret = answer_secret      # verifies answers coming back; the signing secret if unset
        self.headers = headers or {}

    def deliver(self, card: ReviewCard) -> str:
        return self._post(card, card.model_dump_json().encode())

    def _post(self, card: ReviewCard, body: bytes) -> str:
        return _post_signed(self, card, body)


# ================================================================================ A2UI (Ask AI)
A2UI_CATALOG = "https://a2ui.org/specification/v0_8/standard_catalog_definition.json"


def _close_codes(card: ReviewCard, limit: int = 2) -> list[str]:
    pref = [c for c in ("no_action", "false_positive") if c in card.disposition_codes]
    return (pref or card.disposition_codes)[:limit]


def _txt(cid: str, text: str, hint: str | None = None) -> dict[str, Any]:
    t: dict[str, Any] = {"text": {"literalString": text}}
    if hint:
        t["usageHint"] = hint
    return {"id": cid, "component": {"Text": t}}


def _button(cid: str, label: str, name: str, context: dict[str, str]) -> list[dict[str, Any]]:
    return [_txt(f"{cid}_t", label),
            {"id": cid, "component": {"Button": {"child": f"{cid}_t", "action": {
                "name": name, "context": [{"key": k, "value": {"literalString": v}} for k, v in context.items()]}}}}]


def a2ui_messages(card: ReviewCard) -> list[dict[str, Any]]:
    """The review card as A2UI v0.8 messages (surfaceUpdate, then beginRendering), for chat surfaces such as
    the Ask AI gateway. Buttons send a userAction named ``sentinel.answer`` with the review and decision."""
    sid = f"review-{card.review_id}"
    facts = ", ".join(f"{k}: {v}" for k, v in card.facts.items() if k not in ("event_type", "source"))
    comps: list[dict[str, Any]] = [_txt("title", card.title, "h3"), _txt("reason", card.reason)]
    body = ["title", "reason"]
    if facts:
        comps.append(_txt("facts", facts, "caption"))
        body.append("facts")
    if card.proposal_steps:
        prop = "; ".join(f"{s.action}({', '.join(f'{k}={v}' for k, v in s.params.items())})"
                         for s in card.proposal_steps)
        conf = f" - {round(card.proposal_confidence * 100)}% sure" if card.proposal_confidence is not None else ""
        comps.append(_txt("proposal", f"Proposed: {prop}{conf}. {card.proposal_rationale}".strip()))
        body.append("proposal")
    buttons = []
    if "approve" in card.answer_options and card.proposal_steps:
        comps += _button("approve", "Approve", "sentinel.answer", {"review_id": card.review_id, "decision": "approve",
                                                                   **({"answer_token": card.answer_token}
                                                                      if card.answer_token else {})})
        buttons.append("approve")
    for i, code in enumerate(_close_codes(card)):
        comps += _button(f"close{i}", f"Close: {code.replace('_', ' ')}", "sentinel.answer",
                         {"review_id": card.review_id, "decision": "reject", "disposition_code": code,
                          **({"answer_token": card.answer_token} if card.answer_token else {})})
        buttons.append(f"close{i}")
    if card.link:
        comps.append(_txt("link", f"Open in the console: {card.link}", "caption"))
        body.append("link")
    comps.append({"id": "buttons", "component": {"Row": {"children": {"explicitList": buttons}}}})
    comps.append({"id": "col", "component": {"Column": {"children": {"explicitList": [*body, "buttons"]}}}})
    comps.append({"id": "root", "component": {"Card": {"child": "col"}}})
    return [{"surfaceUpdate": {"surfaceId": sid, "components": comps}},
            {"beginRendering": {"surfaceId": sid, "root": "root", "catalogId": A2UI_CATALOG}}]


# A2UI v0.9 / v0.9.1 (specification/v0_9_1 of the A2UI project, "closed", the current production release):
# flat components with a "component" type name, createSurface / updateComponents envelopes carrying
# "version", the basic catalogue, and a client action {name, surfaceId, sourceComponentId, timestamp, context}.
A2UI_V08 = "v0.8"
A2UI_VERSIONS = ("v0.8", "v0.9", "v0.9.1")
A2UI_DEFAULT_VERSION = A2UI_V08            # nothing changes for existing chat surfaces until they opt in
A2UI_CATALOG_V09 = "https://a2ui.org/specification/v0_9/catalogs/basic/catalog.json"
_A2UI_V09 = ("v0.9", "v0.9.1")


def check_a2ui_version(version: Any) -> str:
    """The version if Sentinel speaks it; otherwise a clear ValueError (never a silent fallback)."""
    if version not in A2UI_VERSIONS:
        raise ValueError(f"unsupported A2UI version {version!r}; this edge speaks {', '.join(A2UI_VERSIONS)}")
    return version


def _v9_btn(cid: str, label: str, context: dict[str, str]) -> list[dict[str, Any]]:
    return [{"id": f"{cid}_t", "component": "Text", "text": label},
            {"id": cid, "component": "Button", "child": f"{cid}_t",
             "variant": "primary" if cid == "approve" else "default",
             "action": {"event": {"name": "sentinel.answer", "context": dict(context)}}}]


def a2ui_messages_v09(card: ReviewCard, version: str = "v0.9.1") -> list[dict[str, Any]]:
    """The review card as A2UI v0.9/v0.9.1 messages (createSurface, then updateComponents). The same card,
    the same ``sentinel.answer`` action and context as v0.8; only the wire format differs."""
    if version not in _A2UI_V09:
        raise ValueError(f"not an A2UI v0.9 version: {version!r}")
    sid = f"review-{card.review_id}"
    facts = ", ".join(f"{k}: {v}" for k, v in card.facts.items() if k not in ("event_type", "source"))
    comps: list[dict[str, Any]] = [{"id": "title", "component": "Text", "text": card.title, "variant": "h3"},
                                   {"id": "reason", "component": "Text", "text": card.reason}]
    body = ["title", "reason"]
    if facts:
        comps.append({"id": "facts", "component": "Text", "text": facts, "variant": "caption"})
        body.append("facts")
    if card.proposal_steps:
        prop = "; ".join(f"{s.action}({', '.join(f'{k}={v}' for k, v in s.params.items())})"
                         for s in card.proposal_steps)
        conf = f" - {round(card.proposal_confidence * 100)}% sure" if card.proposal_confidence is not None else ""
        comps.append({"id": "proposal", "component": "Text",
                      "text": f"Proposed: {prop}{conf}. {card.proposal_rationale}".strip()})
        body.append("proposal")
    tok = {"answer_token": card.answer_token} if card.answer_token else {}
    buttons = []
    if "approve" in card.answer_options and card.proposal_steps:
        comps += _v9_btn("approve", "Approve", {"review_id": card.review_id, "decision": "approve", **tok})
        buttons.append("approve")
    for i, code in enumerate(_close_codes(card)):
        comps += _v9_btn(f"close{i}", f"Close: {code.replace('_', ' ')}",
                         {"review_id": card.review_id, "decision": "reject", "disposition_code": code, **tok})
        buttons.append(f"close{i}")
    if card.link:
        comps.append({"id": "link", "component": "Text", "text": f"Open in the console: {card.link}",
                      "variant": "caption"})
        body.append("link")
    comps.append({"id": "buttons", "component": "Row", "children": buttons})
    comps.append({"id": "col", "component": "Column", "children": [*body, "buttons"]})
    comps.append({"id": "root", "component": "Card", "child": "col"})
    return [{"version": version, "createSurface": {"surfaceId": sid, "catalogId": A2UI_CATALOG_V09}},
            {"version": version, "updateComponents": {"surfaceId": sid, "components": comps}}]


def render_a2ui(card: ReviewCard, version: str = A2UI_DEFAULT_VERSION) -> list[dict[str, Any]]:
    """The card in the negotiated A2UI version."""
    check_a2ui_version(version)
    return a2ui_messages(card) if version == A2UI_V08 else a2ui_messages_v09(card, version)


def user_action_from_message(msg: dict[str, Any]) -> dict[str, Any]:
    """The action inside an inbound A2UI client message, from either wire format, as ``{name, context, ...}``.

    * v0.8 / legacy: ``{"userAction": {name, context, surfaceId, ...}}``
    * v0.9 / v0.9.1: ``{"version": "v0.9.1", "action": {name, surfaceId, sourceComponentId, timestamp, context}}``

    Both versions are accepted whatever the edge renders. A declared ``version`` Sentinel does not speak is
    refused; a v0.9 answer whose surface is not the review it names is refused (it came from another card)."""
    if not isinstance(msg, dict):
        raise ValueError("an A2UI message is a JSON object")
    ver = msg.get("version")
    if ver is not None:
        check_a2ui_version(ver)
    if "action" in msg:
        if ver not in _A2UI_V09:
            raise ValueError("an A2UI 'action' message must declare version v0.9 or v0.9.1")
        act = msg["action"]
        if not isinstance(act, dict):
            raise ValueError("A2UI action must be an object")
        for k in ("name", "surfaceId", "sourceComponentId", "timestamp", "context"):
            if k not in act:
                raise ValueError(f"A2UI {ver} action is missing {k!r}")
    elif "userAction" in msg:
        if ver in _A2UI_V09:
            raise ValueError(f"A2UI {ver} sends 'action', not 'userAction'")
        act = msg["userAction"]
        if not isinstance(act, dict):
            raise ValueError("A2UI userAction must be an object")
    else:
        raise ValueError("no A2UI action in the message")
    ctx = act.get("context") or {}
    if not isinstance(ctx, dict):
        raise ValueError("A2UI action context must be an object")
    sid, rid = act.get("surfaceId"), ctx.get("review_id")
    if "action" in msg and act.get("name") == "sentinel.answer" and sid != f"review-{rid}":
        raise ValueError("the action's surface is not the review it names")
    return act


def answer_from_user_action(action: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    """An A2UI userAction from a review card -> (review_id, decision). The card's answer token, when the
    button carried one, is in ``decision["answer_token"]``."""
    if action.get("name") != "sentinel.answer":
        raise ValueError(f"not a Sentinel answer: {action.get('name')!r}")
    ctx = action.get("context") or {}
    rid, kind = ctx.get("review_id"), ctx.get("decision")
    if not rid or kind not in ("approve", "reject"):
        raise ValueError("answer needs review_id and decision approve|reject")
    dec: dict[str, Any] = {"kind": kind}
    if kind == "reject":
        dec["disposition_code"] = ctx.get("disposition_code")
        dec["note"] = str(ctx.get("note") or "closed from chat")[:500]
    if ctx.get("answer_token"):
        dec["answer_token"] = str(ctx["answer_token"])
    return rid, dec


class A2UIEdge(WebhookEdge):
    """A signed webhook whose body carries the card and its A2UI rendering:
    ``{"card": {...}, "a2ui": [messages...]}``. ``a2ui_version`` (``v0.8`` default, ``v0.9``, ``v0.9.1``) is the
    version this chat surface renders; answers in either version are always accepted."""

    def __init__(self, name: str, url: str, secret: str, timeout_s: float = 10.0,
                 headers: dict[str, str] | None = None, answer_secret: str | None = None,
                 a2ui_version: str = A2UI_DEFAULT_VERSION) -> None:
        super().__init__(name, url, secret, timeout_s, headers, answer_secret)
        try:
            self.a2ui_version = check_a2ui_version(a2ui_version)
        except ValueError as e:
            raise ValueError(f"edge {name}: {e}") from None

    def deliver(self, card: ReviewCard) -> str:
        out: dict[str, Any] = {"card": card.model_dump(mode="json"), "a2ui": render_a2ui(card, self.a2ui_version)}
        if self.a2ui_version != A2UI_DEFAULT_VERSION:
            out["a2ui_version"] = self.a2ui_version        # the default body is unchanged
        return self._post(card, json.dumps(out).encode())


def _post_signed(edge: WebhookEdge, card: ReviewCard, body: bytes) -> str:
    from . import egress
    ts, sig = sign(edge.secret, body)
    req = urllib.request.Request(edge.url, data=body, method="POST", headers={  # noqa: S310 - scheme checked
        "Content-Type": "application/json", "X-Sentinel-Timestamp": ts, "X-Sentinel-Signature": sig,
        "X-Sentinel-Card": card.card_id, **edge.headers})
    try:
        status, _, raw = egress.open_url(req, edge.timeout_s)
        text = raw[:4096].decode(errors="replace")
    except egress.EgressError as e:
        raise EdgeError(f"{edge.name}: {e}") from None
    except urllib.error.HTTPError as e:
        raise EdgeError(f"{edge.name}: HTTP {e.code}") from None
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        raise EdgeError(f"{edge.name}: {type(e).__name__}: {e}") from None
    if not 200 <= status < 300:
        raise EdgeError(f"{edge.name}: HTTP {status}")
    try:
        return str(json.loads(text).get("ref", card.card_id))
    except (ValueError, AttributeError):
        return card.card_id



# ================================================================================ WhatsApp
def digits(phone: str) -> str:
    return "".join(ch for ch in str(phone or "") if ch.isdigit())


class WhatsAppEdge:
    """Review cards on WhatsApp through the WhatsApp Business Cloud API (Meta), or a BSP that exposes the same
    API (set ``base_url``). The card goes as an interactive message with reply buttons (Approve / Close),
    or, to reach people outside the 24-hour service window, as an approved template with quick-reply
    buttons. Replies come back to ``/v1/whatsapp/{edge}`` (signed by Meta with the app secret) and are
    matched to the person by their WhatsApp number in the people configuration.

    Template mode expects a template whose body takes two parameters (title, reason) and which has two
    quick-reply buttons (approve, close)."""

    MAX_BODY = 1024

    def __init__(self, name: str, phone_number_id: str, access_token: str, app_secret: str, verify_token: str,
                 *, base_url: str = "https://graph.facebook.com/v21.0", template: dict[str, Any] | None = None,
                 timeout_s: float = 10.0) -> None:
        if not base_url.lower().startswith(("https://", "http://127.0.0.1", "http://localhost")):
            raise ValueError("whatsapp base_url must be https")
        for k, v in (("access_token", access_token), ("app_secret", app_secret), ("verify_token", verify_token)):
            if not v:
                raise ValueError(f"whatsapp {name}: {k} is required")
        self.name, self.phone_number_id, self.access_token = name, phone_number_id, access_token
        self.app_secret, self.verify_token, self.base_url = app_secret, verify_token, base_url.rstrip("/")
        self.template, self.timeout_s = template, timeout_s

    @staticmethod
    def reply_id(review_id: str, decision: str, code: str | None = None) -> str:
        return ":".join(["sentinel", review_id, decision, *([code] if code else [])])

    def _template_language(self, lang: str) -> str:
        """The reader's language when the approved template exists in it (``template.languages``)."""
        have = self.template.get("languages") or []
        return lang if lang in have else self.template.get("language", "en")

    def message(self, card: ReviewCard) -> dict[str, Any]:
        to = digits(card.recipient_contact.get("whatsapp") or card.recipient_contact.get("phone") or "")
        if not to:
            raise EdgeError(f"{self.name}: {card.recipient_id or 'recipient'} has no WhatsApp number")
        close = _close_codes(card, 1)
        approve = bool(card.proposal_steps) and "approve" in card.answer_options
        if self.template:
            buttons = []
            if approve:
                buttons.append(self.reply_id(card.review_id, "approve"))
            if close:
                buttons.append(self.reply_id(card.review_id, "reject", close[0]))
            return {"messaging_product": "whatsapp", "to": to, "type": "template", "template": {
                "name": self.template["name"], "language": {"code": self._template_language(card.language)},
                "components": [{"type": "body", "parameters": [{"type": "text", "text": card.title[:200]},
                                                               {"type": "text", "text": card.reason[:500]}]},
                               *({"type": "button", "sub_type": "quick_reply", "index": str(i),
                                  "parameters": [{"type": "payload", "payload": p}]} for i, p in enumerate(buttons))]}}
        from .i18n import t
        lang = card.language
        lines = [f"*{card.title}*", card.reason]
        facts = ", ".join(f"{k}: {v}" for k, v in card.facts.items() if k not in ("event_type", "source"))
        if facts:
            lines.append(facts)
        if card.proposal_steps:
            lines.append(t(lang, "suggested") + ": " + "; ".join(s.action for s in card.proposal_steps)
                         + (f" ({t(lang, 'sure', n=round(card.proposal_confidence * 100))})"
                            if card.proposal_confidence is not None else ""))
        if card.link:
            lines.append(card.link)
        text = "\n".join(lines)
        if len(text) > self.MAX_BODY:
            text = text[: self.MAX_BODY - 1] + "…"
        btns = []
        if approve:
            btns.append({"type": "reply", "reply": {"id": self.reply_id(card.review_id, "approve"),
                                                    "title": t(lang, "approve")[:20]}})
        if close:
            btns.append({"type": "reply", "reply": {"id": self.reply_id(card.review_id, "reject", close[0]),
                                                    "title": t(lang, "close_as",
                                                               code=close[0].replace("_", " "))[:20]}})
        if not btns:
            return {"messaging_product": "whatsapp", "to": to, "type": "text", "text": {"body": text}}
        return {"messaging_product": "whatsapp", "to": to, "type": "interactive", "interactive": {
            "type": "button", "body": {"text": text}, "action": {"buttons": btns}}}

    def deliver(self, card: ReviewCard) -> str:
        body = json.dumps(self.message(card)).encode()
        req = urllib.request.Request(f"{self.base_url}/{self.phone_number_id}/messages", data=body,  # noqa: S310
                                     method="POST", headers={"Content-Type": "application/json",
                                                             "Authorization": f"Bearer {self.access_token}"})
        from . import egress
        try:
            _, _, raw = egress.open_url(req, self.timeout_s)
            out = json.loads(raw or b"{}")
        except egress.EgressError as e:
            raise EdgeError(f"{self.name}: {e}") from None
        except urllib.error.HTTPError as e:
            raise EdgeError(f"{self.name}: HTTP {e.code}") from None
        except (urllib.error.URLError, TimeoutError, OSError, ValueError) as e:
            raise EdgeError(f"{self.name}: {type(e).__name__}: {e}") from None
        msgs = out.get("messages") or [{}]
        return str(msgs[0].get("id") or card.card_id)

    def check_signature(self, body: bytes, header: str) -> bool:
        expected = "sha256=" + hmac.new(self.app_secret.encode(), body, hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, header or "")

    @staticmethod
    def replies(payload: dict[str, Any]) -> list[tuple[str, str, dict[str, Any]]]:
        """(sender's number, review id, decision) for each button reply in a webhook payload."""
        out = []
        for entry in payload.get("entry") or []:
            for change in entry.get("changes") or []:
                for m in (change.get("value") or {}).get("messages") or []:
                    if m.get("type") == "interactive":
                        rid = ((m.get("interactive") or {}).get("button_reply") or {}).get("id", "")
                    elif m.get("type") == "button":
                        rid = (m.get("button") or {}).get("payload", "")
                    else:
                        continue
                    parts = str(rid).split(":")
                    if len(parts) < 3 or parts[0] != "sentinel" or parts[2] not in ("approve", "reject"):
                        continue
                    dec: dict[str, Any] = {"kind": parts[2]}
                    if parts[2] == "reject":
                        dec["disposition_code"] = parts[3] if len(parts) > 3 else None
                        dec["note"] = "closed on WhatsApp"
                    out.append((digits(m.get("from", "")), parts[1], dec))
        return out


# ================================================================================ from configuration
EdgeBuilder = Callable[[str, dict[str, Any], Callable[[str], str]], Any]
EDGE_KINDS: dict[str, tuple[set[str], EdgeBuilder]] = {}


def register_edge_kind(kind: str, settings: set[str], build: EdgeBuilder) -> None:
    """Add an edge kind configuration can use. ``build(name, settings, secret)`` returns an object with
    ``name`` and ``deliver(card) -> str``; ``secret(key)`` reads the allowlisted environment variable named by
    that setting. Packs installed as Python packages register kinds through the ``sentinel.edge_kinds``
    entry point group (the entry point loads to a ``(settings, build)`` pair)."""
    EDGE_KINDS[kind] = ({"kind", "timeout_s", *settings}, build)


def _builtin_kinds() -> None:
    from .channels import EmailEdge, SlackEdge, TeamsEdge

    def hook(cls: type) -> EdgeBuilder:
        return lambda n, c, secret: cls(n, c.get("url", ""), secret("secret_env"),
                                        timeout_s=float(c.get("timeout_s", 10)),
                                        answer_secret=secret("answer_secret_env") if c.get("answer_secret_env")
                                        else None)
    register_edge_kind("webhook", {"url", "secret_env", "answer_secret_env"}, hook(WebhookEdge))
    register_edge_kind("a2ui", {"url", "secret_env", "answer_secret_env", "a2ui_version"},
                       lambda n, c, secret: A2UIEdge(
                           n, c.get("url", ""), secret("secret_env"), timeout_s=float(c.get("timeout_s", 10)),
                           answer_secret=secret("answer_secret_env") if c.get("answer_secret_env") else None,
                           a2ui_version=str(c.get("a2ui_version", A2UI_DEFAULT_VERSION))))
    register_edge_kind("whatsapp", {"phone_number_id", "access_token_env", "app_secret_env", "verify_token_env",
                                    "base_url", "template"},
                       lambda n, c, secret: WhatsAppEdge(
                           n, str(c.get("phone_number_id") or ""), secret("access_token_env"),
                           secret("app_secret_env"), secret("verify_token_env"),
                           base_url=c.get("base_url", "https://graph.facebook.com/v21.0"), template=c.get("template"),
                           timeout_s=float(c.get("timeout_s", 10))))
    register_edge_kind("slack", {"bot_token_env", "signing_secret_env", "channel", "base_url"},
                       lambda n, c, secret: SlackEdge(n, secret("bot_token_env"), secret("signing_secret_env"),
                                                      channel=c.get("channel"),
                                                      base_url=c.get("base_url", "https://slack.com/api"),
                                                      timeout_s=float(c.get("timeout_s", 10))))
    register_edge_kind("teams", {"webhook_url_env", "console_url"},
                       lambda n, c, secret: TeamsEdge(n, secret("webhook_url_env"), console_url=c.get("console_url"),
                                                      timeout_s=float(c.get("timeout_s", 10))))
    register_edge_kind("email", {"host", "port", "starttls", "from_addr", "username_env", "password_env",
                                 "console_url"},
                       lambda n, c, secret: EmailEdge(
                           n, str(c.get("host") or ""), str(c.get("from_addr") or ""), port=int(c.get("port", 587)),
                           starttls=bool(c.get("starttls", True)),
                           username=secret("username_env") if c.get("username_env") else None,
                           password=secret("password_env") if c.get("password_env") else None,
                           console_url=c.get("console_url"), timeout_s=float(c.get("timeout_s", 20))))
    from .wa_providers import register as _wa_providers
    _wa_providers()
    try:
        from importlib.metadata import entry_points
        for ep in entry_points(group="sentinel.edge_kinds"):
            settings, build = ep.load()
            register_edge_kind(ep.name, set(settings), build)
    except Exception:  # noqa: BLE001,S110 - a broken plug-in must not stop the built-in kinds
        pass


def build_edges(spec: dict[str, Any], env: dict[str, str] | None = None) -> dict[str, Any]:
    """Edges from the connectors configuration::

        edges:
          ask_ai:   {kind: a2ui, url: "https://askai.example.in/sentinel/cards", secret_env: SENTINEL_EDGE_ASK_AI}
          whatsapp: {kind: whatsapp, phone_number_id: "1234567890", access_token_env: SENTINEL_SECRET_WA_TOKEN,
                     app_secret_env: SENTINEL_SECRET_WA_APP_SECRET, verify_token_env: SENTINEL_SECRET_WA_VERIFY_TOKEN,
                     template: {name: sentinel_review, language: en}}      # optional
          ops_hook: {kind: webhook, url: "https://...", secret_env: SENTINEL_SECRET_OPS_HOOK}
          slack / teams / email: see sentinel.channels; more kinds through register_edge_kind()
    """
    from .envsecrets import lookup
    if not EDGE_KINDS:
        _builtin_kinds()
    out: dict[str, Any] = {}
    for name, cfg in (spec or {}).items():
        cfg = dict(cfg or {})
        kind = cfg.get("kind")
        if kind not in EDGE_KINDS:
            raise ValueError(f"edge {name}: kind must be one of {sorted(EDGE_KINDS)}")
        allowed, build = EDGE_KINDS[kind]
        unknown = set(cfg) - allowed
        if unknown:
            raise ValueError(f"edge {name}: unknown settings {sorted(unknown)}")

        def secret(key: str, _name: str = name, _cfg: dict[str, Any] = cfg) -> str:
            from .envsecrets import require_allowed
            var = _cfg.get(key)
            if not var:
                raise ValueError(f"edge {_name}: {key} is required")
            require_allowed(var, f"edge {_name}")
            value = env.get(var) if env is not None else lookup(var)
            if not value:
                raise MissingKey(var)
            return value
        try:
            out[name] = build(name, cfg, secret)
        except MissingKey as e:              # configured, waiting for its key: cards go to the console meanwhile
            out[name] = PendingEdge(name, kind, e.name)
    return out


class MissingKey(ValueError):
    def __init__(self, name: str) -> None:
        super().__init__(f"{name} is not set")
        self.name = name


class PendingEdge:
    """An edge whose key has not been entered yet. Delivery fails (and is retried) with a clear reason."""

    def __init__(self, name: str, kind: str, missing: str) -> None:
        self.name, self.kind, self.missing = name, kind, missing

    def deliver(self, card: ReviewCard) -> str:
        raise EdgeError(f"{self.name}: waiting for key {self.missing} (enter it on the console's Keys page)")
