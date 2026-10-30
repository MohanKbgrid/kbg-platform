# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""More places to send review cards: Slack (two-way), Microsoft Teams and email (one-way, with a link).

    edges:
      slack:  {kind: slack, bot_token_env: SENTINEL_SECRET_SLACK_BOT, signing_secret_env: SENTINEL_SECRET_SLACK_SIGNING,
               channel: "C0123456"}            # optional: a channel instead of a direct message to the person
      teams:  {kind: teams, webhook_url_env: SENTINEL_SECRET_TEAMS_WEBHOOK, console_url: "https://sentinel.example"}
      email:  {kind: email, host: smtp.example.in, port: 587, from_addr: "sentinel@example.in",
               username_env: SENTINEL_SECRET_SMTP_USER, password_env: SENTINEL_SECRET_SMTP_PASSWORD,
               console_url: "https://sentinel.example"}

Slack: the card is a Block Kit message with Approve / Close buttons; button presses come back to
``/v1/slack/{edge}`` (signed with the app's signing secret) and are matched to a person by their Slack member
id (``contact.slack`` in the people configuration). Teams and email carry the case and a link to the review
in the console; answers are given there.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import smtplib
import time
import urllib.error
import urllib.request
from email.message import EmailMessage
from typing import Any

from .edges import EdgeError, ReviewCard, _close_codes
from .i18n import t


def _summary(card: ReviewCard) -> list[str]:
    lines = [card.reason]
    facts = ", ".join(f"{k}: {v}" for k, v in card.facts.items() if k not in ("event_type", "source"))
    if facts:
        lines.append(facts)
    if card.proposal_steps:
        lang = card.language
        conf = (f" ({t(lang, 'sure', n=round(card.proposal_confidence * 100))})"
                if card.proposal_confidence is not None else "")
        lines.append(t(lang, "suggested") + ": " + "; ".join(s.action for s in card.proposal_steps) + conf)
    return lines


def _link(card: ReviewCard, console_url: str | None) -> str | None:
    if card.link:
        return card.link
    return f"{console_url.rstrip('/')}/console#/case?id={card.incident_id}" if console_url else None


def _post_json(url: str, body: dict[str, Any], headers: dict[str, str], timeout_s: float, who: str) -> bytes:
    from . import egress
    req = urllib.request.Request(url, data=json.dumps(body).encode(), method="POST",  # noqa: S310 - egress
                                 headers={"Content-Type": "application/json; charset=utf-8", **headers})
    try:
        _, _, raw = egress.open_url(req, timeout_s)
        return raw or b""
    except egress.EgressError as e:
        raise EdgeError(f"{who}: {e}") from None
    except urllib.error.HTTPError as e:
        raise EdgeError(f"{who}: HTTP {e.code}") from None
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        raise EdgeError(f"{who}: {type(e).__name__}: {e}") from None


class SlackEdge:
    kind = "slack"

    def __init__(self, name: str, bot_token: str, signing_secret: str, *, channel: str | None = None,
                 base_url: str = "https://slack.com/api", timeout_s: float = 10.0) -> None:
        if not base_url.lower().startswith(("https://", "http://127.0.0.1", "http://localhost")):
            raise ValueError("slack base_url must be https")
        self.name, self.bot_token, self.signing_secret = name, bot_token, signing_secret
        self.channel, self.base_url, self.timeout_s = channel, base_url.rstrip("/"), timeout_s

    @staticmethod
    def value(review_id: str, decision: str, code: str | None = None) -> str:
        return ":".join(["sentinel", review_id, decision, *([code] if code else [])])

    def message(self, card: ReviewCard) -> dict[str, Any]:
        to = self.channel or card.recipient_contact.get("slack")
        if not to:
            raise EdgeError(f"{self.name}: {card.recipient_id or 'recipient'} has no Slack member id")
        buttons = []
        if card.proposal_steps and "approve" in card.answer_options:
            buttons.append({"type": "button", "style": "primary", "text": {"type": "plain_text",
                                                                          "text": t(card.language, "approve")},
                            "action_id": "sentinel_approve", "value": self.value(card.review_id, "approve")})
        for code in _close_codes(card, 2):
            label = t(card.language, "close_as", code=code.replace("_", " "))[:75]
            buttons.append({"type": "button", "text": {"type": "plain_text", "text": label},
                            "action_id": f"sentinel_close_{code}"[:255],
                            "value": self.value(card.review_id, "reject", code)})
        blocks: list[dict[str, Any]] = [
            {"type": "header", "text": {"type": "plain_text", "text": card.title[:150]}},
            {"type": "section", "text": {"type": "mrkdwn", "text": "\n".join(_summary(card))[:2900]}}]
        if card.link:
            blocks.append({"type": "context", "elements": [
                {"type": "mrkdwn", "text": f"<{card.link}|{t(card.language, 'open')}>"}]})
        if buttons:
            blocks.append({"type": "actions", "block_id": f"sentinel:{card.review_id}", "elements": buttons})
        return {"channel": to, "text": f"{card.title}: {card.reason}"[:300], "blocks": blocks}

    def deliver(self, card: ReviewCard) -> str:
        raw = _post_json(f"{self.base_url}/chat.postMessage", self.message(card),
                         {"Authorization": f"Bearer {self.bot_token}"}, self.timeout_s, self.name)
        try:
            out = json.loads(raw or b"{}")
        except ValueError:
            raise EdgeError(f"{self.name}: Slack sent no JSON") from None
        if not out.get("ok"):
            raise EdgeError(f"{self.name}: Slack refused the message ({out.get('error', 'unknown')})")
        return str(out.get("ts") or card.card_id)

    def send_text(self, contact: dict[str, str], subject: str, text: str) -> str:
        to = self.channel or contact.get("slack")
        if not to:
            raise EdgeError(f"{self.name}: no Slack member id")
        raw = _post_json(f"{self.base_url}/chat.postMessage", {"channel": to, "text": f"*{subject}*\n{text}"[:3900]},
                         {"Authorization": f"Bearer {self.bot_token}"}, self.timeout_s, self.name)
        out = json.loads(raw or b"{}")
        if not out.get("ok"):
            raise EdgeError(f"{self.name}: Slack refused the message ({out.get('error', 'unknown')})")
        return str(out.get("ts") or "")

    def check_signature(self, body: bytes, ts: str, signature: str, max_skew_s: int = 300) -> bool:
        try:
            if abs(time.time() - int(ts)) > max_skew_s:
                return False
        except (TypeError, ValueError):
            return False
        base = b"v0:" + str(ts).encode() + b":" + body
        expected = "v0=" + hmac.new(self.signing_secret.encode(), base, hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, signature or "")

    @staticmethod
    def answers(payload: dict[str, Any]) -> list[tuple[str, str, dict[str, Any]]]:
        """(Slack member id, review id, decision) for each button press in an interaction payload."""
        user = str((payload.get("user") or {}).get("id") or "")
        out = []
        for a in payload.get("actions") or []:
            parts = str(a.get("value") or "").split(":")
            if len(parts) < 3 or parts[0] != "sentinel" or parts[2] not in ("approve", "reject"):
                continue
            dec: dict[str, Any] = {"kind": parts[2]}
            if parts[2] == "reject":
                dec["disposition_code"] = parts[3] if len(parts) > 3 else None
                dec["note"] = "closed in Slack"
            out.append((user, parts[1], dec))
        return out


class TeamsEdge:
    """A Teams channel through a Workflows (or incoming) webhook: an Adaptive Card with a link to the review."""
    kind = "teams"

    def __init__(self, name: str, webhook_url: str, *, console_url: str | None = None, timeout_s: float = 10.0) -> None:
        if not webhook_url.lower().startswith(("https://", "http://127.0.0.1", "http://localhost")):
            raise ValueError("teams webhook URL must be https")
        self.name, self.webhook_url, self.console_url, self.timeout_s = name, webhook_url, console_url, timeout_s

    def message(self, card: ReviewCard) -> dict[str, Any]:
        body: list[dict[str, Any]] = [
            {"type": "TextBlock", "size": "Medium", "weight": "Bolder", "text": card.title[:200], "wrap": True},
            {"type": "TextBlock", "text": "\n\n".join(_summary(card))[:2000], "wrap": True},
            {"type": "FactSet", "facts": [{"title": "For", "value": card.recipient_name or card.assignee_role},
                                          {"title": "Due", "value": card.due_at.isoformat(timespec="minutes")}]}]
        link = _link(card, self.console_url)
        actions = [{"type": "Action.OpenUrl", "title": t(card.language, "open"), "url": link}] if link else []
        return {"type": "message", "attachments": [{"contentType": "application/vnd.microsoft.card.adaptive",
                                                    "content": {"type": "AdaptiveCard", "version": "1.4",
                                                                "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                                                                "body": body, "actions": actions}}]}

    def deliver(self, card: ReviewCard) -> str:
        _post_json(self.webhook_url, self.message(card), {}, self.timeout_s, self.name)
        return card.card_id

    def send_text(self, contact: dict[str, str], subject: str, text: str) -> str:
        card = {"type": "AdaptiveCard", "version": "1.4", "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                "body": [{"type": "TextBlock", "weight": "Bolder", "text": subject, "wrap": True},
                         {"type": "TextBlock", "text": text[:4000], "wrap": True}]}
        body = {"type": "message",
                "attachments": [{"contentType": "application/vnd.microsoft.card.adaptive", "content": card}]}
        _post_json(self.webhook_url, body, {}, self.timeout_s, self.name)
        return ""


class EmailEdge:
    """Review cards by email (SMTP with STARTTLS), to the person's ``contact.email``, with a link to decide."""
    kind = "email"

    def __init__(self, name: str, host: str, from_addr: str, *, port: int = 587, starttls: bool = True,
                 username: str | None = None, password: str | None = None, console_url: str | None = None,
                 timeout_s: float = 20.0, smtp_factory: Any = None) -> None:
        if not host or not from_addr:
            raise ValueError(f"email {name}: host and from_addr are required")
        self.name, self.host, self.port, self.from_addr = name, host, int(port), from_addr
        self.starttls, self.username, self.password = starttls, username, password
        self.console_url, self.timeout_s = console_url, timeout_s
        self.smtp_factory = smtp_factory or smtplib.SMTP

    def message(self, card: ReviewCard) -> EmailMessage:
        to = card.recipient_contact.get("email")
        if not to:
            raise EdgeError(f"{self.name}: {card.recipient_id or 'recipient'} has no email address")
        m = EmailMessage()
        m["From"], m["To"] = self.from_addr, to
        m["Subject"] = f"[Sentinel] {card.title}"[:200]
        link = _link(card, self.console_url)
        m.set_content("\n".join([*_summary(card), "", f"Due: {card.due_at.isoformat(timespec='minutes')}",
                                 *([f"Decide: {link}"] if link else [])]))
        return m

    def send_text(self, contact: dict[str, str], subject: str, text: str) -> str:
        to = contact.get("email")
        if not to:
            raise EdgeError(f"{self.name}: no email address")
        m = EmailMessage()
        m["From"], m["To"], m["Subject"] = self.from_addr, to, subject[:200]
        m.set_content(text)
        self._send(m)
        return ""

    def deliver(self, card: ReviewCard) -> str:
        self._send(self.message(card))
        return card.card_id

    def _send(self, msg: EmailMessage) -> None:
        from . import egress
        try:
            egress.check_host(self.host, self.port)
            with self.smtp_factory(self.host, self.port, timeout=self.timeout_s) as s:
                if self.starttls:
                    s.starttls()
                if self.username:
                    s.login(self.username, self.password or "")
                s.send_message(msg)
        except egress.EgressError as e:
            raise EdgeError(f"{self.name}: {e}") from None
        except (smtplib.SMTPException, OSError) as e:
            raise EdgeError(f"{self.name}: {type(e).__name__}: {e}") from None
