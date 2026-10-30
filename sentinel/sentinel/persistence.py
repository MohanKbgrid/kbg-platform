# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""How long a case stays alive and how often it asks for attention.

The usual protocol of incident tools (PagerDuty, Opsgenie, Alertmanager, ServiceNow), per exception:

* **Repeat limit** (``escalation: {repeat: N}``). An unanswered review climbs the role tree one level per
  SLA; at the top it is sent again at most N times, then it goes quiet: no more cards, it stays overdue on
  the console and goes on the daily overdue list to the people of its role.
* **Closing at the source** (``clear_when``). An event that says the problem is gone (``order.fulfilled``
  for the same order), or a read-only lookup asked every few minutes (the order's WMS status is now
  ``shipped``), closes the case as ``resolved_in_source``.
* **Expiry** (``expires_after_hours``). A case nobody has touched, and the source has not reported again,
  closes as ``expired``.
* **Pauses** (``pause_on``). A person stops the clock while waiting on someone outside (a customer, a
  vendor); the review comes back when the time is up or when the source reports again.
* **Silences**. Planned noise (a stock count tonight): matching cases are recorded and held, nothing runs
  on its own and nobody is sent a card until the silence ends.

Closing at the source and expiry are not decisions: they teach nothing, so earned trust does not move.
The registry's ``defaults:`` gives every exception that does not set its own a repeat limit, an expiry and
pause reasons, and sets when the daily overdue list is sent.
"""
from __future__ import annotations

from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Any

from .models import CaseDefaults, EscalationRule, Pattern, Silence

if TYPE_CHECKING:
    from .engine import Engine

SILENCES = "__silences__"
DIGEST = "__overdue_digest__"
MAX_PAUSE = timedelta(days=30)
MAX_SILENCE = timedelta(days=14)
KEEP_ENDED = 200                                   # ended silences kept for the record


def escalation(p: Pattern, d: CaseDefaults) -> EscalationRule | None:
    return p.escalation or d.escalation


def expires_after(p: Pattern, d: CaseDefaults) -> float | None:
    h = p.expires_after_hours if p.expires_after_hours is not None else d.expires_after_hours
    return h or None                               # 0 means never


def pause_reasons(p: Pattern, d: CaseDefaults) -> list[str]:
    return list(p.pause_on or d.pause_on)


def event_facts(engine: Engine, event: Any) -> dict[str, Any]:
    """Facts of a clearing event: its fingerprint rule's, over the payload's top-level values."""
    base = {k: v for k, v in (event.payload or {}).items() if isinstance(v, str | int | float | bool)}
    return {**base, **engine.fp.facts(event)}


class Silences:
    """Silences kept in the store (one small document), so every process sees the same ones."""

    def __init__(self, engine: Engine) -> None:
        self.engine = engine

    def _doc(self) -> dict[str, Any]:
        return self.engine.store.get_source_state(SILENCES) or {"items": []}

    def all(self) -> list[Silence]:
        return [Silence.model_validate(x) for x in self._doc().get("items", [])]

    def active(self, now: datetime | None = None) -> list[Silence]:
        now = now or self.engine.clock()
        return [s for s in self.all() if s.active(now)]

    def match(self, pattern_id: str, facts: dict[str, Any], now: datetime | None = None) -> Silence | None:
        hits = [s for s in self.active(now) if s.covers(pattern_id, facts)]
        return max(hits, key=lambda s: s.ends_at) if hits else None

    def add(self, *, pattern: str | None, facts: dict[str, Any], ends_at: datetime, reason: str, by: str,
            starts_at: datetime | None = None) -> Silence:
        now = self.engine.clock()
        starts_at = starts_at or now
        if not reason.strip():
            raise ValueError("say why (the reason is shown on every case it holds)")
        if ends_at <= starts_at:
            raise ValueError("a silence must end after it starts")
        if ends_at - starts_at > MAX_SILENCE:
            raise ValueError(f"a silence lasts at most {MAX_SILENCE.days} days")
        if pattern is None and not facts:
            raise ValueError("a silence needs an exception or at least one fact (location, channel...)")
        if pattern is not None:
            self.engine.registry.get(pattern)          # KeyError for an unknown exception
        s = Silence(pattern=pattern, facts=facts, starts_at=starts_at, ends_at=ends_at, reason=reason.strip(),
                    by=by, created_at=now)
        self._write(lambda items: [*items, s.model_dump(mode="json")])
        self.engine.store.audit(None, "silence_added", s.model_dump(mode="json"))
        return s

    def end(self, silence_id: str, by: str) -> Silence:
        now = self.engine.clock()
        found: list[Silence] = []

        def change(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
            out = []
            for x in items:
                s = Silence.model_validate(x)
                if s.id == silence_id and s.ended_at is None:
                    s.ended_at, s.ended_by = now, by
                    found.append(s)
                out.append(s.model_dump(mode="json"))
            return out
        self._write(change)
        if not found:
            raise KeyError(silence_id)
        self.engine.store.audit(None, "silence_ended", {"id": silence_id, "by": by})
        return found[0]

    def _write(self, change: Any) -> None:
        st = self.engine.store
        now = self.engine.clock()
        with st.transaction():
            st.lock("silences")
            items = change(list(self._doc().get("items", [])))
            live = [x for x in items if Silence.model_validate(x).active(now)
                    or Silence.model_validate(x).starts_at > now]
            done = [x for x in items if x not in live][-KEEP_ENDED:]
            st.put_source_state(SILENCES, {"items": [*done, *live]})


def digest_due(engine: Engine, now: datetime) -> str | None:
    """Today's date (site time) when the daily overdue list has not gone out yet and it is time."""
    from zoneinfo import ZoneInfo
    d = engine.case_defaults
    try:
        local = now.astimezone(ZoneInfo(d.timezone))
    except Exception:  # noqa: BLE001 - an unknown zone falls back to UTC
        local = now
    day = local.date().isoformat()
    if local.hour < d.digest_hour or (engine.store.get_source_state(DIGEST) or {}).get("day") == day:
        return None
    return day


def digest_lines(engine: Engine, reviews: list[Any]) -> dict[str | None, list[str]]:
    """The overdue list per person (None: no people configuration)."""
    out: dict[str | None, list[str]] = {}
    now = engine.clock()
    for r in reviews:
        inc = engine.store.get_incident(r.incident_id)
        if inc is None:
            continue
        p = engine.registry.get(inc.pattern_id)
        facts = ", ".join(f"{k}={v}" for k, v in inc.facts.items() if k not in ("event_type", "source"))
        days = max(0, (now - inc.created_at).days)
        link = f" {engine.card_link_base}/reviews/{r.id}" if engine.card_link_base else ""
        line = f"- {p.description or p.id}: {facts} (open {days}d, overdue since {r.due_at:%d %b %H:%M}){link}"
        people = (engine.directory.people_in(r.assignee_role, inc.facts) if engine.directory is not None
                  else [None])
        for person in people:
            out.setdefault(person.id if person is not None else None, []).append(line)
    return out


def send_digest(engine: Engine, day: str | None = None) -> dict[str, Any]:
    """Send each person the reviews that stopped being re-sent and are still open. Marked as sent for the day
    even when nobody could be reached, so it is tried once a day."""
    quiet = [r for r in engine.store.open_reviews() if r.quiet]
    lists = digest_lines(engine, quiet)
    sent, skipped = [], []
    subject = f"Sentinel: {len(quiet)} case(s) still open past their escalation"
    for pid, lines in lists.items():
        text = "\n".join(["These cases are past every escalation and are no longer sent as cards. Please decide "
                          "them on the console, or pause them if you are waiting on someone:", "", *lines])
        if pid is None or engine.directory is None:
            skipped.append({"person": pid, "reason": "no people configuration"})
            continue
        p = engine.directory.people.get(pid)
        names = list(p.edges) + [n for n in engine.overlay.edges if n not in p.edges] if p else []
        for name in names:
            fn = getattr(engine.overlay.edges.get(name), "send_text", None)
            if fn is None:
                continue
            try:
                fn(p.contact, subject, text)
                sent.append({"person": pid, "edge": name, "cases": len(lines)})
                break
            except Exception as e:  # noqa: BLE001 - try the next edge
                skipped.append({"person": pid, "edge": name, "reason": str(e)[:200]})
        else:
            if not any(s["person"] == pid for s in sent):
                skipped.append({"person": pid, "reason": "no email, Slack or Teams edge reached them"})
    if day:
        engine.store.put_source_state(DIGEST, {"day": day, "cases": len(quiet), "sent": len(sent)})
    engine.store.audit(None, "overdue_digest", {"cases": len(quiet), "sent": len(sent), "skipped": len(skipped)})
    engine.notify("overdue_digest", {"cases": [r.id for r in quiet], "sent": sent})
    return {"cases": len(quiet), "sent": sent, "skipped": skipped}
