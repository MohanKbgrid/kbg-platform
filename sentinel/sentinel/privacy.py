# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""Personal data under India's DPDP Act: find a person's data, hand it over, erase it, and stop keeping
personal fields longer than needed.

``find``      every case whose stored text mentions an identifier (phone, email, customer id, name)
``access``    what Sentinel holds about that person, as one JSON document (a data principal's request)
``erase``     replace the identifier, and the overlay's personal fields (``pii_keys``), with "[erased]" in
              the cases' events, facts, decisions, reviews and audit entries, and drop their similar-case
              vectors. Cases still being worked are left alone unless asked. The erasure itself is audited
              with a hash of the identifier, never the identifier.
``scrub``     retention by data class: for closed cases older than N days, personal fields are removed while
              the rest of the case (what happened and how it was decided) stays for learning and audit.

Not reached: archives written by retention, and backups. They age out on their own schedules; say so in the
reply to the person, and keep those schedules short (OPERATIONS.md).
"""
from __future__ import annotations

import hashlib
import re
from datetime import timedelta
from typing import TYPE_CHECKING, Any

from .models import Event, Incident, IncidentState

if TYPE_CHECKING:
    from .engine import Engine

ERASED, REMOVED = "[erased]", "[removed]"
MIN_LEN = 4


def _check(identifier: str) -> str:
    v = (identifier or "").strip()
    if len(v) < MIN_LEN:
        raise ValueError(f"an identifier needs at least {MIN_LEN} characters (a phone, email or customer id)")
    return v


def ident_hash(identifier: str) -> str:
    return hashlib.sha256(identifier.strip().lower().encode()).hexdigest()[:16]


def find(engine: Engine, identifier: str, *, limit: int = 2000) -> list[Incident]:
    v = _check(identifier)
    out: list[Incident] = []
    cursor = None
    while len(out) < limit:
        page = engine.store.search_incidents(text=v, before=cursor, limit=200)
        if not page:
            break
        out += page
        cursor = (page[-1].created_at.timestamp(), page[-1].id)
        if len(page) < 200:
            break
    return out[:limit]


def access(engine: Engine, identifier: str, actor: str) -> dict[str, Any]:
    v = _check(identifier)
    cases = []
    for inc in find(engine, v):
        events = [e.payload for eid in (engine.store.event_ids(inc.id) or inc.event_ids)[:100]
                  if (e := engine.store.get_event(eid)) is not None]
        d = engine.store.get_disposition(inc.id)
        cases.append({"case": inc.id, "kind": inc.pattern_id, "opened": inc.created_at.isoformat(),
                      "state": inc.state.value, "facts": inc.facts, "events": events,
                      "outcome": {"code": d.code, "decided_by": d.resolver, "note": d.note,
                                  "when": d.created_at.isoformat()} if d else None})
    engine.store.audit(None, "privacy_access", {"identifier_sha256": ident_hash(v), "cases": len(cases),
                                                "actor": actor})
    return {"identifier_sha256": ident_hash(v), "generated_at": engine.clock().isoformat(),
            "controller_note": "Personal data held by Sentinel in operational cases. Archives and backups age out "
                               "on their own schedule.", "cases": cases}


def _redactor(identifier: str | None, keys: set[str], mark: str) -> Any:
    rx = re.compile(re.escape(identifier), re.I) if identifier else None

    def walk(v: Any, key: str | None = None) -> Any:
        if key is not None and key.lower() in keys and v not in (None, "", [], {}):
            return mark
        if isinstance(v, dict):
            return {k: walk(x, str(k)) for k, x in v.items()}
        if isinstance(v, list):
            return [walk(x) for x in v]
        if isinstance(v, str) and rx is not None:
            return rx.sub(mark, v)
        return v
    return walk


def _rewrite(engine: Engine, inc: Incident, walk: Any) -> int:
    """Apply ``walk`` to everything stored about one case. Returns how many records changed."""
    store, n = engine.store, 0
    for eid in store.event_ids(inc.id) or inc.event_ids:
        ev = store.get_event(eid)
        if ev is None:
            continue
        new = walk(ev.payload)
        if new != ev.payload:
            store.update_event(Event.model_validate({**ev.model_dump(), "payload": new}))
            n += 1
    first, facts = walk(inc.first_event), walk(inc.facts)
    fp = walk(inc.fingerprint)
    if (first, facts, fp) != (inc.first_event, inc.facts, inc.fingerprint):
        inc.first_event, inc.facts, inc.fingerprint = first, facts, fp
        if inc.proposal is not None:
            inc.proposal = type(inc.proposal).model_validate(walk(inc.proposal.model_dump()))
        store.put_incident(inc)
        n += 1
    d = store.get_disposition(inc.id)
    if d is not None:
        nd = walk(d.model_dump(mode="json"))
        if nd != d.model_dump(mode="json"):
            store.put_disposition(type(d).model_validate(nd))
            n += 1
    for rv in store.reviews_for_incident(inc.id):
        nr = walk(rv.model_dump(mode="json"))
        if nr != rv.model_dump(mode="json"):
            store.put_review(type(rv).model_validate(nr))
            n += 1
    from .auditchain import redact
    for a in store.audit_log(inc.id):
        na = walk(a["data"])
        if na != a["data"]:
            redact(store, a["seq"], na)             # keeps the sealed audit chain verifiable
            n += 1
    return n


def erase(engine: Engine, identifier: str, actor: str, reason: str = "", *,
          include_open: bool = False) -> dict[str, Any]:
    v = _check(identifier)
    keys = {k.lower() for k in getattr(engine.overlay, "pii_keys", []) or []}
    walk = _redactor(v, keys, ERASED)
    done, skipped, changed = [], [], 0
    for inc in find(engine, v):
        if inc.state is not IncidentState.DISPOSITIONED and not include_open:
            skipped.append(inc.id)
            continue
        with engine._guard(inc.id):
            fresh = engine.store.get_incident(inc.id) or inc
            changed += _rewrite(engine, fresh, walk)
            engine.store.delete_case_vector(inc.id)
        done.append(inc.id)
    engine.store.audit(None, "privacy_erasure", {"identifier_sha256": ident_hash(v), "cases": len(done),
                                                 "records": changed, "skipped_open": skipped, "actor": actor,
                                                 "reason": reason[:500]})
    return {"identifier_sha256": ident_hash(v), "erased_cases": done, "records_changed": changed,
            "skipped_open": skipped,
            "note": "Cases still being worked were left alone; erase again once they close, or pass include_open."
            if skipped else ""}


def scrub(engine: Engine, older_than_days: float, *, apply: bool = False, batch: int = 500) -> dict[str, Any]:
    """Remove the overlay's personal fields from closed cases older than ``older_than_days``. Resumes where
    the last run stopped (a watermark), so a daily run only reads new ground."""
    keys = {k.lower() for k in getattr(engine.overlay, "pii_keys", []) or []}
    if not keys:
        return {"scrubbed": 0, "note": "the overlay declares no pii_keys: nothing to remove by data class"}
    cutoff = (engine.clock() - timedelta(days=older_than_days)).timestamp()
    mark = engine.store.get_source_state("privacy:scrub") or {}
    since = float(mark.get("until", 0.0))
    walk = _redactor(None, keys, REMOVED)
    seen = scrubbed = changed = 0
    oldest_open: float | None = None
    cursor = None
    while True:
        page = engine.store.search_incidents(since_ts=since, until_ts=cutoff, before=cursor, limit=batch)
        if not page:
            break
        cursor = (page[-1].created_at.timestamp(), page[-1].id)
        for inc in page:
            if inc.state is not IncidentState.DISPOSITIONED:     # still being worked: come back to it later
                ts = inc.created_at.timestamp()
                oldest_open = ts if oldest_open is None else min(oldest_open, ts)
                continue
            seen += 1
            if apply:
                n = _rewrite(engine, inc, walk)
                scrubbed += bool(n)
                changed += n
        if len(page) < batch:
            break
    if apply:
        until = cutoff if oldest_open is None else oldest_open
        engine.store.put_source_state("privacy:scrub", {"until": until})
        engine.store.audit(None, "privacy_scrub", {"older_than_days": older_than_days, "cases": scrubbed,
                                                   "records": changed, "keys": sorted(keys)})
    return {"checked": seen, "scrubbed": scrubbed, "records_changed": changed, "applied": apply,
            "keys": sorted(keys)}
