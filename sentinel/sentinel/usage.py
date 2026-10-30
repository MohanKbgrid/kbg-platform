# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""Usage metering and the signed monthly usage export (an auditable monthly summary a site can keep or share).

One document per site and calendar month (UTC), per tenant:

  incidents            cases opened (after grouping: repeats of an open case are not counted again)
  events               events received
  resolved_automatic   resolved by a playbook or the model, executed (not shadow), not reversed and not failed
                       its outcome check; counted only once the reversal window after the month has passed
  resolved_by_people   decided by a person;    reviewers   distinct people who decided
  reversed             automatic resolutions later reversed
  domains              registry layers (domain packs) that handled cases
  model                calls, tokens and estimated cost;  messages   review cards sent, by edge

The document is canonical JSON with a SHA-256 digest, an HMAC-SHA256 signature made with the site's usage key
(``SENTINEL_SECRET_USAGE_KEY``, any long random value that you choose and keep) and the digest of the previous
month's export, so a gap or an edited month shows. ``verify`` checks a document with the same key.
"""
from __future__ import annotations
from .envsecrets import lookup as _lookup

import hashlib
import hmac
import json
import os
from datetime import datetime, timedelta, UTC
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .engine import Engine

KEY_ENV = "SENTINEL_SECRET_USAGE_KEY"
FORMAT = "sentinel-usage/1"


def month_bounds(month: str) -> tuple[datetime, datetime]:
    try:
        start = datetime.strptime(month, "%Y-%m").replace(tzinfo=UTC)
    except ValueError:
        raise ValueError("month looks like 2026-10") from None
    end = (start + timedelta(days=32)).replace(day=1)
    return start, end


def previous_month(now: datetime) -> str:
    first = now.astimezone(UTC).replace(day=1)
    return (first - timedelta(days=1)).strftime("%Y-%m")


def measure(engine: Engine, month: str, *, reversal_days: int = 7) -> dict[str, Any]:
    start, end = month_bounds(month)
    rows = engine.store.usage_rows(start.timestamp(), end.timestamp())
    layers = {p.id: (p.layer or engine.overlay.name) for p in engine.registry.all()}
    tenants: dict[str, dict[str, Any]] = {}

    def t(name: str | None) -> dict[str, Any]:
        return tenants.setdefault(name or "default", {
            "incidents": 0, "events": 0, "resolved_automatic": 0, "resolved_by_people": 0, "resolved_other": 0,
            "reversed": 0, "outcome_failed": 0, "shadow": 0, "reviewers": set(), "domains": set(),
            "by_pattern": {}, "model": {"calls": 0, "tokens_in": 0, "tokens_out": 0, "est_cost": 0.0}})

    for r in rows["incidents"]:
        x = t(r["tenant"])
        x["incidents"] += int(r["n"])
        x["domains"].add(layers.get(r["pattern_id"], "unmatched" if r["pattern_id"] == "__unmatched__" else "retired"))
        x["by_pattern"].setdefault(r["pattern_id"], {"incidents": 0, "automatic": 0})["incidents"] += int(r["n"])
    for r in rows["events"]:
        t(r["tenant"])["events"] += int(r["n"])
    for r in rows["dispositions"]:
        x = t(r["tenant"])
        if r["shadow"]:
            x["shadow"] += 1
        elif r["resolver"] in ("auto", "llm"):
            if r["reversed"]:
                x["reversed"] += 1
            elif r["outcome"] == "failed":
                x["outcome_failed"] += 1
            else:
                x["resolved_automatic"] += 1
                x["by_pattern"].setdefault(r["pattern_id"], {"incidents": 0, "automatic": 0})["automatic"] += 1
        elif r["resolver"] == "human":
            x["resolved_by_people"] += 1
            if r["actor"]:
                x["reviewers"].add(r["actor"])
        else:
            x["resolved_other"] += 1
    for r in rows["models"]:
        m = t(r["tenant"])["model"]
        m["calls"] += int(r["calls"])
        m["tokens_in"] += int(r["tokens_in"] or 0)
        m["tokens_out"] += int(r["tokens_out"] or 0)
        m["est_cost"] = round(m["est_cost"] + float(r["cost"] or 0), 6)
    for x in tenants.values():
        x["reviewers"] = len(x["reviewers"])
        x["domains"] = sorted(x["domains"])
    now = engine.clock()
    final = now >= end + timedelta(days=reversal_days)
    return {"format": FORMAT, "site": os.environ.get("SENTINEL_SITE_ID") or engine.overlay.name,
            "overlay": engine.overlay.name, "month": month, "period": [start.isoformat(), end.isoformat()],
            "generated_at": now.astimezone(UTC).isoformat(), "reversal_window_days": reversal_days,
            "final": final, "tenants": tenants, "messages": {r["edge"]: int(r["n"]) for r in rows["messages"]},
            "version": _version()}


def _version() -> str:
    try:
        from importlib.metadata import version
        return version("kbg-sentinel")
    except Exception:  # noqa: BLE001 - not installed as a package (tests, a checkout)
        return "dev"


def _canonical(doc: dict[str, Any]) -> bytes:
    body = {k: v for k, v in doc.items() if k not in ("digest", "signature")}
    return json.dumps(body, sort_keys=True, separators=(",", ":"), default=str).encode()


def export(engine: Engine, month: str, *, reversal_days: int = 7, key: str | None = None) -> dict[str, Any]:
    """Measure, chain to the previous export and sign. The export is recorded in the audit trail."""
    doc = measure(engine, month, reversal_days=reversal_days)
    chain = engine.store.get_source_state("usage:exports") or {}
    prev = sorted(m for m in chain if m < month)
    doc["previous"] = {"month": prev[-1], "digest": chain[prev[-1]]} if prev else None
    doc["digest"] = hashlib.sha256(_canonical(doc)).hexdigest()
    secret = key if key is not None else _lookup(KEY_ENV)
    doc["signature"] = (hmac.new(secret.encode(), _canonical(doc), hashlib.sha256).hexdigest() if secret else None)
    if doc["final"]:
        chain[month] = doc["digest"]
        engine.store.put_source_state("usage:exports", chain)
    engine.store.audit(None, "usage_exported", {"month": month, "final": doc["final"], "digest": doc["digest"],
                                                "signed": bool(secret)})
    return doc


def verify(doc: dict[str, Any], key: str) -> list[str]:
    """Problems with an export (empty: it is intact and was signed with this key)."""
    out = []
    if doc.get("format") != FORMAT:
        out.append(f"unknown format {doc.get('format')!r}")
    if hashlib.sha256(_canonical(doc)).hexdigest() != doc.get("digest"):
        out.append("the content does not match its digest: it was changed after export")
    sig = doc.get("signature")
    if not sig:
        out.append("not signed (the site had no usage key)")
    elif not hmac.compare_digest(hmac.new(key.encode(), _canonical(doc), hashlib.sha256).hexdigest(), sig):
        out.append("the signature does not match this key")
    if not doc.get("final"):
        out.append("not final: the reversal window had not passed when it was made")
    return out
