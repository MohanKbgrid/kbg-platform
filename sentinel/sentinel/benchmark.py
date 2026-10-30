# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""Anonymised benchmarks: how a site's exceptions compare with other sites running the same ones.

Only exceptions that come from a shared template or pack are compared (their layer is ``template:<name>`` or
``pack:<id>``), because only those mean the same thing everywhere. A site's monthly **snapshot** holds, per
shared exception, counts and rates only: cases, the share handled automatically, the share reversed, the
share closed within the exception's SLA, and the median minutes to close. No facts, ids, names, payloads or
the site's own exceptions leave the site, and the site is identified only by a random id kept in its database.

KBGrid **builds** the benchmark from many snapshots: for each exception and measure, the 25th, 50th and 75th
percentiles across sites, published only when at least ``k`` sites (default 5) contributed, so no site's
figures can be read back. A site then **compares** its own month with the benchmark (the Value page shows it
when ``SENTINEL_BENCHMARK`` points at the file).

    sentinel benchmark snapshot --month 2026-09 --out snap.json      # on each site (opt-in)
    sentinel benchmark build snaps/ --out benchmark.json --k 5       # KBGrid
    sentinel benchmark compare benchmark.json --month 2026-09        # on a site
"""
from __future__ import annotations

import json
import statistics
import uuid
from datetime import timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .engine import Engine

FORMAT = "sentinel-benchmark-snapshot/1"
BENCH = "sentinel-benchmark/1"
SITE_KEY = "__benchmark_site__"
MEASURES = ("automatic", "reversed", "within_sla", "minutes_to_close")
MIN_CASES = 20                    # a site's figure for an exception counts only with enough cases behind it


def shared_key(pattern: Any) -> str | None:
    layer = getattr(pattern, "layer", None) or ""
    return f"{layer}/{pattern.id}" if layer.startswith(("template:", "pack:")) else None


def _site_id(engine: Engine) -> str:
    st = engine.store.get_source_state(SITE_KEY)
    if not st:
        st = {"id": uuid.uuid4().hex}
        engine.store.put_source_state(SITE_KEY, st)
    return st["id"]


def snapshot(engine: Engine, month: str, *, industry: str = "", limit: int = 100_000,
             audit: bool = True) -> dict[str, Any]:
    from .usage import month_bounds
    start, end = month_bounds(month)
    keys = {p.id: (shared_key(p), p) for p in engine.registry.all()}
    acc: dict[str, dict[str, Any]] = {}
    cursor = None
    seen = 0
    while seen < limit:
        page = engine.store.search_incidents(since_ts=start.timestamp(), until_ts=end.timestamp(), before=cursor,
                                             limit=500)
        if not page:
            break
        for inc in page:
            key, pattern = keys.get(inc.pattern_id, (None, None))
            if key is None:
                continue
            a = acc.setdefault(key, {"cases": 0, "closed": 0, "automatic": 0, "reversed": 0, "within_sla": 0,
                                     "minutes": []})
            a["cases"] += 1
            d = engine.store.get_disposition(inc.id)
            if d is None or d.shadow:
                continue
            a["closed"] += 1
            mins = max(0.0, (d.created_at - inc.created_at).total_seconds() / 60)
            a["minutes"].append(mins)
            if d.resolver in ("auto", "llm"):
                a["automatic"] += 1
            if d.reversed:
                a["reversed"] += 1
            if pattern.sla_minutes and mins <= pattern.sla_minutes:
                a["within_sla"] += 1
        seen += len(page)
        cursor = (page[-1].created_at.timestamp(), page[-1].id)
        if len(page) < 500:
            break
    out = {}
    for key, a in sorted(acc.items()):
        if a["cases"] < MIN_CASES or not a["closed"]:
            continue
        out[key] = {"cases": a["cases"], "automatic": round(a["automatic"] / a["closed"], 4),
                    "reversed": round(a["reversed"] / max(1, a["automatic"]), 4),
                    "within_sla": round(a["within_sla"] / a["closed"], 4),
                    "minutes_to_close": round(statistics.median(a["minutes"]), 1)}
    doc = {"format": FORMAT, "site": _site_id(engine), "month": month, "industry": industry, "exceptions": out}
    if audit:
        engine.store.audit(None, "benchmark_snapshot", {"month": month, "exceptions": len(out)})
    return doc


def _pct(values: list[float], q: float) -> float:
    s = sorted(values)
    if len(s) == 1:
        return s[0]
    pos = q * (len(s) - 1)
    lo, hi = int(pos), min(int(pos) + 1, len(s) - 1)
    return round(s[lo] + (s[hi] - s[lo]) * (pos - lo), 4)


def build(snapshots: list[dict[str, Any]], *, k: int = 5) -> dict[str, Any]:
    """Percentiles per (industry, exception, measure), only where at least ``k`` distinct sites contributed."""
    if k < 3:
        raise ValueError("k must be at least 3")
    latest: dict[tuple[str, str], dict[str, Any]] = {}
    for s in snapshots:
        if s.get("format") != FORMAT:
            continue
        key = (s["site"], s.get("industry") or "")
        if key not in latest or s["month"] > latest[key]["month"]:
            latest[key] = s
    groups: dict[tuple[str, str], dict[str, list[float]]] = {}
    sites: dict[tuple[str, str], set[str]] = {}
    for (site, industry), s in latest.items():
        for exc, m in s["exceptions"].items():
            for ind in {industry, ""}:                     # each industry, and all sites together
                g = groups.setdefault((ind, exc), {x: [] for x in MEASURES})
                sites.setdefault((ind, exc), set()).add(site)
                for x in MEASURES:
                    g[x].append(float(m[x]))
    out: dict[str, dict[str, Any]] = {}
    for (ind, exc), g in sorted(groups.items()):
        n = len(sites[(ind, exc)])
        if n < k:
            continue
        out.setdefault(ind or "all", {})[exc] = {
            "sites": n, **{x: {"p25": _pct(v, 0.25), "p50": _pct(v, 0.5), "p75": _pct(v, 0.75)}
                           for x, v in g.items()}}
    months = sorted({s["month"] for s in latest.values()})
    return {"format": BENCH, "k": k, "months": [months[0], months[-1]] if months else [], "benchmarks": out}


HIGHER_IS_BETTER = {"automatic": True, "reversed": False, "within_sla": True, "minutes_to_close": False}


def compare(snap: dict[str, Any], bench: dict[str, Any], industry: str = "") -> list[dict[str, Any]]:
    table = bench["benchmarks"].get(industry or "all") or {}
    fallback = bench["benchmarks"].get("all") or {}
    rows = []
    for exc, mine in sorted(snap["exceptions"].items()):
        peers = table.get(exc) or fallback.get(exc)
        if not peers:
            continue
        for x in MEASURES:
            p = peers[x]
            v = mine[x]
            better = HIGHER_IS_BETTER[x]
            standing = ("top quarter" if (v >= p["p75"] if better else v <= p["p25"]) else
                        "bottom quarter" if (v <= p["p25"] if better else v >= p["p75"]) else "middle half")
            rows.append({"exception": exc, "measure": x, "yours": v, **p, "sites": peers["sites"],
                         "standing": standing})
    return rows


def load_dir(path: str | Path) -> list[dict[str, Any]]:
    out = []
    for f in sorted(Path(path).glob("*.json")):
        try:
            out.append(json.loads(f.read_text(encoding="utf-8")))
        except (OSError, ValueError):
            continue
    return out


def last_month(engine: Engine) -> str:
    first = engine.clock().replace(day=1)
    return (first - timedelta(days=1)).strftime("%Y-%m")
