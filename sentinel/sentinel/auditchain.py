# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""Tamper-evident audit trail.

Audit rows are written as they happen, without any global lock (so ingest and decisions scale). A sealer then
takes settled rows (older than ``SETTLE_S``) in order, gives each a chain number and a SHA-256 hash of its
content, and records the batch as a *seal*: the digest of the batch's row hashes, chained to the previous
seal's hash and, with ``SENTINEL_SECRET_AUDIT_KEY``, signed (HMAC-SHA256).

Legitimate changes leave a trace the verifier understands:
  retention   removes rows of archived cases and leaves a tombstone with each row's hash
  erasure     (DPDP) rewrites personal data in a row and records its original and new hash

``verify`` recomputes every sealed row's hash, every batch digest and the seal chain, and reports edited,
deleted or re-ordered rows, broken or forged seals, and how many rows wait to be sealed. ``export`` writes
seals, rows, tombstones and redactions as JSON lines that ``verify_export`` checks offline. With
``SENTINEL_AUDIT_WEBHOOK`` set, each new seal and its rows are posted (signed) to a SIEM or log store.
"""
from __future__ import annotations

import gzip
import hashlib
import hmac
import json
import os
import time
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from .envsecrets import lookup as _lookup
from .retention import _Q

SETTLE_S = 300.0          # a row is sealed only once it is this old: transactions in flight have committed
BATCH = 5000
KEY_ENV, WEBHOOK_ENV = "SENTINEL_SECRET_AUDIT_KEY", "SENTINEL_AUDIT_WEBHOOK"
GENESIS = "0" * 64


def _data(v: Any) -> Any:
    return json.loads(v) if isinstance(v, str) else v


def row_hash(row: dict[str, Any]) -> str:
    body = {"seq": int(row["seq"]), "ts": round(float(row["ts"]), 6), "incident_id": row.get("incident_id"),
            "kind": row["kind"], "data": _data(row["data"])}
    return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()


def _digest(hashes: Iterable[str]) -> str:
    h = hashlib.sha256()
    for x in hashes:
        h.update(x.encode())
    return h.hexdigest()


def _seal_hash(prev: str, seal_no: int, from_no: int, to_no: int, digest: str) -> str:
    return hashlib.sha256(f"{prev}|{seal_no}|{from_no}|{to_no}|{digest}".encode()).hexdigest()


def _sign(seal_hash: str, key: str | None) -> str | None:
    return hmac.new(key.encode(), seal_hash.encode(), hashlib.sha256).hexdigest() if key else None


def seal(store: Any, *, now: float | None = None, settle_s: float = SETTLE_S, key: str | None = None,
         limit: int = BATCH) -> dict[str, Any]:
    """Seal settled rows. Safe to run from several workers: the store's mutex makes one sealer at a time."""
    q = _Q(store)
    now = time.time() if now is None else now
    key = key if key is not None else _lookup(KEY_ENV)
    with store.mutex("audit:seal"), store.transaction():
        store.lock("audit:seal")
        last = q("SELECT seal_no, to_no, seal_hash FROM {s}.audit_seals ORDER BY seal_no DESC LIMIT 1")
        rows = q("SELECT seq, ts, incident_id, kind, data FROM {s}.audit WHERE chain_no IS NULL AND ts < ? "
                 "ORDER BY seq LIMIT ?", (now - settle_s, limit))
        if not rows:
            return {"sealed": 0}
        seal_no = (int(last[0]["seal_no"]) + 1) if last else 1
        start = (int(last[0]["to_no"]) + 1) if last else 1
        prev = last[0]["seal_hash"] if last else GENESIS
        hashes = []
        for i, r in enumerate(rows):
            h = row_hash(r)
            hashes.append(h)
            q("UPDATE {s}.audit SET chain_no = ?, row_hash = ? WHERE seq = ?", (start + i, h, r["seq"]))
        end = start + len(rows) - 1
        digest = _digest(hashes)
        sh = _seal_hash(prev, seal_no, start, end, digest)
        q("INSERT INTO {s}.audit_seals(seal_no, from_no, to_no, batch_digest, prev_hash, seal_hash, signature, "
          "created_ts) VALUES (?,?,?,?,?,?,?,?)", (seal_no, start, end, digest, prev, sh, _sign(sh, key), now))
    out = {"sealed": len(rows), "seal_no": seal_no, "from": start, "to": end}
    forward(store, key=key)
    return out


def tombstone(store: Any, where: str, args: list[Any], reason: str, now: float | None = None) -> None:
    """Record the hashes of sealed audit rows about to be deleted (call inside the deleting transaction)."""
    q = _Q(store)
    # ``where`` is retention's own fixed filter (column IN (?, ...)); every value is a parameter
    q("INSERT INTO {s}.audit_tombstones(chain_no, row_hash, removed_ts, reason) SELECT chain_no, row_hash, ?, ? "  # noqa: S608
      f"FROM {{s}}.audit WHERE ({where}) AND chain_no IS NOT NULL", [time.time() if now is None else now, reason,
                                                                      *args])


def redact(store: Any, seq: int, data: dict[str, Any]) -> None:
    """Rewrite one audit row's data (erasure) and keep its sealed hash verifiable."""
    q = _Q(store)
    with store.transaction():
        rows = q("SELECT seq, ts, incident_id, kind, data, chain_no, row_hash FROM {s}.audit WHERE seq = ?", (seq,))
        if not rows:
            return
        r = rows[0]
        store.update_audit_data(seq, data)
        if r["chain_no"] is None:
            return
        new = row_hash({**r, "data": data})
        known = q("SELECT original_hash FROM {s}.audit_redactions WHERE chain_no = ?", (r["chain_no"],))
        original = known[0]["original_hash"] if known else r["row_hash"]
        q("DELETE FROM {s}.audit_redactions WHERE chain_no = ?", (r["chain_no"],))
        q("INSERT INTO {s}.audit_redactions(chain_no, original_hash, redacted_hash, redacted_ts) VALUES (?,?,?,?)",
          (r["chain_no"], original, new, time.time()))


# ---- verification -----------------------------------------------------------------------------------------
def check(seals: list[dict[str, Any]], rows: dict[int, dict[str, Any]], tombstones: dict[int, str],
          redactions: dict[int, tuple[str, str]], key: str | None, *,
          anchor: dict[str, Any] | None = None) -> list[str]:
    """Problems in a run of seals and the rows they cover. ``anchor`` is the seal just before the run (None:
    the run starts at the beginning of the chain)."""
    problems: list[str] = []
    if anchor is None:
        prev, expect_no, expect_from = GENESIS, 1, 1
    else:
        prev, expect_no, expect_from = anchor["seal_hash"], int(anchor["seal_no"]) + 1, int(anchor["to_no"]) + 1
    for s in sorted(seals, key=lambda x: int(x["seal_no"])):
        n, a, b = int(s["seal_no"]), int(s["from_no"]), int(s["to_no"])
        if n != expect_no:
            problems.append(f"seal {expect_no} is missing (next is {n})")
        if a != expect_from:
            problems.append(f"seal {n} starts at row {a}, expected {expect_from}")
        if s["prev_hash"] != prev:
            problems.append(f"seal {n} does not follow seal {n - 1}")
        if _seal_hash(s["prev_hash"], n, a, b, s["batch_digest"]) != s["seal_hash"]:
            problems.append(f"seal {n} was altered")
        if key and not hmac.compare_digest(_sign(s["seal_hash"], key) or "", s.get("signature") or ""):
            problems.append(f"seal {n}: signature does not match the audit key")
        hashes, bad = [], []
        for c in range(a, b + 1):
            r = rows.get(c)
            if r is None:
                t = tombstones.get(c)
                if t is None:
                    bad.append(f"row {c} was deleted")
                hashes.append(t or "")
                continue
            h = row_hash(r)
            red = redactions.get(c)
            if red and h == red[1]:
                h = red[0]                        # erased personal data: the original hash still counts
            if h != r.get("row_hash"):
                bad.append(f"row {c} ({r['kind']}) was edited" + (" after erasure" if red else ""))
            hashes.append(h)
        if _digest(hashes) != s["batch_digest"]:
            problems += bad or [f"seal {n}: rows changed"]
        prev, expect_no, expect_from = s["seal_hash"], n + 1, b + 1
    return problems


def verify(store: Any, *, key: str | None = None, group: int = 50) -> dict[str, Any]:
    q = _Q(store)
    key = key if key is not None else _lookup(KEY_ENV)
    seals = q("SELECT * FROM {s}.audit_seals ORDER BY seal_no")
    tomb = {int(r["chain_no"]): r["row_hash"] for r in q("SELECT chain_no, row_hash FROM {s}.audit_tombstones")}
    red = {int(r["chain_no"]): (r["original_hash"], r["redacted_hash"])
           for r in q("SELECT chain_no, original_hash, redacted_hash FROM {s}.audit_redactions")}
    problems: list[str] = []
    rows_checked = 0
    for i in range(0, len(seals), group):                 # a few seals at a time: bounded memory
        part = seals[i:i + group]
        rows = {int(r["chain_no"]): r for r in q(
            "SELECT seq, ts, incident_id, kind, data, chain_no, row_hash FROM {s}.audit WHERE chain_no BETWEEN ? AND ?",
            (int(part[0]["from_no"]), int(part[-1]["to_no"])))}
        rows_checked += len(rows)
        problems += check(part, rows, tomb, red, key, anchor=seals[i - 1] if i else None)
    unsealed = q("SELECT COUNT(*) AS n FROM {s}.audit WHERE chain_no IS NULL")[0]["n"]
    problems += _tail_check(q, seals)
    return {"ok": not problems, "seals": len(seals), "rows_checked": rows_checked, "removed": len(tomb),
            "redacted": len(red), "unsealed": int(unsealed), "signed": bool(key), "problems": problems[:200]}


def _tail_check(q: Any, seals: list[dict[str, Any]]) -> list[str]:
    """Rows cut from the end of the trail. A seal proves what it covers, but nothing inside the chain says how
    far the chain had got, so removing the newest seal together with its rows would pass the checks above.
    The table's own sequence counter does remember: every row ever written took a number from it, so if the
    newest row present is older than the counter, rows after it were removed. (On Postgres a write rolled
    back a moment ago also leaves the counter ahead; it clears as soon as the next row is written.)"""
    if q.pg:
        rows = q("SELECT pg_sequence_last_value(pg_get_serial_sequence('{s}.audit', 'seq')) AS c")
    else:
        rows = q("SELECT seq AS c FROM sqlite_sequence WHERE name = 'audit'")
    counter = int(rows[0]["c"]) if rows and rows[0]["c"] is not None else 0
    newest = q("SELECT max(seq) AS m FROM {s}.audit")[0]["m"]
    newest = int(newest) if newest is not None else 0
    out = []
    if counter > newest:
        out.append(f"rows after audit seq {newest} are missing: the audit counter reached {counter}"
                   + (f" (newest seal is {seals[-1]['seal_no']})" if seals else ""))
    top = q("SELECT max(chain_no) AS m FROM {s}.audit")[0]["m"]
    if seals and top is not None and int(top) > int(seals[-1]["to_no"]):
        out.append(f"rows up to chain number {top} were sealed but their seal is missing")
    return out


def export(store: Any, path: str, *, since_seal: int = 0) -> dict[str, Any]:
    """Seals after ``since_seal`` (with that seal as the anchor), their rows, tombstones and redactions."""
    q = _Q(store)
    seals = q("SELECT * FROM {s}.audit_seals WHERE seal_no > ? ORDER BY seal_no", (since_seal,))
    anchor = q("SELECT * FROM {s}.audit_seals WHERE seal_no = ?", (since_seal,)) if since_seal else []
    n = 0
    with gzip.open(path, "wt", encoding="utf-8") as f:
        f.write(json.dumps({"format": "sentinel-audit/1", "anchor": anchor[0] if anchor else None},
                           default=str) + "\n")
        for s in seals:
            f.write(json.dumps({"seal": s}, default=str) + "\n")
        if seals:
            a, b = int(seals[0]["from_no"]), int(seals[-1]["to_no"])
            for r in q("SELECT seq, ts, incident_id, kind, data, chain_no, row_hash FROM {s}.audit "
                       "WHERE chain_no BETWEEN ? AND ? ORDER BY chain_no", (a, b)):
                f.write(json.dumps({"row": {**r, "data": _data(r["data"])}}, default=str) + "\n")
                n += 1
            for r in q("SELECT * FROM {s}.audit_tombstones WHERE chain_no BETWEEN ? AND ?", (a, b)):
                f.write(json.dumps({"tombstone": r}, default=str) + "\n")
            for r in q("SELECT * FROM {s}.audit_redactions WHERE chain_no BETWEEN ? AND ?", (a, b)):
                f.write(json.dumps({"redaction": r}, default=str) + "\n")
    return {"path": path, "seals": len(seals), "rows": n}


def verify_export(path: str, key: str | None = None) -> list[str]:
    """Check an export file offline (no database needed)."""
    seals, rows, tomb, red = [], {}, {}, {}
    with gzip.open(Path(path), "rt", encoding="utf-8") as f:
        head = json.loads(f.readline())
        if head.get("format") != "sentinel-audit/1":
            return ["not a Sentinel audit export"]
        for line in f:
            x = json.loads(line)
            if "seal" in x:
                seals.append(x["seal"])
            elif "row" in x:
                rows[int(x["row"]["chain_no"])] = x["row"]
            elif "tombstone" in x:
                tomb[int(x["tombstone"]["chain_no"])] = x["tombstone"]["row_hash"]
            elif "redaction" in x:
                r = x["redaction"]
                red[int(r["chain_no"])] = (r["original_hash"], r["redacted_hash"])
    return check(seals, rows, tomb, red, key, anchor=head.get("anchor"))


# ---- forwarding to a SIEM ---------------------------------------------------------------------------------
def forward(store: Any, *, key: str | None = None, opener: Any = None) -> int:
    """Post new seals and their rows to ``SENTINEL_AUDIT_WEBHOOK`` (signed); remembers what was sent."""
    url = os.environ.get(WEBHOOK_ENV)
    if not url:
        return 0
    import urllib.request

    from . import egress
    from .edges import sign
    q = _Q(store)
    state = store.get_source_state("audit:forwarded") or {}
    done = int(state.get("seal_no", 0))
    sent = 0
    for s in q("SELECT * FROM {s}.audit_seals WHERE seal_no > ? ORDER BY seal_no LIMIT 20", (done,)):
        rows = q("SELECT seq, ts, incident_id, kind, data, chain_no, row_hash FROM {s}.audit "
                 "WHERE chain_no BETWEEN ? AND ? ORDER BY chain_no", (s["from_no"], s["to_no"]))
        body = json.dumps({"seal": s, "rows": [{**r, "data": _data(r["data"])} for r in rows]}, default=str).encode()
        headers = {"Content-Type": "application/json"}
        if key:
            ts, sig = sign(key, body)
            headers.update({"X-Sentinel-Timestamp": ts, "X-Sentinel-Signature": sig})
        req = urllib.request.Request(url, data=body, method="POST", headers=headers)  # noqa: S310 - egress
        try:
            egress.open_url(req, 20.0, base_opener=opener)
        except Exception:  # noqa: BLE001 - tried again after the next seal
            break
        done = int(s["seal_no"])
        sent += 1
        store.put_source_state("audit:forwarded", {"seal_no": done})
    return sent
