# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""H14 / AU: tamper-evident audit chain, tombstones for retention, redactions for erasure, export, SIEM."""
from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from sentinel import Decision, DecisionKind
from sentinel.auditchain import export, forward, seal, verify, verify_export
from sentinel.retention import _Q
from tests.conftest import job_event


_N = [0]


def _fill(eng, n=3):
    for _ in range(n):
        _N[0] += 1
        i = _N[0]
        r = eng.ingest(job_event(error="AUTH", ref=f"A{i}", system=f"s{i}", key=f"a{i}"))
        eng.decide(eng.store.open_review_for(r.incident_id).id,
                   Decision(kind=DecisionKind.REJECT, actor="op", disposition_code="no_action"))


def test_seal_and_verify_detects_edits_deletions_and_forged_seals(engine_factory):
    eng = engine_factory()
    _fill(eng)
    assert seal(eng.store, settle_s=0, key="k")["sealed"] > 0
    _fill(eng, 2)
    seal(eng.store, settle_s=0, key="k")
    ok = verify(eng.store, key="k")
    assert ok["ok"] and ok["seals"] == 2 and ok["unsealed"] == 0
    q = _Q(eng.store)
    row = q("SELECT seq, data FROM {s}.audit WHERE kind = 'decision' ORDER BY seq LIMIT 1")[0]
    data = json.loads(row["data"]) if isinstance(row["data"], str) else row["data"]
    eng.store.update_audit_data(row["seq"], {**data, "code": "resolved"})           # someone rewrites history
    bad = verify(eng.store, key="k")
    assert not bad["ok"] and any("was edited" in p for p in bad["problems"])
    eng.store.update_audit_data(row["seq"], data)
    assert verify(eng.store, key="k")["ok"]
    q("DELETE FROM {s}.audit WHERE seq = ?", (row["seq"],))
    assert any("was deleted" in p for p in verify(eng.store, key="k")["problems"])
    assert any("signature" in p for p in verify(eng.store, key="other")["problems"])


def test_retention_and_erasure_keep_the_chain_valid(engine_factory, clock, tmp_path, overlay):
    overlay.pii_keys = ["phone"]
    eng = engine_factory(ov=overlay)
    r = eng.ingest(job_event(error="AUTH", ref="E1", key="e1", phone="98400-11111"))
    eng.decide(eng.store.open_review_for(r.incident_id).id,
               Decision(kind=DecisionKind.REJECT, actor="op", disposition_code="no_action", note="rang 98400-11111"))
    _fill(eng)
    seal(eng.store, settle_s=0)
    from sentinel.privacy import erase
    erase(eng, "98400-11111", "op")
    v = verify(eng.store)
    assert v["ok"] and v["redacted"] >= 1
    clock.advance(days=400)
    from sentinel import retention
    retention.run(eng.store, clock(), 365, archive_dir=str(tmp_path), apply=True)
    v = verify(eng.store)
    assert v["ok"] and v["removed"] > 0


def test_export_verifies_offline_and_concurrent_sealers_do_not_fork(engine_factory, tmp_path):
    eng = engine_factory()
    _fill(eng)
    seal(eng.store, settle_s=0, key="k")
    _fill(eng, 2)
    seal(eng.store, settle_s=0, key="k")
    full = tmp_path / "a.jsonl.gz"
    export(eng.store, str(full))
    assert verify_export(str(full), "k") == []
    part = tmp_path / "b.jsonl.gz"
    export(eng.store, str(part), since_seal=1)
    assert verify_export(str(part), "k") == []
    import gzip
    lines = gzip.open(full, "rt").read().splitlines()
    tampered = [json.dumps({"row": {**json.loads(x)["row"], "kind": "forged"}}) if '"row"' in x and i == 3 else x
                for i, x in enumerate(lines)]
    bad = tmp_path / "c.jsonl.gz"
    with gzip.open(bad, "wt") as f:
        f.write("\n".join(tampered) + "\n")
    assert verify_export(str(bad), "k")
    _fill(eng, 3)
    results = []
    threads = [threading.Thread(target=lambda: results.append(seal(eng.store, settle_s=0))) for _ in range(4)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert verify(eng.store)["ok"]


def test_forward_to_a_siem(engine_factory, monkeypatch):
    got = []

    class H(BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802
            got.append((dict(self.headers), json.loads(self.rfile.read(int(self.headers["Content-Length"])))))
            self.send_response(200)
            self.end_headers()

        def log_message(self, *a):
            pass
    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    monkeypatch.setenv("SENTINEL_AUDIT_WEBHOOK", f"http://127.0.0.1:{srv.server_address[1]}/hec")
    eng = engine_factory()
    _fill(eng, 2)
    seal(eng.store, settle_s=0, key="k")
    assert got and got[0][1]["seal"]["seal_no"] == 1 and got[0][1]["rows"]
    assert got[0][0].get("X-Sentinel-Signature")
    assert forward(eng.store, key="k") == 0                                          # already sent
    srv.shutdown()
