# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""Duplicates are recognised per tenant and source, and a compound cursor skips no rows that share a
timestamp across a page boundary (review finding H10)."""
from __future__ import annotations

import http.server
import json
import threading
import urllib.parse
import urllib.request

import pytest

from sentinel import Event
from sentinel.sources import Source, run_once


def test_same_key_from_two_systems_is_two_events(engine):
    a = Event(type="job.failed", source="billing", idempotency_key="42", payload={"system": "b", "error_code": "X"})
    b = Event(type="job.failed", source="payroll", idempotency_key="42", payload={"system": "p", "error_code": "X"})
    c = Event(type="job.failed", source="billing", idempotency_key="42", payload={"system": "b", "error_code": "X"})
    d = Event(type="job.failed", source="billing", tenant="other", idempotency_key="42",
              payload={"system": "b", "error_code": "X"})
    assert [engine.ingest(e).status for e in (a, b, c)] == ["new", "new", "duplicate"]
    assert engine.ingest(d).status != "duplicate"


ROWS = [("2026-10-01T10:00:00", 1), ("2026-10-01T10:00:00", 2), ("2026-10-01T10:00:00", 3),
        ("2026-10-01T11:00:00", 4)]


class Pages(http.server.BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        q = dict(urllib.parse.parse_qsl(urllib.parse.urlparse(self.path).query))
        after, tie = q.get("after", ""), int(q.get("tie") or 0)
        rows = [r for r in ROWS if (r[0], r[1]) > (after, tie)][:2]          # two per page
        body = json.dumps({"rows": [{"updated_at": t, "id": i} for t, i in rows]}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


@pytest.fixture
def pages():
    srv = http.server.HTTPServer(("127.0.0.1", 0), Pages)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


def test_compound_cursor_reads_every_row(pages):
    s = Source.model_validate({
        "name": "rows", "kind": "poll", "every_s": 60, "items": "body.rows",
        "url": pages + "/rows?after={{cursor}}&tie={{cursor_tie}}",
        "cursor": {"field": "item.updated_at", "tie": "item.id", "initial": "", "tie_initial": 0},
        "emit": [{"type": "row.changed", "key": "{{item.id}}", "payload": {"id": "{{item.id}}"}}]})
    op = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    state, seen = {}, []
    for _ in range(4):
        events, state = run_once(s, state, opener=op)
        seen += [e.payload["id"] for e in events]
    assert sorted(map(int, seen)) == [1, 2, 3, 4]             # row 3 shares row 2's time across the page edge
    assert state["cursor"] == "2026-10-01T11:00:00" and state["cursor_tie"] == 4
