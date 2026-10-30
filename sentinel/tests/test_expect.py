# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""D6: expect sources - 'did not happen by' exceptions (indent not in by 05:30, settlement not filed by 21:00)."""
from __future__ import annotations

import http.server
import json
import threading
from datetime import UTC, datetime

import pytest
import yaml

from sentinel.sources import expect_due, parse_sources


@pytest.fixture
def indents():
    state = {"rows": [{"route": "R1"}, {"route": "R2"}]}

    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            data = json.dumps({"indents": state["rows"]}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *a):
            pass
    srv = http.server.HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}", state
    srv.shutdown()


def spec(base, **over):
    s = {"kind": "expect", "at": "05:30", "tz": "Asia/Kolkata", "match_on": "{{item.route}}",
         "expected": [{"route": "R1"}, {"route": "R2"}, {"route": "R3"}],
         "present": {"url": f"{base}/indents?date=today", "items": "body.indents"},
         "emit": [{"type": "indent.missing", "key": "{{item.route}}:{{item.date}}",
                   "payload": {"route": "{{item.route}}", "date": "{{item.date}}", "deadline": "{{item.deadline}}"}}]}
    s.update(over)
    return {"indents": s}


def test_due_time_and_days():
    s = parse_sources(spec("http://x", days=["mon", "tue"]))["indents"]
    sat_morning = datetime(2026, 10, 10, 0, 30, tzinfo=UTC)               # 06:00 IST on a Saturday
    assert expect_due(s, sat_morning)[0] is False                          # not a working day
    s2 = parse_sources(spec("http://x"))["indents"]
    assert expect_due(s2, datetime(2026, 10, 10, 0, 0, tzinfo=UTC))[0] is True    # 05:30 IST exactly
    assert expect_due(s2, datetime(2026, 10, 9, 23, 59, tzinfo=UTC))[0] is False  # 05:29 IST
    off = parse_sources(spec("http://x", tz="+05:30"))["indents"]
    assert expect_due(off, datetime(2026, 10, 10, 0, 0, tzinfo=UTC))[1] == "2026-10-10"
    with pytest.raises(Exception, match="HH:MM"):
        parse_sources(spec("http://x", at="5.30"))
    with pytest.raises(Exception, match="match_on"):
        parse_sources(spec("http://x", match_on=None))


def test_missing_items_become_events_once_a_day(engine_factory, indents, clock):
    base, state = indents
    eng = engine_factory()
    eng.publish_config(eng.save_config("connectors", yaml.safe_dump({"sources": spec(base)}), "m")[0].id, actor="m")
    assert eng.schedule_sources() == 1                                      # 14:30 IST: due
    assert eng.schedule_sources() == 0                                      # once per day
    eng.work("w")
    incs = eng.store.incidents()
    assert len(incs) == 1 and incs[0].first_event["payload"] == {
        "route": "R3", "date": "2026-10-10", "deadline": "2026-10-10T05:30:00+05:30"}
    assert eng.store.get_source_state("indents")["last_missing"] == 1
    eng.poll_source("indents")                                              # run again by hand: same key
    assert len(eng.store.incidents()) == 1
    state["rows"] = []
    clock.advance(days=1)
    eng.schedule_sources()
    eng.work("w")
    assert eng.store.get_source_state("indents")["last_missing"] == 3       # a new day: all three missing
    assert len(eng.store.event_ids(incs[0].id)) == 4                        # no fingerprint rule: one case


def test_nothing_at_all_and_checks(engine_factory, indents):
    base, state = indents
    state["rows"] = []
    eng = engine_factory()
    text = yaml.safe_dump({"sources": spec(base, expected=None, match_on=None,
                                           emit=[{"type": "settlement.missing", "key": "settle:{{item.date}}"}])})
    _, probs = eng.check_config("connectors", text)
    assert not [p for p in probs if p.severity == "error"]
    eng.publish_config(eng.save_config("connectors", text, "m")[0].id, actor="m")
    assert eng.poll_source("indents")["events"] == 1
    state["rows"] = [{"x": 1}]
    assert eng.poll_source("indents")["events"] == 0
    nokey = yaml.safe_dump({"sources": spec(base, emit=[{"type": "indent.missing"}])})
    assert any("give the emit a key" in p.message for p in eng.check_config("connectors", nokey)[1])
