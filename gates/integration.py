# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""Surface 7, Integration: the nine gate tests of canon/surfaces/07-integration.md (INT-1 .. INT-9).

INT-8 and INT-9 are the two newest. `bases/core.Outbox` is itself a subject of INT-8, INT-9 and INT-4
(see gates/bindings_bases.py); everything else here is proven against the reference subject below.
"""
from __future__ import annotations

from .framework import Gate, Refused, make_gate

CANON = "canon/surfaces/07-integration.md, Gate tests"


def int1(s) -> "list[str]":
    """An unmapped key refuses the push and names the dimension and the key; nothing posts (gate 1)."""
    p = []
    try:
        s.push({"material": "UNMAPPED-KEY-1"})
        p.append("an unmapped key was accepted")
    except Refused as e:
        if not ("material" in e.message and "UNMAPPED-KEY-1" in e.message):
            p.append(f"the refusal does not name the dimension and the key: {e.message!r}")
    if s.posted_count() != 0:
        p.append("a refused push left a posting")
    return p


def int2(s) -> "list[str]":
    """Explosion is all-or-nothing: one missing target refuses the whole document (gate 2)."""
    s.map_code("account", "A1", "X1")
    p = []
    try:
        s.push_exploded(["A1", "A2"])
        p.append("a split with a missing target was accepted")
    except Refused:
        pass
    if s.posted_lines() != 0:
        p.append(f"a refused split left {s.posted_lines()} posted line(s): a partial explosion")
    return p


def int3(s) -> "list[str]":
    """A mapping change is not retroactive: a document already sent still shows what was sent (gate 3)."""
    s.map_code("material", "M1", "TARGET-A")
    sid = s.send({"material": "M1"})
    before = s.read_sent(sid)
    s.map_code("material", "M1", "TARGET-B")
    after = s.read_sent(sid)
    p = []
    if before != after:
        p.append(f"the sent document changed with the mapping: {before!r} became {after!r}")
    if before.get("target") != "TARGET-A":
        p.append(f"the sent document does not show what was sent: {before!r}")
    return p


def int4(s) -> "list[str]":
    """Retry re-drives the same row: one outbox row with attempts = 2 (gate 4)."""
    s.set_mode("production")
    s.fail_push("orders", "k1")
    s.retry("orders", "k1")
    rows = s.rows_of("orders", "k1")
    if len(rows) != 1:
        return [f"a retry made {len(rows)} rows for one push"]
    return [] if rows[0]["attempts"] == 2 else [f"the one row shows attempts={rows[0]['attempts']!r}, expected 2"]


def int5(s) -> "list[str]":
    """The environment gate holds, proven three ways, then flips on config alone (gate 5)."""
    p = []
    s.set_mode("uat")
    s.enqueue("orders", "k1")
    s.dispatch()
    if s.mode() == "production":
        p.append("(a) the resolved mode is production in a test environment")
    states = s.row_states()
    if not states or set(states) != {"held"}:
        p.append(f"(b) every relevant outbox row must be held, got {sorted(set(states))}")
    if s.outbound_calls() != 0:
        p.append("(c) an outbound call was made while the gate was closed")
    s.set_mode("production")
    s.dispatch()
    if "confirmed" not in s.row_states() or s.outbound_calls() == 0:
        p.append("flipping the mode in config alone did not change the state: the gate is not live")
    return p


def int6(s) -> "list[str]":
    """The dispatcher is actually scheduled and has a recent run record (gate 6)."""
    p = []
    if not s.schedule_exists():
        p.append("no schedule exists (a comment describing one is not a schedule)")
    age = s.last_run_age_seconds()
    if age is None or age > s.expected_interval_seconds() * 3:
        p.append(f"no run record was written recently: last run age {age!r} s")
    if s.idle_healthy_is_distinguishable_from_dead() is not True:
        p.append("an idle healthy job cannot be told from a dead one")
    return p


def int7(s) -> "list[str]":
    """A far-side error gives a non-zero result and a recorded failure (gate 7)."""
    s.set_mode("production")
    s.enqueue("orders", "k7")
    s.force_far_error(True)
    exit_code = s.dispatch()
    p = []
    if exit_code == 0:
        p.append("a far-side error produced a zero result: swallowed")
    if s.recorded_failures() < 1:
        p.append("a far-side error left no recorded failure")
    return p


def int8(s) -> "list[str]":
    """The first enqueue of a new (topic, source_key) makes exactly one row, and a repeat is that row (gate 8)."""
    first = s.enqueue("orders", "new-key")
    p = []
    if s.row_count() != 1:
        p.append(f"the first enqueue into an empty outbox left {s.row_count()} rows, not exactly one")
    again = s.enqueue("orders", "new-key")
    if s.row_count() != 1 or again != first:
        p.append("enqueueing the same key again did not return the same single row")
    return p


def int9(s) -> "list[str]":
    """A held row consumes no attempt and is re-drivable; attempts then count only real calls (gate 9)."""
    s.set_mode("dev")
    s.enqueue("orders", "k1")
    s.enqueue("orders", "k2")
    for _ in range(5):
        s.dispatch()
    p = []
    rows = s.all_rows()
    if any(r["state"] != "held" for r in rows):
        p.append(f"a held row changed state while held: {[r['state'] for r in rows]}")
    if any(r["attempts"] != 0 for r in rows):
        p.append(f"held rows consumed attempts: {[r['attempts'] for r in rows]}")
    s.set_mode("production")
    s.dispatch()
    rows = s.all_rows()
    if any(r["state"] != "confirmed" for r in rows):
        p.append("held rows were not re-driven once the gate opened")
    if any(r["attempts"] != 1 for r in rows):
        p.append(f"attempts after one real send are {[r['attempts'] for r in rows]}, expected 1 each")
    return p


class RefIntegration:
    """PROOF subject. Flaws: accepts_unmapped, unnamed_refusal, partial_post, partial_explosion, retroactive, dup_rows,
    gate_ignored, flip_ignored, fakes_success, comment_only, stale_run, idle_blind, swallowed, unrecorded,
    unawaited_lookup, held_counts_attempt, held_dead_letters, no_redrive."""

    def __init__(self, flaws=frozenset()):
        self.f = frozenset(flaws)
        self.maps, self.sent, self.posted, self.lines = {}, {}, [], 0
        self._mode, self.rows, self.calls, self.far_error, self.failures = "production", {}, 0, False, 0

    # mapping
    def map_code(self, dim, key, target):
        self.maps[(dim, key)] = target
        if "retroactive" in self.f:
            for d in self.sent.values():
                d["target"] = target

    def push(self, doc):
        key = doc["material"]
        if ("material", key) not in self.maps and "accepts_unmapped" not in self.f:
            if "partial_post" in self.f:
                self.posted.append(doc)
            raise Refused("unmapped", "refused" if "unnamed_refusal" in self.f
                          else f"unmapped key {key!r} of dimension 'material'")
        self.posted.append(doc)

    def posted_count(self):
        return len(self.posted)

    def push_exploded(self, targets):
        missing = [t for t in targets if ("account", t) not in self.maps]
        if missing and "partial_explosion" not in self.f:
            raise Refused("unmapped", f"unmapped {missing}")
        self.lines += len(targets) - len(missing)

    def posted_lines(self):
        return self.lines

    def send(self, doc):
        sid = len(self.sent) + 1
        self.sent[sid] = {"material": doc["material"], "target": self.maps[("material", doc["material"])]}
        return sid

    def read_sent(self, sid):
        return dict(self.sent[sid])

    # outbox
    def set_mode(self, m):
        self._mode = m

    def mode(self):
        return self._mode

    def enqueue(self, topic, key):
        k = (topic, key)
        if "unawaited_lookup" in self.f:
            return k                              # the 'existing' lookup was truthy: nothing is ever written
        if k not in self.rows:
            self.rows[k] = {"state": "held" if self._mode != "production" else "queued", "attempts": 0}
        return k

    def row_count(self):
        return len(self.rows)

    def all_rows(self):
        return [dict(r) for r in self.rows.values()]

    def row_states(self):
        return [r["state"] for r in self.rows.values()]

    def outbound_calls(self):
        return self.calls

    def force_far_error(self, on):
        self.far_error = on

    def dispatch(self):
        code = 0
        for k in list(self.rows):
            r = self.rows[k]
            if r["state"] in ("confirmed", "dead_letter"):
                continue
            closed = self._mode != "production" and "gate_ignored" not in self.f
            if "flip_ignored" in self.f and r["state"] == "held":
                continue
            if "no_redrive" in self.f and r["state"] == "held" and not closed:
                continue
            if closed:
                r["state"] = "confirmed" if "fakes_success" in self.f else "held"
                if "held_counts_attempt" in self.f or "held_dead_letters" in self.f:
                    r["attempts"] += 1
                if "held_dead_letters" in self.f and r["attempts"] >= 3:
                    r["state"] = "dead_letter"
                continue
            self.calls += 1
            r["attempts"] += 1
            if self.far_error:
                r["state"] = "failed"
                if "unrecorded" not in self.f:
                    self.failures += 1
                code = 0 if "swallowed" in self.f else 1
                if "dup_rows" in self.f:
                    self.rows[(k[0], k[1] + "#retry")] = {"state": "failed", "attempts": 1}
            else:
                r["state"] = "confirmed"
        return code

    def recorded_failures(self):
        return self.failures

    def fail_push(self, topic, key):
        self.enqueue(topic, key)
        self.far_error = True
        self.dispatch()

    def retry(self, topic, key):
        self.far_error = False
        self.dispatch()

    def rows_of(self, topic, key):
        return [dict(r) for k, r in self.rows.items() if k[0] == topic and k[1].startswith(key)]

    # schedule
    def schedule_exists(self):
        return "comment_only" not in self.f

    def last_run_age_seconds(self):
        return 100000 if "stale_run" in self.f else 5

    def expected_interval_seconds(self):
        return 60

    def idle_healthy_is_distinguishable_from_dead(self):
        return "idle_blind" not in self.f


GATES: "list[Gate]" = [
    make_gate("INT-1", 7, "an unmapped key refuses and names itself", CANON + " 1", int1, RefIntegration,
              "accepts_unmapped", "unnamed_refusal", "partial_post"),
    make_gate("INT-2", 7, "explosion is all-or-nothing", CANON + " 2", int2, RefIntegration, "partial_explosion"),
    make_gate("INT-3", 7, "a mapping change is not retroactive", CANON + " 3", int3, RefIntegration, "retroactive"),
    make_gate("INT-4", 7, "retry re-drives the same row", CANON + " 4", int4, RefIntegration, "dup_rows"),
    make_gate("INT-5", 7, "the environment gate holds, proven three ways", CANON + " 5", int5, RefIntegration,
              "gate_ignored", "flip_ignored", "fakes_success"),
    make_gate("INT-6", 7, "the dispatcher is actually scheduled", CANON + " 6", int6, RefIntegration,
              "comment_only", "stale_run", "idle_blind"),
    make_gate("INT-7", 7, "failures are loud", CANON + " 7", int7, RefIntegration, "swallowed", "unrecorded"),
    make_gate("INT-8", 7, "the first enqueue of a new key produces exactly one row", CANON + " 8", int8,
              RefIntegration, "unawaited_lookup"),
    make_gate("INT-9", 7, "a held row consumes no attempt", CANON + " 9", int9, RefIntegration,
              "held_counts_attempt", "held_dead_letters", "no_redrive"),
]
