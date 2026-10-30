# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""Surface 6, Experience patterns: the seven gate tests of canon/surfaces/06-experience.md (UX-1 .. UX-7).

The subject is a rendering/behaviour facade (for a web product, a thin adapter over its component
tests); the gate asserts the contract, not the markup.
"""
from __future__ import annotations

from .framework import Gate, make_gate
from .rbac import KINDS

CANON = "canon/surfaces/06-experience.md, Gate tests"
STATES = ("loading", "empty_never", "empty_filtered", "denied", "partial_failure", "stale", "too_much", "error")
MIN_TARGET_PX = 44


def ux1(s) -> "list[str]":
    """Rank before limit: the top-ranked row is on page 1 even when its natural order is last (gate 1)."""
    s.seed_rows(30, page_size=10)
    return [] if s.page(1)[0] == s.top_ranked() else ["the top-ranked row is not on page 1: the set was limited before it was ranked"]


def ux2(s) -> "list[str]":
    """All eight states render their specific copy, and each denial kind its own (gate 2)."""
    p = []
    r = s.render("loading", shape="table")
    if r.get("kind") == "spinner" or r.get("shape") != "table":
        p.append("loading must be a skeleton in the shape of the content, not a spinner")
    r = s.render("empty_never")
    if not r.get("action"):
        p.append("an empty never-had-data state offers no action that would put data there")
    r = s.render("empty_filtered", filter="status=open")
    if "status=open" not in r.get("copy", "") or not r.get("clear_action"):
        p.append("a filtered-to-nothing state does not name the filter and offer to clear it")
    r = s.render("partial_failure", loaded=["orders"], failed=["stock"])
    if "stock" not in r.get("copy", "") or r.get("whole_page_failed") or "orders" not in r.get("copy", ""):
        p.append("a partial failure must show what loaded, name what did not, and not fail the page")
    r = s.render("stale", as_of="2026-10-30 09:00")
    if "2026-10-30 09:00" not in r.get("copy", ""):
        p.append("a stale state does not say when the data is from")
    r = s.render("too_much", count=40000, threshold=5000)
    if r.get("rows_rendered") or not r.get("requires_filter"):
        p.append("above the threshold the screen must insist on a filter, not render the rows")
    r = s.render("error")
    if not r.get("reference"):
        p.append("an error state carries no reference support can trace")
    copies = {}
    for k in KINDS:
        r = s.render("denied", kind=k, reason="the stated reason", who="the Plant Manager")
        copies[k] = r.get("copy", "")
        if not r.get("visible") or "the stated reason" not in copies[k]:
            p.append(f"a {k} denial is hidden or omits its reason")
    if len(set(copies.values())) < len(KINDS):
        p.append("denials of different kinds share the same copy: the kind must decide the wording")
    if any(w in copies["STATE_GATE"].lower() for w in ("request access", "ask the", "ask your")):
        p.append("a state gate tells the user to ask someone for access")
    if "the Plant Manager" not in copies["AUTHORITY"]:
        p.append("an authority denial does not say who can act")
    if s.render("denied", kind="COMPLETED", reason="done", who="").get("is_error"):
        p.append("a completed action is shown as an error")
    return p


def ux3(s) -> "list[str]":
    """Export provenance records the filters actually applied, with source, time, actor, count, version (gate 3)."""
    out = s.export({"status": "open"})
    pv = out["provenance"]
    p = [f"provenance lacks {k}" for k in ("source", "generated_at", "generated_by", "calc_version") if not pv.get(k)]
    if pv.get("filters") != {"status": "open"}:
        p.append(f"provenance records filters {pv.get('filters')!r}, not the ones applied")
    if pv.get("row_count") != len(out["rows"]):
        p.append("provenance row_count does not match the rows exported")
    return p


def ux4(s) -> "list[str]":
    """A stored artifact is re-served, not re-rendered (gate 4)."""
    a = s.produce("day-close-1")
    s.change_template()
    return [] if s.reserve("day-close-1") == a else ["a produced artifact changed after the template changed"]


def ux5(s) -> "list[str]":
    """Offline flush is idempotent: three flushes leave identical counts (gate 5)."""
    for i in range(3):
        s.capture(f"c{i}")
    counts = []
    for _ in range(3):
        s.flush()
        counts.append(s.server_count())
    return [] if len(set(counts)) == 1 and counts[0] == 3 else [f"repeated flushes gave counts {counts}"]


def ux6(s) -> "list[str]":
    """The sync indicator cannot lie: after a failed flush it shows queue depth and not synced (gate 6)."""
    s.capture("c1")
    s.capture("c2")
    s.fail_next_flush()
    s.flush()
    ind = s.indicator()
    p = []
    if ind.get("state") == "synced":
        p.append("the indicator reports synced with items still queued")
    if ind.get("queued") != 2:
        p.append(f"the indicator shows queue depth {ind.get('queued')!r}, expected 2")
    return p


def ux7(s) -> "list[str]":
    """Floor screens: every interactive element meets the 44px minimum, measured (gate 7)."""
    return [f"{e['id']} is {e['w']}x{e['h']}px, below {MIN_TARGET_PX}" for e in s.floor_elements()
            if min(e["w"], e["h"]) < MIN_TARGET_PX]


class RefUx:
    """PROOF subject. Flaws: limit_then_rank, spinner_only, empty_generic, filtered_unnamed, denied_hidden,
    denied_same_copy, state_gate_asks_access, completed_as_error, partial_fails_page, stale_no_date,
    renders_all_rows, error_no_reference, default_filters_recorded, missing_generated_by, rowcount_wrong,
    rerendered, duplicates_on_reflush, reports_synced, hides_depth, small_target."""

    def __init__(self, flaws=frozenset()):
        self.f = frozenset(flaws)
        self.tmpl, self.arts, self.queue, self.server, self.fail = "v1", {}, [], [], False

    def seed_rows(self, n, page_size):
        self.rows, self.ps = [{"id": i, "rank": i, "natural": i} for i in range(n)], page_size

    def page(self, k):
        if "limit_then_rank" in self.f:      # limit by natural order first, then rank the survivors
            pool = sorted(self.rows, key=lambda r: r["natural"])[:self.ps]
            return [r["id"] for r in sorted(pool, key=lambda r: -r["rank"])]
        return [r["id"] for r in sorted(self.rows, key=lambda r: -r["rank"])[(k - 1) * self.ps:k * self.ps]]

    def top_ranked(self):
        return max(self.rows, key=lambda r: r["rank"])["id"]

    def render(self, state, **c):
        f = self.f
        if state == "loading":
            return {"kind": "spinner" if "spinner_only" in f else "skeleton", "shape": c.get("shape") if "spinner_only" not in f else None}
        if state == "empty_never":
            return {"copy": "No orders yet.", "action": None if "empty_generic" in f else "Create the first order"}
        if state == "empty_filtered":
            return {"copy": "Nothing matches." if "filtered_unnamed" in f else f"Nothing matches {c['filter']}.",
                    "clear_action": "filtered_unnamed" not in f}
        if state == "partial_failure":
            return {"copy": f"Loaded {', '.join(c['loaded'])}. Could not load {', '.join(c['failed'])}.",
                    "whole_page_failed": "partial_fails_page" in f}
        if state == "stale":
            return {"copy": "Data may have moved." if "stale_no_date" in f else f"As of {c['as_of']}; it may have moved."}
        if state == "too_much":
            big = "renders_all_rows" in f
            return {"rows_rendered": c["count"] if big else 0, "requires_filter": not big}
        if state == "error":
            return {"copy": "Something went wrong.", "reference": "" if "error_no_reference" in f else "ERR-7F3A"}
        k = c["kind"]
        wording = {"AUTHORITY": f"Ask {c['who']}.", "STATE_GATE": "It is in a state that does not allow this.",
                   "CONFIG_GATE": "Switched off by a setting.", "PRECONDITION": "Something is missing first.",
                   "READINESS": "Not ready yet; temporary.", "APPROVAL_PENDING": "Waiting on an approver.",
                   "COMPLETED": "Already done."}
        text = "Not allowed." if "denied_same_copy" in f else wording[k]
        if "state_gate_asks_access" in f and k == "STATE_GATE":
            text = f"Request access from {c['who']}."
        return {"visible": "denied_hidden" not in f, "copy": f"{text} ({c['reason']})",
                "is_error": "completed_as_error" in f and k == "COMPLETED"}

    def export(self, filters):
        applied = {} if "default_filters_recorded" in self.f else dict(filters)
        rows = [{"id": 1}, {"id": 2}]
        return {"rows": rows, "provenance": {
            "source": "orders", "filters": applied, "generated_at": "2026-10-30T09:00Z",
            "generated_by": "" if "missing_generated_by" in self.f else "pat", "calc_version": "3",
            "row_count": 99 if "rowcount_wrong" in self.f else len(rows)}}

    def produce(self, key):
        self.arts[key] = f"{key}|{self.tmpl}"
        return self.arts[key]

    def change_template(self):
        self.tmpl = "v2"

    def reserve(self, key):
        return f"{key}|{self.tmpl}" if "rerendered" in self.f else self.arts[key]

    def capture(self, cid):
        self.queue.append(cid)

    def fail_next_flush(self):
        self.fail = True

    def flush(self):
        if self.fail:
            self.fail = False
            return
        self.server += self.queue
        if "duplicates_on_reflush" not in self.f:
            self.server = list(dict.fromkeys(self.server))
        # a successful flush empties the queue; the buggy variant re-sends its seen list next time
        self.queue = [] if "duplicates_on_reflush" not in self.f else list(self.queue)

    def server_count(self):
        return len(self.server)

    def indicator(self):
        if "reports_synced" in self.f:
            return {"state": "synced", "queued": len(self.queue)}
        return {"state": "queued" if self.queue else "synced", "queued": 0 if "hides_depth" in self.f else len(self.queue)}

    def floor_elements(self):
        return [{"id": "btn-save", "w": 48, "h": 48}, {"id": "btn-x", "w": 30 if "small_target" in self.f else 44, "h": 44}]


GATES: "list[Gate]" = [
    make_gate("UX-1", 6, "rank before limit", CANON + " 1", ux1, RefUx, "limit_then_rank"),
    make_gate("UX-2", 6, "all eight states render, and each denial kind its own copy", CANON + " 2", ux2, RefUx,
              "spinner_only", "empty_generic", "filtered_unnamed", "denied_hidden", "denied_same_copy",
              "state_gate_asks_access", "completed_as_error", "partial_fails_page", "stale_no_date",
              "renders_all_rows", "error_no_reference"),
    make_gate("UX-3", 6, "export carries provenance of what was applied", CANON + " 3", ux3, RefUx,
              "default_filters_recorded", "missing_generated_by", "rowcount_wrong"),
    make_gate("UX-4", 6, "a stored artifact is re-served, not re-rendered", CANON + " 4", ux4, RefUx, "rerendered"),
    make_gate("UX-5", 6, "offline flush is idempotent", CANON + " 5", ux5, RefUx, "duplicates_on_reflush"),
    make_gate("UX-6", 6, "the sync indicator cannot lie", CANON + " 6", ux6, RefUx, "reports_synced", "hides_depth"),
    make_gate("UX-7", 6, "floor targets meet the minimum", CANON + " 7", ux7, RefUx, "small_target"),
]
