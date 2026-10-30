# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""Surface 4, Workflow and the work queue: the nine gate tests of canon/surfaces/04-workflow.md (WF-1 .. WF-9)."""
from __future__ import annotations

import inspect

from .framework import Gate, make_gate

CANON = "canon/surfaces/04-workflow.md, Gate tests"
APPROVER_PARAMS = {"approver", "approver_id", "assignee", "assigned_to", "user", "user_id", "position", "owner"}


def wf1(s) -> "list[str]":
    """The caller cannot name the approver; editing the matrix alone re-routes an identical call (gate 1)."""
    p = []
    named = APPROVER_PARAMS & set(inspect.signature(s.raise_item).parameters)
    if named:
        p.append(f"raise_item accepts an approver-shaped argument: {sorted(named)}")
    s.set_matrix([(0, 1000, "SUPERVISOR")])
    a = s.raise_item("order", 500).position
    s.set_matrix([(0, 1000, "MANAGER")])
    b = s.raise_item("order", 500).position
    if a == b:
        p.append("changing the approval matrix alone did not re-route an identical call")
    return p


def wf2(s) -> "list[str]":
    """A threshold walks the chart: below and above a band reach two positions, no code between (gate 2)."""
    s.set_matrix([(0, 1000, "SUPERVISOR"), (1000, 10 ** 9, "MANAGER")])
    lo, hi = s.raise_item("order", 100).position, s.raise_item("order", 5000).position
    return [] if lo != hi else [f"a low and a high value both reached {lo}: the value band is ignored"]


def wf3(s) -> "list[str]":
    """An empty seat escalates to the parent, and the item says why (gate 3)."""
    s.set_matrix([(0, 10 ** 9, "SUPERVISOR")])
    s.vacate("SUPERVISOR")
    r = s.raise_item("order", 10)
    p = []
    if r.position != s.parent_of("SUPERVISOR"):
        p.append(f"work for a vacant seat went to {r.position!r}, not its parent")
    if not (r.reason or "").strip():
        p.append("the item does not state why it was escalated")
    return p


def wf4(s) -> "list[str]":
    """An SLA breach is a persisted event naming elapsed time and position; it survives viewing (gate 4)."""
    s.add_item("item-1", position="DESK", due_in_minutes=10)
    s.advance(minutes=30)
    s.sweep()
    ev = s.breach_events()
    p = []
    if len(ev) != 1:
        return [f"expected one breach event, got {len(ev)}"]
    if ev[0].get("elapsed_minutes") is None or not ev[0].get("position"):
        p.append(f"the breach event must name the elapsed time and the position: {ev[0]!r}")
    s.view_queue()
    if s.breach_events() != ev:
        p.append("the breach event did not persist after the queue was viewed")
    return p


def wf5(s) -> "list[str]":
    """Risk sort is over the WHOLE set, then paged, and responds to each input twice (gate 5)."""
    s.seed(items=30, page_size=10)
    p = []
    first = s.page(1)[0]
    if first != s.highest_risk():
        p.append("the highest-risk item is not first on page 1: ranked within a page or by arrival")
    s.raise_input(s.lowest_risk())
    m1 = s.page(1)[0]
    if m1 == first:
        p.append("raising a value did not move the order")
    s.escalate(s.lowest_risk())
    if s.page(1)[0] == m1:
        p.append("an escalation did not move the order a second time")
    return p


def wf6(s) -> "list[str]":
    """The formula shown on screen is the constant the server ranks by, not a copy (gate 6)."""
    return [] if s.formula_on_screen() == s.formula_in_ranker() else ["the formula on screen is not the constant the ranker uses"]


def wf7(s) -> "list[str]":
    """Availability is disabled-with-reason and the write endpoint 403s with the same reason (gate 7)."""
    a = s.item_actions("outsider", "i1")
    status, reason = s.act("outsider", "i1")
    p = []
    if a.get("enabled") is not False or not a.get("reason"):
        p.append(f"an action the user may not take must be enabled:false with a reason: {a!r}")
    if status != 403:
        p.append(f"the write endpoint answered {status!r}, not 403")
    elif reason != a.get("reason"):
        p.append(f"the 403 reason {reason!r} differs from the availability reason {a.get('reason')!r}")
    return p


def wf8(s) -> "list[str]":
    """Approving past a level records the bypassed level (gate 8)."""
    s.approve("director", "i2", skip_level=1)
    ev = s.audit("i2")
    return [] if any(e.get("bypassed_level") == 1 for e in ev) else ["a skip-level approval did not record the bypassed level"]


def wf9(s) -> "list[str]":
    """Deleting the source object leaves the item alive, honest to render, closable; audit intact (gate 9)."""
    s.raise_for_object("obj-1")
    s.delete_object("obj-1")
    it = s.get_item("obj-1")
    p = []
    if it is None:
        return ["the queue item vanished with its source object"]
    if not (it.get("title") or "").strip() or it.get("render_error"):
        p.append("the orphaned item does not render honestly")
    s.close_item("obj-1")
    if s.get_item("obj-1")["status"] != "closed":
        p.append("the orphaned item cannot be closed")
    if not s.audit("obj-1"):
        p.append("the audit trail was deleted with the source")
    return p


class _Item:
    def __init__(self, position, reason=""):
        self.position, self.reason = position, reason


class RefWorkflow:
    """PROOF subject. Flaws: takes_approver, hardwired_route, ignores_value, falls_into_hole, silent_escalation,
    no_event, vanishes_on_view, unnamed_breach, page_local, static_order, ignores_escalation, formula_copy,
    different_reason, not_recorded, cascade_deletes, orphan_render_error, audit_deleted."""

    def __init__(self, flaws=frozenset()):
        self.f = frozenset(flaws)
        self.matrix, self.vacant, self.t, self.items, self.events = [], set(), 0, [], []
        self.W = 3
        self.queue_items, self._audit, self._objs = {}, {}, set()
        if "takes_approver" in self.f:
            self.raise_item = self._raise_with_approver

    def set_matrix(self, rows):
        self.matrix = rows

    def parent_of(self, pos):
        return "DEPARTMENT_HEAD"

    def vacate(self, pos):
        self.vacant.add(pos)

    def raise_item(self, kind, value):
        row = next((r for r in self.matrix if r[0] <= (0 if "ignores_value" in self.f else value) < r[1]), self.matrix[0])
        pos = "SUPERVISOR" if "hardwired_route" in self.f else row[2]
        if pos in self.vacant:
            if "falls_into_hole" in self.f:
                return _Item(pos)
            return _Item(self.parent_of(pos), "" if "silent_escalation" in self.f else f"{pos} is vacant")
        return _Item(pos)

    def _raise_with_approver(self, kind, value, approver=None):
        return _Item(approver or "SUPERVISOR")

    # SLA
    def add_item(self, i, position, due_in_minutes):
        self.items.append((i, position, self.t + due_in_minutes))

    def advance(self, minutes):
        self.t += minutes

    def sweep(self):
        if "no_event" in self.f:
            return
        for i, pos, due in self.items:
            if self.t > due and not any(e["item"] == i for e in self.events):
                self.events.append({"item": i, "elapsed_minutes": None if "unnamed_breach" in self.f else self.t - due,
                                    "position": None if "unnamed_breach" in self.f else pos})

    def breach_events(self):
        return list(self.events)

    def view_queue(self):
        if "vanishes_on_view" in self.f:
            self.events.clear()

    # ranking
    def seed(self, items, page_size):
        self.ps = page_size
        self.rank_items = [{"id": i, "arrival": i, "raw": i, "esc": 0} for i in range(items)]

    def _risk(self, it):
        return it["raw"] * self.W + (0 if "ignores_escalation" in self.f else it["esc"] * 1000)

    def _ranked(self):
        its = self.rank_items
        if "static_order" in self.f:
            return sorted(its, key=lambda x: x["arrival"])
        if "page_local" in self.f:
            return [y for k in range(0, len(its), self.ps) for y in sorted(its[k:k + self.ps], key=lambda x: -self._risk(x))]
        return sorted(its, key=lambda x: -self._risk(x))

    def page(self, n):
        return [x["id"] for x in self._ranked()[(n - 1) * self.ps:n * self.ps]]

    def highest_risk(self):
        return max(self.rank_items, key=self._risk)["id"]

    def lowest_risk(self):
        return min(self.rank_items, key=self._risk)["id"]

    def raise_input(self, i):
        next(x for x in self.rank_items if x["id"] == i)["raw"] += 100

    def escalate(self, i):
        next(x for x in self.rank_items if x["id"] == i)["esc"] += 1

    def formula_on_screen(self):
        return {"weight": 5 if "formula_copy" in self.f else self.W}

    def formula_in_ranker(self):
        return {"weight": self.W}

    # actions
    def item_actions(self, user, item):
        return {"enabled": False, "reason": "needs the Plant Manager position"}

    def act(self, user, item):
        return 403, ("forbidden" if "different_reason" in self.f else "needs the Plant Manager position")

    def approve(self, who, item, skip_level):
        self._audit.setdefault(item, []).append({"actor": who, "bypassed_level": None if "not_recorded" in self.f else skip_level})

    def audit(self, item):
        return self._audit.get(item, [])

    # orphaned items
    def raise_for_object(self, obj):
        self._objs.add(obj)
        self.queue_items[obj] = {"title": f"Review {obj}", "status": "open"}
        self._audit[obj] = [{"event": "raised"}]

    def delete_object(self, obj):
        self._objs.discard(obj)
        if "cascade_deletes" in self.f:
            self.queue_items.pop(obj, None)
        if "orphan_render_error" in self.f and obj in self.queue_items:
            self.queue_items[obj] = {"title": "", "status": "open", "render_error": "source missing"}
        if "audit_deleted" in self.f:
            self._audit.pop(obj, None)

    def get_item(self, obj):
        return self.queue_items.get(obj)

    def close_item(self, obj):
        self.queue_items[obj]["status"] = "closed"


GATES: "list[Gate]" = [
    make_gate("WF-1", 4, "the caller cannot name the approver", CANON + " 1", wf1, RefWorkflow,
              "takes_approver", "hardwired_route"),
    make_gate("WF-2", 4, "a threshold walks the chart", CANON + " 2", wf2, RefWorkflow, "ignores_value"),
    make_gate("WF-3", 4, "an empty seat escalates and says why", CANON + " 3", wf3, RefWorkflow,
              "falls_into_hole", "silent_escalation"),
    make_gate("WF-4", 4, "an SLA breach is a persisted event", CANON + " 4", wf4, RefWorkflow,
              "no_event", "vanishes_on_view", "unnamed_breach"),
    make_gate("WF-5", 4, "risk sort is server-side over the whole set", CANON + " 5", wf5, RefWorkflow,
              "page_local", "static_order", "ignores_escalation"),
    make_gate("WF-6", 4, "the formula on screen is the one the server sorts by", CANON + " 6", wf6, RefWorkflow,
              "formula_copy"),
    make_gate("WF-7", 4, "actions and permissions agree", CANON + " 7", wf7, RefWorkflow, "different_reason"),
    make_gate("WF-8", 4, "a skip-level approval is recorded", CANON + " 8", wf8, RefWorkflow, "not_recorded"),
    make_gate("WF-9", 4, "deleting the source object does not corrupt the queue", CANON + " 9", wf9, RefWorkflow,
              "cascade_deletes", "orphan_render_error", "audit_deleted"),
]
