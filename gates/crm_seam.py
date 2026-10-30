# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""Seam 10, CRM: the four gate tests of canon/surfaces/10-crm-seam.md (CRM-1 .. CRM-4)."""
from __future__ import annotations

import re

from .framework import Gate, Refused, make_gate

CANON = "canon/surfaces/10-crm-seam.md, Gate tests"


def crm1(s) -> "list[str]":
    """Transactions never join a CRM attribute; they reference only the identity record (gate 1)."""
    tables = [t.lower() for t in s.crm_attribute_tables()]
    return [f"transactional query references CRM attribute table {t!r}: {q[:80]}"
            for q in s.transactional_queries() for t in tables if re.search(rf"\b{re.escape(t)}\b", q.lower())]


def crm2(s) -> "list[str]":
    """CRM cannot write transactional state; its legitimate route is a workflow proposal (gate 2)."""
    p = []
    before = s.credit_limit()
    try:
        s.crm_write_credit_limit(5000)
        p.append("the CRM path wrote transactional state directly")
    except Refused:
        pass
    if s.credit_limit() != before:
        p.append("the transactional value changed without a proposal being accepted")
    pid = s.crm_propose_credit_limit(5000)
    if not pid or pid not in s.workflow_proposals():
        p.append("the CRM has no route to propose a change through workflow")
    return p


def crm3(s) -> "list[str]":
    """Seeded customers arrive Active with no approval tasks; a field-captured one raises one (gate 3)."""
    s.seed_customers(5)
    p = []
    if s.approval_tasks() != 0:
        p.append(f"seeding raised {s.approval_tasks()} approval task(s)")
    if set(s.statuses()) != {"ACTIVE"}:
        p.append(f"seeded customers are not all Active: {sorted(set(s.statuses()))}")
    s.capture_customer()
    if s.approval_tasks() != 1:
        p.append(f"a field-captured customer raised {s.approval_tasks()} approval task(s), expected 1")
    return p


def crm4(s) -> "list[str]":
    """The extraction is a routing change: the transactional suite passes unchanged behind an interface (gate 4)."""
    direct, behind = s.run_transactional_suite("direct"), s.run_transactional_suite("interface")
    p = []
    if not all(direct.values()):
        p.append("the transactional suite is red before the CRM is moved behind an interface")
    if direct != behind:
        p.append("the transactional suite changed when the CRM tables were put behind an interface")
    return p


class RefCrm:
    """PROOF subject. Flaws: joins_crm_attribute, direct_write, no_proposal_route, seeds_raise_tasks,
    capture_skips_approval, suite_breaks_behind_interface."""

    def __init__(self, flaws=frozenset()):
        self.f = frozenset(flaws)
        self._limit, self._props, self._status, self._tasks = 1000, [], [], 0

    def crm_attribute_tables(self):
        return ["crm_segment", "crm_contact"]

    def transactional_queries(self):
        q = ["select c.id, c.legal_name from customer c where c.id = :id",
             "select i.id, c.tax_id from invoice i join customer c on c.id = i.customer_id"]
        if "joins_crm_attribute" in self.f:
            q.append("select i.id from invoice i join crm_segment s on s.customer_id = i.customer_id")
        return q

    def credit_limit(self):
        return self._limit

    def crm_write_credit_limit(self, v):
        if "direct_write" in self.f:
            self._limit = v
            return
        raise Refused("crm_cannot_write")

    def crm_propose_credit_limit(self, v):
        if "no_proposal_route" in self.f:
            return None
        self._props.append("P1")
        return "P1"

    def workflow_proposals(self):
        return list(self._props)

    def seed_customers(self, n):
        self._status += ["ACTIVE"] * n
        if "seeds_raise_tasks" in self.f:
            self._tasks += n

    def capture_customer(self):
        self._status.append("LEAD")
        if "capture_skips_approval" not in self.f:
            self._tasks += 1

    def approval_tasks(self):
        return self._tasks

    def statuses(self):
        return list(self._status)

    def run_transactional_suite(self, mode):
        res = {"post_invoice": True, "settle_invoice": True}
        if mode == "interface" and "suite_breaks_behind_interface" in self.f:
            res["settle_invoice"] = False
        return res


GATES: "list[Gate]" = [
    make_gate("CRM-1", 10, "transactions never join a CRM attribute", CANON + " 1", crm1, RefCrm, "joins_crm_attribute"),
    make_gate("CRM-2", 10, "CRM cannot write transactional state", CANON + " 2", crm2, RefCrm,
              "direct_write", "no_proposal_route"),
    make_gate("CRM-3", 10, "seeded customers arrive Active", CANON + " 3", crm3, RefCrm,
              "seeds_raise_tasks", "capture_skips_approval"),
    make_gate("CRM-4", 10, "the extraction is a routing change", CANON + " 4", crm4, RefCrm,
              "suite_breaks_behind_interface"),
]
