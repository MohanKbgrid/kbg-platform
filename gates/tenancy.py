# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""Surface 1, Tenancy: the seven gate tests of canon/surfaces/01-tenancy.md.

Gate ids TEN-1 .. TEN-7 follow the canon's numbering. The subject offers the calls named in each
gate; the reference subject at the foot of the file is the PROOF, not a product.
"""
from __future__ import annotations

from .framework import Gate, Refused, make_gate

CANON = "canon/surfaces/01-tenancy.md, Gate tests"


def ten1(s) -> "list[str]":
    """A new table cannot ship without a tenant column; each exception names its reason (gate 1)."""
    p = []
    for name, t in sorted(s.tables().items()):
        if "company_id" not in t["columns"] and not (t.get("exception") or "").strip():
            p.append(f"table {name} has no company_id and no stated reason for the exception")
    return p


def ten2(s) -> "list[str]":
    """Cross-tenant read is impossible: B's rows are absent from A's response (gate 2)."""
    s.seed("A", ["a1", "a2"])
    s.seed("B", ["b1", "b2"])
    got = {r["id"] for r in s.list_rows("A")}
    p = []
    if got & {"b1", "b2"}:
        p.append(f"company A's response contains company B's rows: {sorted(got & {'b1', 'b2'})}")
    if not {"a1", "a2"} <= got:
        p.append("company A cannot read its own rows")
    return p


def ten3(s) -> "list[str]":
    """A write cannot choose its own tenant: the stored row carries the resolved one (gate 3)."""
    stored = s.create("A", body_company_id="B")
    return [] if stored == "A" else [f"a create resolved to A but stored company {stored!r}: the body chose the tenant"]


def ten4(s) -> "list[str]":
    """The unscoped view is deliberate: null context returns everyone, and only for an entitled role (gate 4)."""
    s.seed("A", ["a1"])
    s.seed("B", ["b1"])
    p = []
    try:
        s.list_rows(None, role="clerk")
        p.append("the unscoped view was served to a role not entitled to it")
    except Refused:
        pass
    ids = {r["id"] for r in s.list_rows(None, role="leadership")}
    if not {"a1", "b1"} <= ids:
        p.append(f"the unscoped view did not return both companies' rows: {sorted(ids)}")
    return p


def ten5(s) -> "list[str]":
    """A disabled module is absent for that company and still works for the other (gate 5)."""
    s.set_module("A", "billing", False)
    p = []
    if s.module_status("A", "billing") != 404:
        p.append("a disabled module still answers for the company it is disabled for")
    if s.module_status("B", "billing") != 200:
        p.append("disabling a module for A broke it for B")
    return p


def ten6(s) -> "list[str]":
    """Connector resolution: company row, then global, then refuse. Never a hardcoded value (gate 6)."""
    s.set_connector("global", "gw", "G-URL")
    s.set_connector("A", "gw", "A-URL")
    p = []
    if s.resolve_connector("A", "gw") != "A-URL":
        p.append("the global connector won over the company's own")
    s.drop_connector("A", "gw")
    try:
        if s.resolve_connector("A", "gw") != "G-URL":
            p.append("removing the company row did not fall back to the global row")
    except Refused:
        p.append("removing the company row refused instead of falling back to the global row")
    s.drop_connector("global", "gw")
    try:
        got = s.resolve_connector("A", "gw")
        p.append(f"with no row at all the resolver returned {got!r} instead of refusing")
    except Refused:
        pass
    return p


def ten7(s) -> "list[str]":
    """A third company is data only: onboard it and run a full round trip with no deploy (gate 7)."""
    s.onboard("C")
    got = s.round_trip("C")
    return [] if got == "C" else [f"a round trip for a newly added company C ended with {got!r}: tenancy is hardcoded somewhere"]


class RefTenancy:
    """PROOF subject. Flaws: table_without_column, exception_without_reason, leaks_other_tenant,
    body_chooses_tenant, unscoped_without_role, unscoped_returns_one, still_serves, disables_for_all,
    global_wins, hardcoded_fallback, no_fallback, hardcoded_company_list."""

    def __init__(self, flaws=frozenset()):
        self.f = frozenset(flaws)
        self.rows, self.modules, self.conn, self.companies = [], {}, {}, {"A", "B"}

    def tables(self):
        t = {"orders": {"columns": {"id", "company_id"}},
             "company": {"columns": {"id"}, "exception": "the tenant itself"}}
        if "table_without_column" in self.f:
            t["invoices"] = {"columns": {"id"}}
        if "exception_without_reason" in self.f:
            t["lookup"] = {"columns": {"id"}, "exception": "  "}
        return t

    def seed(self, company, ids):
        self.rows += [{"id": i, "company_id": company} for i in ids]

    def list_rows(self, ctx, role=None):
        if ctx is None:
            if role != "leadership" and "unscoped_without_role" not in self.f:
                raise Refused("not_entitled")
            rows = [r for r in self.rows if "unscoped_returns_one" not in self.f or r["company_id"] == "A"]
            return rows
        return self.rows if "leaks_other_tenant" in self.f else [r for r in self.rows if r["company_id"] == ctx]

    def create(self, ctx, body_company_id):
        return body_company_id if "body_chooses_tenant" in self.f else ctx

    def set_module(self, company, module, enabled):
        self.modules[(company, module)] = enabled
        if "disables_for_all" in self.f:
            for c in self.companies:
                self.modules[(c, module)] = enabled

    def module_status(self, company, module):
        if "still_serves" in self.f:
            return 200
        return 200 if self.modules.get((company, module), True) else 404

    def set_connector(self, owner, key, value):
        self.conn[(owner, key)] = value

    def drop_connector(self, owner, key):
        self.conn.pop((owner, key), None)

    def resolve_connector(self, company, key):
        own, glob = self.conn.get((company, key)), self.conn.get(("global", key))
        if "global_wins" in self.f and glob is not None:
            return glob
        if own is not None:
            return own
        if glob is not None and "no_fallback" not in self.f:
            return glob
        if "hardcoded_fallback" in self.f:
            return "https://built-in.example/default"
        raise Refused("no_connector", f"no connector {key!r} for {company}")

    def onboard(self, code):
        self.companies.add(code)

    def round_trip(self, code):
        if "hardcoded_company_list" in self.f and code not in {"A", "B"}:
            return None
        return code


GATES: "list[Gate]" = [
    make_gate("TEN-1", 1, "a new table cannot ship without a tenant column", CANON + " 1", ten1, RefTenancy,
              "table_without_column", "exception_without_reason"),
    make_gate("TEN-2", 1, "cross-tenant read is impossible", CANON + " 2", ten2, RefTenancy, "leaks_other_tenant"),
    make_gate("TEN-3", 1, "a write cannot choose its own tenant", CANON + " 3", ten3, RefTenancy, "body_chooses_tenant"),
    make_gate("TEN-4", 1, "the unscoped view is deliberate and entitled", CANON + " 4", ten4, RefTenancy,
              "unscoped_without_role", "unscoped_returns_one"),
    make_gate("TEN-5", 1, "a disabled module is absent for that company only", CANON + " 5", ten5, RefTenancy,
              "still_serves", "disables_for_all"),
    make_gate("TEN-6", 1, "connector resolution prefers the company row, then global, then refuses", CANON + " 6",
              ten6, RefTenancy, "global_wins", "no_fallback", "hardcoded_fallback"),
    make_gate("TEN-7", 1, "adding a third company requires no code change", CANON + " 7", ten7, RefTenancy,
              "hardcoded_company_list"),
]
