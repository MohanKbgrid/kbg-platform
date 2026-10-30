# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""Surface 9, Accounting: the ten gate tests of canon/surfaces/09-accounting.md (ACC-1 .. ACC-10).

The subject stands for the product's posting engine. Charts of accounts, dimensions and adapters
are the product's own and appear only through the subject's calls.
"""
from __future__ import annotations

from copy import deepcopy

from .framework import Gate, Refused, make_gate

CANON = "canon/surfaces/09-accounting.md, Gate tests"


def _balanced(v) -> bool:
    return sum(l["dr"] for l in v["lines"]) == sum(l["cr"] for l in v["lines"])


def acc1(s) -> "list[str]":
    """Every voucher balances on every posting path, including failure paths (gate 1)."""
    p = []
    for path in s.posting_paths():
        s.post(path, f"k-{path}", 100)
    p += [f"voucher {v['id']} does not balance" for v in s.vouchers() if not _balanced(v)]
    n = len(s.vouchers())
    for path in s.posting_paths():
        try:
            s.post_failing(path, f"bad-{path}")
        except Refused:
            pass
    p += [f"a failed post left voucher {v['id']} unbalanced" for v in s.vouchers() if not _balanced(v)]
    if len(s.vouchers()) != n:
        p.append("a failed post left a voucher behind")
    return p


def acc2(s) -> "list[str]":
    """Validation precedes mutation: a failed re-post leaves the prior lines in place (gate 2)."""
    s.post("sales", "K2", 100)
    before = deepcopy(s.lines_of("K2"))
    try:
        s.repost_invalid("K2")
    except Refused:
        pass
    return [] if s.lines_of("K2") == before else ["a failed re-post removed or changed the prior lines: delete-before-validate"]


def acc3(s) -> "list[str]":
    """Idempotency: the same source key twice is one voucher and no doubled amount (gate 3)."""
    s.post("sales", "K3", 100)
    s.post("sales", "K3", 100)
    mine = [v for v in s.vouchers() if v["key"] == "K3"]
    p = []
    if len(mine) != 1:
        p.append(f"the same source key produced {len(mine)} vouchers")
    if sum(l["dr"] for v in mine for l in v["lines"]) != 100:
        p.append("amounts were doubled by the second post")
    return p


def acc4(s) -> "list[str]":
    """A closed period refuses, naming the period; the seeded period is open again afterwards (gate 4)."""
    name = s.seeded_period()
    s.close_period(name)
    p = []
    try:
        s.post_in(name, "K4", 10)
        p.append("a posting into a closed period was accepted")
    except Refused as e:
        if name not in e.message:
            p.append(f"the refusal does not name the period {name!r}: {e.message!r}")
    s.restore_period(name)
    if not s.period_open(name):
        p.append("the seeded period was left closed: the suite poisons every later run")
    return p


def acc5(s) -> "list[str]":
    """Dimensions are populated on every line of every path, not null (gate 5)."""
    p = []
    for path, info in s.dimension_report().items():
        for i, line in enumerate(info["lines"]):
            p += [f"{path} line {i}: dimension {d} is null although the event knows it"
                  for d in info["known"] if line.get(d) in (None, "")]
    return p


def acc6(s) -> "list[str]":
    """A correction is a new document referencing the original, which is unchanged (gate 6)."""
    v = s.post("sales", "K6", 100)
    snap = s.snapshot(v)
    c = s.correct(v, 90)
    p = []
    if s.snapshot(v) != snap:
        p.append("the original voucher changed when it was corrected")
    if c == v or s.get(c).get("corrects") != v:
        p.append("the correction is not a new document that references the original")
    return p


def acc7(s) -> "list[str]":
    """A reversal links to what it reverses and the pair nets to zero (gate 7)."""
    v = s.post("sales", "K7", 100)
    r = s.reverse(v)
    p = []
    if s.get(r).get("reverses_voucher_id") != v:
        p.append("the reversal does not set reverses_voucher_id")
    net = sum(l["dr"] - l["cr"] for vid in (v, r) for l in s.get(vid)["lines"] if l["account"] == "RECEIVABLE") \
        if hasattr(s, "get") else 0
    if net != 0:
        p.append(f"the original and its reversal net to {net}, not zero")
    return p


def acc8(s) -> "list[str]":
    """Number series are per company and per year, and atomic (gate 8)."""
    n = 30
    nums = s.allocate_concurrently("A", "JV", "2026-27", n)
    p = []
    if sorted(nums) != list(range(1, n + 1)):
        p.append("concurrent allocation produced duplicates or gaps")
    if s.allocate_concurrently("A", "JV", "2027-28", 2) != [1, 2]:
        p.append("a new fiscal year did not start its own sequence")
    if s.allocate_concurrently("B", "JV", "2026-27", 2) != [1, 2]:
        p.append("a second company did not get an independent sequence")
    return p


def acc9(s) -> "list[str]":
    """The adapter refuses what it cannot represent, naming it (gate 9)."""
    try:
        s.adapter_push({"amount": 10, "tax_treatment": "exotic-unrepresentable"})
        return ["an unrepresentable element was accepted and approximated"]
    except Refused as e:
        return [] if "tax_treatment" in e.message else [f"the refusal does not name the element: {e.message!r}"]


def acc10(s) -> "list[str]":
    """The ledger ties out to the source for a period, with the denominator stated (gate 10)."""
    t = s.tie_out("2026-10")
    L, S = t["ledger"], t["source"]
    p = []
    for k in ("unit", "grain", "period"):
        if L[k] != S[k]:
            p.append(f"the two sides are not comparable: {k} {L[k]!r} vs {S[k]!r}")
    if not p and L["value"] != S["value"]:
        p.append(f"ledger {L['value']} does not equal source {S['value']}")
    return p


class RefLedger:
    """PROOF subject. Flaws: unbalanced_voucher, failure_leaves_half, delete_before_validate, duplicates, closed_accepts,
    unnamed_refusal, no_restore, null_dimension, updates_in_place, no_reference, no_link, not_netting, racy,
    continues_across_years, approximates, mixed_unit, mismatch, other_period."""

    def __init__(self, flaws=frozenset()):
        self.f = frozenset(flaws)
        self._v, self.closed, self.counters, self.keymap = [], set(), {}, {}

    def posting_paths(self):
        return ["sales", "receipt"]

    def _lines(self, path, amount):
        cr = amount - 1 if ("unbalanced_voucher" in self.f and path == "receipt") else amount
        return [{"account": "RECEIVABLE", "dr": amount, "cr": 0}, {"account": "SALES", "dr": 0, "cr": cr}]

    def post(self, path, key, amount):
        if key in self.keymap and "duplicates" not in self.f:
            return self.keymap[key]
        v = {"id": f"V{len(self._v) + 1}", "key": key, "lines": self._lines(path, amount),
             "reverses_voucher_id": None, "corrects": None}
        self._v.append(v)
        self.keymap[key] = v["id"]
        return v["id"]

    def vouchers(self):
        return self._v

    def post_failing(self, path, key):
        if "failure_leaves_half" in self.f:
            self._v.append({"id": f"V{len(self._v) + 1}", "key": key, "lines": [{"account": "X", "dr": 5, "cr": 0}],
                            "reverses_voucher_id": None, "corrects": None})
        raise Refused("invalid")

    def lines_of(self, key):
        return [l for v in self._v if v["key"] == key for l in v["lines"]]

    def repost_invalid(self, key):
        v = next(v for v in self._v if v["key"] == key)
        if "delete_before_validate" in self.f:
            v["lines"] = []
        raise Refused("invalid")

    def seeded_period(self):
        return "2026-10"

    def close_period(self, name):
        self.closed.add(name)

    def post_in(self, name, key, amount):
        if name in self.closed and "closed_accepts" not in self.f:
            raise Refused("period_closed", "period is closed" if "unnamed_refusal" in self.f else f"period {name} is closed")
        self.post("sales", key, amount)

    def restore_period(self, name):
        if "no_restore" not in self.f:
            self.closed.discard(name)

    def period_open(self, name):
        return name not in self.closed

    def dimension_report(self):
        known = ["customer", "plant"]
        line = {"customer": "C1", "plant": None if "null_dimension" in self.f else "P1"}
        return {"sales": {"known": known, "lines": [line]}, "receipt": {"known": known, "lines": [dict(line, plant="P1")]}}

    def get(self, vid):
        return next(v for v in self._v if v["id"] == vid)

    def snapshot(self, vid):
        return repr(self.get(vid))

    def correct(self, vid, new_amount):
        if "updates_in_place" in self.f:
            self.get(vid)["lines"] = self._lines("sales", new_amount)
            return vid
        c = self.post("sales", f"{self.get(vid)['key']}-corr", new_amount)
        if "no_reference" not in self.f:
            self.get(c)["corrects"] = vid
        return c

    def reverse(self, vid):
        orig = self.get(vid)
        lines = [dict(l) for l in orig["lines"]] if "not_netting" in self.f else \
            [{"account": l["account"], "dr": l["cr"], "cr": l["dr"]} for l in orig["lines"]]
        rid = f"V{len(self._v) + 1}"
        self._v.append({"id": rid, "key": orig["key"] + "-rev", "lines": lines,
                        "reverses_voucher_id": None if "no_link" in self.f else vid, "corrects": None})
        return rid

    def allocate_concurrently(self, company, series, fy, n):
        key = (company, series, "*" if "continues_across_years" in self.f else fy)
        out = []
        if "racy" in self.f:
            for _ in range(0, n, 2):
                v = self.counters.get(key, 0) + 1
                self.counters[key] = v
                out += [v, v]
            return out[:n]
        for _ in range(n):
            self.counters[key] = self.counters.get(key, 0) + 1
            out.append(self.counters[key])
        return out

    def adapter_push(self, event):
        if "tax_treatment" in event and "approximates" not in self.f:
            raise Refused("unrepresentable", "cannot represent field tax_treatment")

    def tie_out(self, period):
        ledger = {"value": 1000, "unit": "minor" if "mixed_unit" in self.f else "major", "grain": "document", "period": period}
        source = {"value": 999 if "mismatch" in self.f else 1000, "unit": "major", "grain": "document",
                  "period": "2026-09" if "other_period" in self.f else period}
        return {"ledger": ledger, "source": source}


GATES: "list[Gate]" = [
    make_gate("ACC-1", 9, "every voucher balances, including failure paths", CANON + " 1", acc1, RefLedger,
              "unbalanced_voucher", "failure_leaves_half"),
    make_gate("ACC-2", 9, "validation precedes mutation", CANON + " 2", acc2, RefLedger, "delete_before_validate"),
    make_gate("ACC-3", 9, "posting is idempotent on the source key", CANON + " 3", acc3, RefLedger, "duplicates"),
    make_gate("ACC-4", 9, "a closed period refuses, naming the period", CANON + " 4", acc4, RefLedger,
              "closed_accepts", "unnamed_refusal", "no_restore"),
    make_gate("ACC-5", 9, "dimensions are populated, not null", CANON + " 5", acc5, RefLedger, "null_dimension"),
    make_gate("ACC-6", 9, "a correction is a new document", CANON + " 6", acc6, RefLedger,
              "updates_in_place", "no_reference"),
    make_gate("ACC-7", 9, "a reversal links and nets to zero", CANON + " 7", acc7, RefLedger, "no_link", "not_netting"),
    make_gate("ACC-8", 9, "number series are per company and year, and atomic", CANON + " 8", acc8, RefLedger,
              "racy", "continues_across_years"),
    make_gate("ACC-9", 9, "the adapter refuses what it cannot represent", CANON + " 9", acc9, RefLedger, "approximates"),
    make_gate("ACC-10", 9, "the ledger ties out to the source, denominator stated", CANON + " 10", acc10, RefLedger,
              "mixed_unit", "mismatch", "other_period"),
]
