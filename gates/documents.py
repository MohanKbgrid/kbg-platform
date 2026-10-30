# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""Surface 5, Documents and required evidence: the seven gate tests of canon/surfaces/05-documents.md (DOC-1 .. DOC-7)."""
from __future__ import annotations

import hashlib

from .framework import Gate, Refused, make_gate

CANON = "canon/surfaces/05-documents.md, Gate tests"
NEEDED = "counterfoil_photo"


def doc1(s) -> "list[str]":
    """A required document blocks the transition, naming the missing type; attaching it unblocks (gate 1)."""
    p = []
    try:
        s.complete("A", "obj-1")
        p.append("the step completed without the required document")
    except Refused as e:
        if NEEDED not in e.message:
            p.append(f"the refusal does not name the missing type: {e.message!r}")
    s.attach("A", "obj-1", NEEDED)
    try:
        s.complete("A", "obj-1")
    except Refused as e:
        p.append(f"the step still refuses with the document attached: {e.message!r}")
    return p


def doc2(s) -> "list[str]":
    """Requirements are per tenant: A blocks, B proceeds, with no code difference (gate 2)."""
    p = []
    try:
        s.complete("A", "obj-2")
        p.append("company A, which requires the document, was not blocked")
    except Refused:
        pass
    try:
        s.complete("B", "obj-2")
    except Refused:
        p.append("company B, which does not require it, was blocked")
    return p


def doc3(s) -> "list[str]":
    """A generated artifact is stored with a checksum and re-served as stored, never re-rendered (gate 3)."""
    doc_id = s.generate("gate-pass-1")
    meta = s.metadata(doc_id)
    stored = s.fetch(doc_id)
    p = []
    if meta.get("checksum") != hashlib.sha256(stored).hexdigest():
        p.append("the document has no checksum, or it is not the checksum of its bytes")
    s.change_template()
    if s.fetch(doc_id) != stored:
        p.append("the bytes changed after the template changed: the artifact is re-rendered, not re-served")
    return p


def doc4(s) -> "list[str]":
    """A reprint is labelled DUPLICATE and counted (gate 4)."""
    doc_id = s.generate("gate-pass-2")
    first, second = s.print_document(doc_id), s.print_document(doc_id)
    p = []
    if first["label"] == "DUPLICATE":
        p.append("the first print is labelled DUPLICATE")
    if second["label"] != "DUPLICATE":
        p.append("the second print is not labelled DUPLICATE")
    if s.metadata(doc_id).get("print_count") != 2:
        p.append(f"print_count is {s.metadata(doc_id).get('print_count')!r}, expected 2")
    return p


def doc5(s) -> "list[str]":
    """Numbering is atomic (no duplicates, no gaps) and independent per company (gate 5)."""
    n = 40
    nums = s.allocate_concurrently("A", "INV", "2026-27", n)
    p = []
    if len(set(nums)) != len(nums):
        p.append(f"concurrent allocation produced {len(nums) - len(set(nums))} duplicate number(s)")
    if sorted(set(nums)) != list(range(1, n + 1)):
        p.append("concurrent allocation left a gap or did not start at 1")
    other = s.allocate_concurrently("B", "INV", "2026-27", 3)
    if sorted(other) != [1, 2, 3]:
        p.append(f"a second company's series is not independent: {sorted(other)}")
    return p


def doc6(s) -> "list[str]":
    """The same client-minted document id submitted three times yields one row (gate 6)."""
    for _ in range(3):
        s.submit("11111111-1111-4111-8111-111111111111", b"photo-bytes")
    return [] if s.count() == 1 else [f"three submissions of one client id produced {s.count()} rows"]


def doc7(s) -> "list[str]":
    """Metadata does not live in the filename: renaming the blob changes nothing the database says (gate 7)."""
    doc_id = s.generate("gate-pass-3")
    before = s.metadata(doc_id)
    s.rename_blob(doc_id)
    after = s.metadata(doc_id)
    return [] if before == after else [f"renaming the stored blob changed what the document reports: {before!r} -> {after!r}"]


class RefDocs:
    """PROOF subject. Flaws: decoration_only, unnamed_refusal, global_requirement, rerenders, no_checksum, no_label,
    no_count, racy, shared_across_companies, gaps, server_mints_id, infers_from_filename."""

    def __init__(self, flaws=frozenset()):
        self.f = frozenset(flaws)
        self.attached, self.req, self.docs, self.template = set(), {"A"}, {}, "v1"
        self.counters, self.rows, self.blob_names = {}, {}, {}

    def attach(self, company, obj, typ):
        self.attached.add((company, obj, typ))

    def complete(self, company, obj):
        if "decoration_only" in self.f:
            return
        needs = self.req if "global_requirement" not in self.f else {"A", "B"}
        if company in needs and (company, obj, NEEDED) not in self.attached:
            raise Refused("missing_document", "a required document is missing" if "unnamed_refusal" in self.f
                          else f"missing required document type {NEEDED}")

    def _render(self, key):
        return f"{key}|{self.template}".encode()

    def generate(self, key):
        did = f"d{len(self.docs) + 1}"
        data = self._render(key)
        self.docs[did] = {"key": key, "bytes": data, "prints": 0,
                          "checksum": "" if "no_checksum" in self.f else hashlib.sha256(data).hexdigest()}
        self.blob_names[did] = f"blob-{did}"
        return did

    def metadata(self, did):
        d = self.docs[did]
        if "infers_from_filename" in self.f:
            return {"checksum": d["checksum"], "print_count": d["prints"], "name": self.blob_names[did]}
        return {"checksum": d["checksum"], "print_count": d["prints"]}

    def fetch(self, did):
        d = self.docs[did]
        return self._render(d["key"]) if "rerenders" in self.f else d["bytes"]

    def change_template(self):
        self.template = "v2"

    def print_document(self, did):
        d = self.docs[did]
        d["prints"] += 0 if "no_count" in self.f else 1
        n = d.setdefault("n", 0) + 1
        d["n"] = n
        return {"label": "DUPLICATE" if n > 1 and "no_label" not in self.f else "ORIGINAL"}

    def allocate_concurrently(self, company, series, fy, n):
        key = ("*" if "shared_across_companies" in self.f else company, series, fy)
        out = []
        if "racy" in self.f:                    # workers in pairs read the same counter: a lost update
            for _ in range(0, n, 2):
                v = self.counters.get(key, 0) + 1
                self.counters[key] = v
                out += [v, v]
            return out[:n]
        for _ in range(n):
            self.counters[key] = self.counters.get(key, 0) + 1
            out.append(self.counters[key])
            if "gaps" in self.f and len(out) % 10 == 0:
                self.counters[key] += 1          # a failed attempt burns a number
        return out

    def submit(self, client_id, data):
        rid = f"srv-{len(self.rows)}" if "server_mints_id" in self.f else client_id
        self.rows[rid] = data

    def count(self):
        return len(self.rows)

    def rename_blob(self, did):
        self.blob_names[did] = "renamed.bin"


GATES: "list[Gate]" = [
    make_gate("DOC-1", 5, "a required document blocks the transition", CANON + " 1", doc1, RefDocs,
              "decoration_only", "unnamed_refusal"),
    make_gate("DOC-2", 5, "requirements are per tenant", CANON + " 2", doc2, RefDocs, "global_requirement"),
    make_gate("DOC-3", 5, "a generated artifact is stored, not re-rendered", CANON + " 3", doc3, RefDocs,
              "rerenders", "no_checksum"),
    make_gate("DOC-4", 5, "a reprint is labelled and counted", CANON + " 4", doc4, RefDocs, "no_label", "no_count"),
    make_gate("DOC-5", 5, "numbering is atomic and scoped", CANON + " 5", doc5, RefDocs,
              "racy", "shared_across_companies", "gaps"),
    make_gate("DOC-6", 5, "a re-flushed capture does not duplicate", CANON + " 6", doc6, RefDocs, "server_mints_id"),
    make_gate("DOC-7", 5, "metadata does not live in the filename", CANON + " 7", doc7, RefDocs, "infers_from_filename"),
]
