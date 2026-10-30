# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""Surface 7, "Distributing master data offline": the eight rules of canon/surfaces/07-integration.md
(DST-1 .. DST-8), each a runnable gate.

The rules come from a retail estate that distributes prices, items and limits from a hub to
regions, stores and tills that must keep selling while disconnected. They are written neutrally:
the "hub" is any system of record, a "receiver" is any node that holds a copy, and a "dataset" is
any set of master rows. None of this depends on retail.

The subjects below are reference implementations of the rules, the PROOF side. A product binds the
same calls to its own hub and receivers.
"""
from __future__ import annotations

import re

from .framework import Gate, Refused, make_gate

CANON = "canon/surfaces/07-integration.md, Distributing master data offline, rule"

_NAME = re.compile(r"^[a-z_][a-z0-9_]{2,}(\.[a-z_][a-z0-9_]{2,})+$")


def protected_name_ok(name: str) -> bool:
    """A protected name has at least two dot-separated segments of at least three characters each."""
    return bool(_NAME.match(name or ""))


def starts_a_segment_with(name: str, protected: str) -> bool:
    """True if `protected` is, or begins at a segment boundary inside, `name` (variant spellings included)."""
    return bool(re.search(r"(^|\.)" + re.escape(protected), name))


# --------------------------------------------------------------------------------------------- DST-1

def dst1(s) -> "list[str]":
    """A committed fact in a dead-letter queue can be replayed, never discarded; the list is insert-only; empty fails closed."""
    p = []
    prot = s.protected_types()
    if not prot:
        return ["the protected list is empty in the subject under test"]
    for t in prot:
        d = s.dead_letter(t)
        try:
            s.discard(d, approval="appr-1")
            p.append(f"a committed fact of type {t!r} was discarded")
        except Refused:
            pass
        try:
            s.replay(d)
        except Refused:
            p.append(f"a committed fact of type {t!r} could not be replayed")
        for variant in (t + ".v1", "app." + t, t + "_v2"):
            try:
                s.discard(s.dead_letter(variant), approval="appr-1")
                p.append(f"a variant spelling {variant!r} of a committed type was discarded")
            except Refused:
                pass
    ordinary = s.dead_letter("heartbeat.ping")
    try:
        s.discard(ordinary, approval=None)
        p.append("an ordinary message was discarded without a recorded approval")
    except Refused:
        pass
    try:
        s.discard(ordinary, approval="appr-2")
    except Refused:
        p.append("an ordinary message cannot be discarded even with approval: the guard is blanket")
    for role in s.roles():
        for op in ("update", "delete", "truncate"):
            try:
                s.mutate_list(role, op)
                p.append(f"role {role} could {op} the protected list")
            except Refused:
                pass
    try:
        s.add_protected("service", "stock.counted")
        p.append("a service role inserted into the protected list outside a reviewed change")
    except Refused:
        pass
    try:
        s.discard_with_empty_list("heartbeat.ping")
        p.append("with the protected list emptied a discard was judged instead of failing closed")
    except Refused:
        pass
    return p


# --------------------------------------------------------------------------------------------- DST-2

def dst2(s) -> "list[str]":
    """A protected name needs two segments of three or more characters; variants are blocked at registration."""
    p = []
    for bad in ("bill", "a.b", "ab.cde", "abc.de", "x.committed", ""):
        try:
            s.add_protected("owner", bad)
            p.append(f"the protected name {bad!r} was accepted (too short or too few segments)")
        except Refused:
            pass
    try:
        s.add_protected("owner", "stock.counted")
    except Refused:
        p.append("a well-formed protected name was refused")
    prot = s.protected_types()[0]
    try:
        s.register_contract(f"app.{prot}", link=None)
        p.append("a variant spelling of a protected name registered as an ordinary contract")
    except Refused:
        pass
    try:
        s.register_contract(f"app.{prot}", link=prot)
    except Refused:
        p.append("a variant linked to the protected name it varies was refused")
    try:
        s.register_contract("unrelated.contract", link=prot)
        p.append("a contract was linked to a protected name it does not vary")
    except Refused:
        pass
    try:
        s.register_contract("heartbeat.ping", link=None)
    except Refused:
        p.append("an ordinary contract name was refused")
    return p


class RefDlq:
    """PROOF subject for DST-1 and DST-2. Flaws: discards_committed, discard_unapproved, replay_blocked, exact_match_only,
    list_updatable, list_deletable, list_truncatable, empty_list_allows, service_can_insert, short_segment_ok,
    one_segment_ok, variant_registers_unlinked, link_any_name, blanket_guard."""

    def __init__(self, flaws=frozenset()):
        self.f = frozenset(flaws)
        self.protected = ["bill.committed", "stock.adjusted"]
        self.dl, self.status = {}, {}

    def protected_types(self):
        return list(self.protected)

    def roles(self):
        return ["service", "admin", "owner"]

    def _is_protected(self, t):
        if "exact_match_only" in self.f:
            return t in self.protected
        return any(starts_a_segment_with(t, x) for x in self.protected)

    def dead_letter(self, t):
        i = f"dl{len(self.dl) + 1}"
        self.dl[i], self.status[i] = t, "OPEN"
        return i

    def discard(self, i, approval):
        t = self.dl[i]
        if not approval and "discard_unapproved" not in self.f:
            raise Refused("approval_required")
        if not self.protected and "empty_list_allows" not in self.f:
            raise Refused("empty_list", "no discard can be judged")
        if "blanket_guard" in self.f or (self._is_protected(t) and "discards_committed" not in self.f):
            raise Refused("committed_fact")
        self.status[i] = "DISCARDED"

    def replay(self, i):
        if "replay_blocked" in self.f and self._is_protected(self.dl[i]):
            raise Refused("replay_blocked")
        self.status[i] = "REPLAYED"

    def mutate_list(self, role, op):
        allowed = {"update": "list_updatable", "delete": "list_deletable", "truncate": "list_truncatable"}[op]
        if allowed not in self.f:
            raise Refused("insert_only")

    def add_protected(self, role, name):
        if role != "owner" and "service_can_insert" not in self.f:
            raise Refused("reviewed_change_only")
        ok = protected_name_ok(name)
        if "short_segment_ok" in self.f:
            ok = ok or bool(re.match(r"^[a-z]\.[a-z]{3,}$", name))
        if "one_segment_ok" in self.f:
            ok = ok or bool(re.match(r"^[a-z]{3,}$", name))
        if not ok:
            raise Refused("bad_shape", f"{name!r} needs two segments of at least three characters")
        self.protected.append(name)

    def discard_with_empty_list(self, t):
        saved, self.protected = self.protected, []
        try:
            self.discard(self.dead_letter(t), approval="appr-9")
        finally:
            self.protected = saved

    def register_contract(self, name, link):
        varies = [x for x in self.protected if starts_a_segment_with(name, x)]
        if varies and link is None and "variant_registers_unlinked" not in self.f:
            raise Refused("must_link", f"{name!r} varies protected name {varies[0]!r}: link it or rename")
        if link is not None and "link_any_name" not in self.f and not starts_a_segment_with(name, link):
            raise Refused("bad_link", f"{name!r} does not vary {link!r}")


# --------------------------------------------------------------------------------------------- DST-3

def dst3(s) -> "list[str]":
    """Idempotency key is (tenant, source system, change id); a replay has one effect (gate rule 3)."""
    p = []
    s.apply("T1", "ERP", "chg-1", {"v": 1})
    again = s.apply("T1", "ERP", "chg-1", {"v": 1})
    if s.effects() != 1:
        p.append(f"a replay of one change had {s.effects()} effects")
    if again != "ALREADY_APPLIED":
        p.append(f"a replay answered {again!r}, not ALREADY_APPLIED")
    s.apply("T1", "HR", "chg-1", {"v": 1})
    if s.effects() != 2:
        p.append("the same change id from another source system was treated as a replay")
    s.apply("T2", "ERP", "chg-1", {"v": 1})
    if s.effects() != 3:
        p.append("the same change id and source in another tenant was treated as a replay")
    return p


class RefIdem:
    """PROOF subject for DST-3. Flaws: key_ignores_tenant, key_ignores_source, replay_double_effect."""

    def __init__(self, flaws=frozenset()):
        self.f, self.seen, self.n = frozenset(flaws), set(), 0

    def apply(self, tenant, source, change_id, payload):
        key = (None if "key_ignores_tenant" in self.f else tenant, None if "key_ignores_source" in self.f else source, change_id)
        if key in self.seen:
            if "replay_double_effect" in self.f:
                self.n += 1
            return "ALREADY_APPLIED"
        self.seen.add(key)
        self.n += 1
        return "APPLIED"

    def effects(self):
        return self.n


# --------------------------------------------------------------------------------------------- DST-4

def dst4(s) -> "list[str]":
    """Crosswalk rows supersede and never overwrite (doctrine D2) (gate rule 4)."""
    p = []
    s.map("T1", "ERP", "article", "SRC-1", "G-1", actor="pat")
    s.map("T1", "ERP", "article", "SRC-1", "G-2", actor="sam")
    rows = s.rows("T1", "ERP", "article", "SRC-1")
    if len(rows) != 2:
        p.append(f"after a remap there are {len(rows)} rows: the old mapping was overwritten")
    if sum(1 for r in rows if r["active"]) != 1:
        p.append("exactly one mapping must be active after a remap")
    if not any(r["global_id"] == "G-1" and not r["active"] for r in rows):
        p.append("the original mapping is not preserved as superseded")
    if not all(r.get("actor") for r in rows):
        p.append("a mapping row does not record who made it")
    for op in ("update", "delete"):
        try:
            s.raw(op, "T1", "ERP", "article", "SRC-1")
            p.append(f"a direct {op} of a crosswalk row was accepted")
        except Refused:
            pass
    return p


class RefCrosswalk:
    """PROOF subject for DST-4. Flaws: overwrites, two_active, no_actor, raw_update_allowed, raw_delete_allowed."""

    def __init__(self, flaws=frozenset()):
        self.f, self.r = frozenset(flaws), []

    def map(self, tenant, system, kind, source_id, global_id, actor):
        k = (tenant, system, kind, source_id)
        if "overwrites" in self.f:
            self.r = [x for x in self.r if x["k"] != k]
        elif "two_active" not in self.f:
            for x in self.r:
                if x["k"] == k:
                    x["active"] = False
        self.r.append({"k": k, "global_id": global_id, "active": True, "actor": "" if "no_actor" in self.f else actor})

    def rows(self, tenant, system, kind, source_id):
        return [dict(x) for x in self.r if x["k"] == (tenant, system, kind, source_id)]

    def raw(self, op, *key):
        flaw = "raw_update_allowed" if op == "update" else "raw_delete_allowed"
        if flaw not in self.f:
            raise Refused("append_only")


# --------------------------------------------------------------------------------------------- DST-5

def dst5(s) -> "list[str]":
    """One issuer numbers versions per (tenant, dataset, receiver); gaps and old cursors get an atomic snapshot;
    a snapshot is never older than what is applied; an external snapshot is guarded (gate rule 5)."""
    p = []
    # numbering
    a = [s.issue("T1", "prices", "R1") for _ in range(3)]
    if a != [1, 2, 3]:
        p.append(f"versions for one (tenant, dataset, receiver) are {a}, expected 1, 2, 3")
    if s.issue("T1", "prices", "R2") != 1:
        p.append("a second receiver's versions are not numbered on their own")
    if s.issue("T2", "prices", "R1") != 1:
        p.append("a second tenant's versions are not numbered on their own")
    conc = s.issue_concurrently("T1", "limits", "R1", 20)
    if len(set(conc)) != len(conc):
        p.append("concurrent issuing repeated a version number")
    try:
        s.issue("T1", "prices", "R1", issuer="some-other-node")
        p.append("a second issuer numbered versions for the same dataset")
    except Refused:
        pass
    # gap and retention
    s.set_cursor("RX", 1)
    if s.deliver_delta("RX", 3) != "snapshot":
        p.append("a receiver offered version 3 while holding 1 did not ask for a snapshot")
    if s.held("RX") != 1:
        p.append("a gap moved the cursor before any snapshot was applied")
    s.configure_stream(latest=5, retention_versions=2)
    if s.pull("RX", cursor=1) != "snapshot":
        p.append("a cursor older than the retained versions was not given a snapshot")
    if s.pull("RX", cursor=4) != "delta":
        p.append("a cursor inside retention was given a snapshot instead of the delta")
    # atomic snapshot
    s.load_rows("RX", {"a": 1, "b": 2})
    before = (s.rows_of("RX"), s.held("RX"))
    try:
        s.apply_snapshot("RX", 5, {"a": 10, "b": 20, "c": 30}, fail_after=1)
    except Refused:
        pass
    if (s.rows_of("RX"), s.held("RX")) != before:
        p.append("a snapshot that failed midway left the receiver partly updated")
    s.apply_snapshot("RX", 5, {"c": 30})
    if s.rows_of("RX") != {"c": 30} or s.held("RX") != 5:
        p.append("a snapshot is not applied in one step as the whole dataset (rows absent from it must go)")
    # never older than applied
    try:
        s.request_snapshot("RX", at_version=4)
        p.append("a snapshot older than the highest applied version was served")
    except Refused:
        pass
    # external source guard
    s.set_previous_count("catalogue", 1000)
    try:
        s.build_external_snapshot("catalogue", 10, confirmed_by=None)
        p.append("an external snapshot with a large row-count change was accepted unconfirmed")
    except Refused:
        pass
    try:
        s.build_external_snapshot("catalogue", 10, confirmed_by="not-the-owner")
        p.append("an external snapshot was confirmed by someone who is not the dataset owner")
    except Refused:
        pass
    try:
        s.build_external_snapshot("catalogue", 10, confirmed_by=s.dataset_owner("catalogue"))
    except Refused:
        p.append("the dataset owner could not confirm a large change")
    s.set_previous_count("catalogue", 1000)
    try:
        s.build_external_snapshot("catalogue", 990, confirmed_by=None)
    except Refused:
        p.append("a small row-count change from an external source was refused")
    try:
        s.serve_current_state("catalogue", 10)
    except Refused:
        p.append("serving the issuer's own state in a gap was blocked by the external-source guard")
    return p


class RefDist:
    """PROOF subject for DST-5 and DST-6. Flaws (5): two_issuers, version_shared_across_receivers,
    version_shared_across_tenants, duplicate_versions_concurrent, applies_through_gap, ignores_retention,
    snapshot_partial, snapshot_merges, snapshot_may_regress, external_unguarded, confirm_by_anyone,
    guard_blocks_own_state. Flaws (6): urgent_waits_for_gap, cursor_advances, stale_revives, uses_content_version,
    accepts_non_set_state."""

    OWNER = "catalogue_owner"
    MAX_CHANGE = 0.2

    def __init__(self, flaws=frozenset()):
        self.f = frozenset(flaws)
        self.ver, self.rc, self.prev, self.stream = {}, {}, {}, (0, 0)

    def _r(self, rid):
        return self.rc.setdefault(rid, {"held": 0, "rows": {}, "applied_max": 0, "state": {}})

    # numbering
    def issue(self, tenant, dataset, receiver, issuer="core"):
        if issuer != "core" and "two_issuers" not in self.f:
            raise Refused("not_the_issuer")
        key = (tenant, dataset, receiver)
        if "version_shared_across_receivers" in self.f:
            key = (tenant, dataset)
        if "version_shared_across_tenants" in self.f:
            key = (dataset, receiver)
        self.ver[key] = self.ver.get(key, 0) + 1
        return self.ver[key]

    def issue_concurrently(self, tenant, dataset, receiver, n):
        if "duplicate_versions_concurrent" in self.f:
            out = []
            while len(out) < n:
                v = self.issue(tenant, dataset, receiver)
                out += [v, v]
            return out[:n]
        return [self.issue(tenant, dataset, receiver) for _ in range(n)]

    # gap, retention, snapshot
    def set_cursor(self, rid, held):
        self._r(rid)["held"] = held

    def held(self, rid):
        return self._r(rid)["held"]

    def deliver_delta(self, rid, version):
        r = self._r(rid)
        if version <= r["held"]:
            return "ignored"
        if version == r["held"] + 1 or "applies_through_gap" in self.f:
            r["held"] = version
            return "applied"
        return "snapshot"

    def configure_stream(self, latest, retention_versions):
        self.stream = (latest, retention_versions)

    def pull(self, rid, cursor):
        latest, keep = self.stream
        if cursor >= latest:
            return "current"
        oldest = latest - keep + 1
        if cursor + 1 < oldest and "ignores_retention" not in self.f:
            return "snapshot"
        return "delta"

    def load_rows(self, rid, rows):
        self._r(rid)["rows"] = dict(rows)

    def rows_of(self, rid):
        return dict(self._r(rid)["rows"])

    def apply_snapshot(self, rid, version, rows, fail_after=None):
        r = self._r(rid)
        if "snapshot_partial" in self.f:
            for i, (k, v) in enumerate(rows.items()):
                if fail_after is not None and i >= fail_after:
                    raise Refused("failed_midway")
                r["rows"][k] = v
        else:
            if fail_after is not None and fail_after < len(rows):
                raise Refused("failed_midway")
            new = dict(r["rows"]) if "snapshot_merges" in self.f else {}
            new.update(rows)
            r["rows"] = new
        r["held"] = version
        r["applied_max"] = max(r["applied_max"], version)

    def request_snapshot(self, rid, at_version):
        if at_version < self._r(rid)["applied_max"] and "snapshot_may_regress" not in self.f:
            raise Refused("older_than_applied")

    # external guard
    def dataset_owner(self, dataset):
        return self.OWNER

    def set_previous_count(self, dataset, n):
        self.prev[dataset] = n

    def _large(self, dataset, n):
        prev = self.prev[dataset]
        return prev and abs(n - prev) / prev > self.MAX_CHANGE

    def build_external_snapshot(self, dataset, n, confirmed_by):
        if self._large(dataset, n) and "external_unguarded" not in self.f:
            ok = confirmed_by is not None if "confirm_by_anyone" in self.f else confirmed_by == self.dataset_owner(dataset)
            if not ok:
                raise Refused("needs_owner_confirmation")
        self.prev[dataset] = n

    def serve_current_state(self, dataset, n):
        if self._large(dataset, n) and "guard_blocks_own_state" in self.f:
            raise Refused("needs_owner_confirmation")
        self.prev[dataset] = n

    # --- DST-6
    def apply_change(self, rid, row, state, version, urgent=False, content_version=0, op="set_state"):
        r = self._r(rid)
        if urgent and op != "set_state" and "accepts_non_set_state" not in self.f:
            raise Refused("not_self_contained", "an urgent change must be a set-state operation")
        gap = version > r["held"] + 1
        if not urgent:
            if gap and "applies_through_gap" not in self.f:
                return "gap"
        elif gap and "urgent_waits_for_gap" in self.f:
            return "gap"
        cur = r["state"].get(row, {"state": None, "version": 0, "content": 0})
        newer = content_version > cur["content"] if "uses_content_version" in self.f else version > cur["version"]
        applied = newer or "stale_revives" in self.f
        if applied:
            r["state"][row] = {"state": state, "version": version, "content": content_version}
        if not urgent or "cursor_advances" in self.f:
            r["held"] = max(r["held"], version)
        return "applied" if applied else "stale"

    def row_state(self, rid, row):
        return self._r(rid)["state"].get(row, {}).get("state")


# --------------------------------------------------------------------------------------------- DST-6

def dst6(s) -> "list[str]":
    """Urgent changes are self-contained set-state operations; they may apply out of order; a row changes only if the
    incoming issue version is higher than the row's state version (gate rule 6)."""
    p = []
    s.apply_change("RX", "r1", "active", 1, content_version=7)
    got = s.apply_change("RX", "r1", "blocked", 5, urgent=True, content_version=7)
    if got != "applied" or s.row_state("RX", "r1") != "blocked":
        p.append("an urgent block arriving in a gap was not applied")
    if s.held("RX") != 1:
        p.append(f"an urgent change moved the cursor to {s.held('RX')}; it must stay at 1")
    s.apply_change("RX", "r1", "active", 2, content_version=7)
    if s.row_state("RX", "r1") != "blocked":
        p.append("an older activation, replayed after the block, revived the row")
    s.apply_change("RX", "r1", "active", 6, urgent=True, content_version=3)
    if s.row_state("RX", "r1") != "active":
        p.append("a later-issued activation naming an older content version could not clear the block")
    try:
        s.apply_change("RX", "r1", "blocked", 7, urgent=True, op="decrement_stock")
        p.append("an urgent change that is not a set-state operation was accepted")
    except Refused:
        pass
    return p


# --------------------------------------------------------------------------------------------- DST-7

def dst7(s) -> "list[str]":
    """When several sources speak about one item it is blocked if any source blocks it; the issuer resolves before
    distributing and keeps every source (gate rule 7)."""
    p = []
    s.set_source("i1", "erp", blocked=False)
    s.set_source("i1", "hub", blocked=True, reason="recall", override_role=None, start=10)
    if s.resolve("i1")["sellable"]:
        p.append("an item blocked by one source is sellable")
    s.set_source("i2", "erp", blocked=True, reason="status inactive", start=1)
    s.set_source("i2", "hub", blocked=False)
    if s.resolve("i2")["sellable"]:
        p.append("a later source lifted another source's block")
    s.set_source("i3", "erp", blocked=False)
    s.set_source("i3", "hub", blocked=False)
    if not s.resolve("i3")["sellable"]:
        p.append("an item no source blocks is not sellable")
    s.set_source("i4", "erp", blocked=True, reason="status", override_role="MANAGER", start=1)
    s.set_source("i4", "hub", blocked=True, reason="quality", override_role="DIRECTOR", start=2)
    r = s.resolve("i4")
    if r["override_role"] != "DIRECTOR":
        p.append(f"with two blocking sources the override role is {r['override_role']!r}, not the highest ranked")
    if r["block_reason"] != "status":
        p.append(f"the block reason is {r['block_reason']!r}, not the first blocking source in the fixed order")
    s.set_source("i5", "erp", blocked=True, reason="status", override_role=None, start=1)
    s.set_source("i5", "hub", blocked=True, reason="quality", override_role="DIRECTOR", start=2)
    if s.resolve("i5")["override_role"] is not None:
        p.append("an override role survived although one blocking source names none")
    if len(s.sources("i1")) != 2:
        p.append("the issuer did not keep every source of the item")
    v0 = s.resolve("i1")["version"]
    s.set_source("i1", "hub", blocked=False)
    v1 = s.resolve("i1")["version"]
    s.set_source("i1", "hub", blocked=True, reason="recall", start=20)
    v2 = s.resolve("i1")["version"]
    if not (v1 > v0 and v2 > v1):
        p.append("a new version was not issued when a block ended and when it started")
    return p


class RefMulti:
    """PROOF subject for DST-7. Flaws: last_writer_wins, first_source_only, lowest_override_role,
    override_default_when_one_has_none, drops_sources, no_version_on_change, reason_unordered."""

    ORDER = ["erp", "hub"]
    RANK = {"CLERK": 1, "MANAGER": 2, "DIRECTOR": 3}

    def __init__(self, flaws=frozenset()):
        self.f = frozenset(flaws)
        self.src, self.ver, self.last = {}, {}, {}

    def _view(self, item):
        rows = list(self.src.get(item, {}).values())
        if "first_source_only" in self.f:
            rows = [r for r in rows if r["source"] == "erp"]
        if "last_writer_wins" in self.f and item in self.last:
            rows = [r for r in rows if r["source"] == self.last[item]]
        blockers = sorted((r for r in rows if r["blocked"]), key=lambda r: (self.ORDER.index(r["source"]), r["start"]))
        if not blockers:
            return {"sellable": True, "block_reason": None, "override_role": None}
        roles = [b["override_role"] for b in blockers]
        named = [r for r in roles if r]
        if any(r is None for r in roles) and "override_default_when_one_has_none" not in self.f:
            role = None
        elif named:
            pick = min if "lowest_override_role" in self.f else max
            role = pick(named, key=lambda r: self.RANK[r])
        else:
            role = None
        reason = (blockers[-1] if "reason_unordered" in self.f else blockers[0])["reason"]
        return {"sellable": False, "block_reason": reason, "override_role": role}

    def set_source(self, item, source, blocked, reason="", override_role=None, start=0):
        before = self._view(item)
        row = {"source": source, "blocked": blocked, "reason": reason, "override_role": override_role, "start": start}
        if "drops_sources" in self.f:
            self.src[item] = {source: row}
        else:
            self.src.setdefault(item, {})[source] = row
        self.last[item] = source
        if self._view(item) != before and "no_version_on_change" not in self.f:
            self.ver[item] = self.ver.get(item, 0) + 1
        self.ver.setdefault(item, 0)

    def resolve(self, item):
        return dict(self._view(item), version=self.ver[item])

    def sources(self, item):
        return list(self.src[item].values())


# --------------------------------------------------------------------------------------------- DST-8

def dst8(s) -> "list[str]":
    """Every interface run records counts and balances (duplicate, sequence, balancing); a run that cannot balance is a
    finding, never a pass (gate rule 8)."""
    p = []
    recs = [{"seq": 1, "id": "a", "value": 100}, {"seq": 2, "id": "b", "value": 100}, {"seq": 3, "id": "c", "value": 100}]
    ok = s.run_interface("sales_feed", recs, control={"count": 3, "value": 300})
    if ok["status"] != "OK" or ok["findings"]:
        p.append(f"a clean, balanced run is not OK: {ok['status']} {ok['findings']}")
    if ok["source_count"] != ok["accepted_count"] + ok["rejected_count"] \
            or ok["source_value"] != ok["accepted_value"] + ok["rejected_value"]:
        p.append("the run's reported counts and values do not add up: source != accepted + rejected")
    dup = s.run_interface("sales_feed", recs[:2] + [dict(recs[1], seq=3)], control={"count": 3, "value": 300})
    if "duplicate" not in dup["findings"] or dup["status"] == "OK":
        p.append("a duplicate record in the input was not a finding")
    gap = s.run_interface("sales_feed", [recs[0], recs[1], dict(recs[2], seq=4)], control={"count": 3, "value": 300})
    if "sequence" not in gap["findings"] or gap["status"] == "OK":
        p.append("a missing sequence number was not a finding")
    off = s.run_interface("sales_feed", recs, control={"count": 4, "value": 400})
    if "balancing" not in off["findings"] or off["status"] == "OK":
        p.append("a run whose control totals disagree with what it read was not a finding")
    nocontrol = s.run_interface("sales_feed", recs, control=None)
    if nocontrol["status"] == "OK" or "cannot_balance" not in nocontrol["findings"]:
        p.append("a run with no control total to balance against passed instead of being a finding")
    if len(s.recorded_runs()) != 5:
        p.append(f"{len(s.recorded_runs())} runs were recorded for 5 runs made: a run left no record")
    return p


class RefControls:
    """PROOF subject for DST-8. Flaws: loses_a_record_and_passes, no_duplicate_check, no_sequence_check,
    passes_unbalanced, unbalanceable_passes, failed_run_unrecorded."""

    def __init__(self, flaws=frozenset()):
        self.f, self.runs = frozenset(flaws), []

    def run_interface(self, name, records, control):
        seen, accepted, rejected, findings = set(), [], [], []
        for r in records:
            if r["id"] in seen:
                rejected.append(r)
                if "no_duplicate_check" not in self.f:
                    findings.append("duplicate")
                continue
            seen.add(r["id"])
            accepted.append(r)
        seqs = [r["seq"] for r in records]
        if seqs != list(range(seqs[0], seqs[0] + len(seqs))) and "no_sequence_check" not in self.f:
            findings.append("sequence")
        if "loses_a_record_and_passes" in self.f:
            accepted = accepted[:-1]
        src_c, src_v = len(records), sum(r["value"] for r in records)
        if control is None:
            if "unbalanceable_passes" not in self.f:
                findings.append("cannot_balance")
        elif "passes_unbalanced" not in self.f and (control["count"] != src_c or control["value"] != src_v):
            findings.append("balancing")
        run = {"interface": name, "status": "OK" if not findings else "PARTIAL", "findings": sorted(set(findings)),
               "source_count": src_c, "source_value": src_v,
               "accepted_count": len(accepted), "accepted_value": sum(r["value"] for r in accepted),
               "rejected_count": len(rejected), "rejected_value": sum(r["value"] for r in rejected)}
        if not (run["status"] != "OK" and "failed_run_unrecorded" in self.f):
            self.runs.append(run)
        return run

    def recorded_runs(self):
        return list(self.runs)


GATES: "list[Gate]" = [
    make_gate("DST-1", 7, "a committed fact in a dead-letter queue is replayable, never discardable", CANON + " 1", dst1,
              RefDlq, "discards_committed", "discard_unapproved", "replay_blocked", "exact_match_only", "list_updatable",
              "list_deletable", "list_truncatable", "empty_list_allows", "service_can_insert", "blanket_guard"),
    make_gate("DST-2", 7, "a protected name needs two segments of three characters; variants are blocked", CANON + " 2",
              dst2, RefDlq, "short_segment_ok", "one_segment_ok", "variant_registers_unlinked", "link_any_name"),
    make_gate("DST-3", 7, "idempotency key is (tenant, source system, change id); a replay has one effect", CANON + " 3",
              dst3, RefIdem, "key_ignores_tenant", "key_ignores_source", "replay_double_effect"),
    make_gate("DST-4", 7, "crosswalk rows supersede and never overwrite", CANON + " 4", dst4, RefCrosswalk,
              "overwrites", "two_active", "no_actor", "raw_update_allowed", "raw_delete_allowed"),
    make_gate("DST-5", 7, "one issuer numbers versions; gaps get an atomic snapshot; external snapshots are guarded",
              CANON + " 5", dst5, RefDist, "two_issuers", "version_shared_across_receivers",
              "version_shared_across_tenants", "duplicate_versions_concurrent", "applies_through_gap", "ignores_retention",
              "snapshot_partial", "snapshot_merges", "snapshot_may_regress", "external_unguarded", "confirm_by_anyone",
              "guard_blocks_own_state"),
    make_gate("DST-6", 7, "urgent changes are self-contained set-state and apply out of order; issue order guards a row",
              CANON + " 6", dst6, RefDist, "urgent_waits_for_gap", "cursor_advances", "stale_revives",
              "uses_content_version", "accepts_non_set_state"),
    make_gate("DST-7", 7, "blocked if any source blocks; the issuer resolves and keeps every source", CANON + " 7", dst7,
              RefMulti, "last_writer_wins", "first_source_only", "lowest_override_role",
              "override_default_when_one_has_none", "drops_sources", "no_version_on_change", "reason_unordered"),
    make_gate("DST-8", 7, "every interface run records counts and balances; one that cannot balance is a finding",
              CANON + " 8", dst8, RefControls, "loses_a_record_and_passes", "no_duplicate_check", "no_sequence_check",
              "passes_unbalanced", "unbalanceable_passes", "failed_run_unrecorded"),
]
