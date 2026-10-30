# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""Surface 3, RBAC: the nine gate tests of canon/surfaces/03-rbac.md (RBAC-1 .. RBAC-9).

RBAC-9 (a denial names its kind, and only a known one) is newer than `bases/core`: the base's
`Decision` carries a reason and `who_can` but no `kind` yet (canon divergence register, W5 item H2).
The gate is therefore proven here against a reference subject, and a product vendoring the base
will see it fail until the base is updated.
"""
from __future__ import annotations

import ast

from .framework import Gate, Refused, make_gate

CANON = "canon/surfaces/03-rbac.md, Gate tests"
KINDS = ("AUTHORITY", "STATE_GATE", "CONFIG_GATE", "PRECONDITION", "READINESS", "APPROVAL_PENDING", "COMPLETED")


def rbac1(s) -> "list[str]":
    """A new action is denied for every existing role until granted (gate 1)."""
    s.add_action("brand.new.action")
    p = [f"role {r} may perform a never-granted action" for r in s.roles() if s.can(r, "brand.new.action")["allowed"]]
    s.grant(s.roles()[0], "brand.new.action")
    if not s.can(s.roles()[0], "brand.new.action")["allowed"]:
        p.append("an explicit grant did not allow the action")
    return p


def _role_literals(tree: ast.AST, role_codes) -> "list[tuple[int, str]]":
    roles = {r.lower() for r in role_codes}
    found = []

    def lits(n):
        return [x.value for x in ast.walk(n) if isinstance(x, ast.Constant) and isinstance(x.value, str)]

    def names_role(n):
        for x in ast.walk(n):
            nm = x.attr if isinstance(x, ast.Attribute) else x.id if isinstance(x, ast.Name) else ""
            if nm.lower() in ("role", "roles", "role_code", "user_role"):
                return True
        return False

    def inspect(test):
        for c in [n for n in ast.walk(test) if isinstance(n, ast.Compare)]:
            parts = [c.left] + list(c.comparators)
            L = [v for part in parts for v in lits(part)]
            if any(v.lower() in roles for v in L) or (L and names_role(c)):
                found.append((c.lineno, ast.unparse(c)[:100]))

    for n in ast.walk(tree):
        if isinstance(n, (ast.If, ast.IfExp, ast.While, ast.Assert)):
            inspect(n.test)
        elif isinstance(n, ast.comprehension):
            for t in n.ifs:
                inspect(t)
    return found


def rbac2(s) -> "list[str]":
    """No role code appears in a conditional of application code (gate 2). Crude, and it catches the real thing."""
    p = []
    for path, text in sorted(s.sources.items()):
        try:
            tree = ast.parse(text)
        except SyntaxError as e:
            p.append(f"{path} does not parse: {e.msg}")
            continue
        p += [f"{path}:{ln} a role name in a conditional: {t}" for ln, t in _role_literals(tree, s.role_codes)]
    return p


def rbac3(s) -> "list[str]":
    """Scope scopes: a person with plant A reads A, not B, and cannot write B despite the permission (gate 3)."""
    s.set_scope("pat", "A")
    p = []
    rows = s.read("pat", "A") + s.read("pat", "B")
    if any(r["plant"] == "B" for r in rows):
        p.append("a person scoped to plant A read plant B's rows")
    try:
        s.write("pat", "B")
        p.append("a person scoped to plant A wrote to plant B with a valid permission")
    except Refused:
        pass
    return p


def rbac4(s) -> "list[str]":
    """A position change moves permissions, queue and approval authority, by one assignment row (gate 4)."""
    s.assign_position("pat", "X")
    before = s.snapshot("pat")
    edits = s.edits_made()
    s.assign_position("pat", "Y")
    after = s.snapshot("pat")
    p = [f"after the move the {k} did not change" for k in ("permissions", "queue", "approval_limit") if before[k] == after[k]]
    if s.edits_made() - edits != 1:
        p.append(f"the move edited {s.edits_made() - edits} rows, not exactly one assignment row")
    return p


def rbac5(s) -> "list[str]":
    """The button and the API agree: enabled:false with reason and kind, and a 403 with the same ones (gate 5)."""
    a = s.availability("nobody", "order.correct")
    status, body = s.call("nobody", "order.correct")
    p = []
    if a.get("enabled") is not False or not a.get("reason") or a.get("kind") not in KINDS:
        p.append(f"a denied action must be enabled:false with a reason and a known kind: {a!r}")
    if status != 403:
        p.append(f"the endpoint called anyway answered {status!r}, not 403")
    else:
        if body.get("reason") != a.get("reason"):
            p.append(f"the 403 reason {body.get('reason')!r} is not the availability reason {a.get('reason')!r}")
        if body.get("kind") != a.get("kind"):
            p.append(f"the 403 kind {body.get('kind')!r} is not the availability kind {a.get('kind')!r}")
    if s.availability("granted", "order.correct").get("enabled") is not True:
        p.append("a granted action is not enabled")
    return p


def rbac6(s) -> "list[str]":
    """SoD refuses at assignment, naming the conflict: not a warning, not a later report (gate 6)."""
    s.assign_role("pat", "REQUESTER")
    p = []
    try:
        r = s.assign_role("pat", "APPROVER")
        p.append(f"both halves of a conflict pair were assigned to one person (answer: {r!r})")
    except Refused as e:
        if s.conflict_name not in e.message:
            p.append(f"the refusal does not name the conflict: {e.message!r}")
    if s.roles_of("pat") != {"REQUESTER"}:
        p.append(f"the refused assignment left a role behind: {sorted(s.roles_of('pat'))}")
    return p


def rbac7(s) -> "list[str]":
    """Delegation: the log records acted-for; past the end date the action is denied (gate 7)."""
    s.delegate("boss", "deputy", days=5)
    p = []
    if not s.act("deputy", "report.sign")["allowed"]:
        p.append("a valid delegation did not allow the action")
    if not any(e.get("acted_for") == "boss" for e in s.decision_log()):
        p.append("the log does not record who the action was taken for")
    s.advance_days(6)
    if s.act("deputy", "report.sign")["allowed"]:
        p.append("the delegation still allows the action after its end date")
    return p


def rbac8(s) -> "list[str]":
    """The decision log records allows as well as denials (gate 8)."""
    s.act("clerk", "order.read")
    s.act("clerk", "order.delete")
    log = s.decision_log()
    p = []
    if not any(e["allowed"] for e in log):
        p.append("a permitted action left no log row")
    if not any(not e["allowed"] for e in log):
        p.append("a denied action left no log row")
    return p


def rbac9(s) -> "list[str]":
    """A denial names its kind, only a known one, and never without a reason (gate 9)."""
    p = []
    for k in KINDS:
        d = s.denial_for(k)
        if d.get("kind") != k:
            p.append(f"a {k} denial carried kind {d.get('kind')!r}")
        if not (d.get("reason") or "").strip():
            p.append(f"a {k} denial carries no reason")
    for kind, reason, what in (("NOT_A_KIND", "x", "an unknown kind"), ("AUTHORITY", "  ", "a blank reason")):
        try:
            s.build_denial(kind, reason)
            p.append(f"a denial with {what} was accepted")
        except (Refused, ValueError):
            pass
    return p


class RefAuthority:
    """PROOF subject. Flaws: default_allow, role_literal, role_attribute, role_in_list, read_leaks, write_unscoped,
    perms_stuck, queue_stuck, approvals_stuck, edits_more, no_reason, no_kind, different_reason, different_kind,
    wrong_status, no_sod, warning_only, unnamed_conflict, leaves_role, no_acted_for, never_expires, denials_only,
    allows_only, kind_dropped, always_authority, accepts_unknown_kind, accepts_blank_reason."""

    conflict_name = "REQUESTER_vs_APPROVER"
    role_codes = {"PLANT_MGR", "BILLING"}
    POS = {"X": ({"a.read"}, {"q-x"}, 100), "Y": ({"a.read", "a.approve"}, {"q-y"}, 5000)}

    def __init__(self, flaws=frozenset()):
        self.f = frozenset(flaws)
        self.grants, self.actions, self.scopes, self.pos, self._edits = {}, set(), {}, {}, 0
        self.role_map, self.deleg, self.today, self.log = {}, {}, 0, []
        self._first_pos = {}

    @property
    def sources(self):
        bad = {"role_literal": "def f(u):\n    if u.group == 'PLANT_MGR':\n        return 1\n",
               "role_attribute": "def f(u):\n    return 1 if u.role == 'whatever' else 0\n",
               "role_in_list": "def f(code):\n    assert code in ('BILLING', 'x')\n"}
        src = {"app/ok.py": "def f(p):\n    if p.can('x'):\n        return 1\n"}
        for k, v in bad.items():
            if k in self.f:
                src["app/bad.py"] = v
        return src

    def roles(self):
        return ["clerk", "manager"]

    def add_action(self, a):
        self.actions.add(a)

    def grant(self, role, a):
        self.grants.setdefault(role, set()).add(a)

    def can(self, role, a):
        allowed = a in self.grants.get(role, set()) or "default_allow" in self.f
        return {"allowed": allowed}

    def set_scope(self, who, plant):
        self.scopes[who] = plant

    def read(self, who, plant):
        ok = plant == self.scopes[who] or "read_leaks" in self.f
        return [{"plant": plant}] if ok else []

    def write(self, who, plant):
        if plant != self.scopes[who] and "write_unscoped" not in self.f:
            raise Refused("out_of_scope")

    def assign_position(self, who, pos):
        self.pos[who] = pos
        self._first_pos.setdefault(who, pos)
        self._edits += 2 if "edits_more" in self.f else 1

    def snapshot(self, who):
        cur, first = self.POS[self.pos[who]], self.POS[self._first_pos[who]]
        perms, queue, lim = cur
        return {"permissions": first[0] if "perms_stuck" in self.f else perms,
                "queue": first[1] if "queue_stuck" in self.f else queue,
                "approval_limit": first[2] if "approvals_stuck" in self.f else lim}

    def edits_made(self):
        return self._edits

    def availability(self, actor, action):
        if actor == "granted":
            return {"enabled": True, "reason": None, "kind": None}
        return {"enabled": False, "reason": "" if "no_reason" in self.f else f"no grant of {action}",
                "kind": None if "no_kind" in self.f else "AUTHORITY"}

    def call(self, actor, action):
        if actor == "granted":
            return 200, {}
        return (200 if "wrong_status" in self.f else 403), {
            "reason": "forbidden" if "different_reason" in self.f else f"no grant of {action}",
            "kind": "STATE_GATE" if "different_kind" in self.f else "AUTHORITY"}

    def assign_role(self, who, role):
        have = self.role_map.setdefault(who, set())
        clash = {role} | have >= {"REQUESTER", "APPROVER"}
        if clash and "no_sod" not in self.f:
            if "leaves_role" in self.f:
                have.add(role)
            if "warning_only" in self.f:
                have.add(role)
                return "warning: conflict"
            raise Refused("sod_conflict", "not allowed" if "unnamed_conflict" in self.f
                          else f"segregation-of-duties conflict {self.conflict_name}")
        have.add(role)
        return "ok"

    def roles_of(self, who):
        return set(self.role_map.get(who, ()))

    def delegate(self, grantor, grantee, days):
        self.deleg[grantee] = (grantor, self.today + days)

    def advance_days(self, n):
        self.today += n

    def act(self, who, action):
        g = self.deleg.get(who)
        live = bool(g) and ("never_expires" in self.f or self.today <= g[1])
        allowed = live or (who == "clerk" and action == "order.read")
        entry = {"actor": who, "action": action, "allowed": allowed,
                 "acted_for": g[0] if live and "no_acted_for" not in self.f else None}
        if (allowed and "denials_only" not in self.f) or (not allowed and "allows_only" not in self.f):
            self.log.append(entry)
        return {"allowed": allowed}

    def decision_log(self):
        return list(self.log)

    def build_denial(self, kind, reason):
        if kind not in KINDS and "accepts_unknown_kind" not in self.f:
            raise Refused("unknown_kind")
        if not reason.strip() and "accepts_blank_reason" not in self.f:
            raise Refused("blank_reason")
        return {"allowed": False, "kind": None if "kind_dropped" in self.f else kind, "reason": reason}

    def denial_for(self, kind):
        d = self.build_denial("AUTHORITY" if "always_authority" in self.f else kind, f"reason for {kind}")
        return d


GATES: "list[Gate]" = [
    make_gate("RBAC-1", 3, "a permission not granted is denied", CANON + " 1", rbac1, RefAuthority, "default_allow"),
    make_gate("RBAC-2", 3, "role names appear in no conditional", CANON + " 2", rbac2, RefAuthority,
              "role_literal", "role_attribute", "role_in_list"),
    make_gate("RBAC-3", 3, "scope actually scopes, reads and writes", CANON + " 3", rbac3, RefAuthority,
              "read_leaks", "write_unscoped"),
    make_gate("RBAC-4", 3, "a position change moves everything with one row", CANON + " 4", rbac4, RefAuthority,
              "perms_stuck", "queue_stuck", "approvals_stuck", "edits_more"),
    make_gate("RBAC-5", 3, "the button and the API agree on reason and kind", CANON + " 5", rbac5, RefAuthority,
              "no_reason", "no_kind", "different_reason", "different_kind", "wrong_status"),
    make_gate("RBAC-6", 3, "SoD refuses at assignment, naming the conflict", CANON + " 6", rbac6, RefAuthority,
              "no_sod", "warning_only", "unnamed_conflict", "leaves_role"),
    make_gate("RBAC-7", 3, "delegation expires and is attributable", CANON + " 7", rbac7, RefAuthority,
              "no_acted_for", "never_expires"),
    make_gate("RBAC-8", 3, "the decision log records allows too", CANON + " 8", rbac8, RefAuthority,
              "denials_only", "allows_only"),
    make_gate("RBAC-9", 3, "a denial names its kind, and only a known one", CANON + " 9", rbac9, RefAuthority,
              "kind_dropped", "always_authority", "accepts_unknown_kind", "accepts_blank_reason",
              note="bases/core Decision has no `kind` yet (canon divergence register, W5 H2): the base does not "
                   "conform. Proven here against a reference subject."),
]
