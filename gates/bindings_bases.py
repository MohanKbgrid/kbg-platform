# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""A worked BINDING: `bases/core` judged by the kit.

This is the example of how a product binds the gates, and it is also the base's own conformance
statement. Run it with

    python -m gates --bindings gates.bindings_bases

Gates the base can be a subject of are bound to adapters over its real primitives (`Authority`,
`Outbox` with `decide()`, `VersionedWriter`, `capture_id`). RBAC-5 and RBAC-9 are bound to `Decision.deny(kind=...)`;
`_kind_gap` is kept only to test the `appeared` mechanism (a gap turns into a FAIL once the fact exists, so a gap cannot
outlive its cause). Every other gate is unbound here: the base has no code mapping, tenancy, ledger or agent concept to judge.
"""
from __future__ import annotations

import os
import sys
from typing import Any, Callable, Dict

from .framework import Gap


def _base():
    src = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "bases", "core", "src")
    if src not in sys.path:
        sys.path.insert(0, src)
    import kbg_platform_core as k  # noqa: PLC0415
    from kbg_platform_core import outbox as ob  # noqa: PLC0415
    return k, ob


# ------------------------------------------------------------------------------ RBAC (Authority)

class BaseAuthoritySubject:
    """RBAC-1 and RBAC-8 over `Authority`: a grant table, deny by default, every decision logged."""

    def __init__(self) -> None:
        k, _ = _base()
        self.grants: Dict[str, set] = {"clerk": {"order.read"}}
        self.log: list = []
        grants = self.grants

        class _Auth(k.Authority):
            def _evaluate(self, actor, action, obj=None):
                return k.Decision.allow() if action in grants.get(actor, set()) else None

        self.auth = _Auth(log=self.log.append)

    def roles(self):
        return ["clerk", "manager"]

    def add_action(self, a):
        pass

    def grant(self, role, a):
        self.grants.setdefault(role, set()).add(a)

    def can(self, role, a):
        return {"allowed": self.auth.check(role, a).allowed}

    def act(self, who, action):
        return {"allowed": self.auth.check(who, action).allowed}

    def decision_log(self):
        return list(self.log)


class BaseKindSubject:
    """RBAC-5 and RBAC-9 over the base's `Decision` and `Authority`: a denial carries a reason AND a known kind."""

    def __init__(self) -> None:
        k, _ = _base()
        self.k = k

        class _Auth(k.Authority):
            def _evaluate(self, actor, action, obj=None):
                if actor == "granted":
                    return k.Decision.allow()
                return k.Decision.deny("requires the Plant Manager role", who_can="Plant Manager")

        self.auth = _Auth()

    def availability(self, who, action):
        return self.auth.check(who, action).as_availability()

    def call(self, who, action):
        try:
            self.auth.require(who, action)
            return 200, {}
        except self.k.PermissionDenied as e:
            return 403, e.decision.as_blocked_by()

    def denial_for(self, kind):
        d = self.k.Decision.deny(f"blocked: {kind.lower()}", kind=kind)
        return {"kind": d.kind, "reason": d.reason}

    def build_denial(self, kind, reason):
        return self.k.Decision.deny(reason, kind=kind)       # raises ValueError for an unknown kind or a blank reason


# ------------------------------------------------------------------------------ Integration (Outbox)

class BaseOutboxSubject:
    """INT-4, 5, 7, 8, 9 over `Outbox` and `decide()`; every transition is the base's own (settle / release_held)."""

    def __init__(self) -> None:
        k, ob = _base()
        self.k, self.ob = k, ob
        self.rows: Dict[Any, Any] = {}
        rows = self.rows

        class _Store:
            def get(self, topic, key):
                return rows.get((topic, key))

            def upsert(self, row):
                rows[(row.topic, row.source_key)] = row
                return row

        self.box = k.Outbox(k.Mode.PRODUCTION, _Store())
        self.calls, self.far_error, self.failures = 0, False, 0

    def set_mode(self, m):
        self.box.mode = self.k.Mode(m)

    def mode(self):
        return self.box.mode.value

    def enqueue(self, topic, key):
        self.box.enqueue(topic=topic, source_key=key, payload={})
        return (topic, key)

    def row_count(self):
        return len(self.rows)

    def all_rows(self):
        return [{"state": r.state.value, "attempts": r.attempts} for r in self.rows.values()]

    def row_states(self):
        return [r["state"] for r in self.all_rows()]

    def outbound_calls(self):
        return self.calls

    def force_far_error(self, on):
        self.far_error = on

    def recorded_failures(self):
        return self.failures

    def dispatch(self):
        """Drive the BASE: release_held when the gate opens, then settle() every row. The adapter owns only the far
        side (a counter and a switch); every state change comes from Outbox itself, so a defect in the base is judged."""
        State = self.k.State
        code = 0
        for row in list(self.rows.values()):
            if row.state in (State.CONFIRMED, State.DEAD_LETTER):
                continue
            if self.box.mode.may_send:
                self.box.release_held(row)
                self.calls += 1
                result = {"ok": False, "error": "far side refused"} if self.far_error else {"ok": True}
            else:
                result = self.box.held_result()
                if row.state is State.QUEUED:
                    row.state = State.HELD          # a row queued before the gate shut is held, not sent
            before = row.attempts
            self.box.settle(row, result)
            if row.state in (State.FAILED, State.DEAD_LETTER) and row.attempts > before:
                self.failures += 1
                code = 1
        return code

    def fail_push(self, topic, key):
        self.enqueue(topic, key)
        self.far_error = True
        self.dispatch()

    def retry(self, topic, key):
        self.far_error = False
        self.dispatch()

    def rows_of(self, topic, key):
        return [{"state": r.state.value, "attempts": r.attempts} for (t, kk), r in self.rows.items() if (t, kk) == (topic, key)]


# ------------------------------------------------------------------------------ Config (VersionedWriter)

class BaseVersionedSecretSubject:
    """CFG-3 over `VersionedWriter`: a rotation supersedes, one version stays active, each is attributed."""

    def __init__(self) -> None:
        k, _ = _base()
        self.k, self.table = k, []
        table = self.table

        class _Store:
            def get_active(self, key):
                for i, r in enumerate(table):
                    if r["active"]:
                        return k.VersionedRecord(key, r["value"], r["version"], i)
                return None

            def close(self, record, actor):
                table[record.id]["active"] = False

            def insert(self, key, value, version, supersedes, actor, **extra):
                table.append({"value": value, "version": version, "active": True, "changed_by": actor})
                return len(table) - 1

        self.writer = k.VersionedWriter(_Store())

    def store_secret(self, v, actor="system"):
        self.writer.set(("svc",), v, actor=actor)

    def rotate(self, v, actor):
        self.writer.set(("svc",), v, actor=actor)

    def versions(self):
        return [dict(r) for r in self.table]


# ------------------------------------------------------------------------------ Documents (capture_id)

class BaseCaptureSubject:
    """DOC-6 over `capture_id`: the client-minted id is the identity, so a re-flush collides."""

    def __init__(self) -> None:
        self.k, _ = _base()
        self.rows: Dict[Any, Any] = {}

    def submit(self, client_id, data):
        self.rows[self.k.capture_id(client_id)] = data

    def count(self):
        return len(self.rows)


def _kind_gap(gate: str) -> Callable[[], Any]:
    def bind():
        k, _ = _base()
        raise Gap("bases/core Decision carries no denial `kind` yet (canon divergence register, W5 item H2); "
                  f"{gate} cannot be judged until it does",
                  appeared=lambda: "kind" in k.Decision.__dataclass_fields__)
    return bind


BINDINGS: Dict[str, Callable[[], Any]] = {
    "RBAC-1": BaseAuthoritySubject,
    "RBAC-5": BaseKindSubject,
    "RBAC-8": BaseAuthoritySubject,
    "RBAC-9": BaseKindSubject,
    "CFG-3": BaseVersionedSecretSubject,
    "DOC-6": BaseCaptureSubject,
    "INT-4": BaseOutboxSubject,
    "INT-5": BaseOutboxSubject,
    "INT-7": BaseOutboxSubject,
    "INT-8": BaseOutboxSubject,
    "INT-9": BaseOutboxSubject,
}
