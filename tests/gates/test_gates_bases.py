# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""bases/core judged by the kit (gates/bindings_bases.py)."""
from gates import FAIL, GAP, PASS, registry, run_gate
from gates import bindings_bases as bb

BY_ID = {g.id: g for g in registry()}


def test_the_base_passes_every_gate_it_can_be_a_subject_of():
    for gid in ("RBAC-1", "RBAC-8", "CFG-3", "DOC-6", "INT-4", "INT-5", "INT-7", "INT-8", "INT-9"):
        r = run_gate(BY_ID[gid], bb.BINDINGS)
        assert r.status == PASS, (gid, r.detail)


def test_the_base_conforms_on_denial_kind():
    for gid in ("RBAC-5", "RBAC-9"):
        r = run_gate(BY_ID[gid], bb.BINDINGS)
        assert r.status == PASS, r.detail


def test_the_gap_turns_into_a_fail_when_the_base_grows_a_kind():
    """The `appeared` mechanism: once the fact exists, a binding that still says Gap is a FAIL. The base has a kind
    now, so a binding written back when it had none must be red until it is rewritten."""
    r = run_gate(BY_ID["RBAC-9"], {"RBAC-9": bb._kind_gap("RBAC-9")})
    assert r.status == FAIL and "APPEARED" in r.detail[0]


def test_the_gate_goes_red_against_a_broken_real_base_dispatcher():
    """INT-9 can go red against the real base: a dispatcher that counts an attempt while held."""
    class Broken(bb.BaseOutboxSubject):
        def dispatch(self):
            code = super().dispatch()
            if not self.box.mode.may_send:
                for r in self.rows.values():
                    r.attempts += 1
            return code
    assert BY_ID["INT-9"].logic(Broken())
