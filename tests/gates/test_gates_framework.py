# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""The framework itself: Gap, appeared, Dormant, an unproven gate is refused, the CLI exit codes."""
from gates import DORMANT, FAIL, GAP, PASS, Dormant, Gap, Gate, main, run_gate, selftest
from gates.framework import registry
from gates.tenancy import RefTenancy

TEN2 = next(g for g in registry() if g.id == "TEN-2")


def test_unbound_gate_is_a_gap_not_a_pass():
    assert run_gate(TEN2, {}).status == GAP


def test_good_binding_passes_and_defective_binding_fails():
    assert run_gate(TEN2, {"TEN-2": RefTenancy}).status == PASS
    r = run_gate(TEN2, {"TEN-2": lambda: RefTenancy({"leaks_other_tenant"})})
    assert r.status == FAIL and r.detail


def test_a_gap_is_reported_with_its_reason():
    def bind():
        raise Gap("the product has no tenant table")
    r = run_gate(TEN2, {"TEN-2": bind})
    assert r.status == GAP and "no tenant table" in r.detail[0]


def test_a_gap_that_outlived_its_cause_is_a_fail():
    def bind():
        raise Gap("not built yet", appeared=lambda: True)
    r = run_gate(TEN2, {"TEN-2": bind})
    assert r.status == FAIL and "APPEARED" in r.detail[0]


def test_a_gap_whose_cause_is_still_missing_stays_a_gap():
    def bind():
        raise Gap("not built yet", appeared=lambda: False)
    assert run_gate(TEN2, {"TEN-2": bind}).status == GAP


def test_dormant():
    def bind():
        raise Dormant("no AI-origin command yet")
    assert run_gate(TEN2, {"TEN-2": bind}).status == DORMANT


def test_a_gate_that_cannot_go_red_is_refused_by_selftest():
    vacuous = Gate("X-1", 1, "always green", "canon/surfaces/x.md", lambda s: [], lambda: object(),
                   {"nothing": lambda: object()})
    assert any("NOT caught" in b for b in selftest(vacuous))


def test_a_gate_with_no_planted_defect_is_refused():
    g = Gate("X-2", 1, "unproven", "canon/surfaces/x.md", lambda s: ["red"], lambda: object(), {})
    assert any("never been seen red" in b for b in selftest(g))


def test_a_gate_red_on_its_good_subject_is_refused():
    g = Gate("X-3", 1, "always red", "canon/surfaces/x.md", lambda s: ["red"], lambda: object(), {"p": lambda: object()})
    assert any("good reference subject is red" in b for b in selftest(g))


def test_a_gate_that_crashes_on_a_plant_is_refused():
    class Bad:
        bad = True

    def logic(s):
        if getattr(s, "bad", False):
            raise KeyError("boom")
        return []
    g = Gate("X-4", 1, "crashy", "canon/surfaces/x.md", logic, lambda: object(), {"p": lambda: Bad()})
    assert any("crashed the gate" in b for b in selftest(g))


def test_cli_selftest_exits_zero(capsys):
    assert main(["--selftest"]) == 0
    assert "ALL PROVEN" in capsys.readouterr().out


def test_cli_list_names_the_canon_line(capsys):
    assert main(["--list", "--surface", "3"]) == 0
    out = capsys.readouterr().out
    assert "RBAC-9" in out and "03-rbac.md" in out


def test_cli_unbound_run_is_all_gaps_exit_zero_but_strict_fails(capsys):
    assert main([]) == 0
    assert main(["--strict"]) == 1
    capsys.readouterr()


def test_cli_fails_on_a_defective_product(tmp_path, monkeypatch, capsys):
    (tmp_path / "myprod_bindings.py").write_text(
        "from gates.tenancy import RefTenancy\nBINDINGS = {'TEN-2': lambda: RefTenancy({'leaks_other_tenant'})}\n")
    monkeypatch.syspath_prepend(str(tmp_path))
    assert main(["--bindings", "myprod_bindings", "--surface", "1"]) == 1
    assert "FAIL" in capsys.readouterr().out
