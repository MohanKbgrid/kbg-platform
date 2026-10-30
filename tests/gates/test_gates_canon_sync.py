# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""The kit and the canon stay in step: every numbered gate test in a surface spec has a runnable gate."""
import re
from pathlib import Path

import pytest

from gates import registry

CANON = Path(__file__).resolve().parents[2] / "canon" / "surfaces"
FILES = {"TEN": "01-tenancy", "CFG": "02-config", "RBAC": "03-rbac", "WF": "04-workflow", "DOC": "05-documents",
         "UX": "06-experience", "INT": "07-integration", "AI": "08-runtime-ai", "ACC": "09-accounting",
         "CRM": "10-crm-seam"}
IDS = {g.id for g in registry()}


def gate_test_numbers(text: str) -> "list[int]":
    m = re.search(r"^## Gate tests.*?(?=^## |\Z)", text, re.S | re.M)
    assert m, "no '## Gate tests' section"
    return [int(n) for n in re.findall(r"^(\d+)\. ", m.group(0), re.M)]


@pytest.mark.parametrize("prefix,stem", sorted(FILES.items()))
def test_every_canon_gate_test_has_a_gate(prefix, stem):
    nums = gate_test_numbers((CANON / f"{stem}.md").read_text(encoding="utf-8"))
    assert nums == list(range(1, len(nums) + 1))
    missing = [f"{prefix}-{n}" for n in nums if f"{prefix}-{n}" not in IDS]
    assert not missing, f"canon gate tests with no runnable gate: {missing}"
    extra = sorted(i for i in IDS if i.startswith(prefix + "-") and int(i.split("-")[1]) > len(nums))
    assert not extra, f"gates with no canon gate test: {extra}"


def test_each_gate_cites_a_canon_file_that_exists():
    for g in registry():
        path = g.canon.split(",")[0]
        assert (CANON.parent.parent / path).is_file(), (g.id, path)
