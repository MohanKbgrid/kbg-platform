# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""The seven denial kinds exist in three places (canon text, the Python base, the UI kit). They must not drift."""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "bases" / "core" / "src"))


def canon_kinds() -> set[str]:
    text = (ROOT / "canon" / "surfaces" / "03-rbac.md").read_text(encoding="utf-8")
    return set(re.findall(r"^\s*\|\s*`([A-Z_]+)`\s*\|", text, re.M))


def ui_kinds() -> set[str]:
    text = (ROOT / "bases" / "ui-kit" / "src" / "access" / "denial.ts").read_text(encoding="utf-8")
    block = re.search(r"DENIAL_KINDS[^=]*=\s*\[(.*?)\]", text, re.S).group(1)
    return set(re.findall(r"['\"]([A-Z_]+)['\"]", block))


def test_the_three_copies_of_the_denial_kinds_agree():
    from kbg_platform_core.authority import BLOCK_KINDS
    core = set(BLOCK_KINDS)
    assert len(core) == 7
    assert core <= canon_kinds(), core - canon_kinds()
    assert ui_kinds() == core, (ui_kinds() ^ core)
