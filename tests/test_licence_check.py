# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""Planted-defect tests for tools/licence_check.py: a good tree passes, each defect is caught."""
import importlib.util
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("licence_check", ROOT / "tools" / "licence_check.py")
lc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lc)


def good_tree(tmp: Path) -> Path:
    for n in lc.REQUIRED:
        shutil.copy(ROOT / n, tmp / n)
    for pkg in lc.PACKAGE_DIRS:
        (tmp / pkg).mkdir(parents=True, exist_ok=True)
        for n in ("LICENSE", "NOTICE"):
            shutil.copy(ROOT / n, tmp / pkg / n)
    (tmp / "a.py").write_text("# SPDX-License-Identifier: Apache-2.0\nx = 1\n")
    (tmp / "package.json").write_text('{"license": "Apache-2.0"}')
    return tmp


def test_real_repo_passes():
    assert lc.check(ROOT) == []


def test_good_tree_passes(tmp_path):
    assert lc.check(good_tree(tmp_path)) == []


def test_missing_header_caught(tmp_path):
    t = good_tree(tmp_path)
    (t / "b.py").write_text("x = 2\n")
    assert any("b.py" in p for p in lc.check(t))


def test_header_too_deep_is_not_a_header(tmp_path):
    t = good_tree(tmp_path)
    (t / "c.py").write_text("\n" * 10 + "# SPDX-License-Identifier: Apache-2.0\n")
    assert any("c.py" in p for p in lc.check(t))


def test_missing_licence_file_caught(tmp_path):
    t = good_tree(tmp_path)
    (t / "NOTICE").unlink()
    assert "missing NOTICE" in lc.check(t)


def test_unlicensed_manifest_caught(tmp_path):
    t = good_tree(tmp_path)
    (t / "package.json").write_text('{"license": "UNLICENSED"}')
    assert any("UNLICENSED" in p for p in lc.check(t))


def test_wrong_licence_text_caught(tmp_path):
    t = good_tree(tmp_path)
    (t / "LICENSE").write_text("all rights reserved")
    assert any("LICENSE" in p for p in lc.check(t))


def test_package_without_licence_or_notice_caught(tmp_path):
    t = good_tree(tmp_path)
    (t / "sentinel" / "NOTICE").unlink()
    assert any("sentinel/NOTICE missing" in p for p in lc.check(t))


def test_package_copy_that_drifted_caught(tmp_path):
    t = good_tree(tmp_path)
    (t / "bases/core" / "LICENSE").write_text("Apache License, but edited")
    assert any("bases/core/LICENSE differs" in p for p in lc.check(t))
