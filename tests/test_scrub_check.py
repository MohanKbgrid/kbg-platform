# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""Planted-defect tests for tools/scrub_check.py, using a synthetic name so no real customer is written here."""
import importlib.util
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("scrub_check", ROOT / "tools" / "scrub_check.py")
sc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sc)

PATS = sc.load_patterns("# a comment\n\nzzcustomer\n\\bqqcorp\\b\n")


def repo(tmp: Path, files: dict[str, str]) -> Path:
    subprocess.run(["git", "init", "-q", str(tmp)], check=True)
    for rel, body in files.items():
        f = tmp / rel
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(body, encoding="utf-8")
    subprocess.run(["git", "-C", str(tmp), "add", "-A"], check=True)
    return tmp


def test_clean_tree_passes(tmp_path):
    assert sc.scan(repo(tmp_path, {"canon/a.md": "an acme demo"}), PATS) == []


def test_name_in_content_is_caught_case_insensitively(tmp_path):
    hits = sc.scan(repo(tmp_path, {"sentinel/x.py": "# for ZZCustomer only\n"}), PATS)
    assert hits == ["sentinel/x.py:1: matches a scrub pattern"]


def test_name_in_file_name_is_caught(tmp_path):
    assert any("file name" in h for h in sc.scan(repo(tmp_path, {"docs/zzcustomer-notes.md": "ok"}), PATS))


def test_word_boundary_pattern_does_not_overmatch(tmp_path):
    assert sc.scan(repo(tmp_path, {"docs/a.md": "qqcorporate is fine, QQCorp is not"}), PATS) != []
    assert sc.scan(repo(tmp_path / "b", {"docs/a.md": "qqcorporate is fine"}), PATS) == []


def test_unscanned_layer_is_skipped(tmp_path):
    assert sc.scan(repo(tmp_path, {"scratch/p.tsx": "zzcustomer"}), PATS) == []


def test_log_never_echoes_the_name(tmp_path):
    assert all("zzcustomer" not in h.lower() for h in sc.scan(repo(tmp_path, {"docs/a.md": "zzcustomer"}), PATS))


def test_no_patterns_fails_unless_allowed(tmp_path, monkeypatch):
    monkeypatch.delenv("KBG_SCRUB_PATTERNS", raising=False)
    root = repo(tmp_path, {"docs/a.md": "x"})
    assert sc.main(["--root", str(root)]) == 2
    assert sc.main(["--root", str(root), "--allow-missing"]) == 0
