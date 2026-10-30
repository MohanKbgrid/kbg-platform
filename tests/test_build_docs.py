# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""tools/build_docs.py keeps repository-relative paths, so links between documents keep working."""
import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("build_docs", ROOT / "tools" / "build_docs.py")
bd = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bd)


def make(tmp: Path) -> Path:
    for rel, body in {
        "README.md": "# home", "canon/README.md": "# canon", "canon/surfaces/01.md": "x",
        "bases/core/README.md": "# core", "bases/core/secret.py": "no",
        "sentinel/README.md": "# s", "sentinel/docs/A.md": "a", "sentinel/docs/img/p.png": "png",
        "sentinel/sentinel/engine.py": "code", "node_modules/x/README.md": "no",
    }.items():
        f = tmp / rel
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(body)
    return tmp


def test_documents_keep_their_repository_paths(tmp_path):
    root = make(tmp_path / "repo")
    stage = tmp_path / "stage"
    copied = bd.assemble(root, stage)
    assert (stage / "canon/surfaces/01.md").read_text() == "x"
    assert (stage / "sentinel/docs/img/p.png").exists()
    assert "README.md" in copied and "bases/core/README.md" in copied


def test_only_documentation_is_copied(tmp_path):
    root = make(tmp_path / "repo")
    stage = tmp_path / "stage"
    bd.assemble(root, stage)
    assert not (stage / "bases/core/secret.py").exists()
    assert not (stage / "sentinel/sentinel/engine.py").exists()
    assert not (stage / "node_modules").exists()


def test_a_rebuild_leaves_nothing_stale(tmp_path):
    root = make(tmp_path / "repo")
    stage = tmp_path / "stage"
    bd.assemble(root, stage)
    (root / "canon/surfaces/01.md").unlink()
    bd.assemble(root, stage)
    assert not (stage / "canon/surfaces/01.md").exists()
