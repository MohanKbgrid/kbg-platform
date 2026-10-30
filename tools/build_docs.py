# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""Assemble the documentation site's source folder, then (optionally) build it with MkDocs.

    python tools/build_docs.py            # assemble .site-src/ only
    python tools/build_docs.py --build    # assemble, then run `mkdocs build` into site/

The docs live next to the code they describe (canon/, gates/, bases/, sentinel/docs/), and they link to each other
by repository path. MkDocs wants one folder. This script copies the documents into `.site-src/` KEEPING their
repository-relative paths, so every relative link between them keeps working, and the site covers every layer.
It copies only documentation: .md files and the images they use.
"""
from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
STAGE = ROOT / ".site-src"
TOP_LEVEL = ["README.md", "CONTRIBUTING.md", "GOVERNANCE.md", "ROADMAP.md", "SECURITY.md", "CODE_OF_CONDUCT.md"]
TREES = ["canon", "gates", "docs", "sentinel/docs"]          # copied whole: .md, .png, .gif, .svg
SINGLE = ["bases/core/README.md", "bases/ui-kit/README.md", "sentinel/README.md", "sentinel/CHANGELOG.md",
          "sentinel/deploy/README.md", "sentinel/SECURITY.md"]
DOC_SUFFIXES = {".md", ".png", ".gif", ".svg", ".jpg", ".jpeg"}


def assemble(root: Path = ROOT, stage: Path = STAGE) -> list[str]:
    if stage.exists():
        shutil.rmtree(stage)
    stage.mkdir(parents=True)
    copied: list[str] = []

    def put(src: Path) -> None:
        rel = src.relative_to(root)
        dst = stage / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
        copied.append(str(rel))

    for name in TOP_LEVEL + SINGLE:
        if (root / name).is_file():
            put(root / name)
    for tree in TREES:
        base = root / tree
        if base.is_dir():
            for p in sorted(base.rglob("*")):
                if p.is_file() and p.suffix.lower() in DOC_SUFFIXES and "node_modules" not in p.parts:
                    put(p)
    return copied


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--build", action="store_true", help="also run mkdocs build (needs mkdocs-material)")
    a = ap.parse_args(argv)
    copied = assemble()
    print(f"assembled {len(copied)} documents into {STAGE.name}/")
    if not a.build:
        return 0
    return subprocess.call([sys.executable, "-m", "mkdocs", "build", "-f", str(ROOT / "mkdocs.yml")], cwd=ROOT)


if __name__ == "__main__":
    sys.exit(main())
