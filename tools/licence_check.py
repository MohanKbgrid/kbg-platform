# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""Fail if the licence files are missing or any source file lacks its SPDX header.

    python tools/licence_check.py            # check the repository this file lives in
    python tools/licence_check.py --root DIR

Checks, in order:
  1. LICENSE (Apache-2.0), LICENSE-docs (CC BY 4.0) and NOTICE exist and say what they should.
  2. Every tracked source file (.py .ts .tsx .mjs .css) starts with
     `SPDX-License-Identifier: Apache-2.0` within its first 5 lines.
  3. No package manifest declares UNLICENSED.

node_modules and dist are skipped.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

SOURCE_SUFFIXES = {".py", ".ts", ".tsx", ".mjs", ".css"}
SKIP_PREFIXES = ()
SKIP_PARTS = {"node_modules", "dist", ".git"}
SPDX = "SPDX-License-Identifier: Apache-2.0"
REQUIRED = {
    "LICENSE": "Apache License",
    "LICENSE-docs": "Attribution 4.0 International",
    "NOTICE": "KB Grid",
}


PACKAGE_DIRS = ("sentinel", "bases/core", "bases/ui-kit")


def tracked_files(root: Path) -> list[str]:
    try:
        out = subprocess.check_output(["git", "-C", str(root), "ls-files"], text=True, stderr=subprocess.DEVNULL)
        return [f for f in out.splitlines() if f]
    except (subprocess.CalledProcessError, FileNotFoundError):
        return [str(p.relative_to(root)) for p in root.rglob("*") if p.is_file()]


def check(root: Path) -> list[str]:
    problems: list[str] = []
    for name, needle in REQUIRED.items():
        f = root / name
        if not f.is_file():
            problems.append(f"missing {name}")
        elif needle not in f.read_text(encoding="utf-8", errors="replace"):
            problems.append(f"{name} does not contain {needle!r}")
    # Each published package ships its own copy: a wheel, sdist, npm package or image cannot reach the repository root.
    for pkg in PACKAGE_DIRS:
        for name in ("LICENSE", "NOTICE"):
            f, top = root / pkg / name, root / name
            if not f.is_file():
                problems.append(f"{pkg}/{name} missing (published packages must carry it)")
            elif top.is_file() and f.read_bytes() != top.read_bytes():
                problems.append(f"{pkg}/{name} differs from the root {name}")
    for rel in tracked_files(root):
        if rel.startswith(SKIP_PREFIXES) or SKIP_PARTS & set(Path(rel).parts):
            continue
        p = root / rel
        if p.suffix in SOURCE_SUFFIXES and p.is_file():
            head = "\n".join(p.read_text(encoding="utf-8", errors="replace").splitlines()[:5])
            if SPDX not in head:
                problems.append(f"{rel}: missing '{SPDX}' header")
        if p.name == "package.json" and p.is_file():
            if json.loads(p.read_text(encoding="utf-8")).get("license") == "UNLICENSED":
                problems.append(f"{rel}: license is UNLICENSED")
    return problems


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--root", type=Path, default=Path(__file__).resolve().parent.parent)
    problems = check(ap.parse_args(argv).root)
    for p in problems:
        print("FAIL", p)
    print(f"licence check: {'FAILED, %d problem(s)' % len(problems) if problems else 'ok'}")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
