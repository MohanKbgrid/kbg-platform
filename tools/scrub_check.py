# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""Fail if a customer or internal-product name appears in a public layer.

    KBG_SCRUB_PATTERNS="$(cat patterns.txt)" python tools/scrub_check.py
    python tools/scrub_check.py --patterns-file patterns.txt

The pattern list is one case-insensitive regular expression per line (blank lines and # comments are
ignored). It is deliberately NOT in this repository, because the list of names to hide would itself publish
them. In CI it comes from a repository secret (KBG_SCRUB_PATTERNS); locally from a private file.

With no patterns the check fails (exit 2) unless --allow-missing is given, so a CI job that lost its secret
cannot pass by scanning nothing.

Scans every git-tracked text file under the public layers, and the file names themselves. website/ is skipped:
it moves to its own repository.
"""
from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from pathlib import Path

PUBLIC_LAYERS = ("canon", "gates", "bases", "sentinel", "docs", "tools", "tests", "README.md", "NOTICE", "LICENSE-docs")
BINARY_SUFFIXES = {".png", ".jpg", ".jpeg", ".gif", ".ico", ".woff", ".woff2", ".pdf", ".gz", ".zip", ".db"}


def load_patterns(text: str) -> list[re.Pattern[str]]:
    out = []
    for line in text.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            out.append(re.compile(line, re.IGNORECASE))
    return out


def tracked(root: Path) -> list[str]:
    out = subprocess.check_output(["git", "-C", str(root), "ls-files"], text=True)
    return [f for f in out.splitlines() if f]


def scan(root: Path, patterns: list[re.Pattern[str]]) -> list[str]:
    hits: list[str] = []
    for rel in tracked(root):
        if not rel.startswith(PUBLIC_LAYERS):
            continue
        for pat in patterns:
            if pat.search(rel):
                hits.append(f"{rel}: file name matches a scrub pattern")
        p = root / rel
        if p.suffix.lower() in BINARY_SUFFIXES or not p.is_file():
            continue
        try:
            text = p.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for n, line in enumerate(text.splitlines(), 1):
            if any(pat.search(line) for pat in patterns):
                # never echo the matching text: the log must not publish the name either
                hits.append(f"{rel}:{n}: matches a scrub pattern")
    return hits


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--root", type=Path, default=Path(__file__).resolve().parent.parent)
    ap.add_argument("--patterns-file", type=Path)
    ap.add_argument("--allow-missing", action="store_true", help="exit 0 with a warning when there are no patterns")
    a = ap.parse_args(argv)
    raw = a.patterns_file.read_text(encoding="utf-8") if a.patterns_file else os.environ.get("KBG_SCRUB_PATTERNS", "")
    patterns = load_patterns(raw)
    if not patterns:
        print("scrub check: no patterns supplied (set KBG_SCRUB_PATTERNS or --patterns-file)")
        return 0 if a.allow_missing else 2
    hits = scan(a.root, patterns)
    for h in hits:
        print("FAIL", h)
    print(f"scrub check: {'FAILED, %d hit(s)' % len(hits) if hits else 'ok'} ({len(patterns)} patterns)")
    return 1 if hits else 0


if __name__ == "__main__":
    sys.exit(main())
