# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""Fail if any runtime dependency is not under an approved open-source licence.

    python scripts/check_licences.py                 # core + postgres, api, analytics, anthropic extras
    python scripts/check_licences.py --extras api    # a subset

Walks the installed dependency tree of kbg-sentinel (with the chosen extras) and checks each package's
licence metadata (License-Expression, License, classifiers) against the allowlist below. Development
tools (pytest, ruff ...) are not part of what ships, so they are not checked.
"""
from __future__ import annotations

import argparse
import re
import sys
from importlib import metadata

from packaging.requirements import Requirement

ALLOWED = {
    "MIT", "MIT-0", "MIT-CMU", "BSD", "BSD-2-Clause", "BSD-3-Clause", "0BSD", "Apache-2.0", "Apache", "ISC", "PSF-2.0",
    "Python-2.0", "MPL-2.0", "LGPL-2.1", "LGPL-3.0", "LGPL-3.0-only", "LGPL-3.0-or-later", "LGPL-2.1-or-later",
    "Unlicense", "CC0-1.0", "Zlib", "HPND",
}
CLASSIFIER_MAP = {
    "MIT License": "MIT", "BSD License": "BSD", "Apache Software License": "Apache-2.0",
    "ISC License (ISCL)": "ISC", "Python Software Foundation License": "PSF-2.0",
    "Mozilla Public License 2.0 (MPL 2.0)": "MPL-2.0",
    "GNU Lesser General Public License v3 (LGPLv3)": "LGPL-3.0",
    "GNU Lesser General Public License v3 or later (LGPLv3+)": "LGPL-3.0-or-later",
    "GNU Lesser General Public License v2 or later (LGPLv2+)": "LGPL-2.1-or-later",
    "The Unlicense (Unlicense)": "Unlicense", "Historical Permission Notice and Disclaimer (HPND)": "HPND",
}
TEXT_HINTS = [("apache", "Apache-2.0"), ("mit", "MIT"), ("bsd", "BSD"), ("isc", "ISC"), ("mpl", "MPL-2.0"),
              ("lgpl", "LGPL-3.0"), ("psf", "PSF-2.0"), ("python software foundation", "PSF-2.0")]
DEFAULT_EXTRAS = ["postgres", "api", "analytics", "anthropic"]


def licences(dist: metadata.Distribution) -> set[str]:
    md = dist.metadata
    expr = md.get("License-Expression")
    if expr:
        return {t for t in re.split(r"\s+(?:OR|AND|WITH)\s+|[()]", expr) if t.strip()} or {expr}
    found = {CLASSIFIER_MAP[c.split(" :: ")[-1]] for c in md.get_all("Classifier") or []
             if c.startswith("License ::") and c.split(" :: ")[-1] in CLASSIFIER_MAP}
    if found:
        return found
    text = (md.get("License") or "").strip().lower()
    if text and len(text) < 200:
        for hint, lic in TEXT_HINTS:
            if re.search(rf"\b{re.escape(hint)}\b", text):
                return {lic}
    if text:   # full licence text pasted into the field
        for hint, lic in TEXT_HINTS:
            if hint in text[:400]:
                return {lic}
    return set()


def walk(root: str, extras: list[str]) -> dict[str, metadata.Distribution]:
    seen: dict[str, metadata.Distribution] = {}
    todo: list[tuple[str, set[str]]] = [(root, set(extras))]
    while todo:
        name, ex = todo.pop()
        key = re.sub(r"[-_.]+", "-", name).lower()
        try:
            dist = metadata.distribution(name)
        except metadata.PackageNotFoundError:
            continue
        if key in seen and not ex:
            continue
        seen[key] = dist
        for raw in dist.requires or []:
            req = Requirement(raw)
            env = {"extra": ""}
            ok = req.marker is None or req.marker.evaluate(env) or any(
                req.marker.evaluate({"extra": e}) for e in ex)
            if ok:
                todo.append((req.name, set(req.extras)))
    return seen


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--extras", nargs="*", default=DEFAULT_EXTRAS)
    a = ap.parse_args()
    deps = walk("kbg-sentinel", a.extras)
    bad = []
    for key, dist in sorted(deps.items()):
        if key == "kbg-sentinel":
            continue
        lic = licences(dist)
        ok = bool(lic) and any(x in ALLOWED for x in lic)
        shown = ", ".join(sorted(lic)) or "?"
        print(f"{'ok ' if ok else 'BAD'}  {dist.metadata['Name']:<28} {dist.version:<12} {shown}")
        if not ok:
            bad.append(dist.metadata["Name"])
    if bad:
        print(f"\nNot on the open-source allowlist: {', '.join(bad)}", file=sys.stderr)
        return 1
    print(f"\n{len(deps) - 1} runtime dependencies, all open source.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
