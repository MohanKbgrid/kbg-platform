# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""A CycloneDX 1.5 software bill of materials for kbg-sentinel and its runtime dependencies, offline.

    python scripts/sbom.py --out sbom.cdx.json                  # what pip installed with the default extras
    python scripts/sbom.py --extras api postgres --out sbom.json

It reads installed package metadata (no network), so run it in the environment that ships: the CI image
build runs it inside the image and attaches the result to the release. Each component carries its name,
version, package URL (purl) and the licences found by ``check_licences.py``.
"""
from __future__ import annotations

import argparse
import json
import sys
import uuid
from datetime import UTC, datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from check_licences import DEFAULT_EXTRAS, licences, walk  # noqa: E402


NOT_SPDX = {"BSD", "Apache"}         # family names from classifiers, not SPDX identifiers


def purl(name: str, version: str) -> str:
    return f"pkg:pypi/{name.lower().replace('_', '-')}@{version}"


def build(extras: list[str]) -> dict:
    deps = walk("kbg-sentinel", extras)
    root = deps.get("kbg-sentinel")
    version = root.version if root is not None else "dev"
    comps, refs = [], {}
    for key, dist in sorted(deps.items()):
        if key == "kbg-sentinel":
            continue
        ref = purl(dist.metadata["Name"], dist.version)
        refs[key] = ref
        comp = {"type": "library", "bom-ref": ref, "name": dist.metadata["Name"], "version": dist.version,
                "purl": ref}
        lic = sorted(licences(dist))
        if lic:
            comp["licenses"] = [{"license": {"name" if x in NOT_SPDX else "id": x}} for x in lic]
        comps.append(comp)
    root_ref = purl("kbg-sentinel", version)
    dependencies = [{"ref": root_ref, "dependsOn": sorted(refs.values())}]
    return {
        "bomFormat": "CycloneDX", "specVersion": "1.5", "serialNumber": f"urn:uuid:{uuid.uuid4()}", "version": 1,
        "metadata": {"timestamp": datetime.now(UTC).replace(microsecond=0).isoformat(),
                     "tools": {"components": [{"type": "application", "name": "kbg-sentinel scripts/sbom.py"}]},
                     "component": {"type": "application", "bom-ref": root_ref, "name": "kbg-sentinel",
                                   "version": version, "purl": root_ref,
                                   "supplier": {"name": "KBGrid Technologies"}},
                     "properties": [{"name": "extras", "value": ",".join(extras)}]},
        "components": comps, "dependencies": dependencies,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--extras", nargs="*", default=DEFAULT_EXTRAS)
    ap.add_argument("--out", default="-")
    a = ap.parse_args()
    doc = build(a.extras)
    text = json.dumps(doc, indent=2)
    if a.out == "-":
        print(text)
    else:
        Path(a.out).write_text(text, encoding="utf-8")
        print(f"{len(doc['components'])} components -> {a.out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
