# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""SEC: the offline SBOM lists every runtime dependency with a package URL."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "scripts"))


def test_sbom_is_cyclonedx_with_purls():
    import sbom
    doc = sbom.build(["api"])
    assert doc["bomFormat"] == "CycloneDX" and doc["specVersion"] == "1.5"
    names = {c["name"].lower() for c in doc["components"]}
    assert {"pydantic", "fastapi", "pyyaml"} <= names
    assert all(c["purl"].startswith("pkg:pypi/") for c in doc["components"])
    assert doc["dependencies"][0]["ref"] == doc["metadata"]["component"]["bom-ref"]
