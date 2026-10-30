# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""ADR-004: every release from v0.14.3 is classified, and the version is the same everywhere."""
from __future__ import annotations

import re
import tomllib
from pathlib import Path

import sentinel

ROOT = Path(__file__).resolve().parent.parent
CLASSES = ("Compatible", "Behavioural", "Breaking")
FIRST_CLASSIFIED = (0, 14, 3)


def _entries() -> list[tuple[tuple[int, ...], str]]:
    text = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    parts = re.split(r"^## v(\d+)\.(\d+)\.(\d+).*$", text, flags=re.M)
    out = []
    for i in range(1, len(parts), 4):
        out.append(((int(parts[i]), int(parts[i + 1]), int(parts[i + 2])), parts[i + 3]))
    return out


def test_every_release_since_adoption_is_classified() -> None:
    entries = [(v, body) for v, body in _entries() if v >= FIRST_CLASSIFIED]
    assert entries, "no classified releases found"
    for v, body in entries:
        m = re.search(r"^\*\*Class:\*\*\s*(\w+)", body, flags=re.M)
        assert m, f"v{'.'.join(map(str, v))}: no **Class:** line"
        assert m.group(1) in CLASSES, f"v{'.'.join(map(str, v))}: class {m.group(1)!r} is not one of {CLASSES}"
        assert re.search(r"^\*\*Adopt:\*\*\s*\S", body, flags=re.M), f"v{'.'.join(map(str, v))}: no **Adopt:** line"
        if m.group(1) == "Behavioural":
            assert re.search(r"pattern", body, flags=re.I), "a behavioural release names the patterns it can affect"
        if m.group(1) == "Breaking":
            assert re.search(r"migrat", body, flags=re.I), "a breaking release carries its migration"


def test_releases_are_newest_first_and_unique() -> None:
    versions = [v for v, _ in _entries()]
    assert versions == sorted(versions, reverse=True)
    assert len(versions) == len(set(versions))


def test_version_matches_changelog_and_package() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]["version"]
    top = ".".join(map(str, _entries()[0][0]))
    assert project == sentinel.__version__ == top


def test_adoption_template_has_the_support_record_fields() -> None:
    text = (ROOT / "docs" / "templates" / "SENTINEL_ADOPTION.md").read_text(encoding="utf-8")
    for field in ("Current pinned pair", "Rollback pair", "Changes between pins", "Pack check", "Replay",
                  "Dual run", "Switch", "Watch"):
        assert field in text, field
