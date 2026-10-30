# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""Nothing in the open framework may degrade, cap or switch off a feature on a licence check."""
from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

from sentinel.cli import main
from sentinel.testing import engine_for
from tests.conftest import Backend, make_overlay

PKG = Path(__file__).resolve().parent.parent / "sentinel"


def test_there_is_no_licence_module():
    assert importlib.util.find_spec("sentinel.licence") is None


def test_no_source_file_reads_a_licence_setting():
    offenders = [str(p.relative_to(PKG)) for p in PKG.rglob("*") if p.is_file() and p.suffix in {".py", ".js", ".yaml"}
                 and "SENTINEL_LICENCE" in p.read_text(encoding="utf-8")]
    assert offenders == []


def test_a_licence_variable_in_the_environment_changes_nothing(monkeypatch):
    monkeypatch.setenv("SENTINEL_LICENCE", "garbage-token")
    monkeypatch.setenv("SENTINEL_LICENCE_KEYS", "/nonexistent")
    h = engine_for(make_overlay(Backend())).health()
    assert h["status"] == "ok" and "licence" not in h


def test_there_is_no_licence_command(capsys):
    with pytest.raises(SystemExit) as e:
        main(["licence", "status"])
    assert e.value.code == 2
