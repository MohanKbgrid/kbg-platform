# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""Importable overlay factory for CLI tests (module:factory form)."""
from tests.conftest import Backend, make_overlay


def build_overlay():
    return make_overlay(Backend())
