# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""KBG conformance kit: the canon's gate tests, runnable.

One gate module per canon surface. LOGIC and PROOF ship here; a product supplies only its own
BINDING. See README.md.
"""
from .framework import (DORMANT, FAIL, GAP, PASS, Dormant, Gap, Gate, Refused, Result, main,
                        registry, run_gate, selftest)

__all__ = ["Gap", "Dormant", "Refused", "Gate", "Result", "run_gate", "selftest", "registry",
           "main", "PASS", "FAIL", "GAP", "DORMANT"]
