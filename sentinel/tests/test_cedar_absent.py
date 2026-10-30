# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""Without the ``cedar`` extra: nothing imports cedarpy, the built-in engine is untouched, and choosing the Cedar
backend anyway fails closed with a message that names the extra. Runs whether or not cedarpy is installed."""
from __future__ import annotations

import sys

from sentinel.org import Person, authorise
from tests.test_rbac import make_directory


def test_the_core_never_imports_cedarpy(monkeypatch):
    for name in [n for n in sys.modules if n == "cedarpy" or n.startswith("cedarpy.")]:
        monkeypatch.delitem(sys.modules, name)
    monkeypatch.setitem(sys.modules, "cedarpy", None)           # an import of it now raises ImportError
    d = make_directory()
    assert authorise(d, Person("ravi"), "retry").allowed         # the built-in engine does not need it


def test_missing_extra_refuses_with_the_reason(monkeypatch):
    monkeypatch.setitem(sys.modules, "cedarpy", None)
    from sentinel.cedar_authz import CedarBackend, available
    assert not available()
    b = CedarBackend('permit (principal, action, resource);')
    assert not b.ready and "kbg-sentinel[cedar]" in b.load_error
    dec = authorise(make_directory(), Person("ravi"), "retry", backend=b)
    assert not dec.allowed and "kbg-sentinel[cedar]" in dec.reason
