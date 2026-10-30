# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""F2: usage metering and the signed, chained monthly export."""
from __future__ import annotations

import json
from datetime import timedelta

from sentinel import Decision, DecisionKind
from sentinel.usage import export, measure, month_bounds, verify
from tests.conftest import job_event


def _month(eng):
    return eng.clock().strftime("%Y-%m")


def test_measure_counts_what_billing_needs(engine_factory):
    eng = engine_factory()
    a = eng.ingest(job_event(error="TIMEOUT", ref="U1", key="u1"))                 # automatic
    eng.ingest(job_event(error="TIMEOUT", ref="U2", system="crm", key="u2"))       # automatic, then reversed
    b = eng.store.incidents()[-1].id
    eng.reverse(b, actor="lata")
    h = eng.ingest(job_event(error="AUTH", ref="U3", key="u3"))                    # a person
    eng.decide(eng.store.open_review_for(h.incident_id).id,
               Decision(kind=DecisionKind.REJECT, actor="lata", disposition_code="no_action"))
    eng.ingest(job_event(error="AUTH", ref="U4", key="u4"))                        # grouped into U3? new: closed
    doc = measure(eng, _month(eng))
    t = doc["tenants"]["default"]
    assert t["resolved_automatic"] == 1 and t["reversed"] == 1 and t["resolved_by_people"] == 1
    assert t["reviewers"] == 1 and t["events"] == 4 and t["incidents"] >= 3
    assert t["by_pattern"]["job_timeout"]["automatic"] == 1 and a.incident_id
    assert doc["final"] is False


def test_export_is_signed_chained_and_tamper_evident(engine_factory, clock):
    eng = engine_factory()
    eng.ingest(job_event(error="TIMEOUT", ref="S1", key="s1"))
    first = _month(eng)
    clock.advance(days=45)                                             # a month later, window passed
    d1 = export(eng, first, key="k")
    assert d1["final"] and d1["previous"] is None and verify(d1, "k") == []
    assert verify(d1, "other") == ["the signature does not match this key"]
    bad = json.loads(json.dumps(d1))
    bad["tenants"]["default"]["resolved_automatic"] = 0
    assert "it was changed after export" in verify(bad, "k")[0]
    second = eng.clock().strftime("%Y-%m")
    start, end = month_bounds(second)
    clock.now = end + timedelta(days=8)
    d2 = export(eng, second, key="k")
    assert d2["previous"] == {"month": first, "digest": d1["digest"]}
    unsigned = export(eng, second, key="")
    assert any("not signed" in m for m in verify(unsigned, "k"))
    assert any(a["kind"] == "usage_exported" for a in eng.store.audit_log())


def test_cli(tmp_path, capsys, monkeypatch):
    from sentinel.cli import main
    monkeypatch.setenv("SENTINEL_SECRET_USAGE_KEY", "sitekey")
    base = ["--overlay", "tests.test_templates_cli:_overlay", "--db", str(tmp_path / "u.db")]
    out = tmp_path / "usage.json"
    assert main([*base, "usage", "--month", "2026-01", "--out", str(out)]) == 0
    assert json.loads(capsys.readouterr().out)["signed"] is True
    assert main(["usage-verify", str(out)]) == 0
    assert json.loads(capsys.readouterr().out)["ok"] is True
