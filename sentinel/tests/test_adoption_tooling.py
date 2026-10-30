# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""S9 (ADR-004): per-client fleet targets, the support-window flag, and dual-run tooling (trace under each pin,
compare, trust guard). Dual run proved on the R06 exemplar with a candidate that changes one pattern."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from sentinel import Overlay, load_layers
from sentinel import egress
from sentinel.cli import main
from sentinel.dualrun import compare, read_jsonl, trace_events, write_jsonl
from sentinel.fleet import FleetFile, Site, collect, minors_behind
from sentinel.models import Event
from sentinel.testing import engine_for
from tests.test_role_slots import _actions

PACK = Path(__file__).parent / "packs" / "r06_stock_integrity"


# ---- fleet: per-client target and support window ----------------------------------------------------

@pytest.fixture
def sites(monkeypatch):
    versions = {"https://chain": "0.16.1", "https://acme": "0.14.2", "https://dairy": "0.21.0"}

    def fake_open(req, timeout, base_opener=None):
        base = req.full_url.rsplit("/v1/", 1)[0]
        return 200, {}, json.dumps({"version": versions[base], "health": "ok", "problems": [],
                                    "last_backup": "2026-10-19T00:00:00Z"}).encode()
    monkeypatch.setattr(egress, "open_url", fake_open)
    for env in ("T_CHAIN", "T_ACME", "T_DAIRY"):
        monkeypatch.setenv(env, "tok")


def test_each_client_has_its_own_target_and_window(sites):
    fleet = FleetFile(target_version="0.21.0", latest_version="0.22.0", support_window=2, sites={
        "chain": Site(url="https://chain", token_env="T_CHAIN", target_version="0.16.1",
                    adoption="retail-pos tenants/chain/SENTINEL_ADOPTION.md"),
        "acme": Site(url="https://acme", token_env="T_ACME"),
        "dairy": Site(url="https://dairy", token_env="T_DAIRY")})
    rows = {r["name"]: r for r in collect(fleet, timeout_s=1)["sites"]}
    assert rows["chain"]["target_version"] == "0.16.1" and "behind" not in rows["chain"]["flags"]   # on its target
    assert "outside support window" in rows["chain"]["flags"] and rows["chain"]["minors_behind"] == 6
    assert rows["chain"]["adoption"].endswith("SENTINEL_ADOPTION.md")
    assert rows["acme"]["target_version"] == "0.21.0" and "behind" in rows["acme"]["flags"]
    assert any("0.21.0" in c for c in rows["acme"]["upgrade"])
    assert rows["dairy"]["flags"] == [] and rows["dairy"]["minors_behind"] == 1                       # previous minor


def test_minors_behind():
    assert minors_behind("0.21.3", "0.22.0") == 1
    assert minors_behind("0.22.0", "0.22.4") == 0
    assert minors_behind("0.9.0", "1.0.0") >= 1000                        # another major: outside any window
    assert minors_behind(None, "0.2.0") == 2


# ---- dual run ----------------------------------------------------------------------------------------

def engine(candidate=False):
    layers = [PACK / "template.yaml", PACK / "tenant_chain_a.yaml"]
    if candidate:                                       # the candidate pin matches UOM errors on any factor
        layers.append(("candidate", {"overrides": [{"id": "r06_uom_error", "set": {"match": {}}}]}))
    doc = load_layers(layers)
    return engine_for(Overlay(name="r06", fingerprint_rules=doc.fingerprints, patterns=doc.patterns,
                              roles=doc.roles, actions=_actions(), slots=doc.slots, slot_bindings=doc.slot_bindings))


EVENTS = [
    {"type": "inv.sales_stopped", "idempotency_key": "e1", "payload": {"store": "TVM01", "article": "A",
                                                                        "book_qty": 3}},
    {"type": "inv.qty_factor_mismatch", "idempotency_key": "e2", "payload": {"store": "TVM01", "article": "B",
                                                                              "factor": 7}},
    {"type": "inv.qty_factor_mismatch", "idempotency_key": "e3", "payload": {"store": "TVM01", "article": "C",
                                                                              "factor": 12}},
]


def test_dual_run_lists_differences_and_the_trust_guard():
    prod = trace_events(engine(), EVENTS, version="0.21.0")
    cand = trace_events(engine(candidate=True), EVENTS, version="0.22.0")
    rep = compare(prod, cand)
    assert rep["events"] == 3 and rep["unchanged"] == 2
    assert rep["versions"] == {"production": ["0.21.0"], "candidate": ["0.22.0"]}
    assert set(rep["patterns"]) == {"__unmatched__", "r06_uom_error"}
    ex = rep["patterns"]["r06_uom_error"]["examples"][0]
    assert ex["key"] == "e2" and ex["changed"]["pattern"] == {"production": "__unmatched__",
                                                              "candidate": "r06_uom_error"}
    assert rep["trust_guard"] == ["__unmatched__", "r06_uom_error"]
    assert "drop one mode" in rep["verdict"]


def test_identical_pins_keep_trust_and_tracing_changes_nothing():
    eng = engine()
    a = trace_events(eng, EVENTS)
    b = trace_events(engine(), EVENTS)
    rep = compare(a, b)
    assert rep["patterns"] == {} and rep["trust_guard"] == [] and rep["verdict"].startswith("no differences")
    assert eng.store.recent_audit(10) == [] and not eng.store.open_reviews()        # read-only


def test_unpaired_events_are_reported():
    a = trace_events(engine(), EVENTS)
    rep = compare(a, a[:2])
    assert rep["unpaired"] == ["e3"]


def test_cli_compare(tmp_path, capsys):
    p, c = tmp_path / "prod.jsonl", tmp_path / "cand.jsonl"
    write_jsonl(trace_events(engine(), EVENTS), p)
    write_jsonl(trace_events(engine(candidate=True), EVENTS), c)
    assert read_jsonl(p)[0]["key"] == "e1"
    assert main(["dualrun", "compare", str(p), str(p)]) == 0
    capsys.readouterr()
    assert main(["dualrun", "compare", str(p), str(c)]) == 1
    assert "r06_uom_error" in json.loads(capsys.readouterr().out)["trust_guard"]


def test_events_can_be_event_objects():
    rows = trace_events(engine(), [Event(type="inv.fefo_breach", source="pos", idempotency_key="k",
                                         payload={"store": "TVM02", "article": "A"})])
    assert rows[0]["key"] == "k" and rows[0]["pattern"] == "r06_fefo_breach"
    assert rows[0]["actions"] == ["task.shelf_check"]
