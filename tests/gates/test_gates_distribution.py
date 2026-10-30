# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""Distributing master data offline (DST-1 .. DST-8): the rule helpers, and each rule red-then-green on a named defect."""
import pytest

from gates import registry
from gates.framework import Refused
from gates.integration_distribution import (RefControls, RefCrosswalk, RefDist, RefDlq, RefIdem, RefMulti,
                                            protected_name_ok, starts_a_segment_with)

BY_ID = {g.id: g for g in registry()}


@pytest.mark.parametrize("name,ok", [
    ("bill.committed", True), ("stock.counted", True), ("a.b.cde", False), ("abc.de", False), ("bill", False),
    ("x.committed", False), ("", False), ("Bill.Committed", False), ("abc.def.ghi", True), ("abc..def", False)])
def test_protected_name_shape(name, ok):
    assert protected_name_ok(name) is ok


@pytest.mark.parametrize("name,hit", [
    ("bill.committed", True), ("bill.committed.v1", True), ("app.bill.committed", True), ("bill.committed_v2", True),
    ("xbill.committed", False), ("bill.committee", False), ("heartbeat.ping", False)])
def test_a_variant_spelling_is_matched_at_a_segment_start(name, hit):
    assert starts_a_segment_with(name, "bill.committed") is hit


def test_dst1_committed_fact_stays_replayable():
    s = RefDlq()
    d = s.dead_letter("bill.committed")
    with pytest.raises(Refused):
        s.discard(d, approval="a")
    s.replay(d)
    assert s.status[d] == "REPLAYED"


def test_dst1_an_emptied_list_fails_closed_not_open():
    with pytest.raises(Refused):
        RefDlq().discard_with_empty_list("heartbeat.ping")
    assert BY_ID["DST-1"].logic(RefDlq({"empty_list_allows"}))


def test_dst3_the_key_has_three_parts():
    s = RefIdem()
    assert [s.apply("T", "A", "1", {}), s.apply("T", "A", "1", {}), s.apply("T", "B", "1", {}), s.apply("U", "A", "1", {})] \
        == ["APPLIED", "ALREADY_APPLIED", "APPLIED", "APPLIED"]


def test_dst4_remap_keeps_history():
    s = RefCrosswalk()
    s.map("T", "ERP", "article", "S", "G1", "pat")
    s.map("T", "ERP", "article", "S", "G2", "sam")
    assert [(r["global_id"], r["active"]) for r in s.rows("T", "ERP", "article", "S")] == [("G1", False), ("G2", True)]


def test_dst5_snapshot_failure_midway_changes_nothing():
    s = RefDist()
    s.load_rows("R", {"a": 1})
    with pytest.raises(Refused):
        s.apply_snapshot("R", 9, {"x": 1, "y": 2}, fail_after=1)
    assert s.rows_of("R") == {"a": 1} and s.held("R") == 0
    assert BY_ID["DST-5"].logic(RefDist({"snapshot_partial"}))


def test_dst5_own_state_is_served_even_when_it_shrinks():
    s = RefDist()
    s.set_previous_count("d", 1000)
    s.serve_current_state("d", 10)
    assert BY_ID["DST-5"].logic(RefDist({"guard_blocks_own_state"}))


def test_dst6_replayed_activation_cannot_revive_a_block_but_a_later_one_can():
    s = RefDist()
    s.apply_change("R", "r", "active", 1, content_version=7)
    s.apply_change("R", "r", "blocked", 5, urgent=True, content_version=7)
    assert s.apply_change("R", "r", "active", 2, content_version=7) == "stale" and s.row_state("R", "r") == "blocked"
    assert s.apply_change("R", "r", "active", 6, urgent=True, content_version=3) == "applied"
    assert s.row_state("R", "r") == "active"


def test_dst7_any_source_blocks_and_every_source_is_kept():
    s = RefMulti()
    s.set_source("i", "erp", blocked=True, reason="status", start=1)
    s.set_source("i", "hub", blocked=False)
    assert s.resolve("i")["sellable"] is False and len(s.sources("i")) == 2


def test_dst8_a_run_that_cannot_balance_is_a_finding():
    s = RefControls()
    r = s.run_interface("f", [{"seq": 1, "id": "a", "value": 1}], control=None)
    assert r["status"] != "OK" and r["findings"] == ["cannot_balance"]
    assert s.recorded_runs() == [r]
    assert BY_ID["DST-8"].logic(RefControls({"unbalanceable_passes"}))
