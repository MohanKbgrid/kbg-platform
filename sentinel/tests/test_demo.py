# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""The five-minute demo (python -m sentinel.demo): it builds, seeds, serves, and tells the same story every time."""
from __future__ import annotations

import pytest

from sentinel import Route, demo

pytest.importorskip("fastapi")
httpx = pytest.importorskip("httpx")


@pytest.fixture
def seeded(tmp_path):
    eng, systems, model = demo.build_engine(str(tmp_path / "demo.db"))
    info = demo.seed(eng)
    return eng, systems, model, info


@pytest.fixture
def running(seeded):
    d = demo.RunningDemo(seeded[0]).start()
    yield d
    d.stop()


def auth(person):
    return {"Authorization": f"Bearer {demo.TOKENS[person]}"}


def test_demo_builds_and_seeds_the_story(seeded):
    eng, _s, _m, info = seeded
    assert info == {"seeded": True, "events": 31}
    s = demo.summary(eng)
    assert s["cases"] == 31
    assert s["by_state"] == {"awaiting_human": 8, "dispositioned": 21, "suppressed": 2}
    assert s["open_reviews"] == 8


def test_cases_land_where_the_story_says(seeded):
    eng = seeded[0]
    t = demo.case_table(eng)
    auto = [k for k in t if k.startswith(("order_stuck_in_stock:AR-100", "channel_sync_failed:"))]
    assert len(auto) == 16 and all(t[k][1] == "dispositioned" for k in auto if "AR-1003" not in k)
    assert t["channel_sync_rejected:AR-10022"][1] == "awaiting_human"      # a rejected update needs a person
    assert t["payment_orphaned:PAY-9001"][1] == "dispositioned"            # fixed by finance
    assert t["payment_orphaned:PAY-9002"][1] == "awaiting_human"
    assert t["stock_drift_large:SKU-2010"][1] == "awaiting_human"
    assert t["stock_drift_small:SKU-2004"][1] == "awaiting_human"          # waits since the step back
    assert t["order_stuck_in_stock:AR-10031"][1] == "suppressed"           # the store outage covers it
    assert t["location_down:STORE-12"][1] == "awaiting_human"


def test_automatic_retry_recovers_and_reversal_restores(seeded):
    _eng, systems, model, _ = seeded
    assert systems.sync_attempts["AR-10020"] == 2 and "AR-10020" in systems.synced     # failed once, then landed
    assert systems.channel_stock[("webstore", "SKU-2003")] == 28                     # the reversed correction
    assert systems.channel_stock[("webstore", "SKU-2001")] == 120
    assert systems.orders["AR-10001"]["expedited"] is True
    assert model.calls > 0 and "no network" in model.model


def test_reversal_stepped_the_pattern_back_and_a_step_up_is_pending(seeded):
    s = demo.summary(seeded[0])
    assert s["routes"]["stock_drift_small"] == "hitl"
    assert s["routes"]["order_stuck_no_stock"] == "hitl"
    assert s["pending_promotions"] == {"order_stuck_no_stock": "llm"}


def test_seeding_twice_is_a_no_op(seeded, tmp_path):
    eng = seeded[0]
    before = demo.case_table(eng)
    assert demo.seed(eng) == {"seeded": False, "events": 0}
    eng2, _s, _m = demo.build_engine(str(tmp_path / "demo.db"))          # reopen the same file
    assert demo.seed(eng2)["seeded"] is False
    assert demo.case_table(eng2) == before


def test_two_runs_are_identical(seeded):
    eng_b, systems_b, _m = demo.build_engine()
    demo.seed(eng_b)
    assert demo.case_table(seeded[0]) == demo.case_table(eng_b)
    assert demo.summary(seeded[0]) == demo.summary(eng_b)
    assert systems_b.log == seeded[1].log


def test_api_console_and_tokens(running):
    base = running.base
    assert httpx.get(base + "/healthz").status_code == 200
    page = httpx.get(base + "/console")
    assert page.status_code == 200 and "Sentinel" in page.text
    assert httpx.get(base + "/v1/reviews").status_code == 401
    assert httpx.get(base + "/v1/reviews", headers={"Authorization": "Bearer nope"}).status_code == 401
    for pid in demo.TOKENS:
        assert httpx.get(base + "/v1/reviews", headers=auth(pid)).status_code == 200, pid
    assert len(httpx.get(base + "/v1/reviews", headers=auth("nora")).json()) >= 2   # her no-stock orders wait


def test_a_person_approves_the_step_up_and_it_is_gated_by_role(running):
    base = running.base
    denied = httpx.post(base + "/v1/patterns/order_stuck_no_stock/promotion/approve", headers=auth("nora"))
    assert denied.status_code in (401, 403)
    ok = httpx.post(base + "/v1/patterns/order_stuck_no_stock/promotion/approve", headers=auth("dev"))
    assert ok.status_code == 200 and ok.json()["route"] == "llm"
    assert running.engine.pattern_state(running.engine.registry.get("order_stuck_no_stock")).route is Route.LLM


def test_tokens_are_distinct():
    assert len(set(demo.TOKENS.values())) == len(demo.TOKENS)


def test_main_check_mode_exits_clean(capsys):
    assert demo.main(["--check"]) == 0
    assert '"cases": 31' in capsys.readouterr().out
