# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""The Agents & oversight page and the money-ranked Reviews view in a real browser (headless Chromium): every
control, at desktop and phone width, light and dark, no script errors. Runs on the R06 exemplar."""
from __future__ import annotations

import socket
import threading
import time
from datetime import UTC, datetime
from pathlib import Path

import pytest
import yaml

pytest.importorskip("fastapi")
sync_api = pytest.importorskip("playwright.sync_api")

from sentinel import Engine, Guardrails, Overlay, Route, SQLiteStore, load_layers  # noqa: E402
from sentinel.api import Principal, create_app, token_hash  # noqa: E402
from sentinel.bindings import load_binding  # noqa: E402
from sentinel.models import Event  # noqa: E402
from sentinel.rbac import parse_directory  # noqa: E402
from sentinel.testing import FrozenClock  # noqa: E402
from tests.test_role_slots import _actions  # noqa: E402

PACK = Path(__file__).parent / "packs" / "r06_stock_integrity"


@pytest.fixture
def served(tmp_path):
    import uvicorn
    data = yaml.safe_load((PACK / "people_chain_a_org.yaml").read_text(encoding="utf-8"))
    data.pop("vacancy")
    data["agents"] = [{"template": "*", "mode": "OBSERVE"},
                      {"template": "r06_phantom_stock", "scope": {"store": "TVM02"}, "mode": "ACT",
                       "grants": {"task.shelf_check": "EDIT"}}]
    data["oversight"] = [{"role": "internal_audit"}]
    data["authority"].append({"role_id": "ops_head", "action": "__set_route__"})
    doc = load_layers([PACK / "template.yaml", PACK / "tenant_chain_a.yaml",
                       ("scale", {"overrides": [{"id": "r06_unrecorded_loss",
                                                 "set": {"digest_above": 1, "money_fact": "value"}}],
                                  "fingerprints": [{"event_type": "inv.depletion_without_sales",
                                                    "fields": {"store": "store", "article": "article",
                                                               "value": "value"},
                                                    "group_by": ["store", "article"]}]})])
    ov = Overlay(name="r06", fingerprint_rules=doc.fingerprints, patterns=doc.patterns, roles=doc.roles,
                 actions=_actions(), directory=parse_directory(data), slots=doc.slots,
                 slot_bindings=doc.slot_bindings, binding=load_binding(PACK / "binding.yaml"))
    eng = Engine(ov, store=SQLiteStore(str(tmp_path / "c.db")), licence=False,
                 clock=FrozenClock(datetime(2026, 10, 20, 9, tzinfo=UTC)),
                 guardrails=Guardrails(allow_irreversible_unattended=True))
    for art, v in (("A1", 120), ("A2", 9000), ("A3", 450)):
        eng.ingest(Event(type="inv.depletion_without_sales", source="pos",
                         payload={"store": "TVM01", "article": art, "value": v}))
    eng.set_route("r06_phantom_stock", Route.AUTO, actor="devi")
    app = create_app(eng, {token_hash("ganesh-tok"): Principal("person", "ganesh"),
                           token_hash("kavya-tok"): Principal("person", "kavya")}, config_sync_s=0)
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_config=None, access_log=False))
    t = threading.Thread(target=server.run, daemon=True)
    t.start()
    for _ in range(200):
        if server.started:
            break
        time.sleep(0.02)
    yield eng, f"http://127.0.0.1:{port}"
    server.should_exit = True
    t.join(5)


@pytest.fixture
def browser():
    with sync_api.sync_playwright() as p:
        try:
            b = p.chromium.launch()
        except Exception as e:  # noqa: BLE001
            pytest.skip(f"no Chromium for Playwright: {e}")
        yield b
        b.close()


def open_page(browser, base, token, width=1400, dark=False):
    ctx = browser.new_context(viewport={"width": width, "height": 900}, color_scheme="dark" if dark else "light")
    pg = ctx.new_page()
    pg.errors = []
    pg.on("pageerror", lambda e: pg.errors.append(str(e)))
    pg.on("console", lambda m: m.type == "error" and pg.errors.append(m.text))
    pg.goto(base + "/console")
    pg.fill("#token", token)
    pg.click("#signin")
    pg.wait_for_selector("nav.nav")
    return pg


@pytest.mark.parametrize("width,dark", [(1400, False), (390, False), (1400, True), (390, True)])
def test_agents_page_renders_everywhere(served, browser, width, dark):
    _, base = served
    pg = open_page(browser, base, "ganesh-tok", width, dark)
    pg.goto(base + "/console#/agents")
    pg.wait_for_selector("main h1:has-text('Agents & oversight')")
    pg.wait_for_selector("main table")
    body = pg.inner_text("main")
    for want in ("store_manager", "accountable", "OBSERVE", "ACT", "internal_audit", "stock.write_off",
                 "r06_phantom_stock", "digest past 1", "ranked by value"):
        assert want in body, want
    assert pg.evaluate("document.documentElement.scrollWidth <= window.innerWidth + 1")    # no sideways page scroll
    assert pg.errors == []


def test_mode_lookup_and_oversight_stop(served, browser):
    eng, base = served
    pg = open_page(browser, base, "ganesh-tok")
    pg.goto(base + "/console#/agents")
    pg.wait_for_selector("text=Which mode applies here?")
    pg.select_option("select[aria-label=Template]", "r06_phantom_stock")
    pg.fill("input[aria-label=Scope]", "store=TVM02")
    pg.click("text=Look up")
    pg.wait_for_selector("text=r06_phantom_stock@store=TVM02")
    assert "ACT" in pg.inner_text("main")
    pg.fill("input[aria-label='Agent to act on']", "r06_phantom_stock@store=TVM02")
    pg.click("button:has-text('Apply')")                           # no reason: refused in the page
    pg.wait_for_selector(".toast.bad")
    pg.fill("input[aria-label=Reason]", "count tasks look wrong at TVM02")
    pg.click("button:has-text('Apply')")
    pg.wait_for_selector(".toast:not(.bad)")
    st = eng.store.get_pattern_state("r06_phantom_stock@store=TVM02")
    assert st.route is Route.HITL and st.cap is Route.HITL
    assert pg.errors == []


def test_oversight_form_only_for_oversight_roles(served, browser):
    _, base = served
    pg = open_page(browser, base, "kavya-tok")
    pg.goto(base + "/console#/agents")
    pg.wait_for_selector("text=Oversight")
    assert pg.locator("input[aria-label=Reason]").count() == 0
    assert pg.errors == []


@pytest.mark.parametrize("width", [1400, 390])
def test_reviews_rank_by_money_and_bulk(served, browser, width):
    eng, base = served
    pg = open_page(browser, base, "kavya-tok", width)
    pg.goto(base + "/console#/reviews")
    pg.wait_for_selector(".review")
    pg.select_option("select[aria-label=Order]", "money")
    pg.wait_for_function("location.hash.includes('order=money')")
    pg.wait_for_selector(".review")
    stakes = pg.locator(".review .badge.b-warn").all_inner_texts()
    assert stakes[:3] == ["9,000 at stake", "450 at stake", "120 at stake"], stakes
    assert pg.locator("text=on digest").count() == 2                 # the first case was a card
    pg.click("text=Select all shown")
    pg.click("text=Approve selected")
    pg.wait_for_selector(".toast")
    assert not [r for r in eng.store.open_reviews() if eng.store.get_incident(r.incident_id).pattern_id
                == "r06_unrecorded_loss"]
    assert pg.errors == []
