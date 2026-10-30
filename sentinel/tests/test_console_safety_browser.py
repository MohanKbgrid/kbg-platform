# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""Spot checks, agent incidents and data trust on the Agents & oversight page, in a real browser (headless
Chromium): every control, desktop and phone width, light and dark, no script errors."""
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
from sentinel.models import Event  # noqa: E402
from sentinel.rbac import parse_directory  # noqa: E402
from sentinel.testing import FrozenClock  # noqa: E402
from tests.test_layer_safety import Store, actions  # noqa: E402

PACK = Path(__file__).parent / "packs" / "r06_stock_integrity"


@pytest.fixture
def served(tmp_path):
    import uvicorn
    data = yaml.safe_load((PACK / "people_chain_a_org.yaml").read_text(encoding="utf-8"))
    data.pop("vacancy")
    data["oversight"] = [{"role": "internal_audit"}]
    data["authority"] += [{"role_id": "internal_audit", "action": "__reverse__"}]
    doc = load_layers([PACK / "template.yaml", PACK / "tenant_chain_a.yaml",
                       ("live", {"overrides": [{"id": "r06_phantom_stock",
                                                "set": {"shadow": False, "route": "auto", "spot_check_rate": 1.0}}],
                                 "defaults": {"data_trust": {"act_min": 0.95, "propose_min": 0.8}}})])
    world = Store()
    ov = Overlay(name="r06", fingerprint_rules=doc.fingerprints, patterns=doc.patterns, roles=doc.roles,
                 actions=actions(world), directory=parse_directory(data), slots=doc.slots,
                 slot_bindings=doc.slot_bindings, case_defaults=doc.defaults)
    eng = Engine(ov, store=SQLiteStore(str(tmp_path / "s.db")),
                 clock=FrozenClock(datetime(2026, 10, 20, 9, tzinfo=UTC)),
                 guardrails=Guardrails(allow_irreversible_unattended=True))
    eng.set_data_trust({"store": "TVM01"}, 0.99, source="ira")
    eng.set_data_trust({"store": "TVM03"}, 0.62, source="ira")
    for art in ("A1", "A2"):
        eng.ingest(Event(type="inv.sales_stopped", source="pos", payload={"store": "TVM01", "article": art,
                                                                           "book_qty": 4}))
    app = create_app(eng, {token_hash("ganesh-tok"): Principal("person", "ganesh"),
                           token_hash("meena-tok"): Principal("person", "meena")}, config_sync_s=0)
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
    yield eng, world, f"http://127.0.0.1:{port}"
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


def open_agents(browser, base, token, width=1400, dark=False, answer=None):
    ctx = browser.new_context(viewport={"width": width, "height": 900}, color_scheme="dark" if dark else "light")
    pg = ctx.new_page()
    pg.errors = []
    pg.on("pageerror", lambda e: pg.errors.append(str(e)))
    pg.on("console", lambda m: m.type == "error" and pg.errors.append(m.text))
    if answer is not None:
        pg.on("dialog", lambda d: d.accept(answer))
    pg.goto(base + "/console")
    pg.fill("#token", token)
    pg.click("#signin")
    pg.wait_for_selector("nav.nav")
    pg.goto(base + "/console#/agents")
    pg.wait_for_selector("main h1:has-text('Agents & oversight')")
    pg.wait_for_selector("text=Spot checks")
    return pg


@pytest.mark.parametrize("width,dark", [(1400, False), (390, True)])
def test_sections_render(served, browser, width, dark):
    _, _, base = served
    pg = open_agents(browser, base, "ganesh-tok", width, dark)
    body = pg.inner_text("main").lower()                                  # headings render uppercase
    for want in ("Spot checks (2)", "Data trust by scope", "store=TVM03", "OBSERVE", "0.62", "Agent incidents",
                 "100% spot-checked", "Open agent incident"):
        assert want.lower() in body, want
    assert pg.evaluate("document.documentElement.scrollWidth <= window.innerWidth + 1")
    assert "null" not in body and pg.errors == []


def test_spot_check_right_and_wrong(served, browser):
    eng, world, base = served
    pg = open_agents(browser, base, "ganesh-tok", answer="shelf was full")
    pg.locator("button:has-text('Right')").first.click()
    pg.wait_for_selector("h3:text-is('Spot checks (1)')")
    pg.locator("button:has-text('Wrong…')").first.click()
    pg.wait_for_selector("text=Nothing waiting for you.")
    verdicts = sorted(d.spot_check for d in eng.store.dispositions())
    assert world.undone and verdicts == ["failed", "passed"]
    assert pg.errors == []


def test_agent_incident_open_and_close(served, browser):
    eng, world, base = served
    pg = open_agents(browser, base, "ganesh-tok", answer="feed lagged; fixed")
    pg.fill("input[aria-label='Agent in the incident']", "r06_phantom_stock")
    pg.click("button:has-text('Open agent incident')")                   # no reason: refused in the page
    pg.wait_for_selector(".toast.bad")
    pg.fill("input[aria-label='Incident reason']", "tasks raised for full shelves")
    pg.check("input[aria-label='Undo what can be undone']")
    pg.click("button:has-text('Open agent incident')")
    pg.wait_for_selector("main .badge.b-bad:has-text('open')")
    assert eng.store.get_pattern_state("r06_phantom_stock").route is Route.HITL and len(world.undone) == 2
    pg.click("button:has-text('Close…')")
    pg.wait_for_selector("main .badge.b-ok:has-text('closed')")
    assert eng.agent_incidents()[0]["postmortem"] == "feed lagged; fixed"
    assert pg.errors == []


def test_owner_sees_checks_but_not_the_incident_form(served, browser):
    _, _, base = served
    pg = open_agents(browser, base, "meena-tok")
    assert "spot checks (2)" in pg.inner_text("main").lower()
    assert pg.locator("button:has-text('Open agent incident')").count() == 0
    assert pg.errors == []


@pytest.mark.parametrize("width,dark", [(1400, False), (390, True)])
def test_judged_wrong_with_nobody_to_undo_it_is_held_by_oversight(served, browser, width, dark):
    """v0.24.0 pass 2, defect 1: no active __reverse__ holder. The case waits with oversight, which sees why it
    can't be undone and can keep it with a reason; there is no Undo button that would only fail."""
    eng, world, base = served
    d = eng.directory
    d.rules[:] = [r for r in d.rules if r.action != "__reverse__"]
    inc = eng.spot_checks("meena")[0]["incident"]
    res = eng.spot_check_verdict(inc, "meena", False, "wrong article")
    assert res["undo_by"]["can_undo"] is False and res["undo_by"]["people"] == ["ganesh"]
    pg = open_agents(browser, base, "ganesh-tok", width, dark, answer="count confirmed the stock")
    card = pg.locator("div.row", has_text="judged wrong: undo needed")
    assert "Nobody active may undo" in card.inner_text()
    assert card.locator("button:has-text('Undo it')").count() == 0
    assert pg.evaluate("document.documentElement.scrollWidth <= window.innerWidth + 1")
    assert "null" not in pg.inner_text("main").lower()
    card.locator("button:has-text('Keep it…')").click()
    pg.wait_for_selector("text=Kept, with your reason")
    assert eng.store.get_disposition(inc).spot_check == "failed_kept" and world.undone == []
    assert pg.errors == []
