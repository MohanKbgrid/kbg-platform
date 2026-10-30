# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""The console in a real browser (headless Chromium): sign in, every page renders without script errors,
edit an exception through the form and publish it, add a person, decide a review."""
from __future__ import annotations

import socket
import threading
import time

import pytest

pytest.importorskip("fastapi")
sync_api = pytest.importorskip("playwright.sync_api")

from sentinel import Guardrails, SQLiteStore  # noqa: E402
from sentinel.api import Principal, create_app, token_hash  # noqa: E402
from sentinel.rbac import AuthorityRule  # noqa: E402
from tests.conftest import job_event  # noqa: E402
from tests.test_rbac import make_directory  # noqa: E402

PAGES = ["overview", "reviews", "cases", "trace", "value", "plan", "privacy", "fleet", "golive", "exceptions", "learning", "insights", "activity", "setup", "people", "connectors", "models",
         "access", "changes", "keys", "silences", "metrics", "capabilities", "agents"]


@pytest.fixture
def served(engine_factory, tmp_path):
    import uvicorn
    d = make_directory()
    d.rules.append(AuthorityRule(role_id="ops_head", action="__configure__"))
    eng = engine_factory(directory=d, guardrails=Guardrails(), store=SQLiteStore(str(tmp_path / "b.db")))
    eng.ingest(job_event(error="E7", ref="J7", key="k7"))                 # one review waiting
    app = create_app(eng, {token_hash("hari-token"): Principal("person", "hari")}, config_sync_s=0)
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
def page():
    with sync_api.sync_playwright() as p:
        try:
            browser = p.chromium.launch()
        except Exception as e:  # noqa: BLE001
            pytest.skip(f"no Chromium for Playwright: {e}")
        pg = browser.new_page(viewport={"width": 1400, "height": 900})
        pg.errors = []
        pg.on("pageerror", lambda e: pg.errors.append(str(e)))
        pg.on("console", lambda m: m.type == "error" and pg.errors.append(m.text))
        yield pg
        browser.close()


def sign_in(pg, base):
    pg.goto(base + "/console")
    pg.fill("#token", "hari-token")
    pg.click("#signin")
    pg.wait_for_selector(".topbar h1")


def test_every_page_renders(served, page):
    _, base = served
    sign_in(page, base)
    for name in PAGES:
        page.goto(f"{base}/console#/{name}")
        page.wait_for_timeout(300)
        assert page.inner_text(".topbar h1") != "Something went wrong", name
    assert page.errors == []


def test_bad_token_is_refused(served, page):
    _, base = served
    page.goto(base + "/console")
    page.fill("#token", "wrong")
    page.click("#signin")
    page.wait_for_selector(".problems .error")


def test_edit_publish_add_person_and_decide(served, page):
    eng, base = served
    sign_in(page, base)
    page.goto(base + "/console#/exceptions")
    page.click("text=site_down")
    page.locator(".drawer .field", has_text="SLA (minutes)").locator("input").fill("45")
    page.click(".drawer >> text=Keep change")
    page.click(".pending >> text=Review and save")
    page.wait_for_selector(".modal .diff")
    assert "sla_minutes: 45" in page.inner_text(".modal .diff")
    page.click(".modal >> text=Save and publish")
    page.wait_for_selector(".toast")
    assert eng.registry.get("site_down").sla_minutes == 45

    page.goto(base + "/console#/people")
    page.wait_for_selector("text=Role tree")
    page.click(".topbar >> text=Add person")
    page.locator(".drawer .field", has_text="Id").locator("input").fill("priya")
    page.click(".drawer >> text=Add role")
    page.locator(".drawer select").first.select_option("ops")
    page.locator(".drawer input[placeholder^='scope']").fill("system=billing")
    page.click(".drawer >> text=Keep change")
    page.click(".pending >> text=Review and save")
    page.wait_for_selector(".modal")
    page.click(".modal >> text=Save and publish")
    page.wait_for_selector(".toast")
    assert eng.directory.roles_of("priya", {"system": "billing"}) == {"ops"}
    assert eng.directory.roles_of("priya", {"system": "crm"}) == set()

    page.goto(base + "/console#/reviews")
    page.wait_for_selector("text=Choose an action")
    page.click("text=Choose an action")
    page.wait_for_selector(".modal")
    assert '"ref": ""' in page.input_value(".modal textarea")          # the action's parameters, ready to fill
    page.fill(".modal textarea", '{"ref": "J7"}')
    page.click(".modal >> text=Do it")
    import time
    for _ in range(50):                    # the earlier publish's toast may still be showing: wait for the work
        if not eng.store.open_reviews():
            break
        time.sleep(0.1)
    assert eng.store.open_reviews() == [] and page.errors == []


def test_segment_promotions_in_the_exceptions_page(engine_factory, backend, tmp_path, page):
    import uvicorn

    from sentinel import Pattern, PatternState, PlaybookStep, Route
    from tests.conftest import make_overlay
    pat = Pattern(id="job_timeout", event_types=["job.failed"], match={"error": "TIMEOUT"}, route=Route.HITL,
                  playbook=[PlaybookStep(action="retry", params={"ref": "{{payload.ref}}"})],
                  allowed_actions=["retry", "notify"], owner_role="ops", trust_by=["system"])
    eng = engine_factory(ov=make_overlay(backend, patterns=[pat]), directory=make_directory(),
                         store=SQLiteStore(str(tmp_path / "s.db")))
    p = eng.registry.get("job_timeout")
    for seg, pending in (("system=billing", Route.LLM), ("system=payroll", None)):
        eng.store.put_pattern_state(PatternState(pattern_id=f"job_timeout@{seg}", route=Route.HITL, streak=4,
                                                 definition_hash=p.definition_hash(), pending_promotion=pending))
    app = create_app(eng, {token_hash("hari-token"): Principal("person", "hari")}, config_sync_s=0)
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
    try:
        base = f"http://127.0.0.1:{port}"
        sign_in(page, base)
        page.goto(f"{base}/console#/exceptions")
        page.wait_for_selector(".seg")
        text = page.inner_text("table")
        assert "earned per system" in text and "system=billing" in text and "system=payroll" in text
        page.screenshot(path=str(tmp_path / "segments.png"))
        page.click(".seg >> text=Approve")
        page.wait_for_timeout(500)
        assert eng.store.get_pattern_state("job_timeout@system=billing").route is Route.LLM
        assert page.errors == []
    finally:
        server.should_exit = True
        t.join(5)


def test_single_sign_on_and_giving_access(engine_factory, tmp_path, page, monkeypatch):
    import uvicorn

    from sentinel.sso import SSOConfig
    from tests.fake_oidc import FakeOIDC
    idp = FakeOIDC(secret=None)
    d = make_directory()
    d.rules.append(AuthorityRule(role_id="ops_head", action="__access__"))
    d.people["hari"].contact["email"] = "hari@acme.in"
    eng = engine_factory(directory=d, store=SQLiteStore(str(tmp_path / "a.db")))
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    base = f"http://127.0.0.1:{port}"
    sso = SSOConfig(issuer=idp.issuer, client_id="sentinel-console", redirect_url=f"{base}/console/sso/callback")
    app = create_app(eng, {}, config_sync_s=0, sso=sso)
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_config=None, access_log=False))
    t = threading.Thread(target=server.run, daemon=True)
    t.start()
    for _ in range(200):
        if server.started:
            break
        time.sleep(0.02)
    try:
        page.goto(base + "/console")
        page.wait_for_selector("#sso-login")
        page.screenshot(path=str(tmp_path / "signin.png"))
        page.click("#sso-login")
        page.wait_for_selector(".topbar h1")
        assert "#sso=" not in page.url                                      # the token left the address bar
        page.goto(f"{base}/console#/access")
        page.wait_for_selector("text=Give access")
        page.click("text=Give access")
        page.select_option("#tok-kind", "service")
        page.fill("#tok-principal", "shopify-hooks")
        page.fill("#tok-label", "webhooks")
        page.click("#tok-give")
        page.wait_for_selector("#tok-value")
        token = page.inner_text("#tok-value").strip()
        assert token.startswith("stk_")
        page.screenshot(path=str(tmp_path / "access.png"))
        page.click("text=Done")
        page.wait_for_selector("text=shopify-hooks")
        assert "sign-on session" in page.inner_text("table")
        page.click("text=Sign out")
        page.wait_for_selector("#sso-login")
        sessions = [x for x in eng.store.api_tokens() if x.source == "sso"]
        assert sessions and all(x.revoked_at for x in sessions)               # signing out ended the session
        assert page.errors == []
    finally:
        server.should_exit = True
        t.join(5)
        idp.close()


def test_cases_trace_and_reverse(served, page, backend):
    """A2 + A3: find a case, read its story, trace its event again, and reverse an automatic fix."""
    eng, base = served
    r = eng.ingest(job_event(error="TIMEOUT", ref="ORD-5521", key="k8", system="crm"))
    rv = eng.store.open_review_for(r.incident_id)
    if rv is not None:                                  # this directory keeps retries for a person: approve it
        from sentinel import Decision, DecisionKind
        eng.decide(rv.id, Decision(kind=DecisionKind.APPROVE, actor="hari"))
    assert eng.store.get_disposition(r.incident_id) is not None
    sign_in(page, base)
    page.goto(base + "/console#/cases")
    page.fill("input[placeholder^='Order number']", "ord-5521")
    page.click(".card >> text=Search")
    page.wait_for_selector(f"text={r.incident_id}")
    page.click(f"text={r.incident_id}")
    page.wait_for_selector("h3:text-is('Story')", timeout=5000)
    assert "opened as job_timeout" in page.inner_text(".content")
    page.click("text=Trace its event again")
    page.wait_for_selector("text=Step by step")
    assert "Ignored: already received" not in page.inner_text(".content")        # a new event id each trace
    assert "job_timeout" in page.inner_text(".content")
    page.goto(f"{base}/console#/case?id={r.incident_id}")
    page.wait_for_selector("text=Reverse this fix")
    page.click("text=Reverse this fix")
    page.fill(".modal textarea", "retried the wrong job")
    page.click(".modal >> button.danger")
    page.wait_for_selector(".toast")
    assert eng.store.get_disposition(r.incident_id).reversed is True
    assert page.errors == []


def test_mobile_review_page_and_bulk_bar(served, page):
    eng, base = served
    page.set_viewport_size({"width": 390, "height": 844})
    page.goto(base + "/console/m")
    page.fill("input[type=password]", "hari-token")
    page.click(".m-signin button")
    page.wait_for_selector(".m-card:not(.m-signin) h3")             # a case card, not the sign-in card
    assert "1 waiting" in page.inner_text("#m-count")
    page.click(".m-actions button:has-text('Close')")
    page.wait_for_selector("text=Nothing waiting for you.")
    assert eng.store.open_reviews() == []
    for i in range(3):
        eng.ingest(job_event(error="E8", ref=f"J8{i}", system=f"s{i}", key=f"k8{i}"))
    page.set_viewport_size({"width": 1400, "height": 900})
    page.goto(base + "/console")
    page.evaluate("sessionStorage.setItem('sentinel_token', 'hari-token')")
    page.goto(base + "/console#/reviews")
    page.reload()                                      # render the reviews page fresh, with the token
    page.wait_for_selector("text=Select all shown", timeout=60000)
    page.click("text=Select all shown")
    page.click("text=Close selected")
    page.wait_for_selector(".toast")
    assert eng.store.open_reviews() == [] and page.errors == []


def test_playbook_builder(served, page):
    eng, base = served
    sign_in(page, base)
    page.goto(base + "/console#/exceptions")
    page.click("text=site_down")
    pb = page.locator(".drawer .playbook")
    pb.locator("text=+ Lookup").click()
    pb.locator(".step").nth(0).locator("select").nth(1).select_option("lookup")
    pb.locator(".step").nth(0).locator(".pf", has_text="ref").locator("input").fill("{{payload.site}}")
    pb.locator(".step").nth(0).locator("text=+ condition").click()
    row = pb.locator(".step").nth(0).locator(".wrow")
    row.locator("input").nth(0).fill("payload.site")
    row.locator("select").select_option("not_empty")
    pb.locator("text=+ Action").click()
    second = pb.locator(".step").nth(1)
    second.locator("select").nth(1).select_option("notify")
    second.locator(".pf", has_text="ref").locator("input").fill("{{payload.site}}")
    page.click(".drawer >> text=Keep change")
    assert "notify needs msg" in page.inner_text(".toast")             # required parameter missing
    second.locator(".pf", has_text="msg").locator("input").fill("Site {{payload.site}} is down")
    second.locator("text=↑").click()                                  # reorder: notify first
    page.click(".drawer >> text=Keep change")
    page.click(".pending >> text=Review and save")
    page.wait_for_selector(".modal .diff")
    page.click(".modal >> text=Save and publish")
    page.wait_for_selector(".toast")
    steps = eng.registry.get("site_down").playbook
    assert [s.kind for s in steps] == ["action", "lookup"]
    assert steps[0].params == {"ref": "{{payload.site}}", "msg": "Site {{payload.site}} is down"}
    assert steps[1].when == {"payload.site": {"empty": False}} and steps[1].as_ == "lookup"
    assert page.errors == []


def test_add_a_ready_made_connector(served, page):
    eng, base = served
    sign_in(page, base)
    page.goto(base + "/console#/connectors")
    page.wait_for_selector("text=Ready-made connectors")
    page.locator("tr", has_text="Shiprocket").locator("text=Add to draft").click()
    page.wait_for_selector(".modal >> text=SENTINEL_SECRET_SHIPROCKET_EMAIL")
    page.click(".modal button:text-is(\"OK\")")
    page.click(".pending >> text=Review and save")
    page.wait_for_selector(".modal .diff")
    page.click(".modal >> text=Save and publish")
    page.wait_for_selector(".toast")
    assert "shiprocket.track_awb" in eng.tools.tools and "shiprocket.ndr_reattempt" in {
        s.name for s in eng.actions.specs()}
    assert page.errors == []


def test_keys_page_saves_a_key(served, page, monkeypatch):
    from sentinel import connectors as ct
    from sentinel.config import dump_yaml
    from sentinel.secretstore import new_master_key
    monkeypatch.setenv("SENTINEL_MASTER_KEY", new_master_key())
    eng, base = served
    cv, _ = eng.save_config("connectors", dump_yaml(ct.merge({}, "delhivery")), "hari")
    eng.publish_config(cv.id, actor="hari")
    sign_in(page, base)
    page.goto(base + "/console#/keys")
    row = page.locator("tr", has_text="SENTINEL_SECRET_DELHIVERY_TOKEN")
    row.wait_for()
    assert "missing" in row.inner_text()
    row.locator("input[type=password]").fill("dlv-token-1234")
    row.locator("button:text-is('Save')").click()
    page.wait_for_selector(".toast")
    page.wait_for_timeout(500)
    row = page.locator("tr", has_text="SENTINEL_SECRET_DELHIVERY_TOKEN")
    assert "set here" in row.inner_text() and "1234" in row.inner_text() and "dlv-token" not in row.inner_text()
    assert page.errors == []
    from sentinel import envsecrets
    envsecrets._STORED.clear()


def test_silence_from_the_console_holds_a_case(served, page):
    eng, base = served
    sign_in(page, base)
    page.goto(base + "/console#/silences")
    page.click("button:text-is('New silence')")
    page.fill("input[placeholder^='e.g. stock count']", "stock count tonight")
    page.fill("textarea[placeholder='location=WH_CHN']", "system=hr")
    page.click(".modal button:text-is('Silence')")
    page.wait_for_selector("td:has-text('stock count tonight')")
    assert len(eng.silences.active()) == 1
    eng.ingest(job_event(error="AUTH", system="hr", ref="J8", key="k8"))
    page.goto(base + "/console#/reviews")
    page.wait_for_selector("text=Held by a silence")
    page.goto(base + "/console#/silences")
    row = page.locator("tr", has_text="stock count tonight")
    row.wait_for()
    assert "1" in row.locator("td.num").inner_text()
    row.locator("button:text-is('End now')").click()
    page.wait_for_selector(".toast")
    assert eng.silences.active() == []
    assert page.errors == []


def test_metrics_page_and_raising_a_case(served, page):
    pytest.importorskip("duckdb")
    import yaml
    eng, base = served
    text = yaml.safe_dump({"datasets": {"cases": {"kind": "sentinel", "name": "cases"}},
                           "metrics": {"cases_opened": {"title": "Cases opened", "dataset": "cases", "time": "created_at",
                                                        "value": "count(*)", "dimensions": ["pattern"]}}})
    cv, probs = eng.save_config("metrics", text, "hari")
    eng.publish_config(cv.id, actor="hari")
    sign_in(page, base)
    page.goto(base + "/console#/metrics")
    tile = page.locator(".card.stat", has_text="Cases opened")
    tile.wait_for()
    assert "1" in tile.inner_text()
    tile.click()
    page.wait_for_selector("aside.drawer td:has-text('job_failed_other')")
    page.fill("aside.drawer input[placeholder^='What should']", "too many failures")
    page.click("aside.drawer button:text-is('Open a case')")
    page.wait_for_selector(".toast")
    assert any(i.first_event["type"] == "kpi.raised" for i in eng.store.incidents())
    assert page.errors == []
