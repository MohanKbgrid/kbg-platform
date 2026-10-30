# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""Metrics: KPIs over datasets, monitors that raise cases (analytics -> agents), the metric lookup and
outcome check (agents -> analytics), and Ask AI answers with A2UI and a raise button (people -> agents)."""
from __future__ import annotations

import json
from datetime import timedelta

import pytest
import yaml

from sentinel import FingerprintRule, Guardrails, IncidentState as S, Pattern, Route
from sentinel.kpi import KpiError, parse, widget
from sentinel.models import ClearEvent, ClearWhen
from sentinel.rbac import AuthorityRule
from tests.conftest import Backend, make_overlay
from tests.test_rbac import make_directory

pytest.importorskip("duckdb")

LATE = {"WH_CHN": 0.0}        # share of orders late at each location, changed by the tests


def orders(clock):
    def rows(services, now):
        out = []
        for day in range(14):
            for i in range(20):
                for loc in ("WH_CHN", "STORE_FLG"):
                    t = clock() - timedelta(days=day, hours=1 + i % 5)
                    late = day == 0 and i < LATE.get(loc, 0.0) * 20
                    out.append({"order_id": f"{loc}-{day}-{i}", "location": loc,
                                "channel": "shopify" if i % 2 else "ajio", "promised_at": t.isoformat(),
                                "on_time": not late, "in_full": True, "hours_to_dispatch": 30.0 if late else 8.0})
        return out
    return rows


METRICS = {
    "datasets": {"orders": {"kind": "overlay", "name": "orders", "refresh_minutes": 1},
                 "cases": {"kind": "sentinel", "name": "cases"}},
    "metrics": {
        "otif": {"title": "On time in full", "dataset": "orders", "time": "promised_at",
                 "value": "avg(case when on_time and in_full then 1.0 else 0 end)", "format": "percent",
                 "dimensions": ["location", "channel"], "target": {"gte": 0.97}, "owner": "ops"},
        "dispatch_hours": {"title": "Hours to dispatch", "dataset": "orders", "time": "promised_at",
                           "value": "avg(hours_to_dispatch)", "format": "hours", "dimensions": ["location"],
                           "target": {"lte": 24}, "roles": ["lead"]},
        "cases_opened": {"title": "Cases opened", "dataset": "cases", "time": "created_at", "value": "count(*)",
                         "dimensions": ["pattern"]},
    },
    "monitors": {"otif_by_location": {"metric": "otif", "by": ["location"], "window_days": 1, "every_minutes": 60,
                                      "min_rows": 10}},
}


@pytest.fixture
def eng(engine_factory, clock):
    LATE.clear()
    ov = make_overlay(Backend(), patterns=[
        Pattern(id="otif_breach", event_types=["kpi.breach"], match={"monitor": "otif_by_location"}, route=Route.HITL,
                allowed_actions=["notify"], owner_role="ops", escalation_role="lead",
                clear_when=ClearWhen(events=[ClearEvent(type="kpi.recovered", same=["monitor", "location"])]),
                outcome_check={"verifier": "metric", "after_minutes": 60, "params": {"metric": "otif",
                                                                                    "facts": ["location"]}}),
        Pattern(id="kpi_raised", event_types=["kpi.raised"], route=Route.HITL, allowed_actions=["notify"],
                owner_role="ops")])
    ov.fingerprint_rules += [
        FingerprintRule(event_type="kpi.breach", fields={"monitor": "monitor", "metric": "metric",
                                                         "location": "location"}, group_by=["monitor", "location"]),
        FingerprintRule(event_type="kpi.recovered", fields={"monitor": "monitor", "location": "location"}),
        FingerprintRule(event_type="kpi.raised", fields={"metric": "metric", "location": "location",
                                                         "raised_by": "raised_by"})]
    ov.datasets = {"orders": orders(clock)}
    d = make_directory()
    d.rules.append(AuthorityRule(role_id="ops_head", action="__configure__"))
    e = engine_factory(ov=ov, directory=d, guardrails=Guardrails())
    cv, probs = e.save_config("metrics", yaml.safe_dump(METRICS), author="hari")
    assert not [p for p in probs if p.severity == "error"], probs
    assert not [p for p in probs if "fingerprint" in p.message or "closes on" in p.message], probs
    e.publish_config(cv.id, actor="hari")
    return e


def test_query_by_dimension_over_time_and_compared(eng, clock):
    LATE["WH_CHN"] = 0.25
    r = eng.kpi.query("otif", by=["location"], days=1, compare=True)
    by = {x["location"]: x for x in r["rows"]}
    assert by["WH_CHN"]["value"] == pytest.approx(0.75) and by["WH_CHN"]["target_ok"] is False
    assert by["STORE_FLG"]["target_ok"] is True and by["WH_CHN"]["baseline"] == 1.0
    assert by["WH_CHN"]["change_pct"] == pytest.approx(-25.0) and r["total"]["text"] == "87.5%"
    t = eng.kpi.query("otif", grain="day", days=7, filters={"location": "WH_CHN"})
    assert len(t["rows"]) >= 7 and widget(t)["type"] == "line"
    assert widget(r)["type"] == "bar" and widget(eng.kpi.query("otif"))["type"] == "kpi"
    with pytest.raises(KpiError, match="cannot be split"):
        eng.kpi.query("otif", by=["sku"])
    with pytest.raises(KpiError, match="unknown metric"):
        eng.kpi.query("nope")


def test_metric_sql_cannot_reach_outside(eng):
    with pytest.raises(Exception, match="only an expression"):
        parse({**METRICS, "metrics": {"x": {**METRICS["metrics"]["otif"], "value": "1; drop table ds_orders"}}})
    doc = parse({**METRICS, "metrics": {"x": {**METRICS["metrics"]["otif"],
                                              "value": "(select count(*) from read_csv('/etc/passwd'))"}}})
    from sentinel.kpi import Warehouse
    w = Warehouse(eng, doc)
    with pytest.raises(KpiError, match="(?i)external|disabled|permission"):
        w.query("x")


def test_monitor_raises_a_case_keeps_it_alive_and_closes_it_on_recovery(eng, clock):
    LATE["WH_CHN"] = 0.3
    out = eng.run_monitor("otif_by_location")
    assert out["raised"] == ["location=WH_CHN"]
    inc = next(i for i in eng.store.incidents() if i.pattern_id == "otif_breach")
    assert inc.facts["location"] == "WH_CHN" and inc.state is S.AWAITING_HUMAN
    clock.advance(minutes=61)
    assert eng.run_monitor("otif_by_location")["still_breaching"] == ["location=WH_CHN"]
    assert len([i for i in eng.store.incidents() if i.pattern_id == "otif_breach"]) == 1   # one case, reported again
    assert eng.store.open_review_for(inc.id).reported_at is not None
    LATE["WH_CHN"] = 0.0
    clock.advance(minutes=61)
    assert eng.run_monitor("otif_by_location")["recovered"] == ["location=WH_CHN"]
    assert eng.store.get_disposition(inc.id).code == "resolved_in_source"
    assert eng.schedule_sources() >= 1 and eng.work("w")["done"] >= 1             # the worker runs monitors too


def test_agents_read_metrics_and_the_outcome_check_measures_the_fix(eng, clock, backend):
    assert "metrics.query" in eng.tools.tools
    got = eng.tools.call("metrics.query", {"metric": "otif", "by": ["location"], "days": 1}, {})
    assert got["total"]["text"] == "100.0%" and "rows" in got
    assert "error" in eng.tools.call("metrics.query", {"metric": "nope"}, {})
    LATE["WH_CHN"] = 0.3
    clock.advance(minutes=2)                                          # the dataset refreshes every minute
    eng.run_monitor("otif_by_location")
    inc = next(i for i in eng.store.incidents() if i.pattern_id == "otif_breach")
    rev = eng.store.open_review_for(inc.id)
    from sentinel import Decision, DecisionKind
    eng.decide(rev.id, Decision(kind=DecisionKind.MODIFY, actor="ravi", action="notify",
                                params={"ref": "WH_CHN", "msg": "expedite the late picks"}))
    LATE["WH_CHN"] = 0.0
    clock.advance(minutes=61)
    eng.work("w")
    assert eng.store.get_disposition(inc.id).outcome == "held"


def test_sentinel_cases_are_a_dataset(eng):
    LATE["WH_CHN"] = 0.3
    eng.run_monitor("otif_by_location")
    r = eng.kpi.query("cases_opened", by=["pattern"], days=1)
    assert {x["pattern"]: x["value"] for x in r["rows"]}["otif_breach"] == 1


def test_ask_ai_answers_with_a2ui_and_raises_cases(eng, clock):
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from sentinel.api import Principal, create_app, token_hash
    from sentinel.edges import sign
    tokens = {token_hash("ravi-t"): Principal("person", "ravi"), token_hash("lata-t"): Principal("person", "lata")}
    import os
    os.environ["SENTINEL_EDGE_ASK_AI"] = "s" * 32
    text = yaml.safe_dump({"edges": {"ask_ai": {"kind": "a2ui", "url": "https://askai.example/cards",
                                                "secret_env": "SENTINEL_EDGE_ASK_AI"}}})
    cv, _ = eng.save_config("connectors", text, author="hari")
    eng.publish_config(cv.id, actor="hari")
    c = TestClient(create_app(eng, tokens, console=False))
    h = {"Authorization": "Bearer ravi-t"}
    cat = c.get("/v1/ask/catalog", headers=h).json()
    names = {m["name"] for m in cat["metrics"]}
    assert "otif" in names and "dispatch_hours" not in names                 # ravi (ops) is not a lead
    assert {t["name"] for t in cat["tools"]} == {"sentinel_metric", "sentinel_raise"}
    assert "dispatch_hours" in {m["name"] for m in c.get("/v1/ask/catalog",
                                                         headers={"Authorization": "Bearer lata-t"}).json()["metrics"]}
    LATE["WH_CHN"] = 0.25
    ans = c.post("/v1/ask/metric", headers=h, json={"metric": "otif", "by": ["location"], "days": 1}).json()
    assert ans["widget"]["type"] == "bar" and "missing target: WH_CHN" in ans["summary"]
    comps = {x["id"]: x["component"] for x in ans["a2ui"][0]["surfaceUpdate"]["components"]}
    assert comps["raise"]["Button"]["action"]["name"] == "sentinel.raise" and "Chart" in comps["chart"]
    assert c.post("/v1/ask/metric", headers=h, json={"metric": "dispatch_hours"}).status_code == 404
    assert c.post("/v1/ask/metric", headers=h, json={"metric": "otif", "by": ["sku"]}).status_code == 422
    r = c.post("/v1/ask/raise", headers=h, json={"metric": "otif", "filters": {"location": "WH_CHN"},
                                                 "note": "please look"}).json()
    inc = eng.store.get_incident(r["incident_id"])
    assert inc.pattern_id == "kpi_raised" and inc.facts["location"] == "WH_CHN" and inc.facts["raised_by"] == "ravi"
    # the button on the A2UI answer, pressed in chat: a signed userAction
    ctx = {e["key"]: e["value"]["literalString"] for e in comps["raise"]["Button"]["action"]["context"]}
    msg = json.dumps({"person_id": "lata", "userAction": {"name": "sentinel.raise", "context": ctx}}).encode()
    ts, sig = sign("s" * 32, msg)
    res = c.post("/v1/edges/ask_ai/a2ui", content=msg, headers={"X-Sentinel-Timestamp": ts,
                                                                "X-Sentinel-Signature": sig})
    assert res.status_code == 200, res.text
    assert eng.store.get_incident(res.json()["incident_id"]).facts["raised_by"] == "lata"
    bad = c.post("/v1/edges/ask_ai/a2ui", content=msg, headers={"X-Sentinel-Timestamp": ts,
                                                                "X-Sentinel-Signature": "sha256=0"})
    assert bad.status_code == 401
    del os.environ["SENTINEL_EDGE_ASK_AI"]


def test_configuration_checks():
    from sentinel.config import Context, check
    ctx = Context(actions=None, verifiers={}, edges=set(), fingerprints=[], patterns=[], roles={},  # type: ignore[arg-type]
                  directory=None)
    bad = {**METRICS, "monitors": {"m": {"metric": "otif", "by": ["sku"]}, "n": {"metric": "nope"}}}
    _, probs = check("metrics", yaml.safe_dump(bad), ctx)
    msgs = [p.message for p in probs if p.severity == "error"]
    assert any("not a dimension" in m for m in msgs) and any("unknown metric" in m for m in msgs)
    _, probs = check("metrics", yaml.safe_dump(METRICS), ctx)
    assert any("no fingerprint rule for kpi.breach" in p.message for p in probs)


def test_sql_datasets_bind_params_and_read_numerics(engine_factory, monkeypatch):
    import os
    dsn = os.environ.get("SENTINEL_TEST_PG")
    if not dsn:
        pytest.skip("needs SENTINEL_TEST_PG")
    monkeypatch.setenv("SENTINEL_SECRET_TEST_DB", dsn)
    monkeypatch.setenv("SENTINEL_SECRET_TEST_TENANT", "t1")
    doc = parse({"datasets": {"x": {"kind": "sql", "dsn_env": "SENTINEL_SECRET_TEST_DB",
                                    "params": {"tenant": "{{env.SENTINEL_SECRET_TEST_TENANT}}"},
                                    "query": "SELECT %(tenant)s AS tenant, 12.50::numeric AS amount, "
                                             "'2026-10-10T08:00:00+00:00'::timestamptz AS at"}},
                 "metrics": {"amt": {"title": "Amount", "dataset": "x", "time": "at", "value": "sum(amount)",
                                     "dimensions": ["tenant"]}}})
    from sentinel.kpi import Warehouse
    w = Warehouse(engine_factory(), doc)
    r = w.query("amt", by=["tenant"], days=1)
    assert r["rows"] == [{"tenant": "t1", "value": 12.5, "rows": 1, "text": "12.5", "target_ok": None}]


def test_http_datasets_load(engine_factory):
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    class H(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            body = json.dumps({"data": [{"at": "2026-10-10T08:00:00+00:00", "n": 3}]}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass
    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        doc = parse({"datasets": {"x": {"kind": "http", "url": f"http://127.0.0.1:{srv.server_port}/x",
                                        "items": "body.data"}},
                     "metrics": {"n": {"title": "N", "dataset": "x", "time": "at", "value": "sum(n)"}}})
        from sentinel.kpi import Warehouse
        assert Warehouse(engine_factory(), doc).query("n", days=1)["total"]["value"] == 3
    finally:
        srv.shutdown()


def test_derived_columns_hold_the_rule_whatever_the_source(engine_factory, clock):
    """A business rule written once in configuration (derive), computed in order on the loaded rows, so the
    same rule applies to an overlay, SQL, HTTP or connector dataset."""
    from sentinel.kpi import Warehouse
    ov = make_overlay(Backend())
    now = clock()
    ov.datasets = {"stock": lambda s, n: [
        {"sku": "A", "on_hand": 10.0, "daily": 2.0, "at": now.isoformat()},
        {"sku": "B", "on_hand": 90.0, "daily": 3.0, "at": now.isoformat()}]}
    doc = parse({"datasets": {"stock": {"kind": "overlay", "name": "stock",
                                        "derive": {"cover": "on_hand / nullif(daily, 0)",
                                                   "short": "cover < 7"}}},
                 "metrics": {"short_skus": {"title": "Short", "dataset": "stock", "time": "at",
                                            "value": "sum(case when short then 1 else 0 end)",
                                            "dimensions": ["sku"]}}})
    w = Warehouse(engine_factory(ov=ov), doc)
    r = w.query("short_skus", by=["sku"], days=1)
    assert {x["sku"]: x["value"] for x in r["rows"]} == {"A": 1, "B": 0}
    assert "cover" in w.columns("stock")
    with pytest.raises(ValueError, match="only an expression"):
        parse({"datasets": {"s": {"kind": "overlay", "name": "s", "derive": {"x": "1; drop table t"}}}})
    bad = parse({"datasets": {"stock": {"kind": "overlay", "name": "stock", "derive": {"x": "no_such_col + 1"}}},
                 "metrics": {"m": {"title": "M", "dataset": "stock", "time": "at", "value": "count(*)"}}})
    with pytest.raises(KpiError, match="derive x"):
        Warehouse(engine_factory(ov=ov), bad).query("m", days=1)
