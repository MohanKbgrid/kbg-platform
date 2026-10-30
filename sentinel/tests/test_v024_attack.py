# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""The builder's own adversarial suite for v0.24.0, generated from the attack table (ADR-007).

Two parts:
1. A hostile-input sweep over every POST/PUT/PATCH route of the API and console, with a service token and a person
   token holding every right: no input may produce a 500.
2. One test per attack-table cell not already proven elsewhere (each cites its row). Cells proven by other suites
   are listed in ``PROVEN_ELSEWHERE`` so the table and the tests stay in step.
"""
from __future__ import annotations

import json
import threading
from datetime import timedelta

import pytest
import yaml

from sentinel import AuthorizationError, EngineError
from sentinel.org import Agent
from sentinel.orgsync import PolicyError, bind_assertion, load_policy
from tests.test_orgsync import NOW, PACK, engine as osync_engine, keys  # noqa: F401  (fixture)

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from sentinel.api import Principal, create_app, token_hash  # noqa: E402

PROVEN_ELSEWHERE = {
    "bundle: tamper, foreign key, version/content, site pin, skew, expiry": "tests/test_orgsync.py",
    "assertion: every claim, mode narrowing, ttl, replay, other site": "tests/test_orgsync.py, test_v024_pass2.py",
    "receipt: strict fields, batch atomic, flags, reuse, mismatch, dedupe race": "tests/test_v024_pass2.py",
    "data trust: fact rule, strict score, caps, stale, unknown": "tests/test_layer_safety.py, test_v024_pass2.py",
    "spot check: verdict write-once, holder walk, one charge, settled by reversal": "tests/test_v024_pass2.py",
    "agent incident: oversight only, write-once close, strict inputs": "tests/test_layer_safety.py",
    "claims: atomic take, breaker release": "tests/test_layer_safety.py",
    "configuration: strict settings, people fact rule": "tests/test_v024_pass2.py",
}


def _assertion(eng):
    seen = []
    inc = eng.store.get_incident(eng.ingest(__import__("tests.test_layer_safety", fromlist=["stopped"])
                                            .stopped("TVM01")).incident_id)
    return eng.agent_assertion(inc, "task.count", "TVM01/A1"), inc, seen


# ---- 1. hostile sweep -----------------------------------------------------------------------------------

HOSTILE_RAW = [
    "", "null", "[]", '"x"', "1", "true", "{", '{"a":NaN}', '{"a":Infinity}', '{"a":-Infinity}',
    '{"a":1e400}', '{"a":' + "9" * 5000 + "}", "[" * 3000 + "]" * 3000, '{"a":' + '{"b":' * 2000 + "1" + "}" * 2001,
    '{"' + "k" * 100_000 + '":1}', json.dumps({"x": "y" * 1_000_000}),
]
FIELDS = ["pattern", "reason", "note", "ok", "hours", "undo", "facts", "scope", "score", "source", "receipts",
          "postmortem", "route", "action", "days", "share", "text", "doc", "items", "kind", "principal", "event",
          "identifier", "metric", "filters", "by", "review_ids", "decision", "value", "version_ids", "patterns"]
VALUES = [None, True, 1.5, -1, "", "x" * 10_000, [], [1, [2]], {}, {"": None}, float("nan")]


def _routes(app):
    """Every writing route, including those in included routers (FastAPI keeps them nested)."""
    out = []

    def walk(routes, prefix=""):
        for r in routes:
            inner = getattr(r, "original_router", None)
            if inner is not None:
                ctx = getattr(r, "include_context", None)
                walk(inner.routes, prefix + (getattr(ctx, "prefix", "") or "") + (inner.prefix or ""))
                continue
            for m in (getattr(r, "methods", None) or set()) & {"POST", "PUT", "PATCH"}:
                out.append((m, (prefix + r.path).replace("{", "").replace("}", "")))
    walk(app.routes)
    return sorted(set(out))


@pytest.fixture
def sweep_client(keys):  # noqa: F811
    eng = osync_engine(keys)
    data = yaml.safe_load((PACK / "people_chain_a_org.yaml").read_text(encoding="utf-8"))
    roles = {a["role_id"] for a in data["assignments"]}
    assert roles
    toks = {token_hash("svc"): Principal("service", "mon"), token_hash("g"): Principal("person", "ganesh")}
    return eng, TestClient(create_app(eng, toks, config_sync_s=0), raise_server_exceptions=False)


def test_no_route_answers_500_to_hostile_input(sweep_client):
    eng, c = sweep_client
    routes = _routes(c.app)
    assert len(routes) > 30
    fails = []
    for method, path in routes:
        for auth in ("Bearer svc", "Bearer g"):
            h = {"Authorization": auth, "Content-Type": "application/json"}
            for raw in HOSTILE_RAW:
                r = c.request(method, path, content=raw, headers=h)
                if r.status_code >= 500:
                    fails.append((method, path, auth, raw[:40], r.status_code))
            for f in FIELDS:
                for v in VALUES:
                    try:
                        body = json.dumps({f: v})
                    except ValueError:
                        continue
                    r = c.request(method, path, content=body, headers=h)
                    if r.status_code >= 500:
                        fails.append((method, path, auth, f"{f}={v!r}"[:40], r.status_code))
    assert not fails, fails[:20]


# ---- 2. cells -----------------------------------------------------------------------------------------

def test_G1_one_assertion_one_write_under_threads(keys):  # noqa: F811
    """Row 2, "One use, one process": two threads on one snapshot never both pass one assertion."""
    eng = osync_engine(keys)
    for _ in range(20):
        tok, _, _ = _assertion(eng)
        snap = load_policy(eng.export_policy(), keys["public"], clock=lambda: NOW)
        results, barrier = [], threading.Barrier(8)

        def go():
            barrier.wait()
            dec, _ = snap.authorise(None, "task.count", "TVM01/A1", {"store": "TVM01"}, assertion=tok, now=NOW)
            results.append(dec.allowed)
        ts = [threading.Thread(target=go) for _ in range(8)]
        for t in ts:
            t.start()
        for t in ts:
            t.join()
        assert results.count(True) <= 1, results


def test_G5_bind_assertion_one_use_under_threads(keys):  # noqa: F811
    eng = osync_engine(keys)
    tok, _, _ = _assertion(eng)
    used, ok, barrier = {}, [], threading.Barrier(8)

    def go():
        barrier.wait()
        try:
            bind_assertion(tok, keys["public"], action="task.count", obj="TVM01/A1", scope={"store": "TVM01"},
                           site=eng.overlay.name, used=used, now=NOW)
            ok.append(1)
        except PolicyError:
            pass
    ts = [threading.Thread(target=go) for _ in range(8)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    assert len(ok) == 1


def _dt_engine(keys, sources):  # noqa: F811
    from sentinel.models import DataTrust
    eng = osync_engine(keys)
    eng.case_defaults.data_trust = DataTrust(act_min=0.95, propose_min=0.8, sources=sources)
    toks = {token_hash("mon"): Principal("service", "monitoring"), token_hash("pos"): Principal("service", "pos")}
    return eng, TestClient(create_app(eng, toks, config_sync_s=0), raise_server_exceptions=False)


def test_G2_only_listed_principals_post_data_trust(keys):  # noqa: F811
    """Row 4, "Who may set it"."""
    eng, c = _dt_engine(keys, ["monitoring"])
    body = {"scope": {"store": "TVM01"}, "score": 1.0, "source": "monitoring"}
    assert c.post("/v1/data-trust", json=body, headers={"Authorization": "Bearer pos"}).status_code == 403
    assert eng.data_trust_scores() == []
    r = c.post("/v1/data-trust", json=body, headers={"Authorization": "Bearer mon"})
    assert r.status_code == 200 and eng.data_trust_scores()[0]["by"] == "monitoring"
    with pytest.raises(AuthorizationError):
        eng.set_data_trust({"store": "TVM02"}, 1.0, by="pos")
    for bad in ([], [""], "monitoring", [1]):
        from sentinel.models import DataTrust
        with pytest.raises(ValueError):
            DataTrust(sources=bad)


def test_G2_without_sources_validate_warns(keys):  # noqa: F811
    eng, _ = _dt_engine(keys, None)
    assert any("data_trust has no sources" in w for w in eng.coverage())


def test_G3_concurrent_scores_keep_every_index_entry(keys, tmp_path):  # noqa: F811
    from sentinel import Engine, SQLiteStore
    from sentinel.models import DataTrust
    base = osync_engine(keys)
    db = str(tmp_path / "s.db")
    engines = [Engine(base.overlay, store=SQLiteStore(db), licence=False, clock=base.clock) for _ in range(4)]
    for e in engines:
        e.case_defaults.data_trust = DataTrust()
    barrier = threading.Barrier(4)

    def go(e, n):
        barrier.wait()
        for i in range(25):
            e.set_data_trust({"store": f"S{n}-{i}"}, 0.9)
    ts = [threading.Thread(target=go, args=(e, n)) for n, e in enumerate(engines)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    assert len(engines[0].data_trust_scores()) == 100


def test_G4_receipts_record_who_posted_them(keys):  # noqa: F811
    eng, c = _dt_engine(keys, None)
    snap = load_policy(eng.export_policy(), keys["public"], clock=lambda: NOW)
    _, rec = snap.authorise("meena", "task.count", "x", {"store": "TVM01"}, now=NOW)
    r = c.post("/v1/receipts", json={"receipts": [rec.model_dump(mode="json")]}, headers={"Authorization": "Bearer pos"})
    assert r.status_code == 200
    assert eng.store.recent_audit(5, kinds=["authority_receipt"])[0]["data"]["posted_by"] == "pos"


def test_row1_bundle_from_another_key_or_tampered_never_loads(keys):  # noqa: F811
    eng = osync_engine(keys)
    token = eng.export_policy()
    h, p, s = token.split(".")
    with pytest.raises(PolicyError):
        load_policy(f"{h}.{p[:-2]}AA.{s}", keys["public"], clock=lambda: NOW)
    eng.policy_signer = keys["evil"]
    with pytest.raises(PolicyError):
        load_policy(eng.export_policy(), keys["public"], clock=lambda: NOW)


def test_row2_assertion_for_a_person_or_another_agent_is_refused(keys):  # noqa: F811
    eng = osync_engine(keys)
    tok, inc, _ = _assertion(eng)
    snap = load_policy(eng.export_policy(), keys["public"], clock=lambda: NOW)
    for actor in ("someone_else@*", Agent("other@*", bound_role="store_manager")):
        dec, _ = snap.authorise(actor, "task.count", "TVM01/A1", {"store": "TVM01"}, assertion=tok, now=NOW)
        assert not dec.allowed


def test_row2_an_expired_assertion_is_refused_at_the_edge(keys):  # noqa: F811
    eng = osync_engine(keys)
    tok, _, _ = _assertion(eng)
    snap = load_policy(eng.export_policy(), keys["public"], clock=lambda: NOW)
    dec, _ = snap.authorise(None, "task.count", "TVM01/A1", {"store": "TVM01"}, assertion=tok,
                            now=NOW + timedelta(seconds=300))
    assert not dec.allowed


def test_row5_meta_rights_come_from_unscoped_assignments_only(keys):  # noqa: F811
    """Row 5, "Meta rights": a store-scoped holder of __reverse__ can reverse nothing."""
    from sentinel.rbac import parse_directory
    data = yaml.safe_load((PACK / "people_chain_a_org.yaml").read_text(encoding="utf-8"))
    data.pop("vacancy")
    data["authority"] += [{"role_id": "store_manager", "action": "__reverse__"}]
    d = parse_directory(data)
    assert not d.authorize_meta("meena", "__reverse__", "r06_phantom_stock").allowed


def test_the_attack_table_names_every_gap_it_found():
    from pathlib import Path
    adr = (Path(__file__).parents[1] / "docs" / "adr" /
           "ADR-007-v024-offline-enforcement-and-layer-safety.md").read_text(encoding="utf-8")
    for g in ("G1", "G2", "G3", "G4", "G5", "G6"):
        assert f"**{g} " in adr, g
    assert EngineError  # imported for the cells above


def test_a_refusal_is_always_403_never_masked(keys):  # noqa: F811
    """Sibling of G2: handlers that catch EngineError must not turn an AuthorizationError into 409/422."""
    import ast
    from pathlib import Path
    root = Path(__file__).parents[1] / "sentinel"
    masked = []
    for f in (root / "api.py", root / "console" / "__init__.py"):
        for node in ast.walk(ast.parse(f.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Try):
                names = [ast.unparse(h.type) for h in node.handlers if h.type is not None]
                if any("EngineError" in n for n in names) and not any("AuthorizationError" in n for n in names):
                    calls = {ast.unparse(c.func) for c in ast.walk(node) if isinstance(c, ast.Call)}
                    if any(c.startswith("engine.") for c in calls):
                        masked.append((f.name, node.lineno))
    assert not masked, masked


# ---- pass 8 folded in: whitespace facts; trace and ingest agree ----------------------------------------------

@pytest.mark.parametrize("value", ["  ", "\t", "\n", "   "])
def test_whitespace_only_values_and_names_break_the_fact_rule(value):
    from sentinel.factrule import fact_problem
    from sentinel.orgsync import Receipt
    assert fact_problem("depot", value) and fact_problem(value, "D1")
    assert fact_problem("depot", " D1 ") is None                     # trimmed by the fingerprint, still a value
    with pytest.raises(ValueError):
        Receipt.model_validate({"at": "2026-10-20T09:00:00Z", "bundle_version": "v", "actor": "a",
                                "actor_kind": "person", "action": "x", "allowed": True, "scope": {"depot": value}})


def _events():
    from tests.test_layer_safety import stopped
    from sentinel.models import Event
    out = [stopped("TVM01", "A1"), stopped("TVM02", "A2")]
    for odd in (["TVM01"], {"a": 1}, 1.5, True, "", "  "):
        out.append(Event(type="inv.sales_stopped", source="pos", payload={"store": odd, "article": "A9",
                                                                           "book_qty": 4}))
    return out


@pytest.mark.parametrize("i", range(8))
def test_trace_predicts_the_route_ingest_takes(keys, i):  # noqa: F811
    """One source of truth: a dry run (trace, golden cases, dual run) and ingest decide the route the same way."""
    eng = osync_engine(keys)
    ev = _events()[i]
    t = eng.trace(ev)
    inc = eng.store.get_incident(eng.ingest(ev).incident_id)
    assert t["route"]["route"] == inc.route.value, (ev.payload, t["route"], inc.route.value)
    acted = inc.state.value == "dispositioned"
    assert (t["outcome"] == "automatic") == acted, (ev.payload, t["outcome"], inc.state)


def test_whitespace_relied_fact_goes_to_a_person_without_a_key(keys):  # noqa: F811
    from sentinel.models import Event, Route
    eng = osync_engine(keys)
    eng.policy_signer = None
    ev = Event(type="inv.sales_stopped", source="pos", payload={"store": "  ", "article": "A1", "book_qty": 4})
    inc = eng.store.get_incident(eng.ingest(ev).incident_id)
    assert inc.route is Route.HITL and inc.odd_facts == ["store"]



# ---- final handover: in-process paths attributed; every configured fact name follows the rule ------------------

def test_in_process_writes_are_attributed_to_the_engine(keys):  # noqa: F811
    eng, _ = _dt_engine(keys, ["monitoring"])
    eng.set_data_trust({"store": "TVM01"}, 0.99, source="monitoring")
    assert eng.data_trust_scores()[0]["by"] == "engine"
    snap = load_policy(eng.export_policy(), keys["public"], clock=lambda: NOW)
    _, rec = snap.authorise("meena", "task.count", "x", {"store": "TVM01"}, now=NOW)
    eng.record_receipts([rec])
    assert eng.store.recent_audit(5, kinds=["authority_receipt"])[0]["data"]["posted_by"] == "engine"


@pytest.mark.parametrize("name", ["  ", "\t", "", "\n "])
def test_every_configured_fact_name_follows_the_rule(name):
    from sentinel.fingerprint import FingerprintRule
    from sentinel.models import DataTrust, Pattern
    from sentinel.rbac import AuthorityRule, UnattendedRule
    for kw in ({"claims": [name]}, {"trust_by": [name]}, {"money_fact": name}, {"inhibit_on": [name]},
               {"brief_fields": [name]}):
        with pytest.raises(ValueError):
            Pattern(id="p", event_types=["x"], **kw)
    for kw in ({"fields": {name: "a"}}, {"group_by": [name]}):
        with pytest.raises(ValueError):
            FingerprintRule(event_type="x", **kw)
    with pytest.raises(ValueError):
        DataTrust(sources=[name])
    with pytest.raises(ValueError):
        AuthorityRule(role_id="r", action="a", amount_param=name)
    with pytest.raises(ValueError):
        UnattendedRule(action="a", amount_param=name)
