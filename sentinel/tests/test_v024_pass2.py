# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""v0.24.0 second independent pass: 8 defects, fixed per class (BUILDER_MISSES).

Classes: a judged-wrong case with nobody to hold it (dead end); inputs coerced instead of refused (strict inputs);
two paths to the same outcome that disagree (one mistake, one charge; a reverse settles "undo needed")."""
from __future__ import annotations

from datetime import UTC, datetime

import pytest
import yaml

from sentinel import AuthorizationError, EngineError, Overlay, load_layers
from sentinel.orgsync import Receipt
from sentinel.rbac import parse_directory
from sentinel.testing import FrozenClock, engine_for

from tests.test_layer_safety import NOW, PACK, SPOT, Store, actions, stopped


def directory(*, reverse=True, oversight=True, drop_people=()):
    data = yaml.safe_load((PACK / "people_chain_a_org.yaml").read_text(encoding="utf-8"))
    data.pop("vacancy")
    if oversight:
        data["oversight"] = [{"role": "internal_audit"}]
    if reverse:
        data["authority"] += [{"role_id": "ops_head", "action": "__reverse__"},
                              {"role_id": "internal_audit", "action": "__reverse__"}]
    for p in data["people"]:
        if p["id"] in drop_people:
            p["active"] = False
    return parse_directory(data)


def engine(d, *layers):
    world = Store()
    live = {"overrides": [{"id": "r06_phantom_stock", "set": {"shadow": False, "route": "auto"}}]}
    doc = load_layers([PACK / "template.yaml", PACK / "tenant_chain_a.yaml", ("live", live), SPOT, *layers])
    ov = Overlay(name="r06", fingerprint_rules=doc.fingerprints, patterns=doc.patterns, roles=doc.roles,
                 actions=actions(world), directory=d, slots=doc.slots, slot_bindings=doc.slot_bindings,
                 case_defaults=doc.defaults)
    return engine_for(ov, clock=FrozenClock(NOW)), world


def state(eng):
    return eng.store.get_pattern_state("r06_phantom_stock@store=TVM01").model_dump()


# ---- class: no dead ends (defect 1) -------------------------------------------------------------------

def test_no_reverse_holder_goes_to_oversight_who_can_keep_but_not_undo():
    eng, world = engine(directory(reverse=False))
    inc = eng.ingest(stopped("TVM01")).incident_id
    res = eng.spot_check_verdict(inc, "meena", False, "wrong article")
    assert res["reversed"] is False and res["undo_by"]["can_undo"] is False
    assert res["undo_by"]["fallback"] == "internal_audit" and res["undo_by"]["people"] == ["ganesh"]
    queued = [c for c in eng.spot_checks("ganesh") if c["incident"] == inc]
    assert queued and queued[0]["can_undo"] is False and queued[0]["held_by"] == "internal_audit"
    with pytest.raises(AuthorizationError, match="grant it in the people configuration"):
        eng.spot_check_verdict(inc, "ganesh", False, "undo")
    with pytest.raises(EngineError, match="say why"):
        eng.spot_check_verdict(inc, "ganesh", True, "")
    assert eng.spot_check_verdict(inc, "ganesh", True, "count confirmed it")["verdict"] == "failed_kept"
    assert world.undone == []
    assert eng.store.recent_audit(5, kinds=["spot_check_undo_unowned"])[0]["data"]["held_by"] == "internal_audit"


def test_fallback_climbs_to_the_owner_role_then_the_checker():
    eng, _ = engine(directory(reverse=False, oversight=False))
    inc = eng.ingest(stopped("TVM01")).incident_id
    res = eng.spot_check_verdict(inc, "meena", False, "wrong")
    assert res["undo_by"]["people"] and res["undo_by"]["can_undo"] is False      # owner role in scope holds it
    assert any(c["incident"] == inc for p in res["undo_by"]["people"] for c in eng.spot_checks(p))


def test_an_inactive_reverse_holder_does_not_count():
    eng, _ = engine(directory(drop_people=("devi", "ganesh")))
    inc = eng.ingest(stopped("TVM01")).incident_id
    res = eng.spot_check_verdict(inc, "meena", False, "wrong")
    assert res["undo_by"]["can_undo"] is False and res["undo_by"]["people"]
    assert "devi" not in res["undo_by"]["people"] and "ganesh" not in res["undo_by"]["people"]


# ---- class: one mistake, one charge; a reverse settles undo-needed (defects 7, 8) ------------------------

@pytest.mark.parametrize("finish", ["undo_button", "plain_reverse"])
def test_judged_wrong_then_undone_counts_once_and_settles(finish):
    once, _ = engine(directory())
    a = once.ingest(stopped("TVM01")).incident_id
    once.spot_check_verdict(a, "ganesh", False, "wrong")                 # ganesh reverses directly: one charge
    eng, world = engine(directory())
    b = eng.ingest(stopped("TVM01")).incident_id
    eng.spot_check_verdict(b, "meena", False, "wrong")                   # meena can't undo: charged here
    if finish == "undo_button":
        eng.spot_check_verdict(b, "devi", False, "undo")
    else:
        eng.reverse(b, "devi", "undo")
    assert state(eng)["reversals"] == state(once)["reversals"] == 1
    assert state(eng)["route"] == state(once)["route"]
    d = eng.store.get_disposition(b)
    assert d.reversed and d.spot_check == "failed" and d.trust_charged
    assert all(c["incident"] != b for c in eng.spot_checks("devi"))
    with pytest.raises(EngineError, match="already checked"):
        eng.spot_check_verdict(b, "devi", False, "again")                     # undone once: a second undo refused
    with pytest.raises(EngineError, match="already checked"):
        eng.spot_check_verdict(b, "devi", True, "it was right")              # can't be marked right once undone
    assert state(eng)["reversals"] == 1
    assert world.undone == [("shelf", "TVM01", "A1")]


def test_agent_incident_undo_then_wrong_verdict_counts_once():
    eng, _ = engine(directory())
    inc = eng.ingest(stopped("TVM01")).incident_id
    eng.agent_incident("r06_phantom_stock", "ganesh", "bad batch", undo=True)
    before = state(eng)
    assert eng.spot_check_verdict(inc, "ganesh", False, "wrong")["already"]
    assert state(eng) == before


# ---- class: strict inputs (defects 2-6) ----------------------------------------------------------------

GOOD = {"at": "2026-10-20T09:00:00Z", "bundle_version": "v1", "actor": "a", "actor_kind": "agent",
        "action": "x", "allowed": True}


@pytest.mark.parametrize("field,bad", [
    ("actor_kind", "Agent"), ("actor_kind", "robot"), ("actor_kind", ""), ("id", ""), ("allowed", "yes"),
    ("allowed", 1), ("stale", "no"), ("amount", True), ("amount", "5"), ("amount", float("nan")),
    ("actor", 5), ("reason", ["x"]), ("checks", "a"), ("checks", [1]), ("assertion_id", 7), ("bundle_version", ""),
])
def test_receipts_refuse_wrong_types(field, bad):
    with pytest.raises(ValueError):
        Receipt.model_validate({**GOOD, field: bad})


def test_receipts_still_take_what_cores_send():
    from decimal import Decimal
    r = Receipt.model_validate({**GOOD, "amount": Decimal("12.5"), "scope": {"store": "T1"}})
    assert r.amount == 12.5


@pytest.mark.parametrize("scope,score,source", [
    ({"store": "T1"}, "0.9", ""), ({"store": True}, 0.9, ""), ({"store": 1.5}, 0.9, ""),
    ({"store": "T1"}, 0.9, ["x"]), ({"store": "T1"}, None, ""),
])
def test_data_trust_refuses_wrong_types(scope, score, source):
    eng, _ = engine(directory())
    with pytest.raises(EngineError):
        eng.set_data_trust(scope, score, source)


def test_engine_text_fields_are_strict():
    eng, _ = engine(directory())
    inc = eng.ingest(stopped("TVM01")).incident_id
    with pytest.raises(EngineError):
        eng.agent_incident("r06_phantom_stock", "ganesh", ["x"])
    with pytest.raises(EngineError):
        eng.spot_check_verdict(inc, "ganesh", False, ["x"])
    rec = eng.agent_incident("r06_phantom_stock", "ganesh", "x")
    with pytest.raises(EngineError):
        eng.close_agent_incident(rec["id"], "ganesh", 5)
    assert eng.agent_incidents()[0]["status"] == "open"


def test_http_bodies_are_strict_on_every_dict_endpoint():
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from sentinel.api import Principal, create_app, token_hash
    eng, _ = engine(directory())
    inc = eng.ingest(stopped("TVM01")).incident_id
    toks = {token_hash("g"): Principal("person", "ganesh"), token_hash("svc"): Principal("service", "mon")}
    c = TestClient(create_app(eng, toks, config_sync_s=0), raise_server_exceptions=False)
    g, s = {"Authorization": "Bearer g"}, {"Authorization": "Bearer svc"}
    bad = [
        ("/v1/receipts", s, {"receipts": [{**GOOD, "actor_kind": "Agent"}]}),
        ("/v1/receipts", s, {"receipts": [{**GOOD, "id": ""}]}),
        ("/v1/data-trust", s, {"scope": {"store": "T1"}, "score": "0.9"}),
        ("/v1/data-trust", s, {"scope": {"store": True}, "score": 0.9}),
        ("/v1/data-trust", s, {"scope": {"store": "T1"}, "score": 0.9, "source": ["x"]}),
        ("/v1/data-trust", s, {"scope": {"store": "T1"}, "score": 0.9, "components": "x"}),
        (f"/console/api/spot-checks/{inc}", g, {"ok": False, "note": ["x"]}),
        ("/console/api/agent-incidents", g, {"pattern": "r06_phantom_stock", "reason": ["x"]}),
        ("/console/api/agent-incidents", g, {"pattern": "r06_phantom_stock", "reason": 5}),
        ("/console/api/agent-incidents", g, {"pattern": ["r06_phantom_stock"], "reason": "x"}),
        ("/console/api/agents/effective", g, {"pattern": "r06_phantom_stock", "facts": {"store": True}}),
        ("/console/api/oversee", g, {"pattern": "r06_phantom_stock", "action": "stop", "reason": 5}),
    ]
    for url, hdr, body in bad:
        r = c.post(url, json=body, headers=hdr)
        assert r.status_code == 422, (url, body, r.status_code, r.text[:200])
    opened = c.post("/console/api/agent-incidents", json={"pattern": "r06_phantom_stock", "reason": "x"},
                    headers=g).json()
    r = c.post(f"/console/api/agent-incidents/{opened['id']}/close", json={"postmortem": 5}, headers=g)
    assert r.status_code == 422 and eng.agent_incidents()[0]["status"] == "open"


def test_receipt_at_is_still_parsed_from_iso_text():
    r = Receipt.model_validate(GOOD)
    assert r.at == datetime(2026, 10, 20, 9, 0, tzinfo=UTC)


def test_every_request_model_refuses_lax_booleans_and_numbers():
    """The same class on the typed bodies: pydantic's lax mode would read "yes"/1 as true and "24" as 24.0."""
    import pydantic

    import sentinel.api as api_mod
    import sentinel.console as con
    from sentinel.inputs import Body
    models = [m for mod in (api_mod, con) for m in vars(mod).values()
              if isinstance(m, type) and issubclass(m, pydantic.BaseModel) and m.__module__ == mod.__name__]
    assert models and all(issubclass(m, Body) for m in models), [m.__name__ for m in models
                                                                 if not issubclass(m, Body)]
    for M, d in [(con.SilenceIn, {"reason": "x", "hours": "24"}), (con.SilenceIn, {"reason": "x", "hours": True}),
                 (con.PauseIn, {"reason": "x", "hours": float("inf")}),
                 (con.PrivacyIn, {"identifier": "a", "reason": "r", "include_open": "yes"}),
                 (con.TraceIn, {"event": {}, "run_lookups": 1}), (api_mod.AskMetricIn, {"metric": "m", "compare": 1}),
                 (con.TokenIn, {"kind": "person", "principal": "p", "days": "30"})]:
        with pytest.raises(pydantic.ValidationError):
            M.model_validate(d)
    assert con.SilenceIn.model_validate({"reason": "x", "hours": 2}).hours == 2


# ---- third pass (5 Low): NaN in typed bodies, receipt time, unknown assertions, empty ids, settled checks --------

def test_nan_and_infinity_literals_get_422_not_500():
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from sentinel.api import Principal, create_app, token_hash
    eng, _ = engine(directory())
    c = TestClient(create_app(eng, {token_hash("g"): Principal("person", "ganesh")}, config_sync_s=0),
                   raise_server_exceptions=False)
    h = {"Authorization": "Bearer g", "Content-Type": "application/json"}
    for url, raw in [("/console/api/silences", '{"reason":"x","hours":NaN}'),
                     ("/console/api/silences", '{"reason":"x","hours":Infinity}'),
                     ("/console/api/privacy/find", '{"identifier":NaN,"reason":"r"}'),
                     ("/console/api/trace", '{"event":NaN}'),
                     ("/console/api/metrics/query", '{"metric":"m","days":-Infinity}')]:
        r = c.post(url, content=raw, headers=h)
        assert r.status_code == 422, (url, r.status_code, r.text[:200])
        assert "nan" not in r.text.lower() or "loc" in r.text


@pytest.mark.parametrize("at", [1, 1.5, "24", "yesterday", True, None, "2026-10-20T09:00:00", "2026-10-20"])
def test_receipt_time_must_be_iso_text(at):
    with pytest.raises(ValueError):
        Receipt.model_validate({**GOOD, "at": at})


def test_receipts_naming_an_assertion_sentinel_never_issued_are_flagged(tmp_path):
    pytest.importorskip("cryptography")
    eng, _ = engine(directory())
    from sentinel.orgsync import PolicySigner, keygen
    eng.policy_signer = PolicySigner.from_file(keygen(tmp_path, "k1")["private"], "k1")
    inc = eng.store.get_incident(eng.ingest(stopped("TVM01")).incident_id)
    token = eng.agent_assertion(inc, "task.count", "TVM01/A1")
    import json as _j

    from sentinel.jws import b64url_decode
    jti = _j.loads(b64url_decode(token.split(".")[1]))["jti"]
    issued = eng.store.get_source_state(f"assertion:{jti}")
    base = {**GOOD, "action": "task.count", "obj": "TVM01/A1", "actor": issued["agent"],
            "agent_template": issued["template"], "agent_incident": inc.id, "scope": {"store": "TVM01"}}
    bad = {"r3": {"action": "stock.adjust"}, "r4": {"agent_incident": None}, "r5": {"actor": "someone@*"},
           "r6": {"agent_template": "other"}, "r7": {"scope": {"store": "TVM02"}}, "r8": {"actor_kind": "person"},
           "r9": {"obj": None}}
    out = eng.record_receipts([{**base, "id": "r1", "assertion_id": "ast_fake"},
                               {**base, "id": "r2", "assertion_id": jti},
                               *({**base, "id": k, "assertion_id": jti, "allowed": False, **v}
                                 for k, v in bad.items())])
    flags = {x["receipt"]: set(x["flags"]) for x in out["flags"]}
    assert "unknown_assertion" in flags["r1"]
    assert not ({"unknown_assertion", "assertion_mismatch"} & flags.get("r2", set()))
    for k in bad:
        assert "assertion_mismatch" in flags[k], k
    again = eng.record_receipts([{**base, "id": "r10", "assertion_id": jti, "core": "till-2"}])  # a second write
    assert "assertion_reused" in again["flags"][0]["flags"]
    assert eng.store.recent_audit(5, kinds=["assertion_reused"])


def test_empty_fact_values_are_refused():
    eng, _ = engine(directory())
    with pytest.raises(EngineError):
        eng.set_data_trust({"store": ""}, 0.5)
    with pytest.raises(EngineError):
        eng.set_data_trust({"": "T1"}, 0.5)


@pytest.mark.parametrize("how", ["incident_undo", "hand_reverse_first"])
def test_an_undone_decision_never_waits_as_pending(how):
    eng, _ = engine(directory())
    inc = eng.ingest(stopped("TVM01")).incident_id
    if how == "hand_reverse_first":
        eng.reverse(inc, "ganesh", "wrong")
        eng.agent_incident("r06_phantom_stock", "ganesh", "harm", undo=True)
    else:
        eng.agent_incident("r06_phantom_stock", "ganesh", "harm", undo=True)
    assert eng.store.get_disposition(inc).spot_check == "reversed"
    assert all(c["incident"] != inc for p in ("meena", "ganesh", "devi") for c in eng.spot_checks(p))
    with pytest.raises(EngineError, match="already checked"):
        eng.spot_check_verdict(inc, "ganesh", True, "fine")                   # never marked right once undone
    assert eng.spot_check_verdict(inc, "ganesh", False, "agreed")["already"]  # agreeing that it was wrong: no effect
    assert state(eng)["reversals"] == 1


def test_the_same_receipt_posted_twice_at_once_is_recorded_once(tmp_path):
    """State and its audit row land in one transaction; a duplicate id racing on two engines is recorded once."""
    import threading

    from sentinel import Engine, SQLiteStore
    eng0, _ = engine(directory())
    db = str(tmp_path / "s.db")
    engines = [Engine(eng0.overlay, store=SQLiteStore(db), clock=FrozenClock(NOW)) for _ in range(2)]
    rows = [{**GOOD, "id": f"r{i}"} for i in range(40)]
    outs = []
    ts = [threading.Thread(target=lambda e=e: outs.append(e.record_receipts(rows))) for e in engines]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    assert sum(o["received"] for o in outs) == 40 and sum(o["duplicates"] for o in outs) == 40
    assert len(engines[0].store.recent_audit(500, kinds=["authority_receipt"])) == 40


# ---- fifth pass: receipt scope as strict as data trust; a batch never half-lands ---------------------------------

@pytest.mark.parametrize("scope", [{"depot": ["D1"]}, {"depot": {"a": 1}}, {"depot": 1.5}, {"depot": True},
                                   {"depot": ""}, {"": "D1"}])
def test_receipt_scope_follows_the_fact_rule(scope):
    with pytest.raises(ValueError):
        Receipt.model_validate({**GOOD, "scope": scope})


def test_a_bad_receipt_refuses_the_whole_batch_over_http():
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from sentinel.api import Principal, create_app, token_hash
    eng, _ = engine(directory())
    c = TestClient(create_app(eng, {token_hash("svc"): Principal("service", "pos")}, config_sync_s=0),
                   raise_server_exceptions=False)
    body = {"receipts": [{**GOOD, "id": "ok1"}, {**GOOD, "id": "bad", "scope": {"depot": ["D1"]}},
                         {**GOOD, "id": "ok2"}]}
    r = c.post("/v1/receipts", json=body, headers={"Authorization": "Bearer svc"})
    assert r.status_code == 422
    assert eng.store.recent_audit(10, kinds=["authority_receipt"]) == []          # nothing half-landed
    r = c.post("/v1/receipts", json={"receipts": [body["receipts"][0], body["receipts"][2]]},
               headers={"Authorization": "Bearer svc"})
    assert r.status_code == 200 and r.json()["received"] == 2


def test_a_cores_own_receipt_always_validates_whatever_the_caller_passed(tmp_path):
    pytest.importorskip("cryptography")
    from sentinel.orgsync import PolicySigner, keygen, load_keys, load_policy
    eng, _ = engine(directory())
    k = keygen(tmp_path, "k1")
    eng.policy_signer = PolicySigner.from_file(k["private"], "k1")
    snap = load_policy(eng.export_policy(), load_keys(k["public"]), clock=lambda: NOW)
    _, rec = snap.authorise("meena", "task.count", "x", {"store": ["TVM01"], "qty": 1.5, "flag": True, "": "y"},
                            now=NOW)
    again = Receipt.model_validate(rec.model_dump(mode="json"))                 # what the core posts
    assert again.scope["store"] == '["TVM01"]' and again.scope["qty"] == "1.5" and again.scope['(name: "")'] == "y"
    assert eng.record_receipts([rec.model_dump(mode="json")])["received"] == 1


# ---- sixth pass: one fact rule everywhere; strict registry settings ----------------------------------------------

def test_one_fact_rule_for_receipts_data_trust_and_console_facts():
    from sentinel.factrule import fact_problem
    for name, value in [("", "D1"), ("depot", ""), ("depot", 1.5), ("depot", True), ("depot", ["D1"]), (5, "x")]:
        assert fact_problem(name, value) is not None
        with pytest.raises(ValueError):
            Receipt.model_validate({**GOOD, "scope": {name: value}})
    assert fact_problem("depot", None)                                       # one rule: an unset fact is left out
    with pytest.raises(ValueError):
        Receipt.model_validate({**GOOD, "scope": {"depot": None}})
    eng, _ = engine(directory())
    with pytest.raises(EngineError, match="needs a value"):
        eng.set_data_trust({"store": None}, 0.5)
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from sentinel.api import Principal, create_app, token_hash
    c = TestClient(create_app(eng, {token_hash("g"): Principal("person", "ganesh")}, config_sync_s=0),
                   raise_server_exceptions=False)
    h = {"Authorization": "Bearer g"}
    url = "/console/api/agents/effective"
    assert c.post(url, json={"pattern": "r06_phantom_stock", "facts": {"": "D1"}}, headers=h).status_code == 422
    assert c.post(url, json={"pattern": "r06_phantom_stock", "facts": {"store": None}}, headers=h).status_code == 422


def test_no_assertion_is_minted_for_a_scope_fact_no_core_could_match(tmp_path):
    pytest.importorskip("cryptography")
    from sentinel.orgsync import PolicyError, PolicySigner, keygen
    eng, _ = engine(directory())
    eng.policy_signer = PolicySigner.from_file(keygen(tmp_path, "k1")["private"], "k1")
    inc = eng.store.get_incident(eng.ingest(stopped("TVM01")).incident_id)
    assert eng.agent_assertion(inc, "task.count", "x")                  # plain: minted
    for odd in (1.5, True, "", ["TVM01"], {"a": 1}):
        bad = inc.model_copy(update={"facts": {**inc.facts, "store": odd}})
        with pytest.raises(PolicyError, match="not plain"):
            eng.agent_assertion(bad, "task.count", "x")
    assert eng.store.recent_audit(10, kinds=["agent_assertion_refused"])


@pytest.mark.parametrize("override", [
    {"spot_check_rate": "0.5"}, {"claim_minutes": "30"}, {"digest_above": "3"}, {"spot_check_rate": float("nan")},
    {"data_trust_exempt": "yes"}, {"data_trust_exempt": 1}, {"claims": [""]}, {"trust_by": [""]},
])
def test_registry_settings_are_strict(override):
    from sentinel.models import Pattern
    with pytest.raises(ValueError):
        Pattern(id="p", event_types=["x"], **override)


@pytest.mark.parametrize("dt", [{"act_min": True}, {"max_age_hours": True}, {"max_age_hours": float("inf")},
                                {"propose_min": "0.8"}])
def test_data_trust_defaults_are_strict(dt):
    from sentinel.models import DataTrust
    with pytest.raises(ValueError):
        DataTrust(**dt)


# ---- seventh pass: odd relied-on facts go to a person; people configuration follows the fact rule -------------

@pytest.mark.parametrize("odd", [["TVM01"], {"a": 1}, 1.5, True, ""])
def test_a_relied_on_fact_that_is_not_plain_sends_the_case_to_a_person(odd):
    from sentinel import IncidentState as St
    from sentinel.models import Event, Route
    eng, world = engine(directory())
    ev = Event(type="inv.sales_stopped", source="pos", payload={"store": odd, "article": "A1", "book_qty": 4})
    inc = eng.store.get_incident(eng.ingest(ev).incident_id)
    assert inc.route is Route.HITL and inc.state is St.AWAITING_HUMAN and inc.odd_facts == ["store"]
    assert world.calls == []                                        # the agent did not act alone
    assert eng.store.audit_log(inc.id)[1]["kind"] == "scope_fact_not_plain" or \
        "scope_fact_not_plain" in [a["kind"] for a in eng.store.audit_log(inc.id)]


def test_an_odd_value_cannot_slip_past_a_per_scope_control():
    from sentinel.models import Event, Route
    eng, world = engine(directory())
    eng.set_data_trust({"store": "TVM01"}, 0.1)                       # store is relied on (and a scope dimension)
    ev = Event(type="inv.sales_stopped", source="pos", payload={"store": ["TVM01"], "article": "A2", "book_qty": 4})
    assert eng.store.get_incident(eng.ingest(ev).incident_id).route is Route.HITL and world.calls == []


@pytest.mark.parametrize("bad", [
    {"assignments": [{"person_id": "meena", "role_id": "store_manager", "scope": {"store": 1.5}}]},
    {"assignments": [{"person_id": "meena", "role_id": "store_manager", "scope": {"store": True}}]},
    {"assignments": [{"person_id": "meena", "role_id": "store_manager", "scope": {"": "TVM01"}}]},
    {"assignments": [{"person_id": "meena", "role_id": "store_manager", "scope": {"store": []}}]},
    {"agents": [{"template": "r06_phantom_stock", "scope": {"store": True}, "mode": "OBSERVE"}]},
    {"agents": [{"template": "r06_phantom_stock", "scope": {"store": None}, "mode": "OBSERVE"}]},
    {"authority": [{"role_id": "store_manager", "action": "task.count", "max_amount": True}]},
    {"authority": [{"role_id": "store_manager", "action": "task.count", "max_amount": "1000"}]},
    {"authority": [{"role_id": "store_manager", "action": "task.count", "max_amount": float("nan")}]},
])
def test_people_configuration_follows_the_fact_rule(bad):
    data = yaml.safe_load((PACK / "people_chain_a_org.yaml").read_text(encoding="utf-8"))
    data.pop("vacancy")
    for k, v in bad.items():
        data[k] = [*data.get(k, []), *v]
    with pytest.raises(ValueError):
        parse_directory(data)


def test_a_list_of_stores_in_an_assignment_is_still_fine():
    data = yaml.safe_load((PACK / "people_chain_a_org.yaml").read_text(encoding="utf-8"))
    data.pop("vacancy")
    data["assignments"] = [*data["assignments"],
                           {"person_id": "meena", "role_id": data["assignments"][0]["role_id"],
                            "scope": {"store": ["TVM01", "TVM02"]}}]
    assert parse_directory(data)


def test_money_fact_must_name_a_fact_and_empty_names_never_overwrite():
    from sentinel.factrule import as_facts
    from sentinel.models import Pattern
    with pytest.raises(ValueError):
        Pattern(id="p", event_types=["x"], money_fact="")
    out = as_facts({"": "D1", "_": "D9", "(name: \"\")": "Z"})
    assert out["_"] == "D9" and "D1" in out.values() and "Z" in out.values() and len(out) == 3
