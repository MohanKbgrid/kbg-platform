# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""Org and authority for domain cores, offline: a signed policy bundle, signed agent assertions, and decision
receipts back to Sentinel (ADR-003 C1/C2). Proved on the R06 exemplar: the store's POS core enforces locally."""
from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import yaml

pytest.importorskip("cryptography")

from sentinel import ActionRegistry, ActionResult, Overlay, load_layers  # noqa: E402
from sentinel.models import Event  # noqa: E402
from sentinel.org import Agent, Person  # noqa: E402
from sentinel.orgsync import (PolicyError, PolicySigner, Receipt, keygen, load_keys, load_policy,  # noqa: E402
                              sign_agent_assertion, verify_agent_assertion)
from sentinel.rbac import parse_directory  # noqa: E402
from sentinel.testing import FrozenClock, engine_for  # noqa: E402

PACK = Path(__file__).parent / "packs" / "r06_stock_integrity"
NOW = datetime(2026, 10, 20, 9, 0, tzinfo=UTC)


@pytest.fixture(scope="module")
def keys(tmp_path_factory):
    d = tmp_path_factory.mktemp("policy")
    k = keygen(d, "site-1")
    other = keygen(tmp_path_factory.mktemp("other"), "evil")
    return {"signer": PolicySigner.from_file(k["private"], "site-1"), "public": load_keys(k["public"]),
            "evil": PolicySigner.from_file(other["private"], "site-1"), "paths": k}


def directory():
    data = yaml.safe_load((PACK / "people_chain_a_org.yaml").read_text(encoding="utf-8"))
    data["authority"] += [{"role_id": "store_manager", "action": "stock.adjust", "max_amount": 5000},
                          {"role_id": "regional_manager", "action": "stock.adjust", "max_amount": 50000}]
    data["sod"] = [{"first": "task.count", "second": "stock.adjust"}]
    data["agents"] = [{"template": "*", "mode": "OBSERVE"},
                      {"template": "r06_phantom_stock", "scope": {"store": "TVM02"}, "mode": "ACT"},
                      {"template": "r06_phantom_stock", "scope": {"store": "TVM01"}, "mode": "ACT"}]
    data.pop("vacancy")
    return parse_directory(data)


def engine(keys, seen=None):
    acts = ActionRegistry()

    @acts.action("task.shelf_check", reversible=False, params={"store": "str", "article": "str", "kind?": "str"},
                 description="ask the store to check the shelf")
    def shelf(ctx, p):
        if seen is not None:
            seen.append(ctx.assert_for("task.shelf_check", f"{p['store']}/{p['article']}") if ctx.assert_for
                        else None)
        return ActionResult(ok=True)

    @acts.action("task.count", reversible=False, params={"store": "str", "article": "str"},
                 description="ask the store to count")
    def count(ctx, p):
        return ActionResult(ok=True)

    doc = load_layers([PACK / "template.yaml", PACK / "tenant_chain_a.yaml",
                       ("live", {"overrides": [{"id": "r06_phantom_stock", "set": {"shadow": False, "route": "auto"}}]})])
    eng = engine_for(Overlay(name="r06", fingerprint_rules=doc.fingerprints, patterns=doc.patterns, roles=doc.roles,
                             actions=acts, directory=directory(), slots=doc.slots, slot_bindings=doc.slot_bindings),
                     clock=FrozenClock(NOW))
    eng.policy_signer = keys["signer"]
    return eng


# ---- the bundle -------------------------------------------------------------------------------------

def test_bundle_round_trip_and_version(keys):
    eng = engine(keys)
    token = eng.export_policy(ttl_hours=12)
    snap = load_policy(token, keys["public"], core="pos", clock=lambda: NOW)
    assert snap.site == "r06" and len(snap.version) == 16 and not snap.stale()
    assert snap.expires_at - snap.issued_at == timedelta(hours=12)
    assert snap.directory.roles_of("meena", {"store": "TVM01"}, at=NOW) == {"store_manager"}   # at the frozen date, not today
    issued = eng.store.get_source_state("policy_bundles")["issued"]
    assert issued[-1]["version"] == snap.version
    assert eng.export_policy() and len(eng.store.get_source_state("policy_bundles")["issued"]) == 1   # same content


def test_tampered_or_foreign_bundles_are_refused(keys):
    eng = engine(keys)
    token = eng.export_policy()
    h, p, s = token.split(".")
    from sentinel.jws import b64url, b64url_decode
    claims = json.loads(b64url_decode(p))
    claims["people"]["authority"].append({"role_id": "store_manager", "action": "*"})      # grant myself all
    forged = ".".join([h, b64url(json.dumps(claims).encode()), s])
    with pytest.raises(PolicyError, match="signature"):
        load_policy(forged, keys["public"], clock=lambda: NOW)
    eng.policy_signer = keys["evil"]                                    # same kid, wrong key
    with pytest.raises(PolicyError, match="signature"):
        load_policy(eng.export_policy(), keys["public"], clock=lambda: NOW)
    with pytest.raises(PolicyError, match="unreadable"):
        load_policy("not.a-token", keys["public"], clock=lambda: NOW)


def test_people_decide_against_the_bundle_offline_and_stale_is_flagged(keys):
    snap = load_policy(engine(keys).export_policy(ttl_hours=1), keys["public"], core="pos", clock=lambda: NOW)
    dec, rec = snap.authorise("meena", "stock.adjust", "TVM01/A1", {"store": "TVM01"}, 3000, now=NOW)
    assert dec and rec.allowed and rec.bundle_version == snap.version and rec.actor_kind == "person"
    later = NOW + timedelta(hours=2)
    dec, rec = snap.authorise("meena", "stock.adjust", "TVM01/A1", {"store": "TVM01"}, 3000, now=later)
    assert dec and rec.stale and "stale_bundle" in rec.checks                    # a till must still sell
    dec, rec = snap.authorise("meena", "stock.adjust", "TVM01/A1", {"store": "TVM01"}, 8000, now=NOW)
    assert not dec and dec.escalate_to == "regional_manager"


# ---- agent assertions --------------------------------------------------------------------------------

def test_an_unattended_action_carries_a_signed_assertion_the_core_accepts(keys):
    seen = []
    eng = engine(keys, seen)
    snap = load_policy(eng.export_policy(), keys["public"], core="pos", clock=lambda: NOW)
    eng.ingest(Event(type="inv.sales_stopped", source="pos", payload={"store": "TVM02", "article": "A1",
                                                                       "book_qty": 4}))
    assert seen and seen[0]
    claims = verify_agent_assertion(seen[0], keys["public"], now=NOW)
    assert claims["agent"] == "r06_phantom_stock@store=TVM02" and claims["mode"] == "ACT"
    assert claims["bound_role"] == "store_manager" and claims["action"] == "task.shelf_check"
    dec, rec = snap.authorise(None, "task.shelf_check", "TVM02/A1", {"store": "TVM02"}, assertion=seen[0], now=NOW)
    assert dec and rec.actor_kind == "agent" and rec.agent_template == "r06_phantom_stock" and rec.assertion_id
    assert rec.decided_by_role == "store_manager"


def test_assertions_are_bound_to_action_object_scope_mode_and_time(keys):
    signer, pub = keys["signer"], keys["public"]
    snap = load_policy(engine(keys).export_policy(), pub, core="pos", clock=lambda: NOW)

    def tok(**kw):
        base = dict(agent="r06@store=TVM01", template="r06_phantom_stock", bound_role="store_manager", mode="ACT",
                    scope={"store": "TVM01"}, action="stock.adjust", obj="TVM01/A1", incident="inc_1", site="r06",
                    now=NOW)
        base.update(kw)
        return sign_agent_assertion(signer, **base)
    ok, _ = snap.authorise(None, "stock.adjust", "TVM01/A1", {"store": "TVM01"}, 100, assertion=tok(), now=NOW)
    assert ok
    cases = [({"action": "task.count"}, "for 'task.count'"), ({"obj": "TVM01/A2"}, "object"),
             ({"scope": {"store": "TVM02"}}, "does not cover"), ({"mode": "PROPOSE"}, "a person decides"),
             ({"site": "other"}, "site")]
    for change, why in cases:
        dec, rec = snap.authorise(None, "stock.adjust", "TVM01/A1", {"store": "TVM01"}, 100, assertion=tok(**change),
                                  now=NOW)
        assert not dec and why in dec.reason and not rec.allowed, (change, dec.reason)
    dec, _ = snap.authorise(None, "stock.adjust", "TVM01/A1", {"store": "TVM01"}, 100, assertion=tok(),
                            now=NOW + timedelta(minutes=6))
    assert not dec and "expired" in dec.reason
    dec, _ = snap.authorise(None, "stock.adjust", "TVM01/A1", {"store": "TVM01"}, 100,
                            assertion=sign_agent_assertion(keys["evil"], agent="x", template="t",
                                                           bound_role="regional_manager", mode="ACT", scope={},
                                                           action="stock.adjust", obj=None, incident=None, now=NOW),
                            now=NOW)
    assert not dec and "signature" in dec.reason
    dec, _ = snap.authorise(None, "stock.adjust", "TVM01/A1", {"store": "TVM01"}, 9000, assertion=tok(), now=NOW)
    assert not dec and "acts as 'store_manager'" in dec.reason                   # still never above its human


def test_agents_need_an_assertion_and_a_fresh_bundle(keys):
    snap = load_policy(engine(keys).export_policy(ttl_hours=1), keys["public"], clock=lambda: NOW)
    dec, rec = snap.authorise(Agent("r06@store=TVM01", bound_role="store_manager"), "task.count", "x",
                              {"store": "TVM01"}, now=NOW)
    assert not dec and "needs a signed agent assertion" in dec.reason and rec.actor_kind == "agent"
    tok = sign_agent_assertion(keys["signer"], agent="a", template="t", bound_role="store_manager", mode="ACT",
                               scope={"store": "TVM01"}, action="task.count", obj=None, incident=None,
                               now=NOW + timedelta(hours=2))
    dec, _ = snap.authorise(None, "task.count", "x", {"store": "TVM01"}, assertion=tok, now=NOW + timedelta(hours=2))
    assert not dec and "expired" in dec.reason and "bundle_fresh" in dec.checks


# ---- receipts ----------------------------------------------------------------------------------------

def test_receipts_are_audited_once_and_unknown_versions_flagged(keys):
    eng = engine(keys)
    snap = load_policy(eng.export_policy(), keys["public"], core="pos", clock=lambda: NOW)
    _, r1 = snap.authorise("meena", "task.count", "TVM01/A1", {"store": "TVM01"}, now=NOW)
    _, r2 = snap.authorise("arun", "task.count", "TVM01/A1", {"store": "TVM01"}, now=NOW)
    odd = Receipt(at=NOW, bundle_version="ffffffffffffffff", actor="r06@x", actor_kind="agent", action="stock.adjust",
                  allowed=True)
    out = eng.record_receipts([r1.model_dump(mode="json"), r2, odd])
    assert out["received"] == 3 and out["allowed"] == 2 and out["refused"] == 1 and out["unknown_version"] == 1
    assert {f for x in out["flags"] for f in x["flags"]} == {"unknown_bundle_version", "agent_write_without_assertion"}
    assert eng.record_receipts([r1])["duplicates"] == 1
    assert len(eng.store.recent_audit(20, kinds=["authority_receipt"])) == 3


def test_receipts_api_and_cli(keys, tmp_path, monkeypatch, capsys):
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from sentinel.api import Principal, create_app, token_hash
    from sentinel.cli import main
    eng = engine(keys)
    token = eng.export_policy()
    snap = load_policy(token, keys["public"], clock=lambda: NOW)
    _, rec = snap.authorise("meena", "task.count", "x", {"store": "TVM01"}, now=NOW)
    app = create_app(eng, {token_hash("pos"): Principal("service", "pos"),
                           token_hash("p"): Principal("person", "meena")}, config_sync_s=0)
    c = TestClient(app)
    body = {"receipts": [rec.model_dump(mode="json")]}
    assert c.post("/v1/receipts", json=body, headers={"Authorization": "Bearer p"}).status_code == 403
    r = c.post("/v1/receipts", json=body, headers={"Authorization": "Bearer pos"})
    assert r.status_code == 200 and r.json()["received"] == 1
    assert c.post("/v1/receipts", json={"receipts": "x"}, headers={"Authorization": "Bearer pos"}).status_code == 422
    f = tmp_path / "b.jwt"
    eng.clock = lambda: datetime.now(UTC) + timedelta(days=1)   # issued a day ahead of the wall clock, whatever today is
    f.write_text(eng.export_policy())
    assert main(["policy", "verify", str(f), "--keys", keys["paths"]["public"]]) == 1
    assert "issued in the future" in json.loads(capsys.readouterr().out)["error"]
    eng.clock = lambda: datetime.now(UTC)                     # the CLI checks on the wall clock
    fresh = eng.export_policy()
    f.write_text(fresh)
    assert main(["policy", "verify", str(f), "--keys", keys["paths"]["public"]]) == 0
    assert json.loads(capsys.readouterr().out)["ok"] is True
    f.write_text(fresh[:-4] + "AAAA")
    assert main(["policy", "verify", str(f), "--keys", keys["paths"]["public"]]) == 1


def test_no_key_means_no_assertions_and_a_clear_export_error(keys):
    seen = []
    eng = engine(keys, seen)
    eng.policy_signer = None
    with pytest.raises(PolicyError, match="SENTINEL_POLICY_KEY"):
        eng.export_policy()
    eng.ingest(Event(type="inv.sales_stopped", source="pos", payload={"store": "TVM02", "article": "A1",
                                                                       "book_qty": 4}))
    assert seen == [None]


def test_one_assertion_one_write(keys):
    snap = load_policy(engine(keys).export_policy(), keys["public"], clock=lambda: NOW)
    tok = sign_agent_assertion(keys["signer"], agent="a", template="r06_phantom_stock", bound_role="store_manager",
                               mode="ACT", scope={"store": "TVM01"}, action="task.count", obj="x", incident=None,
                               site="r06", now=NOW)
    assert snap.authorise(None, "task.count", "x", {"store": "TVM01"}, assertion=tok, now=NOW)[0]
    dec, _ = snap.authorise(None, "task.count", "x", {"store": "TVM01"}, assertion=tok, now=NOW)
    assert not dec and "already used" in dec.reason


def test_binding_is_total(keys):
    """v0.24.0 tester defects 1, 2, 3, 6: scope, actor, bundle mode and clock are all bound."""
    eng = engine(keys)
    snap = load_policy(eng.export_policy(), keys["public"], clock=lambda: NOW, site="r06")

    def tok(**kw):
        base = dict(agent="r06_phantom_stock@store=TVM01", template="r06_phantom_stock", bound_role="store_manager",
                    mode="ACT", scope={"store": "TVM01"}, action="task.count", obj="TVM01/A1", incident="i",
                    site="r06", now=NOW)
        base.update(kw)
        return sign_agent_assertion(keys["signer"], **base)
    for scope in ({"region": "central"}, {"store": "TVM01", "region": "central"}, {"line": "L7"}):
        dec, _ = snap.authorise(None, "task.count", "TVM01/A1", scope, assertion=tok(), now=NOW)
        assert not dec and "does not cover" in dec.reason, scope
    assert snap.authorise(None, "task.count", "TVM01/A1", {"region": "south"}, assertion=tok(), now=NOW)[0]  # roll-up
    for actor in ("r06_other@*", "meena", Agent("r06_other@*", bound_role="store_manager")):
        dec, _ = snap.authorise(actor, "task.count", "TVM01/A1", {"store": "TVM01"}, assertion=tok(), now=NOW)
        assert not dec, actor
    dec, _ = snap.authorise(Person("meena"), "task.count", "TVM01/A1", {"store": "TVM01"}, assertion=tok(), now=NOW)
    assert not dec and "is a person" in dec.reason
    dec, _ = snap.authorise(None, "task.count", "TVM01/A1", {"store": "TVM01"},
                            assertion=tok(agent="r06_phantom_stock@store=TVM03", scope={"store": "TVM03"}), now=NOW)
    assert not dec                                                            # TVM03 is OBSERVE (the "*" row)
    with pytest.raises(PolicyError, match="another site|for site"):
        load_policy(eng.export_policy(), keys["public"], clock=lambda: NOW, site="elsewhere")
    with pytest.raises(PolicyError, match="issued in the future"):
        load_policy(eng.export_policy(), keys["public"], clock=lambda: NOW - timedelta(hours=3))
    assert snap.stale(NOW - timedelta(hours=1))


def test_receipts_are_checked_against_the_issued_expiry(keys):
    eng = engine(keys)
    snap = load_policy(eng.export_policy(ttl_hours=1), keys["public"], clock=lambda: NOW)
    late = Receipt(at=NOW + timedelta(hours=5), bundle_version=snap.version, actor="meena", actor_kind="person",
                   action="task.count", allowed=True, stale=False)
    early = Receipt(at=NOW - timedelta(hours=2), bundle_version=snap.version, actor="meena", actor_kind="person",
                    action="task.count", allowed=True)
    out = eng.record_receipts([late, early])
    assert {f for x in out["flags"] for f in x["flags"]} == {"after_bundle_expiry", "before_bundle_issue"}



def test_bind_assertion_for_a_core_with_its_own_authority(keys):
    """Option A in the POS handoff: the core verifies and binds the token, then runs its own Limits check."""
    from sentinel.orgsync import bind_assertion
    tok = sign_agent_assertion(keys["signer"], agent="r06@store=TVM01", template="r06_phantom_stock",
                               bound_role="store_manager", mode="ACT", scope={"store": "TVM01"}, action="stock.adjust",
                               obj="TVM01/A1", incident="i", site="r06", now=NOW)
    used: dict = {}
    expand = directory().expand_facts
    claims = bind_assertion(tok, keys["public"], action="stock.adjust", obj="TVM01/A1", scope={"region": "south"},
                            site="r06", used=used, expand=expand, now=NOW)
    assert claims["bound_role"] == "store_manager" and claims["jti"] in used
    with pytest.raises(PolicyError, match="already used"):
        bind_assertion(tok, keys["public"], action="stock.adjust", obj="TVM01/A1", scope={}, site="r06", used=used,
                       now=NOW)
    for kw, why in (({"action": "task.count"}, "for 'stock.adjust'"), ({"site": "x"}, "site"),
                    ({"scope": {"region": "central"}}, "does not cover"), ({"actor": "other"}, "not other")):
        args = dict(action="stock.adjust", obj="TVM01/A1", scope={"store": "TVM01"}, site="r06", used={},
                    expand=expand, now=NOW)
        args.update(kw)
        with pytest.raises(PolicyError, match=why):
            bind_assertion(tok, keys["public"], **args)
    with pytest.raises(PolicyError, match="does not cover"):          # without roll-ups, region is not covered
        bind_assertion(tok, keys["public"], action="stock.adjust", obj="TVM01/A1", scope={"region": "south"},
                       site="r06", used={}, now=NOW)
