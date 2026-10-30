# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""G1 / D8 / D4: domain packs, the overlay test kit, and console changes kept as a layer over the packs."""
from __future__ import annotations

import textwrap

import pytest
import yaml

from sentinel.config import dump_yaml
from sentinel.packs import PackError, build_overlay, load, satisfies
from sentinel.testing import conformance, engine_for, run_golden

CORE = {"id": "kbgrid.core-trunk", "version": "1.2.0", "namespace": "core", "sentinel": ">=0.10",
        "layers": ["registry.yaml"]}
CORE_REG = {"roles": {"ops": "Operations"}, "fingerprints": [], "patterns": []}
DAIRY = {"id": "kbgrid.dairy-dsd", "version": "1.3.0", "namespace": "dairy", "sentinel": ">=0.10,<2",
         "requires": ["kbgrid.core-trunk>=1.0"], "layers": ["registry/dairy.yaml"], "python": "dairy_pack:register",
         "provides": {"actions": [{"name": "dairy.place_hold", "capabilities": ["write:sap.sales_order"]}],
                      "tools": [{"name": "dairy.outlet", "capabilities": ["read:sap.customer"]}]},
         "config_schema": {"sap_company_db": "str"}, "golden": "golden"}
DAIRY_REG = {"fingerprints": [{"event_type": "order.credit_exceeded", "fields": {"outlet": "outlet"}}],
             "patterns": [{"id": "credit_limit_exceeded", "description": "Order over the outlet's credit limit",
                           "event_types": ["order.credit_exceeded"], "route": "auto", "owner_role": "ops",
                           "allowed_actions": ["dairy.place_hold"],
                           "playbook": [{"action": "dairy.place_hold", "params": {"outlet": "{{payload.outlet}}"}}]}]}
CODE = textwrap.dedent('''
    from sentinel import ActionResult
    CALLS = []

    def register(ctx):
        @ctx.action("dairy.place_hold", reversible=True, description="Hold the outlet's orders",
                    params={"outlet": "str"})
        def hold(c, p):
            CALLS.append(("hold", p, ctx.config["sap_company_db"]))
            return ActionResult(ok=True)

        @hold.compensator
        def release(c, p):
            return ActionResult(ok=True)

        @ctx.tool("dairy.outlet", "outlet account", {"outlet": "str"})
        def outlet(args, services):
            return {"outlet": args["outlet"], "limit": 50000}
''')


def write(tmp_path, monkeypatch, *, grant=("write:sap.sales_order", "read:sap.customer"), dairy=None,
          customer=None, code=CODE):
    (tmp_path / "core").mkdir(exist_ok=True)
    (tmp_path / "core" / "sentinel-pack.yaml").write_text(yaml.safe_dump(CORE))
    (tmp_path / "core" / "registry.yaml").write_text(yaml.safe_dump(CORE_REG))
    d = tmp_path / "dairy"
    (d / "registry").mkdir(parents=True, exist_ok=True)
    (d / "golden").mkdir(exist_ok=True)
    (d / "sentinel-pack.yaml").write_text(yaml.safe_dump(dairy or DAIRY))
    (d / "registry" / "dairy.yaml").write_text(yaml.safe_dump(DAIRY_REG))
    (d / "golden" / "credit.yaml").write_text(yaml.safe_dump({
        "name": "credit hold", "event": {"type": "order.credit_exceeded", "payload": {"outlet": "O-17"}},
        "expect": {"pattern": "credit_limit_exceeded", "outcome": "automatic", "actions": ["dairy.place_hold"]}}))
    (tmp_path / "dairy_pack.py").write_text(code)
    monkeypatch.syspath_prepend(str(tmp_path))
    import sys
    sys.modules.pop("dairy_pack", None)
    packs = {"packs": [{"id": "kbgrid.dairy-dsd", "path": "dairy", "config": {"sap_company_db": "CO01"},
                        "grant": list(grant)},
                       {"id": "kbgrid.core-trunk", "path": "core"}]}
    if customer:
        (tmp_path / "northwind.yaml").write_text(yaml.safe_dump(customer))
        packs["layers"] = ["northwind.yaml"]
    f = tmp_path / "packs.yaml"
    f.write_text(yaml.safe_dump(packs))
    return f


def test_versions():
    assert satisfies("1.3.0", ">=1.0,<2") and not satisfies("2.0.0", ">=1.0,<2")
    assert satisfies("0.10.0", ">=0.10") and not satisfies("0.9.5", ">=0.10")
    assert satisfies("1.4.2", "~=1.4") and not satisfies("2.0", "~=1.4")


def test_packs_load_in_order_conform_and_pass_golden_cases(tmp_path, monkeypatch):
    f = write(tmp_path, monkeypatch, customer={"overrides": [{"id": "credit_limit_exceeded", "set": {"sla_minutes": 30}}]})
    ps = load(f)
    assert [p.id for p in ps.packs] == ["kbgrid.core-trunk", "kbgrid.dairy-dsd"] and ps.problems == []
    ov = build_overlay(f, name="northwind")
    assert ov.patterns[0].sla_minutes == 30 and ov.patterns[0].overridden_in == ["northwind"]
    assert conformance(ov) == []
    eng = engine_for(ov)
    assert run_golden(eng, tmp_path / "dairy" / "golden") == []
    eng.ingest(__import__("sentinel").Event(type="order.credit_exceeded", source="sap", payload={"outlet": "O-1"}))
    import dairy_pack
    assert dairy_pack.CALLS == [("hold", {"outlet": "O-1"}, "CO01")]
    bad = tmp_path / "golden-bad.yaml"
    bad.write_text(yaml.safe_dump({"event": {"type": "order.credit_exceeded", "payload": {"outlet": "x"}},
                                   "expect": {"outcome": "person"}}))
    assert "outcome expected 'person'" in run_golden(eng, bad)[0]


def test_capabilities_not_granted_refuse_and_go_to_a_person(tmp_path, monkeypatch):
    ov = build_overlay(write(tmp_path, monkeypatch, grant=["read:sap.customer"]))
    assert ov.packs.refused == {"dairy.place_hold": ["write:sap.sales_order"]}
    eng = engine_for(ov)
    r = eng.ingest(__import__("sentinel").Event(type="order.credit_exceeded", source="sap", payload={"outlet": "O-2"}))
    import dairy_pack
    assert dairy_pack.CALLS == []
    assert eng.store.get_incident(r.incident_id).state.value in ("failed", "awaiting_human")


def test_pack_rules(tmp_path, monkeypatch):
    with pytest.raises(PackError, match="must be named dairy"):
        build_overlay(write(tmp_path, monkeypatch, code=CODE.replace('"dairy.place_hold", reversible',
                                                                   '"place_hold", reversible')))
    with pytest.raises(PackError, match="needs Sentinel"):
        load(write(tmp_path, monkeypatch, dairy={**DAIRY, "sentinel": ">=9.0"}))
    with pytest.raises(PackError, match="needs kbgrid.core-trunk"):
        load(write(tmp_path, monkeypatch, dairy={**DAIRY, "requires": ["kbgrid.core-trunk>=5"]}))
    ps = load(write(tmp_path, monkeypatch, dairy={**DAIRY, "provides": {"actions": [], "tools": []}}))
    assert any("not declared in provides.actions" in p for p in ps.problems)


def test_console_changes_survive_a_pack_upgrade(tmp_path, monkeypatch, engine_factory, overlay):
    """D4: the console's changes are a layer; a new pack version underneath still takes effect."""
    from sentinel import Engine, SQLiteStore
    from tests.conftest import Backend, make_overlay
    db = str(tmp_path / "d4.db")
    eng = Engine(make_overlay(Backend()), store=SQLiteStore(db), licence=False)
    doc = yaml.safe_load(eng.config_text("registry"))
    for p in doc["patterns"]:
        if p["id"] == "site_down":
            p["sla_minutes"] = 45                                    # a console change
    doc["patterns"].append({"id": "console_new", "event_types": ["site.down"], "match": {"site": "X"},
                            "owner_role": "lead"})
    cv, _ = eng.save_config("registry", dump_yaml(doc), "m")
    assert cv.layer["overrides"] == [{"id": "site_down", "set": {"sla_minutes": 45}}]
    eng.publish_config(cv.id, actor="m")
    upgraded = make_overlay(Backend())                               # the next version of the code / pack
    for i, p in enumerate(upgraded.patterns):
        if p.id == "site_down":
            upgraded.patterns[i] = p.model_copy(update={"severity": "critical"})
        if p.id == "job_timeout":
            upgraded.patterns[i] = p.model_copy(update={"description": "upstream wording"})
    eng2 = Engine(upgraded, store=SQLiteStore(db), licence=False)
    sd = eng2.registry.get("site_down")
    assert sd.sla_minutes == 45 and sd.severity == "critical"        # both changes kept
    assert eng2.registry.get("job_timeout").description == "upstream wording"
    assert eng2.registry.get("console_new")
    assert "upstream wording" in eng2.config_text("registry")
    assert any(a["kind"] == "registry_rebased" for a in eng2.store.audit_log())
    gone = make_overlay(Backend(), patterns=[p for p in upgraded.patterns if p.id != "site_down"])
    eng3 = Engine(gone, store=SQLiteStore(db), licence=False, raise_on_invalid=False)
    assert any(a["kind"] == "registry_rebase_failed" for a in eng3.store.audit_log())
    assert eng3.registry.get("site_down").sla_minutes == 45           # fell back to what was published


def test_pack_check_cli(tmp_path, monkeypatch, capsys):
    import json

    from sentinel.cli import main
    f = write(tmp_path, monkeypatch)
    assert main(["pack", "check", str(f)]) == 0
    res = json.loads(capsys.readouterr().out)
    assert res["ok"] and res["golden"] == {"kbgrid.dairy-dsd": []}
    monkeypatch.setenv("SENTINEL_PACKS", str(f))
    assert main(["--overlay", "sentinel.packs:from_env", "--db", str(tmp_path / "x.db"), "validate"]) == 0
