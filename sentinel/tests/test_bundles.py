# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""C5: environments and configuration bundles (dev -> staging -> prod)."""
from __future__ import annotations

import json

import pytest

from sentinel import bundles
from tests.test_config import edit_pattern, registry_doc


def test_export_import_promotes_the_same_configuration(engine_factory, monkeypatch):
    monkeypatch.setenv("SENTINEL_ENV", "staging")
    src = engine_factory()
    src.publish_config(src.save_config("registry", edit_pattern(registry_doc(src), "site_down", sla_minutes=11),
                                       "mohan")[0].id, actor="mohan")
    doc = bundles.export(src, ["registry"], key="bk")
    assert doc["env"] == "staging" and bundles.verify(doc, "bk") == []

    monkeypatch.setenv("SENTINEL_ENV", "prod")
    monkeypatch.setenv("SENTINEL_ENV_ACCEPTS", "staging")
    dst = engine_factory()
    p = bundles.plan(dst, doc)
    assert p["registry"]["changed"] and "sla_minutes: 11" in p["registry"]["diff"]
    out = bundles.import_bundle(dst, doc, "lead", key="bk")
    assert out["published"] == [{"kind": "registry", "version": 1}]
    assert dst.registry.get("site_down").sla_minutes == 11
    assert bundles.import_bundle(dst, doc, "lead", key="bk") == {"published": [], "unchanged": ["registry"]}
    assert any(a["kind"] == "bundle_imported" for a in dst.store.audit_log())
    assert dst.health()["environment"] == "prod"


def test_refuses_tampered_unsigned_wrong_env_or_unfit(engine_factory, monkeypatch):
    monkeypatch.setenv("SENTINEL_ENV", "dev")
    eng = engine_factory()
    doc = bundles.export(eng, ["registry"], key="bk")
    bad = json.loads(json.dumps(doc))
    bad["configs"]["registry"]["text"] += "\n# edited\n"
    with pytest.raises(ValueError, match="checksum"):
        bundles.import_bundle(eng, bad, "lead", key="bk")
    unsigned = bundles.export(eng, ["registry"], key="")
    with pytest.raises(ValueError, match="not signed"):
        bundles.import_bundle(eng, unsigned, "lead", key="bk")
    monkeypatch.setenv("SENTINEL_ENV_ACCEPTS", "staging")
    with pytest.raises(ValueError, match="accepts bundles only from staging"):
        bundles.import_bundle(eng, doc, "lead", key="bk")
    monkeypatch.delenv("SENTINEL_ENV_ACCEPTS")
    unfit = registry_doc(eng)
    unfit["patterns"][0]["allowed_actions"] = ["teleport"]
    from sentinel.config import dump_yaml
    doc2 = bundles.export(eng, ["registry"], key="bk")
    doc2["configs"]["registry"]["text"] = text = dump_yaml(unfit)
    doc2["configs"]["registry"]["checksum"] = bundles._sum(text)
    doc2["digest"] = __import__("hashlib").sha256(bundles._canonical(doc2)).hexdigest()
    with pytest.raises(ValueError, match="does not fit this site"):
        bundles.import_bundle(eng, doc2, "lead", key=None)
    with pytest.raises(ValueError, match="unknown kinds"):
        bundles.export(eng, ["nope"])


def test_cli(tmp_path, capsys, monkeypatch):
    from sentinel.cli import main
    monkeypatch.setenv("SENTINEL_ENV", "dev")
    base = ["--overlay", "tests.test_templates_cli:_overlay", "--db", str(tmp_path / "b.db")]
    out = tmp_path / "bundle.json"
    assert main([*base, "bundle", "export", "--kinds", "registry", "--out", str(out)]) == 0
    capsys.readouterr()
    assert main([*base, "bundle", "plan", str(out)]) == 0
    res = json.loads(capsys.readouterr().out)
    assert res["from"] == "dev" and res["kinds"]["registry"]["changed"] is False
    assert main([*base, "bundle", "import", str(out), "--by", "mohan"]) == 0
