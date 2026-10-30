# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""G2: the pack catalogue - build, search, add with dependencies, digests, upgrades."""
from __future__ import annotations

import json
import shutil

import pytest
import yaml

from sentinel import catalogue as cat
from sentinel.packs import PackError, load
from tests.test_packs import DAIRY, write


def _folder(tmp_path, monkeypatch):
    src = tmp_path / "src"
    src.mkdir()
    write(src, monkeypatch)
    m = yaml.safe_load((src / "dairy" / "sentinel-pack.yaml").read_text())
    m.update({"title": "Dairy distribution", "industry": "dairy", "tags": ["dsd", "credit"]})
    (src / "dairy" / "sentinel-pack.yaml").write_text(yaml.safe_dump(m))
    (src / "packs.yaml").unlink()
    return src


def test_build_search_and_add(tmp_path, monkeypatch):
    src = _folder(tmp_path, monkeypatch)
    doc = cat.build(src, key="ck", relative_to=tmp_path)
    assert doc["problems"] == [] and {e["id"] for e in doc["packs"]} == {"kbgrid.core-trunk", "kbgrid.dairy-dsd"}
    dairy = next(e for e in doc["packs"] if e["id"] == "kbgrid.dairy-dsd")
    assert dairy["exceptions"] == ["credit_limit_exceeded"] and dairy["industry"] == "dairy"
    assert dairy["capabilities"] == ["read:sap.customer", "write:sap.sales_order"]
    (tmp_path / "catalogue.json").write_text(json.dumps(doc))
    with pytest.raises(PackError, match="signature"):
        cat.load(tmp_path / "catalogue.json", key="other")
    c = cat.load(tmp_path / "catalogue.json", key="ck")
    assert [e["id"] for e in cat.search(c, "credit")] == ["kbgrid.dairy-dsd"]
    assert cat.search(c, industry="dairy")[0]["fits"] is True

    site = tmp_path / "site"
    site.mkdir()
    out = cat.add(c, "kbgrid.dairy-dsd", site / "packs.yaml")
    assert {x["id"] for x in out["added"]} == {"kbgrid.dairy-dsd", "kbgrid.core-trunk"}   # its dependency too
    assert out["settings_to_fill"] == {"kbgrid.dairy-dsd": ["sap_company_db"]}
    assert out["capabilities_to_grant"]["kbgrid.dairy-dsd"] == ["read:sap.customer", "write:sap.sales_order"]
    spec = yaml.safe_load((site / "packs.yaml").read_text())
    assert [x["id"] for x in spec["packs"]] == ["kbgrid.core-trunk", "kbgrid.dairy-dsd"]
    assert all(x["grant"] == [] for x in spec["packs"])                  # nothing granted by default
    ps = load(site / "packs.yaml")
    assert set(ps.refused) == {"dairy.place_hold", "dairy.outlet"}


def test_upgrade_keeps_settings_and_tampering_is_refused(tmp_path, monkeypatch):
    src = _folder(tmp_path, monkeypatch)
    site = tmp_path / "site"
    site.mkdir()
    (tmp_path / "c.json").write_text(json.dumps(cat.build(src, relative_to=tmp_path)))
    cat.add(cat.load(tmp_path / "c.json"), "kbgrid.dairy-dsd", site / "packs.yaml")
    spec = yaml.safe_load((site / "packs.yaml").read_text())
    spec["packs"][1].update({"config": {"sap_company_db": "CO01"}, "grant": ["read:sap.customer"]})
    (site / "packs.yaml").write_text(yaml.safe_dump(spec))
    shutil.copytree(src / "dairy", src / "dairy2")
    (src / "dairy2" / "sentinel-pack.yaml").write_text(yaml.safe_dump({**DAIRY, "version": "1.4.0"}))
    (src / "dairy3").mkdir()
    (src / "dairy3" / "sentinel-pack.yaml").write_text(yaml.safe_dump({**DAIRY, "version": "9.0.0",
                                                                         "sentinel": ">=9"}))
    (tmp_path / "c.json").write_text(json.dumps(cat.build(src, relative_to=tmp_path)))
    c = cat.load(tmp_path / "c.json")
    assert cat.search(c, "dairy")[0]["version"] == "1.4.0"                # newest that fits this Sentinel
    out = cat.add(c, "kbgrid.dairy-dsd", site / "packs.yaml")
    assert out["upgraded"][0]["version"] == "1.4.0" and out["added"] == []
    spec = yaml.safe_load((site / "packs.yaml").read_text())
    dairy = next(x for x in spec["packs"] if x["id"] == "kbgrid.dairy-dsd")
    assert dairy["config"] == {"sap_company_db": "CO01"} and dairy["grant"] == ["read:sap.customer"]
    assert dairy["path"].endswith("1.4.0") and out["capabilities_to_grant"]["kbgrid.dairy-dsd"] == [
        "write:sap.sales_order"]
    (src / "dairy2" / "registry" / "dairy.yaml").write_text("patterns: []\n")      # changed after cataloguing
    with pytest.raises(PackError, match="digest"):
        cat.add(c, "kbgrid.dairy-dsd", site / "packs.yaml")
    with pytest.raises(PackError, match="works with Sentinel"):
        cat.pick(c, "kbgrid.dairy-dsd", ">=9")


def test_cli(tmp_path, monkeypatch, capsys):
    from sentinel.cli import main
    src = _folder(tmp_path, monkeypatch)
    out = tmp_path / "c.json"
    assert main(["pack", "catalogue", "build", str(src), "--out", str(out)]) == 0
    capsys.readouterr()
    assert main(["pack", "search", "dairy", "--catalogue", str(out)]) == 0
    assert json.loads(capsys.readouterr().out)[0]["id"] == "kbgrid.dairy-dsd"
    assert main(["pack", "add", "kbgrid.dairy-dsd", "--catalogue", str(out), "--packs-file",
                 str(tmp_path / "site.yaml")]) == 0
    assert main(["pack", "search", "x"]) == 2                       # no catalogue given


def test_console_lists_the_catalogue(tmp_path, monkeypatch, engine_factory):
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from sentinel.api import Principal, create_app, token_hash
    src = _folder(tmp_path, monkeypatch)
    (tmp_path / "c.json").write_text(json.dumps(cat.build(src, relative_to=tmp_path)))
    c = TestClient(create_app(engine_factory(), {token_hash("p"): Principal("person", "hari")}))
    h = {"Authorization": "Bearer p"}
    assert c.get("/console/api/packs", headers=h).json() == {"configured": False, "packs": []}
    monkeypatch.setenv("SENTINEL_PACK_CATALOGUE", str(tmp_path / "c.json"))
    got = c.get("/console/api/packs", headers=h).json()["packs"]
    assert {x["id"] for x in got} == {"kbgrid.core-trunk", "kbgrid.dairy-dsd"} and all(x["fits"] for x in got)
