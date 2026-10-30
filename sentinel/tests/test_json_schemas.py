# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""The JSON Schemas for Sentinel's YAML: current, valid, accepting every shipped file, refusing a planted defect."""
from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path

import pytest
import yaml

jsonschema = pytest.importorskip("jsonschema")

ROOT = Path(__file__).resolve().parent.parent
SCHEMAS = ROOT / "schemas"
CFG = ROOT / "deploy" / "site" / "config"


def _gen():
    spec = importlib.util.spec_from_file_location("gen_json_schemas", ROOT / "scripts" / "gen_json_schemas.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def schema(name: str) -> dict:
    return json.loads((SCHEMAS / f"{name}.schema.json").read_text(encoding="utf-8"))


def load(path: Path):
    """YAML as JSON: an unquoted 2026-10-25 is a date to PyYAML and a string to a schema-aware editor."""
    doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    return json.loads(json.dumps(doc, default=lambda o: o.isoformat()))


def errors(name: str, doc) -> list[str]:
    v = jsonschema.Draft202012Validator(schema(name))
    return [f"{'/'.join(map(str, e.absolute_path))}: {e.message[:200]}" for e in v.iter_errors(doc)]


def shipped() -> list[tuple[str, str, object]]:
    """(label, schema, document) for every shipped template and example file."""
    out: list[tuple[str, str, object]] = []
    for p in sorted((ROOT / "sentinel" / "templates").glob("*.yaml")):
        d = load(p)
        out += [(p.name, "template", d), (f"{p.name}#registry", "registry", d["registry"]),
                (f"{p.name}#people", "people", d["people"])]
    for p in sorted((ROOT / "sentinel" / "connectors").glob("*.yaml")):
        d = load(p)
        out += [(p.name, "connector-template", d), (f"{p.name}#connectors", "connectors", d["connectors"])]
    out += [("models.yaml.example", "models", load(CFG / "models.yaml.example")),
            ("connectors.yaml.example", "connectors", load(CFG / "connectors.yaml.example")),
            ("metrics.yaml.example", "metrics", load(CFG / "metrics.yaml.example"))]
    pack = ROOT / "tests" / "packs" / "r06_stock_integrity"
    out += [("people_chain_a.yaml", "people", load(pack / "people_chain_a.yaml")),
            ("people_chain_a_org.yaml", "people", load(pack / "people_chain_a_org.yaml")),
            ("pack template.yaml", "registry", load(pack / "template.yaml")),
            ("tenant_chain_a.yaml", "registry", load(pack / "tenant_chain_a.yaml"))]
    return out


def test_schemas_are_current():
    g = _gen()
    docs = g.build()
    assert set(docs) == {p.name for p in SCHEMAS.glob("*.schema.json")}
    for name, doc in docs.items():
        assert (SCHEMAS / name).read_text(encoding="utf-8") == g.render(doc), \
            f"{name} is stale: run python scripts/gen_json_schemas.py"


def test_schemas_are_valid_draft_2020_12_with_one_placeholder_base():
    g = _gen()
    for p in SCHEMAS.glob("*.schema.json"):
        s = json.loads(p.read_text(encoding="utf-8"))
        jsonschema.Draft202012Validator.check_schema(s)
        assert s["$schema"] == "https://json-schema.org/draft/2020-12/schema"
        assert s["$id"] == g.SCHEMA_BASE + p.name
    assert g.SCHEMA_BASE.startswith("https://kbg-platform.example/")
    text = "".join(p.read_text(encoding="utf-8") for p in SCHEMAS.glob("*.json"))
    assert '"$ref": "http' not in text, "references must be local so editors need no network"


@pytest.mark.parametrize("label,name,doc", shipped(), ids=[s[0] for s in shipped()])
def test_every_shipped_file_validates(label, name, doc):
    assert errors(name, doc) == []


def test_shipped_set_is_not_empty():
    labels = [s[0] for s in shipped()]
    assert len(labels) >= 25 and "shopify.yaml" in labels and "metrics.yaml.example" in labels


def test_the_loaders_accept_the_shipped_files_too():
    """The schema is not stricter than the code on what ships: the loaders take the same files."""
    from sentinel.kpi import parse
    from sentinel.overlay import parse_registry
    from sentinel.rbac import parse_directory
    parse(load(CFG / "metrics.yaml.example"))
    for p in sorted((ROOT / "sentinel" / "templates").glob("*.yaml")):
        d = load(p)
        parse_registry(d["registry"])
        parse_directory(d["people"])


# ---- planted defects: an invalid file is refused ------------------------------------------------------------

def _template():
    return copy.deepcopy(load(ROOT / "sentinel" / "templates" / "retail-fulfilment.yaml"))


def test_planted_defects_are_refused():
    t = _template()
    t["registry"]["patterns"][0]["sla_minutes"] = "soon"
    assert errors("template", t) and errors("registry", t["registry"])

    r = _template()["registry"]
    r["colour"] = "blue"                                  # an unknown top-level key (the loader refuses it too)
    assert errors("registry", r)

    r = _template()["registry"]
    del r["patterns"][0]["id"]
    assert errors("registry", r)

    r = _template()["registry"]
    r["patterns"][0]["route"] = "teleport"
    assert errors("registry", r)

    p = _template()["people"]
    p["people"] = "everyone"
    assert errors("people", p)

    m = load(CFG / "models.yaml.example")
    m["models"]["claude"]["provider"] = "telepathy"
    assert errors("models", m)
    m = load(CFG / "models.yaml.example")
    m["escalate_below"] = 3
    assert errors("models", m)
    m = load(CFG / "models.yaml.example")
    del m["models"]
    assert errors("models", m)

    k = load(CFG / "metrics.yaml.example")
    k["metrics"]["otif"]["format"] = "furlongs"
    assert errors("metrics", k)

    c = load(ROOT / "sentinel" / "connectors" / "shopify.yaml")
    c["connectors"]["sources"]["shopify_unfulfilled"]["every_s"] = "often"
    assert errors("connector-template", c)
    c = load(ROOT / "sentinel" / "connectors" / "shopify.yaml")
    del c["connectors"]
    assert errors("connector-template", c)


def test_an_unplanted_copy_is_clean():
    assert errors("registry", _template()["registry"]) == []
