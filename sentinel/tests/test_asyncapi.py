# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""docs/asyncapi.yaml (AsyncAPI 3.0) cannot drift from the envelope and the shipped event types."""
from __future__ import annotations

import importlib.util
from pathlib import Path

import yaml

from sentinel import connectors, templates
from sentinel.models import Event

ROOT = Path(__file__).resolve().parent.parent
DOC = ROOT / "docs" / "asyncapi.yaml"


def _gen():
    spec = importlib.util.spec_from_file_location("gen_asyncapi", ROOT / "scripts" / "gen_asyncapi.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _doc() -> dict:
    return yaml.safe_load(DOC.read_text(encoding="utf-8"))


def _walk(o):
    if isinstance(o, dict):
        for k, v in o.items():
            if k == "$ref":
                yield v
            else:
                yield from _walk(v)
    elif isinstance(o, list):
        for v in o:
            yield from _walk(v)


def _resolve(doc: dict, ref: str):
    assert ref.startswith("#/"), ref
    node = doc
    for part in ref[2:].split("/"):
        node = node[part]
    return node


def test_the_file_is_what_the_generator_writes():
    assert DOC.read_text(encoding="utf-8") == _gen().render(), \
        "docs/asyncapi.yaml is stale: run python scripts/gen_asyncapi.py"


def test_it_is_asyncapi_3_with_the_required_parts():
    d = _doc()
    assert d["asyncapi"] == "3.0.0" and d["info"]["title"] and d["info"]["version"]
    assert set(d["channels"]) == {"events", "cloudevents"}
    for op in d["operations"].values():
        assert op["action"] in ("send", "receive") and "$ref" in op["channel"]
    assert d["components"]["securitySchemes"]["serviceToken"]["scheme"] == "bearer"


def test_every_reference_resolves():
    d = _doc()
    refs = list(_walk(d))
    assert len(refs) > 50
    for r in refs:
        _resolve(d, r)


def test_the_envelope_is_the_code_s_envelope():
    d = _doc()
    schema = d["components"]["schemas"]["Event"]
    assert set(schema["properties"]) == set(Event.model_fields)
    assert set(schema["required"]) == {n for n, f in Event.model_fields.items() if f.is_required()}


def test_every_shipped_event_type_has_a_message():
    d = _doc()
    named = {m["name"] for k, m in d["components"]["messages"].items() if k != "CloudEvent"}
    expected: set[str] = set()
    for n in templates.names():
        reg = templates.load(n)["registry"]
        expected |= {r["event_type"] for r in reg.get("fingerprints") or []}
        for p in reg.get("patterns") or []:
            expected |= {t for t in p.get("event_types") or [] if t != "*"}
    for n in connectors.names():
        c = connectors.load(n)
        expected |= set(c.get("events") or [])
        expected |= {r["event_type"] for r in c.get("fingerprints") or []}
    assert len(expected) >= 20
    assert expected <= named, sorted(expected - named)
    # identifiers do not collide: two event types never share a message
    assert len(named) == len({_gen()._ident(t) for t in named})
    for ident in d["channels"]["events"]["messages"]:
        msg = d["components"]["messages"][ident]
        assert msg["name"] in named


def test_a_payload_lists_what_the_fingerprint_rules_read():
    d = _doc()
    props = d["components"]["schemas"]["Payload_order_unfulfilled"]["properties"]
    assert {"channel", "location", "stock_status", "order_id", "hours_since_paid"} <= set(props)
    assert props["hours_since_paid"] == {"type": "number"}


def test_drift_is_caught(tmp_path, monkeypatch):
    """Planted drift: an edited file no longer matches the generator."""
    g = _gen()
    stale = DOC.read_text(encoding="utf-8").replace("order.unfulfilled", "order.unfulfilled2", 1)
    assert stale != g.render()
    monkeypatch.setattr(g, "OUT", tmp_path / "asyncapi.yaml")
    (tmp_path / "asyncapi.yaml").write_text(stale, encoding="utf-8")
    monkeypatch.setattr("sys.argv", ["gen_asyncapi.py", "--check"])
    assert g.main() == 1
