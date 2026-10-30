# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""D5: start a project from a template (layer, stubs, scaffold) and publish configuration from the CLI."""
from __future__ import annotations

import json

import pytest
import yaml

from sentinel import ActionRegistry, Engine, LayerError, Overlay, SQLiteStore, load_layers
from sentinel import templates
from sentinel.cli import main


def test_a_layer_can_start_from_a_template(tmp_path):
    base = templates.load("retail-fulfilment")["registry"]
    some = base["patterns"][0]["id"]
    f = tmp_path / "project.yaml"
    f.write_text(yaml.safe_dump({"template": "retail-fulfilment", "layer": "acme",
                                 "overrides": [{"id": some, "set": {"sla_minutes": 15}}],
                                 "disable": [base["patterns"][1]["id"]]}))
    doc = load_layers([f])
    ids = {p.id: p for p in doc.patterns}
    assert len(ids) == len(base["patterns"]) - 1
    assert ids[some].sla_minutes == 15 and ids[some].layer == "template:retail-fulfilment"
    assert ids[some].overridden_in == ["acme"]
    bad = tmp_path / "bad.yaml"
    bad.write_text("template: no-such-thing\n")
    with pytest.raises(LayerError, match="unknown template"):
        load_layers([bad])
    with pytest.raises(KeyError):
        templates.load("../secrets")


def test_stub_actions_let_a_template_run_safely(tmp_path):
    reg = templates.load("retail-fulfilment")["registry"]
    f = tmp_path / "p.yaml"
    f.write_text("template: retail-fulfilment\n")
    doc = load_layers([f])
    acts = templates.stub_actions(reg)
    ov = Overlay(name="acme", fingerprint_rules=doc.fingerprints, patterns=doc.patterns, actions=acts,
                 roles=doc.roles)
    eng = Engine(ov, store=SQLiteStore(":memory:"), raise_on_invalid=False)
    assert all(eng.actions.has(a) for a in templates.needs(reg)["actions"])
    name = templates.needs(reg)["actions"][0]
    res = acts.get(name).handler(None, {})
    assert res.ok is False and res.retryable is False and "stub" in res.detail
    mine = ActionRegistry()
    mine.register(acts.get(name).spec.model_copy(update={"description": "real"}), lambda c, p: None)
    templates.stub_actions(reg, into=mine)
    assert mine.get(name).spec.description == "real"                   # real actions are never replaced


def test_template_cli(tmp_path, capsys):
    assert main(["template", "list"]) == 0
    assert "retail-fulfilment" in capsys.readouterr().out
    assert main(["template", "show", "manufacturing"]) == 0
    assert json.loads(capsys.readouterr().out)["needs"]["actions"]
    out = tmp_path / "proj"
    assert main(["template", "init", "retail-fulfilment", "--out", str(out)]) == 0
    capsys.readouterr()
    assert (out / "registry.yaml").read_text().count("template: retail-fulfilment") == 1
    src = (out / "actions.py").read_text()
    compile(src, "actions.py", "exec")
    assert "NotImplementedError" in src
    assert load_layers([out / "registry.yaml"]).patterns
    assert main(["template", "init", "retail-fulfilment", "--out", str(out)]) == 1     # will not overwrite
    assert main(["template", "show", "nope"]) == 2


OVERLAY = "tests.test_templates_cli:_overlay"


def _overlay():
    from tests.conftest import Backend, make_overlay
    return make_overlay(Backend())


def test_config_cli_check_and_publish(tmp_path, capsys):
    db = str(tmp_path / "s.db")
    base = ["--overlay", OVERLAY, "--db", db]
    assert main([*base, "config", "show", "registry"]) == 0
    doc = yaml.safe_load(capsys.readouterr().out)
    for p in doc["patterns"]:
        if p["id"] == "job_timeout":
            p["sla_minutes"] = 7
    good = tmp_path / "r.yaml"
    good.write_text(yaml.safe_dump(doc))
    assert main([*base, "config", "check", "registry", str(good)]) == 0
    assert json.loads(capsys.readouterr().out)["ok"] is True
    bad_doc = json.loads(json.dumps(doc))
    bad_doc["patterns"][0]["allowed_actions"] = ["no_such_action"]
    bad = tmp_path / "bad.yaml"
    bad.write_text(yaml.safe_dump(bad_doc))
    assert main([*base, "config", "publish", "registry", str(bad), "--by", "mohan"]) == 1
    assert json.loads(capsys.readouterr().out)["ok"] is False
    assert main([*base, "config", "publish", "registry", str(good), "--by", "mohan", "--note", "sla"]) == 0
    assert json.loads(capsys.readouterr().out)["published"] == "registry"
    assert main([*base, "config", "show", "registry"]) == 0
    shown = yaml.safe_load(capsys.readouterr().out)
    assert next(p for p in shown["patterns"] if p["id"] == "job_timeout")["sla_minutes"] == 7
    assert main([*base, "config", "show", "nonsense"]) == 2
