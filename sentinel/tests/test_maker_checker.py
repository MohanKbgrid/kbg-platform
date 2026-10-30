# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""C1: two-person approval for publishing configuration (maker-checker)."""
from __future__ import annotations

import pytest
import yaml

from sentinel import AuthorizationError
from sentinel.config import ApprovalNeeded, ConfigError, dump_yaml
from sentinel.rbac import AuthorityRule, ConfigApproval
from tests.test_config import edit_pattern, registry_doc
from tests.test_rbac import make_directory


@pytest.fixture
def eng(engine_factory):
    d = make_directory(config_approval=ConfigApproval(approvals=1))
    d.rules.append(AuthorityRule(role_id="ops_head", action="__configure__"))
    return engine_factory(directory=d)


def _draft(eng, author, sla):
    return eng.save_config("registry", edit_pattern(registry_doc(eng), "site_down", sla_minutes=sla), author)[0]


def test_author_cannot_publish_alone_another_approves(eng):
    cv = _draft(eng, "hari", 41)
    with pytest.raises(ApprovalNeeded):
        eng.publish_config(cv.id, actor="hari")
    assert eng.registry.get("site_down").sla_minutes == 30
    waiting = eng.store.get_config_version(cv.id)
    assert waiting.status == "draft" and waiting.requested_by == "hari" and waiting.approvals == []
    with pytest.raises(AuthorizationError, match="author"):
        eng.approve_config(cv.id, "hari")
    with pytest.raises(AuthorizationError):
        eng.approve_config(cv.id, "lata")                         # no __configure__
    out = eng.approve_config(cv.id, "hema")
    assert [v.status for v in out] == ["published"] and eng.registry.get("site_down").sla_minutes == 41
    with pytest.raises(ConfigError, match="only drafts"):
        eng.approve_config(cv.id, "hema")
    kinds = [a["kind"] for a in eng.store.audit_log()]
    assert "config_approval_requested" in kinds and "config_approved" in kinds


def test_publishing_someone_elses_draft_is_the_approval(eng):
    cv = _draft(eng, "hari", 42)
    eng.publish_config(cv.id, actor="hema")
    assert eng.registry.get("site_down").sla_minutes == 42
    assert eng.store.get_config_version(cv.id).approvals == ["hema"]


def test_rollback_needs_approval_too_and_sets_publish_together(eng):
    v1 = _draft(eng, "hari", 43)
    eng.publish_config(v1.id, actor="hema")
    v2 = _draft(eng, "hari", 44)
    eng.publish_config(v2.id, actor="hema")
    with pytest.raises(ApprovalNeeded) as e:                       # hari rolls back to v1: a new version, his
        eng.publish_config(v1.id, actor="hari")
    copy = e.value.versions[0]
    assert copy.copied_from == v1.id and eng.registry.get("site_down").sla_minutes == 44
    eng.approve_config(copy.id, "hema")
    assert eng.registry.get("site_down").sla_minutes == 43
    people = yaml.safe_load(eng.config_text("people"))
    people["people"].append({"id": "nia"})
    pv = eng.save_config("people", dump_yaml(people), "hari")[0]
    rv = _draft(eng, "hari", 45)
    with pytest.raises(ApprovalNeeded):
        eng.publish_config_set([pv.id, rv.id], actor="hari")
    assert eng.approve_config(pv.id, "hema")                       # the approver publishes the whole set
    assert "nia" in eng.directory.people and eng.registry.get("site_down").sla_minutes == 45


def test_policy_checks_and_round_trip(engine_factory):
    d = make_directory(config_approval=ConfigApproval(approvals=2))
    d.rules.append(AuthorityRule(role_id="ops_head", action="__configure__"))
    eng = engine_factory(directory=d)
    text = eng.config_text("people")
    assert "config_approval" in text and "approvals: 2" in text
    _, probs = eng.check_config("people", text)
    assert any("config_approval needs 3 active people" in p.message for p in probs if p.severity == "error")
    off = yaml.safe_load(text)
    off["config_approval"]["kinds"] = ["nonsense"]
    _, probs = eng.check_config("people", dump_yaml(off))
    assert any("unknown kinds" in p.message for p in probs)


def test_without_a_policy_nothing_changes(engine_factory):
    d = make_directory()
    d.rules.append(AuthorityRule(role_id="ops_head", action="__configure__"))
    eng = engine_factory(directory=d)
    cv = _draft(eng, "hari", 46)
    eng.publish_config(cv.id, actor="hari")
    assert eng.registry.get("site_down").sla_minutes == 46


def test_cli_waits_and_approves(tmp_path, capsys, monkeypatch):
    import json

    from sentinel.cli import main
    pfile = tmp_path / "people.yaml"
    from sentinel.config import directory_doc
    d = make_directory(config_approval=ConfigApproval(approvals=1))
    d.rules.append(AuthorityRule(role_id="ops_head", action="__configure__"))
    pfile.write_text(dump_yaml(directory_doc(d)))
    base = ["--overlay", "tests.test_templates_cli:_overlay", "--db", str(tmp_path / "m.db"),
            "--directory", str(pfile)]
    assert main([*base, "config", "show", "registry"]) == 0
    doc = yaml.safe_load(capsys.readouterr().out)
    next(p for p in doc["patterns"] if p["id"] == "site_down")["sla_minutes"] = 47
    f = tmp_path / "r.yaml"
    f.write_text(dump_yaml(doc))
    assert main([*base, "config", "publish", "registry", str(f), "--by", "hari"]) == 3
    vid = json.loads(capsys.readouterr().out)["waiting_for_approval"][0]["id"]
    assert main([*base, "config", "waiting"]) == 0
    assert json.loads(capsys.readouterr().out)[0]["id"] == vid
    assert main([*base, "config", "approve", vid, "--by", "hema"]) == 0
    assert json.loads(capsys.readouterr().out)["published"][0]["status"] == "published"
