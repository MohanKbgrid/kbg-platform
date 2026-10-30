# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""Versioned configuration: drafts, validation, publish with RBAC, hot apply, sync across processes, rollback."""
from __future__ import annotations

import pytest
import yaml

from sentinel import AuthorizationError, Engine, Guardrails, LearningPolicy, Route
from sentinel.config import ConfigError, diff, dump_yaml
from sentinel.rbac import AuthorityRule
from sentinel.worker import Worker
from tests.conftest import job_event, make_overlay, stuck_event
from tests.test_rbac import make_directory


def errors(problems):
    return [p.message for p in problems if p.severity == "error"]


def warnings(problems):
    return [p.message for p in problems if p.severity == "warning"]


def registry_doc(eng):
    return yaml.safe_load(eng.config_text("registry"))


def edit_pattern(doc, pid, **changes):
    for p in doc["patterns"]:
        if p["id"] == pid:
            p.update(changes)
    return dump_yaml(doc)


def test_running_registry_round_trips(engine):
    text = engine.config_text("registry")
    parsed, problems = engine.check_config("registry", text)
    assert errors(problems) == []
    before = {p.id: p.definition_hash() for p in engine.registry.all()}
    assert {p.id: p.definition_hash() for p in parsed.patterns} == before


def test_draft_with_errors_is_kept_but_cannot_be_published(engine):
    doc = registry_doc(engine)
    text = edit_pattern(doc, "job_timeout", allowed_actions=["retry", "teleport"])
    cv, problems = engine.save_config("registry", text, author="mohan", note="try teleport")
    assert cv.version == 1 and cv.status == "draft"
    assert any("'teleport' is not registered - the overlay must implement it" in m for m in errors(problems))
    with pytest.raises(ConfigError) as ei:
        engine.publish_config(cv.id, actor="mohan")
    assert ei.value.problems and engine.store.published_config("registry") is None


@pytest.mark.parametrize("text,needle", [("patterns: [\n  - id: x\n    bad: : :", "not valid YAML (line"),
                                         ("- just\n- a list", "top level must be a mapping"),
                                         ("patterns:\n  - id: x\n", "event_types")])
def test_unreadable_configuration(engine, text, needle):
    _, problems = engine.check_config("registry", text)
    assert any(needle in m for m in errors(problems))


def test_publish_applies_at_once_and_other_processes_sync(engine_factory, overlay, clock):
    eng = engine_factory()
    other = Engine(make_overlay(eng.overlay.services["backend"]), store=eng.store, clock=clock,
                   guardrails=Guardrails(allow_irreversible_unattended=True), learning=LearningPolicy())
    doc = registry_doc(eng)
    text = edit_pattern(doc, "job_failed_other", sla_minutes=15, route="hitl")
    cv, problems = eng.save_config("registry", text, author="mohan")
    pub = eng.publish_config(cv.id, actor="mohan")
    assert pub.status == "published" and pub.published_by == "mohan"
    assert eng.registry.get("job_failed_other").sla_minutes == 15
    assert other.registry.get("job_failed_other").sla_minutes == 240        # not yet
    assert other.sync_config() == ["registry"] and other.sync_config() == []
    assert other.registry.get("job_failed_other").sla_minutes == 15
    r = other.ingest(job_event(error="E9"))
    rv = other.store.open_review_for(r.incident_id)
    assert (rv.due_at - clock()).total_seconds() == 15 * 60
    kinds = [a["kind"] for a in eng.store.audit_log()]
    assert "config_saved" in kinds and "config_published" in kinds


def test_new_engine_starts_from_the_published_configuration(engine_factory, clock):
    eng = engine_factory()
    text = edit_pattern(registry_doc(eng), "site_down", sla_minutes=5)
    eng.publish_config(eng.save_config("registry", text, "mohan")[0].id, actor="mohan")
    fresh = Engine(make_overlay(eng.overlay.services["backend"]), store=eng.store, clock=clock)
    assert fresh.registry.get("site_down").sla_minutes == 5


def test_rollback_republishes_an_old_version_as_new(engine_factory):
    eng = engine_factory()
    base = registry_doc(eng)
    v1 = eng.publish_config(eng.save_config("registry", edit_pattern(base, "site_down", sla_minutes=10), "m")[0].id,
                            actor="m")
    v2 = eng.publish_config(eng.save_config("registry", edit_pattern(base, "site_down", sla_minutes=20), "m")[0].id,
                            actor="m")
    assert eng.registry.get("site_down").sla_minutes == 20
    v3 = eng.publish_config(v1.id, actor="lead")
    assert (v3.version, v3.copied_from, v3.note) == (3, v1.id, "republished v1")
    assert eng.registry.get("site_down").sla_minutes == 10
    statuses = {c.version: c.status for c in eng.store.config_versions("registry")}
    assert statuses == {1: "superseded", 2: "superseded", 3: "published"} and v2.id
    d = diff(v3.text, v2.text)
    assert "-  sla_minutes: 10" in d and "+  sla_minutes: 20" in d


def test_behaviour_change_resets_earned_trust_cosmetic_change_does_not(engine_factory):
    eng = engine_factory()
    for i in range(3):
        eng.ingest(job_event(ref=f"J{i}", key=f"k{i}"))           # job_timeout auto-resolves: earns a streak
    streak = eng.pattern_state(eng.registry.get("job_timeout")).streak
    assert streak == 3
    doc = registry_doc(eng)
    eng.publish_config(eng.save_config("registry", edit_pattern(doc, "job_timeout", description="Retry timeouts"),
                                       "m")[0].id, actor="m")
    assert eng.pattern_state(eng.registry.get("job_timeout")).streak == 3
    eng.publish_config(eng.save_config("registry", edit_pattern(doc, "job_timeout",
                                                                allowed_actions=["retry", "notify", "cancel"]),
                                       "m")[0].id, actor="m")
    assert eng.pattern_state(eng.registry.get("job_timeout")).streak == 0
    assert "pattern_changed" in [a["kind"] for a in eng.store.audit_log()]


def test_publishing_needs_the_configure_right(engine_factory):
    d = make_directory()
    d.rules.append(AuthorityRule(role_id="ops_head", action="__configure__"))
    eng = engine_factory(directory=d, guardrails=Guardrails())
    cv, _ = eng.save_config("registry", edit_pattern(registry_doc(eng), "site_down", sla_minutes=7), "ravi")
    with pytest.raises(AuthorizationError):
        eng.publish_config(cv.id, actor="ravi")
    assert eng.publish_config(cv.id, actor="hari").status == "published"


def test_people_configuration_checks_against_the_registry(engine_factory):
    d = make_directory()
    d.rules.append(AuthorityRule(role_id="ops_head", action="__configure__"))
    eng = engine_factory(directory=d, guardrails=Guardrails())
    doc = yaml.safe_load(eng.config_text("people"))
    assert {"ops_head", "lead", "ops"} <= set(doc["roles"]) and any(p["id"] == "asha" for p in doc["people"])
    broken = dict(doc, roles={k: v for k, v in doc["roles"].items() if k != "supervisor"})
    _, problems = eng.check_config("people", dump_yaml(broken))
    assert any("supervisor" in m for m in errors(problems))
    nobody = dict(doc, assignments=[a for a in doc["assignments"] if a["role_id"] != "lead"])
    _, problems = eng.check_config("people", dump_yaml(nobody))
    assert errors(problems) == [] and any("role 'lead' has no people of its own; only ['ops_head']" in w
                                          for w in warnings(problems))
    added = dict(doc, people=[*doc["people"], {"id": "priya", "name": "Priya", "edges": ["teams"]}],
                 assignments=[*doc["assignments"], {"person_id": "priya", "role_id": "lead"}])
    cv, problems = eng.save_config("people", dump_yaml(added), "hari")
    assert errors(problems) == []
    eng.publish_config(cv.id, actor="hari")
    assert "priya" in eng.directory.people and eng.directory.roles_of("priya") == {"lead"}


def test_models_configuration(engine_factory, monkeypatch):
    eng = engine_factory()
    good = """models:
  local: {provider: ollama, model: "qwen2.5:7b-instruct", base_url: "http://127.0.0.1:9", api_key_env: SENTINEL_SECRET_GW_KEY}
  lex: {provider: hashing, dim: 64}
routes: {triage: {model: local}}
default: local
embedder: lex
"""
    _, problems = eng.check_config("models", good)
    assert errors(problems) == [] and any("SENTINEL_SECRET_GW_KEY is not set" in w for w in warnings(problems))
    _, problems = eng.check_config("models", good.replace("default: local", "default: nowhere"))
    assert any("unknown model 'nowhere'" in m for m in errors(problems))
    cv, _ = eng.save_config("models", good, "m")
    with pytest.raises(ConfigError, match="SENTINEL_SECRET_GW_KEY"):            # cannot be applied without the key
        eng.publish_config(cv.id, actor="m")
    monkeypatch.setenv("SENTINEL_SECRET_GW_KEY", "k")
    eng.publish_config(cv.id, actor="m")
    assert eng.router is not None and eng.embedder.model == "hashing-64" and eng.llm is not None
    assert yaml.safe_load(eng.config_text("models"))["embedder"] == "lex"


def test_model_task_without_a_route_is_an_error(engine_factory):
    eng = engine_factory()
    doc = registry_doc(eng)
    eng.publish_config(eng.save_config("registry", edit_pattern(doc, "item_stuck_long", model_task="triage"),
                                       "m")[0].id, actor="m")
    _, problems = eng.check_config("models", "models: {a: {provider: hashing}}\nembedder: a\nroutes: {}\n")
    assert errors(problems)


def test_broken_stored_configuration_never_stops_a_process(engine_factory, clock):
    eng = engine_factory()
    cv, _ = eng.save_config("registry", "patterns: []\n", "m")
    eng.publish_config(cv.id, actor="m")                       # valid but empty (a warning only)
    cv2, _ = eng.save_config("registry", eng.config_text("registry"), "m")
    cv2.text, cv2.status = "patterns: [{id: x}]", "published"    # simulate corruption in the store
    eng.store.put_config_version(cv2)
    fresh = Engine(make_overlay(eng.overlay.services["backend"]), store=eng.store, clock=clock)
    assert fresh.registry.all() is not None
    assert "config_apply_failed" in [a["kind"] for a in eng.store.audit_log()]


def test_workers_pick_up_published_configuration(engine_factory, clock):
    eng = engine_factory()
    w_engine = Engine(make_overlay(eng.overlay.services["backend"]), store=eng.store, clock=clock,
                      async_mode=True)
    worker = Worker(w_engine, config_every_s=0)
    text = edit_pattern(registry_doc(eng), "item_stuck_long", route="hitl", max_route="hitl")
    eng.publish_config(eng.save_config("registry", text, "m")[0].id, actor="m")
    worker.run_once()
    assert w_engine.registry.get("item_stuck_long").route is Route.HITL
    w_engine.ingest(stuck_event(ref="Z1"))
    worker.run_once()
    assert len(w_engine.store.open_reviews()) == 1


def test_fingerprint_rule_change_resets_trust_and_upgrade_does_not(engine_factory):
    """D2: the facts a pattern matches and groups on are part of what it means."""
    eng = engine_factory()
    for i in range(3):
        eng.ingest(job_event(ref=f"J{i}", key=f"k{i}"))
    p = eng.registry.get("job_timeout")
    st = eng.pattern_state(p)
    assert st.streak == 3 and st.definition_hash == p.definition_hash(eng._fingerprint_hash(p))
    st.definition_hash = p.definition_hash()                  # as an older version stored it
    eng.store.put_pattern_state(st)
    assert eng.pattern_state(p).streak == 3                    # adopted on upgrade, not reset
    doc = registry_doc(eng)
    for r in doc["fingerprints"]:
        if r["event_type"] == "job.failed":
            r["fields"]["error"] = "detail.code"                 # the same fact now read from somewhere else
    eng.publish_config(eng.save_config("registry", dump_yaml(doc), "m")[0].id, actor="m")
    assert eng.pattern_state(eng.registry.get("job_timeout")).streak == 0
    assert "pattern_changed" in [a["kind"] for a in eng.store.audit_log()]


def test_match_uses_the_condition_language(engine_factory):
    from sentinel import Pattern
    from sentinel.expr import match_facts
    p = Pattern(id="big", event_types=["e"], match={"amount": {"gt": 5000}, "channel": ["web", "app"],
                                                     "region": "*", "not": {"tier": "gold"}})
    assert p.matches("e", {"amount": 9000, "channel": "web", "region": None, "tier": "std"})
    assert not p.matches("e", {"amount": 10, "channel": "web", "region": "N", "tier": "std"})
    assert not p.matches("e", {"amount": 9000, "channel": "pos", "region": "N", "tier": "std"})
    assert not p.matches("e", {"amount": 9000, "channel": "web", "tier": "std"})          # region not a fact
    assert not p.matches("e", {"amount": 9000, "channel": "web", "region": "N", "tier": "gold"})
    assert match_facts({"any": [{"a": "*"}, {"b": [1, 2]}]}, {"b": 2})
    eng = engine_factory()
    doc = registry_doc(eng)
    probs = eng.check_config("registry", edit_pattern(doc, "job_timeout", match={"error": {"gt": 1, "zz": 2}}))[1]
    assert any("match:" in m and "unknown operators" in m for m in errors(probs))
