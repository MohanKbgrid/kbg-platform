# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""Model evaluation: replay known-good past cases, compare with people and the primary model, verdicts."""
from __future__ import annotations

import json

import pytest

from sentinel import Decision, DecisionKind, ModelRouter, ScriptedLLM, SQLiteStore
from sentinel.cli import main
from sentinel.similarity import HashingEmbedder
from tests.conftest import job_event
from tests.fake_model_server import FakeModelServer


def _decide_like_people(brief):
    err = brief["incident"]["facts"]["error"]
    ref = brief["event"]["payload"]["ref"]
    action = "cancel" if err.startswith("E-CANCEL") else "retry"
    return {"action": action, "params": {"ref": ref}, "disposition_code": "resolved", "confidence": 0.9,
            "rationale": "as people do"}


def good_model(seen=None):
    def fn(system, messages):
        brief = json.loads(messages[0]["content"])
        if seen is not None:
            seen.append(brief)
        return json.dumps({"final": _decide_like_people(brief)})
    m = ScriptedLLM(fn=fn)
    m.model = "good-slm"
    return m


def bad_model():
    def fn(system, messages):
        brief = json.loads(messages[0]["content"])
        return json.dumps({"final": {"action": "notify", "params": {"ref": brief["event"]["payload"]["ref"],
                                                                    "msg": "fyi"},
                                     "disposition_code": "resolved", "confidence": 0.9, "rationale": "r"}})
    m = ScriptedLLM(fn=fn)
    m.model = "bad-slm"
    return m


def history(eng, n=24, reverse_first=True):
    """n person-decided cases: E-RETRY* retried, E-CANCEL* cancelled."""
    for i in range(n):
        eng.clock.advance(minutes=10)
        err = ("E-CANCEL" if i % 3 == 0 else "E-RETRY") + str(i)
        r = eng.ingest(job_event(error=err, ref=f"J{i}", key=f"k{i}"))
        rv = eng.store.open_review_for(r.incident_id)
        action = "cancel" if err.startswith("E-CANCEL") else "retry"
        eng.decide(rv.id, Decision(kind=DecisionKind.MODIFY, actor="priya", action=action, params={"ref": f"J{i}"}))
    if reverse_first:
        first = [d for d in eng.store.dispositions("job_failed_other")][0]
        eng.reverse(first.incident_id, actor="lead", note="should not have")


def test_good_model_is_ready_bad_model_is_not(engine_factory):
    eng = engine_factory(llm=ModelRouter(default=good_model()))      # the primary proposes on every review
    history(eng)
    good = eng.evaluate(good_model(), min_cases=20)
    s = good.by_pattern["job_failed_other"]
    assert s["cases"] == 23                                            # reversed case excluded
    assert s["exact"] == 1.0 and s["verdict"] == "ready" and good.ready_patterns() == ["job_failed_other"]
    assert s["agrees_with_primary"] == 1.0 and s["compared_with_primary"] == 23
    bad = eng.evaluate(bad_model(), min_cases=20)
    b = bad.by_pattern["job_failed_other"]
    assert b["exact"] == 0.0 and b["code"] == 1.0 and b["verdict"] == "not yet"
    assert "exact agreement 0.00 below 0.90" in b["reasons"]
    audits = [a["data"] for a in eng.store.audit_log() if a["kind"] == "model_evaluation"]
    assert [a["model"] for a in audits] == ["good-slm", "bad-slm"]
    runs = [r for r in eng.store.model_runs() if r["task"] == "eval"]
    assert len(runs) == 46 and all(r["shadow"] for r in runs)        # metered, marked as shadow


def test_too_few_cases_and_errors_block_readiness(engine_factory):
    eng = engine_factory()
    history(eng, n=6, reverse_first=False)
    rep = eng.evaluate(good_model(), min_cases=20)
    assert rep.by_pattern["job_failed_other"]["reasons"] == ["only 6 cases (need 20)"]
    flaky = ScriptedLLM(fn=lambda s, m: (_ for _ in ()).throw(RuntimeError("503")))
    flaky.model = "flaky"
    rep = eng.evaluate(flaky, min_cases=1)
    s = rep.by_pattern["job_failed_other"]
    assert s["errors"] == 6 and s["verdict"] == "not yet" and any("error rate" in r for r in s["reasons"])


def test_replay_sees_only_the_past(engine_factory):
    eng = engine_factory(embedder=HashingEmbedder(128))
    history(eng, n=8, reverse_first=False)
    seen = []
    eng.evaluate(good_model(seen), min_cases=1)
    by_ref = {b["event"]["payload"]["ref"]: b for b in seen}
    oldest = by_ref["J0"]
    assert oldest["how_humans_resolved_this_before"] == [] and "similar_past_cases" not in oldest
    newest = by_ref["J7"]
    assert len(newest["how_humans_resolved_this_before"]) == 5            # history_limit
    refs = {s["steps"][0]["params"]["ref"] for s in newest["similar_past_cases"]}
    assert "J7" not in refs and refs <= {f"J{i}" for i in range(7)}


def test_filters_and_validation(engine_factory):
    eng = engine_factory()
    history(eng, n=4, reverse_first=False)
    assert eng.evaluate(good_model(), patterns=["job_timeout"], min_cases=1).overall["cases"] == 0
    assert eng.evaluate(good_model(), limit=2, min_cases=1).overall["cases"] == 2
    assert eng.evaluate(good_model(), threads=3, min_cases=1).overall["exact"] == 1.0
    with pytest.raises(ValueError):
        eng.evaluate(good_model(), patterns=["nope"])
    with pytest.raises(ValueError):
        eng.evaluate(good_model(), limit=0)


def test_cli_evaluate_and_backfill_with_a_real_http_model(engine_factory, tmp_path, capsys, monkeypatch):
    srv = FakeModelServer(reply=lambda body: json.dumps({"final": _decide_like_people(
        json.loads(body["messages"][1]["content"]))}))
    try:
        db = str(tmp_path / "s.db")
        eng = engine_factory(store=SQLiteStore(db))
        history(eng, n=5, reverse_first=False)
        eng.store.close()
        models = tmp_path / "models.yaml"
        models.write_text(f"""models:
  local: {{provider: ollama, model: "qwen2.5:7b-instruct", base_url: "{srv.url}", trust_env: false}}
  lex: {{provider: hashing, dim: 64}}
default: local
embedder: lex
""")
        monkeypatch.setenv("SENTINEL_OVERLAY", "tests.toy_overlay:build_overlay")
        base = ["--db", db, "--models", str(models)]
        assert main([*base, "embed-backfill"]) == 0
        assert json.loads(capsys.readouterr().out) == {"embedded": 5}
        assert main([*base, "evaluate", "--candidate", "local", "--min-cases", "3"]) == 0
        out = capsys.readouterr().out
        assert "model qwen2.5:7b-instruct: 5 cases, exact 1.0, ready for: job_failed_other" in out
        assert main([*base, "evaluate", "--candidate", "nope"]) == 2
        assert main([*base, "evaluate", "--candidate", "local", "--json"]) == 0
        rep = json.loads(capsys.readouterr().out)
        assert len(rep["cases"]) == 5 and rep["by_pattern"]["job_failed_other"]["verdict"] == "not yet"
    finally:
        srv.close()


def test_evaluations_show_in_analytics(engine_factory, tmp_path):
    pytest.importorskip("duckdb")
    from sentinel.analytics import Analytics
    db = str(tmp_path / "e.db")
    eng = engine_factory(store=SQLiteStore(db))
    history(eng, n=4, reverse_first=False)
    eng.evaluate(good_model(), min_cases=2)
    eng.evaluate(bad_model(), min_cases=2)
    eng.store.close()
    with Analytics(sqlite=db) as an:
        rows = an.evaluations()
    assert [(r["model"], r["exact"], r["ready_for"]) for r in rows] == [("bad-slm", 0.0, ""),
                                                                         ("good-slm", 1.0, "job_failed_other")]
