# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""Similar-case search: embedders, masked case text, vector storage (SQLite, Postgres, pgvector), retrieval."""
from __future__ import annotations

import json
import os
import uuid

import pytest

from sentinel import ModelRouter, PIIMasker, ScriptedLLM, load_models
from sentinel.similarity import HashingEmbedder, case_text, cosine
from tests.conftest import new_store, stuck_event

# ------------------------------------------------------------------ embedder and text


def test_hashing_embedder_is_deterministic_normalised_and_lexical():
    e = HashingEmbedder(128)
    a, b, c = e.embed(["order stuck at WH_CHN shopify", "order stuck at WH_CHN ajio", "payment refund razorpay"])
    assert e.embed(["order stuck at WH_CHN shopify"])[0] == a
    assert abs(sum(x * x for x in a) - 1) < 1e-9 and len(a) == 128
    assert cosine(a, b) > cosine(a, c)
    with pytest.raises(ValueError):
        HashingEmbedder(4)


def test_case_text_is_masked_stable_and_has_no_resolution():
    t1 = case_text("p", "desc", {"site": "S1", "b": 1}, "item.stuck",
                   {"customer": "Asha Krishnan", "phone": "9876543210", "note": "mail a@b.in"}, PIIMasker())
    t2 = case_text("p", "desc", {"b": 1, "site": "S1"}, "item.stuck",
                   {"note": "mail a@b.in", "phone": "9876543210", "customer": "Asha Krishnan"}, PIIMasker())
    assert t1 == t2
    for secret in ("Asha", "9876543210", "a@b.in"):
        assert secret not in t1
    assert "fact.site=S1" in t1 and "resolved" not in t1


# ------------------------------------------------------------------ storage

def _store_cases(st, model="m", tenant="t"):
    st.put_case_vector("i1", "p", tenant, model, [1.0, 0.0, 0.0])
    st.put_case_vector("i2", "p", tenant, model, [0.9, 0.1, 0.0])
    st.put_case_vector("i3", "p", tenant, model, [0.0, 1.0, 0.0])
    st.put_case_vector("i4", "q", tenant, model, [1.0, 0.0, 0.0])          # other pattern
    st.put_case_vector("i5", "p", "other", model, [1.0, 0.0, 0.0])         # other tenant
    st.put_case_vector("i6", "p", tenant, "other-model", [1.0, 0.0, 0.0])  # other model
    st.put_case_vector("i7", "p", tenant, model, [1.0, 0.0])               # other dimension


def _check(st):
    _store_cases(st)
    hits = st.similar_cases("p", "t", "m", [1.0, 0.0, 0.0], k=5)
    assert [h[0] for h in hits] == ["i1", "i2", "i3"]
    assert hits[0][1] == pytest.approx(1.0) and hits[2][1] == pytest.approx(0.0, abs=1e-6)
    assert [h[0] for h in st.similar_cases("p", "t", "m", [1.0, 0.0, 0.0], k=1, exclude="i1")] == ["i2"]
    assert st.has_case_vector("i1", "m") and not st.has_case_vector("i1", "other-model")
    st.put_case_vector("i3", "p", "t", "m", [1.0, 0.0, 0.0])               # replaced
    assert {h[0] for h in st.similar_cases("p", "t", "m", [1.0, 0.0, 0.0], k=2)} <= {"i1", "i3", "i2"}


def test_case_vectors_in_the_test_store():
    _check(new_store())


@pytest.mark.skipif(not os.environ.get("SENTINEL_TEST_PG"), reason="needs SENTINEL_TEST_PG")
def test_postgres_float_array_fallback():
    from sentinel.pg_store import PostgresStore
    st = PostgresStore(os.environ["SENTINEL_TEST_PG"], schema=f"t_{uuid.uuid4().hex[:12]}", use_pgvector=False)
    try:
        assert st.pgvector is False
        _check(st)
    finally:
        st.drop()
        st.close()


@pytest.mark.skipif(not os.environ.get("SENTINEL_TEST_PGVECTOR"), reason="needs SENTINEL_TEST_PGVECTOR")
def test_pgvector_search_matches_exact_cosine():
    from sentinel.pg_store import PostgresStore
    st = PostgresStore(os.environ["SENTINEL_TEST_PGVECTOR"], schema=f"t_{uuid.uuid4().hex[:12]}", use_pgvector=True)
    try:
        assert st.pgvector is True
        _check(st)
        e = HashingEmbedder(64)
        texts = [f"order {i} stuck at {'WH' if i % 2 else 'STORE'}" for i in range(30)]
        for i, v in enumerate(e.embed(texts)):
            st.put_case_vector(f"x{i}", "z", "t", e.model, v)
        q = e.embed(["order 3 stuck at WH"])[0]
        got = st.similar_cases("z", "t", e.model, q, k=5)
        want = sorted(((f"x{i}", cosine(q, v)) for i, v in enumerate(e.embed(texts))), key=lambda t: -t[1])[:5]
        assert got[0][0] == want[0][0] == "x3"                 # exact match first
        assert all(abs(g[1] - w[1]) < 1e-5 for g, w in zip(got, want, strict=True))    # same scores (ties may swap)
        reopened = PostgresStore(os.environ["SENTINEL_TEST_PGVECTOR"], schema=st.schema)
        assert reopened.pgvector is True                  # detected from the existing column
        reopened.close()
    finally:
        st.drop()
        st.close()


# ------------------------------------------------------------------ in the engine

def _hold_llm(seen):
    def fn(system, messages):
        brief = json.loads(messages[0]["content"])
        seen.append(brief)
        ref = brief["incident"]["facts"]["ref"]
        return json.dumps({"final": {"action": "hold", "params": {"ref": ref}, "disposition_code": "resolved",
                                     "confidence": 0.95, "rationale": "r"}})
    return ScriptedLLM(fn=fn)


def test_brief_shows_nearest_past_cases_with_how_they_ended(engine_factory):
    seen = []
    eng = engine_factory(llm=_hold_llm(seen), embedder=HashingEmbedder(256), similar_k=3)
    for i, site in enumerate(["S1", "S2", "S1", "S3", "S2"]):
        eng.ingest(stuck_event(ref=f"I{i}", site=site))
    assert seen[0].get("similar_past_cases") is None                 # nothing closed before the first
    first_s1 = next(i for i in eng.store.incidents() if i.facts.get("ref") == "I0")
    eng.reverse(first_s1.id, actor="lead", note="wrong item")
    seen.clear()
    ev = stuck_event(ref="I9", site="S1")
    ev = ev.model_copy(update={"payload": {**ev.payload, "customer": "Asha Krishnan"}})
    eng.ingest(ev)
    sims = seen[0]["similar_past_cases"]
    assert len(sims) == 3 and sims[0]["similarity"] >= sims[1]["similarity"] >= sims[2]["similarity"]
    assert {s["facts"]["site"] for s in sims[:2]} == {"S1"}             # same site ranks first
    assert any(s["reversed"] for s in sims) and all(s["steps"][0]["action"] == "hold" for s in sims)
    assert "Asha Krishnan" not in json.dumps(seen)
    runs = eng.store.model_runs()
    assert not runs or all(r["task"] == "embed" for r in runs)


def test_async_mode_embeds_in_the_background(engine_factory):
    eng = engine_factory(llm=_hold_llm([]), embedder=HashingEmbedder(64), async_mode=True)
    r = eng.ingest(stuck_event(ref="A1"))
    eng.work("w1", limit=10)                     # resolve -> disposition -> embed job
    eng.work("w1", limit=10)
    assert eng.store.has_case_vector(r.incident_id, "hashing-64")


class _Down:
    model = "embed-down"

    def embed(self, texts):
        raise ConnectionError("mac mini unreachable")


def test_embedder_outage_never_blocks_resolution(engine_factory, backend):
    seen = []
    eng = engine_factory(llm=_hold_llm(seen), embedder=_Down())
    eng.ingest(stuck_event(ref="D1"))
    eng.ingest(stuck_event(ref="D2"))
    assert backend.calls == [("hold", {"ref": "D1"}), ("hold", {"ref": "D2"})]
    assert "similar_past_cases" not in seen[-1] and seen[-1]["how_humans_resolved_this_before"]
    assert 'sentinel_embeddings_total{model="embed-down",ok="false"}' in eng.metrics.render()


def test_backfill_embeds_history_once(engine_factory):
    eng = engine_factory(llm=_hold_llm([]))
    for i in range(4):
        eng.ingest(stuck_event(ref=f"B{i}"))
    eng2 = engine_factory(llm=_hold_llm([]), store=eng.store, embedder=HashingEmbedder(64))
    assert eng2.backfill_embeddings(batch=3) == 4
    assert eng2.backfill_embeddings() == 0


def test_router_embedder_is_used_and_metered(engine_factory):
    seen = []
    router = ModelRouter(default=_hold_llm(seen), embedder=HashingEmbedder(64))
    eng = engine_factory(llm=router)
    eng.ingest(stuck_event(ref="R1"))
    eng.ingest(stuck_event(ref="R2"))
    assert seen[-1]["similar_past_cases"][0]["facts"]["ref"] == "R1"
    assert "embed" in {r["task"] for r in eng.store.model_runs()}


def test_models_file_embedder():
    r = load_models({"models": {"lex": {"provider": "hashing", "dim": 128},
                                "c": {"provider": "anthropic", "model": "claude-x"}},
                     "default": "c", "embedder": "lex"},
                    factory=lambda spec: HashingEmbedder(spec.get("dim", 64)) if spec["provider"] == "hashing"
                    else type("C", (), {"model": spec["model"], "complete": lambda *a: "{}"})())
    assert r.embedder.model == "hashing-128" and r.named["lex"] is r.embedder
    with pytest.raises(ValueError, match="cannot make embeddings"):
        load_models({"models": {"c": {"provider": "anthropic", "model": "x"}}, "default": "c", "embedder": "c"},
                    factory=lambda spec: type("C", (), {"model": "x", "complete": lambda *a: "{}"})())
    with pytest.raises(ValueError, match="cannot answer prompts"):
        load_models({"models": {"lex": {"provider": "hashing"}}, "default": "lex"})


def test_review_cards_carry_how_similar_cases_ended(engine_factory, overlay):
    from sentinel import Decision, DecisionKind, MemoryEdge
    from tests.conftest import job_event
    edge = MemoryEdge("ask_ai")
    overlay.edges["ask_ai"] = edge
    overlay.default_edges = ["ask_ai"]
    eng = engine_factory(ov=overlay, embedder=HashingEmbedder(128))
    for i in range(3):
        r = eng.ingest(job_event(error="AUTH", system="billing", ref=f"J{i}", key=f"j{i}"))
        rv = eng.store.open_review_for(r.incident_id)
        eng.decide(rv.id, Decision(kind=DecisionKind.MODIFY, actor="p", action="retry", params={"ref": f"J{i}"}))
    eng.work("w")
    edge.cards.clear()
    eng.ingest(job_event(error="AUTH", system="billing", ref="J9", key="j9"))
    eng.work("w")
    card = edge.cards[-1]
    assert len(card.similar_cases) == 3 and all(s["actions"] == ["retry"] for s in card.similar_cases)
    listed = eng.build_card(eng.store.open_review_for(card.incident_id))
    assert listed.similar_cases == []                 # listing cards never calls the embedder


@pytest.mark.skipif(not os.environ.get("SENTINEL_TEST_PGVECTOR"), reason="needs SENTINEL_TEST_PGVECTOR")
def test_hnsw_index_gives_the_same_neighbours():
    from sentinel.pg_store import PostgresStore
    st = PostgresStore(os.environ["SENTINEL_TEST_PGVECTOR"], schema=f"t_{uuid.uuid4().hex[:12]}", use_pgvector=True)
    try:
        e = HashingEmbedder(64)
        texts = [f"order {i} stuck at {'WH' if i % 3 else 'STORE'} line {i % 7}" for i in range(300)]
        for i, v in enumerate(e.embed(texts)):
            st.put_case_vector(f"x{i}", "z" if i % 2 else "y", "t", e.model, v)
        q = e.embed(["order 33 stuck at STORE line 5"])[0]
        exact = st.similar_cases("z", "t", e.model, q, k=5)
        assert st.vector_indexes() == set()
        assert st.ensure_vector_index(64) == "ix_cvec_hnsw_64"
        assert st.vector_indexes() == {64}
        plan = st._x("EXPLAIN SELECT incident_id FROM {s}.case_vectors WHERE dim = 64 "
                     "ORDER BY (vec::vector(64)) <=> %s::vector(64) LIMIT 5",
                     (str(q).replace(" ", ""),)).fetchall()
        assert "ix_cvec_hnsw_64" in " ".join(str(r) for r in plan)
        approx = st.similar_cases("z", "t", e.model, q, k=5)
        assert len(approx) == 5 and approx[0][0] == exact[0][0]             # filtered to pattern z, still k rows
        assert all(int(i[1:]) % 2 for i, _ in approx)
        assert len({i for i, _ in approx} & {i for i, _ in exact}) >= 4      # approximate, but close
    finally:
        st.drop()
        st.close()
