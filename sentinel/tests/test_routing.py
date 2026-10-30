# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""PII masking, model routing, metering and shadow comparison of candidate models."""
from __future__ import annotations

import json

import pytest

from sentinel import ModelRouter, PIIMasker, ScriptedLLM, Vault
from tests.conftest import stuck_event

# ------------------------------------------------------------------ masker

def test_masks_common_indian_pii_and_round_trips():
    m, v = PIIMasker(), Vault()
    text = ("Call +91 98765 43210 or 9123456780, mail asha.k@example.in, PAN ABCDE1234F, "
            "Aadhaar 2345 6789 0123, card 4111 1111 1111 1111, order SH-1001 qty 12")
    out = m.mask_text(text, v)
    for secret in ("98765 43210", "9123456780", "asha.k@example.in", "ABCDE1234F", "2345 6789 0123",
                   "4111 1111 1111 1111"):
        assert secret not in out
    assert "SH-1001" in out and "qty 12" in out
    assert PIIMasker.unmask(out, v) == text


def test_non_luhn_long_numbers_are_not_cards():
    m, v = PIIMasker(), Vault()
    assert m.mask_text("tracking 1234567890123", v) == "tracking 1234567890123"


def test_key_based_masking_is_stable_and_nested():
    m, v = PIIMasker().with_keys("consignee"), Vault()
    data = {"customer": "Asha K", "lines": [{"consignee": "Ravi"}], "nested": {"customer": "Asha K"}, "qty": 2}
    out = m.mask(data, v)
    assert out["customer"] == out["nested"]["customer"] != "Asha K"          # same value -> same token
    assert out["lines"][0]["consignee"].startswith("[PII_") and out["qty"] == 2
    assert PIIMasker.unmask(out, v) == data

# ------------------------------------------------------------------ in the agent loop

def _final(params, conf=0.95):
    return json.dumps({"final": {"action": "hold", "params": params, "disposition_code": "resolved",
                                 "confidence": conf, "rationale": "r"}})


def test_model_never_sees_raw_pii_but_actions_get_real_values(engine_factory, overlay, backend):
    overlay.tools.register(__import__("sentinel").Tool(
        "customer_contact", "contact for an item", {"ref": "str"},
        lambda args, services: {"phone": "9876543210", "email": "buyer@shop.in"}))
    seen: list[str] = []

    def fn(system, messages):
        seen.extend(m["content"] for m in messages)
        if len(messages) == 1:
            return json.dumps({"tool": "customer_contact", "args": {"ref": "I1"}})
        brief = json.loads(messages[0]["content"])
        token = brief["event"]["payload"]["customer"]
        return _final({"ref": "I1", "reason": f"hold for {token}"})
    eng = engine_factory(llm=ScriptedLLM(fn=fn))
    ev = stuck_event()
    ev = ev.model_copy(update={"payload": {**ev.payload, "customer": "Asha Krishnan",
                                            "note": "call 98450 12345"}})
    eng.ingest(ev)
    blob = "\n".join(seen)
    for secret in ("Asha Krishnan", "98450 12345", "9876543210", "buyer@shop.in"):
        assert secret not in blob
    assert backend.calls == [("hold", {"ref": "I1", "reason": "hold for Asha Krishnan"})]


def test_masking_can_be_switched_off(engine_factory, backend):
    seen = []
    eng = engine_factory(llm=ScriptedLLM(fn=lambda s, m: (seen.append(m[0]["content"]),
                                                           _final({"ref": "I1"}))[1]), masker=None)
    ev = stuck_event()
    eng.ingest(ev.model_copy(update={"payload": {**ev.payload, "customer": "Asha"}}))
    assert "Asha" in seen[0]

# ------------------------------------------------------------------ router

def test_router_routes_meters_and_prices():
    primary = ScriptedLLM(["x" * 4000])
    primary.model = "claude-big"
    small = ScriptedLLM(["ok"])
    small.model = "slm-small"
    r = ModelRouter(routes={"classify": small}, default=primary, prices={"claude-big": (3.0, 15.0)})
    assert r.client("diagnose").complete("s" * 3999, [{"role": "user", "content": "u"}]) == "x" * 4000
    assert r.client("classify").complete("s", []) == "ok"
    with pytest.raises(LookupError):
        ModelRouter().client("diagnose")
    summary = r.summary()
    big = summary["diagnose:claude-big"]
    assert big["calls"] == 1 and big["est_cost"] == pytest.approx(3.0 + 15.0)
    assert summary["classify:slm-small"]["est_cost"] == 0.0


def test_router_records_errors():
    bad = ScriptedLLM([RuntimeError("503")])
    r = ModelRouter(default=bad)
    with pytest.raises(RuntimeError):
        r.client("diagnose").complete("s", [])
    assert r.summary()["diagnose:ScriptedLLM"]["errors"] == 1


def test_candidate_model_runs_in_shadow_and_is_scored(engine_factory, backend):
    primary = ScriptedLLM(fn=lambda s, m: _final({"ref": json.loads(m[0]["content"])["incident"]["facts"]["ref"]}))
    primary.model = "claude"
    answers = iter([True, False])

    def cand_fn(s, m):
        ref = json.loads(m[0]["content"])["incident"]["facts"]["ref"]
        return _final({"ref": ref} if next(answers) else {"ref": "WRONG"})
    candidate = ScriptedLLM(fn=cand_fn)
    candidate.model = "slm"
    eng = engine_factory(llm=ModelRouter(default=primary, candidates={"diagnose": candidate}))
    eng.ingest(stuck_event(ref="I1"))
    eng.ingest(stuck_event(ref="I2"))
    assert backend.calls == [("hold", {"ref": "I1"}), ("hold", {"ref": "I2"})]   # only the primary acts
    shadows = [a["data"] for a in eng.store.audit_log() if a["kind"] == "model_shadow"]
    assert [s["agreed"] for s in shadows] == [True, False] and shadows[0]["model"] == "slm"
    models = eng.report()["models"]
    assert models["diagnose:slm (shadow)"]["agreement"] == 0.5
    assert models["diagnose:claude"]["calls"] == 2
