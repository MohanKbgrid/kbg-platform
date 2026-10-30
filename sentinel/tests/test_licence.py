# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""F1: signed licences that degrade to human review and never stop the site."""
from __future__ import annotations

import json

import pytest

pytest.importorskip("cryptography")

from sentinel.licence import LicenceGuard, keygen, issue, load_keys, parse, LicenceError  # noqa: E402
from tests.conftest import job_event  # noqa: E402


@pytest.fixture(scope="module")
def issuer(tmp_path_factory):
    d = tmp_path_factory.mktemp("issuer")
    return keygen(str(d), "kbgrid-2026")


def lic(issuer, **over):
    payload = {"licensee": "Acme Home", "site": "acme-prod", "tier": "growth", "valid_from": "2026-10-01",
               "valid_until": "2027-09-30", "grace_days": 14,
               "limits": {"incidents_per_month": 1000, "automatic_per_month": 2}}
    payload.update(over)
    return issue(issuer["private"], payload, "kbgrid-2026")


def guard(issuer, token, site="acme-prod"):
    return LicenceGuard(token, load_keys(issuer["public"]), site=site, ttl_s=0)


def test_valid_licence_lets_trust_work(engine_factory, issuer, backend):
    eng = engine_factory(licence=guard(issuer, lic(issuer)))
    eng.ingest(job_event(error="TIMEOUT", ref="L1", key="l1"))
    assert backend.calls == [("retry", {"ref": "L1"})]
    st = eng.licence.status(eng)
    assert st["state"] == "ok" and st["licence"]["tier"] == "growth" and st["usage"]["incidents"] == 1
    assert eng.health()["licence"] == "ok"


@pytest.mark.parametrize("case", ["tampered", "other_site", "expired", "no_keys", "garbage"])
def test_bad_licences_degrade_to_people_without_stopping(engine_factory, issuer, backend, case):
    token = lic(issuer)
    keys = load_keys(issuer["public"])
    site = "acme-prod"
    if case == "tampered":
        h, p, s = token.split(".")
        from sentinel.jws import b64url, b64url_decode
        body = json.loads(b64url_decode(p))
        body["limits"]["incidents_per_month"] = 10**9
        token = ".".join([h, b64url(json.dumps(body).encode()), s])
    elif case == "other_site":
        site = "someone-else"
    elif case == "expired":
        token = lic(issuer, valid_from="2025-01-01", valid_until="2026-09-01", grace_days=14)
    elif case == "no_keys":
        keys = []
    else:
        token = "not-a-licence"
    eng = engine_factory(licence=LicenceGuard(token, keys, site=site, ttl_s=0))
    r = eng.ingest(job_event(error="TIMEOUT", ref="D1", key="d1"))
    assert backend.calls == []                                          # nothing acted alone
    assert eng.store.open_review_for(r.incident_id) is not None         # but the case is there for a person
    assert eng.licence.status(eng)["state"] == "degraded"
    assert any(p.startswith("licence:") for p in eng.health()["problems"])
    assert "licence is not valid" in eng.trace(job_event(error="TIMEOUT", ref="D2", system="x"))["route"]["why"]


def test_grace_and_limits(engine_factory, issuer, backend, clock):
    eng = engine_factory(licence=guard(issuer, lic(issuer, valid_until="2026-10-05")))   # expired 5 days ago
    st = eng.licence.status(eng)
    assert st["state"] == "grace" and "days of grace left" in st["reasons"][0].replace("day(s)", "days")
    eng.ingest(job_event(error="TIMEOUT", ref="G1", key="g1"))
    assert backend.calls                                                # grace: still works
    capped = engine_factory(licence=guard(issuer, lic(issuer, hard_cap=True,
                                                      limits={"incidents_per_month": 1})))
    capped.ingest(job_event(error="AUTH", ref="C1", key="c1"))
    capped.ingest(job_event(error="AUTH", ref="C2", system="y", key="c2"))
    assert capped.licence.status(capped)["state"] == "degraded"
    soft = engine_factory(licence=guard(issuer, lic(issuer, limits={"incidents_per_month": 1, "automatic_per_month": 0})))
    soft.ingest(job_event(error="TIMEOUT", ref="S1", key="s1"))
    soft.ingest(job_event(error="TIMEOUT", ref="S2", system="z", key="s2"))
    st = soft.licence.status(soft)
    assert st["state"] == "grace" and any("billed" in r for r in st["reasons"])


def test_parse_rejects_wrong_type_and_cli(issuer, tmp_path, capsys, monkeypatch):
    with pytest.raises(LicenceError):
        parse("a.b.c", load_keys(issuer["public"]))
    from sentinel.cli import main
    payload = tmp_path / "p.json"
    payload.write_text(json.dumps({"licensee": "X", "site": "s1", "valid_from": "2026-01-01",
                                   "valid_until": "2027-01-01"}))
    out = tmp_path / "licence.txt"
    assert main(["licence", "issue", str(payload), "--key", issuer["private"], "--out", str(out)]) == 0
    capsys.readouterr()
    base = ["--overlay", "tests.test_templates_cli:_overlay", "--db", str(tmp_path / "l.db")]
    assert main([*base, "licence", "status"]) == 0
    assert json.loads(capsys.readouterr().out)["state"] == "not enforced"
    monkeypatch.setenv("SENTINEL_LICENCE", str(out))
    monkeypatch.setenv("SENTINEL_LICENCE_KEYS", issuer["public"])
    monkeypatch.setenv("SENTINEL_SITE_ID", "s1")
    assert main([*base, "licence", "status"]) == 0
    assert json.loads(capsys.readouterr().out)["licence"]["licensee"] == "X"
