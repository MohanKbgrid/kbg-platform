# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""Access from the console: stored tokens (give, use, expire, revoke) and single sign-on with OpenID Connect."""
from __future__ import annotations

import urllib.parse
import urllib.request

import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from sentinel.api import Principal, create_app, token_hash  # noqa: E402
from sentinel.rbac import AuthorityRule  # noqa: E402
from sentinel.sso import SSOConfig  # noqa: E402
from tests.fake_oidc import FakeOIDC  # noqa: E402
from tests.test_rbac import make_directory  # noqa: E402

REDIRECT = "http://localhost/console/sso/callback"


@pytest.fixture
def eng(engine_factory):
    d = make_directory()
    d.rules.append(AuthorityRule(role_id="ops_head", action="__access__"))
    d.people["hari"].contact["email"] = "Hari@ACME.in"
    return engine_factory(directory=d)


@pytest.fixture
def idp():
    p = FakeOIDC()
    yield p
    p.close()


def client(eng, sso=None):
    return TestClient(create_app(eng, {token_hash("hari-token"): Principal("person", "hari"),
                                       token_hash("ravi-token"): Principal("person", "ravi")},
                                 config_sync_s=0, sso=sso))


def auth(t):
    return {"Authorization": f"Bearer {t}"}


def test_give_use_and_revoke_a_token(eng, clock):
    c = client(eng)
    r = c.post("/console/api/access/tokens", json={"kind": "service", "principal": "shopify-hooks",
                                                   "label": "webhooks", "days": 30}, headers=auth("hari-token"))
    assert r.status_code == 200, r.text
    raw, tid = r.json()["token"], r.json()["id"]
    assert raw.startswith("stk_") and "hash" not in r.json()
    assert c.post("/v1/events", json={"type": "job.failed", "source": "x", "payload": {"system": "s",
                                      "error_code": "E1", "ref": "R"}}, headers=auth(raw)).status_code in (200, 202)
    listed = c.get("/console/api/access/tokens", headers=auth("hari-token")).json()
    assert [t["principal"] for t in listed] == ["shopify-hooks"] and listed[0]["last_used_at"]
    assert all(raw not in str(v) for t in listed for v in t.values())
    assert c.post(f"/console/api/access/tokens/{tid}/revoke", json={}, headers=auth("hari-token")).json()["status"] == "revoked"
    assert c.post("/v1/events", json={"type": "job.failed", "source": "x", "payload": {}},
                  headers=auth(raw)).status_code == 401
    kinds = [a["kind"] for a in eng.store.recent_audit(10)]
    assert "token_issued" in kinds and "token_revoked" in kinds


def test_tokens_expire(eng, clock):
    c = client(eng)
    raw = c.post("/console/api/access/tokens", json={"kind": "person", "principal": "ravi", "days": 1},
                 headers=auth("hari-token")).json()["token"]
    assert c.get("/console/api/me", headers=auth(raw)).json()["id"] == "ravi"
    clock.advance(hours=25)
    assert c.get("/console/api/me", headers=auth(raw)).status_code == 401


def test_access_needs_the_right(eng):
    c = client(eng)
    assert c.get("/console/api/access/tokens", headers=auth("ravi-token")).status_code == 403
    assert c.post("/console/api/access/tokens", json={"kind": "person", "principal": "ravi"},
                  headers=auth("ravi-token")).status_code == 403
    assert c.post("/console/api/access/tokens", json={"kind": "person", "principal": "stranger"},
                  headers=auth("hari-token")).status_code == 422
    assert c.get("/console/api/me", headers=auth("hari-token")).json()["can"]["__access__"] is True


def sso_cfg(idp, **kw):
    return SSOConfig(issuer=idp.issuer,
                     client_id="sentinel-console", client_secret_env="TEST_OIDC_SECRET", redirect_url=REDIRECT, **kw)


def sign_in(c, follow_state=None):
    r = c.get("/console/sso/login", follow_redirects=False)
    assert r.status_code == 302, r.text
    auth_url = r.headers["location"]
    q = dict(urllib.parse.parse_qsl(urllib.parse.urlparse(auth_url).query))
    assert q["code_challenge_method"] == "S256" and q["redirect_uri"] == REDIRECT and "openid" in q["scope"]

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **k):
            return None
    try:
        urllib.request.build_opener(NoRedirect).open(auth_url)
        raise AssertionError("expected a redirect")
    except urllib.error.HTTPError as e:
        back = e.headers["Location"]
    bq = dict(urllib.parse.parse_qsl(urllib.parse.urlparse(back).query))
    if follow_state is not None:
        bq["state"] = follow_state
    return c.get("/console/sso/callback", params=bq, follow_redirects=False)


@pytest.fixture(autouse=True)
def _secret(monkeypatch):
    monkeypatch.setenv("TEST_OIDC_SECRET", "s3cret")


def test_single_sign_on(eng, idp):
    c = client(eng, sso_cfg(idp))
    assert c.get("/console/sso/info").json()["enabled"] is True
    r = sign_in(c)
    assert r.status_code == 302 and r.headers["location"].startswith("/console#sso=")
    raw = r.headers["location"].split("#sso=", 1)[1]
    assert c.get("/console/api/me", headers=auth(raw)).json()["id"] == "hari"     # matched on email, any case
    assert idp.token_requests[-1]["client_secret"] == "s3cret"
    assert c.post("/console/api/logout", headers=auth(raw)).json() == {"ended": True}
    assert c.get("/console/api/me", headers=auth(raw)).status_code == 401
    assert c.post("/console/api/logout", headers=auth("hari-token")).json() == {"ended": False}


def test_a_different_account_with_the_same_email_cannot_take_over(eng, idp):
    c = client(eng, sso_cfg(idp))
    assert sign_in(c).status_code == 302                                       # binds hari to u-hari
    idp.user = {"sub": "u-attacker", "email": "hari@acme.in", "email_verified": True}
    r = sign_in(c)
    assert r.status_code == 403 and "different account" in r.text
    assert c.post("/console/api/access/sso-reset/hari", headers=auth("hari-token")).status_code == 200
    assert sign_in(c).status_code == 302                                       # after an admin reset, binds anew


def test_sign_on_refusals(eng, idp):
    c = client(eng, sso_cfg(idp))
    assert sign_in(c, follow_state="forged").status_code == 403
    idp.user = {"sub": "u-x", "email": "someone@else.in", "email_verified": True}
    r = sign_in(c)
    assert r.status_code == 403 and "not set up" in r.text
    idp.user = {"sub": "u-hari", "email": "hari@acme.in", "email_verified": False}
    assert "verified" in sign_in(c).text
    idp.user = {"sub": "u-hari", "email": "hari@acme.in"}                    # no email_verified at all
    assert "verified" in sign_in(c).text
    idp.user = {"sub": "u-hari", "email": "hari@acme.in", "email_verified": True}
    idp.forge = True                                                          # signed with someone else's key
    assert "signature is not valid" in sign_in(c).text
    idp.forge = False
    idp.alg = "HS256"
    assert "only RS256" in sign_in(c).text
    idp.alg = "RS256"
    for bad in ({"aud": "another-app"}, {"nonce": "x"}, {"iss": "https://evil"}, {"exp": 1}):
        idp.tamper = bad
        assert sign_in(c).status_code == 403, bad
    idp.tamper = {}
    eng.directory.people["hari"].active = False
    assert "not active" in sign_in(c).text
    assert any(a["kind"] == "sso_refused" for a in eng.store.recent_audit(50))


def test_sign_on_session_expires(eng, idp, clock):
    c = client(eng, sso_cfg(idp, session_hours=2))
    raw = sign_in(c).headers["location"].split("#sso=", 1)[1]
    assert c.get("/console/api/me", headers=auth(raw)).status_code == 200
    clock.advance(hours=3)
    assert c.get("/console/api/me", headers=auth(raw)).status_code == 401


def test_sso_config_checks():
    with pytest.raises(ValueError, match="https"):
        SSOConfig(issuer="http://idp.example.in", client_id="c", redirect_url=REDIRECT)
    cfg = SSOConfig(issuer="https://idp.example.in", client_id="c", redirect_url=REDIRECT,
                    client_secret_env="NOPE_SECRET_NOT_SET")
    with pytest.raises(Exception, match="NOPE_SECRET_NOT_SET"):
        _ = cfg.secret
