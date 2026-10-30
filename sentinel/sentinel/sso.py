# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""Single sign-on for the console with OpenID Connect (Keycloak, Authentik, Zitadel, Microsoft Entra ID,
Google Workspace, Okta ...). Standard library only.

In the tokens file::

    sso:
      issuer: "https://login.example.in/realms/acme"
      client_id: sentinel-console
      client_secret_env: SENTINEL_OIDC_SECRET       # confidential client; omit for a public client
      redirect_url: "https://sentinel.example.in/console/sso/callback"
      claim: email                                  # matched to a person's contact.email, else to their id
      session_hours: 10

The flow is the authorization-code flow with PKCE. The state, nonce and PKCE verifier travel in a short-lived
HttpOnly cookie, so any API replica can finish a sign-in another started. The ID token's RS256 signature is
checked against the provider's published keys (JWKS), as are its issuer, audience, expiry and nonce; every
provider endpoint must be https. Only people in the people configuration may sign in, and only while active.
A person is matched on the configured claim (verified email by default) the first time, and from then on
the provider's stable user id (``sub``) must stay the same, so an account that later shows the same email
cannot take over. A sign-in issues a console session token (stored hashed, revocable, it expires).
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from pydantic import BaseModel, Field


class SSOError(RuntimeError):
    pass


class SSOConfig(BaseModel):
    issuer: str
    client_id: str
    client_secret_env: str | None = None
    redirect_url: str
    scopes: list[str] = Field(default_factory=lambda: ["openid", "email", "profile"])
    claim: str = "email"
    session_hours: float = Field(default=10, gt=0, le=24 * 30)
    button: str = "Sign in with your company account"
    timeout_s: float = 10.0
    require_verified_email: bool = True       # with claim "email": the provider must say it is verified

    def model_post_init(self, _ctx: Any) -> None:
        for name in ("issuer", "redirect_url"):
            v = getattr(self, name)
            if not v.startswith(("https://", "http://localhost", "http://127.0.0.1")):
                raise ValueError(f"sso.{name} must be https (http only for localhost)")

    @property
    def secret(self) -> str | None:
        if not self.client_secret_env:
            return None
        v = os.environ.get(self.client_secret_env)
        if not v:
            raise SSOError(f"environment variable {self.client_secret_env} is not set")
        return v


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


class OIDC:
    COOKIE = "sentinel_sso"
    DISCOVERY_TTL_S = 3600

    def __init__(self, cfg: SSOConfig) -> None:
        self.cfg = cfg
        self._disc: tuple[float, dict[str, Any]] | None = None
        self._jwks: tuple[float, list[dict[str, Any]]] | None = None
        self._lock = threading.Lock()

    # ---- http ----------------------------------------------------------------------------------------
    def _get_json(self, url: str) -> dict[str, Any]:
        req = urllib.request.Request(url, headers={"Accept": "application/json"})  # noqa: S310
        try:
            with urllib.request.urlopen(req, timeout=self.cfg.timeout_s) as r:  # noqa: S310 - https checked
                return json.loads(r.read())
        except (urllib.error.URLError, OSError, ValueError) as e:
            raise SSOError(f"identity provider unreachable: {getattr(e, 'reason', e)}") from None

    def discovery(self) -> dict[str, Any]:
        with self._lock:
            if self._disc and time.monotonic() - self._disc[0] < self.DISCOVERY_TTL_S:
                return self._disc[1]
        d = self._get_json(self.cfg.issuer.rstrip("/") + "/.well-known/openid-configuration")
        if d.get("issuer", "").rstrip("/") != self.cfg.issuer.rstrip("/"):
            raise SSOError(f"identity provider says its issuer is {d.get('issuer')!r}, not {self.cfg.issuer!r}")
        for k in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
            if not d.get(k):
                raise SSOError(f"identity provider has no {k}")
            if not str(d[k]).startswith(("https://", "http://localhost", "http://127.0.0.1")):
                raise SSOError(f"identity provider's {k} is not https")
        with self._lock:
            self._disc = (time.monotonic(), d)
        return d

    # ---- flow ------------------------------------------------------------------------------------------
    def start(self) -> tuple[str, str]:
        """(URL to send the browser to, value for the HttpOnly cookie)."""
        d = self.discovery()
        state, nonce, verifier = secrets.token_urlsafe(24), secrets.token_urlsafe(24), secrets.token_urlsafe(48)
        challenge = _b64url(hashlib.sha256(verifier.encode()).digest())
        q = {"response_type": "code", "client_id": self.cfg.client_id, "redirect_uri": self.cfg.redirect_url,
             "scope": " ".join(self.cfg.scopes), "state": state, "nonce": nonce,
             "code_challenge": challenge, "code_challenge_method": "S256"}
        sep = "&" if "?" in d["authorization_endpoint"] else "?"
        cookie = _b64url(json.dumps({"s": state, "n": nonce, "v": verifier, "t": int(time.time())}).encode())
        return d["authorization_endpoint"] + sep + urllib.parse.urlencode(q), cookie

    def finish(self, code: str, state: str, cookie: str | None) -> dict[str, Any]:
        """Exchange the code and return the checked ID token claims."""
        if not cookie:
            raise SSOError("sign-in expired or started in another browser; try again")
        try:
            pending = json.loads(_b64url_decode(cookie))
        except ValueError:
            raise SSOError("sign-in state is unreadable; try again") from None
        if not secrets.compare_digest(str(pending.get("s", "")), state or ""):
            raise SSOError("sign-in state does not match; try again")
        if time.time() - float(pending.get("t", 0)) > 600:
            raise SSOError("sign-in took too long; try again")
        d = self.discovery()
        form = {"grant_type": "authorization_code", "code": code, "redirect_uri": self.cfg.redirect_url,
                "client_id": self.cfg.client_id, "code_verifier": pending["v"]}
        secret = self.cfg.secret
        if secret:
            form["client_secret"] = secret
        req = urllib.request.Request(d["token_endpoint"], data=urllib.parse.urlencode(form).encode(),  # noqa: S310
                                     method="POST", headers={"Content-Type": "application/x-www-form-urlencoded",
                                                             "Accept": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=self.cfg.timeout_s) as r:  # noqa: S310
                tok = json.loads(r.read())
        except urllib.error.HTTPError as e:
            raise SSOError(f"identity provider refused the sign-in (HTTP {e.code})") from None
        except (urllib.error.URLError, OSError, ValueError) as e:
            raise SSOError(f"identity provider unreachable: {getattr(e, 'reason', e)}") from None
        idt = tok.get("id_token")
        if not idt or idt.count(".") != 2:
            raise SSOError("identity provider returned no ID token (is the 'openid' scope allowed?)")
        try:
            claims = json.loads(_b64url_decode(idt.split(".")[1]))
        except ValueError:
            raise SSOError("ID token is unreadable") from None
        self.verify_signature(idt)
        self.check(claims, pending["n"])
        return claims

    # ---- signature (RS256 against the provider's JWKS; standard library only) --------------------------

    def _keys(self, refresh: bool = False) -> list[dict[str, Any]]:
        with self._lock:
            if not refresh and self._jwks and time.monotonic() - self._jwks[0] < self.DISCOVERY_TTL_S:
                return self._jwks[1]
        keys = self._get_json(self.discovery()["jwks_uri"]).get("keys") or []
        with self._lock:
            self._jwks = (time.monotonic(), keys)
        return keys

    def verify_signature(self, token: str) -> None:
        try:
            head_b64, body_b64, sig_b64 = token.split(".")
            header = json.loads(_b64url_decode(head_b64))
            sig = _b64url_decode(sig_b64)
        except ValueError:
            raise SSOError("ID token is unreadable") from None
        if header.get("alg") != "RS256":
            raise SSOError(f"ID token is signed with {header.get('alg')!r}; only RS256 is accepted")
        kid = header.get("kid")
        for refresh in (False, True):                 # keys rotate: fetch again once for an unknown key id
            keys = [k for k in self._keys(refresh) if k.get("kty") == "RSA" and (kid is None or k.get("kid") == kid)]
            if keys:
                break
        if not keys:
            raise SSOError("the provider has no key for this ID token")
        from .jws import rs256_verify
        signing_input = f"{head_b64}.{body_b64}".encode()
        for k in keys:
            if rs256_verify(k, signing_input, sig):
                return
        raise SSOError("ID token signature is not valid")

    def check(self, claims: dict[str, Any], nonce: str) -> None:
        if str(claims.get("iss", "")).rstrip("/") != self.cfg.issuer.rstrip("/"):
            raise SSOError("ID token is from another issuer")
        aud = claims.get("aud")
        auds = aud if isinstance(aud, list) else [aud]
        if self.cfg.client_id not in auds or (len(auds) > 1 and claims.get("azp") != self.cfg.client_id):
            raise SSOError("ID token is for another application")
        if float(claims.get("exp", 0)) < time.time() - 60:
            raise SSOError("ID token has expired")
        if not secrets.compare_digest(str(claims.get("nonce", "")), nonce):
            raise SSOError("ID token nonce does not match")

    def person_for(self, claims: dict[str, Any], directory: Any) -> str:
        if directory is None:
            raise SSOError("single sign-on needs a people configuration (who may use the console)")
        value = claims.get(self.cfg.claim)
        if not value:
            raise SSOError(f"the identity provider did not send '{self.cfg.claim}'")
        if self.cfg.claim == "email" and self.cfg.require_verified_email and claims.get("email_verified") is not True:
            raise SSOError("the identity provider did not confirm your email address is verified")
        v = str(value).strip().lower()
        for p in directory.people.values():
            if p.id.lower() == v or str(p.contact.get("email", "")).strip().lower() == v:
                if not p.active:
                    raise SSOError(f"{p.id} is not active")
                return p.id
        raise SSOError(f"{value} is not set up in Sentinel; ask your administrator to add you")

    def bind(self, store: Any, claims: dict[str, Any], person_id: str) -> None:
        """The first sign-in ties the person to the provider's stable user id; later sign-ins must match."""
        sub = str(claims.get("sub") or "")
        if not sub:
            raise SSOError("the identity provider sent no user id (sub)")
        key = f"sso:{self.cfg.issuer.rstrip('/')}:person:{person_id}"
        known = store.get_source_state(key)
        if not known or not known.get("sub"):
            store.put_source_state(key, {"sub": sub})
            store.audit(None, "sso_bound", {"person": person_id})
        elif known.get("sub") != sub:
            raise SSOError(f"{person_id} is tied to a different account at the identity provider; ask your "
                           "administrator to reset the sign-in link")
