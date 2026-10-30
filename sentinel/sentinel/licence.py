# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""Signed licences that degrade to human review and never stop the site.

Sentinel is open source and runs without a licence. A commercial install sets ``SENTINEL_LICENCE`` (the
licence token, or a path to a file holding it) and ``SENTINEL_LICENCE_KEYS`` (a path to the issuer's public
keys, JWK set JSON). From then on the licence is checked every few minutes:

  ok         valid, within its limits
  grace      expired less than ``grace_days`` ago, or over a soft limit: everything still works; the console
             and /healthz say so
  degraded   no valid licence, expired beyond the grace period, for another site, or over a hard cap:
             every exception is handled by a person (no playbook or model acts alone); events, reviews,
             decisions, reversals and reports keep working

A licence is a compact RS256 token (``header.payload.signature``) whose payload is::

  {"licensee": "Acme Home", "site": "acme-prod", "tier": "growth",
   "valid_from": "2026-11-01", "valid_until": "2027-10-31", "grace_days": 14,
   "limits": {"incidents_per_month": 10000, "automatic_per_month": 3000, "domains": 2, "reviewers": 25},
   "hard_cap": false, "features": ["whatsapp", "sso"]}

``issue`` and ``keygen`` (vendor side) need the ``cryptography`` package; checking needs only the standard
library.
"""
from __future__ import annotations

import json
import os
import threading
import time
from datetime import date, datetime, timedelta, UTC
from pathlib import Path
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, Field

from .jws import b64url, b64url_decode, rs256_verify

if TYPE_CHECKING:
    from .engine import Engine

TOKEN_ENV, KEYS_ENV, SITE_ENV = "SENTINEL_LICENCE", "SENTINEL_LICENCE_KEYS", "SENTINEL_SITE_ID"


class LicenceError(ValueError):
    pass


class Limits(BaseModel):
    incidents_per_month: int | None = None
    automatic_per_month: int | None = None        # an allowance: beyond it is billed, never blocked
    domains: int | None = None
    reviewers: int | None = None


class Licence(BaseModel):
    licensee: str
    site: str
    tier: str = "custom"
    valid_from: date
    valid_until: date
    grace_days: int = Field(default=14, ge=0, le=90)
    limits: Limits = Field(default_factory=Limits)
    hard_cap: bool = False                          # over incidents_per_month: degraded instead of grace
    features: list[str] = Field(default_factory=list)
    issued_at: datetime | None = None


def parse(token: str, keys: list[dict[str, Any]]) -> Licence:
    """Check the signature and return the licence (dates and limits are judged by ``status``)."""
    try:
        h64, p64, s64 = token.strip().split(".")
        header = json.loads(b64url_decode(h64))
        payload = json.loads(b64url_decode(p64))
        sig = b64url_decode(s64)
    except ValueError:
        raise LicenceError("the licence is unreadable") from None
    if header.get("alg") != "RS256" or header.get("typ") != "sentinel-licence":
        raise LicenceError("not a Sentinel licence")
    cands = [k for k in keys if k.get("kty") == "RSA" and (header.get("kid") is None or k.get("kid") == header["kid"])]
    if not any(rs256_verify(k, f"{h64}.{p64}".encode(), sig) for k in cands):
        raise LicenceError("the licence signature does not match the issuer's keys")
    try:
        return Licence.model_validate(payload)
    except Exception as e:  # noqa: BLE001 - shown to the operator
        raise LicenceError(f"the licence content is invalid: {e}") from None


def load_keys(path: str | None) -> list[dict[str, Any]]:
    if not path:
        return []
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return list(data.get("keys") or []) if isinstance(data, dict) else list(data)


def load_token(value: str | None) -> str | None:
    if not value:
        return None
    v = value.strip()
    if v.count(".") == 2 and "/" not in v and "\\" not in v:
        return v
    return Path(v).read_text(encoding="utf-8").strip()


class LicenceGuard:
    """What the engine asks: is the site degraded right now? Cached; re-checked every ``ttl_s``."""

    def __init__(self, token: str | None, keys: list[dict[str, Any]], *, site: str | None = None,
                 ttl_s: float = 300.0) -> None:
        self.token, self.keys, self.site, self.ttl_s = token, keys, site, ttl_s
        self._cache: tuple[float, dict[str, Any]] | None = None
        self._lock = threading.Lock()

    @classmethod
    def from_env(cls) -> LicenceGuard | None:
        if not os.environ.get(TOKEN_ENV):
            return None                              # open-source install: nothing is enforced
        try:
            token = load_token(os.environ.get(TOKEN_ENV))
        except OSError:
            token = None
        try:
            keys = load_keys(os.environ.get(KEYS_ENV))
        except (OSError, ValueError):
            keys = []
        return cls(token, keys, site=os.environ.get(SITE_ENV))

    def status(self, engine: Engine, *, fresh: bool = False) -> dict[str, Any]:
        with self._lock:
            if not fresh and self._cache and time.monotonic() - self._cache[0] < self.ttl_s:
                return self._cache[1]
        st = self._compute(engine)
        with self._lock:
            self._cache = (time.monotonic(), st)
        return st

    def degraded(self, engine: Engine) -> bool:
        return self.status(engine)["state"] == "degraded"

    def _compute(self, engine: Engine) -> dict[str, Any]:
        out: dict[str, Any] = {"state": "ok", "reasons": [], "licence": None, "usage": {}}

        def bad(msg: str) -> dict[str, Any]:
            out["state"] = "degraded"
            out["reasons"].append(msg)
            return out
        if not self.token:
            return bad("no licence could be read from SENTINEL_LICENCE")
        if not self.keys:
            return bad("no issuer keys (SENTINEL_LICENCE_KEYS) to check the licence with")
        try:
            lic = parse(self.token, self.keys)
        except LicenceError as e:
            return bad(str(e))
        out["licence"] = lic.model_dump(mode="json")
        today = engine.clock().astimezone(UTC).date()
        if self.site and lic.site != self.site:
            return bad(f"the licence is for site {lic.site!r}, this is {self.site!r}")
        if today < lic.valid_from:
            return bad(f"the licence starts on {lic.valid_from}")
        if today > lic.valid_until:
            left = (lic.valid_until + timedelta(days=lic.grace_days) - today).days
            if left < 0:
                return bad(f"the licence expired on {lic.valid_until} (grace ended)")
            out["state"] = "grace"
            out["reasons"].append(f"the licence expired on {lic.valid_until}; {left} day(s) of grace left")
        from .usage import measure
        month = engine.clock().astimezone(UTC).strftime("%Y-%m")
        m = measure(engine, month)
        incidents = sum(t["incidents"] for t in m["tenants"].values())
        automatic = sum(t["resolved_automatic"] for t in m["tenants"].values())
        reviewers = sum(t["reviewers"] for t in m["tenants"].values())
        domains = len({d for t in m["tenants"].values() for d in t["domains"]} - {"unmatched", "retired"})
        out["usage"] = {"month": month, "incidents": incidents, "automatic": automatic, "reviewers": reviewers,
                        "domains": domains}
        lim = lic.limits
        if lim.incidents_per_month is not None and incidents > lim.incidents_per_month:
            msg = f"{incidents} cases this month; the licence covers {lim.incidents_per_month}"
            if lic.hard_cap:
                return bad(msg)
            out["state"] = "grace" if out["state"] == "ok" else out["state"]
            out["reasons"].append(msg + " (billed as overage)")
        if lim.automatic_per_month is not None and automatic > lim.automatic_per_month:
            out["reasons"].append(f"{automatic} automatic resolutions; {lim.automatic_per_month} included, the rest "
                                  "are billed")
        for name, used, cap in (("reviewers", reviewers, lim.reviewers), ("domains", domains, lim.domains)):
            if cap is not None and used > cap:
                out["state"] = "grace" if out["state"] == "ok" else out["state"]
                out["reasons"].append(f"{used} {name} this month; the licence covers {cap}")
        return out


# ---- vendor side ----------------------------------------------------------------------------------------
def keygen(out_dir: str, kid: str) -> dict[str, str]:
    """A new issuer key pair: private.pem (keep it offline) and keys.json (give it to every site)."""
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
    except ImportError:
        raise LicenceError('issuing licences needs: pip install cryptography') from None
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    nums = key.public_key().public_numbers()
    jwk = {"kty": "RSA", "kid": kid, "alg": "RS256", "use": "sig",
           "n": b64url(nums.n.to_bytes((nums.n.bit_length() + 7) // 8, "big")),
           "e": b64url(nums.e.to_bytes((nums.e.bit_length() + 7) // 8, "big"))}
    d = Path(out_dir)
    d.mkdir(parents=True, exist_ok=True)
    priv = d / "private.pem"
    priv.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                       serialization.NoEncryption()))
    os.chmod(priv, 0o600)
    pub = d / "keys.json"
    pub.write_text(json.dumps({"keys": [jwk]}, indent=2), encoding="utf-8")
    return {"private": str(priv), "public": str(pub)}


def issue(private_pem: str, payload: dict[str, Any], kid: str | None = None) -> str:
    try:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding
    except ImportError:
        raise LicenceError('issuing licences needs: pip install cryptography') from None
    lic = Licence.model_validate({**payload, "issued_at": payload.get("issued_at")
                                  or datetime.now(UTC).isoformat()})
    key = serialization.load_pem_private_key(Path(private_pem).read_bytes(), password=None)
    header = {"alg": "RS256", "typ": "sentinel-licence", **({"kid": kid} if kid else {})}
    h64 = b64url(json.dumps(header, separators=(",", ":")).encode())
    p64 = b64url(lic.model_dump_json(exclude_none=True).encode())
    sig = key.sign(f"{h64}.{p64}".encode(), padding.PKCS1v15(), hashes.SHA256())  # type: ignore[union-attr]
    return f"{h64}.{p64}.{b64url(sig)}"
