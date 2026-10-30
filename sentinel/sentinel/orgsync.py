# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""Org and authority for domain cores, offline (ADR-003 C1/C2): a signed policy bundle, signed agent assertions,
and decision receipts back to Sentinel.

A domain core (POS, HMS, a dairy depot app) enforces ``authorise()`` where the write happens, against a synced
copy of the people configuration, so a till keeps working when the network is down. Three pieces make that copy
trustworthy:

1. **Policy bundle.** Sentinel signs the people configuration (roles, people, assignments, authority, sod,
   agents, oversight ...) as an RS256 token with a version, an issue time and an expiry::

       token = engine.export_policy(ttl_hours=24)              # or: sentinel policy export
       snap = load_policy(token, keys)                         # in the core; standard library only

   The core checks the signature with the site's public key (``keys.json``). After ``expires_at`` the bundle is
   **stale**: agents may not write at all until a fresh one arrives; people still may (a till must sell), and
   their receipts say the decision used a stale bundle.

2. **Agent assertion.** When an agent acts unattended, the action handler gets ``ctx.assert_for(action, obj)``:
   a short-lived token signed by Sentinel naming the agent (template@scope), its bound role, its mode, the case,
   the action and the object. The core passes it to ``snap.authorise(...)``; it is refused if the signature,
   expiry, site, action or object differ, if the core passes any scope fact the token does not cover (directly or
   by roll-up), if a caller-named actor is not the token's agent, if the token or the bundle the core holds puts
   the agent below ACT, or if the same assertion was already used (one assertion, one write). So the audit can
   prove which template, in which scope, under whose authority, asked for each write.

3. **Receipts.** Every ``snap.authorise`` returns a ``Receipt`` (bundle version, actor, action, object, amount,
   allowed, deciding role, checks, stale). The core posts them back (``POST /v1/receipts``) and Sentinel audits
   them (``authority_receipt``), flagging unknown or stale bundle versions. Layer D then sees what cores allowed.

Signing needs the ``cryptography`` package (Sentinel's ``api`` extra); verifying needs only the standard library.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import threading
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator

from .factrule import as_facts, fact_problem
from .jws import b64url, b64url_decode, rs256_verify
from .models import new_id
from .org import Agent, Decision, Person, authorise

BUNDLE_TYP = "sentinel-policy"
ASSERT_TYP = "sentinel-agent"
SKEW = timedelta(minutes=5)                     # clocks may differ this much between Sentinel and a core


class PolicyError(ValueError):
    """A bundle or assertion that cannot be trusted (signature, type, content)."""


# ---- keys and signing (Sentinel side) ------------------------------------------------------------------

def keygen(out_dir: str | Path, kid: str) -> dict[str, str]:
    """A site key pair for policy bundles and agent assertions: private.pem (stays with Sentinel) and keys.json
    (give it to every domain core)."""
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
    except ImportError:
        raise PolicyError("signing policy needs: pip install cryptography") from None
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


def load_keys(source: str | Path | Mapping[str, Any] | list[Any]) -> list[dict[str, Any]]:
    """Public keys from keys.json (a path), its parsed content, or a list of JWKs."""
    if isinstance(source, (str, Path)):
        source = json.loads(Path(source).read_text(encoding="utf-8"))
    if isinstance(source, Mapping):
        return list(source.get("keys") or [])
    return list(source)


@dataclass
class PolicySigner:
    """Signs bundles and assertions with the site's private key."""
    private_pem: bytes
    kid: str | None = None
    _key: Any = field(default=None, repr=False)

    @classmethod
    def from_file(cls, path: str | Path, kid: str | None = None) -> PolicySigner:
        return cls(Path(path).read_bytes(), kid)

    @classmethod
    def from_env(cls) -> PolicySigner | None:
        """SENTINEL_POLICY_KEY = path to private.pem; SENTINEL_POLICY_KID = its key id (optional)."""
        path = os.environ.get("SENTINEL_POLICY_KEY")
        return cls.from_file(path, os.environ.get("SENTINEL_POLICY_KID") or None) if path else None

    def sign(self, typ: str, payload: dict[str, Any]) -> str:
        try:
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import padding
        except ImportError:
            raise PolicyError("signing policy needs: pip install cryptography") from None
        if self._key is None:
            self._key = serialization.load_pem_private_key(self.private_pem, password=None)
        header = {"alg": "RS256", "typ": typ, **({"kid": self.kid} if self.kid else {})}
        h64 = b64url(json.dumps(header, separators=(",", ":")).encode())
        p64 = b64url(json.dumps(payload, separators=(",", ":"), sort_keys=True, default=str).encode())
        sig = self._key.sign(f"{h64}.{p64}".encode(), padding.PKCS1v15(), hashes.SHA256())
        return f"{h64}.{p64}.{b64url(sig)}"


def _verify(token: str, typ: str, keys: list[dict[str, Any]]) -> dict[str, Any]:
    try:
        h64, p64, s64 = token.strip().split(".")
        header = json.loads(b64url_decode(h64))
        payload = json.loads(b64url_decode(p64))
        sig = b64url_decode(s64)
    except (ValueError, AttributeError):
        raise PolicyError("unreadable token") from None
    if header.get("alg") != "RS256" or header.get("typ") != typ:
        raise PolicyError(f"not a {typ} token")
    cands = [k for k in keys if k.get("kty") == "RSA" and (header.get("kid") is None or k.get("kid") == header["kid"])]
    if not cands or not any(rs256_verify(k, f"{h64}.{p64}".encode(), sig) for k in cands):
        raise PolicyError("signature does not match the site's keys")
    if not isinstance(payload, dict):
        raise PolicyError("token content is not an object")
    return payload


def _ts(v: Any) -> datetime:
    try:
        t = datetime.fromisoformat(str(v))
    except ValueError:
        raise PolicyError(f"bad timestamp {v!r}") from None
    return t if t.tzinfo else t.replace(tzinfo=UTC)


def policy_version(people_doc: dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(people_doc, sort_keys=True, default=str).encode()).hexdigest()[:16]


def export_policy(directory: Any, signer: PolicySigner, *, ttl_hours: float = 24, now: datetime | None = None,
                  site: str | None = None) -> tuple[str, dict[str, Any]]:
    """(token, its claims) for this people configuration."""
    from .config import directory_doc
    if isinstance(ttl_hours, bool) or not isinstance(ttl_hours, int | float) or not (0 < ttl_hours <= 24 * 366):
        raise PolicyError("ttl_hours must be a number above 0 and at most a year")
    now = now or datetime.now(UTC)
    doc = directory_doc(directory)
    claims = {"site": site or "", "version": policy_version(doc), "issued_at": now.isoformat(),
              "expires_at": (now + timedelta(hours=ttl_hours)).isoformat(), "people": doc}
    return signer.sign(BUNDLE_TYP, claims), {k: v for k, v in claims.items() if k != "people"}


def sign_agent_assertion(signer: PolicySigner, *, agent: str, template: str, bound_role: str, mode: str,
                         scope: Mapping[str, Any], action: str, obj: str | None, incident: str | None,
                         site: str | None = None, ttl_seconds: int = 300, now: datetime | None = None,
                         capability: str | None = None) -> str:
    """A short-lived token an agent's action carries to the domain core."""
    now = now or datetime.now(UTC)
    if isinstance(ttl_seconds, bool) or not isinstance(ttl_seconds, int) or not 0 < ttl_seconds <= 3600:
        raise PolicyError("an agent assertion lives between 1 second and 1 hour")
    return signer.sign(ASSERT_TYP, {"agent": agent, "template": template, "capability": capability,
                                    "bound_role": bound_role, "mode": mode,
                                    "scope": dict(scope), "action": action, "obj": obj, "incident": incident,
                                    "site": site or "", "iat": now.isoformat(),
                                    "exp": (now + timedelta(seconds=ttl_seconds)).isoformat(),
                                    "jti": new_id("ast")})


def verify_agent_assertion(token: str, keys: list[dict[str, Any]], *, now: datetime | None = None) -> dict[str, Any]:
    claims = _verify(token, ASSERT_TYP, keys)
    now = now or datetime.now(UTC)
    for k in ("agent", "bound_role", "mode", "action", "exp"):
        if k not in claims:
            raise PolicyError(f"agent assertion lacks {k}")
    if now >= _ts(claims["exp"]):
        raise PolicyError("agent assertion has expired")
    if _ts(claims.get("iat", claims["exp"])) > now + timedelta(minutes=5):
        raise PolicyError("agent assertion is issued in the future")
    return claims


# ---- receipts ------------------------------------------------------------------------------------------

class Receipt(BaseModel):
    """What a domain core decided with ``authorise``: posted back to Sentinel for Layer D.

    Strict: every field must arrive as its own JSON type (BUILDER_MISSES check 6). A receipt is evidence, so a
    coerced value ("yes" read as allowed, true read as amount 1) would be a false record."""
    id: str = Field(default_factory=lambda: new_id("rcp"), min_length=1, max_length=200)
    at: datetime
    site: str = ""
    core: str = ""                                  # which domain core decided (pos, hms ...)
    bundle_version: str = Field(min_length=1)
    stale: bool = False
    actor: str = Field(min_length=1)
    actor_kind: Literal["person", "agent"]
    agent_template: str | None = None
    agent_incident: str | None = None
    assertion_id: str | None = None
    action: str = Field(min_length=1)
    obj: str | None = None
    scope: dict[str, Any] = Field(default_factory=dict)
    amount: float | None = None
    allowed: bool
    decided_by_role: str | None = None
    checks: list[str] = Field(default_factory=list)
    reason: str = ""

    @field_validator("id", "site", "core", "bundle_version", "actor", "agent_template", "agent_incident",
                     "assertion_id", "action", "obj", "decided_by_role", "reason", mode="before")
    @classmethod
    def _text(cls, v: Any) -> Any:
        if v is not None and not isinstance(v, str):
            raise ValueError("must be text")
        return v

    @field_validator("at", mode="before")
    @classmethod
    def _at(cls, v: Any) -> Any:
        if isinstance(v, datetime):
            return v
        if not isinstance(v, str):
            raise ValueError("must be an ISO-8601 timestamp")
        try:
            at = datetime.fromisoformat(v.replace("Z", "+00:00"))
        except ValueError:
            raise ValueError("must be an ISO-8601 timestamp") from None
        if at.tzinfo is None or "T" not in v:          # a core's local time read as UTC would move every flag
            raise ValueError("must be an ISO-8601 date-time with a UTC offset or Z")
        return at

    @field_validator("scope", mode="before")
    @classmethod
    def _scope(cls, v: Any) -> Any:
        """The fact rule (sentinel.factrule): an unset fact is left out, never null."""
        if not isinstance(v, dict):
            raise ValueError("must be an object")
        for k, x in v.items():
            if (why := fact_problem(k, x)) is not None:
                raise ValueError(why)
        return v

    @field_validator("stale", "allowed", mode="before")
    @classmethod
    def _flag(cls, v: Any) -> Any:
        if not isinstance(v, bool):
            raise ValueError("must be true or false")
        return v

    @field_validator("amount", mode="before")
    @classmethod
    def _amount(cls, v: Any) -> Any:
        if v is None:
            return v
        if isinstance(v, bool) or not isinstance(v, int | float | Decimal):
            raise ValueError("must be a number")
        if not math.isfinite(float(v)):
            raise ValueError("must be a finite number")
        return float(v)

    @field_validator("checks", mode="before")
    @classmethod
    def _checks(cls, v: Any) -> Any:
        if not isinstance(v, list) or not all(isinstance(x, str) for x in v):
            raise ValueError("must be a list of text")
        return v


# ---- the core side -------------------------------------------------------------------------------------

@dataclass
class PolicySnapshot:
    """A verified policy bundle, as a domain core holds it. ``authorise`` returns (Decision, Receipt)."""
    directory: Any
    version: str
    issued_at: datetime
    expires_at: datetime
    site: str
    keys: list[dict[str, Any]]
    core: str = ""
    require_assertion: bool = True                   # agents must carry a signed assertion
    clock: Callable[[], datetime] = field(default=lambda: datetime.now(UTC))
    _used: dict[str, datetime] = field(default_factory=dict, repr=False)   # assertion id -> its expiry
    _lock: Any = field(default_factory=threading.Lock, repr=False)         # one use: check and mark together

    def _unmatched(self, claims: dict[str, Any], given: str | None, action: str, obj: str | None,
                   scope: dict[str, Any], now: datetime) -> str:
        return _unmatched_impl(self, claims, given, action, obj, scope, now)

    def stale(self, now: datetime | None = None) -> bool:
        """Expired, or issued in the core's future beyond the allowed skew (its clock or Sentinel's is wrong)."""
        now = now or self.clock()
        return now >= self.expires_at or now < self.issued_at - SKEW

    def authorise(self, actor: Person | Agent | str, action: str, obj: str | None = None,
                  scope: Mapping[str, Any] | None = None, amount: float | None = None, *,
                  assertion: str | None = None, now: datetime | None = None, **kw: Any) -> tuple[Decision, Receipt]:
        now = now or self.clock()
        scope = dict(scope or {})
        stale = self.stale(now)
        claims: dict[str, Any] | None = None
        is_agent = isinstance(actor, Agent) or assertion is not None

        def receipt(dec: Decision, actor_id: str, kind: str) -> tuple[Decision, Receipt]:
            return dec, Receipt(at=now, site=self.site, core=self.core, bundle_version=self.version, stale=stale,
                                actor=actor_id, actor_kind=kind,
                                agent_template=(claims or {}).get("template"),
                                agent_incident=(claims or {}).get("incident"),
                                assertion_id=(claims or {}).get("jti"), action=action, obj=obj,
                                scope=as_facts(scope),
                                amount=amount, allowed=dec.allowed, decided_by_role=dec.decided_by_role,
                                checks=list(dec.checks), reason=dec.reason)

        def refuse(why: str, actor_id: str, kind: str, check: str) -> tuple[Decision, Receipt]:
            return receipt(Decision(False, why, actor_id, action, checks=[check]), actor_id, kind)

        if is_agent:
            given = actor.id if isinstance(actor, Agent | Person) else actor     # what the caller says it is
            aid = str(given or "agent")
            if isinstance(actor, Person):
                return refuse(f"{aid} is a person: an agent's assertion is never used for a person", aid, "agent",
                              "assertion")
            if self.stale(now):
                state = (f"expired at {self.expires_at.isoformat()}" if now >= self.expires_at else
                         f"is issued in the future ({self.issued_at.isoformat()}); check the clocks")
                return refuse(f"policy bundle {self.version} {state}: agents may not write until a current one "
                              "arrives", aid, "agent", "bundle_fresh")
            if assertion is None:
                if self.require_assertion:
                    return refuse(f"{aid}: an agent's write needs a signed agent assertion", aid, "agent",
                                  "assertion")
                if not isinstance(actor, Agent):
                    return refuse("an agent actor needs its bound role", aid, "agent", "assertion")
            else:
                try:
                    claims = verify_agent_assertion(assertion, self.keys, now=now)
                except PolicyError as e:
                    return refuse(f"agent assertion refused: {e}", aid, "agent", "assertion")
                with self._lock:                                  # two threads never both pass one assertion
                    why = self._unmatched(claims, given, action, obj, scope, now)
                    if not why:
                        aid = str(claims["agent"])
                        pol = self.directory.agent_policy(str(claims.get("template") or ""),
                                                          claims.get("capability"),
                                                          {**(claims.get("scope") or {}), **scope}, at=now) \
                            if getattr(self.directory, "agents", None) else None
                        if pol is not None and pol.mode != "ACT":   # the bundle the core holds narrows the token
                            why = f"{aid} is in {pol.mode} here by the current policy bundle: a person decides"
                            check = "mode"
                        else:
                            self._used[str(claims["jti"])] = _ts(claims["exp"])
                    else:
                        check = "assertion"
                if why:
                    return refuse(why, str(claims.get("agent") or aid), "agent", check)
                scope = {**(claims.get("scope") or {}), **scope}
                actor = Agent(aid, bound_role=str(claims["bound_role"]), on_behalf_of=claims.get("template"))
        old = getattr(self.directory, "clock", None)
        self.directory.clock = lambda: now
        try:
            dec = authorise(self.directory, actor, action, obj, scope, amount, **kw)
        finally:
            self.directory.clock = old
        if isinstance(actor, Agent):
            return receipt(dec, actor.id, "agent")
        aid = actor.id if not isinstance(actor, str) else actor
        if stale:
            dec.checks.append("stale_bundle")
        return receipt(dec, aid, "person")


def _same(a: Any, b: Any) -> bool:
    return a == b or (a is not None and b is not None and str(a) == str(b))


def _unmatched_impl(snap: PolicySnapshot, claims: dict[str, Any], given: str | None, action: str, obj: str | None,
                    scope: dict[str, Any], now: datetime) -> str:
    """Why the assertion does not authorise exactly this write ('' when every claim matches). Allow only if the
    token names this actor, site, action and object, and covers every scope fact the core passes (directly or by
    roll-up); anything absent on one side is a mismatch."""
    aid = str(claims["agent"])
    if given is not None and str(given) != aid:
        return f"the assertion is for {aid}, not {given}"
    jti = str(claims.get("jti") or "")
    snap._used = {k: v for k, v in snap._used.items() if v > now}           # forget expired ones
    if not jti:
        return "the assertion has no id, so it cannot be held to one write"
    if jti in snap._used:
        return f"agent assertion {jti} was already used: one assertion, one write"
    if snap.site and not _same(claims.get("site"), snap.site):
        return f"the assertion is for site {claims.get('site')!r}, not {snap.site!r}"
    if claims.get("action") != action:
        return f"the assertion is for {claims.get('action')!r}, not {action!r}"
    if not _same(claims.get("obj"), obj):
        return f"the assertion is for object {claims.get('obj')!r}, not {obj!r}"
    if claims.get("mode") != "ACT":
        return f"{aid} is in {claims.get('mode')} here: a person decides"
    covered = snap.directory.expand_facts(dict(claims.get("scope") or {})) \
        if hasattr(snap.directory, "expand_facts") else {k: {v} for k, v in (claims.get("scope") or {}).items()}
    for k, v in scope.items():
        vals = covered.get(k)
        if not vals or not any(_same(v, x) for x in vals):
            return f"the assertion does not cover {k}={v} (it is for {claims.get('scope')})"
    return ""


class _Binder:
    """The minimum ``_unmatched_impl`` needs, for cores that hold their own authority (no bundle)."""

    def __init__(self, site: str, used: dict[str, datetime], expand: Callable[[dict[str, Any]], dict[str, set[Any]]]
                 | None) -> None:
        self.site, self._used = site, used
        self.directory = type("D", (), {"expand_facts": staticmethod(expand)})() if expand else object()


def bind_assertion(token: str, keys: Iterable[dict[str, Any]] | str | Path, *, action: str, obj: str | None,
                   scope: Mapping[str, Any], site: str, used: dict[str, datetime], actor: str | None = None,
                   expand: Callable[[dict[str, Any]], dict[str, set[Any]]] | None = None,
                   now: datetime | None = None) -> dict[str, Any]:
    """For a core that keeps its own authority (it does not load Sentinel's bundle): verify an agent assertion and
    bind it to exactly this write, with the same rules ``PolicySnapshot.authorise`` uses: every claim must match
    (site, action, object, actor if named, ACT mode, every scope fact covered, directly or via ``expand`` roll-ups),
    and one use only (``used`` is the core's id -> expiry map; it is checked and marked under a lock within one
    process. A core with several processes or machines keeps the id unique in a table as well). Returns the
    claims (agent, template, bound_role, scope, incident, jti) or raises PolicyError. The core then runs its own
    authority check for ``bound_role`` in that scope."""
    ks = load_keys(keys) if isinstance(keys, (str, Path)) else list(keys)
    now = now or datetime.now(UTC)
    claims = verify_agent_assertion(token, ks, now=now)
    with _BIND_LOCK:                                      # check and mark together (threads in one process)
        binder = _Binder(site, used, expand)
        why = _unmatched_impl(binder, claims, actor, action, obj, dict(scope), now)   # type: ignore[arg-type]
        used.clear()
        used.update(binder._used)
        if why:
            raise PolicyError(why)
        used[str(claims["jti"])] = _ts(claims["exp"])
    return claims


_BIND_LOCK = threading.Lock()


def load_policy(token: str, keys: Iterable[dict[str, Any]] | str | Path, *, core: str = "",
                require_assertion: bool = True, clock: Callable[[], datetime] | None = None,
                site: str | None = None) -> PolicySnapshot:
    """Verify a bundle and build the core's snapshot (refused if the signature or content is wrong, if it is
    issued in the future, or if ``site`` is given and the bundle is for another site)."""
    from .rbac import parse_directory
    ks = load_keys(keys) if isinstance(keys, (str, Path)) else list(keys)
    claims = _verify(token, BUNDLE_TYP, ks)
    people = claims.get("people")
    if not isinstance(people, dict):
        raise PolicyError("the bundle carries no people configuration")
    if policy_version(people) != claims.get("version"):
        raise PolicyError("the bundle's version does not match its content")
    try:
        directory = parse_directory(people, "policy bundle")
    except Exception as e:  # noqa: BLE001 - shown to the core's operator
        raise PolicyError(f"the bundle's people configuration is invalid: {e}") from None
    issued, expires = _ts(claims.get("issued_at")), _ts(claims.get("expires_at"))
    if expires <= issued:
        raise PolicyError("the bundle expires before it was issued")
    if site is not None and str(claims.get("site") or "") != site:
        raise PolicyError(f"the bundle is for site {claims.get('site')!r}, not {site!r}")
    now = (clock or (lambda: datetime.now(UTC)))()
    if issued > now + SKEW:
        raise PolicyError(f"the bundle is issued in the future ({issued.isoformat()}); check the clocks")
    return PolicySnapshot(directory=directory, version=str(claims["version"]), issued_at=issued, expires_at=expires,
                          site=str(claims.get("site") or ""), keys=ks, core=core,
                          require_assertion=require_assertion, clock=clock or (lambda: datetime.now(UTC)))


__all__ = ["ASSERT_TYP", "BUNDLE_TYP", "PolicyError", "PolicySigner", "PolicySnapshot", "Receipt", "bind_assertion",
           "export_policy", "keygen", "load_keys", "load_policy", "policy_version", "sign_agent_assertion",
           "verify_agent_assertion"]
