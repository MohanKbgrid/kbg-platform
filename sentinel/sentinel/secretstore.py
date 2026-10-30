# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""Keys entered in the console: connector credentials kept encrypted in the site's own database.

Connectors are configured once and wait for their keys. A person with the ``__configure__`` right enters each
key on the console's **Keys** page (or ``sentinel secret set NAME``); the value is encrypted with AES-256-GCM
under a key derived from ``SENTINEL_MASTER_KEY`` (and the tenant, in hosted mode), stored, and never shown
again - the page shows only whether it is set, where it comes from, its last four characters and who set it.
A key set here takes precedence over an environment variable of the same name. Every change is audited and
reaches every process at its next configuration sync; the connectors are rebuilt with the new key at once.

Without ``SENTINEL_MASTER_KEY`` the page is read-only and keys come from the environment as before.
Generate a master key with ``sentinel new-master-key`` and keep it out of the database and its backups.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets as _secrets
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .engine import Engine

MASTER_ENV = "SENTINEL_MASTER_KEY"
INDEX = "__secrets__"
PREFIX = "__secret__:"


class SecretStoreError(RuntimeError):
    pass


def new_master_key() -> str:
    return base64.urlsafe_b64encode(_secrets.token_bytes(32)).decode()


def _key(tenant: str | None) -> bytes:
    raw = os.environ.get(MASTER_ENV, "").strip()
    if not raw:
        raise SecretStoreError(f"set {MASTER_ENV} to store keys in the console (sentinel new-master-key)")
    try:
        master = base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))
    except ValueError:
        raise SecretStoreError(f"{MASTER_ENV} is not valid base64") from None
    if len(master) < 32:
        raise SecretStoreError(f"{MASTER_ENV} must be at least 32 bytes")
    # HKDF-SHA256 (RFC 5869), one key per tenant
    prk = hmac.new(b"sentinel-secrets-v1", master, hashlib.sha256).digest()
    return hmac.new(prk, f"tenant:{tenant or '-'}".encode() + b"\x01", hashlib.sha256).digest()


def available() -> bool:
    return bool(os.environ.get(MASTER_ENV, "").strip())


def _aead() -> Any:
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError as e:  # pragma: no cover
        raise SecretStoreError('keys in the console need the "cryptography" package (pip install cryptography)') \
            from e
    return AESGCM


def encrypt(name: str, value: str, tenant: str | None) -> str:
    nonce = _secrets.token_bytes(12)
    ct = _aead()(_key(tenant)).encrypt(nonce, value.encode(), name.encode())
    return base64.b64encode(nonce + ct).decode()


def decrypt(name: str, blob: str, tenant: str | None) -> str:
    raw = base64.b64decode(blob)
    try:
        return _aead()(_key(tenant)).decrypt(raw[:12], raw[12:], name.encode()).decode()
    except Exception:  # noqa: BLE001 - wrong master key or tampered row
        raise SecretStoreError(f"{name}: cannot be decrypted with this {MASTER_ENV}") from None


class SecretStore:
    """Encrypted keys in the store's source_state, with an index; a decrypted cache per engine."""

    def __init__(self, engine: Engine) -> None:
        self.engine = engine
        self.cache: dict[str, str] = {}
        self.rev: int | None = None
        self.problems: list[str] = []

    @property
    def tenant(self) -> str | None:
        from .envsecrets import TENANT
        return TENANT.get()

    def _index(self) -> dict[str, Any]:
        return self.engine.store.get_source_state(INDEX) or {"rev": 0, "names": {}}

    def refresh(self) -> bool:
        """Reload the cache when another process changed a key. True when it changed."""
        idx = self._index()
        if idx.get("rev") == self.rev:
            return False
        cache, problems = {}, []
        if available():
            for name in idx.get("names", {}):
                row = self.engine.store.get_source_state(PREFIX + name)
                if not row:
                    continue
                try:
                    cache[name] = decrypt(name, row["blob"], self.tenant)
                except SecretStoreError as e:
                    problems.append(str(e))
        elif idx.get("names"):
            problems.append(f"{len(idx['names'])} key(s) are stored but {MASTER_ENV} is not set")
        self.cache, self.problems, self.rev = cache, problems, idx.get("rev")
        return True

    def set(self, name: str, value: str, actor: str) -> dict[str, Any]:
        from .envsecrets import allowed
        if not allowed(name):
            raise SecretStoreError(f"{name}: keys are named SENTINEL_SECRET_... or SENTINEL_EDGE_..."
                                   + (f" (for this tenant: {self._tenant_prefix()})" if self.tenant else ""))
        value = value.strip()
        if not value:
            raise SecretStoreError("an empty value: use clear to remove a key")
        if len(value) > 16000:
            raise SecretStoreError("the value is too long")
        blob = encrypt(name, value, self.tenant)
        now = self.engine.clock().isoformat()
        st = self.engine.store
        with st.transaction():
            st.lock("secrets")
            idx = self._index()
            idx["names"][name] = {"hint": value[-4:] if len(value) >= 8 else "", "by": actor, "at": now}
            idx["rev"] = int(idx.get("rev", 0)) + 1
            st.put_source_state(PREFIX + name, {"blob": blob})
            st.put_source_state(INDEX, idx)
            st.audit(None, "secret_set", {"name": name, "actor": actor})
        return idx["names"][name]

    def clear(self, name: str, actor: str) -> bool:
        st = self.engine.store
        with st.transaction():
            st.lock("secrets")
            idx = self._index()
            if name not in idx["names"]:
                return False
            del idx["names"][name]
            idx["rev"] = int(idx.get("rev", 0)) + 1
            st.put_source_state(PREFIX + name, {})
            st.put_source_state(INDEX, idx)
            st.audit(None, "secret_cleared", {"name": name, "actor": actor})
        return True

    def _tenant_prefix(self) -> str:
        from .envsecrets import tenant_prefixes
        return tenant_prefixes(self.tenant or "")[0]

    def listing(self) -> dict[str, dict[str, Any]]:
        return dict(self._index().get("names", {}))


_NAME_RE = r"SENTINEL_(?:SECRET|EDGE)_[A-Z0-9_]+"

# Keys the platform itself uses (optional: each turns on a feature)
PLATFORM = {
    "SENTINEL_SECRET_AUDIT_KEY": ("audit trail", "signs the sealed audit chain (any long random value)"),
    "SENTINEL_SECRET_USAGE_KEY": ("usage export", "signs the monthly usage export; KBGrid holds the same value"),
    "SENTINEL_SECRET_BUNDLE_KEY": ("configuration bundles", "signs bundles moved between environments"),
    "SENTINEL_SECRET_SCIM_TOKEN": ("SCIM", "the bearer token the company directory uses for /scim/v2"),
    "SENTINEL_SECRET_CATALOGUE_KEY": ("pack catalogue", "checks the signature of KBGrid's pack catalogue"),
}


def required(engine: Engine) -> list[dict[str, Any]]:
    """Every key the published connectors and models name, with where it is used, what it is (from the
    connector templates), and whether it is set - in the console, in the environment, or not at all."""
    import re

    from . import connectors as templates
    from .envsecrets import source
    uses: dict[str, set[str]] = {}
    for kind in ("connectors", "models"):
        cv = engine.store.published_config(kind)
        text = cv.text if cv is not None else ""
        if kind == "connectors" and not text:
            continue
        current: str | None = None
        for line in text.splitlines():
            m = re.match(r"^  ([A-Za-z0-9_.-]+):\s*$", line) or re.match(r"^  ([A-Za-z0-9_.-]+):\s", line)
            if m and not line.startswith("   "):
                current = m.group(1)
            for name in re.findall(_NAME_RE, line):
                uses.setdefault(name, set()).add(f"{kind}: {current}" if current else kind)
    described: dict[str, str] = {}
    published = engine.store.published_config("connectors")
    published_text = published.text if published is not None else ""
    for t in templates.names():
        tpl = templates.load(t)
        for k, v in (tpl.get("settings") or {}).items():
            described.setdefault(k, v)
        # a template in use: every setting it lists is needed, even ones only the overlay's code reads
        names = [n for sec in (tpl.get("connectors") or {}).values() if isinstance(sec, dict) for n in sec]
        if names and any(re.search(rf"(?m)^  {re.escape(n)}:", published_text) for n in names):
            for k in tpl.get("settings") or {}:
                uses.setdefault(k, set()).add(f"connectors: {tpl.get('title', t)}")
    stored = engine.secrets.listing()
    out = []
    for name in sorted(set(uses) | set(stored) | set(PLATFORM)):
        meta = stored.get(name) or {}
        platform = PLATFORM.get(name)
        out.append({"name": name, "used_by": sorted(uses.get(name, [])) or ([platform[0]] if platform else []),
                    "description": described.get(name) or (platform[1] if platform else ""),
                    "source": source(name), "hint": meta.get("hint", ""), "set_by": meta.get("by"),
                    "set_at": meta.get("at"), "platform": bool(platform) and name not in uses,
                    "unused": name not in uses and not platform})
    return out
