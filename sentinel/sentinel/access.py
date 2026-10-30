# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""Access tokens kept in the store, so people and systems can be given access from the console.

Tokens in the tokens file still work (and are how the first administrator gets in). Tokens made here are
stored only as SHA-256 hashes; the token itself is shown once, when it is made. A token is for a person
(the console, the review API) or a service (ingest), may expire, and can be revoked at once. Single
sign-on sessions are tokens of the same kind with a short life.

Giving and revoking access needs the ``__access__`` right (people configuration).
"""
from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timedelta
from typing import Literal

from pydantic import BaseModel, Field

from .models import new_id, utcnow


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


class ApiToken(BaseModel):
    id: str = Field(default_factory=lambda: new_id("tok"))
    hash: str
    kind: Literal["person", "service"]
    principal: str
    label: str = ""
    source: Literal["console", "sso", "cli"] = "console"
    created_by: str = ""
    created_at: datetime = Field(default_factory=utcnow)
    expires_at: datetime | None = None
    revoked_at: datetime | None = None
    revoked_by: str | None = None
    last_used_at: datetime | None = None

    def valid(self, now: datetime) -> bool:
        return self.revoked_at is None and (self.expires_at is None or now < self.expires_at)

    def public(self, now: datetime) -> dict:
        d = self.model_dump(mode="json", exclude={"hash"})
        d["status"] = "revoked" if self.revoked_at else ("expired" if not self.valid(now) else "active")
        return d


class Access:
    """Make, find and revoke stored tokens."""

    USE_WRITE_EVERY = timedelta(minutes=5)       # last_used_at is refreshed at most this often

    def __init__(self, store, clock) -> None:
        self.store, self.clock = store, clock

    def issue(self, kind: str, principal: str, *, by: str, label: str = "", days: float | None = None,
              source: str = "console") -> tuple[str, ApiToken]:
        raw = ("sso_" if source == "sso" else "stk_") + secrets.token_urlsafe(32)
        now = self.clock()
        t = ApiToken(hash=token_hash(raw), kind=kind, principal=principal, label=label, source=source,
                     created_by=by, created_at=now, expires_at=now + timedelta(days=days) if days else None)
        self.store.put_api_token(t)
        self.store.audit(None, "token_issued", {"token": t.id, "kind": kind, "principal": principal, "by": by,
                                                "source": source, "expires_at": t.expires_at})
        return raw, t

    def resolve(self, raw: str) -> ApiToken | None:
        t = self.store.api_token_by_hash(token_hash(raw))
        now = self.clock()
        if t is None or not t.valid(now):
            return None
        if t.last_used_at is None or now - t.last_used_at > self.USE_WRITE_EVERY:
            t.last_used_at = now
            self.store.put_api_token(t)
        return t

    def revoke(self, token_id: str, *, by: str) -> ApiToken:
        t = next((x for x in self.store.api_tokens() if x.id == token_id), None)
        if t is None:
            raise KeyError(token_id)
        if t.revoked_at is None:
            t.revoked_at, t.revoked_by = self.clock(), by
            self.store.put_api_token(t)
            self.store.audit(None, "token_revoked", {"token": t.id, "principal": t.principal, "by": by})
        return t

    def list(self) -> list[dict]:
        now = self.clock()
        return [t.public(now) for t in self.store.api_tokens() if t.source != "sso" or t.valid(now)]
