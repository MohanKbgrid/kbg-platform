# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""Environments and configuration bundles: build in dev, check in staging, promote the same thing to production.

Each site names its environment with ``SENTINEL_ENV`` (``dev``, ``staging``, ``prod`` or any name); it shows
in ``/healthz``, on the console and on every bundle. A bundle is the published configuration of chosen kinds
(registry, models, connectors; people usually differ per environment and are left out unless asked for),
with a checksum per kind, a digest, and an HMAC signature made with ``SENTINEL_SECRET_BUNDLE_KEY`` when set.

Importing checks the signature, refuses a bundle from an environment the site does not accept
(``SENTINEL_ENV_ACCEPTS=staging`` on production), checks every kind against this site's actions, tools and
people, then saves and publishes all changed kinds together, through the same rights and maker-checker as the
console. Nothing is published when any kind has an error.
"""
from __future__ import annotations
from .envsecrets import lookup as _lookup

import difflib
import hashlib
import hmac
import json
import os
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .engine import Engine

ENV = "SENTINEL_ENV"
ACCEPTS = "SENTINEL_ENV_ACCEPTS"
KEY_ENV = "SENTINEL_SECRET_BUNDLE_KEY"
FORMAT = "sentinel-bundle/1"
DEFAULT_KINDS = ("registry", "models", "connectors")


def environment() -> str:
    return os.environ.get(ENV, "").strip() or "unnamed"


def _canonical(doc: dict[str, Any]) -> bytes:
    return json.dumps({k: v for k, v in doc.items() if k not in ("digest", "signature")}, sort_keys=True,
                      separators=(",", ":"), default=str).encode()


def _sum(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def export(engine: Engine, kinds: list[str] | None = None, *, key: str | None = None,
           note: str = "") -> dict[str, Any]:
    from .config import KINDS
    from .usage import _version
    kinds = list(kinds or DEFAULT_KINDS)
    bad = [k for k in kinds if k not in KINDS]
    if bad:
        raise ValueError(f"unknown kinds {bad} (known: {list(KINDS)})")
    configs = {}
    for k in kinds:
        cv = engine.store.published_config(k)
        text = engine.config_text(k)
        configs[k] = {"text": text, "checksum": _sum(text), "version": cv.version if cv else None}
    doc = {"format": FORMAT, "env": environment(), "overlay": engine.overlay.name, "sentinel": _version(),
           "created": engine.clock().isoformat(), "note": note, "configs": configs}
    doc["digest"] = hashlib.sha256(_canonical(doc)).hexdigest()
    secret = key if key is not None else _lookup(KEY_ENV)
    if secret:
        doc["signature"] = hmac.new(secret.encode(), _canonical(doc), hashlib.sha256).hexdigest()
    engine.store.audit(None, "bundle_exported", {"kinds": kinds, "digest": doc["digest"], "env": doc["env"]})
    return doc


def verify(doc: dict[str, Any], key: str | None) -> list[str]:
    out = []
    if doc.get("format") != FORMAT:
        return [f"not a configuration bundle (format {doc.get('format')!r})"]
    if hashlib.sha256(_canonical(doc)).hexdigest() != doc.get("digest"):
        out.append("the bundle was changed after it was exported (digest mismatch)")
    for k, c in (doc.get("configs") or {}).items():
        if _sum(c.get("text", "")) != c.get("checksum"):
            out.append(f"{k}: checksum mismatch")
    if key:
        sig = doc.get("signature")
        if not sig:
            out.append("not signed (the exporting site had no bundle key)")
        elif not hmac.compare_digest(hmac.new(key.encode(), _canonical(doc), hashlib.sha256).hexdigest(), sig):
            out.append("the signature does not match this key")
    return out


def plan(engine: Engine, doc: dict[str, Any]) -> dict[str, Any]:
    """What importing would change, per kind: unchanged or a diff, and the problems this site finds."""
    out = {}
    for k, c in doc["configs"].items():
        cur = engine.config_text(k)
        _, probs = engine.check_config(k, c["text"])
        out[k] = {"changed": _sum(cur) != c["checksum"],
                  "diff": "".join(difflib.unified_diff(cur.splitlines(True), c["text"].splitlines(True),
                                                       f"{environment()}/{k}", f"{doc['env']}/{k}")),
                  "problems": [{"severity": p.severity, "message": p.message} for p in probs]}
    return out


def accepts(source_env: str) -> bool:
    allowed = [x.strip() for x in os.environ.get(ACCEPTS, "").split(",") if x.strip()]
    return not allowed or source_env in allowed


def import_bundle(engine: Engine, doc: dict[str, Any], actor: str, *, key: str | None = None,
                  note: str = "") -> dict[str, Any]:
    """Check and publish a bundle's changed kinds together. Raises ValueError when it cannot be imported;
    ``ApprovalNeeded`` (from the engine) when maker-checker holds it for a second person."""
    key = key if key is not None else _lookup(KEY_ENV)
    problems = verify(doc, key)
    if problems:
        raise ValueError("; ".join(problems))
    if not accepts(doc["env"]):
        raise ValueError(f"this site ({environment()}) accepts bundles only from {os.environ.get(ACCEPTS)}; "
                         f"this one is from {doc['env']}")
    p = plan(engine, doc)
    errors = {k: [x["message"] for x in v["problems"] if x["severity"] == "error"] for k, v in p.items()}
    errors = {k: v for k, v in errors.items() if v}
    if errors:
        raise ValueError(f"the bundle does not fit this site: {errors}")
    changed = [k for k, v in p.items() if v["changed"]]
    if not changed:
        return {"published": [], "unchanged": sorted(p)}
    why = note or f"bundle {doc['digest'][:12]} from {doc['env']}"
    ids = [engine.save_config(k, doc["configs"][k]["text"], actor, why)[0].id for k in changed]
    engine.store.audit(None, "bundle_imported", {"kinds": changed, "digest": doc["digest"], "from": doc["env"],
                                                 "actor": actor})
    pub = engine.publish_config_set(ids, actor)     # ApprovalNeeded propagates: a second person approves
    return {"published": [{"kind": cv.kind, "version": cv.version} for cv in pub],
            "unchanged": sorted(set(p) - set(changed))}
