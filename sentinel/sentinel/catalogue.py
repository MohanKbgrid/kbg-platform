# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""The pack catalogue: what packs exist, which fit this site, and adding one safely.

KBGrid builds a catalogue from a folder of packs (each a directory with ``sentinel-pack.yaml``)::

    sentinel pack catalogue build packs/ --out catalogue.json

Each entry carries the pack's id, version, title, industry, what it provides, the capabilities its actions
and tools need, the settings it asks for, the exceptions its layers define, and a SHA-256 digest of every
file in it. With ``SENTINEL_SECRET_CATALOGUE_KEY`` set the catalogue is signed (HMAC).

A site searches it and adds a pack::

    sentinel pack search dairy --catalogue catalogue.json
    sentinel pack add kbgrid.dairy-dsd --catalogue catalogue.json --packs-file packs.yaml

``add`` picks the newest version that works with this Sentinel, checks the files against the digest, copies
the pack (and any packs it needs that the site lacks) next to the packs file, and lists it there with empty
settings and **no capabilities granted**: the output says which settings to fill and which capabilities the
site may grant. Adding a newer version of a listed pack replaces its files and keeps its settings and grants.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import shutil
from pathlib import Path
from typing import Any

import yaml

from .envsecrets import lookup as _lookup
from .packs import MANIFEST, PackError, _req, parse_version, read_pack, satisfies

FORMAT = "sentinel-catalogue/1"
KEY_ENV = "SENTINEL_SECRET_CATALOGUE_KEY"
SKIP = {"__pycache__", ".git", ".pytest_cache"}


def tree_digest(root: str | Path) -> str:
    """SHA-256 over every file's relative path and bytes, in a fixed order."""
    root = Path(root)
    h = hashlib.sha256()
    for f in sorted(p for p in root.rglob("*") if p.is_file() and not (set(p.relative_to(root).parts) & SKIP)):
        rel = f.relative_to(root).as_posix()
        h.update(rel.encode() + b"\0")
        h.update(hashlib.sha256(f.read_bytes()).digest())
    return h.hexdigest()


def _exceptions(root: Path, layers: list[str]) -> list[str]:
    out = []
    for x in layers:
        try:
            data = yaml.safe_load((root / x).read_text(encoding="utf-8")) or {}
        except OSError:
            continue
        out += [p.get("id") for p in data.get("patterns") or [] if isinstance(p, dict) and p.get("id")]
    return out


def entry(root: str | Path, base: str | Path) -> dict[str, Any]:
    p = read_pack(root)
    m = p.manifest
    caps = sorted({c for kind in m.provides.values() for x in kind for c in x.capabilities})
    return {"id": m.id, "version": m.version, "title": m.title or m.id, "description": m.description,
            "industry": m.industry, "tags": m.tags, "namespace": m.namespace, "sentinel": m.sentinel,
            "requires": m.requires, "settings": m.config_schema, "capabilities": caps,
            "provides": {k: [x.name for x in v] for k, v in m.provides.items()},
            "exceptions": _exceptions(Path(root), m.layers), "has_golden": bool(m.golden),
            "path": os.path.relpath(Path(root).resolve(), Path(base).resolve()).replace(os.sep, "/"),
            "sha256": tree_digest(root)}


def _canonical(doc: dict[str, Any]) -> bytes:
    return json.dumps({k: v for k, v in doc.items() if k != "signature"}, sort_keys=True,
                      separators=(",", ":")).encode()


def build(folder: str | Path, *, key: str | None = None, relative_to: str | Path | None = None) -> dict[str, Any]:
    """Paths in the catalogue are relative to ``relative_to``: the folder the catalogue file will be in."""
    folder = Path(folder)
    rel_base = Path(relative_to) if relative_to is not None else folder
    entries, problems = [], []
    for mf in sorted(folder.rglob(MANIFEST)):
        if set(mf.relative_to(folder).parts) & SKIP:
            continue
        try:
            entries.append(entry(mf.parent, rel_base))
        except PackError as e:
            problems.append(str(e))
    seen = set()
    for e in entries:
        if (e["id"], e["version"]) in seen:
            problems.append(f"{e['id']} {e['version']} appears twice")
        seen.add((e["id"], e["version"]))
    entries.sort(key=lambda e: (e["id"], parse_version(e["version"])))
    doc = {"format": FORMAT, "packs": entries, "problems": problems}
    secret = key if key is not None else _lookup(KEY_ENV)
    if secret:
        doc["signature"] = hmac.new(secret.encode(), _canonical(doc), hashlib.sha256).hexdigest()
    return doc


def load(path: str | Path, *, key: str | None = None) -> dict[str, Any]:
    doc = json.loads(Path(path).read_text(encoding="utf-8"))
    if doc.get("format") != FORMAT:
        raise PackError(f"{path} is not a pack catalogue")
    secret = key if key is not None else _lookup(KEY_ENV)
    if secret:
        sig = doc.get("signature")
        if not sig or not hmac.compare_digest(sig, hmac.new(secret.encode(), _canonical(doc),
                                                            hashlib.sha256).hexdigest()):
            raise PackError(f"{path}: the catalogue signature does not match this site's key")
    doc["_root"] = str(Path(path).resolve().parent)
    return doc


def _sv(sentinel_version: str | None) -> str:
    from . import __version__
    return sentinel_version or __version__


def search(cat: dict[str, Any], text: str = "", *, industry: str = "",
           sentinel_version: str | None = None) -> list[dict[str, Any]]:
    """The newest version of each matching pack, with whether it works with this Sentinel."""
    sv = _sv(sentinel_version)
    q = text.strip().lower()
    best: dict[str, dict[str, Any]] = {}
    for e in cat["packs"]:
        hay = " ".join([e["id"], e["title"], e["description"], e["industry"], *e["tags"], *e["exceptions"]]).lower()
        if q and q not in hay:
            continue
        if industry and e["industry"].lower() != industry.lower():
            continue
        fits = not e["sentinel"] or satisfies(sv, e["sentinel"])
        cur = best.get(e["id"])
        # prefer versions that fit, then the newest
        rank = (fits, parse_version(e["version"]))
        if cur is None or rank > (cur["fits"], parse_version(cur["version"])):
            best[e["id"]] = {**e, "fits": fits}
    return sorted(best.values(), key=lambda e: e["id"])


def pick(cat: dict[str, Any], pack_id: str, version: str = "", *, sentinel_version: str | None = None) -> dict:
    sv = _sv(sentinel_version)
    cands = [e for e in cat["packs"] if e["id"] == pack_id and (not version or satisfies(e["version"], version))]
    if not cands:
        raise PackError(f"{pack_id}{' ' + version if version else ''} is not in the catalogue")
    fit = [e for e in cands if not e["sentinel"] or satisfies(sv, e["sentinel"])]
    if not fit:
        raise PackError(f"no version of {pack_id} works with Sentinel {sv} "
                        f"(the catalogue has {sorted({e['version'] for e in cands})})")
    return max(fit, key=lambda e: parse_version(e["version"]))


def add(cat: dict[str, Any], pack_id: str, packs_file: str | Path, *, version: str = "", dest: str = "packs",
        sentinel_version: str | None = None) -> dict[str, Any]:
    pf = Path(packs_file)
    spec = yaml.safe_load(pf.read_text(encoding="utf-8")) if pf.exists() else {}
    spec = spec or {}
    listed = {x.get("id"): x for x in spec.get("packs") or []}
    added, upgraded, todo = [], [], [(pack_id, version)]
    plan: list[dict[str, Any]] = []
    while todo:
        pid, rng = todo.pop()
        if pid in listed and pid != pack_id:
            have = read_pack(pf.parent / listed[pid]["path"]).manifest.version if listed[pid].get("path") else None
            if have and (not rng or satisfies(have, rng)):
                continue
        if any(x["id"] == pid for x in plan):
            continue
        e = pick(cat, pid, rng, sentinel_version=sentinel_version)
        plan.append(e)
        todo += [_req(r) for r in e["requires"]]
    for e in plan:
        src = Path(cat["_root"]) / e["path"]
        if not (src / MANIFEST).is_file():
            raise PackError(f"{e['id']} {e['version']}: {src} is missing (keep the catalogue next to its packs)")
        if tree_digest(src) != e["sha256"]:
            raise PackError(f"{e['id']} {e['version']}: files differ from the catalogue (digest mismatch)")
    entries = list(spec.get("packs") or [])
    for e in reversed(plan):                           # dependencies first in the file
        rel = f"{dest}/{e['id']}-{e['version']}"
        target = pf.parent / rel
        if target.exists():
            shutil.rmtree(target)
        shutil.copytree(Path(cat["_root"]) / e["path"], target, ignore=shutil.ignore_patterns(*SKIP))
        old = listed.get(e["id"])
        if old is not None:
            old_path = old.get("path")
            old["path"] = rel
            upgraded.append({"id": e["id"], "version": e["version"], "from": old_path})
        else:
            item = {"id": e["id"], "path": rel, "config": {}, "grant": []}
            entries.append(item)
            listed[e["id"]] = item
            added.append({"id": e["id"], "version": e["version"]})
    spec["packs"] = entries
    pf.write_text(yaml.safe_dump(spec, sort_keys=False, allow_unicode=True), encoding="utf-8")
    todo_settings = {e["id"]: [k for k in e["settings"] if k not in (listed[e["id"]].get("config") or {})]
                     for e in plan}
    to_grant = {e["id"]: [c for c in e["capabilities"] if c not in (listed[e["id"]].get("grant") or [])]
                for e in plan}
    return {"added": added, "upgraded": upgraded,
            "settings_to_fill": {k: v for k, v in todo_settings.items() if v},
            "capabilities_to_grant": {k: v for k, v in to_grant.items() if v},
            "next": f"fill the settings and grant what you accept in {pf.name}, then: sentinel pack check {pf.name}"}
