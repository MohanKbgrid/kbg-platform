# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""Connector templates: ready-made connectors configuration for systems Indian businesses run.

    sentinel connector list
    sentinel connector show shiprocket                     # what it reads, does and needs
    sentinel connector add shiprocket --into connectors.yaml

A template is configuration only: login (``auth``), data sources (webhooks and polls that become events),
read-only lookups and HTTP actions, plus the environment variables to set and suggested fingerprint rules
for the events it emits. ``add`` merges it into a connectors file (refusing names that are already there);
publish that file as usual (``sentinel config publish connectors connectors.yaml``). Every action in a template
is honest about undo: only those with a real reverse call are reversible; the rest always need a person until
trust is earned, and customer-facing ones should stay capped at a person.

Endpoints and field names follow each vendor's public API at the time of writing; check them against the
customer's account (and ``sentinel trace`` a sample event) before going live.
"""
from __future__ import annotations

from importlib import resources
from pathlib import Path
from typing import Any

import yaml

_DIR = resources.files(__name__)
SECTIONS = ("auth", "sources", "lookups", "actions", "mcp", "edges")


def names() -> list[str]:
    return sorted(p.name[:-5] for p in _DIR.iterdir() if p.name.endswith(".yaml"))


def load(name: str) -> dict[str, Any]:
    if not name.replace("-", "").replace("_", "").isalnum():
        raise KeyError(f"unknown connector template {name!r}")
    f = _DIR / f"{name}.yaml"
    if not f.is_file():
        raise KeyError(f"unknown connector template {name!r} (known: {names()})")
    return yaml.safe_load(f.read_text(encoding="utf-8"))


def summary(name: str) -> dict[str, Any]:
    t = load(name)
    c = t.get("connectors") or {}
    acts = c.get("actions") or {}
    return {"name": t["name"], "title": t["title"], "description": " ".join(str(t.get("description", "")).split()),
            "settings": t.get("settings") or {}, "events": t.get("events") or [],
            "sources": sorted(c.get("sources") or {}), "lookups": sorted(c.get("lookups") or {}),
            "actions": {n: ("reversible" if a.get("compensate") else "safe" if a.get("safe") else "needs a person")
                        for n, a in sorted(acts.items())},
            "fingerprints": t.get("fingerprints") or []}


def datasets(name: str) -> dict[str, Any]:
    """The template's standard datasets (metrics configuration), by name: the same columns from any system,
    so KPIs and data checks written once read from whichever system the business uses."""
    return dict(load(name).get("datasets") or {})


def with_datasets(metrics: dict[str, Any], sources: str | dict[str, str]) -> dict[str, Any]:
    """``metrics`` with some of its datasets read from connector templates instead: ``"zoho-books"`` (every
    dataset that template provides) or ``{"bank_lines": "tally", "invoices": "zoho-books"}``. The business's own
    owner, description and refresh are kept; the template's checks are added to its own."""
    out = {**metrics, "datasets": dict(metrics.get("datasets") or {})}
    pairs: list[tuple[str, str]]
    if isinstance(sources, str):
        pairs = [(n, sources) for n in datasets(sources)]
    else:
        pairs = list(sources.items())
    for ds_name, tpl in pairs:
        t = datasets(tpl).get(ds_name)
        if t is None:
            raise KeyError(f"connector template {tpl!r} has no dataset {ds_name!r} (it has {sorted(datasets(tpl))})")
        mine = out["datasets"].get(ds_name) or {}
        new = {**t}
        for k in ("owner",):
            if k in mine:
                new[k] = mine[k]
        if mine.get("checks") or t.get("checks"):
            checks = {**(mine.get("checks") or {}), **(t.get("checks") or {})}
            if mine.get("checks", {}).get("invalid") or t.get("checks", {}).get("invalid"):
                checks["invalid"] = {**(mine.get("checks", {}).get("invalid") or {}),
                                     **(t.get("checks", {}).get("invalid") or {})}
            new["checks"] = checks
        if mine.get("vars"):
            new["vars"] = {**(t.get("vars") or {}), **mine["vars"]}
        out["datasets"][ds_name] = new
    return out


def merge(into: dict[str, Any] | None, name: str) -> dict[str, Any]:
    """The connectors document with the template added. Raises ValueError on a name already in use."""
    doc = {k: dict(v) if isinstance(v, dict) else v for k, v in (into or {}).items()}
    t = load(name)
    clashes = []
    for sec in SECTIONS:
        new = (t.get("connectors") or {}).get(sec) or {}
        have = doc.get(sec) or {}
        clashes += [f"{sec}.{k}" for k in new if k in have]
        if new:
            doc[sec] = {**have, **new}
    if clashes:
        raise ValueError(f"already in the connectors file: {clashes}")
    return doc


def add_to_file(name: str, path: str | Path) -> dict[str, Any]:
    p = Path(path)
    current = yaml.safe_load(p.read_text(encoding="utf-8")) if p.exists() else {}
    doc = merge(current or {}, name)
    p.write_text(yaml.safe_dump(doc, sort_keys=False, allow_unicode=True, width=120), encoding="utf-8")
    s = summary(name)
    return {"written": str(p), "set_these": s["settings"], "fingerprints_for_the_registry": s["fingerprints"],
            "next": f"set the variables, add the fingerprints and patterns for {s['events']}, then "
                    f"sentinel config check connectors {p.name} and sentinel config publish connectors {p.name}"}
