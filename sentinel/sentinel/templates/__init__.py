# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""Domain templates: a starting registry (roles, fingerprints, exception patterns) and people tree per domain.

A template is configuration only. It names the actions and outcome verifiers it expects; the project's
overlay implements them in Python. ``needs`` lists them, and validation against a running overlay says
which are still missing - that list is the overlay's to-do list.
"""
from __future__ import annotations

from importlib import resources
from typing import Any

import yaml

_DIR = resources.files(__name__)


def load(name: str) -> dict[str, Any]:
    """The template as data: name, title, description, registry and people."""
    if not name.replace("-", "").replace("_", "").isalnum():
        raise KeyError(f"unknown template {name!r}")
    f = _DIR / f"{name}.yaml"
    if not f.is_file():
        raise KeyError(f"unknown template {name!r}")
    return yaml.safe_load(f.read_text(encoding="utf-8"))


_load = load


def names() -> list[str]:
    return sorted(p.name[:-5] for p in _DIR.iterdir() if p.name.endswith(".yaml"))


def needs(registry: dict[str, Any]) -> dict[str, list[str]]:
    actions: set[str] = set()
    verifiers: set[str] = set()
    for p in registry.get("patterns") or []:
        actions.update(p.get("allowed_actions") or [])
        actions.update(st["action"] for st in p.get("playbook") or [])
        if p.get("outcome_check"):
            verifiers.add(p["outcome_check"]["verifier"])
    return {"actions": sorted(actions), "verifiers": sorted(verifiers)}


def summary(name: str) -> dict[str, Any]:
    t = _load(name)
    reg = t["registry"]
    return {"name": t["name"], "title": t["title"], "description": " ".join(t["description"].split()),
            "patterns": len(reg.get("patterns") or []), "roles": len((t.get("people") or {}).get("roles") or {}),
            "event_types": sorted({f["event_type"] for f in reg.get("fingerprints") or []}), "needs": needs(reg)}


def get(name: str) -> dict[str, Any]:
    """Summary plus ready-to-edit YAML for the registry and people configuration."""
    from ..config import dump_yaml
    t = _load(name)
    return {**summary(name), "registry": dump_yaml(t["registry"]), "people": dump_yaml(t.get("people") or {})}


def all_summaries() -> list[dict[str, Any]]:
    return [summary(n) for n in names()]


def stub_actions(registry: dict[str, Any], into: Any = None) -> Any:
    """Register a stub for every action the template needs that ``into`` (an ActionRegistry) does not have
    yet, so a project can start from a template and run it before its real actions exist. A stub never
    changes anything: it fails without retry, so every case that reaches it ends with a person, and the
    audit says which action is still a stub."""
    from ..actions import ActionRegistry
    from ..models import ActionResult, ActionSpec
    reg = into if into is not None else ActionRegistry()
    for name in needs(registry)["actions"]:
        if reg.has(name):
            continue

        def stub(ctx: Any, params: dict[str, Any], _name: str = name) -> ActionResult:
            return ActionResult(ok=False, retryable=False,
                                detail=f"{_name} is a stub: the overlay has not implemented it yet")
        reg.register(ActionSpec(name=name, description=f"STUB - implement {name} in the overlay", max_attempts=1),
                     stub)
    return reg


def scaffold(name: str) -> dict[str, str]:
    """Files to start a project from a template: a registry layer on top of it, its people tree, and an
    actions module with a stub per action it needs (each says what to implement)."""
    t = load(name)
    need = needs(t["registry"])
    layer = (f"# Project layer on top of the {t['title']} template. Add patterns, change inherited ones with\n"
             f"# overrides, or switch them off with disable. Check with: sentinel template show {name}\n"
             f"template: {name}\nlayer: project\npatterns: []\noverrides: []\ndisable: []\n")
    from ..config import dump_yaml
    lines = ['"""Actions for the ' + t["title"] + ' template. Replace each stub with a call to your system.',
             "",
             "Rules: an action must be idempotent (ctx.idempotency_key), say honestly whether it can be undone",
             '(reversible=True needs a compensator) and return ActionResult(ok=..., detail=...)."""',
             "from sentinel import ActionRegistry, ActionResult", "", "actions = ActionRegistry()", ""]
    for a in need["actions"]:
        lines += ["", f'@actions.action("{a}", description="TODO", params={{}})',
                  f"def {a.replace('-', '_').replace('.', '_')}(ctx, params):",
                  f'    raise NotImplementedError("{a}: call your system here")', ""]
    if need["verifiers"]:
        lines += ["", "# Outcome verifiers this template uses (overlay.verifiers):"]
        lines += [f"#   {v}(*, incident, disposition, params, services) -> True (held) | False | None (not yet)"
                  for v in need["verifiers"]]
    return {"registry.yaml": layer, "people.yaml": dump_yaml(t.get("people") or {}),
            "actions.py": "\n".join(lines).rstrip() + "\n"}
