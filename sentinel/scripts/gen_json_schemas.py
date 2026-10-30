# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""Write schemas/*.schema.json (JSON Schema draft 2020-12) for the YAML Sentinel reads, from the code that reads it.

    python scripts/gen_json_schemas.py            # write
    python scripts/gen_json_schemas.py --check    # exit 1 if a file is out of date (CI; tests/test_json_schemas.py)

(`scripts/gen_schema.py` is the unrelated SQL schema generator.)

Each schema is built from the pydantic models the loaders validate with, so it cannot describe a field the code
does not have. Where the loader checks things a schema cannot express (references between files, expressions,
whether an action exists) the schema says nothing: `sentinel validate` / the console check remain the full
check; the schema is for editors and for catching structure and type mistakes early.

SCHEMA_BASE is a PLACEHOLDER host. Change it here, once, and regenerate; nothing else names it.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

SCHEMA_BASE = "https://kbg-platform.example/schemas/"      # PLACEHOLDER: replace with the real publishing URL
DIALECT = "https://json-schema.org/draft/2020-12/schema"
OUT = Path(__file__).resolve().parent.parent / "schemas"


def _model(cls: Any, defs: dict[str, Any], *, optional: tuple[str, ...] = (), as_name: str = "") -> dict[str, Any]:
    """A $ref to `cls`'s schema; its $defs are folded into `defs`. `optional` fields the loader supplies itself
    (a mapping's key becomes its `name`) are not required in the file."""
    s = cls.model_json_schema(ref_template="#/$defs/{model}")
    for k, v in s.pop("$defs", {}).items():
        defs.setdefault(k, v)
    name = as_name or s.get("title", cls.__name__)
    if optional and "required" in s:
        s["required"] = [r for r in s["required"] if r not in optional]
        if not s["required"]:
            del s["required"]
    defs[name] = s
    return {"$ref": f"#/$defs/{name}"}


def _named(cls: Any, defs: dict[str, Any]) -> dict[str, Any]:
    """A mapping of name -> `cls`, where the key supplies the model's `name`."""
    return {"type": "object", "additionalProperties": _model(cls, defs, optional=("name",))}


def _doc(name: str, title: str, description: str, props: dict[str, Any], defs: dict[str, Any],
         *, closed: bool = True, required: tuple[str, ...] = ()) -> dict[str, Any]:
    d: dict[str, Any] = {"$schema": DIALECT, "$id": SCHEMA_BASE + name, "title": title, "description": description,
                         "type": "object", "properties": props}
    if closed:
        d["additionalProperties"] = False
    if required:
        d["required"] = list(required)
    if defs:
        d["$defs"] = dict(sorted(defs.items()))
    return d


def _str_map() -> dict[str, Any]:
    return {"type": "object", "additionalProperties": {"type": "string"}}


def _any_map() -> dict[str, Any]:
    return {"type": "object", "additionalProperties": True}


def registry_props(defs: dict[str, Any]) -> dict[str, Any]:
    from sentinel.fingerprint import FingerprintRule
    from sentinel.models import CaseDefaults, Capability, Pattern
    return {
        "layer": {"type": "string", "description": "Layer name (defaults to the file stem)."},
        "template": {"type": "string", "description": "Start from a built-in domain template."},
        "version": {"type": ["integer", "string", "null"]},
        "overlay": {"description": "Name of the overlay (code) this registry expects."},
        "roles": {**_str_map(), "description": "role id -> what the role is."},
        "slots": {**_str_map(), "description": "Role slots the templates name: slot -> what it is for."},
        "slot_bindings": {**_str_map(), "description": "slot -> the tenant's role for it."},
        "defaults": _model(CaseDefaults, defs),
        "capabilities": {"type": "object", "additionalProperties": _model(Capability, defs, optional=("id",))},
        "fingerprints": {"type": "array", "items": _model(FingerprintRule, defs)},
        "patterns": {"type": "array", "items": _model(Pattern, defs)},
        "overrides": {"type": "array", "items": {
            "type": "object", "required": ["id"], "additionalProperties": False,
            "properties": {"id": {"type": "string"}, "set": _any_map()}}},
        "disable": {"type": "array", "items": {"type": "string"}},
    }


def people_props(defs: dict[str, Any]) -> dict[str, Any]:
    from sentinel import rbac
    role = _model(rbac.Role, defs, optional=("id",), as_name="RoleKeyed")
    return {
        "version": {"type": ["integer", "string", "null"]},
        "roles": {"description": "role id -> {name, parent, description} or a description string; or a list of roles.",
                  "oneOf": [{"type": "object", "additionalProperties": {"anyOf": [role, {"type": "string"}]}},
                            {"type": "array", "items": _model(rbac.Role, defs)}]},
        "people": {"type": "array", "items": _model(rbac.Person, defs)},
        "assignments": {"type": "array", "items": _model(rbac.Assignment, defs)},
        "authority": {"type": "array", "items": _model(rbac.AuthorityRule, defs)},
        "unattended": {"type": "array", "items": _model(rbac.UnattendedRule, defs)},
        "config_approval": _model(rbac.ConfigApproval, defs),
        "value": _model(rbac.ValueSettings, defs),
        "scim": _model(rbac.ScimSettings, defs),
        "scopes": {"type": "object", "additionalProperties": _model(rbac.ScopeDimension, defs)},
        "stop_at": {"type": "array", "items": {"type": "string"}},
        "vacancy": {"type": "string"},
        "sod": {"description": "Segregation-of-duties pairs."},
        "agents": {"type": "array", "items": _model(rbac.AgentPolicy, defs)},
        "oversight": {"type": "array", "items": _model(rbac.OversightRule, defs)},
    }


def connectors_props(defs: dict[str, Any]) -> dict[str, Any]:
    from sentinel.connauth import AuthSpec
    from sentinel.httpactions import HttpAction, HttpLookup
    from sentinel.mcp import MCPServer
    from sentinel.sources import Source
    return {
        "version": {"type": ["integer", "string", "null"]},
        "sources": _named(Source, defs),
        "mcp": _named(MCPServer, defs),
        "edges": {"type": "object", "additionalProperties": _any_map(),
                  "description": "name -> edge settings (see docs/OPERATIONS.md, Edges)."},
        "actions": _named(HttpAction, defs),
        "lookups": _named(HttpLookup, defs),
        "auth": _named(AuthSpec, defs),
    }


def build() -> dict[str, dict[str, Any]]:
    from sentinel.kpi import Dataset, MetricsDoc
    out: dict[str, dict[str, Any]] = {}

    d: dict[str, Any] = {}
    out["registry.schema.json"] = _doc(
        "registry.schema.json", "Sentinel registry (roles, fingerprints, exception patterns)",
        "A registry.yaml or a registry layer: what `sentinel validate` and the console's Registry page read.",
        registry_props(d), d)

    d = {}
    out["people.schema.json"] = _doc(
        "people.schema.json", "Sentinel people (role tree, people, assignments, authority)",
        "people.yaml: who may do what, where. Cross-references between roles and people are checked by the loader.",
        people_props(d), d)

    d = {}
    from sentinel.models import PlaybookStep  # noqa: F401  (ensures the models import cleanly)
    out["connectors.schema.json"] = _doc(
        "connectors.schema.json", "Sentinel connectors configuration (sources, lookups, actions, auth, mcp, edges)",
        "The `connectors` configuration: connectors.yaml, and the `connectors:` block of a connector template.",
        connectors_props(d), d)

    d = {}
    ct = {
        "name": {"type": "string"}, "title": {"type": "string"}, "description": {"type": "string"},
        "settings": {**_str_map(), "description": "Environment variable -> what to put in it."},
        "events": {"type": "array", "items": {"type": "string"}, "description": "Event types the connector emits."},
        "fingerprints": registry_props(d)["fingerprints"],
        "connectors": {"type": "object", "properties": connectors_props(d), "additionalProperties": False},
        "datasets": {"type": "object", "additionalProperties": _model(Dataset, d)},
    }
    out["connector-template.schema.json"] = _doc(
        "connector-template.schema.json", "Sentinel connector template",
        "A ready-made connector (sentinel/connectors/*.yaml): settings to fill in, events, fingerprint rules and the "
        "connectors configuration it adds.", ct, d, required=("name", "connectors"))

    d = {}
    from sentinel.providers import _PROVIDERS
    model = {"type": "object", "required": ["provider"], "additionalProperties": True,
             "properties": {"provider": {"enum": sorted(_PROVIDERS)}, "model": {"type": "string"},
                            "base_url": {"type": "string"}, "api_key_env": {"type": "string"},
                            "timeout_s": {"type": "number", "exclusiveMinimum": 0},
                            "dim": {"type": "integer", "minimum": 1}, "llm": {"type": "string"}}}
    ref = {"anyOf": [{"type": "string"},
                     {"type": "object", "required": ["model"], "additionalProperties": False,
                      "properties": {"model": {"$ref": "#/$defs/modelRef"}, "fallback": {"$ref": "#/$defs/modelRef"},
                                     "cooldown_s": {"type": "number", "minimum": 0}}}]}
    ref_map = {"type": "object", "additionalProperties": {"$ref": "#/$defs/modelRef"}}
    mdl = _doc("models.schema.json", "Sentinel models (models, routes, fallback, escalation, embedder)",
               "models.yaml: which models answer which tasks. Whether a named model exists is checked by the loader.",
               {"models": {"type": "object", "minProperties": 1, "additionalProperties": {"$ref": "#/$defs/model"}},
                "routes": ref_map, "default": {"$ref": "#/$defs/modelRef"}, "escalate": ref_map,
                "escalate_below": {"type": "number", "minimum": 0, "maximum": 1}, "candidates": ref_map,
                "embedder": {"$ref": "#/$defs/modelRef"}, "daily_budget": {"type": "number", "minimum": 0},
                "prices": {"type": "object", "additionalProperties": {
                    "type": "array", "items": {"type": "number", "minimum": 0}, "minItems": 2, "maxItems": 2},
                    "description": "model -> [price per 1k input tokens, price per 1k output tokens]."}},
               {"model": model, "modelRef": ref}, required=("models",))
    out["models.schema.json"] = mdl

    s = MetricsDoc.model_json_schema(ref_template="#/$defs/{model}")
    defs = s.pop("$defs", {})
    out["metrics.schema.json"] = {
        "$schema": DIALECT, "$id": SCHEMA_BASE + "metrics.schema.json", "title": "Sentinel metrics (KPIs, monitors)",
        "description": "metrics.yaml: datasets, metrics and monitors. SQL snippets are checked by the loader.",
        **{k: v for k, v in s.items() if k not in ("title", "$schema")}, "$defs": dict(sorted(defs.items()))}

    d = {}
    reg, ppl = registry_props(d), people_props(d)
    out["template.schema.json"] = _doc(
        "template.schema.json", "Sentinel domain template",
        "A domain template (sentinel/templates/*.yaml): a starting registry and people tree.",
        {"name": {"type": "string"}, "title": {"type": "string"}, "description": {"type": "string"},
         "registry": {"type": "object", "properties": reg, "additionalProperties": False},
         "people": {"type": "object", "properties": ppl, "additionalProperties": False}},
        d, required=("name", "registry"))
    return out


def render(doc: dict[str, Any]) -> str:
    return json.dumps(doc, indent=2, sort_keys=False, ensure_ascii=False) + "\n"


def main() -> int:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    docs = build()
    if "--check" in sys.argv:
        def stale_file(n: str, d: dict[str, Any]) -> bool:
            return not (OUT / n).exists() or (OUT / n).read_text(encoding="utf-8") != render(d)
        bad = [n for n, d in docs.items() if stale_file(n, d)]
        stale = [p.name for p in OUT.glob("*.schema.json") if p.name not in docs] if OUT.exists() else []
        if bad or stale:
            print(f"out of date: {bad + stale}: run python scripts/gen_json_schemas.py", file=sys.stderr)
            return 1
        return 0
    OUT.mkdir(exist_ok=True)
    for n, d in docs.items():
        (OUT / n).write_text(render(d), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
