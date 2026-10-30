# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""Versioned configuration: the exception registry, people and models, edited as drafts and published.

Three kinds of configuration change without code:

  registry   roles, fingerprints and exception patterns         (YAML, same format as registry.yaml)
  people     role tree, people, scoped assignments, authority   (same format as people.yaml)
  models     models, routes, fallback, escalation, embedder     (same format as models.yaml)

Every save is a numbered version. A version is checked before it can be published: errors block it
(unknown actions, roles nobody defined, a broken role tree), warnings do not (a queue nobody can act on,
an event type with no fingerprint rule). Publishing needs the ``__configure__`` right when people are
configured. The published version is what every process runs: the engine applies it at once, and other
processes (workers, other API instances) pick it up on their next sync. Rolling back is publishing an
older version again, which records it as a new version so history stays linear.

Actions, read-only tools and receivers stay in the overlay's Python code - configuration can only use
what the overlay provides, and validation says exactly which actions a template still needs.
"""
from __future__ import annotations

import difflib
import hashlib
import os
from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING, Any

import yaml
from pydantic import BaseModel, Field

from .models import Pattern, new_id, utcnow

if TYPE_CHECKING:
    from .actions import ActionRegistry
    from .fingerprint import FingerprintRule
    from .rbac import Directory

KINDS = ("registry", "people", "models", "connectors", "metrics")


class ConfigError(ValueError):
    def __init__(self, message: str, problems: list[Problem] | None = None) -> None:
        super().__init__(message)
        self.problems = problems or []


@dataclass(frozen=True)
class Problem:
    severity: str          # error | warning
    message: str

    def to_dict(self) -> dict[str, str]:
        return {"severity": self.severity, "message": self.message}


class ApprovalNeeded(Exception):  # noqa: N818 - a state, not a failure
    """Publishing waits for approval by other people (maker-checker). Carries the versions waiting."""

    def __init__(self, message: str, versions: list[Any]) -> None:
        super().__init__(message)
        self.versions = versions


class ConfigVersion(BaseModel):
    id: str = Field(default_factory=lambda: new_id("cfg"))
    kind: str
    version: int
    status: str = "draft"                 # draft | published | superseded
    text: str
    author: str
    note: str = ""
    checksum: str = ""
    created_at: datetime = Field(default_factory=utcnow)
    published_at: datetime | None = None
    published_by: str | None = None
    copied_from: str | None = None
    approvals: list[str] = Field(default_factory=list)      # people who approved this exact version
    requested_by: str | None = None                         # asked to publish it while approvals were missing
    requested_with: list[str] = Field(default_factory=list)  # versions to be published together with it
    layer: dict[str, Any] | None = None                     # registry: this version as changes to the code / packs
    base_checksum: str | None = None                        # registry: the code / packs it was compared with

    def model_post_init(self, _ctx: Any) -> None:
        if self.kind not in KINDS:
            raise ValueError(f"kind must be one of {KINDS}")
        if not self.checksum:
            self.checksum = hashlib.sha256(self.text.encode()).hexdigest()[:16]

    def summary(self) -> dict[str, Any]:
        return self.model_dump(mode="json", exclude={"text"})


# ---- serialising the running configuration -----------------------------------------

def _tidy(x: Any) -> Any:
    """24.0 -> 24, recursively, so YAML written from objects and from edited JSON read the same."""
    if isinstance(x, float) and x.is_integer():
        return int(x)
    if isinstance(x, dict):
        return {k: _tidy(v) for k, v in x.items()}
    if isinstance(x, list):
        return [_tidy(v) for v in x]
    return x


def dump_yaml(doc: dict[str, Any]) -> str:
    return yaml.safe_dump(_tidy(doc), sort_keys=False, allow_unicode=True, width=110, default_flow_style=None)


_PATTERN_SKIP = {"layer", "overridden_in"}


def _slot_skip(p: Pattern) -> set[str]:
    """A slotted pattern is written with its slot only: the role comes from slot_bindings when it is read back,
    so rebinding a slot never leaves a stale role behind in the document."""
    return ({"owner_role"} if p.owner_slot else set()) | ({"escalation_role"} if p.escalation_slot else set())


def registry_doc(roles: dict[str, str], fingerprints: list[FingerprintRule], patterns: list[Pattern],
                 defaults: dict[str, Any] | None = None, capabilities: dict[str, Any] | None = None,
                 slots: dict[str, str] | None = None, slot_bindings: dict[str, str] | None = None) -> dict:
    roles = dict(roles)
    bindings = dict(slot_bindings or {})
    for p in patterns:                      # every role a pattern names is listed, so the document is complete
        for r in filter(None, (p.owner_role, p.escalation_role)):
            roles.setdefault(r, r)
        for sid, r in ((p.owner_slot, p.owner_role), (p.escalation_slot, p.escalation_role)):
            if sid and r:                   # resolved patterns carry their binding: keep it in the document
                bindings.setdefault(sid, r)
    return {
        "roles": roles,
        **({"slots": dict(slots)} if slots else {}),
        **({"slot_bindings": bindings} if bindings else {}),
        "fingerprints": [r.model_dump(mode="json", exclude_defaults=True) for r in fingerprints],
        "patterns": [{"id": p.id, **{k: v for k, v in p.model_dump(mode="json", exclude_defaults=True,
                                                                   exclude=_PATTERN_SKIP | {"id"} | _slot_skip(p)
                                                                   ).items()
                                     if k != "playbook"},
                      **({"playbook": [st.plain() for st in p.playbook]} if p.playbook else {})}
                     for p in patterns],
        **({"defaults": dict(defaults)} if defaults else {}),
        **({"capabilities": {cid: (c.model_dump(mode="json", exclude_defaults=True) if hasattr(c, "model_dump")
                                   else dict(c)) for cid, c in capabilities.items()}} if capabilities else {}),
    }


def doc_checksum(doc: dict) -> str:
    import json as _json
    return hashlib.sha256(_json.dumps(doc, sort_keys=True, default=str).encode()).hexdigest()[:16]


def registry_layer(base: dict, new: dict) -> dict:
    """``new`` as a layer over ``base``: patterns added, fields changed (overrides), patterns removed (disable),
    fingerprint rules and roles added or changed. Applying it to ``base`` gives ``new`` back; applying it to a
    newer base keeps these changes and takes everything else from the new base."""
    from .models import Pattern
    defaults = Pattern(id="x", event_types=["x"]).model_dump(mode="json")
    bp = {p["id"]: p for p in base.get("patterns") or []}
    np_ = {p["id"]: p for p in new.get("patterns") or []}
    layer: dict[str, Any] = {"layer": "console"}
    added = [p for pid, p in np_.items() if pid not in bp]
    removed = [pid for pid in bp if pid not in np_]
    overrides = []
    for pid, p in np_.items():
        if pid not in bp:
            continue
        b = bp[pid]
        changes = {k: v for k, v in p.items() if k != "id" and b.get(k, defaults.get(k)) != v}
        changes.update({k: defaults.get(k) for k in b if k not in p and k != "id" and b[k] != defaults.get(k)})
        if changes:
            overrides.append({"id": pid, "set": changes})
    bf = {r["event_type"]: r for r in base.get("fingerprints") or []}
    fps = [r for r in new.get("fingerprints") or [] if bf.get(r["event_type"]) != r]
    roles = {k: v for k, v in (new.get("roles") or {}).items() if (base.get("roles") or {}).get(k) != v}
    for key in ("slots", "slot_bindings"):     # a tenant's rebinding is kept as a layer like any other change
        changed = {k: v for k, v in (new.get(key) or {}).items() if (base.get(key) or {}).get(k) != v}
        if changed:
            layer[key] = changed
    if (new.get("defaults") or {}) != (base.get("defaults") or {}):
        layer["defaults"] = new.get("defaults") or {}
    bc = base.get("capabilities") or {}
    caps = {k: v for k, v in (new.get("capabilities") or {}).items() if bc.get(k) != v}
    if caps:
        layer["capabilities"] = caps
    for k, v in (("patterns", added), ("overrides", overrides), ("disable", removed), ("fingerprints", fps),
                 ("roles", roles)):
        if v:
            layer[k] = v
    return layer


def apply_layer(base: dict, layer: dict) -> Any:
    """The registry ``base`` + ``layer`` (overlay.load_layers semantics). Raises LayerError on conflicts."""
    from .overlay import load_layers
    keep = ("roles", "fingerprints", "patterns", "defaults", "capabilities", "slots", "slot_bindings")
    return load_layers([("base", {k: v for k, v in base.items() if k in keep}),
                        ("console", {k: v for k, v in layer.items() if k != "layer"})])


def directory_doc(d: Directory) -> dict:
    roles = {}
    for r in d.roles.values():
        roles[r.id] = {k: v for k, v in r.model_dump(exclude={"id"}).items() if v not in (None, "", [])}
    return {
        "roles": roles,
        "people": [p.model_dump(mode="json", exclude_defaults=True) | {"id": p.id} for p in d.people.values()],
        "assignments": [a.model_dump(mode="json", exclude_defaults=True) for a in d.assignments],
        "authority": [r.model_dump(mode="json", exclude_defaults=True) for r in d.rules],
        **({"unattended": [r.model_dump(mode="json", exclude_defaults=True) for r in d.unattended]}
           if d.unattended else {}),
        **({"config_approval": d.config_approval.model_dump(mode="json")} if d.config_approval else {}),
        **({"value": d.value.model_dump(mode="json")} if getattr(d, "value", None) else {}),
        **({"scim": d.scim.model_dump(mode="json", exclude_defaults=True)} if getattr(d, "scim", None) else {}),
        **({"scopes": {k: v.model_dump(mode="json", exclude_defaults=True) for k, v in d.scopes.items()}}
           if getattr(d, "scopes", None) else {}),
        **({"stop_at": list(d.stop_at)} if getattr(d, "stop_at", None) else {}),
        **({"vacancy": d.vacancy} if getattr(d, "vacancy", "off") != "off" else {}),
        **({"sod": [r.model_dump(mode="json", exclude_defaults=True) for r in d.sod]}
           if getattr(d, "sod", None) else {}),
        **({"agents": [a.model_dump(mode="json", exclude_defaults=True) for a in d.agents]}
           if getattr(d, "agents", None) else {}),
        **({"oversight": [o.model_dump(mode="json", exclude_defaults=True) for o in d.oversight]}
           if getattr(d, "oversight", None) else {}),
    }


def diff(a: str, b: str, a_name: str = "published", b_name: str = "draft") -> str:
    return "".join(difflib.unified_diff(a.splitlines(keepends=True), b.splitlines(keepends=True),
                                        fromfile=a_name, tofile=b_name))


# ---- parsing and validation -----------------------------------------------------------

def _load_text(text: str) -> Any:
    try:
        data = yaml.safe_load(text) if text.strip() else {}
    except yaml.YAMLError as e:
        mark = getattr(e, "problem_mark", None)
        where = f" (line {mark.line + 1}, column {mark.column + 1})" if mark is not None else ""
        raise ConfigError(f"not valid YAML{where}: {getattr(e, 'problem', e)}") from None
    if not isinstance(data, dict):
        raise ConfigError("the top level must be a mapping (key: value)")
    return data


class _Stub:
    """Stands in for a model while checking a models file's structure (no network, no keys needed)."""

    def __init__(self, spec: dict[str, Any]) -> None:
        self.model = str(spec.get("model") or f"hashing-{spec.get('dim', 256)}")
        if spec.get("provider") != "hashing":
            self.complete = lambda system, messages: "{}"
        if spec.get("provider") in ("ollama", "openai_compatible", "hashing"):
            self.embed = lambda texts: [[0.0] for _ in texts]


def _stub_factory(spec: dict[str, Any]) -> Any:
    from .providers import _PROVIDERS
    provider = spec.get("provider")
    if provider not in _PROVIDERS:
        raise ValueError(f"provider must be one of {_PROVIDERS}, got {provider!r}")
    if provider != "hashing" and not spec.get("model"):
        raise ValueError(f"{provider}: 'model' is required")
    return _Stub(spec)


@dataclass
class Context:
    """What a configuration is checked against: the overlay's code and the other configuration kinds."""
    actions: ActionRegistry
    verifiers: dict[str, Any]
    edges: set[str]
    fingerprints: list[FingerprintRule]
    patterns: list[Pattern]
    roles: dict[str, str]
    directory: Directory | None
    tools: list[dict[str, Any]] = ()  # type: ignore[assignment]   # lookup tools available (name, params)
    base_edges: set[str] = frozenset()  # type: ignore[assignment]  # edges the overlay's code provides
    mcp_commands: list[list[str]] = ()  # type: ignore[assignment]  # stdio MCP commands the overlay allows
    code_actions: set[str] = frozenset()  # type: ignore[assignment]  # actions the overlay implements in code
    metric_names: set[str] | None = None   # the running metrics (None: no metrics configured)
    capabilities: dict[str, Any] = None  # type: ignore[assignment]   # the running registry's capabilities
    all_tools: set[str] | None = None      # every lookup available now (the overlay's and the connectors')
    binding: Any = None                    # the pack's domain binding (ADR-005), checked on registry publish


def coverage_warnings(fingerprints: list[FingerprintRule], patterns: list[Pattern],
                      directory: Directory | None) -> list[str]:
    """Patterns nobody can act on: their role has no active people, or everyone is scoped on facts the
    pattern's incidents never carry."""
    if directory is None:
        return []
    produced: dict[str, set[str]] = {}
    for rule in fingerprints:
        produced[rule.event_type] = set(rule.fields) | set(rule.buckets) | {"event_type", "source"}
    warnings = []
    for p in patterns:
        facts = set().union(*[produced.get(t, {"event_type", "source"}) for t in p.event_types])
        for role in filter(None, sorted({p.owner_role, p.escalation_role or ""})):
            def active(a: Any) -> bool:
                return a.person_id in directory.people and directory.people[a.person_id].active
            above = directory.ancestors(role) if role in directory.roles else []
            own = [a for a in directory.assignments if a.role_id == role and active(a)]
            holders = own or [a for a in directory.assignments if a.role_id in above and active(a)]
            if not holders:
                warnings.append(f"{p.id}: role {role!r} has no active people, and nobody above it either")
                continue
            if not own:
                warnings.append(f"{p.id}: role {role!r} has no people of its own; only "
                                f"{sorted({a.role_id for a in holders})} above it see its queue")
            if all(set(a.scope) - facts for a in holders):
                need = sorted({k for a in holders for k in a.scope} - facts)
                warnings.append(f"{p.id}: everyone in role {role!r} is scoped on {need}, which "
                                f"{p.event_types} incidents never carry; nobody in that role can act")
    return warnings


def _check_registry(data: dict, ctx: Context) -> tuple[Any, list[Problem]]:
    from .overlay import parse_registry
    from .registry import Registry
    probs: list[Problem] = []
    try:
        doc = parse_registry(data, "registry")
    except Exception as e:  # noqa: BLE001 - shown to the person editing
        return None, [Problem("error", str(e))]
    ids = [p.id for p in doc.patterns]
    for dup in sorted({i for i in ids if ids.count(i) > 1}):
        probs.append(Problem("error", f"pattern id {dup!r} is used more than once"))
    try:
        reg = Registry(doc.patterns)
    except Exception as e:  # noqa: BLE001
        return None, [*probs, Problem("error", str(e))]
    tools = {t["name"]: t.get("params") or {} for t in ctx.tools} if ctx.tools else None
    for msg in reg.validate(ctx.actions, tools):
        hint = " - the overlay must implement it" if "is not registered" in msg else ""
        probs.append(Problem("error", msg + hint))
    for p in doc.patterns:
        if p.outcome_check and p.outcome_check.get("verifier") not in ctx.verifiers:
            probs.append(Problem("error", f"{p.id}: outcome_check verifier {p.outcome_check.get('verifier')!r} "
                                          "is not provided by the overlay"))
        if p.route.value == "auto" and not any(st.kind in ("action", "close") for st in p.playbook):
            probs.append(Problem("error", f"{p.id}: route auto needs a playbook"))
    fp_types = {r.event_type for r in doc.fingerprints}
    for p in doc.patterns:
        missing = [t for t in p.event_types if t not in fp_types and t != "*"]
        if missing:
            probs.append(Problem("warning", f"{p.id}: no fingerprint rule for {missing}; incidents will carry "
                                            "no facts to match or group on"))
        if p.clear_when:
            carried = set().union(*[set(r.fields) | set(r.buckets) for r in doc.fingerprints
                                    if r.event_type in p.event_types] or [set()])
            for ce in p.clear_when.events:
                unknown = [k for k in ce.same if k not in carried]
                if unknown:
                    probs.append(Problem("warning", f"{p.id}: clear_when {ce.type}: {unknown} is not a fact its "
                                                    "cases carry; that event can never close them"))
                if ce.type in p.event_types:
                    probs.append(Problem("error", f"{p.id}: clear_when {ce.type} is also an event that raises it"))
        if p.trust_pool_min and not p.trust_by:
            probs.append(Problem("warning", f"{p.id}: trust_pool_min without trust_by does nothing (there is only "
                                            "one scope to pool)"))
        if p.trust_by:
            carried = set().union(*[set(r.fields) | set(r.buckets) for r in doc.fingerprints
                                    if r.event_type in p.event_types] or [set()])
            unknown = [k for k in p.trust_by if k not in carried]
            if unknown:
                probs.append(Problem("warning", f"{p.id}: trust_by {unknown} is not a fact its events carry; every "
                                                "case would share one segment"))
    if ctx.directory is not None:
        from .models import CaseDefaults
        dflt = CaseDefaults.model_validate(doc.defaults or {}).escalation
        for p in doc.patterns:
            rule = p.escalation or dflt
            tops = rule.stops() if rule else []
            for top in tops:
                if top not in ctx.directory.roles:
                    probs.append(Problem("error", f"{p.id}: escalation stop_at {top!r} is not a role"))
            path = {p.owner_role, *(ctx.directory.ancestors(p.owner_role) if p.owner_role in ctx.directory.roles
                                    else []), *([p.escalation_role] if p.escalation_role else [])}
            if p.escalation_role and p.escalation_role in ctx.directory.roles:
                path |= set(ctx.directory.ancestors(p.escalation_role))
            if tops and not path & set(tops) and p.escalation is not None:
                probs.append(Problem("warning", f"{p.id}: escalation stop_at {tops} is not above {p.owner_role}; "
                                                "it will climb to the top of the tree"))
        everything = [*doc.patterns, reg.fallback]          # unmatched events go to the fallback's role
        for p in everything:
            for role in filter(None, (p.owner_role, p.escalation_role)):
                if role not in ctx.directory.roles:
                    probs.append(Problem("error", f"{p.id}: role {role!r} is not in the people configuration"))
        probs += [Problem("warning", w) for w in coverage_warnings(doc.fingerprints, everything, ctx.directory)]
        if getattr(ctx.directory, "oversight", None):
            probs += [Problem("error", m) for m in ctx.directory.oversight_problems(doc.patterns)]
    for cid, c in doc.capabilities.items():
        mine = [p for p in doc.patterns if p.capability == cid]
        if not mine and not c.outcomes:
            probs.append(Problem("warning", f"capability {cid}: no exception and no outcome metric; nothing "
                                            "observes it yet"))
        if ctx.metric_names is not None:
            for m in c.outcomes:
                if m not in ctx.metric_names:
                    probs.append(Problem("warning", f"capability {cid}: outcome {m!r} is not a configured metric"))
        if ctx.directory is not None and c.owner and c.owner not in ctx.directory.roles:
            probs.append(Problem("error", f"capability {cid}: owner {c.owner!r} is not in the people configuration"))
    if doc.capabilities:
        loose = [p.id for p in doc.patterns if p.capability is None]
        if loose:
            probs.append(Problem("warning", f"exceptions with no capability: {loose}"))
    if ctx.binding is not None:
        from .bindings import check_binding
        probs += [Problem("error", m) for m in check_binding(ctx.binding, doc.patterns, dict(doc.slots or {}))]
    if not doc.patterns:
        probs.append(Problem("warning", "no patterns: every event will go to a person as unmatched"))
    return doc, probs


def _check_people(data: dict, ctx: Context) -> tuple[Any, list[Problem]]:
    from .rbac import META_ACTIONS, parse_directory
    probs: list[Problem] = []
    try:
        d = parse_directory(data, "people")
    except Exception as e:  # noqa: BLE001
        return None, [Problem("error", str(e))]
    for p in ctx.patterns:
        for role in filter(None, (p.owner_role, p.escalation_role)):
            if role not in d.roles:
                probs.append(Problem("error", f"role {role!r} is used by pattern {p.id} but is not defined here"))
    for u in d.unattended:
        if u.action != "*" and not ctx.actions.has(u.action):
            probs.append(Problem("warning", f"unattended limit: action {u.action!r} is not provided by the overlay"))
    for rule in getattr(d, "sod", []):
        for a in (rule.first, rule.second):
            if a != "__approve__" and not ctx.actions.has(a):
                probs.append(Problem("warning", f"sod {rule.first}/{rule.second}: action {a!r} is not provided by "
                                                "the overlay (a domain core may still check it)"))
    for r in d.rules:
        if r.action not in ("*", "__approve__", *META_ACTIONS) and not ctx.actions.has(r.action):
            probs.append(Problem("warning", f"authority for {r.role_id}: action {r.action!r} is not provided by "
                                            "the overlay"))
    for person in d.people.values():
        for e in person.edges:
            if ctx.edges and e not in ctx.edges:
                probs.append(Problem("warning", f"{person.id}: edge {e!r} is not configured in the overlay"))
    if d.config_approval is not None:
        holders = [p for p in d.people.values() if p.active
                   and d.authorize_meta(p.id, "__configure__", "config:registry").allowed]
        need = d.config_approval.approvals + 1
        if len(holders) < need:
            probs.append(Problem("error", f"config_approval needs {need} active people with __configure__ "
                                          f"(an author and {need - 1} approver(s)); only {len(holders)} have it, "
                                          "so nothing could be published again"))
        bad = [k for k in d.config_approval.kinds if k not in KINDS]
        if bad:
            probs.append(Problem("error", f"config_approval: unknown kinds {bad} (known: {list(KINDS)})"))
    if d.scim is not None:
        for role in sorted(d.scim.roles() - set(d.roles)):
            probs.append(Problem("error", f"scim: role {role!r} is given to a group but is not defined here"))
    if not any(r.action == "__configure__" for r in d.rules):
        probs.append(Problem("warning", "nobody has the __configure__ right: configuration could not be "
                                        "published again through the console"))
    probs += [Problem("error", m) for m in d.oversight_problems(ctx.patterns)]
    probs += [Problem("warning", m) for m in d.oversight_overlaps(ctx.patterns)]
    probs += [Problem("warning", w) for w in coverage_warnings(ctx.fingerprints, ctx.patterns, d)]
    return d, probs


def _check_models(data: dict, ctx: Context) -> tuple[Any, list[Problem]]:
    from .providers import load_models
    probs: list[Problem] = []
    try:
        router = load_models(data, factory=_stub_factory)
    except Exception as e:  # noqa: BLE001
        return None, [Problem("error", str(e))]
    for name, spec in (data.get("models") or {}).items():
        env = (spec or {}).get("api_key_env")
        if env and not os.environ.get(env):
            probs.append(Problem("warning", f"{name}: {env} is not set in this process"))
        if (spec or {}).get("provider") == "anthropic" and not os.environ.get("ANTHROPIC_API_KEY") and not env:
            probs.append(Problem("warning", f"{name}: ANTHROPIC_API_KEY is not set in this process"))
    tasks = {p.model_task for p in ctx.patterns if p.model_task}
    for t in sorted(tasks):
        if t not in router.routes and router.default is None:
            probs.append(Problem("error", f"patterns use model_task {t!r} but no route or default serves it"))
    return data, probs


def _check_connectors(data: dict, ctx: Context) -> tuple[Any, list[Problem]]:
    import json
    import re

    from .envsecrets import allowed
    from .mcp import parse_servers
    from .sources import check_source, parse_sources
    probs: list[Problem] = []
    from .httpactions import check_actions, parse_actions
    unknown = set(data) - {"sources", "mcp", "edges", "actions", "lookups", "auth", "version"}
    if unknown:
        return None, [Problem("error", f"unknown top-level keys {sorted(unknown)} (use sources, mcp, edges, "
                                       "actions, lookups and auth)")]
    from . import connauth
    from .httpactions import check_lookups, parse_lookups
    try:
        sources = parse_sources(data.get("sources") or {})
        servers = parse_servers(data.get("mcp") or {})
        actions = parse_actions(data.get("actions") or {})
        lookups = parse_lookups(data.get("lookups") or {})
        auths = connauth.parse(data.get("auth") or {})
    except Exception as e:  # noqa: BLE001
        return None, [Problem("error", str(e))]
    probs += [Problem(sev, msg) for sev, msg in check_lookups(lookups, {t["name"] for t in ctx.tools})]
    for name in sorted(set(connauth.uses(data)) - set(auths)):
        probs.append(Problem("error", f"{{{{auth.{name}}}}} is used but there is no auth: {name} section"))
    for a in auths.values():
        for env in re.findall(r"\{\{\s*env\.([A-Za-z_][A-Za-z0-9_]*)", json.dumps(a.model_dump())):
            if not allowed(env):
                probs.append(Problem("error", f"auth {a.name}: {env} cannot be used by configuration; name the "
                                              "variable SENTINEL_SECRET_..."))
            elif not os.environ.get(env):
                probs.append(Problem("warning", f"auth {a.name}: {env} is not set in this process"))
    code = set(ctx.code_actions) if ctx.code_actions else {s.name for s in ctx.actions.specs()}
    probs += [Problem(sev, msg) for sev, msg in check_actions(actions, set(ctx.code_actions))]
    available = code | set(actions)
    for p in ctx.patterns:
        used = set(p.allowed_actions) | {st.action for st in p.playbook if st.action}
        gone = sorted(used - available)
        if gone:
            probs.append(Problem("error", f"{p.id} uses {gone}, which neither the overlay nor these connectors "
                                          "provide"))
    from .edges import build_edges
    try:
        for e in build_edges(data.get("edges") or {}).values():
            if getattr(e, "missing", None):
                probs.append(Problem("warning", f"edge {e.name}: waiting for key {e.missing} (enter it on the "
                                                "Keys page); its cards go to the console until then"))
    except ValueError as e:
        probs.append(Problem("error", str(e)))
    for name in data.get("edges") or {}:
        if name in ctx.base_edges:
            probs.append(Problem("warning", f"edge {name}: replaces the overlay's own edge of that name"))
    fp_types = {r.event_type for r in ctx.fingerprints}
    handled = {t for p in ctx.patterns if p.id != "__unmatched__" for t in p.event_types}
    for s in sources.values():
        probs += [Problem(sev, msg) for sev, msg in check_source(s)]
        for e in s.emit:
            if "{{" in e.type:
                continue
            if e.type not in fp_types:
                probs.append(Problem("warning", f"source {s.name}: event type {e.type!r} has no fingerprint rule"))
            if e.type not in handled and "*" not in handled:
                probs.append(Problem("warning", f"source {s.name}: no exception pattern handles {e.type!r}; "
                                                "these events will go to a person as unmatched"))
    from .mcp import stdio_problems
    probs += [Problem("error", m) for m in stdio_problems(servers, list(ctx.mcp_commands))]
    for m in servers.values():
        for text in [m.url or "", *m.headers.values(), *m.env.values()]:
            for env in re.findall(r"\{\{\s*env\.([A-Za-z_][A-Za-z0-9_]*)", text):
                if not allowed(env):
                    probs.append(Problem("error", f"mcp {m.name}: {env} cannot be used by configuration; name the "
                                                  "variable SENTINEL_SECRET_... or list it in SENTINEL_CONFIG_SECRETS"))
                elif not os.environ.get(env):
                    probs.append(Problem("warning", f"mcp {m.name}: {env} is not set in this process"))
        clash = [t for t in m.tools if f"{m.name}.{t}" in {x["name"] for x in ctx.tools}]
        for t in clash:
            probs.append(Problem("error", f"mcp {m.name}: tool name {m.name}.{t} clashes with an overlay tool"))
    return data, probs


def _check_metrics(data: dict, ctx: Context) -> tuple[Any, list[Problem]]:
    from .kpi import BREACH, RAISED, RECOVERED, TRUSTED, UNTRUSTED, parse
    try:
        doc = parse(data)
    except Exception as e:  # noqa: BLE001 - shown to the person editing
        return None, [Problem("error", str(e))]
    roles = set(ctx.directory.roles) if ctx.directory is not None else None
    probs = [Problem(sev, msg) for sev, msg in doc.problems(roles)]
    tool_names = set(ctx.all_tools or ())
    for n, d in doc.datasets.items():
        if d.kind == "lookup" and d.lookup not in tool_names:
            probs.append(Problem("warning", f"dataset {n}: lookup {d.lookup!r} is not available yet; add its "
                                            "connector (Data sources) and publish it"))
    for cid, c in (ctx.capabilities or {}).items():
        for m in c.outcomes:
            if m not in doc.metrics:
                probs.append(Problem("warning", f"capability {cid} measures its outcome with {m!r}, which this "
                                                "metrics configuration does not define"))
    fp_types = {r.event_type for r in ctx.fingerprints}
    emitted = {m.emit for m in doc.monitors.values()} | ({RECOVERED} if any(m.recover for m in doc.monitors.values())
                                                          else set()) | ({RAISED} if doc.metrics else set())
    for t in sorted(emitted - fp_types):
        probs.append(Problem("warning", f"no fingerprint rule for {t}: add one to the registry so the cases it "
                                        "raises carry the metric and its dimensions as facts"))
    raised = {t for p in ctx.patterns for t in p.event_types}
    checked = [n for n, d in doc.datasets.items() if d.checks is not None]
    if checked and UNTRUSTED not in raised:
        probs.append(Problem("warning", f"datasets {checked} have checks but no exception is raised by {UNTRUSTED}: "
                                        "nobody is asked to fix data that fails them"))
    elif checked and not any(p.clear_when and any(ce.type == TRUSTED for ce in p.clear_when.events)
                             for p in ctx.patterns if UNTRUSTED in p.event_types):
        probs.append(Problem("warning", f"no exception closes on {TRUSTED}: data cases stay open after the data "
                                        "is right again (add clear_when)"))
    for t in sorted({m.emit for m in doc.monitors.values()} - raised):
        probs.append(Problem("warning", f"no exception is raised by {t}: its cases go to a person as unmatched"))
    if BREACH in raised and not any(p.clear_when and any(ce.type == RECOVERED for ce in p.clear_when.events)
                                    for p in ctx.patterns if BREACH in p.event_types):
        probs.append(Problem("warning", f"no exception closes on {RECOVERED}: breach cases stay open after "
                                        "the KPI recovers (add clear_when)"))
    return doc, probs


_CHECKS = {"registry": _check_registry, "people": _check_people, "models": _check_models,
           "connectors": _check_connectors, "metrics": _check_metrics}


def check(kind: str, text: str, ctx: Context) -> tuple[Any, list[Problem]]:
    """Parse and validate. Returns (parsed or None, problems)."""
    if kind not in KINDS:
        raise ValueError(f"kind must be one of {KINDS}")
    try:
        data = _load_text(text)
    except ConfigError as e:
        return None, [Problem("error", str(e))]
    return _CHECKS[kind](data, ctx)
