# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""Overlays: everything domain-specific lives here, nothing else changes.

An overlay supplies
  * receivers        source name -> fn(raw payload) -> Event | list[Event]
  * fingerprint rules + patterns + roles   (usually from a registry YAML)
  * actions           the only things allowed to change the world
  * tools             read-only lookups the LLM may use
  * services          adapters (API clients, DB handles) passed to actions/tools
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from collections.abc import Callable

import yaml

from .actions import ActionRegistry
from .rbac import Directory
from .fingerprint import FingerprintRule
from .models import Event, Pattern
from .tools import ToolRegistry

Receiver = Callable[[dict[str, Any]], "Event | list[Event]"]


@dataclass
class Overlay:
    name: str
    fingerprint_rules: list[FingerprintRule] = field(default_factory=list)
    patterns: list[Pattern] = field(default_factory=list)
    actions: ActionRegistry = field(default_factory=ActionRegistry)
    tools: ToolRegistry = field(default_factory=ToolRegistry)
    services: dict[str, Any] = field(default_factory=dict)
    receivers: dict[str, Receiver] = field(default_factory=dict)
    roles: dict[str, str] = field(default_factory=dict)
    notifier: Callable[[str, dict[str, Any]], None] | None = None
    directory: Directory | None = None           # people, roles, authority; None = open mode
    verifiers: dict[str, Callable[..., Any]] = field(default_factory=dict)   # outcome checks by name
    pii_keys: list[str] = field(default_factory=list)                        # payload keys that are personal
    edges: dict[str, Any] = field(default_factory=dict)                      # name -> Edge
    role_edges: dict[str, list[str]] = field(default_factory=dict)           # role -> edge names (fallback)
    default_edges: list[str] = field(default_factory=list)                   # when neither person nor role says
    mcp_commands: list[list[str]] = field(default_factory=list)              # stdio MCP servers configuration may start
    case_defaults: dict[str, Any] = field(default_factory=dict)              # the registry's defaults: section
    datasets: dict[str, Callable[[dict[str, Any], Any], Any]] = field(default_factory=dict)  # (services, now) -> rows
    metrics: dict[str, Any] | None = None        # the overlay's own metrics configuration (until one is published)
    capabilities: dict[str, Any] = field(default_factory=dict)              # id -> Capability (the registry's)
    slots: dict[str, str] = field(default_factory=dict)                     # role slots the templates use (ADR-003)
    slot_bindings: dict[str, str] = field(default_factory=dict)             # slot -> this tenant's role
    binding: Any = None                                                     # bindings.DomainBinding (ADR-005)


@dataclass
class RegistryDoc:
    roles: dict[str, str]
    fingerprints: list[FingerprintRule]
    patterns: list[Pattern]
    defaults: dict[str, Any] = field(default_factory=dict)   # CaseDefaults: escalation, expiry, pauses, digest
    capabilities: dict[str, Any] = field(default_factory=dict)   # id -> Capability
    slots: dict[str, str] = field(default_factory=dict)          # slot id -> what the slot is for
    slot_bindings: dict[str, str] = field(default_factory=dict)  # slot id -> the tenant's role id


class SlotError(ValueError):
    """A role slot is used but unbound, undeclared, or bound to an unknown role (ADR-003 invariant 3)."""


def _mapping(raw: Any, where: str, what: str) -> dict[str, str]:
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise ValueError(f"{where}: {what}: a mapping")
    out = {}
    for k, v in raw.items():
        if v is None or isinstance(v, dict | list):
            raise ValueError(f"{where}: {what}: {k!r} needs a text value")
        out[str(k)] = str(v)
    return out


def resolve_slots(patterns: list[Pattern], slots: dict[str, str], bindings: dict[str, str],
                  roles: dict[str, str], where: str = "registry") -> list[Pattern]:
    """Patterns with their role slots bound to this tenant's roles (ADR-003).

    A pattern names ``owner_slot`` / ``escalation_slot`` instead of ``owner_role`` / ``escalation_role``; the
    tenant's ``slot_bindings`` decide the role. Patterns without slots are returned unchanged, so existing
    registries behave exactly as before. Refused (``SlotError``): a slot used but not bound; a slot not in
    ``slots`` when slots are declared; a binding to an unknown role; a pattern that names a slot and also
    writes a role for the same job (any role, even the bound one: the binding alone decides, so a later
    rebinding can never be blocked by a stale role line). Patterns resolved earlier re-resolve against the
    current bindings."""
    problems: list[str] = []
    if slots:
        for sid in sorted(set(bindings) - set(slots)):
            problems.append(f"slot_bindings: {sid!r} is not a declared slot (declared: {sorted(slots)})")
    if roles:
        for sid, role in sorted(bindings.items()):
            if role not in roles:
                problems.append(f"slot_bindings: slot {sid!r} is bound to unknown role {role!r}")
    out: list[Pattern] = []
    for p in patterns:
        changes: dict[str, Any] = {}
        for slot_field, role_field in (("owner_slot", "owner_role"), ("escalation_slot", "escalation_role")):
            sid = getattr(p, slot_field)
            if sid is None:
                continue
            if slots and sid not in slots:
                problems.append(f"pattern {p.id}: {slot_field} {sid!r} is not a declared slot")
                continue
            if sid not in bindings:
                problems.append(f"pattern {p.id}: {slot_field} {sid!r} is not bound in slot_bindings; "
                                "bind it to one of this tenant's roles before publishing")
                continue
            if role_field in p.model_fields_set and not p._slots_resolved:
                problems.append(f"pattern {p.id}: names {slot_field} {sid!r} and {role_field} "
                                f"{getattr(p, role_field)!r}; a pattern uses a slot or a role, not both "
                                f"(remove {role_field}; slot_bindings decides it)")
                continue
            changes[role_field] = bindings[sid]
        if changes:
            q = p.model_copy(update=changes)
            q._slots_resolved = True
            out.append(q)
        else:
            out.append(p)
    if problems:
        raise SlotError(f"{where}: {problems[0]}" + (f" (and {len(problems) - 1} more)" if len(problems) > 1 else ""))
    return out


def _capabilities(raw: Any, where: str) -> dict[str, Any]:
    from .models import Capability
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise ValueError(f"{where}: capabilities: a mapping of id -> capability")
    out = {}
    for cid, body in raw.items():
        try:
            out[str(cid)] = Capability.model_validate(body or {})
        except Exception as e:  # noqa: BLE001 - pydantic error, re-raised readably
            raise ValueError(f"{where}: capability {cid}: {e}") from None
    return out


def check_capabilities(roles: dict[str, str], patterns: list[Pattern], caps: dict[str, Any]) -> list[str]:
    """Each exception's capability exists and allows its route; each capability's owner is a known role."""
    out: list[str] = []
    for cid, c in caps.items():
        if c.owner and roles and c.owner not in roles:
            out.append(f"capability {cid}: owner {c.owner!r} is not a known role")
    for p in patterns:
        if p.capability is None:
            continue
        c = caps.get(p.capability)
        if c is None:
            out.append(f"pattern {p.id}: unknown capability {p.capability!r}")
            continue
        for what, r in (("max_route", p.max_route), ("route", p.route)):
            if r.level > c.max_route.level:
                out.append(f"pattern {p.id}: {what} {r.value} is above capability {p.capability}'s "
                           f"max_route {c.max_route.value}")
    return out


def _defaults(raw: Any, where: str) -> dict[str, Any]:
    from .models import CaseDefaults
    try:
        return CaseDefaults.model_validate(raw or {}).model_dump(mode="json", exclude_defaults=True)
    except Exception as e:  # noqa: BLE001 - pydantic error, re-raised readably
        raise ValueError(f"{where}: defaults: {e}") from None


def load_registry(path: str | Path) -> RegistryDoc:
    """Load a registry YAML (roles, fingerprints, patterns). Validates every entry."""
    return parse_registry(yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}, str(path))


def parse_registry(data: Any, path: str = "registry") -> RegistryDoc:
    """A registry from already-parsed YAML (a mapping)."""
    if not isinstance(data, dict):
        raise ValueError(f"{path}: top level must be a mapping")
    unknown = set(data) - {"roles", "fingerprints", "patterns", "defaults", "version", "overlay", "capabilities",
                           "slots", "slot_bindings"}
    if unknown:
        raise ValueError(f"{path}: unknown top-level keys {sorted(unknown)}")
    roles = data.get("roles") or {}
    fps = [FingerprintRule.model_validate(x) for x in data.get("fingerprints") or []]
    pats = [Pattern.model_validate(x) for x in data.get("patterns") or []]
    slots = _mapping(data.get("slots"), path, "slots")
    bindings = _mapping(data.get("slot_bindings"), path, "slot_bindings")
    pats = resolve_slots(pats, slots, bindings, roles, path)
    for p in pats:
        for role in (p.owner_role, p.escalation_role):
            if role and roles and role not in roles:
                raise ValueError(f"{path}: pattern {p.id} references unknown role {role!r}")
    caps = _capabilities(data.get("capabilities"), path)
    problems = check_capabilities(roles, pats, caps)
    if problems:
        raise ValueError(f"{path}: {problems[0]}")
    return RegistryDoc(roles=roles, fingerprints=fps, patterns=pats, defaults=_defaults(data.get("defaults"), path),
                       capabilities=caps, slots=slots, slot_bindings=bindings)


class LayerError(ValueError):
    pass


def load_layers(paths: list[str | Path | tuple[str, dict[str, Any]]]) -> RegistryDoc:
    """Merge registry layers, lowest first (e.g. trunk.yaml, retail.yaml, acme.yaml).

    Each layer may contain:
      layer: <name>                     # defaults to the file stem
      template: <name>                  # start from a built-in domain template (``sentinel template list``);
                                        # it is merged as a layer of its own just below this one
      roles: {...}                      # merged; later layers may add or redescribe roles
      fingerprints: [...]               # a later rule for the same event_type replaces the earlier one
      patterns: [...]                   # NEW patterns only; redefining an inherited id is refused
      overrides: [{id, set: {...}}]     # change fields of an inherited pattern (validated)
      disable: [ids]                    # switch off inherited patterns for this project
      capabilities: {...}               # merged by id; a later layer may redefine a capability
      slots: {slot: what it is for}     # role slots the templates name (ADR-003); merged
      slot_bindings: {slot: role}       # the tenant's role for each slot; merged, a later layer rebinds
    """
    layers: list[tuple[str, str, dict[str, Any]]] = []          # (where, layer name, data)
    for path in paths:
        if isinstance(path, tuple):                              # (layer name, data) already in memory
            name, data = path
            layers.append((f"layer {name}", str(name), data))
            continue
        path = Path(path)
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        if not isinstance(data, dict):
            raise LayerError(f"{path}: top level must be a mapping")
        if data.get("template"):
            from . import templates
            name = str(data["template"])
            try:
                tpl = templates.load(name)
            except KeyError:
                raise LayerError(f"{path}: unknown template {name!r} (known: {templates.names()})") from None
            layers.append((f"template {name}", f"template:{name}", tpl["registry"]))
        layers.append((str(path), str(data.get("layer") or path.stem), data))
    roles: dict[str, str] = {}
    fps: dict[str, FingerprintRule] = {}
    pats: dict[str, Pattern] = {}
    defaults: dict[str, Any] = {}
    caps: dict[str, Any] = {}
    slots: dict[str, str] = {}
    bindings: dict[str, str] = {}
    for path, layer, data in layers:
        unknown = set(data) - {"roles", "fingerprints", "patterns", "overrides", "disable", "layer", "version",
                               "overlay", "template", "defaults", "capabilities", "slots", "slot_bindings"}
        if unknown:
            raise LayerError(f"{path}: unknown top-level keys {sorted(unknown)}")
        roles.update(data.get("roles") or {})
        defaults.update(_defaults(data.get("defaults"), path))
        try:
            slots.update(_mapping(data.get("slots"), path, "slots"))
            bindings.update(_mapping(data.get("slot_bindings"), path, "slot_bindings"))
        except ValueError as e:
            raise LayerError(str(e)) from None
        try:
            caps.update(_capabilities(data.get("capabilities"), path))
        except ValueError as e:
            raise LayerError(str(e)) from None
        for raw in data.get("fingerprints") or []:
            rule = FingerprintRule.model_validate(raw)
            fps[rule.event_type] = rule
        for raw in data.get("patterns") or []:
            p = Pattern.model_validate({**raw, "layer": layer})
            if p.id in pats:
                raise LayerError(f"{path}: pattern {p.id!r} already defined in layer {pats[p.id].layer!r}; "
                                 "use overrides to change it")
            pats[p.id] = p
        for ov in data.get("overrides") or []:
            pid, changes = ov.get("id"), ov.get("set") or {}
            if pid not in pats:
                raise LayerError(f"{path}: override of unknown pattern {pid!r}")
            if "id" in changes or "layer" in changes:
                raise LayerError(f"{path}: override of {pid} may not change id or layer")
            base = pats[pid].model_dump(exclude_unset=True)     # unset fields stay unset (a slot's role is unset)
            base.update(changes)
            base["overridden_in"] = [*pats[pid].overridden_in, layer]
            try:
                pats[pid] = Pattern.model_validate(base)
            except Exception as e:  # noqa: BLE001 - pydantic validation error, re-raised readably
                raise LayerError(f"{path}: override of {pid} is invalid: {e}") from None
        for pid in data.get("disable") or []:
            if pid not in pats:
                raise LayerError(f"{path}: cannot disable unknown pattern {pid!r}")
            del pats[pid]
    try:
        plist = resolve_slots(list(pats.values()), slots, bindings, roles, "layers")
    except SlotError as e:
        raise LayerError(str(e)) from None
    for p in plist:
        for role in (p.owner_role, p.escalation_role):
            if role and roles and role not in roles:
                raise LayerError(f"pattern {p.id} references unknown role {role!r}")
    problems = check_capabilities(roles, plist, caps)
    if problems:
        raise LayerError(problems[0])
    return RegistryDoc(roles=roles, fingerprints=list(fps.values()), patterns=plist, defaults=defaults,
                       capabilities=caps, slots=slots, slot_bindings=bindings)
