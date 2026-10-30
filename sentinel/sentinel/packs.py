# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""Domain packs: versioned bundles of exceptions, actions and tools for one industry, stacked in layers.

A pack is a directory (or an installed Python package that points to one through the ``sentinel.packs``
entry point) with a ``sentinel-pack.yaml`` manifest::

    id: kbgrid.dairy-dsd
    version: 1.3.0
    namespace: dairy                     # every action and tool it provides is named dairy.<something>
    sentinel: ">=0.10,<0.12"             # Sentinel versions it works with
    requires: ["kbgrid.core-trunk>=1.0"]
    layers: [registry/dairy.yaml]        # registry layers, lowest first (see overlay.load_layers)
    python: dairy_pack.actions:register  # optional: register(ctx) adds actions and tools in code
    provides:
      actions: [{name: dairy.place_hold, capabilities: [write:sap.sales_order]}]
      tools:   [{name: dairy.get_outlet_account, capabilities: [read:sap.customer]}]
    config_schema: {sap_company_db: str, credit_hold_mode: str}
    golden: golden/                      # cases the conformance check replays (sentinel.testing)

A site lists the packs it runs in a packs file, with each pack's settings and the capabilities it grants::

    packs:
      - {id: kbgrid.core-trunk, path: packs/core-trunk}
      - {id: kbgrid.dairy-dsd, path: packs/dairy-dsd, config: {sap_company_db: CO01},
         grant: [write:sap.sales_order, read:sap.customer]}
    layers: [registry/northwind.yaml]        # the customer's own layer on top

An action whose capabilities are not granted is still listed, but it refuses to run and sends the case to a
person, and the configuration check says so. Packs load in dependency order; their layers stack in that
order, then the customer's, then whatever the console publishes (kept as a layer of its own).
"""
from __future__ import annotations

import importlib
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field

from .actions import ActionRegistry
from .models import ActionResult
from .tools import ToolRegistry

MANIFEST = "sentinel-pack.yaml"
_ID = re.compile(r"^[a-z0-9][a-z0-9_.-]{1,80}$")
_NS = re.compile(r"^[a-z][a-z0-9_]{1,30}$")


class PackError(ValueError):
    pass


class Provided(BaseModel):
    name: str
    capabilities: list[str] = Field(default_factory=list)
    reversible: bool | None = None


class Manifest(BaseModel):
    id: str
    version: str
    namespace: str
    sentinel: str = ""
    requires: list[str] = Field(default_factory=list)
    layers: list[str] = Field(default_factory=list)
    python: str | None = None
    provides: dict[str, list[Provided]] = Field(default_factory=dict)
    config_schema: dict[str, str] = Field(default_factory=dict)
    golden: str | None = None
    description: str = ""
    title: str = ""
    industry: str = ""                    # for the catalogue: retail, dairy, manufacturing, healthcare ...
    tags: list[str] = Field(default_factory=list)

    def model_post_init(self, _ctx: Any) -> None:
        if not _ID.match(self.id):
            raise ValueError(f"pack id {self.id!r}: lowercase letters, digits, . _ - only")
        if not _NS.match(self.namespace):
            raise ValueError(f"pack {self.id}: namespace {self.namespace!r} must be a short lowercase word")
        parse_version(self.version)


# ---- versions ---------------------------------------------------------------------------------------------
def parse_version(v: str) -> tuple[int, ...]:
    m = re.match(r"^(\d+)(?:\.(\d+))?(?:\.(\d+))?", str(v).strip())
    if not m:
        raise PackError(f"not a version: {v!r}")
    return tuple(int(x or 0) for x in m.groups())


def satisfies(version: str, spec: str) -> bool:
    """``spec`` is comma-separated comparisons, e.g. ">=0.10,<0.12" (empty: anything)."""
    have = parse_version(version)
    for part in filter(None, (x.strip() for x in (spec or "").split(","))):
        m = re.match(r"^(>=|<=|==|!=|>|<|~=)?\s*(.+)$", part)
        if not m:
            raise PackError(f"bad version range {spec!r}")
        op, want = m.group(1) or "==", parse_version(m.group(2))
        k = max(1, len(want) - 1)
        ok = {">=": have >= want, "<=": have <= want, ">": have > want, "<": have < want, "==": have == want,
              "!=": have != want, "~=": have >= want and have[:k] == want[:k]}[op]
        if not ok:
            return False
    return True


def _req(r: str) -> tuple[str, str]:
    m = re.match(r"^([a-z0-9][a-z0-9_.-]+)\s*(.*)$", r.strip())
    if not m:
        raise PackError(f"bad requirement {r!r}")
    return m.group(1), m.group(2)


# ---- loading ----------------------------------------------------------------------------------------------
@dataclass
class Pack:
    manifest: Manifest
    root: Path
    config: dict[str, Any] = field(default_factory=dict)
    grant: set[str] = field(default_factory=set)

    @property
    def id(self) -> str:
        return self.manifest.id


def read_pack(path: str | Path) -> Pack:
    root = Path(path)
    f = root / MANIFEST
    if not f.is_file():
        raise PackError(f"{root}: no {MANIFEST}")
    try:
        return Pack(Manifest.model_validate(yaml.safe_load(f.read_text(encoding="utf-8")) or {}), root)
    except Exception as e:  # noqa: BLE001 - shown to the operator
        raise PackError(f"{f}: {e}") from None


def installed() -> dict[str, Path]:
    """Packs installed as Python packages (entry point group ``sentinel.packs`` -> a directory path)."""
    out: dict[str, Path] = {}
    try:
        from importlib.metadata import entry_points
        for ep in entry_points(group="sentinel.packs"):
            target = ep.load()
            out[ep.name] = Path(target() if callable(target) else target)
    except Exception:  # noqa: BLE001,S110 - a broken plug-in is reported when someone asks for it
        pass
    return out


@dataclass
class PackSet:
    packs: list[Pack]
    layers: list[Any]                  # paths for overlay.load_layers, in order
    actions: ActionRegistry
    tools: ToolRegistry
    problems: list[str] = field(default_factory=list)
    refused: dict[str, list[str]] = field(default_factory=dict)   # action -> capabilities not granted


class PackContext:
    """What a pack's ``register(ctx)`` gets: registries that enforce its namespace, its settings."""

    def __init__(self, pack: Pack, actions: ActionRegistry, tools: ToolRegistry) -> None:
        self.pack, self.config = pack, dict(pack.config)
        self._actions, self._tools = actions, tools
        self.ns = pack.manifest.namespace

    def _check(self, name: str) -> None:
        if not name.startswith(self.ns + "."):
            raise PackError(f"pack {self.pack.id}: {name!r} must be named {self.ns}.<something>")

    def action(self, name: str, **kw: Any) -> Any:
        self._check(name)
        return self._actions.action(name, **kw)

    def register_action(self, spec: Any, handler: Any, compensate: Any = None) -> None:
        self._check(spec.name)
        self._actions.register(spec, handler, compensate)

    def tool(self, name: str, description: str, params: dict[str, str] | None = None) -> Any:
        self._check(name)
        return self._tools.tool(name, description, params)


def load(packs_file: str | Path, *, sentinel_version: str | None = None) -> PackSet:
    from . import __version__
    sv = sentinel_version or __version__
    base = Path(packs_file).parent
    spec = yaml.safe_load(Path(packs_file).read_text(encoding="utf-8")) or {}
    found = installed()
    packs: dict[str, Pack] = {}
    for item in spec.get("packs") or []:
        pid = item.get("id")
        path = item.get("path")
        root = (base / path) if path else found.get(pid or "")
        if root is None:
            raise PackError(f"pack {pid}: give a path, or install it (no sentinel.packs entry point named {pid})")
        p = read_pack(root)
        if pid and p.id != pid:
            raise PackError(f"{root} is pack {p.id}, not {pid}")
        if p.id in packs:
            raise PackError(f"pack {p.id} is listed twice")
        p.config, p.grant = dict(item.get("config") or {}), set(item.get("grant") or [])
        packs[p.id] = p
    problems: list[str] = []
    # versions and requirements
    for p in packs.values():
        if p.manifest.sentinel and not satisfies(sv, p.manifest.sentinel):
            raise PackError(f"pack {p.id} {p.manifest.version} needs Sentinel {p.manifest.sentinel}; this is {sv}")
        for r in p.manifest.requires:
            rid, rng = _req(r)
            if rid not in packs:
                raise PackError(f"pack {p.id} needs {rid} {rng}".strip() + ", which is not listed")
            if rng and not satisfies(packs[rid].manifest.version, rng):
                raise PackError(f"pack {p.id} needs {rid} {rng}; listed is {packs[rid].manifest.version}")
        missing = [k for k in p.manifest.config_schema if k not in p.config]
        if missing:
            problems.append(f"pack {p.id}: settings not given: {missing}")
        extra = [k for k in p.config if k not in p.manifest.config_schema]
        if extra:
            problems.append(f"pack {p.id}: unknown settings {extra}")
    # namespaces are unique
    seen: dict[str, str] = {}
    for p in packs.values():
        ns = p.manifest.namespace
        if ns in seen:
            raise PackError(f"packs {seen[ns]} and {p.id} both use namespace {ns!r}")
        seen[ns] = p.id
    order = _topo(packs)
    actions, tools = ActionRegistry(), ToolRegistry()
    layers: list[Any] = []
    refused: dict[str, list[str]] = {}
    for p in order:
        for x in p.manifest.layers:                   # named after the pack, so its exceptions can be compared
            data = yaml.safe_load((p.root / x).read_text(encoding="utf-8")) or {}   # across sites (benchmarks)
            layers.append((p.root / x) if not isinstance(data, dict) or data.get("template")
                          else (f"pack:{p.id}", {**data, "layer": f"pack:{p.id}"}))
        a0, t0 = {s.name for s in actions.specs()}, set(tools.tools)
        if p.manifest.python:
            mod, _, fn = p.manifest.python.partition(":")
            try:
                register = getattr(importlib.import_module(mod), fn or "register")
            except Exception as e:  # noqa: BLE001
                raise PackError(f"pack {p.id}: cannot load {p.manifest.python}: {e}") from None
            register(PackContext(p, actions, tools))
        new_a = {s.name for s in actions.specs()} - a0
        new_t = set(tools.tools) - t0
        declared = {x.name: x for x in p.manifest.provides.get("actions", [])}
        declared_t = {x.name: x for x in p.manifest.provides.get("tools", [])}
        for name in sorted(new_a - set(declared)):
            problems.append(f"pack {p.id}: action {name} is not declared in provides.actions")
        for name in sorted(set(declared) - new_a):
            problems.append(f"pack {p.id}: provides.actions lists {name}, which its code does not register")
        for name in sorted(new_t - set(declared_t)):
            problems.append(f"pack {p.id}: tool {name} is not declared in provides.tools")
        for name, d in declared.items():
            lacking = [c for c in d.capabilities if c not in p.grant]
            if lacking and name in new_a:
                refused[name] = lacking
        for name, d in declared_t.items():
            lacking = [c for c in d.capabilities if c not in p.grant]
            if lacking and name in tools.tools:
                refused[name] = lacking
    actions, tools = _gate(actions, tools, refused)
    layers += [base / x for x in spec.get("layers") or []]
    return PackSet(order, layers, actions, tools, problems, refused)


def _topo(packs: dict[str, Pack]) -> list[Pack]:
    out: list[Pack] = []
    state: dict[str, int] = {}

    def visit(pid: str, trail: list[str]) -> None:
        if state.get(pid) == 2:
            return
        if state.get(pid) == 1:
            raise PackError(f"packs require each other in a loop: {' -> '.join([*trail, pid])}")
        state[pid] = 1
        for r in packs[pid].manifest.requires:
            visit(_req(r)[0], [*trail, pid])
        state[pid] = 2
        out.append(packs[pid])
    for pid in packs:
        visit(pid, [])
    return out


def _gate(actions: ActionRegistry, tools: ToolRegistry,
          refused: dict[str, list[str]]) -> tuple[ActionRegistry, ToolRegistry]:
    """Actions and tools whose capabilities are not granted stay listed but refuse to run."""
    if not refused:
        return actions, tools
    gated = ActionRegistry()
    for spec in actions.specs():
        reg = actions.get(spec.name)
        if spec.name in refused:
            need = refused[spec.name]

            def no(ctx: Any, params: dict[str, Any], _n: str = spec.name, _c: list[str] = need) -> ActionResult:
                return ActionResult(ok=False, retryable=False,
                                    detail=f"{_n} needs {_c}, which this site has not granted")
            gated.register(spec, no, (lambda c, p, _f=no: _f(c, p)) if reg.compensate else None)
        else:
            gated.register(spec, reg.handler, reg.compensate)
    gt = ToolRegistry()
    for t in tools.tools.values():
        if t.name in refused:
            def deny(args: dict[str, Any], services: dict[str, Any], _n: str = t.name) -> Any:
                raise PermissionError(f"{_n} needs {refused[_n]}, which this site has not granted")
            gt.register(type(t)(t.name, t.description, t.params, deny))
        else:
            gt.register(t)
    return gated, gt


def build_overlay(packs_file: str | Path, *, name: str | None = None, **overlay_kw: Any) -> Any:
    """An Overlay from a packs file: their stacked registry layers, actions and tools."""
    from .overlay import Overlay, load_layers
    ps = load(packs_file)
    doc = load_layers(ps.layers)
    ov = Overlay(name=name or Path(packs_file).stem, fingerprint_rules=doc.fingerprints, patterns=doc.patterns,
                 roles=doc.roles, actions=ps.actions, tools=ps.tools,
                 **{"slots": doc.slots, "slot_bindings": doc.slot_bindings, **overlay_kw})
    ov.packs = ps  # type: ignore[attr-defined]
    return ov


def from_env() -> Any:
    """``--overlay sentinel.packs:from_env``: the overlay from the packs file named by SENTINEL_PACKS."""
    import os
    path = os.environ.get("SENTINEL_PACKS")
    if not path:
        raise PackError("set SENTINEL_PACKS to the site's packs file")
    return build_overlay(path)


def check(packs_file: str | Path) -> dict[str, Any]:
    """Load, conformance, and every pack's golden cases (for CI before a pack goes to a site)."""
    from .testing import conformance, engine_for, run_golden
    ps = load(packs_file)
    ov = build_overlay(packs_file)
    problems = [*ps.problems, *conformance(ov)]
    eng = engine_for(ov)
    golden: dict[str, list[str]] = {}
    for p in ps.packs:
        if p.manifest.golden and (p.root / p.manifest.golden).exists():
            golden[p.id] = run_golden(eng, p.root / p.manifest.golden)
    return {"packs": [{"id": p.id, "version": p.manifest.version} for p in ps.packs],
            "refused": ps.refused, "problems": problems, "golden": golden,
            "ok": not problems and not any(golden.values())}
