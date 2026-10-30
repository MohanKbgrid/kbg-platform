# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""Actions: the only way the framework changes the world.

Each action declares whether it is reversible. Execution is idempotent:
the engine passes an idempotency key per (incident, attempt-group) and the
store refuses to run the same key twice.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol
from collections.abc import Callable

from .models import ActionResult, ActionSpec, Event, Incident

_TYPES: dict[str, tuple[type, ...]] = {
    "str": (str,),
    "int": (int,),
    "float": (int, float),
    "bool": (bool,),
    "list": (list,),
    "dict": (dict,),
    "any": (object,),
}


class ParamError(ValueError):
    pass


# MCP tools describe their inputs in JSON-schema words; overlay code uses the short words above.
_ALIASES = {"string": "str", "integer": "int", "number": "float", "boolean": "bool", "array": "list",
            "object": "dict"}


def _whole_template(v: Any) -> bool:
    """A value that is one template and nothing else: its type is known only when the case runs."""
    s = v.strip() if isinstance(v, str) else ""
    return s.startswith("{{") and s.endswith("}}") and s.count("{{") == 1


def schema_problems(name: str, schema: dict[str, str], values: dict[str, Any]) -> list[str]:
    """Configuration-time check of a playbook step's params (or a lookup's args) against what the action or
    tool declares: unknown names, missing required ones, and literal values of the wrong type. A value that
    is a single template is checked when the step runs. An empty schema declares nothing, so nothing is
    checked."""
    if not schema or not isinstance(values, dict):
        return []
    out: list[str] = []
    known = {k.rstrip("?"): k.endswith("?") for k in schema}
    types = {k.rstrip("?"): _ALIASES.get(str(t), str(t)) for k, t in schema.items()}
    extra = sorted(set(values) - set(known))
    if extra:
        out.append(f"{name}: unexpected params {extra} (it takes {sorted(known)})")
    for k, optional in known.items():
        if k not in values or values[k] is None:
            if not optional:
                out.append(f"{name}: missing param {k!r}")
            continue
        v, typ = values[k], types[k]
        allowed = _TYPES.get(typ)
        if allowed is None or typ == "any" or _whole_template(v):
            continue
        if isinstance(v, bool) and typ in ("int", "float"):
            out.append(f"{name}: {k} must be {typ}, got bool")
        elif not isinstance(v, allowed):
            out.append(f"{name}: {k} must be {typ}, got {type(v).__name__} {v!r}")
    return out


@dataclass
class ActionContext:
    incident: Incident
    event: Event | None
    actor: str                         # auto | llm | human:<id>
    idempotency_key: str
    services: dict[str, Any] = field(default_factory=dict)  # overlay-provided adapters
    # unattended runs with a policy key: assert_for(action, obj) -> a signed agent assertion for the domain core
    assert_for: Callable[..., str] | None = None


class ActionHandler(Protocol):
    def __call__(self, ctx: ActionContext, params: dict[str, Any]) -> ActionResult: ...


@dataclass
class RegisteredAction:
    spec: ActionSpec
    handler: Callable[[ActionContext, dict[str, Any]], ActionResult]
    compensate: Callable[[ActionContext, dict[str, Any]], ActionResult] | None = None


class ActionRegistry:
    def __init__(self) -> None:
        self._actions: dict[str, RegisteredAction] = {}

    def register(
        self,
        spec: ActionSpec,
        handler: Callable[[ActionContext, dict[str, Any]], ActionResult],
        compensate: Callable[[ActionContext, dict[str, Any]], ActionResult] | None = None,
    ) -> None:
        if spec.name in self._actions:
            raise ValueError(f"action {spec.name} already registered")
        if spec.reversible and compensate is None:
            raise ValueError(f"action {spec.name} is marked reversible but has no compensate handler")
        self._actions[spec.name] = RegisteredAction(spec, handler, compensate)

    def action(self, name: str, *, reversible: bool = False, safe: bool = False, description: str = "",
               params: dict[str, str] | None = None, max_attempts: int = 3):
        """Decorator form. Use `.compensator` on the result to attach the undo."""
        def deco(fn):
            holder = _PendingAction(self, ActionSpec(name=name, reversible=reversible, safe=safe,
                                                     description=description,
                                                     params_schema=params or {}, max_attempts=max_attempts), fn)
            return holder
        return deco

    def get(self, name: str) -> RegisteredAction:
        try:
            return self._actions[name]
        except KeyError:
            raise KeyError(f"unknown action {name!r}") from None

    def has(self, name: str) -> bool:
        return name in self._actions

    def merged(self, other: ActionRegistry) -> ActionRegistry:
        """A new registry with this one's actions and then the other's (a name in both is refused)."""
        out = ActionRegistry()
        for reg in (self, other):
            for a in reg._actions.values():
                out.register(a.spec, a.handler, a.compensate)
        return out

    def specs(self) -> list[ActionSpec]:
        return [a.spec for a in self._actions.values()]

    def validate_params(self, name: str, params: dict[str, Any]) -> dict[str, Any]:
        schema = self.get(name).spec.params_schema
        if not isinstance(params, dict):
            raise ParamError(f"{name}: params must be an object")
        clean: dict[str, Any] = {}
        known = {k.rstrip("?") for k in schema}
        extra = set(params) - known
        if schema and extra:
            raise ParamError(f"{name}: unexpected params {sorted(extra)}")
        for key, typ in schema.items():
            optional = key.endswith("?")
            k = key.rstrip("?")
            if k not in params or params[k] is None:
                if optional:
                    continue
                raise ParamError(f"{name}: missing param {k!r}")
            allowed = _TYPES.get(typ)
            if allowed is None:
                raise ParamError(f"{name}: unknown type {typ!r} in schema")
            v = params[k]
            if typ in ("int", "float") and isinstance(v, bool):
                raise ParamError(f"{name}: {k} must be {typ}")
            if not isinstance(v, allowed):
                raise ParamError(f"{name}: {k} must be {typ}, got {type(v).__name__}")
            clean[k] = v
        if not schema:
            clean = dict(params)
        return clean


class _PendingAction:
    """Lets overlays write @registry.action(...) then optionally @x.compensator."""

    def __init__(self, reg: ActionRegistry, spec: ActionSpec, fn) -> None:
        self.reg, self.spec, self.fn = reg, spec, fn
        if not spec.reversible:
            reg.register(spec, fn)

    def compensator(self, comp):
        self.reg.register(self.spec, self.fn, comp)
        return comp

    def __call__(self, *a, **kw):
        return self.fn(*a, **kw)




def render(value: Any, scope: dict[str, Any]) -> Any:
    """Render '{{payload.order_id}}' style templates (see sentinel.expr for filters)."""
    from .expr import render as _render
    return _render(value, scope)
