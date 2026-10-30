# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""Read-only tools the LLM may call while diagnosing an incident.

Hard rule: tools never change state. Anything that changes the world is an
Action, goes through the guardrails, and is idempotent. The registry refuses
tools that are not declared read-only.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from collections.abc import Callable


@dataclass
class Tool:
    name: str
    description: str
    params: dict[str, str]
    fn: Callable[[dict[str, Any], dict[str, Any]], Any]   # (args, services) -> json-able
    read_only: bool = True
    full: Callable[[dict[str, Any], dict[str, Any]], Any] | None = None   # the whole reply (datasets), not cut short


@dataclass
class ToolRegistry:
    tools: dict[str, Tool] = field(default_factory=dict)

    def register(self, tool: Tool) -> None:
        if not tool.read_only:
            raise ValueError(f"tool {tool.name}: only read-only tools may be exposed to the LLM; use an Action")
        if tool.name in self.tools:
            raise ValueError(f"tool {tool.name} already registered")
        self.tools[tool.name] = tool

    def tool(self, name: str, description: str, params: dict[str, str] | None = None):
        def deco(fn):
            self.register(Tool(name, description, params or {}, fn))
            return fn
        return deco

    def call(self, name: str, args: dict[str, Any], services: dict[str, Any]) -> Any:
        if name not in self.tools:
            raise KeyError(f"unknown tool {name!r}")
        return self.tools[name].fn(args or {}, services)

    def describe(self) -> list[dict[str, Any]]:
        return [{"name": t.name, "description": t.description, "params": t.params} for t in self.tools.values()]

    def merged(self, other: ToolRegistry) -> ToolRegistry:
        out = ToolRegistry(dict(self.tools))
        for t in other.tools.values():
            out.register(t)
        return out
