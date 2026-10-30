# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""MCP servers as read-only lookup tools (and the ``Connectors`` bundle: sources, MCP servers, edges).

    mcp:
      wms:
        transport: http                          # Streamable HTTP
        url: "https://wms.example.in/mcp"
        headers: {Authorization: "Bearer {{env.SENTINEL_SECRET_WMS_MCP_TOKEN}}"}
        tools: [get_stock, get_order]            # allowlist: only these, and only if not marked as writing
      erp:
        transport: stdio
        command: ["python", "-m", "erp_mcp_server"]
        env: {ERP_DSN: "{{env.SENTINEL_SECRET_ERP_DSN}}"}
        tools: [find_invoice]

Stdio servers start a program on the server, so configuration may only name a command that the overlay's
code (``Overlay.mcp_commands``) or the operator (a YAML list of commands in the file named by
``SENTINEL_MCP_COMMANDS``) allows, exactly as written there. The program gets a minimal environment plus the
``env`` given here, whose ``{{env.X}}`` may only read configuration secrets (see ``envsecrets``).
HTTP servers are reached through ``egress`` (no internal addresses unless allowed, no redirects).

Each allowed tool becomes a Sentinel lookup tool named ``<server>.<tool>`` that the model, people's
investigations and branching playbooks may use. MCP tools can change things, so nothing is exposed unless
it is on the allowlist, and a tool whose annotations say it is not read-only is refused even if listed.
Actions that change the world stay in the overlay's code, behind the guardrails.

The client speaks JSON-RPC 2.0 (protocol 2025-06-18): ``initialize``, ``tools/list``, ``tools/call``, over a
subprocess's stdin/stdout or over HTTP (JSON or server-sent-event replies). Standard library only.
"""
from __future__ import annotations

import contextlib
import itertools
import json
import os
import subprocess
import threading
import urllib.error
import urllib.request
from typing import Any, Literal

from pydantic import BaseModel, Field

from .expr import render
from .tools import Tool

PROTOCOL = "2025-06-18"


class MCPError(RuntimeError):
    pass


class MCPServer(BaseModel):
    name: str
    transport: Literal["http", "stdio"]
    url: str | None = None
    headers: dict[str, str] = Field(default_factory=dict)
    command: list[str] | None = None
    env: dict[str, str] = Field(default_factory=dict)
    tools: list[str]
    timeout_s: float = 30.0
    description: str = ""

    def model_post_init(self, _ctx: Any) -> None:
        if self.transport == "http" and not (self.url or "").startswith(("http://", "https://")):
            raise ValueError(f"mcp {self.name}: http transport needs an http(s) url")
        if self.transport == "stdio" and not self.command:
            raise ValueError(f"mcp {self.name}: stdio transport needs a command")
        if not self.tools:
            raise ValueError(f"mcp {self.name}: list the tools to allow (nothing is exposed by default)")


class MCPClient:
    def __init__(self, server: MCPServer) -> None:
        self.server = server
        self._ids = itertools.count(1)
        self._lock = threading.Lock()
        self._proc: subprocess.Popen | None = None
        self._session: str | None = None
        self._ready = False
        self.server_info: dict[str, Any] = {}
        self.verified: set[str] | None = None      # allowlisted tools confirmed not to write (None: not listed yet)

    # ---- transport -----------------------------------------------------
    def _env_scope(self) -> dict[str, Any]:
        from .envsecrets import scope
        return {"env": scope()}

    def _http(self, msg: dict[str, Any], expect_reply: bool = True) -> dict[str, Any] | None:
        s = self.server
        headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream",
                   "MCP-Protocol-Version": PROTOCOL,
                   **{k: str(render(v, self._env_scope())) for k, v in s.headers.items()}}
        if self._session:
            headers["Mcp-Session-Id"] = self._session
        req = urllib.request.Request(s.url, data=json.dumps(msg).encode(), method="POST",  # noqa: S310
                                     headers=headers)
        from . import egress
        try:
            _, rh, raw = egress.open_url(req, s.timeout_s)
            sid = rh.get("Mcp-Session-Id")
            if sid:
                self._session = sid
            ctype = rh.get("Content-Type", "")
        except egress.EgressError as e:
            raise MCPError(f"mcp {s.name}: {e}") from None
        except urllib.error.HTTPError as e:
            raise MCPError(f"mcp {s.name}: HTTP {e.code}") from None
        except (urllib.error.URLError, OSError) as e:
            raise MCPError(f"mcp {s.name}: unreachable ({getattr(e, 'reason', e)})") from None
        if not expect_reply or not raw.strip():
            return None
        if "text/event-stream" in ctype:
            for line in raw.decode("utf-8", "replace").splitlines():
                if line.startswith("data:"):
                    try:
                        obj = json.loads(line[5:].strip())
                    except json.JSONDecodeError:
                        continue
                    if obj.get("id") == msg.get("id"):
                        return obj
            raise MCPError(f"mcp {s.name}: no reply in the event stream")
        return json.loads(raw)

    def _stdio(self, msg: dict[str, Any], expect_reply: bool = True) -> dict[str, Any] | None:
        s = self.server
        if self._proc is None or self._proc.poll() is not None:
            base = {k: v for k, v in os.environ.items()
                    if k in ("PATH", "HOME", "LANG", "LC_ALL", "TZ", "TMPDIR", "SYSTEMROOT", "PYTHONPATH")}
            env = {**base, **{k: str(render(v, self._env_scope())) for k, v in s.env.items()}}
            self._proc = subprocess.Popen(s.command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,  # noqa: S603
                                          stderr=subprocess.DEVNULL, env=env, text=True, bufsize=1)
        assert self._proc.stdin is not None and self._proc.stdout is not None
        self._proc.stdin.write(json.dumps(msg) + "\n")
        self._proc.stdin.flush()
        if not expect_reply:
            return None
        result: list[dict[str, Any]] = []

        def read() -> None:
            assert self._proc is not None and self._proc.stdout is not None
            for line in self._proc.stdout:
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if obj.get("id") == msg["id"]:
                    result.append(obj)
                    return
        t = threading.Thread(target=read, daemon=True)
        t.start()
        t.join(s.timeout_s)
        if not result:
            self.close()
            raise MCPError(f"mcp {s.name}: no reply within {s.timeout_s}s")
        return result[0]

    def _rpc(self, method: str, params: dict[str, Any] | None = None) -> Any:
        msg = {"jsonrpc": "2.0", "id": next(self._ids), "method": method, "params": params or {}}
        send = self._http if self.server.transport == "http" else self._stdio
        reply = send(msg)
        if reply is None:
            raise MCPError(f"mcp {self.server.name}: empty reply to {method}")
        if "error" in reply:
            err = reply["error"]
            raise MCPError(f"mcp {self.server.name}: {method} failed: {err.get('message', err)}")
        return reply.get("result")

    def _notify(self, method: str) -> None:
        msg = {"jsonrpc": "2.0", "method": method}
        (self._http if self.server.transport == "http" else self._stdio)(msg, expect_reply=False)

    # ---- protocol --------------------------------------------------------
    def _ensure(self) -> None:
        if self._ready and (self.server.transport == "http" or (self._proc and self._proc.poll() is None)):
            return
        info = self._rpc("initialize", {"protocolVersion": PROTOCOL, "capabilities": {},
                                        "clientInfo": {"name": "kbg-sentinel", "version": "0.9"}})
        self.server_info = info or {}
        self._notify("notifications/initialized")
        self._ready = True

    def list_tools(self) -> list[dict[str, Any]]:
        with self._lock:
            self._ensure()
            tools, cursor = [], None
            for _ in range(50):
                res = self._rpc("tools/list", {"cursor": cursor} if cursor else {})
                tools += res.get("tools", [])
                cursor = res.get("nextCursor")
                if not cursor:
                    break
            return tools

    def verify(self) -> list[tuple[str, str]]:
        """List the server's tools and decide which allowlisted ones may be used. Returns problems."""
        probs: list[tuple[str, str]] = []
        listed = {t["name"]: t for t in self.list_tools()}
        ok = set()
        for name in self.server.tools:
            t = listed.get(name)
            if t is None:
                probs.append(("error", f"mcp {self.server.name}: the server has no tool {name!r}"))
                continue
            ann = t.get("annotations") or {}
            if ann.get("readOnlyHint") is False or ann.get("destructiveHint") is True:
                probs.append(("error", f"mcp {self.server.name}: {name} says it changes data; lookups must be "
                                       "read-only (make it an overlay action instead)"))
                continue
            if ann.get("readOnlyHint") is not True:
                probs.append(("warning", f"mcp {self.server.name}: {name} does not declare itself read-only; "
                                         "it is exposed because it is on the allowlist"))
            ok.add(name)
        self.verified = ok
        self.listed = listed
        return probs

    def call_tool(self, name: str, args: dict[str, Any]) -> Any:
        if name not in self.server.tools:
            raise MCPError(f"mcp {self.server.name}: tool {name!r} is not on the allowlist")
        if self.verified is None:
            self.verify()
        if name not in (self.verified or set()):
            raise MCPError(f"mcp {self.server.name}: tool {name!r} is not usable as a read-only lookup")
        # a stdio server is one pipe: one call at a time; HTTP servers take calls in parallel
        guard = self._lock if self.server.transport == "stdio" else contextlib.nullcontext()
        with guard:
            for attempt in (1, 2):
                try:
                    self._ensure()
                    res = self._rpc("tools/call", {"name": name, "arguments": args or {}})
                    break
                except MCPError:
                    if attempt == 2:
                        raise
                    self._ready, self._session = False, None      # reconnect once
                    self.close()
        if res.get("structuredContent") is not None:
            out: Any = res["structuredContent"]
        else:
            texts = [c.get("text", "") for c in res.get("content", []) if c.get("type") == "text"]
            joined = "\n".join(texts)
            try:
                out = json.loads(joined)
            except json.JSONDecodeError:
                out = joined
        if res.get("isError"):
            return {"error": out}
        return out

    def close(self) -> None:
        if self._proc is not None:
            try:
                self._proc.kill()
            except OSError:
                pass
            self._proc = None
        self._ready = False


def _params(schema: dict[str, Any]) -> dict[str, str]:
    props = (schema or {}).get("properties") or {}
    required = set((schema or {}).get("required") or [])
    return {(k if k in required else f"{k}?"): str((v or {}).get("type", "any")) for k, v in props.items()}


def tools_from(client: MCPClient) -> tuple[list[Tool], list[tuple[str, str]]]:
    """Wrap the allowed tools of one server. Connects to describe them; if the server cannot be reached the
    tools are still registered (described as unknown) and checked on first use."""
    s = client.server
    try:
        probs = client.verify()
        names = sorted(client.verified or set())
        described = getattr(client, "listed", {})
    except MCPError as e:
        probs = [("warning", f"{e}; its tools are registered and will be checked when first used")]
        names, described = list(s.tools), {}
    tools = []
    for name in names:
        t = described.get(name, {})

        def fn(args: dict[str, Any], services: dict[str, Any], _n: str = name) -> Any:
            return client.call_tool(_n, args)
        tools.append(Tool(name=f"{s.name}.{name}", description=t.get("description") or f"{name} (from {s.name})",
                          params=_params(t.get("inputSchema") or {}), fn=fn))
    return tools, probs


class Connectors:
    """The published connectors configuration, ready to use: data sources and MCP lookup tools."""

    def __init__(self, data: dict[str, Any], allowed_commands: list[list[str]] | None = None) -> None:
        from .sources import parse_sources
        self.data = data or {}
        self.sources = parse_sources(self.data.get("sources") or {})
        self.servers = parse_servers(self.data.get("mcp") or {})
        for msg in stdio_problems(self.servers, allowed_commands):
            raise ValueError(msg)
        from . import connauth
        from .edges import build_edges
        from .httpactions import parse_actions, parse_lookups
        self.edges = build_edges(self.data.get("edges") or {})
        self.actions = parse_actions(self.data.get("actions") or {})
        self.lookups = parse_lookups(self.data.get("lookups") or {})
        self.auth = connauth.parse(self.data.get("auth") or {})
        connauth.configure(self.auth)
        self.clients = {n: MCPClient(s) for n, s in self.servers.items()}
        self.problems: list[tuple[str, str]] = []

    def connect_tools(self) -> list[Tool]:
        from .httpactions import lookup_tools
        tools: list[Tool] = lookup_tools(self.lookups)
        for client in self.clients.values():
            t, probs = tools_from(client)
            tools += t
            self.problems += probs
        return tools

    def close(self) -> None:
        for c in self.clients.values():
            c.close()


def allowed_stdio_commands(extra: list[list[str]] | None = None) -> list[list[str]]:
    """Commands stdio MCP servers may run: the overlay's plus the operator's file (SENTINEL_MCP_COMMANDS)."""
    out = [list(map(str, c)) for c in (extra or [])]
    path = os.environ.get("SENTINEL_MCP_COMMANDS")
    if path:
        import yaml
        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f) or []
        out += [list(map(str, c)) for c in data if isinstance(c, list)]
    return out


def stdio_problems(servers: dict[str, MCPServer], extra: list[list[str]] | None = None) -> list[str]:
    allowed = allowed_stdio_commands(extra)
    return [f"mcp {s.name}: the command {s.command} is not on this server's list of allowed MCP commands "
            "(Overlay.mcp_commands, or the file named by SENTINEL_MCP_COMMANDS)"
            for s in servers.values() if s.transport == "stdio" and list(s.command or []) not in allowed]


def parse_servers(data: dict[str, Any]) -> dict[str, MCPServer]:
    return {name: MCPServer.model_validate({**(spec or {}), "name": name}) for name, spec in (data or {}).items()}
