# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""Outbound requests made because of configuration: polled sources, MCP servers, edges, model servers.

Configuration can be published from the console, so a URL in it must not become a way into the server's
own network or a way out for its secrets. Every such request goes through ``open_url``:

* **Where:** the host is resolved and every address checked. Link-local and cloud metadata addresses
  (169.254.0.0/16, fe80::/10, ...) are always refused. Loopback, private (10/8, 172.16/12, 192.168/16,
  fc00::/7), carrier-grade NAT and other reserved ranges are refused unless allowed in
  ``SENTINEL_EGRESS_ALLOW`` - comma-separated CIDRs or host names, e.g. ``10.20.0.0/16,wms.acme.local``
  for a warehouse system on the office network.
* **No redirects:** a redirect could lead to an address the check refused.
* **Size:** responses over ``SENTINEL_EGRESS_MAX_BYTES`` (default 10 MB) are refused.

When a proxy is configured the destination is still checked here first.
"""
from __future__ import annotations

import ipaddress
import os
import socket
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

ALWAYS_BLOCKED = [ipaddress.ip_network(n) for n in (
    "169.254.0.0/16", "fe80::/10", "0.0.0.0/8", "::/128", "224.0.0.0/4", "ff00::/8", "100.100.100.200/32",
    "fd00:ec2::254/128")]
DEFAULT_MAX_BYTES = 10 * 1024 * 1024


class EgressError(RuntimeError):
    pass


def _allow() -> tuple[list[Any], set[str]]:
    nets, hosts = [], set()
    for item in (os.environ.get("SENTINEL_EGRESS_ALLOW") or "").split(","):
        item = item.strip()
        if not item:
            continue
        try:
            nets.append(ipaddress.ip_network(item, strict=False))
        except ValueError:
            hosts.add(item.lower())
    return nets, hosts


def check_url(url: str) -> None:
    u = urllib.parse.urlsplit(url)
    if u.scheme not in ("http", "https"):
        raise EgressError(f"only http(s) URLs may be called, not {u.scheme!r}")
    host = (u.hostname or "").lower()
    if not host:
        raise EgressError("URL has no host")
    check_host(host, u.port or (443 if u.scheme == "https" else 80))


def check_host(host: str, port: int = 443) -> None:
    nets, hosts = _allow()
    named = host.lower() in hosts
    try:
        addrs = {ai[4][0] for ai in socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)}
    except socket.gaierror:
        return                      # cannot be resolved here: the request fails (or a proxy resolves it)
    for a in addrs:
        ip = ipaddress.ip_address(a.split("%", 1)[0])
        if getattr(ip, "ipv4_mapped", None):
            ip = ip.ipv4_mapped
        listed = named or any(ip in n for n in nets if n.version == ip.version)
        if any(ip in n for n in ALWAYS_BLOCKED if n.version == ip.version) and not any(
                ip in n for n in nets if n.version == ip.version):
            raise EgressError(f"{host} resolves to {ip}, a link-local or metadata address; refused")
        internal = ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_unspecified or (
            ip.version == 4 and ip in ipaddress.ip_network("100.64.0.0/10"))
        if internal and not listed:
            raise EgressError(f"{host} resolves to {ip}, an internal address; add it to SENTINEL_EGRESS_ALLOW "
                              "if this system is meant to be reached")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    handler_order = 100             # before the default redirect handler

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001,ARG002
        raise EgressError(f"{req.full_url} redirected to {newurl}; redirects are not followed")


def opener(*handlers: Any, base: Any = None) -> Any:
    """An opener that refuses redirects (pass `base` to add the refusal to an existing opener)."""
    op = base if base is not None else urllib.request.build_opener(*handlers)
    if not any(isinstance(h, _NoRedirect) for h in getattr(op, "handlers", [])):
        op.add_handler(_NoRedirect())
    return op


def max_bytes() -> int:
    return int(os.environ.get("SENTINEL_EGRESS_MAX_BYTES") or DEFAULT_MAX_BYTES)


def read_capped(resp: Any, limit: int | None = None) -> bytes:
    limit = limit or max_bytes()
    data = resp.read(limit + 1)
    if len(data) > limit:
        raise EgressError(f"response larger than {limit} bytes; refused")
    return data


def open_url(req: urllib.request.Request, timeout: float, *, base_opener: Any = None) -> tuple[int, Any, bytes]:
    """Check, send without following redirects, read with a size cap. Returns (status, headers, body)."""
    check_url(req.full_url)
    op = opener(base=base_opener) if base_opener is not None else opener()
    with op.open(req, timeout=timeout) as resp:
        return resp.status, resp.headers, read_capped(resp)
