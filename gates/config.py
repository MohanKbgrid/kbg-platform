# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""Surface 2, Config: the seven gate tests of canon/surfaces/02-config.md (CFG-1 .. CFG-7)."""
from __future__ import annotations

import base64

from .framework import Gate, Refused, make_gate

CANON = "canon/surfaces/02-config.md, Gate tests"
SECRET = "S3cr3t-Value-0042"


def _leaks(secret: str, text: str) -> bool:
    """True if the text shows the secret, reversed, base64-encoded, or any four-character window of it."""
    enc = base64.b64encode(secret.encode()).decode()
    return (secret in text or secret[::-1] in text or enc in text
            or any(secret[i:i + 4] in text for i in range(len(secret) - 3)))


def cfg1(s) -> "list[str]":
    """A secret cannot be read back: not in any read response, and the mask is not reversible (gate 1)."""
    s.store_secret(SECRET)
    p = [f"the secret (or a recoverable form of it) appears in the response of {name}"
         for name, body in sorted(s.read_endpoints().items()) if _leaks(SECRET, str(body))]
    if _leaks(SECRET, str(s.mask())):
        p.append(f"the returned mask reveals part of the secret: {s.mask()!r}")
    return p


def cfg2(s) -> "list[str]":
    """The in-process resolver decrypts; no route serialises its output (gate 2)."""
    s.store_secret(SECRET)
    p = []
    if s.resolve("svc") != SECRET:
        p.append("the in-process resolver does not return the real value")
    bad = s.routes_serialising_resolver()
    if bad:
        p.append(f"routes that serialise the decrypting resolver to the client: {sorted(bad)}")
    return p


def cfg3(s) -> "list[str]":
    """A rotation supersedes: three versions after two changes, one active, each audited (gate 3)."""
    s.store_secret("v1-secret", actor="alice")
    s.rotate("v2-secret", actor="bob")
    s.rotate("v3-secret", actor="carol")
    vs = s.versions()
    p = []
    if len(vs) != 3:
        p.append(f"expected three versions after two rotations, found {len(vs)}: history was overwritten")
    if sum(1 for v in vs if v["active"]) != 1:
        p.append(f"expected exactly one active version, found {sum(1 for v in vs if v['active'])}")
    if [v.get("changed_by") for v in vs] != ["alice", "bob", "carol"]:
        p.append(f"the audit does not name who changed each version: {[v.get('changed_by') for v in vs]}")
    return p


def cfg4(s) -> "list[str]":
    """Company config beats global; deleting it falls back; deleting that REFUSES (gate 4)."""
    s.set_cfg("global", "limit", 10)
    s.set_cfg("A", "limit", 20)
    p = []
    if s.resolve_cfg("A", "limit") != 20:
        p.append("global config won over the company's own")
    s.drop_cfg("A", "limit")
    if s.resolve_cfg("A", "limit") != 10:
        p.append("deleting the company row did not fall back to global")
    s.drop_cfg("global", "limit")
    try:
        p.append(f"with no row anywhere the resolver returned {s.resolve_cfg('A', 'limit')!r} instead of refusing")
    except Refused:
        pass
    return p


def cfg5(s) -> "list[str]":
    """A missing policy row raises a NAMED error; it never proceeds on a built-in number (gate 5)."""
    s.delete_policy("A")
    try:
        got = s.use_feature("A")
        return [f"with the policy row deleted the feature proceeded and returned {got!r}"]
    except Refused as e:
        return [] if e.code else ["the refusal carries no name"]
    except Exception as e:  # noqa: BLE001
        return [f"the failure was an unnamed {type(e).__name__}, not a named refusal"]


def cfg6(s) -> "list[str]":
    """Changing a threshold changes the output while the measurement stays identical (gate 6)."""
    m = s.measurement()
    a, b = s.run({"threshold": 1}, m), s.run({"threshold": 2}, m)
    p = []
    if a["measured"] != b["measured"]:
        p.append(f"the measurement moved with the configuration: {a['measured']!r} vs {b['measured']!r}")
    if a["result"] == b["result"]:
        p.append("the result did not change when the threshold changed: a hardcoded constant passes only the happy path")
    return p


def cfg7(s) -> "list[str]":
    """Purpose routing is provider-agnostic: a policy edit re-routes, and no code was touched (gate 7)."""
    s.set_routing("approval_pending", "provider_one")
    first = s.send("approval_pending", "hello")
    s.set_routing("approval_pending", "provider_two")
    second = s.send("approval_pending", "hello")
    p = []
    if (first, second) != ("provider_one", "provider_two"):
        p.append(f"changing the routing row did not change the provider used: {first!r} then {second!r}")
    if s.code_touched():
        p.append("re-pointing a purpose required a code change")
    return p


class RefConfig:
    """PROOF subject. Flaws: raw_value_endpoint, partial_mask, base64_mask, resolver_masked,
    route_serialises, overwrites, two_active, blank_audit, global_wins, default_fallback, silent_default,
    unnamed_error, hardcoded_constant, measurement_moves, provider_in_code."""

    def __init__(self, flaws=frozenset()):
        self.f = frozenset(flaws)
        self._secret, self._versions = None, []
        self.cfg, self.policy, self.routing = {}, {"A": True}, {}

    # secrets
    def store_secret(self, v, actor="system"):
        self._secret = v
        self._versions = [{"value": v, "active": True, "changed_by": actor if "blank_audit" not in self.f else ""}]

    def mask(self):
        if "partial_mask" in self.f:
            return self._secret[:6] + "****"
        if "base64_mask" in self.f:
            return base64.b64encode(self._secret.encode()).decode()
        return "********"

    def read_endpoints(self):
        body = {"GET /config": "credential: " + self.mask()}
        if "raw_value_endpoint" in self.f:
            body["GET /config/raw"] = "value: " + self._secret
        return body

    def resolve(self, service):
        return "********" if "resolver_masked" in self.f else self._secret

    def routes_serialising_resolver(self):
        return ["GET /config/debug"] if "route_serialises" in self.f else []

    def rotate(self, v, actor):
        self._secret = v
        row = {"value": v, "active": True, "changed_by": actor if "blank_audit" not in self.f else ""}
        if "overwrites" in self.f:
            self._versions = [row]
            return
        if "two_active" not in self.f:
            for r in self._versions:
                r["active"] = False
        self._versions.append(row)

    def versions(self):
        return list(self._versions)

    # company over global
    def set_cfg(self, owner, key, v):
        self.cfg[(owner, key)] = v

    def drop_cfg(self, owner, key):
        self.cfg.pop((owner, key), None)

    def resolve_cfg(self, company, key):
        own, glob = self.cfg.get((company, key)), self.cfg.get(("global", key))
        if "global_wins" in self.f and glob is not None:
            return glob
        if own is not None:
            return own
        if glob is not None:
            return glob
        if "default_fallback" in self.f:
            return 99
        raise Refused("config_missing", f"no {key} for {company}")

    # policy
    def delete_policy(self, company):
        self.policy.pop(company, None)

    def use_feature(self, company):
        if company in self.policy:
            return "ok"
        if "silent_default" in self.f:
            return "ok-with-built-in-number"
        if "unnamed_error" in self.f:
            raise RuntimeError("boom")
        raise Refused("policy_missing", f"no policy row for {company}")

    # behaviour
    def measurement(self):
        return 10

    def run(self, cfg, m):
        t = 1 if "hardcoded_constant" in self.f else cfg["threshold"]
        return {"measured": (m + cfg["threshold"]) if "measurement_moves" in self.f else m, "result": m > t * 5}

    # routing
    def set_routing(self, purpose, provider):
        self.routing[purpose] = provider

    def send(self, purpose, msg):
        return "provider_one" if "provider_in_code" in self.f else self.routing[purpose]

    def code_touched(self):
        return False


GATES: "list[Gate]" = [
    make_gate("CFG-1", 2, "a secret cannot be read back", CANON + " 1", cfg1, RefConfig,
              "raw_value_endpoint", "partial_mask", "base64_mask"),
    make_gate("CFG-2", 2, "the resolver decrypts and the API does not", CANON + " 2", cfg2, RefConfig,
              "resolver_masked", "route_serialises"),
    make_gate("CFG-3", 2, "a rotation supersedes rather than overwrites", CANON + " 3", cfg3, RefConfig,
              "overwrites", "two_active", "blank_audit"),
    make_gate("CFG-4", 2, "company config beats global, then fallback, then refusal", CANON + " 4", cfg4,
              RefConfig, "global_wins", "default_fallback"),
    make_gate("CFG-5", 2, "a missing policy row refuses with a named error", CANON + " 5", cfg5, RefConfig,
              "silent_default", "unnamed_error"),
    make_gate("CFG-6", 2, "changing config changes behaviour with no deploy", CANON + " 6", cfg6, RefConfig,
              "hardcoded_constant", "measurement_moves"),
    make_gate("CFG-7", 2, "purpose routing is provider-agnostic", CANON + " 7", cfg7, RefConfig, "provider_in_code"),
]
