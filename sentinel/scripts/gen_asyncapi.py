# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""Write docs/asyncapi.yaml (AsyncAPI 3.0): the event envelope and each event type the shipped templates and
connectors emit or handle.

    python scripts/gen_asyncapi.py            # write
    python scripts/gen_asyncapi.py --check    # exit 1 if the file is out of date (CI; tests/test_asyncapi.py)

Everything is read from the code and the shipped YAML: the envelope from `sentinel.models.Event`, the event
types from the templates' fingerprint rules and patterns and from the connector templates (their `events`,
fingerprint rules and source `emit` blocks). A payload property is listed when a fingerprint rule reads it or a
source writes it; a payload is not closed, because a sender may add fields.
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "docs" / "asyncapi.yaml"
SERVER_HOST = "sentinel.example.com"        # placeholder: the address of your Sentinel API


def _ident(event_type: str) -> str:
    return "".join(c if c.isalnum() else "_" for c in event_type)


class _Types:
    def __init__(self) -> None:
        self.by_type: dict[str, dict[str, Any]] = {}

    def get(self, t: str) -> dict[str, Any]:
        return self.by_type.setdefault(t, {"from": set(), "props": {}})

    def prop(self, t: str, path: str, kind: str | None = None) -> None:
        name = path.split(".", 1)[0]
        cur = self.get(t)["props"]
        if kind is not None and "." not in path:
            cur[name] = kind
        else:
            cur.setdefault(name, None)

    def fingerprints(self, t_from: str, rules: list[dict[str, Any]]) -> None:
        for r in rules or []:
            t = r["event_type"]
            self.get(t)["from"].add(t_from)
            for path in (r.get("fields") or {}).values():
                self.prop(t, str(path))
            for b in (r.get("buckets") or {}).values():
                self.prop(t, str(b["field"]), "number")


def collect() -> _Types:
    from sentinel import connectors, templates
    types = _Types()
    for name in templates.names():
        tpl = templates.load(name)
        reg = tpl.get("registry") or {}
        types.fingerprints(f"template:{name}", reg.get("fingerprints") or [])
        for p in reg.get("patterns") or []:
            for t in p.get("event_types") or []:
                if t != "*":
                    types.get(t)["from"].add(f"template:{name}")
    for name in connectors.names():
        c = connectors.load(name)
        for t in c.get("events") or []:
            types.get(t)["from"].add(f"connector:{name}")
        types.fingerprints(f"connector:{name}", c.get("fingerprints") or [])
        for src in ((c.get("connectors") or {}).get("sources") or {}).values():
            for e in src.get("emit") or []:
                t = str(e.get("type", ""))
                if not t or "{{" in t:
                    continue
                types.get(t)["from"].add(f"connector:{name}")
                if isinstance(e.get("payload"), dict):
                    for k in e["payload"]:
                        types.prop(t, str(k))
    return types


def _origin(sources: set[str]) -> str:
    return "Emitted or handled by: " + ", ".join(sorted(sources)) + "."


def build() -> dict[str, Any]:
    import sentinel
    from sentinel.models import Event
    ev = Event.model_json_schema(ref_template="#/components/schemas/{model}")
    ev.pop("$defs", None)
    ev["description"] = ("The canonical envelope every receiver normalises its source into. Duplicates are "
                         "recognised per tenant, source and idempotency_key (or the id when there is no key).")
    schemas: dict[str, Any] = {"Event": ev}
    messages: dict[str, Any] = {}
    for t, info in sorted(collect().by_type.items()):
        ident = _ident(t)
        props = {}
        for name, kind in sorted(info["props"].items()):
            props[name] = {"type": kind} if kind else {}
        schemas[f"Payload_{ident}"] = {"type": "object", "description": f"Payload of {t}. " + _origin(info["from"]),
                                       "properties": props, "additionalProperties": True}
        messages[ident] = {
            "name": t, "title": t, "summary": _origin(info["from"]),
            "payload": {"allOf": [{"$ref": "#/components/schemas/Event"},
                                  {"properties": {"type": {"const": t},
                                                  "payload": {"$ref": f"#/components/schemas/Payload_{ident}"}}}]},
        }
    schemas["CloudEvent"] = {
        "type": "object", "required": ["specversion", "id", "source", "type"],
        "description": "A CloudEvents 1.0 event, structured mode. Mapped into Event: id -> idempotency_key, "
                       "subject -> payload.ce_subject, data -> payload, extension tenant -> tenant, "
                       "extension correlationid -> correlation_id. Binary mode carries the same attributes as "
                       "ce-* headers with the data as the body.",
        "properties": {"specversion": {"const": "1.0"}, "id": {"type": "string", "minLength": 1},
                       "source": {"type": "string", "minLength": 1}, "type": {"type": "string", "minLength": 1},
                       "time": {"type": "string", "format": "date-time"}, "subject": {"type": "string"},
                       "datacontenttype": {"type": "string"}, "data": {}, "data_base64": {"type": "string"},
                       "tenant": {"type": "string"}, "correlationid": {"type": "string"}}}
    messages["CloudEvent"] = {"name": "CloudEvent", "contentType": "application/cloudevents+json",
                              "payload": {"$ref": "#/components/schemas/CloudEvent"}}
    event_msgs = {k: {"$ref": f"#/components/messages/{k}"} for k in messages if k != "CloudEvent"}
    return {
        "asyncapi": "3.0.0",
        "info": {
            "title": "Sentinel event contracts", "version": sentinel.__version__,
            "description": "Events a service sends to Sentinel (POST /v1/events or /v1/cloudevents, service bearer "
                           "token), and the event types the shipped domain templates and connector templates "
                           "use. Generated by scripts/gen_asyncapi.py; do not edit by hand.",
            "license": {"name": "Apache-2.0", "url": "https://www.apache.org/licenses/LICENSE-2.0"}},
        "defaultContentType": "application/json",
        "servers": {"api": {"host": SERVER_HOST, "protocol": "https", "description": "Placeholder host.",
                            "security": [{"$ref": "#/components/securitySchemes/serviceToken"}]}},
        "channels": {
            "events": {"address": "/v1/events", "description": "Canonical envelope, JSON.", "messages": event_msgs},
            "cloudevents": {"address": "/v1/cloudevents",
                            "description": "CloudEvents 1.0, structured or binary mode.",
                            "messages": {"CloudEvent": {"$ref": "#/components/messages/CloudEvent"}}}},
        "operations": {
            "receiveEvent": {"action": "receive", "channel": {"$ref": "#/channels/events"},
                             "summary": "Send an event in the canonical envelope.",
                             "security": [{"$ref": "#/components/securitySchemes/serviceToken"}]},
            "receiveCloudEvent": {"action": "receive", "channel": {"$ref": "#/channels/cloudevents"},
                                  "summary": "Send a CloudEvents 1.0 event.",
                                  "security": [{"$ref": "#/components/securitySchemes/serviceToken"}]}},
        "components": {
            "securitySchemes": {"serviceToken": {"type": "http", "scheme": "bearer",
                                                 "description": "A service token (only its SHA-256 is configured)."}},
            "schemas": schemas, "messages": messages},
    }


def render() -> str:
    head = ("# Generated by scripts/gen_asyncapi.py from the code and the shipped templates: do not edit by hand.\n"
            "# Check: python scripts/gen_asyncapi.py --check\n")
    return head + yaml.safe_dump(build(), sort_keys=False, allow_unicode=True, width=110)


def main() -> int:
    sys.path.insert(0, str(ROOT))
    text = render()
    if "--check" in sys.argv:
        if not OUT.exists() or OUT.read_text(encoding="utf-8") != text:
            print("docs/asyncapi.yaml is out of date: run python scripts/gen_asyncapi.py", file=sys.stderr)
            return 1
        return 0
    OUT.write_text(text, encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
