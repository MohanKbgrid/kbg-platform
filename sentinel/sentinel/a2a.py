# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""A2A (Agent2Agent) server surface, beside the MCP client: other agent frameworks hand cases in and take
decisions back. Switched off unless ``create_app(..., a2a=True)``.

Implements A2A **1.0** (a2aproject/A2A, specification 1.0.x; the JSON-RPC binding of section 9, ProtoJSON field
names of ``a2a.proto``):

* ``GET /.well-known/agent-card.json``: the Agent Card (public, cacheable). Two skills: ``submit_case`` and
  ``get_case``.
* ``POST /a2a``: JSON-RPC 2.0. ``SendMessage`` (hand a case in), ``GetTask`` and ``ListTasks`` (take the state and
  decision back). ``CancelTask`` is refused (a case is closed by a person in Sentinel). Streaming, push
  notifications and the extended card are not offered and answer with the matching A2A error.

How the A2A model maps onto Sentinel:

* A **task** is a Sentinel case (incident). The task id is the incident id. A message that groups into a case
  already open (same fingerprint) returns that case's task.
* ``SendMessage`` carries one ``data`` part ``{"type": ..., "payload": {...}, "correlation_id": ...}`` (and/or
  ``text`` parts, which go to ``payload.text``). It becomes an ordinary event with ``source = "a2a:<caller>"``;
  the message id is the idempotency key, so a retry is a duplicate, not a second case.
* State: open -> SUBMITTED; suppressed, resolving, awaiting a person, resolved, failed -> WORKING (a person may
  still decide; the status message says what it waits for); dispositioned -> COMPLETED. The decision comes back as
  an artifact ``decision`` (code, resolver, outcome, reversed, ...).
* **Authority.** The caller needs the same service bearer token as ``/v1/events`` and the same rate limit and size
  caps. An agent can never approve: no A2A method reaches a decision, an answer, a promotion or a bulk
  action; a message that continues an existing task (``taskId``) is refused. Sentinel's own rule holds as well
  (``AgentPolicy`` refuses APPROVE; ``org.authorise`` denies APPROVE to an agent).
* **Scope.** The tenant is the server's, never the caller's (a request naming another tenant is refused). A caller
  sees only the tasks it submitted itself; any other task id is "not found" (no existence leak).
* **Audit.** Every submission is recorded (``a2a_task_submitted``: caller, tenant, message id, context), as is
  every refusal (``a2a_refused``). The case itself carries the usual audit trail.
"""
from __future__ import annotations

import hashlib
import json
import os
from typing import Any

from .models import Event, IncidentState, new_id

try:                                          # only the HTTP mounting needs FastAPI (names must be module-level)
    from fastapi import Depends, Header, Request
    from fastapi.concurrency import run_in_threadpool
    from fastapi.responses import JSONResponse
except ImportError:  # pragma: no cover
    Depends = Header = Request = run_in_threadpool = JSONResponse = None  # type: ignore[assignment,misc]

PROTOCOL_VERSION = "1.0"                 # Major.Minor, as the specification asks for the A2A-Version header
DOMAIN = "a2a-protocol.org"
MAX_PARTS = 16
MAX_PAGE = 100

# JSON-RPC and A2A error codes (specification section 5.4 / 9.5)
PARSE, INVALID_REQUEST, METHOD_NOT_FOUND, INVALID_PARAMS, INTERNAL = -32700, -32600, -32601, -32602, -32603
TASK_NOT_FOUND, TASK_NOT_CANCELABLE, PUSH_UNSUPPORTED, UNSUPPORTED_OP = -32001, -32002, -32003, -32004
CONTENT_TYPE_UNSUPPORTED, EXT_CARD_NOT_CONFIGURED, VERSION_UNSUPPORTED = -32005, -32007, -32009

_REASONS = {TASK_NOT_FOUND: "TASK_NOT_FOUND", TASK_NOT_CANCELABLE: "TASK_NOT_CANCELABLE",
            PUSH_UNSUPPORTED: "PUSH_NOTIFICATION_NOT_SUPPORTED", UNSUPPORTED_OP: "UNSUPPORTED_OPERATION",
            CONTENT_TYPE_UNSUPPORTED: "CONTENT_TYPE_NOT_SUPPORTED",
            EXT_CARD_NOT_CONFIGURED: "EXTENDED_AGENT_CARD_NOT_CONFIGURED", VERSION_UNSUPPORTED: "VERSION_NOT_SUPPORTED"}

# methods that are not offered, and the A2A error that says so
_NOT_OFFERED = {"SendStreamingMessage": (UNSUPPORTED_OP, "streaming is not offered; poll GetTask"),
                "SubscribeToTask": (UNSUPPORTED_OP, "streaming is not offered; poll GetTask"),
                "CreateTaskPushNotificationConfig": (PUSH_UNSUPPORTED, "push notifications are not offered"),
                "GetTaskPushNotificationConfig": (PUSH_UNSUPPORTED, "push notifications are not offered"),
                "ListTaskPushNotificationConfigs": (PUSH_UNSUPPORTED, "push notifications are not offered"),
                "DeleteTaskPushNotificationConfig": (PUSH_UNSUPPORTED, "push notifications are not offered"),
                "GetExtendedAgentCard": (EXT_CARD_NOT_CONFIGURED, "there is no extended agent card")}


class A2AError(Exception):
    def __init__(self, code: int, message: str, metadata: dict[str, str] | None = None,
                 fields: list[tuple[str, str]] | None = None) -> None:
        super().__init__(message)
        self.code, self.message, self.metadata, self.fields = code, message, metadata or {}, fields or []

    def body(self) -> dict[str, Any]:
        data: list[dict[str, Any]] = []
        if self.code in _REASONS:
            data.append({"@type": "type.googleapis.com/google.rpc.ErrorInfo", "reason": _REASONS[self.code],
                         "domain": DOMAIN, "metadata": self.metadata})
        if self.fields:
            data.append({"@type": "type.googleapis.com/google.rpc.BadRequest",
                         "fieldViolations": [{"field": f, "description": d} for f, d in self.fields]})
        out: dict[str, Any] = {"code": self.code, "message": self.message}
        if data:
            out["data"] = data
        return out


# ------------------------------------------------------------------------------------------------ Agent Card
def agent_card(base_url: str, version: str) -> dict[str, Any]:
    """The Agent Card (section 4.4 / 8.5). Public: it describes capabilities and says where to authenticate."""
    base = base_url.rstrip("/")
    return {
        "name": "Sentinel",
        "description": ("Exception-handling agent framework. Other agents hand cases (events that need a decision) "
                        "to Sentinel and take the state and the decision back. Sentinel's people decide what an "
                        "agent may not: an agent can submit and read, never approve."),
        "supportedInterfaces": [{"url": f"{base}/a2a", "protocolBinding": "JSONRPC",
                                 "protocolVersion": PROTOCOL_VERSION}],
        "provider": {"organization": "KB Grid", "url": "https://github.com/MohanKbgrid/kbg-platform"},
        "version": version,
        "documentationUrl": "https://github.com/MohanKbgrid/kbg-platform/blob/main/sentinel/docs/OPERATIONS.md",
        "capabilities": {"streaming": False, "pushNotifications": False, "extendedAgentCard": False},
        "securitySchemes": {"bearer": {"httpAuthSecurityScheme": {
            "scheme": "Bearer", "description": "A Sentinel service token (the same one used for /v1/events)."}}},
        "securityRequirements": [{"schemes": {"bearer": {"list": []}}}],
        "defaultInputModes": ["application/json", "text/plain"],
        "defaultOutputModes": ["application/json"],
        "skills": [
            {"id": "submit_case", "name": "Submit a case",
             "description": ("Hand Sentinel an event that needs a decision. Send one data part "
                             '{"type": "<event type>", "payload": {...}, "correlation_id": "<optional>"} '
                             "(or a text part). The reply is a task whose id is the case id. The message id is "
                             "the idempotency key."),
             "tags": ["case", "exception", "hand-in"],
             "examples": ['{"type": "order.stuck", "payload": {"order": "SO-1", "reason": "no stock"}}'],
             "inputModes": ["application/json", "text/plain"], "outputModes": ["application/json"]},
            {"id": "get_case", "name": "Get a case's state and decision",
             "description": ("GetTask with the task id returns the state and, once a person or an approved "
                             "playbook has decided, the decision as an artifact. ListTasks lists the cases this "
                             "caller handed in."),
             "tags": ["case", "decision", "hand-back"],
             "examples": ['{"jsonrpc": "2.0", "id": 1, "method": "GetTask", "params": {"id": "inc_..."}}'],
             "inputModes": ["application/json"], "outputModes": ["application/json"]},
        ],
    }


# ------------------------------------------------------------------------------------------------ task mapping
_STATE = {IncidentState.OPEN: "TASK_STATE_SUBMITTED", IncidentState.SUPPRESSED: "TASK_STATE_WORKING",
          IncidentState.RESOLVING: "TASK_STATE_WORKING", IncidentState.AWAITING_HUMAN: "TASK_STATE_WORKING",
          IncidentState.RESOLVED: "TASK_STATE_WORKING", IncidentState.FAILED: "TASK_STATE_WORKING",
          IncidentState.DISPOSITIONED: "TASK_STATE_COMPLETED"}
_WHY = {IncidentState.OPEN: "received", IncidentState.SUPPRESSED: "held back by a related case",
        IncidentState.RESOLVING: "an agent is working on it",
        IncidentState.AWAITING_HUMAN: "waiting for a person to review",
        IncidentState.RESOLVED: "action done, waiting to be closed",
        IncidentState.FAILED: "could not be resolved, a person will decide",
        IncidentState.DISPOSITIONED: "decided"}


def _iso(dt: Any) -> str:
    return dt.isoformat().replace("+00:00", "Z")


class A2AService:
    """The operations, independent of HTTP. ``caller`` is the service token's id."""

    def __init__(self, engine: Any, tenant: Any = None, max_bytes: int | None = None) -> None:
        self.engine = engine
        self._tenant = tenant                       # callable -> str, or str, or None
        self.max_bytes = max_bytes

    # ---- scope -----------------------------------------------------------
    def tenant(self) -> str:
        t = self._tenant() if callable(self._tenant) else self._tenant
        return str(t or "default")

    def _audit(self, incident_id: str | None, kind: str, data: dict[str, Any]) -> None:
        self.engine.store.audit(incident_id, kind, data)

    def refuse(self, caller: str, method: str, code: int, why: str) -> None:
        self._audit(None, "a2a_refused", {"by": caller, "tenant": self.tenant(), "method": method, "code": code,
                                          "reason": why[:300]})

    def _submissions(self, caller: str, limit: int = 5000) -> list[dict[str, Any]]:
        """This caller's submissions in this tenant, newest first (one per task: the first submission)."""
        seen: set[str] = set()
        out = []
        for row in self.engine.store.recent_audit(limit, ["a2a_task_submitted"]):
            d = row["data"]
            if d.get("by") != caller or d.get("tenant") != self.tenant() or not row["incident_id"]:
                continue
            if row["incident_id"] in seen:
                continue
            seen.add(row["incident_id"])
            out.append({**d, "incident_id": row["incident_id"], "ts": row["ts"]})
        return out

    def _own(self, caller: str, task_id: str) -> dict[str, Any]:
        for s in self._submissions(caller):
            if s["incident_id"] == task_id:
                return s
        raise A2AError(TASK_NOT_FOUND, "Task not found", {"taskId": str(task_id)[:100]})

    # ---- task ------------------------------------------------------------
    def task(self, sub: dict[str, Any], *, artifacts: bool = True) -> dict[str, Any]:
        inc = self.engine.store.get_incident(sub["incident_id"])
        if inc is None:
            raise A2AError(TASK_NOT_FOUND, "Task not found", {"taskId": sub["incident_id"]})
        status: dict[str, Any] = {
            "state": _STATE[inc.state], "timestamp": _iso(inc.updated_at),
            "message": {"messageId": f"status-{inc.id}-{inc.state.value}", "role": "ROLE_AGENT",
                        "contextId": sub["context_id"], "taskId": inc.id,
                        "parts": [{"text": _WHY[inc.state]}]}}
        task: dict[str, Any] = {"id": inc.id, "contextId": sub["context_id"], "status": status,
                                "metadata": {"sentinel": {"incidentState": inc.state.value,
                                                          "pattern": inc.pattern_id}}}
        d = self.engine.store.get_disposition(inc.id)
        if d is not None and artifacts:
            task["artifacts"] = [{"artifactId": f"decision-{inc.id}", "name": "decision",
                                  "description": "How the case was decided.",
                                  "parts": [{"data": {
                                      "code": d.code, "resolver": d.resolver, "outcome": d.outcome,
                                      "outcomeDetail": d.outcome_detail, "reversed": d.reversed,
                                      "agreedWithProposal": d.agreed_with_proposal,
                                      "actions": [s.action for s in d.steps], "note": d.note[:500]},
                                      "mediaType": "application/json"}]}]
        return task

    # ---- methods ---------------------------------------------------------
    def send_message(self, caller: str, params: dict[str, Any]) -> dict[str, Any]:
        msg = params.get("message")
        if not isinstance(msg, dict):
            raise A2AError(INVALID_PARAMS, "Invalid parameters", fields=[("message", "required")])
        if params.get("tenant") not in (None, "", self.tenant()):
            raise A2AError(INVALID_PARAMS, "Invalid parameters",
                           fields=[("tenant", "the tenant is the server's; it cannot be chosen by the caller")])
        if msg.get("taskId") or msg.get("referenceTaskIds"):
            # a continuation would be the way an agent answers a case: it cannot (APPROVE is never an agent's)
            raise A2AError(UNSUPPORTED_OP, "this task takes no further input from agents; decisions are made by "
                                           "people in Sentinel")
        mid = msg.get("messageId")
        if not isinstance(mid, str) or not 1 <= len(mid) <= 200:
            raise A2AError(INVALID_PARAMS, "Invalid parameters", fields=[("message.messageId", "1 to 200 characters")])
        if msg.get("role") != "ROLE_USER":
            raise A2AError(INVALID_PARAMS, "Invalid parameters", fields=[("message.role", "must be ROLE_USER")])
        parts = msg.get("parts")
        if not isinstance(parts, list) or not 1 <= len(parts) <= MAX_PARTS:
            raise A2AError(INVALID_PARAMS, "Invalid parameters",
                           fields=[("message.parts", f"between 1 and {MAX_PARTS} parts")])
        etype, payload, texts, corr = "a2a.case", {}, [], None
        for i, p in enumerate(parts):
            if not isinstance(p, dict):
                raise A2AError(INVALID_PARAMS, "Invalid parameters", fields=[(f"message.parts[{i}]", "an object")])
            if "text" in p:
                if not isinstance(p["text"], str):
                    raise A2AError(INVALID_PARAMS, "Invalid parameters", fields=[(f"message.parts[{i}].text", "text")])
                texts.append(p["text"])
            elif "data" in p:
                d = p["data"]
                if not isinstance(d, dict):
                    raise A2AError(INVALID_PARAMS, "Invalid parameters",
                                   fields=[(f"message.parts[{i}].data", "an object")])
                unknown = set(d) - {"type", "payload", "correlation_id"}
                if unknown:
                    raise A2AError(INVALID_PARAMS, "Invalid parameters",
                                   fields=[(f"message.parts[{i}].data", f"unknown keys {sorted(unknown)}; send "
                                                                         "type, payload, correlation_id")])
                if "type" in d:
                    if not isinstance(d["type"], str) or not d["type"].strip():
                        raise A2AError(INVALID_PARAMS, "Invalid parameters",
                                       fields=[(f"message.parts[{i}].data.type", "a non-blank string")])
                    etype = d["type"].strip()
                if "payload" in d:
                    if not isinstance(d["payload"], dict):
                        raise A2AError(INVALID_PARAMS, "Invalid parameters",
                                       fields=[(f"message.parts[{i}].data.payload", "an object")])
                    payload.update(d["payload"])
                if d.get("correlation_id") is not None:
                    corr = str(d["correlation_id"])[:200]
            else:
                raise A2AError(CONTENT_TYPE_UNSUPPORTED, "only text and data parts are accepted",
                               {"part": str(i)})
        if texts:
            payload["text"] = "\n".join(texts)
        context_id = msg.get("contextId") if isinstance(msg.get("contextId"), str) and msg.get("contextId") \
            else new_id("ctx")
        ev = Event(type=etype, source=f"a2a:{caller}", tenant=self.tenant(), idempotency_key=mid[:200],
                   correlation_id=corr or context_id[:200], payload=payload)
        try:
            res = self.engine.ingest(ev)
        except Exception as e:  # noqa: BLE001 - mapped to the A2A error below
            from .engine import PayloadError
            if isinstance(e, PayloadError):
                raise A2AError(INVALID_PARAMS, "Invalid parameters", fields=[("message.parts", str(e)[:300])]) from None
            raise
        if res.status == "duplicate":                        # the same message id again: the task it made
            for s in self._submissions(caller):
                if s.get("message_id") == mid:
                    return {"task": self.task(s)}
            raise A2AError(INVALID_PARAMS, "Invalid parameters",
                           fields=[("message.messageId", "already used by another submission")])
        if res.incident_id is None:
            raise A2AError(INTERNAL, "Internal error")
        sub = {"by": caller, "tenant": self.tenant(), "message_id": mid, "context_id": context_id,
               "event_id": res.event_id, "status": res.status}
        self._audit(res.incident_id, "a2a_task_submitted", sub)
        return {"task": self.task({**sub, "incident_id": res.incident_id})}

    def get_task(self, caller: str, params: dict[str, Any]) -> dict[str, Any]:
        tid = params.get("id")
        if not isinstance(tid, str) or not tid:
            raise A2AError(INVALID_PARAMS, "Invalid parameters", fields=[("id", "required")])
        return self.task(self._own(caller, tid))

    def list_tasks(self, caller: str, params: dict[str, Any]) -> dict[str, Any]:
        if params.get("tenant") not in (None, "", self.tenant()):
            raise A2AError(INVALID_PARAMS, "Invalid parameters", fields=[("tenant", "not this server's tenant")])
        size = params.get("pageSize", 50)
        if isinstance(size, bool) or not isinstance(size, int) or not 1 <= size <= MAX_PAGE:
            raise A2AError(INVALID_PARAMS, "Invalid parameters", fields=[("pageSize", f"1 to {MAX_PAGE}")])
        tok = params.get("pageToken") or "0"
        if not isinstance(tok, str) or not tok.isdigit():
            raise A2AError(INVALID_PARAMS, "Invalid parameters", fields=[("pageToken", "not a token this server gave")])
        want_state, ctx = params.get("status"), params.get("contextId")
        if want_state is not None and want_state not in set(_STATE.values()):
            raise A2AError(INVALID_PARAMS, "Invalid parameters", fields=[("status", "not a TASK_STATE_ value")])
        include_art = params.get("includeArtifacts", False) is True
        rows = [self.task(s, artifacts=include_art) for s in self._submissions(caller)
                if ctx is None or s["context_id"] == ctx]
        if want_state is not None:
            rows = [t for t in rows if t["status"]["state"] == want_state]
        after = params.get("statusTimestampAfter")
        if isinstance(after, str):
            rows = [t for t in rows if t["status"]["timestamp"] > after]
        start = int(tok)
        page = rows[start:start + size]
        nxt = str(start + size) if start + size < len(rows) else ""
        return {"tasks": page, "nextPageToken": nxt, "pageSize": len(page), "totalSize": len(rows)}

    def cancel_task(self, caller: str, params: dict[str, Any]) -> dict[str, Any]:
        tid = params.get("id")
        if not isinstance(tid, str) or not tid:
            raise A2AError(INVALID_PARAMS, "Invalid parameters", fields=[("id", "required")])
        self._own(caller, tid)                               # not found for anyone else's
        raise A2AError(TASK_NOT_CANCELABLE, "Task cannot be canceled by an agent: a case is closed by a person "
                                            "in Sentinel", {"taskId": tid})

    # ---- JSON-RPC --------------------------------------------------------
    METHODS = ("SendMessage", "GetTask", "ListTasks", "CancelTask")

    def check_version(self, header: str | None) -> None:
        got = (header or "").strip()
        major_minor = ".".join(got.split(".")[:2]) if got else "0.3"          # empty means 0.3 (section 3.6.2)
        if major_minor != PROTOCOL_VERSION:
            raise A2AError(VERSION_UNSUPPORTED, f"A2A version {got or '(none, read as 0.3)'} is not supported; "
                           f"this server speaks {PROTOCOL_VERSION}", {"supportedVersions": PROTOCOL_VERSION,
                                                                       "requestedVersion": got})

    def handle(self, caller: str, raw: bytes, version: str | None) -> dict[str, Any]:
        """One JSON-RPC request in, one JSON-RPC response out (never raises)."""
        rid: Any = None
        method = "?"
        try:
            try:
                req = json.loads(raw)
            except (ValueError, UnicodeDecodeError):
                raise A2AError(PARSE, "Invalid JSON payload") from None
            if not isinstance(req, dict) or req.get("jsonrpc") != "2.0" or not isinstance(req.get("method"), str):
                raise A2AError(INVALID_REQUEST, "Request payload validation error")
            rid = req.get("id")
            if "id" not in req or isinstance(rid, bool) or not (rid is None or isinstance(rid, (str, int, float))):
                raise A2AError(INVALID_REQUEST, "Request payload validation error")
            method = req["method"]
            params = req.get("params") if req.get("params") is not None else {}
            if not isinstance(params, dict):
                raise A2AError(INVALID_PARAMS, "Invalid parameters")
            if method in _NOT_OFFERED:
                code, msg = _NOT_OFFERED[method]
                raise A2AError(code, msg)
            if method not in self.METHODS:
                raise A2AError(METHOD_NOT_FOUND, "Method not found")
            self.check_version(version)
            fn = {"SendMessage": self.send_message, "GetTask": self.get_task, "ListTasks": self.list_tasks,
                  "CancelTask": self.cancel_task}[method]
            return {"jsonrpc": "2.0", "id": rid, "result": fn(caller, params)}
        except A2AError as e:
            if e.code != TASK_NOT_FOUND:                     # a lookup miss is not worth an audit row
                self.refuse(caller, method, e.code, e.message)
            return {"jsonrpc": "2.0", "id": rid, "error": e.body()}
        except Exception as e:  # noqa: BLE001 - never a stack trace to a caller
            self.refuse(caller, method, INTERNAL, type(e).__name__)
            return {"jsonrpc": "2.0", "id": rid, "error": A2AError(INTERNAL, "Internal error").body()}


# ------------------------------------------------------------------------------------------------ mounting
def mount_a2a(app: Any, engine: Any, service: Any, capped_body: Any, *, version: str,
              tenant: Any = None) -> A2AService:
    """Add the Agent Card and ``POST /a2a`` to a FastAPI app. ``service`` is api.py's service-token dependency (the
    same bearer auth and rate limit as ``/v1/events``); ``capped_body(request, limit)`` its size-capped reader."""
    from . import envsecrets
    svc = A2AService(engine, tenant or (lambda: envsecrets.TENANT.get()))

    @app.get("/.well-known/agent-card.json")
    def card(request: Request) -> JSONResponse:
        base = os.environ.get("SENTINEL_PUBLIC_URL") or str(request.base_url)
        body = agent_card(base, version)
        etag = '"' + hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()[:32] + '"'
        if request.headers.get("if-none-match") == etag:
            return JSONResponse(None, status_code=304, headers={"ETag": etag})
        return JSONResponse(body, headers={"ETag": etag, "Cache-Control": "public, max-age=300"})

    @app.post("/a2a")
    async def rpc(request: Request, p: Any = Depends(service), a2a_version: str = Header(default="")) -> JSONResponse:
        raw = await capped_body(request, 4 * engine.max_event_bytes)
        ver = a2a_version or request.query_params.get("A2A-Version") or ""
        out = await run_in_threadpool(svc.handle, p.id, raw, ver)
        return JSONResponse(out)

    return svc
