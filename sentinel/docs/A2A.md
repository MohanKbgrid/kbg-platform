# A2A: hand cases to Sentinel, take decisions back

Sentinel's MCP support is a **client**: Sentinel calls other systems' read-only tools. A2A (Agent2Agent, the
`a2aproject/A2A` protocol) is the other direction: **other agent frameworks call Sentinel** to hand a case in and to
take its state and decision back. It is switched off unless you ask for it.

Implemented version: **A2A 1.0** (specification 1.0.x), JSON-RPC binding (section 9), ProtoJSON names from
`a2a.proto`. Not implemented: streaming, push notifications, the extended Agent Card, the gRPC and REST bindings.

## Turn it on

```python
create_app(engine, tokens, a2a=True)
```

Optionally set `SENTINEL_PUBLIC_URL` so the Agent Card advertises the address callers should use (otherwise it uses
the request's own base URL, which behind a proxy may be wrong).

## What it exposes

| Path | Auth | What |
|---|---|---|
| `GET /.well-known/agent-card.json` | none (public) | The Agent Card: one JSON-RPC interface (`/a2a`, protocol 1.0), bearer security scheme, skills `submit_case` and `get_case`. `ETag` and `Cache-Control: max-age=300`. |
| `POST /a2a` | service bearer token | JSON-RPC 2.0. Send `A2A-Version: 1.0` (header or `?A2A-Version=1.0`). |

Methods: `SendMessage`, `GetTask`, `ListTasks`, `CancelTask` (always refused, see below). `SendStreamingMessage`,
`SubscribeToTask` answer `UnsupportedOperationError` (-32004); the push-notification methods answer
`PushNotificationNotSupportedError` (-32003); `GetExtendedAgentCard` answers -32007; anything else is -32601.
A missing, `0.3` or other unsupported `A2A-Version` is `VersionNotSupportedError` (-32009), as the specification
requires (an empty value means 0.3).

## The mapping

* **Task = case.** The task id is the incident id. A message that groups into an already open case returns that case.
* **`SendMessage`** carries `message.role = ROLE_USER`, a `messageId`, and `data` and/or `text` parts:

  ```json
  {"jsonrpc": "2.0", "id": 1, "method": "SendMessage", "params": {"message": {
     "messageId": "order-SO-1-attempt-1", "role": "ROLE_USER",
     "parts": [{"data": {"type": "order.stuck", "payload": {"order": "SO-1"}, "correlation_id": "c-9"}}]}}}
  ```

  It becomes an ordinary event with `source = "a2a:<caller token id>"`, `tenant` = the server's tenant, and
  `idempotency_key = messageId`: a retry with the same message id returns the same task, never a second case. The
  data part accepts only `type`, `payload`, `correlation_id`; the caller cannot choose the source or the tenant.
  Text parts are joined into `payload.text`. File and URL parts are refused (-32005). At most 16 parts.
* **State.** open -> `TASK_STATE_SUBMITTED`; suppressed, resolving, awaiting a person, resolved, failed ->
  `TASK_STATE_WORKING` (the status message says what it waits for; a person may still decide);
  dispositioned -> `TASK_STATE_COMPLETED`. Sentinel never reports `INPUT_REQUIRED`: the agent has no input to give.
* **Decision.** Once decided, the task carries an artifact `decision` with `code`, `resolver` (`human`, `auto`,
  `llm`, `parent`), `outcome`, `outcomeDetail`, `reversed`, `agreedWithProposal`, the action names, and the note.
  The deciding person's id is not sent.
* **`GetTask`** `{id}`; **`ListTasks`** `{contextId, status, pageSize (1..100, default 50), pageToken,
  statusTimestampAfter, includeArtifacts}`.

## Authority, scope, caps, audit

* **Same bearer auth as `/v1/events`**: a Sentinel *service* token (a person's token is 403). Same rate limiter, and
  a body cap of four times the event limit; an event over the limit is -32602.
* **An agent can never approve.** No A2A method reaches a decision, an answer, a promotion, a bulk action or a
  reversal. A message that continues a task (`taskId`, `referenceTaskIds`) is refused with -32004. `CancelTask` is
  -32002: a case is closed by a person in Sentinel. The service token cannot use `/v1/reviews/...` (403). And
  Sentinel's own invariant holds: `AgentPolicy` refuses APPROVE, `org.authorise` denies it to an agent
  (ADR-003 invariant 1). `tests/test_a2a.py::test_an_agent_can_never_approve` asserts each of these.
* **Scope.** A caller sees only the tasks it submitted, in this server's tenant. Another caller's task id, and an id
  that never existed, give the same -32001 (no existence leak). A request naming another `tenant` is -32602.
  In hosted mode each tenant has its own engine and app, so A2A is per tenant.
* **Audit.** Each submission writes `a2a_task_submitted` (caller, tenant, message id, context, event) against the
  case; each refusal writes `a2a_refused` (caller, method, code, reason). The case's own audit trail is unchanged.

## Limits worth knowing

* `GetTask` and `ListTasks` look in the caller's last 5000 submission audit rows; an older task answers -32001.
* Events grouped into one case share one task; a second caller whose event groups into a case another caller opened
  sees that case under its own submission. Keep patterns' fingerprints scoped where that matters.
* Agent Card signing (JWS) is not provided.
