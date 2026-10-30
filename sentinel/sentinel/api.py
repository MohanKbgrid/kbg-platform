# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""HTTP API (FastAPI). `pip install "kbg-sentinel[api]"`.

Auth
  * Bearer tokens map to a principal: a service (may ingest events) or a person (may work reviews,
    subject to RBAC). Only SHA-256 hashes of tokens are configured, never the tokens themselves.
  * Edge answers (`POST /v1/edges/{edge}/answers`) carry no bearer token: they are verified with the
    edge's HMAC secret and timestamp (replay window), the same scheme the edge used to receive the card.

Errors map cleanly: 401 bad token, 403 not authorised (with `escalate_to`), 404 unknown, 409 conflict
(closed review, wrong state), 413 payload too large, 422 invalid input, 429 rate limited.
"""
from __future__ import annotations

import hashlib
import json
import hmac
import threading
import time
from dataclasses import dataclass
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse, PlainTextResponse
from pydantic import ValidationError
from .inputs import Body

from .edges import WhatsAppEdge, answer_from_user_action, user_action_from_message, verify
from .engine import AuthorizationError, Engine, EngineError, PayloadError
from .models import Decision, Event, Route


@dataclass(frozen=True)
class Principal:
    kind: str                   # service | person
    id: str


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


class RateLimiter:
    """Token bucket per principal."""

    def __init__(self, per_minute: int) -> None:
        self.rate = per_minute / 60.0
        self.cap = float(per_minute)
        self._b: dict[str, tuple[float, float]] = {}
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        with self._lock:
            tokens, last = self._b.get(key, (self.cap, now))
            tokens = min(self.cap, tokens + (now - last) * self.rate)
            if tokens < 1:
                self._b[key] = (tokens, now)
                return False
            self._b[key] = (tokens - 1, now)
            return True


class DecisionIn(Body):
    kind: str
    action: str | None = None
    params: dict[str, Any] = {}
    steps: list[dict[str, Any]] | None = None
    disposition_code: str | None = None
    note: str = ""


class BulkIn(Body):
    review_ids: list[str]
    kind: str
    disposition_code: str | None = None
    note: str = ""


class AnswerIn(Body):
    review_id: str
    person_id: str
    decision: DecisionIn
    answer_token: str | None = None          # the card's single-use token (required for this edge's answers)


class AskMetricIn(Body):
    metric: str
    by: list[str] = []
    filters: dict[str, Any] = {}
    days: float | None = None
    grain: str | None = None
    compare: bool = True


class AskRaiseIn(Body):
    metric: str
    filters: dict[str, Any] = {}
    note: str = ""


class RouteIn(Body):
    route: Route


class NoteIn(Body):
    note: str = ""


def create_app(engine: Engine, tokens: dict[str, Principal], *, edge_secrets: dict[str, str] | None = None,
               ingest_per_minute: int = 6000, title: str = "Sentinel", console: bool = True,
               config_sync_s: float = 15.0, sso: Any = None, a2a: bool = False) -> FastAPI:
    """`tokens` maps sha256(token) -> Principal."""
    import contextlib

    @contextlib.asynccontextmanager
    async def lifespan(_app: FastAPI):
        stop = threading.Event()

        def sync_loop() -> None:          # pick up configuration published by other processes
            while not stop.wait(config_sync_s):
                try:
                    engine.sync_config()
                except Exception:  # noqa: BLE001,S110 - logged by the engine; keep serving
                    pass
        t = threading.Thread(target=sync_loop, daemon=True, name="config-sync")
        if config_sync_s > 0:
            t.start()
        yield
        stop.set()

    from . import __version__
    app = FastAPI(title=title, version=__version__, lifespan=lifespan)

    @app.middleware("http")
    async def security_headers(request: Request, call_next: Any) -> Any:
        resp = await call_next(request)
        h = resp.headers
        h.setdefault("X-Content-Type-Options", "nosniff")
        h.setdefault("Referrer-Policy", "no-referrer")
        h.setdefault("X-Frame-Options", "DENY")
        if request.url.path.startswith("/console"):
            h.setdefault("Content-Security-Policy",
                         "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
                         "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; "
                         "form-action 'self'")
            h.setdefault("Cache-Control", "no-store")
        return resp
    edge_secrets = edge_secrets or {}
    limiter = RateLimiter(ingest_per_minute)

    def principal(authorization: str = Header(default="")) -> Principal:
        scheme, _, tok = authorization.partition(" ")
        if scheme.lower() != "bearer" or not tok:
            raise HTTPException(401, "missing bearer token")
        h = token_hash(tok)
        for known, p in tokens.items():
            if hmac.compare_digest(known, h):
                return p
        stored = engine.access.resolve(tok)               # tokens given from the console, and SSO sessions
        if stored is not None:
            return Principal(stored.kind, stored.principal)
        raise HTTPException(401, "unknown token")

    def service(p: Principal = Depends(principal)) -> Principal:
        if p.kind != "service":
            raise HTTPException(403, "service token required")
        if not limiter.allow(p.id):
            raise HTTPException(429, "rate limited")
        return p

    def person(p: Principal = Depends(principal)) -> Principal:
        if p.kind != "person":
            raise HTTPException(403, "person token required")
        return p

    @app.exception_handler(AuthorizationError)
    async def _auth(_: Request, e: AuthorizationError) -> JSONResponse:
        return JSONResponse({"detail": str(e), "escalate_to": e.escalate_to}, status_code=403)

    @app.exception_handler(PayloadError)
    async def _big(_: Request, e: PayloadError) -> JSONResponse:
        return JSONResponse({"detail": str(e)}, status_code=413)

    @app.exception_handler(EngineError)
    async def _engine(_: Request, e: EngineError) -> JSONResponse:
        msg = str(e)
        code = 404 if msg.startswith("unknown") else 409 if ("closed" in msg or "not awaiting" in msg) else 422
        return JSONResponse({"detail": msg}, status_code=code)

    def _errors(errs: Any) -> list[dict[str, Any]]:
        """Validation errors without the echoed input or context: a NaN or Infinity in the body would make the
        422 itself unserialisable (a 500). Location, type and message are enough to fix the request."""
        return [{"loc": [str(x) for x in er.get("loc", ())], "type": str(er.get("type", "")),
                 "msg": str(er.get("msg", ""))} for er in errs]

    @app.exception_handler(ValidationError)
    async def _invalid(_: Request, e: ValidationError) -> JSONResponse:
        return JSONResponse({"detail": _errors(e.errors(include_url=False))}, status_code=422)

    @app.exception_handler(RequestValidationError)
    async def _invalid_request(_: Request, e: RequestValidationError) -> JSONResponse:
        return JSONResponse({"detail": _errors(e.errors())}, status_code=422)

    # ---- open endpoints -------------------------------------------------
    @app.get("/healthz")
    def healthz() -> JSONResponse:
        h = engine.health()
        return JSONResponse(h, status_code=503 if h["status"] == "down" else 200)

    @app.get("/metrics", response_class=PlainTextResponse)
    def metrics() -> str:
        return engine.metrics.render()

    # ---- ingest (services) ----------------------------------------------
    @app.post("/v1/events")
    def post_event(event: Event, _: Principal = Depends(service)) -> dict[str, Any]:
        r = engine.ingest(event)
        return {"status": r.status, "incident_id": r.incident_id, "event_id": r.event_id}

    @app.post("/v1/data-trust")
    def post_data_trust(body: dict[str, Any], sp: Principal = Depends(service)) -> dict[str, Any]:
        """A scope's data trust score from monitoring: {scope: {store: TVM01}, score: 0.91, source, components}."""
        from .engine import EngineError
        from . import inputs as _in
        comps = body.get("components")
        if comps is not None and not isinstance(comps, dict):
            raise HTTPException(422, "components must be an object")
        scope = _in.facts(body, "scope")
        score = _in.number(body, "score", lo=0, hi=1)
        source = _in.text(body, "source", max_len=200)
        try:
            return engine.set_data_trust(scope, score, source, comps, by=sp.id)
        except AuthorizationError as e:
            raise HTTPException(403, str(e)) from None
        except EngineError as e:
            raise HTTPException(422, str(e)) from None

    @app.post("/v1/receipts")
    def post_receipts(body: dict[str, Any], sp: Principal = Depends(service)) -> dict[str, Any]:
        """Decision receipts from domain cores (sentinel.orgsync): audited, bundle versions checked."""
        rows = body.get("receipts")
        if not isinstance(rows, list) or len(rows) > 5000:
            raise HTTPException(422, "receipts: a list of up to 5000")
        try:
            return engine.record_receipts(rows, by=sp.id)
        except ValueError as e:
            raise HTTPException(422, str(e)[:500]) from None

    @app.post("/v1/sources/{source}")
    def post_raw(source: str, raw: dict[str, Any] | list[Any], _: Principal = Depends(service)) -> dict[str, Any]:
        results = engine.receive(source, raw)
        return {"results": [{"status": r.status, "incident_id": r.incident_id, "event_id": r.event_id}
                            for r in results]}

    @app.post("/v1/hooks/{source}")
    async def signed_hook(source: str, request: Request) -> dict[str, Any]:
        """Webhooks from systems that sign their requests (Shopify ...): no bearer token; the
        source's HMAC signature is checked instead."""
        from .sources import verify_signature
        s = engine.sources.get(source)
        if s is None or s.kind != "webhook" or s.signature is None:
            raise HTTPException(404, f"no signed webhook source {source!r}")
        body = await capped_body(request, 4 * engine.max_event_bytes)
        if not limiter.allow(f"hook:{source}"):
            raise HTTPException(429, "rate limited")
        if not verify_signature(s, body, dict(request.headers)):
            raise HTTPException(401, "bad signature")
        try:
            raw = json.loads(body)
        except json.JSONDecodeError:
            raise HTTPException(400, "body must be JSON") from None
        results = await run_in_threadpool(engine.receive, source, raw)
        return {"results": [{"status": r.status, "incident_id": r.incident_id, "event_id": r.event_id}
                            for r in results]}

    # ---- people -----------------------------------------------------------
    @app.get("/v1/reviews")
    def my_reviews(p: Principal = Depends(person)) -> list[dict[str, Any]]:
        return [engine.build_card(r, p.id).model_dump(mode="json") for r in engine.reviews_for(p.id)]

    @app.post("/v1/reviews/{review_id}/decision")
    def decide(review_id: str, body: DecisionIn, p: Principal = Depends(person)) -> dict[str, Any]:
        inc = engine.decide(review_id, Decision.model_validate({**body.model_dump(), "actor": p.id}))
        return {"incident_id": inc.id, "state": inc.state.value}

    @app.post("/v1/reviews/bulk")
    def decide_bulk(body: BulkIn, p: Principal = Depends(person)) -> dict[str, Any]:
        if not 1 <= len(body.review_ids) <= 500:
            raise HTTPException(422, "between 1 and 500 reviews at a time")
        return engine.decide_many(body.review_ids, body.kind, p.id, disposition_code=body.disposition_code,
                                  note=body.note)

    @app.get("/v1/incidents/{incident_id}")
    def incident(incident_id: str, p: Principal = Depends(person)) -> dict[str, Any]:
        inc = engine.store.get_incident(incident_id)
        if inc is None or not engine.can_view_incident(p.id, inc):
            raise HTTPException(404, "unknown incident")          # not "forbidden": don't confirm it exists
        d = engine.store.get_disposition(incident_id)
        return {"incident": inc.model_dump(mode="json"), "events": engine.store.event_ids(incident_id),
                "disposition": d.model_dump(mode="json") if d else None,
                "audit": engine.store.audit_log(incident_id)}

    @app.post("/v1/incidents/{incident_id}/reverse")
    def reverse(incident_id: str, body: NoteIn, p: Principal = Depends(person)) -> dict[str, Any]:
        return engine.reverse(incident_id, actor=p.id, note=body.note).model_dump(mode="json")

    @app.get("/v1/fleet/status")
    def fleet_status(p: Principal = Depends(principal)) -> dict[str, Any]:
        """For the fleet view: a service token named 'fleet', or a person who may configure."""
        ok = (p.kind == "service" and p.id == "fleet") or (
            p.kind == "person" and (engine.directory is None
                                    or engine.directory.authorize_meta(p.id, "__configure__", "*").allowed))
        if not ok:
            raise HTTPException(403, "the fleet status needs the 'fleet' service token")
        from .fleet import site_status
        return site_status(engine)

    @app.get("/v1/report")
    def report(_: Principal = Depends(person)) -> dict[str, Any]:
        return engine.report()

    @app.post("/v1/patterns/{pattern_id}/promotion/approve")
    def approve_promotion(pattern_id: str, p: Principal = Depends(person)) -> dict[str, Any]:
        _known(pattern_id)
        return engine.approve_promotion(pattern_id, actor=p.id).model_dump(mode="json")

    @app.post("/v1/patterns/{pattern_id}/promotion/reject")
    def reject_promotion(pattern_id: str, body: NoteIn, p: Principal = Depends(person)) -> dict[str, Any]:
        _known(pattern_id)
        return engine.reject_promotion(pattern_id, actor=p.id, note=body.note).model_dump(mode="json")

    @app.post("/v1/patterns/{pattern_id}/route")
    def set_route(pattern_id: str, body: RouteIn, p: Principal = Depends(person)) -> dict[str, Any]:
        _known(pattern_id)
        return engine.set_route(pattern_id, body.route, actor=p.id).model_dump(mode="json")

    def _known(pattern_id: str) -> None:
        try:
            engine.registry.get(pattern_id.partition("@")[0])
        except KeyError:
            raise HTTPException(404, f"unknown pattern {pattern_id}") from None

    # ---- edges (signed, no bearer) ----------------------------------------
    @app.post("/v1/edges/{edge}/answers")
    async def edge_answer(edge: str, request: Request,
                          x_sentinel_timestamp: str = Header(default=""),
                          x_sentinel_signature: str = Header(default="")) -> dict[str, Any]:
        body = await signed(edge, request, x_sentinel_timestamp, x_sentinel_signature)
        try:
            ans = AnswerIn.model_validate_json(body)
        except ValidationError as e:
            raise HTTPException(422, e.errors(include_url=False)) from None
        inc = await run_in_threadpool(engine.answer, edge, ans.review_id, ans.person_id, ans.decision.model_dump(),
                                      answer_token=ans.answer_token)
        return {"incident_id": inc.id, "state": inc.state.value}

    async def capped_body(request: Request, limit: int = 1_000_000) -> bytes:
        try:
            if int(request.headers.get("content-length") or 0) > limit:
                raise HTTPException(413, "payload too large")
        except ValueError:
            raise HTTPException(400, "bad content-length") from None
        body = b""
        async for chunk in request.stream():
            body += chunk
            if len(body) > limit:
                raise HTTPException(413, "payload too large")
        return body

    async def signed(edge: str, request: Request, ts: str, sig: str) -> bytes:
        e = engine.overlay.edges.get(edge)
        secret = edge_secrets.get(edge) or getattr(e, "answer_secret", None) or getattr(e, "secret", None)
        body = await capped_body(request)
        if secret is None or not verify(secret, body, ts, sig):
            raise HTTPException(401, "bad edge signature")
        return body

    # ---- Ask AI: analytics for the chat surface, and the way back to the agents --------------------------
    def _ask_metric(person_id: str, body: AskMetricIn) -> dict[str, Any]:
        from .kpi import KpiError, a2ui, can_see, widget
        if engine.kpi is None:
            raise HTTPException(404, "no metrics are configured")
        m = engine.kpi.doc.metrics.get(body.metric)
        if m is None or not can_see(engine, person_id, m):
            raise HTTPException(404, f"unknown metric {body.metric}")
        try:
            res = engine.kpi.query(body.metric, by=body.by, filters=body.filters, days=body.days,
                                   grain=body.grain, compare=body.compare)
        except KpiError as e:
            raise HTTPException(422, str(e)) from None
        t = res["total"]
        summary = f"{res['title']} over the last {body.days or 30:g} days: {t['text']}"
        if res["target_text"]:
            summary += f" against a target of {res['target_text']} ({'met' if t['target_ok'] else 'missed'})"
        if res.get("change_pct") is not None:
            summary += f", {res['change_pct']:+.1f}% on the period before"
        missed = [r for r in res["rows"] if r.get("target_ok") is False]
        if missed:
            summary += "; missing target: " + ", ".join(", ".join(str(r[d]) for d in res["by"]) or r.get("period", "")
                                                       for r in missed[:5])
        return {"result": res, "summary": summary + ".", "widget": widget(res),
                "a2ui": a2ui(res, f"metric-{body.metric}")}

    @app.get("/v1/ask/catalog")
    def ask_catalog(p: Principal = Depends(person)) -> dict[str, Any]:
        """What Ask AI may ask, with tool definitions its model can use as they are."""
        from .kpi import catalogue
        return catalogue(engine, p.id)

    @app.post("/v1/ask/metric")
    async def ask_metric(body: AskMetricIn, p: Principal = Depends(person)) -> dict[str, Any]:
        return await run_in_threadpool(_ask_metric, p.id, body)

    @app.post("/v1/ask/raise")
    async def ask_raise(body: AskRaiseIn, p: Principal = Depends(person)) -> dict[str, Any]:
        """People -> agents: open a case about what a metric shows, for the KPI's owner and its agent."""
        from .kpi import KpiError, raise_case
        try:
            r = await run_in_threadpool(raise_case, engine, p.id, body.metric, body.filters, body.note)
        except PermissionError:
            raise HTTPException(404, f"unknown metric {body.metric}") from None
        except KpiError as e:
            raise HTTPException(422, str(e)) from None
        return {"status": r.status, "incident_id": r.incident_id}

    @app.post("/v1/edges/{edge}/a2ui")
    async def edge_a2ui(edge: str, request: Request, x_sentinel_timestamp: str = Header(default=""),
                        x_sentinel_signature: str = Header(default="")) -> dict[str, Any]:
        """An A2UI userAction from a review card rendered by a chat surface (signed like answers):
        ``{"person_id": "...", "userAction": {"name": "sentinel.answer", "context": {...}, ...}}``."""
        body = await signed(edge, request, x_sentinel_timestamp, x_sentinel_signature)
        try:
            msg = json.loads(body)
            act = user_action_from_message(msg)     # v0.8 userAction or v0.9/v0.9.1 action, else ValueError
            if act.get("name") == "sentinel.raise":       # the button under a metric answer
                from .kpi import KpiError, raise_case
                ctx = act.get("context") or {}
                filters = ctx.get("filters") or {}
                filters = json.loads(filters) if isinstance(filters, str) else filters
                pid = str(msg["person_id"])
                if engine.directory is not None and pid not in engine.directory.people:
                    raise HTTPException(403, f"unknown person {pid}")
                try:
                    r = await run_in_threadpool(raise_case, engine, pid, str(ctx.get("metric", "")), dict(filters),
                                                str(ctx.get("note") or "raised from chat"))
                except (KpiError, PermissionError) as e:
                    raise HTTPException(422, str(e)) from None
                return {"incident_id": r.incident_id, "status": r.status}
            rid, dec = answer_from_user_action(act)
            pid = str(msg["person_id"])
        except (ValueError, KeyError, AttributeError) as e:
            raise HTTPException(422, str(e)) from None
        inc = await run_in_threadpool(engine.answer, edge, rid, pid, dec)
        return {"incident_id": inc.id, "state": inc.state.value}

    def whatsapp_edge(edge: str) -> Any:
        e = engine.overlay.edges.get(edge)
        if not isinstance(e, WhatsAppEdge):
            raise HTTPException(404, f"no WhatsApp edge {edge!r}")
        return e

    @app.get("/v1/whatsapp/{edge}", response_class=PlainTextResponse)
    def whatsapp_verify(edge: str, request: Request) -> str:
        """Meta's webhook verification handshake."""
        e = whatsapp_edge(edge)
        q = request.query_params
        if q.get("hub.mode") == "subscribe" and hmac.compare_digest(q.get("hub.verify_token", ""), e.verify_token):
            return q.get("hub.challenge", "")
        raise HTTPException(403, "verification failed")

    @app.post("/v1/whatsapp/{edge}")
    async def whatsapp_in(edge: str, request: Request,
                          x_hub_signature_256: str = Header(default="")) -> dict[str, Any]:
        """Button replies from WhatsApp. Always 200 once the signature is good (Meta retries otherwise);
        what happened to each reply is in the audit log."""
        e = whatsapp_edge(edge)
        body = await capped_body(request)
        if not e.check_signature(body, x_hub_signature_256):
            raise HTTPException(401, "bad signature")
        try:
            replies = WhatsAppEdge.replies(json.loads(body))
        except ValueError:
            raise HTTPException(422, "not JSON") from None
        done = 0
        for number, rid, dec in replies:
            pid = engine.person_by_number(number)
            if pid is None:
                engine.store.audit(None, "edge_answer_refused", {"edge": edge, "review": rid,
                                                                 "reason": "number not in people configuration"})
                continue
            try:
                await run_in_threadpool(engine.answer, edge, rid, pid, dec, verified_sender=True)
                done += 1
            except (EngineError, AuthorizationError) as err:
                engine.store.audit(None, "edge_answer_refused", {"edge": edge, "review": rid, "person": pid,
                                                                 "reason": str(err)})
        return {"answers": done, "received": len(replies)}

    @app.post("/v1/wa/{edge}")
    async def wa_provider_in(edge: str, request: Request) -> dict[str, Any]:
        """Replies from WhatsApp through Gupshup or Interakt (see sentinel.wa_providers)."""
        from .wa_providers import _ProviderEdge
        e = engine.overlay.edges.get(edge)
        if not isinstance(e, _ProviderEdge):
            raise HTTPException(404, f"no Gupshup or Interakt edge {edge!r}")
        body = await capped_body(request)
        if not e.check_request(body, dict(request.headers), dict(request.query_params)):
            raise HTTPException(401, "bad signature or token")
        try:
            payload = json.loads(body)
        except ValueError:
            raise HTTPException(422, "not JSON") from None
        replies = e.replies(payload) if isinstance(payload, dict) else []
        done = 0
        for number, rid, dec in replies:
            pid = engine.person_by_number(number)
            if pid is None:
                engine.store.audit(None, "edge_answer_refused", {"edge": edge, "review": rid,
                                                                 "reason": "number not in people configuration"})
                continue
            try:
                await run_in_threadpool(engine.answer, edge, rid, pid, dec, verified_sender=True)
                done += 1
            except (EngineError, AuthorizationError) as err:
                engine.store.audit(None, "edge_answer_refused", {"edge": edge, "review": rid, "person": pid,
                                                                 "reason": str(err)})
        return {"answers": done, "received": len(replies)}

    @app.post("/v1/slack/{edge}")
    async def slack_in(edge: str, request: Request, x_slack_request_timestamp: str = Header(default=""),
                       x_slack_signature: str = Header(default="")) -> dict[str, Any]:
        """Button presses from Slack (interactivity request URL). Signed with the app's signing secret; the
        presser is matched to a person by their Slack member id."""
        from urllib.parse import parse_qs

        from .channels import SlackEdge
        e = engine.overlay.edges.get(edge)
        if not isinstance(e, SlackEdge):
            raise HTTPException(404, f"no Slack edge {edge!r}")
        body = await capped_body(request)
        if not e.check_signature(body, x_slack_request_timestamp, x_slack_signature):
            raise HTTPException(401, "bad signature")
        try:
            payload = json.loads((parse_qs(body.decode()).get("payload") or ["{}"])[0])
        except ValueError:
            raise HTTPException(422, "not a Slack interaction") from None
        done = 0
        answers = SlackEdge.answers(payload)
        for member, rid, dec in answers:
            pid = engine.person_by_slack(member)
            if pid is None:
                engine.store.audit(None, "edge_answer_refused", {"edge": edge, "review": rid,
                                                                 "reason": "Slack member not in people configuration"})
                continue
            try:
                await run_in_threadpool(engine.answer, edge, rid, pid, dec, verified_sender=True)
                done += 1
            except (EngineError, AuthorizationError) as err:
                engine.store.audit(None, "edge_answer_refused", {"edge": edge, "review": rid, "person": pid,
                                                                 "reason": str(err)})
        return {"answers": done, "received": len(answers)}

    def scim_token(tok: str) -> bool:
        h = token_hash(tok)
        return any(hmac.compare_digest(k, h) and p.kind == "service" and p.id == "scim" for k, p in tokens.items())

    if a2a:                                   # A2A server surface (sentinel/a2a.py); off unless asked for
        from .a2a import mount_a2a
        mount_a2a(app, engine, service, capped_body, version=__version__)
    from .scim import mount as mount_scim
    mount_scim(app, engine, scim_token)
    if console:
        from .console import mount_console
        mount_console(app, engine, person, sso=sso)
    return app
