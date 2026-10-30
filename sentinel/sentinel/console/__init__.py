# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""Setup and operations console: a web UI at /console and its JSON API at /console/api.

Everyone signs in with their own person token (the same tokens as the review API). What they can see and
do follows the people configuration: anyone may read and draft; publishing configuration needs
``__configure__``; decisions, promotions and route changes go through the same checks as everywhere else.

The UI is static files (no build step, no internet needed): HTML, CSS and plain JavaScript modules.
"""
from __future__ import annotations

import html
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from typing import Literal

from pydantic import Field
from ..inputs import Body

import yaml

from ..config import KINDS, ApprovalNeeded, ConfigError, diff, dump_yaml
from ..engine import AuthorizationError, Engine
from ..registry import ceiling
from .. import inputs as _in

STATIC = Path(__file__).parent / "static"
RIGHTS = ("__configure__", "__promote__", "__set_route__", "__kill_switch__", "__reverse__", "__access__",
          "__silence__", "__privacy__")


class SecretIn(Body):
    value: str = Field(max_length=16000)


class TextIn(Body):
    text: str | None = None
    doc: dict[str, Any] | None = None       # the same configuration as structured data (the UI edits this)
    note: str = ""

    def body(self) -> str:
        if self.doc is not None:
            return dump_yaml(self.doc)
        if self.text is None:
            raise HTTPException(422, "send text or doc")
        return self.text


class SetIn(Body):
    items: dict[str, TextIn]
    note: str = ""


class PublishSetIn(Body):
    version_ids: list[str]


class TokenIn(Body):
    kind: Literal["person", "service"]
    principal: str
    label: str = ""
    days: float | None = Field(default=None, gt=0, le=3650)


class TryIn(Body):
    body: Any = None


class TraceIn(Body):
    event: dict[str, Any]                   # {type, source, payload, tenant?, idempotency_key?}
    registry: str | None = None             # trace against this draft registry (YAML) instead of the running one
    run_lookups: bool = False               # run the playbook's read-only lookups


class ShadowIn(Body):
    patterns: list[str] = Field(min_length=1, max_length=200)
    note: str = ""


class PrivacyIn(Body):
    identifier: str = Field(min_length=4, max_length=200)
    reason: str = Field(default="", max_length=500)
    include_open: bool = False


class PauseIn(Body):
    reason: str
    hours: float | None = Field(default=None, gt=0, le=720)


class SilenceIn(Body):
    reason: str = Field(min_length=1, max_length=500)
    hours: float = Field(gt=0, le=336)
    pattern: str | None = None
    facts: dict[str, Any] = Field(default_factory=dict)


class MetricQueryIn(Body):
    metric: str
    by: list[str] = Field(default_factory=list)
    filters: dict[str, Any] = Field(default_factory=dict)
    days: float | None = None
    grain: str | None = None


class MetricRaiseIn(Body):
    metric: str
    filters: dict[str, Any] = Field(default_factory=dict)
    note: str = ""


class ReverseIn(Body):
    note: str = Field(default="", max_length=2000)


def _problems(probs: list[Any]) -> list[dict[str, str]]:
    return [p.to_dict() for p in probs]


def mount_console(app: FastAPI, engine: Engine, person: Any, sso: Any = None) -> None:
    api = APIRouter(prefix="/console/api")

    def kind_ok(kind: str) -> str:
        if kind not in KINDS:
            raise HTTPException(404, f"unknown configuration kind {kind!r}")
        return kind

    def can(pid: str, meta: str, what: str = "*") -> bool:
        d = engine.directory
        return True if d is None else d.authorize_meta(pid, meta, what).allowed

    from ..bundles import environment
    from ..i18n import STRINGS, norm

    @api.get("/me")
    def me(p: Any = Depends(person)) -> dict[str, Any]:
        d = engine.directory
        known = d is None or p.id in d.people
        lang = norm((d.people[p.id].language if d is not None and p.id in d.people else "") or "en")
        return {"id": p.id, "name": (d.people[p.id].name if d is not None and p.id in d.people else p.id) or p.id,
                "known": known, "roles": sorted(d.roles_of(p.id)) if d is not None and known else [],
                "open_mode": d is None, "can": {m: can(p.id, m) for m in RIGHTS} if known else {},
                "overlay": engine.overlay.name, "environment": environment(),
                "language": lang, "strings": STRINGS[lang]}

    @api.get("/overview")
    def overview(_: Any = Depends(person)) -> dict[str, Any]:
        rep = engine.report()
        pats = rep["patterns"]
        closed = sum(v["dispositions"] for v in pats.values())
        unattended = sum(v["by_resolver"]["auto"] + v["by_resolver"]["llm"] for v in pats.values())
        cfg = {}
        for kind in KINDS:
            active = engine.store.published_config(kind)
            versions = engine.store.config_versions(kind)
            cfg[kind] = {"active": active.summary() if active else None,
                         "drafts": sum(v.status == "draft" for v in versions), "versions": len(versions)}
        d = engine.directory
        return {"overlay": engine.overlay.name, "health": engine.health(), "closed": closed,
                "unattended": unattended, "automation_rate": round(unattended / closed, 3) if closed else None,
                "patterns": len(engine.registry.all()), "pending_promotions": sum((1 if v["pending_promotion"] else 0)
                                                                              + sum(1 for s in v["segments"]
                                                                                    if s["pending_promotion"])
                                                                              for v in pats.values()),
                "people": len(d.people) if d else 0, "roles": len(d.roles) if d else 0, "config": cfg,
                "coverage": engine.coverage(),
                "models": {"routes": sorted(engine.router.routes) if engine.router else [],
                           "embedder": getattr(engine.embedder, "model", None)},
                "activity": engine.store.recent_audit(12, ["config_published", "config_saved", "promotion_approved",
                                                           "route_set", "reversed", "model_evaluation",
                                                           "config_apply_failed", "pattern_changed"])}

    @api.get("/patterns")
    def patterns(_: Any = Depends(person)) -> list[dict[str, Any]]:
        rep = engine.report()["patterns"]
        out = []
        for p in engine.registry.all():
            r = rep.get(p.id, {})
            st = engine.pattern_state(p)
            out.append({"id": p.id, "description": p.description, "event_types": p.event_types, "match": p.match,
                        "configured_route": p.route.value, "route": r.get("route"), "ceiling": ceiling(p).value,
                        "owner_role": p.owner_role, "escalation_role": p.escalation_role,
                        "sla_minutes": p.sla_minutes, "severity": p.severity, "model_task": p.model_task,
                        "allowed_actions": p.allowed_actions,
                        "playbook": [s.action or (f"lookup {s.lookup}" if s.lookup else "close") for s in p.playbook],
                        "streak": st.streak, "samples": st.samples, "reversals": st.reversals,
                        "pending_promotion": st.pending_promotion.value if st.pending_promotion else None,
                        "promotion_approvals": st.promotion_approvals, "dispositions": r.get("dispositions", 0),
                        "automation_rate": r.get("automation_rate"), "shadow_agreement": r.get("shadow_agreement"),
                        "outcome_held_rate": r.get("outcome_held_rate"),
                        "shadow": engine.is_shadow(p),
                        "trust_by": p.trust_by, "segments": r.get("segments", [])})
        return out

    @api.get("/catalogue")
    def catalogue(_: Any = Depends(person)) -> dict[str, Any]:
        acts = []
        for spec in engine.actions.specs():
            acts.append({"name": spec.name, "description": spec.description, "params": spec.params_schema,
                         "risk": "reversible" if spec.reversible else "safe" if spec.safe else "irreversible",
                         "from": "overlay" if engine._base_actions.has(spec.name) else "configuration"})
        return {"actions": acts, "verifiers": sorted(engine.overlay.verifiers), "edges": sorted(engine.overlay.edges),
                "tools": engine.tools.describe(), "sources": sorted(engine.overlay.receivers)}

    @api.get("/directory")
    def directory(_: Any = Depends(person)) -> dict[str, Any]:
        d = engine.directory
        if d is None:
            return {"open_mode": True, "roles": [], "people": [], "authority": []}

        roles = [{"id": r.id, "name": r.name or r.id, "parent": r.parent, "depth": len(d.ancestors(r.id)),
                  "people": sorted(a.person_id for a in d.assignments if a.role_id == r.id)} for r in d.roles.values()]
        people = [{"id": p.id, "name": p.name or p.id, "active": p.active, "edges": p.edges,
                   "assignments": [{"role_id": a.role_id, "scope": a.scope} for a in d.assignments
                                   if a.person_id == p.id]} for p in d.people.values()]
        return {"open_mode": False, "roles": roles, "people": people,
                "authority": [r.model_dump(mode="json") for r in d.rules]}

    # ---- configuration ----------------------------------------------------
    def contacts_ok(pid: str) -> bool:
        return can(pid, "__configure__") or can(pid, "__access__")

    def shown(kind: str, text: str, pid: str) -> str:
        """People's contact details are visible only to those who manage configuration or access."""
        if kind != "people" or contacts_ok(pid):
            return text
        try:
            doc = yaml.safe_load(text) or {}
            for person_doc in doc.get("people") or []:
                if isinstance(person_doc, dict) and person_doc.get("contact"):
                    person_doc["contact"] = {k: "(hidden)" for k in person_doc["contact"]}
            return dump_yaml(doc)
        except Exception:  # noqa: BLE001
            return "# hidden"

    def need_configure_for_people(kind: str, pid: str) -> None:
        if kind == "people" and not contacts_ok(pid):
            raise HTTPException(403, "changing people needs the __configure__ or __access__ right")

    @api.get("/config/{kind}")
    def config(kind: str, p: Any = Depends(person)) -> dict[str, Any]:
        kind_ok(kind)
        active = engine.store.published_config(kind)
        return {"kind": kind, "active": active.summary() if active else None,
                "versions": [v.summary() for v in engine.store.config_versions(kind)],
                "text": shown(kind, engine.config_text(kind), p.id)}

    @api.get("/config/{kind}/doc")
    def config_doc(kind: str, p: Any = Depends(person)) -> dict[str, Any]:
        kind_ok(kind)
        return yaml.safe_load(shown(kind, engine.config_text(kind) or "{}", p.id)) or {}

    @api.post("/config/{kind}/check")
    def check(kind: str, body: TextIn, p: Any = Depends(person)) -> dict[str, Any]:
        kind_ok(kind)
        text = body.body()
        _, probs = engine.check_config(kind, text)
        return {"problems": _problems(probs), "diff": diff(shown(kind, engine.config_text(kind), p.id), text),
                "text": text}

    @api.post("/config/{kind}/drafts")
    def save(kind: str, body: TextIn, p: Any = Depends(person)) -> dict[str, Any]:
        kind_ok(kind)
        text = body.body()
        if len(text) > 1_000_000:
            raise HTTPException(413, "configuration too large")
        need_configure_for_people(kind, p.id)
        cv, probs = engine.save_config(kind, text, author=p.id, note=body.note)
        return {"version": cv.summary(), "problems": _problems(probs)}

    @api.post("/config-set/check")
    def check_set(body: SetIn, who: Any = Depends(person)) -> dict[str, Any]:
        texts = {kind_ok(k): v.body() for k, v in body.items.items()}
        res = engine.check_config_set(texts)
        out, seen = {}, set()
        for k in sorted(texts, key=lambda k: KINDS.index(k) if k != "people" else -1):   # people first
            probs = [p for p in res[k][1] if (p.severity, p.message) not in seen]    # coverage shows once
            seen.update((p.severity, p.message) for p in probs)
            out[k] = {"problems": _problems(probs), "diff": diff(shown(k, engine.config_text(k), who.id), texts[k])}
        return out

    @api.post("/config-set/drafts")
    def save_set(body: SetIn, p: Any = Depends(person)) -> dict[str, Any]:
        texts = {kind_ok(k): v.body() for k, v in body.items.items()}
        for k in texts:
            need_configure_for_people(k, p.id)
        res = engine.check_config_set(texts)
        out = {}
        for k, text in texts.items():
            cv, _ = engine.save_config(k, text, author=p.id, note=body.note)
            out[k] = {"version": cv.summary(), "problems": _problems(res[k][1])}
        return out

    @api.post("/config-set/publish")
    def publish_set(body: PublishSetIn, p: Any = Depends(person)) -> JSONResponse:
        try:
            out = engine.publish_config_set(body.version_ids, actor=p.id)
        except ApprovalNeeded as e:
            return JSONResponse({"waiting": [cv.summary() for cv in e.versions], "detail": str(e)}, status_code=202)
        except ConfigError as e:
            return JSONResponse({"detail": str(e), "problems": _problems(e.problems)}, status_code=422)
        return JSONResponse({"versions": [cv.summary() for cv in out]})

    @api.get("/config/versions/{version_id}")
    def version(version_id: str, p: Any = Depends(person)) -> dict[str, Any]:
        cv = engine.store.get_config_version(version_id)
        if cv is None:
            raise HTTPException(404, "unknown version")
        _, probs = engine.check_config(cv.kind, cv.text)
        return {"version": cv.summary(), "text": shown(cv.kind, cv.text, p.id), "problems": _problems(probs),
                "diff": diff(shown(cv.kind, engine.config_text(cv.kind), p.id), shown(cv.kind, cv.text, p.id),
                             "published", f"v{cv.version}")}

    @api.post("/config/versions/{version_id}/publish")
    def publish(version_id: str, p: Any = Depends(person)) -> JSONResponse:
        try:
            cv = engine.publish_config(version_id, actor=p.id)
        except ApprovalNeeded as e:
            return JSONResponse({"waiting": [x.summary() for x in e.versions], "detail": str(e)}, status_code=202)
        except ConfigError as e:
            return JSONResponse({"detail": str(e), "problems": _problems(e.problems)}, status_code=422)
        return JSONResponse({"version": cv.summary()})

    @api.post("/config/versions/{version_id}/approve")
    def approve(version_id: str, p: Any = Depends(person)) -> JSONResponse:
        try:
            out = engine.approve_config(version_id, actor=p.id)
        except ConfigError as e:
            return JSONResponse({"detail": str(e), "problems": _problems(e.problems)}, status_code=422)
        return JSONResponse({"published": [cv.summary() for cv in out]})

    @api.get("/config/approvals")
    def approvals(p: Any = Depends(person)) -> dict[str, Any]:
        """Drafts someone asked to publish that still wait for approval, and the policy."""
        pol = getattr(engine.directory, "config_approval", None) if engine.directory is not None else None
        waiting = [cv.summary() for k in KINDS for cv in engine.store.config_versions(k)
                   if cv.status == "draft" and cv.requested_by]
        return {"policy": pol.model_dump(mode="json") if pol else None, "waiting": waiting}

    # ---- connectors --------------------------------------------------------------
    @api.get("/connectors")
    def connectors(_: Any = Depends(person)) -> dict[str, Any]:
        srcs = [{"name": n, "kind": s.kind, "enabled": s.enabled, "every_s": s.every_s if s.kind != "webhook" else None,
                 "signed": s.signature is not None, "emits": sorted({e.type for e in s.emit}),
                 "state": engine.store.get_source_state(n) or {}} for n, s in engine.sources.items()]
        conn = engine.connectors
        mcp = [{"name": n, "transport": c.server.transport, "tools": c.server.tools,
                "usable": sorted(c.verified) if c.verified is not None else None}
               for n, c in (conn.clients.items() if conn else [])]
        from ..edges import A2UIEdge, WhatsAppEdge
        configured = set(conn.edges) if conn else set()

        def edge_kind(e: Any) -> str:
            return ("a2ui" if isinstance(e, A2UIEdge) else "whatsapp" if isinstance(e, WhatsAppEdge)
                    else getattr(e, "kind", None) or type(e).__name__.replace("Edge", "").lower() or "edge")
        edges = [{"name": n, "kind": edge_kind(e), "from": "configuration" if n in configured else "overlay",
                  "answers_at": f"/v1/whatsapp/{n}" if isinstance(e, WhatsAppEdge)
                  else f"/v1/slack/{n}" if getattr(e, "kind", None) == "slack"
                  else "the console (link in the message)" if getattr(e, "kind", None) in ("teams", "email")
                  else f"/v1/edges/{n}/a2ui" if isinstance(e, A2UIEdge) else f"/v1/edges/{n}/answers",
                  "people": sorted(p.id for p in (engine.directory.people.values() if engine.directory else [])
                                   if n in p.edges)}
                 for n, e in sorted(engine.overlay.edges.items())]
        from urllib.parse import urlsplit
        acts = [{"name": a.name, "description": a.description, "method": a.request.method,
                 "host": urlsplit(a.request.url).netloc or "(templated)",
                 "params": a.params, "reversible": a.compensate is not None, "safe": a.safe}
                for a in (getattr(conn, "actions", {}) or {}).values()] if conn else []
        return {"sources": srcs, "mcp": mcp, "receivers": sorted(engine.overlay.receivers), "edges": edges,
                "actions": acts}

    @api.post("/sources/{name}/try")
    def try_source(name: str, body: TryIn, _: Any = Depends(person)) -> JSONResponse:
        from ..sources import SourceError, to_events
        s = engine.sources.get(name)
        if s is None:
            raise HTTPException(404, f"unknown source {name}")
        try:
            evs = to_events(s, body.body, now=engine.clock())
        except SourceError as e:
            return JSONResponse({"detail": str(e)}, status_code=422)
        out = []
        for e in evs:
            facts = engine.fp.facts(e)
            out.append({"type": e.type, "key": e.idempotency_key, "payload": e.payload, "facts": facts,
                        "pattern": engine.registry.match(e.type, facts).id})
        return JSONResponse({"events": out})

    # ---- access: tokens for people and systems ---------------------------------
    def need_access(p: Any) -> None:
        if not can(p.id, "__access__"):
            raise HTTPException(403, "giving or revoking access needs the __access__ right")

    @api.post("/logout")
    def logout(request: Request, p: Any = Depends(person)) -> dict[str, Any]:
        """End a single sign-on session (tokens given by an administrator are not affected)."""
        raw = request.headers.get("authorization", "").partition(" ")[2]
        t = engine.access.resolve(raw) if raw else None
        if t is not None and t.source == "sso":
            engine.access.revoke(t.id, by=p.id)
            return {"ended": True}
        return {"ended": False}

    @api.get("/access/tokens")
    def tokens_list(p: Any = Depends(person)) -> list[dict[str, Any]]:
        need_access(p)
        return engine.access.list()

    @api.post("/access/tokens")
    def tokens_issue(body: TokenIn, p: Any = Depends(person)) -> dict[str, Any]:
        need_access(p)
        d = engine.directory
        if body.kind == "person" and d is not None and body.principal not in d.people:
            raise HTTPException(422, f"{body.principal!r} is not in the people configuration")
        if not body.principal.strip():
            raise HTTPException(422, "say who the token is for")
        raw, t = engine.access.issue(body.kind, body.principal.strip(), by=p.id, label=body.label,
                                     days=body.days)
        return {"token": raw, **t.public(engine.clock())}

    @api.post("/access/sso-reset/{person_id}")
    def sso_reset(person_id: str, p: Any = Depends(person)) -> dict[str, Any]:
        """Let a person sign in again with a different account at the identity provider (e.g. a new one)."""
        need_access(p)
        if sso is None:
            raise HTTPException(404, "single sign-on is not configured")
        engine.store.put_source_state(f"sso:{sso.issuer.rstrip('/')}:person:{person_id}", {})
        engine.store.audit(None, "sso_reset", {"person": person_id, "by": p.id})
        return {"reset": person_id}

    @api.post("/access/tokens/{token_id}/revoke")
    def tokens_revoke(token_id: str, p: Any = Depends(person)) -> dict[str, Any]:
        need_access(p)
        try:
            return engine.access.revoke(token_id, by=p.id).public(engine.clock())
        except KeyError:
            raise HTTPException(404, "unknown token") from None

    @api.post("/sources/{name}/poll")
    def poll_now(name: str, p: Any = Depends(person)) -> JSONResponse:
        if not can(p.id, "__configure__"):
            raise HTTPException(403, "fetching a source now needs the __configure__ right")
        try:
            return JSONResponse(engine.poll_source(name))
        except Exception as e:  # noqa: BLE001 - shown to the person
            return JSONResponse({"detail": f"{type(e).__name__}: {e}"}, status_code=502)

    @api.post("/mcp/{name}/test")
    def mcp_test(name: str, p: Any = Depends(person)) -> JSONResponse:
        if not can(p.id, "__configure__"):
            raise HTTPException(403, "testing an MCP server needs the __configure__ right")
        conn = engine.connectors
        if conn is None or name not in conn.clients:
            raise HTTPException(404, f"unknown MCP server {name}")
        c = conn.clients[name]
        try:
            probs = c.verify()
        except Exception as e:  # noqa: BLE001
            return JSONResponse({"detail": str(e)}, status_code=502)
        return JSONResponse({"usable": sorted(c.verified or []), "problems": [{"severity": s, "message": m}
                                                                              for s, m in probs]})

    # ---- templates ----------------------------------------------------------
    @api.get("/templates")
    def templates_list(_: Any = Depends(person)) -> list[dict[str, Any]]:
        from .. import templates
        return templates.all_summaries()

    @api.get("/templates/{name}")
    def template(name: str, _: Any = Depends(person)) -> dict[str, Any]:
        from .. import templates
        try:
            t = templates.get(name)
        except KeyError:
            raise HTTPException(404, f"unknown template {name}") from None
        have = {s.name for s in engine.actions.specs()}
        t["missing"] = {"actions": [a for a in t["needs"]["actions"] if a not in have],
                        "verifiers": [v for v in t["needs"]["verifiers"] if v not in engine.overlay.verifiers]}
        return t

    # ---- trace and cases ---------------------------------------------------------
    @api.post("/trace")
    def trace(body: TraceIn, p: Any = Depends(person)) -> dict[str, Any]:
        """What would happen to this event now. Read-only. Draft registries and lookups need __configure__
        (lookups call the customer's systems, even if only to read)."""
        if (body.registry is not None or body.run_lookups) and not can(p.id, "__configure__"):
            raise HTTPException(403, "tracing against a draft or running lookups needs the __configure__ right")
        from ..models import Event
        try:
            ev = Event.model_validate({"source": "trace", **body.event})
        except Exception as e:  # noqa: BLE001 - shown in the page
            raise HTTPException(422, f"not an event: {e}") from None
        engine._check_payload(ev)
        return engine.trace(ev, registry_text=body.registry, run_lookups=body.run_lookups)

    @api.post("/config/registry/replay")
    def replay(body: TextIn, days: float = 30, p: Any = Depends(person)) -> dict[str, Any]:
        """What a draft registry would change for the last ``days`` of cases (needs __configure__: it reads
        every case)."""
        if not can(p.id, "__configure__"):
            raise HTTPException(403, "replaying cases needs the __configure__ right")
        return engine.replay(body.body(), days=max(1.0, min(days, 365.0)))

    @api.get("/value")
    def value(days: int = 30, _: Any = Depends(person)) -> dict[str, Any]:
        return engine.value(days=max(1, min(days, 366)))

    @api.get("/capabilities")
    def capabilities(days: int = 30, p: Any = Depends(person)) -> dict[str, Any]:
        """Business capabilities: exceptions, outcome metrics, cases and how far each has got."""
        return engine.capability_overview(days=max(1, min(days, 366)), person=p.id)

    @api.get("/methods/candidates")
    def method_candidates(pattern: str | None = None, _: Any = Depends(person)) -> list[dict[str, Any]]:
        """Methods learning has proposed: their evidence, backtest, shadow record and status."""
        return engine.method_candidates(pattern)

    @api.get("/methods/candidates/{candidate_id}/trial")
    def method_trial(candidate_id: str, _: Any = Depends(person)) -> dict[str, Any]:
        """A candidate's randomised trial: both arms' verified outcomes and handling time, and the verdict."""
        from ..methodlearn import MethodLearnError
        try:
            return engine.method_trial(candidate_id)
        except MethodLearnError as e:
            raise HTTPException(404, str(e)) from None

    @api.post("/methods/propose")
    def methods_propose(body: dict[str, Any], p: Any = Depends(person)) -> list[dict[str, Any]]:
        if not can(p.id, "__configure__"):
            raise HTTPException(403, "proposing methods reads every case: it needs the __configure__ right")
        return engine.propose_methods(_in.text(body, "pattern", default="") or None,
                                      days=_in.number(body, "days", default=90, integer=True, lo=1, hi=3660),
                                      min_cases=_in.number(body, "min_cases", default=5, integer=True, lo=1,
                                                           hi=1_000_000))

    @api.post("/methods/candidates/{candidate_id}/{what}")
    def method_decide(candidate_id: str, what: str, body: dict[str, Any], p: Any = Depends(person)) -> dict[str, Any]:
        from ..methodlearn import MethodLearnError
        if what not in ("shadow", "trial", "reject", "promote", "rollback"):
            raise HTTPException(404, f"unknown decision {what}")
        kw = ({"share": _in.number(body, "share", lo=0, hi=1)}
              if what == "trial" and body.get("share") is not None else {})
        try:
            return engine.decide_method(candidate_id, what, p.id, note=_in.text(body, "note"), **kw)
        except AuthorizationError as e:
            raise HTTPException(403, str(e)) from None
        except MethodLearnError as e:
            raise HTTPException(409, str(e)) from None

    @api.get("/methods")
    def methods(days: int = 90, capability: str | None = None, _: Any = Depends(person)) -> dict[str, Any]:
        """Outcomes per method version of each exception, to compare a new way of working with the old."""
        return engine.method_evidence(days=max(1, min(days, 366)), capability=capability)

    @api.get("/secrets")
    def secrets_list(_: Any = Depends(person)) -> dict[str, Any]:
        from ..secretstore import available, required
        engine._load_secrets()
        auth = sorted(getattr(engine.connectors, "auth", {}) or {}) if engine.connectors is not None else []
        return {"can_store": available(), "keys": required(engine), "logins": auth,
                "problems": engine.secrets.problems}

    @api.put("/secrets/{name}")
    def secret_set(name: str, body: SecretIn, p: Any = Depends(person)) -> dict[str, Any]:
        from ..secretstore import SecretStoreError
        try:
            return engine.set_secret(name, body.value, p.id)
        except SecretStoreError as e:
            raise HTTPException(400, str(e)) from None

    @api.delete("/secrets/{name}")
    def secret_clear(name: str, p: Any = Depends(person)) -> dict[str, Any]:
        return {"cleared": engine.clear_secret(name, p.id)}

    @api.post("/secrets/test/{login}")
    def secret_test(login: str, _: Any = Depends(person)) -> dict[str, Any]:
        from .. import connauth
        connauth.invalidate(login)
        try:
            tok = connauth.token(login)
        except connauth.AuthError as e:
            return {"ok": False, "detail": str(e)}
        return {"ok": True, "detail": f"logged in (token ending {tok[-4:]})" if len(tok) >= 8 else "logged in"}

    @api.get("/connector-templates")
    def connector_templates(_: Any = Depends(person)) -> list[dict[str, Any]]:
        from .. import connectors as ct
        return [ct.summary(n) for n in ct.names()]

    @api.get("/connector-templates/{name}")
    def connector_template(name: str, _: Any = Depends(person)) -> dict[str, Any]:
        from .. import connectors as ct
        try:
            t = ct.load(name)
        except KeyError as e:
            raise HTTPException(404, str(e)) from None
        return {"summary": ct.summary(name), "connectors": t.get("connectors") or {}}

    @api.get("/packs")
    def pack_catalogue(_: Any = Depends(person)) -> dict[str, Any]:
        import os as _os

        from .. import catalogue as _cat
        from ..packs import PackError
        path = _os.environ.get("SENTINEL_PACK_CATALOGUE")
        if not path:
            return {"configured": False, "packs": []}
        try:
            entries = _cat.search(_cat.load(path))
        except (PackError, OSError, ValueError) as e:
            return {"configured": True, "packs": [], "error": str(e)}
        layers = {p.layer for p in engine.registry.all() if p.layer and p.layer.startswith("pack:")}
        return {"configured": True, "packs": [{**{k: e[k] for k in ("id", "version", "title", "industry",
                                                                     "exceptions", "capabilities", "fits")},
                                               "installed": "yes" if f"pack:{e['id']}" in layers else None}
                                              for e in entries]}

    @api.get("/benchmark")
    def benchmark(month: str | None = None, _: Any = Depends(person)) -> dict[str, Any]:
        import json as _json
        import os as _os
        from pathlib import Path as _Path

        from .. import benchmark as bm
        path = _os.environ.get("SENTINEL_BENCHMARK")
        if not path or not _Path(path).is_file():
            return {"configured": False, "rows": []}
        bench = _json.loads(_Path(path).read_text(encoding="utf-8"))
        m = month or bm.last_month(engine)
        industry = _os.environ.get("SENTINEL_INDUSTRY", "")
        snap = bm.snapshot(engine, m, industry=industry, audit=False)
        return {"configured": True, "month": m, "industry": industry or "all", "k": bench.get("k"),
                "rows": bm.compare(snap, bench, industry)}

    @api.get("/suggestions")
    def suggestions(days: int = 30, _: Any = Depends(person)) -> list[dict[str, Any]]:
        return engine.suggest_patterns(days=max(1, min(days, 180)))

    @api.get("/model-quality")
    def model_quality(days: int = 30, _: Any = Depends(person)) -> dict[str, Any]:
        return engine.model_quality(days=max(1, min(days, 366)))

    @api.get("/plan")
    def plan(p: Any = Depends(person)) -> dict[str, Any]:
        """This month's usage."""
        from ..usage import measure
        month = engine.clock().strftime("%Y-%m")
        return {"month": month,
                "usage": measure(engine, month) if can(p.id, "__configure__") else None}

    @api.get("/usage/{month}")
    def usage_export(month: str, p: Any = Depends(person)) -> JSONResponse:
        if not can(p.id, "__configure__"):
            raise HTTPException(403, "the usage export needs the __configure__ right")
        from ..usage import export
        try:
            doc = export(engine, month)
        except ValueError as e:
            raise HTTPException(422, str(e)) from None
        return JSONResponse(doc, headers={"Content-Disposition": f'attachment; filename="usage-{month}.json"'})

    @api.post("/privacy/find")
    def privacy_find(body: PrivacyIn, p: Any = Depends(person)) -> dict[str, Any]:
        if not can(p.id, "__privacy__"):
            raise HTTPException(403, "privacy requests need the __privacy__ right")
        from ..privacy import find
        try:
            found = find(engine, body.identifier)
        except ValueError as e:
            raise HTTPException(422, str(e)) from None
        return {"cases": [{"id": i.id, "pattern": i.pattern_id, "state": i.state.value,
                           "created_at": i.created_at.isoformat()} for i in found]}

    @api.post("/privacy/access")
    def privacy_access(body: PrivacyIn, p: Any = Depends(person)) -> JSONResponse:
        try:
            doc = engine.privacy_access(body.identifier, p.id)
        except ValueError as e:
            raise HTTPException(422, str(e)) from None
        return JSONResponse(doc, headers={"Content-Disposition": 'attachment; filename="access-request.json"'})

    @api.post("/privacy/erase")
    def privacy_erase(body: PrivacyIn, p: Any = Depends(person)) -> dict[str, Any]:
        try:
            return engine.privacy_erase(body.identifier, p.id, body.reason, include_open=body.include_open)
        except ValueError as e:
            raise HTTPException(422, str(e)) from None

    @api.get("/fleet")
    def fleet(p: Any = Depends(person)) -> dict[str, Any]:
        """The fleet view, on the instance KBGrid runs it from (SENTINEL_FLEET names the fleet file)."""
        import os as _os
        path = _os.environ.get("SENTINEL_FLEET")
        if not path:
            return {"enabled": False}
        if not can(p.id, "__configure__"):
            raise HTTPException(403, "the fleet view needs the __configure__ right")
        from ..fleet import collect, load
        return {"enabled": True, **collect(load(path))}

    @api.get("/golive")
    def golive(_: Any = Depends(person)) -> dict[str, Any]:
        return engine.readiness()

    @api.post("/golive/{mode}")
    def golive_switch(mode: str, body: ShadowIn, p: Any = Depends(person)) -> JSONResponse:
        if mode not in ("live", "shadow"):
            raise HTTPException(404, "live or shadow")
        try:
            cv = engine.set_shadow(body.patterns, mode == "shadow", p.id, body.note)
        except ApprovalNeeded as e:
            return JSONResponse({"waiting": [x.summary() for x in e.versions], "detail": str(e)}, status_code=202)
        except ConfigError as e:
            return JSONResponse({"detail": str(e), "problems": _problems(e.problems)}, status_code=422)
        return JSONResponse({"version": cv.summary()})

    @api.get("/cases")
    def cases(pattern: str | None = None, state: str | None = None, text: str | None = None,
              fact: list[str] | None = Query(default=None), days: float | None = None, before: str | None = None,
              limit: int = 50, p: Any = Depends(person)) -> dict[str, Any]:
        facts = {}
        for f in fact or []:
            k, sep, v = f.partition("=")
            if not sep or not k:
                raise HTTPException(422, "fact filters look like name=value")
            facts[k.strip()] = v.strip()
        cursor = None
        if before:
            ts, sep, cid = before.partition(":")
            try:
                cursor = (float(ts), cid)
            except ValueError:
                raise HTTPException(422, "bad 'before' cursor") from None
        since = (engine.clock().timestamp() - days * 86400) if days else None
        try:
            return engine.search_cases(p.id, pattern=pattern or None, state=state or None, text=text or None,
                                       facts=facts or None, since_ts=since, before=cursor, limit=limit)
        except ValueError as e:
            raise HTTPException(422, str(e)) from None

    @api.get("/cases/{incident_id}")
    def case(incident_id: str, p: Any = Depends(person)) -> dict[str, Any]:
        inc = engine.store.get_incident(incident_id)
        if inc is None or not engine.can_view_incident(p.id, inc):
            raise HTTPException(404, "unknown case")
        out = engine.case(incident_id) or {}
        out["can_reverse_now"] = bool(out.get("reverse", {}).get("possible")) and can(p.id, "__reverse__",
                                                                                       inc.pattern_id)
        return out

    @api.post("/cases/{incident_id}/reverse")
    def reverse_case(incident_id: str, body: ReverseIn, p: Any = Depends(person)) -> dict[str, Any]:
        from ..engine import EngineError
        inc = engine.store.get_incident(incident_id)
        if inc is None or not engine.can_view_incident(p.id, inc):
            raise HTTPException(404, "unknown case")
        try:
            d = engine.reverse(incident_id, actor=p.id, note=body.note)
        except AuthorizationError as e:                 # a refusal is a 403, never a 409
            raise HTTPException(403, str(e)) from None
        except EngineError as e:
            raise HTTPException(409, str(e)) from None
        return {"reversed": True, "disposition": d.model_dump(mode="json")}

    # ---- operations ------------------------------------------------------------
    @api.get("/reviews")
    def reviews(p: Any = Depends(person), localise: bool = False) -> list[dict[str, Any]]:
        return [engine.build_card(r, p.id, localise=localise).model_dump(mode="json") for r in engine.reviews_for(p.id)]

    @api.get("/reviews/ranked")
    def reviews_ranked(p: Any = Depends(person), pattern: str | None = None) -> list[dict[str, Any]]:
        """The person's open reviews ranked by money at stake, then soonest due (digested ones marked)."""
        return engine.ranked_reviews(p.id, pattern)

    @api.get("/agents")
    def agents(p: Any = Depends(person)) -> dict[str, Any]:
        """Agents at a glance (ADR-003/005): each template's slots and bound roles, trust and scale settings,
        agent policies, oversight and the domain binding. Read-only; changes go through People & roles."""
        d = engine.directory
        ov = engine.overlay
        rows = []
        for pt in engine.registry.all():
            rows.append({"id": pt.id, "capability": pt.capability, "description": pt.description,
                         "owner_slot": pt.owner_slot, "owner_role": pt.owner_role,
                         "escalation_slot": pt.escalation_slot, "escalation_role": pt.escalation_role,
                         "max_route": pt.max_route.value, "shadow": pt.shadow, "trust_by": pt.trust_by,
                         "trust_pool_min": pt.trust_pool_min, "digest_above": pt.digest_above,
                         "money_fact": pt.money_fact, "spot_check_rate": pt.spot_check_rate, "claims": pt.claims,
                         "open": engine.store.count_open_reviews_of_pattern(pt.id),
                         "overseers": d.overseers(pt.id, pt.capability) if d is not None else []})
        mine = set(d.roles_of(p.id)) if d is not None else set()
        b = ov.binding
        return {"slots": dict(ov.slots or {}), "slot_bindings": dict(ov.slot_bindings or {}), "templates": rows,
                "agents": [a.model_dump(mode="json", exclude_defaults=True) for a in (d.agents if d else [])],
                "oversight": [o.model_dump(mode="json") for o in (d.oversight if d else [])],
                "stop_at": list(d.stop_at) if d else [],
                "can_oversee": bool(d is not None and mine & {o.role for o in d.oversight}),
                "data_trust": engine.data_trust_scores(),
                "data_trust_rule": (engine.case_defaults.data_trust.model_dump()
                                    if engine.case_defaults.data_trust else None),
                "binding": ({"domain": b.domain, "never_automate": list(b.never_automate),
                             "binds": [x.model_dump(mode="json") for x in b.binds]} if b is not None else None)}

    @api.get("/spot-checks")
    def spot_checks(p: Any = Depends(person)) -> list[dict[str, Any]]:
        """Sampled unattended decisions this person may check."""
        return engine.spot_checks(p.id)

    @api.post("/spot-checks/{incident_id}")
    def spot_check(incident_id: str, body: dict[str, Any], p: Any = Depends(person)) -> dict[str, Any]:
        from ..engine import EngineError
        ok = _in.boolean(body, "ok")
        note = _in.text(body, "note", max_len=2000)
        try:
            return engine.spot_check_verdict(incident_id, p.id, ok, note)
        except AuthorizationError as e:
            raise HTTPException(403, str(e)) from None
        except EngineError as e:
            raise HTTPException(409, str(e)) from None

    @api.get("/agent-incidents")
    def agent_incidents(_: Any = Depends(person)) -> list[dict[str, Any]]:
        return engine.agent_incidents()

    @api.post("/agent-incidents")
    def open_agent_incident(body: dict[str, Any], p: Any = Depends(person)) -> dict[str, Any]:
        """Stop an agent, list and re-check its recent decisions, optionally undo them (oversight roles only)."""
        from ..engine import EngineError
        hours = _in.number(body, "hours", default=24)
        undo = _in.boolean(body, "undo", default=False)
        pattern, reason = _in.text(body, "pattern"), _in.text(body, "reason", max_len=2000)
        try:
            return engine.agent_incident(pattern, p.id, reason, hours=hours, undo=undo)
        except AuthorizationError as e:
            raise HTTPException(403, str(e)) from None
        except (EngineError, ValueError) as e:
            raise HTTPException(409, str(e)) from None

    @api.post("/agent-incidents/{incident_id}/close")
    def close_agent_incident(incident_id: str, body: dict[str, Any], p: Any = Depends(person)) -> dict[str, Any]:
        from ..engine import EngineError
        try:
            return engine.close_agent_incident(incident_id, p.id, _in.text(body, "postmortem", max_len=20_000))
        except AuthorizationError as e:
            raise HTTPException(403, str(e)) from None
        except EngineError as e:
            raise HTTPException(409, str(e)) from None

    @api.post("/agents/effective")
    def agents_effective(body: dict[str, Any], _: Any = Depends(person)) -> dict[str, Any]:
        """Which agent policy, identity, mode and route apply to a template in a scope (read-only)."""
        try:
            pt = engine.registry.get(_in.text(body, "pattern"))
        except KeyError:
            raise HTTPException(404, f"unknown pattern {body.get('pattern')!r}") from None
        facts = _in.facts(body, "facts")
        pol = engine.agent_policy(pt, facts)
        return {"pattern": pt.id, "facts": facts, "policy": pol.model_dump(mode="json") if pol else None,
                "agent": engine.agent_identity(pt, facts), "mode": pol.mode if pol else None,
                "route": engine.effective_route(pt, facts).value, "shadow": engine.is_shadow(pt, facts),
                "segment": engine.segment_of(pt, facts)}

    @api.post("/oversee")
    def oversee(body: dict[str, Any], p: Any = Depends(person)) -> dict[str, Any]:
        """Layer D's lever: stop, demote or cap an agent (template or one scope). Oversight roles only."""
        from ..engine import EngineError
        from ..models import Route
        try:
            r = _in.text(body, "route")
            route = Route(r) if r else None
            states = engine.oversee(_in.text(body, "pattern"), _in.text(body, "action"), p.id,
                                    _in.text(body, "reason", max_len=2000), route=route)
        except AuthorizationError as e:
            raise HTTPException(403, str(e)) from None
        except (EngineError, ValueError) as e:
            raise HTTPException(409, str(e)) from None
        return {"states": [{"state": x.pattern_id, "route": x.route.value,
                            "cap": x.cap.value if x.cap else None} for x in states]}

    def _lifecycle_call(fn: Any) -> dict[str, Any]:
        from ..engine import EngineError
        try:
            out = fn()
        except AuthorizationError as e:
            raise HTTPException(403, str(e)) from None
        except EngineError as e:
            raise HTTPException(409, str(e)) from None
        except (ValueError, KeyError) as e:
            raise HTTPException(422, str(e).strip("'")) from None
        return out.model_dump(mode="json")

    @api.post("/reviews/{review_id}/pause")
    def pause(review_id: str, body: PauseIn, p: Any = Depends(person)) -> dict[str, Any]:
        return _lifecycle_call(lambda: engine.pause_review(review_id, p.id, body.reason, hours=body.hours))

    @api.post("/reviews/{review_id}/resume")
    def resume(review_id: str, p: Any = Depends(person)) -> dict[str, Any]:
        return _lifecycle_call(lambda: engine.resume_review(review_id, p.id))

    @api.get("/silences")
    def silences(p: Any = Depends(person)) -> dict[str, Any]:
        now = engine.clock()
        items = engine.silences.all()
        held: dict[str, int] = {}
        for r in engine.store.open_reviews():
            if r.hold is not None and r.hold.silence_id:
                held[r.hold.silence_id] = held.get(r.hold.silence_id, 0) + 1
        def row(x: Any) -> dict[str, Any]:
            return {**x.model_dump(mode="json"), "active": x.active(now), "holding": held.get(x.id, 0)}
        return {"active": [row(x) for x in items if x.active(now)],
                "upcoming": [row(x) for x in items if x.ended_at is None and x.starts_at > now],
                "ended": [row(x) for x in reversed(items) if not x.active(now) and not
                          (x.ended_at is None and x.starts_at > now)][:20],
                "can_silence": can(p.id, "__silence__") or can(p.id, "__kill_switch__"),
                "patterns": sorted(x.id for x in engine.registry.all())}

    @api.post("/silences")
    def add_silence(body: SilenceIn, p: Any = Depends(person)) -> dict[str, Any]:
        return _lifecycle_call(lambda: engine.add_silence(p.id, reason=body.reason, hours=body.hours,
                                                          pattern=body.pattern or None, facts=body.facts))

    @api.delete("/silences/{silence_id}")
    def end_silence(silence_id: str, p: Any = Depends(person)) -> dict[str, Any]:
        return _lifecycle_call(lambda: engine.end_silence(silence_id, p.id))

    # ---- metrics: KPIs, monitors and the way from a number to an action ---------------------------------
    @api.get("/metrics")
    def metrics_overview(p: Any = Depends(person)) -> dict[str, Any]:
        from ..kpi import KpiError, can_see
        kp = engine.kpi
        if kp is None:
            return {"configured": False, "metrics": [], "monitors": [], "datasets": []}
        out = []
        for name, m in kp.doc.metrics.items():
            if not can_see(engine, p.id, m):
                continue
            row: dict[str, Any] = {"name": name, "title": m.title, "format": m.format, "target": m.target_text(),
                                   "owner": m.owner, "dimensions": m.dimensions, "description": m.description}
            try:
                now = kp.query(name, days=7, compare=True)
                trend = kp.query(name, days=28, grain="day")
                row.update(value=now["total"], change_pct=now.get("change_pct"),
                           trend=[{"x": r["period"], "y": r["value"]} for r in trend["rows"]])
            except KpiError as e:
                row["error"] = str(e)
            out.append(row)
        mons = []
        for name, mon in kp.doc.monitors.items():
            st = engine.store.get_source_state(f"monitor:{name}") or {}
            mons.append({"name": name, "metric": mon.metric, "by": mon.by, "window_days": mon.window_days,
                         "every_minutes": mon.every_minutes, "when": mon.when, "enabled": mon.enabled,
                         "breaching": st.get("breaching") or {}, "last_run": st.get("last_run")})
        ds = [{"name": n, "kind": d.kind, "rows": kp.counts.get(n), "error": kp.errors.get(n),
               "loaded_at": kp.loaded[n].isoformat() if n in kp.loaded else None,
               "refresh_minutes": d.refresh_minutes, "owner": d.owner,
               "trust": kp.trust.get(n) if d.checks is not None else None} for n, d in kp.doc.datasets.items()]
        return {"configured": True, "metrics": out, "monitors": mons, "datasets": ds,
                "can_run": can(p.id, "__configure__")}

    @api.post("/metrics/query")
    def metrics_query(body: MetricQueryIn, p: Any = Depends(person)) -> dict[str, Any]:
        from ..kpi import KpiError, can_see, widget
        kp = engine.kpi
        m = kp.doc.metrics.get(body.metric) if kp else None
        if m is None or not can_see(engine, p.id, m):
            raise HTTPException(404, f"unknown metric {body.metric}")
        try:
            res = kp.query(body.metric, by=body.by, filters=body.filters, days=body.days, grain=body.grain,
                           compare=True)
        except KpiError as e:
            raise HTTPException(422, str(e)) from None
        return {"result": res, "widget": widget(res)}

    @api.post("/metrics/raise")
    def metrics_raise(body: MetricRaiseIn, p: Any = Depends(person)) -> dict[str, Any]:
        from ..kpi import KpiError, raise_case
        try:
            r = raise_case(engine, p.id, body.metric, body.filters, body.note)
        except PermissionError:
            raise HTTPException(404, f"unknown metric {body.metric}") from None
        except KpiError as e:
            raise HTTPException(422, str(e)) from None
        return {"status": r.status, "incident_id": r.incident_id}

    @api.post("/monitors/{name}/run")
    def monitor_run(name: str, p: Any = Depends(person)) -> dict[str, Any]:
        from ..kpi import KpiError
        if not can(p.id, "__configure__"):
            raise HTTPException(403, "running a monitor now needs the __configure__ right")
        try:
            return engine.run_monitor(name)
        except KpiError as e:
            raise HTTPException(404, str(e)) from None

    @api.get("/learning")
    def learning(_: Any = Depends(person)) -> dict[str, Any]:
        return {"evaluations": engine.store.recent_audit(20, ["model_evaluation"]),
                "changes": engine.store.recent_audit(30, ["learning", "promotion_approved", "promotion_rejected",
                                                          "promotion_approval_recorded", "route_set", "reversed",
                                                          "pattern_changed", "outcome"]),
                "models": engine.router.summary() if engine.router else {}}

    @api.get("/activity")
    def activity(limit: int = 100, _: Any = Depends(person)) -> list[dict[str, Any]]:
        return engine.store.recent_audit(max(1, min(limit, 500)))

    @api.get("/analytics/{report}")
    def analytics(report: str, days: int | None = None, _: Any = Depends(person)) -> JSONResponse:
        try:
            from ..analytics import REPORTS, Analytics
        except ImportError:
            return JSONResponse({"detail": "analytics needs kbg-sentinel[analytics]"}, status_code=501)
        if report not in REPORTS:
            raise HTTPException(404, f"unknown report {report}")
        st = engine.store
        if getattr(st, "dsn", None):
            src = {"pg": st.dsn, "schema": st.schema}
        elif getattr(st, "path", ":memory:") != ":memory:":
            src = {"sqlite": st.path}
        else:
            return JSONResponse({"detail": "analytics needs a file or PostgreSQL store"}, status_code=501)
        try:
            with Analytics(**src) as an:
                fn = getattr(an, report)
                rows = fn() if report in ("trust", "evaluations") else fn(days) if report != "hotspots" else fn(
                    None, days)
        except Exception as e:  # noqa: BLE001 - shown in the page
            return JSONResponse({"detail": f"{type(e).__name__}: {e}"}, status_code=500)
        return JSONResponse(rows, headers={"Cache-Control": "no-store"})

    app.include_router(api)

    @app.exception_handler(AuthorizationError)
    async def _auth(_: Any, e: AuthorizationError) -> JSONResponse:
        return JSONResponse({"detail": str(e), "escalate_to": e.escalate_to}, status_code=403)

    app.mount("/console/static", StaticFiles(directory=STATIC), name="console-static")

    # ---- single sign-on -------------------------------------------------------------
    from ..sso import OIDC, SSOError
    oidc = OIDC(sso) if sso is not None else None

    @app.get("/console/sso/info", include_in_schema=False)
    def sso_info() -> dict[str, Any]:
        return {"enabled": oidc is not None, "button": oidc.cfg.button if oidc else None}

    def sso_page(msg: str, status: int) -> HTMLResponse:
        return HTMLResponse(f"<!doctype html><meta charset=utf-8><title>Sign-in</title>"
                            f"<body style='font:15px system-ui;margin:3em'><p>{html.escape(msg)}</p>"
                            f"<p><a href='/console'>Back to the console</a></p>", status_code=status)

    @app.get("/console/sso/login", include_in_schema=False)
    def sso_login() -> Any:
        if oidc is None:
            raise HTTPException(404, "single sign-on is not configured")
        try:
            url, cookie = oidc.start()
        except SSOError as e:
            return sso_page(str(e), 502)
        resp = RedirectResponse(url, status_code=302)
        resp.set_cookie(OIDC.COOKIE, cookie, max_age=600, path="/console/sso", httponly=True, samesite="lax",
                        secure=oidc.cfg.redirect_url.startswith("https://"))
        return resp

    @app.get("/console/sso/callback", include_in_schema=False)
    def sso_callback(request: Request, code: str = "", state: str = "", error: str = "",
                     error_description: str = "") -> Any:
        if oidc is None:
            raise HTTPException(404, "single sign-on is not configured")
        if error:
            return sso_page(f"Sign-in was not completed: {error_description or error}", 401)
        try:
            claims = oidc.finish(code, state, request.cookies.get(OIDC.COOKIE))
            pid = oidc.person_for(claims, engine.directory)
            oidc.bind(engine.store, claims, pid)
        except SSOError as e:
            engine.store.audit(None, "sso_refused", {"reason": str(e)})
            return sso_page(str(e), 403)
        raw, _ = engine.access.issue("person", pid, by="sso", label="single sign-on", source="sso",
                                     days=oidc.cfg.session_hours / 24)
        resp = RedirectResponse(f"/console#sso={raw}", status_code=302)
        resp.delete_cookie(OIDC.COOKIE, path="/console/sso")
        return resp

    @app.get("/console", include_in_schema=False)
    def console_index() -> FileResponse:
        return FileResponse(STATIC / "index.html", headers={"Cache-Control": "no-cache"})

    @app.get("/console/m", include_in_schema=False)
    def console_mobile() -> FileResponse:
        """The mobile review page for store and warehouse staff."""
        return FileResponse(STATIC / "m.html", headers={"Cache-Control": "no-cache"})

    @app.get("/", include_in_schema=False)
    def root() -> RedirectResponse:
        return RedirectResponse("/console")
