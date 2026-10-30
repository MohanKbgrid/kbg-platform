# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""SCIM 2.0 provisioning: the company directory (Entra ID, Okta, Google, JumpCloud) creates, updates and
removes people, and its groups give them roles.

The people configuration says which roles each group gives:

    scim:
      group_roles:
        "Ops - Fulfilment": [fulfilment_exec]
        "Ops - Leads": [fulfilment_lead, {role: finance_ops, scope: {region: south}}]
      default_roles: []

Provisioned people are kept in the database and added to the people configuration's own (which wins for an
id both define, except that a person the directory deactivates or removes is inactive here too). Their
roles come only from group membership, so moving someone between groups in the directory moves their work
here at the next sync. Authority rules, roles and approval policy stay in the people configuration.

The endpoint is ``/scim/v2`` with a bearer token: ``SENTINEL_SECRET_SCIM_TOKEN`` (in hosted mode
``SENTINEL_SECRET_<TENANT>_SCIM_TOKEN``), or a service token named ``scim`` in tokens.yaml.
"""
from __future__ import annotations

import re
import uuid
from typing import TYPE_CHECKING, Any

from .rbac import Assignment, Directory, Person

try:                                    # the API extra; the merge and the service work without it
    from fastapi import APIRouter, Header, Request
    from fastapi.responses import JSONResponse, Response
    from starlette.concurrency import run_in_threadpool
except ImportError:  # pragma: no cover
    pass

if TYPE_CHECKING:
    from .engine import Engine

STATE = "__scim__"
USER = "urn:ietf:params:scim:schemas:core:2.0:User"
GROUP = "urn:ietf:params:scim:schemas:core:2.0:Group"
LIST = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
PATCH = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
ERROR = "urn:ietf:params:scim:api:messages:2.0:Error"


class ScimError(Exception):
    def __init__(self, status: int, detail: str, scim_type: str | None = None) -> None:
        super().__init__(detail)
        self.status, self.detail, self.scim_type = status, detail, scim_type

    def body(self) -> dict[str, Any]:
        out = {"schemas": [ERROR], "status": str(self.status), "detail": self.detail}
        if self.scim_type:
            out["scimType"] = self.scim_type
        return out


def _empty() -> dict[str, Any]:
    return {"rev": 0, "users": {}, "groups": {}}


def _bool(v: Any) -> bool:
    return v if isinstance(v, bool) else str(v).strip().lower() in ("true", "1", "yes")


def _slug(user_name: str) -> str:
    local = user_name.split("@", 1)[0].lower()
    return re.sub(r"[^a-z0-9._-]+", ".", local).strip(".") or "user"


# ------------------------------------------------------------------ directory merge
def merge(base: Directory, state: dict[str, Any] | None) -> Directory:
    """The people configuration plus provisioned people and their group roles."""
    if not state or base.scim is None or not (state.get("users") or state.get("groups")):
        return base
    settings = base.scim
    people = dict(base.people)
    for u in state["users"].values():
        pid = u["person_id"]
        if pid in base.people:
            if not u["active"]:
                people[pid] = base.people[pid].model_copy(update={"active": False})
            continue
        contact = {"email": u["email"]} if u.get("email") else {}
        if u.get("phone"):
            contact["phone"] = u["phone"]
        people[pid] = Person(id=pid, name=u.get("name") or pid, contact=contact, active=u["active"])
    assignments = list(base.assignments)
    by_id = dict(state["users"])
    for u in by_id.values():
        if u["active"]:
            assignments += [Assignment(person_id=u["person_id"], role_id=r) for r in settings.default_roles
                            if r in base.roles]
    for g in state["groups"].values():
        grants = [x for x in settings.grants(g["name"]) if x.role in base.roles]
        for m in g["members"]:
            u = by_id.get(m)
            if u is None or not u["active"]:
                continue
            assignments += [Assignment(person_id=u["person_id"], role_id=x.role, scope=x.scope) for x in grants]
    return Directory(roles=base.roles.values(), people=people.values(), assignments=assignments, rules=base.rules,
                     two_person_auto_promotion=base.two_person_auto_promotion, unattended=base.unattended,
                     config_approval=base.config_approval, value=base.value, scim=base.scim,
                     scopes=base.scopes, stop_at=base.stop_at, vacancy=base.vacancy, sod=base.sod,
                     agents=base.agents, oversight=base.oversight)


# ------------------------------------------------------------------ resources
def _user_resource(sid: str, u: dict[str, Any], base_url: str = "") -> dict[str, Any]:
    out = {"schemas": [USER], "id": sid, "userName": u["user_name"], "active": u["active"],
           "displayName": u.get("name") or "", "name": {"formatted": u.get("name") or ""},
           "meta": {"resourceType": "User", "location": f"{base_url}/Users/{sid}", "version": f'W/"{u["v"]}"'},
           "sentinelPersonId": u["person_id"]}
    if u.get("external_id"):
        out["externalId"] = u["external_id"]
    if u.get("email"):
        out["emails"] = [{"value": u["email"], "primary": True, "type": "work"}]
    if u.get("phone"):
        out["phoneNumbers"] = [{"value": u["phone"], "type": "work"}]
    return out


def _group_resource(gid: str, g: dict[str, Any], users: dict[str, Any], base_url: str = "") -> dict[str, Any]:
    return {"schemas": [GROUP], "id": gid, "displayName": g["name"],
            "members": [{"value": m, "display": users[m]["user_name"]} for m in g["members"] if m in users],
            "meta": {"resourceType": "Group", "location": f"{base_url}/Groups/{gid}", "version": f'W/"{g["v"]}"'}}


def _user_fields(body: dict[str, Any]) -> dict[str, Any]:
    user_name = str(body.get("userName") or "").strip()
    if not user_name:
        raise ScimError(400, "userName is required", "invalidValue")
    name = body.get("displayName") or ""
    n = body.get("name") or {}
    if not name and isinstance(n, dict):
        name = n.get("formatted") or " ".join(x for x in (n.get("givenName"), n.get("familyName")) if x)
    emails = body.get("emails") or []
    email = next((e.get("value") for e in emails if isinstance(e, dict) and e.get("primary")), None) or \
        next((e.get("value") for e in emails if isinstance(e, dict)), None)
    if not email and "@" in user_name:
        email = user_name
    phones = body.get("phoneNumbers") or []
    phone = next((p.get("value") for p in phones if isinstance(p, dict)), None)
    return {"user_name": user_name, "name": name, "email": (email or "").lower() or None, "phone": phone,
            "external_id": body.get("externalId"), "active": _bool(body.get("active", True))}


def _filter(expr: str | None) -> tuple[str, str] | None:
    """The filters directories send: ``userName eq "x"``, ``externalId eq "x"``, ``displayName eq "x"``."""
    if not expr:
        return None
    m = re.fullmatch(r'\s*(\w+)\s+eq\s+"([^"]*)"\s*', expr)
    if not m:
        raise ScimError(400, f"unsupported filter {expr!r} (only 'attribute eq \"value\"')", "invalidFilter")
    return m.group(1), m.group(2)


# ------------------------------------------------------------------ service
class Scim:
    """SCIM operations against one engine; every change is audited and applied to the directory at once."""

    def __init__(self, engine: Engine, base_url: str = "/scim/v2") -> None:
        self.engine, self.base_url = engine, base_url

    def _check(self) -> None:
        base = getattr(self.engine, "_people_base", None)
        if base is None or base.scim is None:
            raise ScimError(501, "provisioning is off: add a 'scim:' section to the people configuration")

    def _load(self) -> dict[str, Any]:
        return self.engine.store.get_source_state(STATE) or _empty()

    def _save(self, st: dict[str, Any], kind: str, detail: dict[str, Any]) -> None:
        st["rev"] = int(st.get("rev", 0)) + 1
        self.engine.store.put_source_state(STATE, st)
        self.engine.store.audit(None, kind, detail)
        self.engine.refresh_directory()

    def _tx(self):  # noqa: ANN202
        import contextlib
        store = self.engine.store

        @contextlib.contextmanager
        def cm():  # noqa: ANN202
            with store.transaction():
                store.lock("scim")
                yield
        return cm()

    # ---- users
    def list_users(self, filter: str | None = None, start: int = 1, count: int = 100) -> dict[str, Any]:  # noqa: A002
        self._check()
        st = self._load()
        f = _filter(filter)
        key = {"userName": "user_name", "externalId": "external_id", "emails": "email",
               "emails.value": "email"}.get(f[0], f[0]) if f else None
        rows = [(sid, u) for sid, u in sorted(st["users"].items())
                if f is None or str(u.get(key) or "").lower() == f[1].lower()]
        page = rows[max(0, start - 1): max(0, start - 1) + max(0, count)]
        return {"schemas": [LIST], "totalResults": len(rows), "startIndex": start, "itemsPerPage": len(page),
                "Resources": [_user_resource(sid, u, self.base_url) for sid, u in page]}

    def get_user(self, sid: str) -> dict[str, Any]:
        self._check()
        u = self._load()["users"].get(sid)
        if u is None:
            raise ScimError(404, f"user {sid} not found")
        return _user_resource(sid, u, self.base_url)

    def create_user(self, body: dict[str, Any]) -> dict[str, Any]:
        self._check()
        fields = _user_fields(body)
        with self._tx():
            st = self._load()
            if any(u["user_name"].lower() == fields["user_name"].lower() for u in st["users"].values()):
                raise ScimError(409, f"userName {fields['user_name']} already exists", "uniqueness")
            taken = {u["person_id"] for u in st["users"].values()}
            base = self.engine._people_base
            pid = _slug(fields["user_name"])
            email_owner = next((p.id for p in base.people.values()
                                if fields["email"] and (p.contact.get("email") or "").lower() == fields["email"]),
                               None)
            if email_owner:                            # someone the people configuration already knows
                pid = email_owner
            else:
                stem, n = pid, 2
                while pid in taken or pid in base.people:
                    pid, n = f"{stem}{n}", n + 1
            sid = uuid.uuid4().hex
            st["users"][sid] = {**fields, "person_id": pid, "v": 1}
            self._save(st, "scim_user_created", {"id": sid, "person": pid, "user_name": fields["user_name"]})
        return _user_resource(sid, st["users"][sid], self.base_url)

    def replace_user(self, sid: str, body: dict[str, Any]) -> dict[str, Any]:
        self._check()
        fields = _user_fields(body)
        with self._tx():
            st = self._load()
            u = st["users"].get(sid)
            if u is None:
                raise ScimError(404, f"user {sid} not found")
            u.update(fields)
            u["v"] += 1
            self._save(st, "scim_user_updated", {"id": sid, "person": u["person_id"], "active": u["active"]})
        return _user_resource(sid, u, self.base_url)

    def patch_user(self, sid: str, body: dict[str, Any]) -> dict[str, Any]:
        self._check()
        with self._tx():
            st = self._load()
            u = st["users"].get(sid)
            if u is None:
                raise ScimError(404, f"user {sid} not found")
            for op in body.get("Operations") or []:
                kind = str(op.get("op", "")).lower()
                path, value = op.get("path"), op.get("value")
                if kind not in ("replace", "add", "remove"):
                    raise ScimError(400, f"unsupported op {op.get('op')!r}", "invalidSyntax")
                updates = {path: value} if path else (value if isinstance(value, dict) else {})
                for p, v in updates.items():
                    p = str(p)
                    if p == "active":
                        u["active"] = False if kind == "remove" else _bool(v)
                    elif p in ("displayName", "name.formatted"):
                        u["name"] = "" if kind == "remove" else str(v)
                    elif p == "userName":
                        u["user_name"] = str(v)
                    elif p == "externalId":
                        u["external_id"] = v
                    elif p.startswith("emails"):
                        val = v[0].get("value") if isinstance(v, list) and v and isinstance(v[0], dict) else v
                        u["email"] = None if kind == "remove" else (str(val).lower() if val else None)
                    elif p.startswith("phoneNumbers"):
                        val = v[0].get("value") if isinstance(v, list) and v and isinstance(v[0], dict) else v
                        u["phone"] = None if kind == "remove" else val
                    elif p == "name" and isinstance(v, dict):
                        u["name"] = v.get("formatted") or " ".join(
                            x for x in (v.get("givenName"), v.get("familyName")) if x) or u.get("name")
                    # other attributes (title, department, enterprise extension) are accepted and ignored
            u["v"] += 1
            self._save(st, "scim_user_updated", {"id": sid, "person": u["person_id"], "active": u["active"]})
        return _user_resource(sid, u, self.base_url)

    def delete_user(self, sid: str) -> None:
        self._check()
        with self._tx():
            st = self._load()
            u = st["users"].pop(sid, None)
            if u is None:
                raise ScimError(404, f"user {sid} not found")
            for g in st["groups"].values():
                g["members"] = [m for m in g["members"] if m != sid]
            # keep a deactivated record so a person also in the people configuration stays inactive
            if u["person_id"] in self.engine._people_base.people:
                st["users"][f"removed:{sid}"] = {**u, "active": False}
            self._save(st, "scim_user_removed", {"id": sid, "person": u["person_id"]})

    # ---- groups
    def list_groups(self, filter: str | None = None, start: int = 1, count: int = 100) -> dict[str, Any]:  # noqa: A002
        self._check()
        st = self._load()
        f = _filter(filter)
        rows = [(gid, g) for gid, g in sorted(st["groups"].items())
                if f is None or (f[0] == "displayName" and g["name"].lower() == f[1].lower())
                or (f[0] == "externalId" and str(g.get("external_id") or "") == f[1])]
        page = rows[max(0, start - 1): max(0, start - 1) + max(0, count)]
        return {"schemas": [LIST], "totalResults": len(rows), "startIndex": start, "itemsPerPage": len(page),
                "Resources": [_group_resource(gid, g, st["users"], self.base_url) for gid, g in page]}

    def get_group(self, gid: str) -> dict[str, Any]:
        self._check()
        st = self._load()
        g = st["groups"].get(gid)
        if g is None:
            raise ScimError(404, f"group {gid} not found")
        return _group_resource(gid, g, st["users"], self.base_url)

    def _members(self, st: dict[str, Any], raw: Any) -> list[str]:
        out = []
        for m in raw or []:
            v = m.get("value") if isinstance(m, dict) else m
            if v in st["users"] and v not in out:
                out.append(v)
        return out

    def create_group(self, body: dict[str, Any]) -> dict[str, Any]:
        self._check()
        name = str(body.get("displayName") or "").strip()
        if not name:
            raise ScimError(400, "displayName is required", "invalidValue")
        with self._tx():
            st = self._load()
            if any(g["name"].lower() == name.lower() for g in st["groups"].values()):
                raise ScimError(409, f"group {name} already exists", "uniqueness")
            gid = uuid.uuid4().hex
            st["groups"][gid] = {"name": name, "external_id": body.get("externalId"),
                                 "members": self._members(st, body.get("members")), "v": 1}
            roles = [x.role for x in self.engine._people_base.scim.grants(name)]
            self._save(st, "scim_group_created", {"id": gid, "name": name, "roles": roles})
        return _group_resource(gid, st["groups"][gid], st["users"], self.base_url)

    def replace_group(self, gid: str, body: dict[str, Any]) -> dict[str, Any]:
        self._check()
        with self._tx():
            st = self._load()
            g = st["groups"].get(gid)
            if g is None:
                raise ScimError(404, f"group {gid} not found")
            g["name"] = str(body.get("displayName") or g["name"])
            g["members"] = self._members(st, body.get("members"))
            g["v"] += 1
            self._save(st, "scim_group_updated", {"id": gid, "name": g["name"], "members": len(g["members"])})
        return _group_resource(gid, g, st["users"], self.base_url)

    def patch_group(self, gid: str, body: dict[str, Any]) -> dict[str, Any]:
        self._check()
        with self._tx():
            st = self._load()
            g = st["groups"].get(gid)
            if g is None:
                raise ScimError(404, f"group {gid} not found")
            for op in body.get("Operations") or []:
                kind = str(op.get("op", "")).lower()
                path, value = str(op.get("path") or ""), op.get("value")
                if path == "displayName" or (not path and isinstance(value, dict) and "displayName" in value):
                    g["name"] = str(value if path else value["displayName"])
                    continue
                m = re.fullmatch(r'members\[value eq "([^"]+)"\]', path)
                if kind == "remove" and m:
                    g["members"] = [x for x in g["members"] if x != m.group(1)]
                elif kind == "remove" and path == "members":
                    drop = set(self._members(st, value)) if value else set(g["members"])
                    g["members"] = [x for x in g["members"] if x not in drop]
                elif kind in ("add", "replace") and (path == "members" or (not path and isinstance(value, dict))):
                    raw = value.get("members") if (not path and isinstance(value, dict)) else value
                    new = self._members(st, raw)
                    g["members"] = new if kind == "replace" else [*g["members"],
                                                                  *[x for x in new if x not in g["members"]]]
                else:
                    raise ScimError(400, f"unsupported group operation {op}", "invalidPath")
            g["v"] += 1
            self._save(st, "scim_group_updated", {"id": gid, "name": g["name"], "members": len(g["members"])})
        return _group_resource(gid, g, st["users"], self.base_url)

    def delete_group(self, gid: str) -> None:
        self._check()
        with self._tx():
            st = self._load()
            g = st["groups"].pop(gid, None)
            if g is None:
                raise ScimError(404, f"group {gid} not found")
            self._save(st, "scim_group_removed", {"id": gid, "name": g["name"]})


def mount(app: Any, engine: Engine, tokens_ok: Any) -> None:
    """Add /scim/v2 to a FastAPI app. ``tokens_ok(token) -> bool`` accepts a service token named scim."""
    import hmac

    from . import envsecrets
    r = APIRouter(prefix="/scim/v2")
    svc = Scim(engine)

    def auth(authorization: str) -> None:
        scheme, _, tok = authorization.partition(" ")
        if scheme.lower() != "bearer" or not tok:
            raise ScimError(401, "missing bearer token")
        tenant = envsecrets.TENANT.get()
        name = (envsecrets.tenant_prefixes(tenant)[0] if tenant else "SENTINEL_SECRET_") + "SCIM_TOKEN"
        want = envsecrets.get(name, "scim")
        if want and hmac.compare_digest(want.encode(), tok.encode()):
            return
        if tokens_ok(tok):
            return
        raise ScimError(401, "unknown token")

    def run(authorization: str, fn: Any, *args: Any, status: int = 200) -> Response:
        try:
            auth(authorization)
            out = fn(*args)
        except ScimError as e:
            return JSONResponse(e.body(), status_code=e.status, media_type="application/scim+json")
        if out is None:
            return Response(status_code=204)
        return JSONResponse(out, status_code=status, media_type="application/scim+json")

    async def body(req: Request) -> dict[str, Any]:
        try:
            data = await req.json()
        except Exception:  # noqa: BLE001
            data = None
        return data if isinstance(data, dict) else {}

    @r.get("/ServiceProviderConfig")
    def spc(authorization: str = Header(default="")) -> Response:
        return run(authorization, lambda: {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
            "patch": {"supported": True}, "bulk": {"supported": False, "maxOperations": 0, "maxPayloadSize": 0},
            "filter": {"supported": True, "maxResults": 200}, "changePassword": {"supported": False},
            "sort": {"supported": False}, "etag": {"supported": False},
            "authenticationSchemes": [{"type": "oauthbearertoken", "name": "Bearer token", "primary": True,
                                       "description": "A bearer token set on the Sentinel site"}]})

    @r.get("/Users")
    def users(authorization: str = Header(default=""), filter: str | None = None,  # noqa: A002
              startIndex: int = 1, count: int = 100) -> Response:  # noqa: N803
        return run(authorization, svc.list_users, filter, startIndex, min(count, 200))

    @r.post("/Users")
    async def create_user(req: Request, authorization: str = Header(default="")) -> Response:
        return await run_in_threadpool(run, authorization, svc.create_user, await body(req), status=201)

    @r.get("/Users/{sid}")
    def get_user(sid: str, authorization: str = Header(default="")) -> Response:
        return run(authorization, svc.get_user, sid)

    @r.put("/Users/{sid}")
    async def put_user(sid: str, req: Request, authorization: str = Header(default="")) -> Response:
        return await run_in_threadpool(run, authorization, svc.replace_user, sid, await body(req))

    @r.patch("/Users/{sid}")
    async def patch_user(sid: str, req: Request, authorization: str = Header(default="")) -> Response:
        return await run_in_threadpool(run, authorization, svc.patch_user, sid, await body(req))

    @r.delete("/Users/{sid}")
    def delete_user(sid: str, authorization: str = Header(default="")) -> Response:
        return run(authorization, svc.delete_user, sid)

    @r.get("/Groups")
    def groups(authorization: str = Header(default=""), filter: str | None = None,  # noqa: A002
               startIndex: int = 1, count: int = 100) -> Response:  # noqa: N803
        return run(authorization, svc.list_groups, filter, startIndex, min(count, 200))

    @r.post("/Groups")
    async def create_group(req: Request, authorization: str = Header(default="")) -> Response:
        return await run_in_threadpool(run, authorization, svc.create_group, await body(req), status=201)

    @r.get("/Groups/{gid}")
    def get_group(gid: str, authorization: str = Header(default="")) -> Response:
        return run(authorization, svc.get_group, gid)

    @r.put("/Groups/{gid}")
    async def put_group(gid: str, req: Request, authorization: str = Header(default="")) -> Response:
        return await run_in_threadpool(run, authorization, svc.replace_group, gid, await body(req))

    @r.patch("/Groups/{gid}")
    async def patch_group(gid: str, req: Request, authorization: str = Header(default="")) -> Response:
        return await run_in_threadpool(run, authorization, svc.patch_group, gid, await body(req))

    @r.delete("/Groups/{gid}")
    def delete_group(gid: str, authorization: str = Header(default="")) -> Response:
        return run(authorization, svc.delete_group, gid)

    app.include_router(r)
