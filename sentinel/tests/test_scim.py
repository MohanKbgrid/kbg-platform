# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""SCIM 2.0 provisioning with group -> role mapping."""
from __future__ import annotations

import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from sentinel import Guardrails  # noqa: E402
from sentinel.api import Principal, create_app, token_hash  # noqa: E402
from sentinel.rbac import Person, ScimSettings  # noqa: E402
from tests.test_rbac import make_directory  # noqa: E402

H = {"Authorization": "Bearer scim-secret"}


def _setup(engine_factory, monkeypatch, **kw):
    monkeypatch.setenv("SENTINEL_SECRET_SCIM_TOKEN", "scim-secret")
    d = make_directory()
    d.people["asha"] = Person(id="asha", contact={"email": "asha@acme.in"})
    d.scim = ScimSettings(group_roles={"Ops Leads": ["lead"], "Ops South": [{"role": "ops",
                                                                             "scope": {"system": "billing"}}]},
                          default_roles=["operator"])
    eng = engine_factory(directory=d, guardrails=Guardrails(), **kw)
    return eng, TestClient(create_app(eng, {token_hash("svc"): Principal("service", "scim")}, console=False))


def test_users_and_groups_give_roles(engine_factory, monkeypatch):
    eng, c = _setup(engine_factory, monkeypatch)
    assert c.get("/scim/v2/Users", headers={"Authorization": "Bearer nope"}).status_code == 401
    assert c.get("/scim/v2/ServiceProviderConfig", headers={"Authorization": "Bearer svc"}).status_code == 200
    r = c.post("/scim/v2/Users", headers=H, json={
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"], "userName": "priya.k@acme.in",
        "name": {"givenName": "Priya", "familyName": "K"}, "emails": [{"value": "Priya.K@acme.in", "primary": True}],
        "active": True, "externalId": "aad-1"})
    assert r.status_code == 201
    priya = r.json()
    assert priya["sentinelPersonId"] == "priya.k" and priya["displayName"] == "Priya K"
    assert c.post("/scim/v2/Users", headers=H, json={"userName": "priya.k@acme.in"}).status_code == 409
    assert eng.directory.roles_of("priya.k") == {"operator"}                 # default role
    assert eng.directory.people["priya.k"].contact["email"] == "priya.k@acme.in"

    # the existing person is matched by email, not duplicated
    asha = c.post("/scim/v2/Users", headers=H, json={"userName": "asha@acme.in"}).json()
    assert asha["sentinelPersonId"] == "asha"

    g = c.post("/scim/v2/Groups", headers=H, json={"displayName": "Ops Leads",
                                                    "members": [{"value": priya["id"]}]}).json()
    assert "lead" in eng.directory.roles_of("priya.k")
    found = c.get('/scim/v2/Users?filter=userName eq "PRIYA.K@acme.in"', headers=H).json()
    assert found["totalResults"] == 1 and found["Resources"][0]["id"] == priya["id"]
    assert c.get('/scim/v2/Groups?filter=displayName eq "Ops Leads"', headers=H).json()["totalResults"] == 1

    s = c.post("/scim/v2/Groups", headers=H, json={"displayName": "Ops South"}).json()
    c.patch(f"/scim/v2/Groups/{s['id']}", headers=H, json={"Operations": [
        {"op": "add", "path": "members", "value": [{"value": asha["id"]}]}]})
    assert {"ops", "lead"} & eng.directory.roles_of("asha", {"system": "billing"})
    assert "ops" in eng.directory.roles_of("asha", {"system": "billing"})
    # remove from a group (Entra's path filter form)
    c.patch(f"/scim/v2/Groups/{g['id']}", headers=H, json={"Operations": [
        {"op": "remove", "path": f'members[value eq "{priya["id"]}"]'}]})
    assert "lead" not in eng.directory.roles_of("priya.k")

    # deactivate (Entra sends "False" as a string)
    c.patch(f"/scim/v2/Users/{priya['id']}", headers=H, json={"Operations": [
        {"op": "Replace", "path": "active", "value": "False"}]})
    assert eng.directory.people["priya.k"].active is False
    assert eng.directory.roles_of("priya.k") == set()
    # removing someone the people configuration also defines keeps them inactive
    assert c.delete(f"/scim/v2/Users/{asha['id']}", headers=H).status_code == 204
    assert eng.directory.people["asha"].active is False
    kinds = [a["kind"] for a in eng.store.audit_log()]
    assert "scim_user_created" in kinds and "scim_group_updated" in kinds and "scim_user_removed" in kinds


def test_other_processes_pick_up_changes_and_config_shows_base(engine_factory, monkeypatch):
    eng, c = _setup(engine_factory, monkeypatch)
    other = engine_factory(store=eng.store, directory=eng._people_base, guardrails=Guardrails())
    c.post("/scim/v2/Users", headers=H, json={"userName": "nila@acme.in"})
    assert "nila" not in other.directory.people
    assert "scim" in other.sync_config()
    assert "nila" in other.directory.people
    assert "nila" not in eng.config_text("people")                   # provisioned people are not config


def test_off_without_settings_and_bad_roles_refused(engine_factory, monkeypatch):
    monkeypatch.setenv("SENTINEL_SECRET_SCIM_TOKEN", "scim-secret")
    eng = engine_factory(directory=make_directory(), guardrails=Guardrails())
    c = TestClient(create_app(eng, {}, console=False))
    r = c.get("/scim/v2/Users", headers=H)
    assert r.status_code == 501 and "scim" in r.json()["detail"]
    _, probs = eng.check_config("people", eng.config_text("people") + "scim: {group_roles: {X: [ghost]}}\n")
    assert any("ghost" in p.message and p.severity == "error" for p in probs)
