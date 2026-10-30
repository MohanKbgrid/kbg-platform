# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""Keys entered in the console: encrypted, per tenant, applied to connectors at once, audited."""
from __future__ import annotations

import io
import json

import pytest

pytest.importorskip("cryptography")

from sentinel import connectors as ct  # noqa: E402
from sentinel import envsecrets, secretstore  # noqa: E402
from sentinel.config import dump_yaml  # noqa: E402
from sentinel.secretstore import SecretStoreError, decrypt, encrypt, new_master_key, required  # noqa: E402


@pytest.fixture(autouse=True)
def master(monkeypatch):
    monkeypatch.setenv("SENTINEL_MASTER_KEY", new_master_key())
    yield
    envsecrets._STORED.clear()


def _publish_shiprocket(eng):
    cv, _ = eng.save_config("connectors", dump_yaml(ct.merge({}, "shiprocket")), "mohan")
    eng.publish_config(cv.id, actor="mohan")


def test_encryption_is_bound_to_name_and_tenant():
    blob = encrypt("SENTINEL_SECRET_X", "s3cret-value", None)
    assert "s3cret" not in blob and decrypt("SENTINEL_SECRET_X", blob, None) == "s3cret-value"
    with pytest.raises(SecretStoreError):
        decrypt("SENTINEL_SECRET_Y", blob, None)                    # moved to another name
    with pytest.raises(SecretStoreError):
        decrypt("SENTINEL_SECRET_X", blob, "acme")                  # another tenant's key


def test_keys_wait_then_apply_everywhere(engine_factory, monkeypatch):
    monkeypatch.delenv("SENTINEL_SECRET_SHIPROCKET_EMAIL", raising=False)
    eng = engine_factory()
    _publish_shiprocket(eng)
    keys = {k["name"]: k for k in required(eng)}
    assert keys["SENTINEL_SECRET_SHIPROCKET_EMAIL"]["source"] == "missing"
    assert "API user" in keys["SENTINEL_SECRET_SHIPROCKET_EMAIL"]["description"]
    assert "connectors: shiprocket" in " ".join(keys["SENTINEL_SECRET_SHIPROCKET_EMAIL"]["used_by"])
    other = engine_factory(store=eng.store)                          # a second process
    meta = eng.set_secret("SENTINEL_SECRET_SHIPROCKET_EMAIL", "ops@acme.in", "mohan")
    assert meta["hint"] == "e.in" and envsecrets.lookup("SENTINEL_SECRET_SHIPROCKET_EMAIL") == "ops@acme.in"
    raw = json.dumps(eng.store.get_source_state("__secret__:SENTINEL_SECRET_SHIPROCKET_EMAIL"))
    assert "ops@acme.in" not in raw                                  # encrypted at rest
    envsecrets._STORED.clear()
    assert "secrets" in other.sync_config()                          # picked up, connectors rebuilt
    assert envsecrets.source("SENTINEL_SECRET_SHIPROCKET_EMAIL") == "console"
    monkeypatch.setenv("SENTINEL_SECRET_SHIPROCKET_EMAIL", "env@acme.in")
    assert envsecrets.lookup("SENTINEL_SECRET_SHIPROCKET_EMAIL") == "ops@acme.in"   # the console wins
    assert eng.clear_secret("SENTINEL_SECRET_SHIPROCKET_EMAIL", "mohan")
    assert envsecrets.lookup("SENTINEL_SECRET_SHIPROCKET_EMAIL") == "env@acme.in"
    kinds = [a["kind"] for a in eng.store.audit_log()]
    assert "secret_set" in kinds and "secret_cleared" in kinds
    with pytest.raises(SecretStoreError, match="SENTINEL_SECRET_"):
        eng.set_secret("ANTHROPIC_API_KEY", "x" * 20, "mohan")       # never the server's own secrets


def test_rbac_and_no_master_key(engine_factory, monkeypatch):
    from sentinel import AuthorizationError, Guardrails
    from tests.test_rbac import make_directory
    eng = engine_factory(directory=make_directory(), guardrails=Guardrails())
    with pytest.raises(AuthorizationError):
        eng.set_secret("SENTINEL_SECRET_A", "value-1234", "ravi")
    monkeypatch.delenv("SENTINEL_MASTER_KEY")
    assert not secretstore.available()


def test_console_api_and_cli(engine_factory, tmp_path, monkeypatch, capsys):
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from sentinel.api import Principal, create_app, token_hash
    from sentinel.cli import main
    eng = engine_factory()
    _publish_shiprocket(eng)
    c = TestClient(create_app(eng, {token_hash("p"): Principal("person", "hari")}))
    h = {"Authorization": "Bearer p"}
    got = c.get("/console/api/secrets", headers=h).json()
    assert got["can_store"] and got["logins"] == ["shiprocket"]
    r = c.put("/console/api/secrets/SENTINEL_SECRET_SHIPROCKET_PASSWORD", headers=h, json={"value": "pw-12345678"})
    assert r.status_code == 200 and r.json()["hint"] == "5678"
    row = next(k for k in c.get("/console/api/secrets", headers=h).json()["keys"]
               if k["name"] == "SENTINEL_SECRET_SHIPROCKET_PASSWORD")
    assert row["source"] == "console" and "pw-1234" not in json.dumps(row)
    assert c.put("/console/api/secrets/DATABASE_URL", headers=h, json={"value": "x" * 10}).status_code == 400
    assert c.post("/console/api/secrets/test/shiprocket", headers=h, json={}).json()["ok"] is False
    assert main(["new-master-key"]) == 0
    assert len(json.loads(capsys.readouterr().out)["SENTINEL_MASTER_KEY"]) >= 43
    base = ["--overlay", "tests.test_templates_cli:_overlay", "--db", str(tmp_path / "s.db")]
    monkeypatch.setattr("sys.stdin", io.StringIO("tok-abcdefgh\n"))
    assert main([*base, "secret", "set", "SENTINEL_SECRET_DELHIVERY_TOKEN", "--by", "mohan"]) == 0
    capsys.readouterr()
    assert main([*base, "secret", "list"]) == 0
    listed = json.loads(capsys.readouterr().out)
    row = next(x for x in listed if x["name"] == "SENTINEL_SECRET_DELHIVERY_TOKEN")
    assert row["hint"] == "efgh" and row["source"] == "console"
    assert next(x for x in listed if x["name"] == "SENTINEL_SECRET_AUDIT_KEY")["platform"] is True
