# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""CloudEvents 1.0 on /v1/cloudevents: structured and binary mode, same auth/size/idempotency as /v1/events."""
from __future__ import annotations

import base64
import json
from datetime import datetime, UTC

import pytest

from sentinel import cloudevents as ce
from sentinel.cloudevents import CloudEventError

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from sentinel import Guardrails  # noqa: E402
from sentinel.api import Principal, create_app, token_hash  # noqa: E402
from tests.conftest import job_event  # noqa: E402
from tests.test_rbac import make_directory  # noqa: E402

TOKENS = {"svc-token": Principal("service", "ingest"), "ravi-token": Principal("person", "ravi")}
STRUCTURED = {"Content-Type": "application/cloudevents+json", "Authorization": "Bearer svc-token"}


def good(**over):
    d = {"specversion": "1.0", "id": "evt-1001", "source": "https://acme.example/scheduler", "type": "job.failed",
         "time": "2026-10-30T09:15:00Z", "subject": "J1", "datacontenttype": "application/json",
         "data": {"system": "billing", "error_code": "TIMEOUT", "ref": "J1"}}
    d.update(over)
    return {k: v for k, v in d.items() if v is not None}


def binary_headers(**over):
    h = {"ce-specversion": "1.0", "ce-id": "evt-2001", "ce-source": "https://acme.example/scheduler",
         "ce-type": "job.failed", "ce-time": "2026-10-30T09:15:00+05:30", "Content-Type": "application/json",
         "Authorization": "Bearer svc-token"}
    h.update(over)
    return {k: v for k, v in h.items() if v is not None}


@pytest.fixture
def api(engine_factory, overlay):
    eng = engine_factory(ov=overlay, directory=make_directory(), guardrails=Guardrails())
    app = create_app(eng, {token_hash(k): v for k, v in TOKENS.items()}, ingest_per_minute=1000)
    return eng, TestClient(app)


# ---- the mapping, without HTTP -------------------------------------------------------------------------

def test_structured_maps_every_attribute():
    ev = ce.parse({"Content-Type": "application/cloudevents+json; charset=utf-8"},
                  json.dumps(good(tenant="acme", correlationid="c-9")).encode())
    assert ev.idempotency_key == "evt-1001" and ev.type == "job.failed"
    assert ev.source == "https://acme.example/scheduler" and ev.tenant == "acme" and ev.correlation_id == "c-9"
    assert ev.occurred_at == datetime(2026, 10, 30, 9, 15, tzinfo=UTC)
    assert ev.payload == {"system": "billing", "error_code": "TIMEOUT", "ref": "J1", "ce_subject": "J1"}


def test_binary_maps_every_attribute_and_decodes_header_values():
    ev = ce.parse(binary_headers(**{"ce-subject": "order%2042", "ce-tenant": "acme"}),
                  b'{"system": "billing", "ref": "J1"}')
    assert ev.idempotency_key == "evt-2001" and ev.tenant == "acme"
    assert ev.occurred_at.utcoffset().total_seconds() == 5.5 * 3600
    assert ev.payload == {"system": "billing", "ref": "J1", "ce_subject": "order 42"}


def test_non_object_and_base64_data():
    assert ce.parse(STRUCTURED, json.dumps(good(data=[1, 2])).encode()).payload["value"] == [1, 2]
    b64 = base64.b64encode(b'{"a": 1}').decode()
    ev = ce.parse(STRUCTURED, json.dumps(good(data=None, data_base64=b64)).encode())
    assert ev.payload["a"] == 1
    assert ce.parse(STRUCTURED, json.dumps(good(data=None)).encode()).payload == {"ce_subject": "J1"}
    both = good(data_base64=b64)
    with pytest.raises(CloudEventError, match="mutually exclusive"):
        ce.parse(STRUCTURED, json.dumps(both).encode())


@pytest.mark.parametrize("missing", ["id", "source", "type", "specversion"])
def test_missing_required_attribute_is_refused_in_both_modes(missing):
    with pytest.raises(CloudEventError, match=missing):
        ce.parse(STRUCTURED, json.dumps(good(**{missing: None})).encode())
    with pytest.raises(CloudEventError, match=missing):
        ce.parse(binary_headers(**{f"ce-{missing}": None}), b"{}")


@pytest.mark.parametrize("bad", [good(specversion="0.3"), good(id=""), good(id=7), good(time="yesterday"),
                                 good(time="2026-10-30T09:15:00"), good(type="  "), good(source="x" * 2000)])
def test_malformed_attributes_are_400(bad):
    with pytest.raises(CloudEventError) as e:
        ce.parse(STRUCTURED, json.dumps(bad).encode())
    assert e.value.status == 400


def test_unsupported_shapes_are_415_or_400():
    with pytest.raises(CloudEventError) as e:
        ce.parse({"Content-Type": ce.BATCH}, b"[]")
    assert e.value.status == 415
    with pytest.raises(CloudEventError) as e:
        ce.parse({"Content-Type": "application/json"}, b"{}")          # not a CloudEvent at all
    assert e.value.status == 415
    with pytest.raises(CloudEventError) as e:
        ce.parse(binary_headers(**{"Content-Type": "image/png"}), b"\x89PNG")
    assert e.value.status == 415
    with pytest.raises(CloudEventError):
        ce.parse(STRUCTURED, b"[1]")
    with pytest.raises(CloudEventError):
        ce.parse(STRUCTURED, b"\xff\xfe")


# ---- over HTTP: auth, idempotency, size, and the old format -------------------------------------------------

def test_structured_over_http_and_duplicate_id(api):
    eng, c = api
    r = c.post("/v1/cloudevents", content=json.dumps(good()), headers=STRUCTURED)
    assert r.status_code == 200 and r.json()["status"] == "new"
    again = c.post("/v1/cloudevents", content=json.dumps(good()), headers=STRUCTURED)
    assert again.status_code == 200 and again.json()["status"] == "duplicate"
    other = c.post("/v1/cloudevents", content=json.dumps(good(id="evt-1002")), headers=STRUCTURED)
    assert other.json()["status"] in ("new", "grouped")


def test_binary_over_http_and_duplicate_id(api):
    eng, c = api
    body = json.dumps({"system": "billing", "error_code": "AUTH", "ref": "J7"})
    r = c.post("/v1/cloudevents", content=body, headers=binary_headers())
    assert r.status_code == 200 and r.json()["status"] == "new"
    assert c.post("/v1/cloudevents", content=body, headers=binary_headers()).json()["status"] == "duplicate"


def test_a_binary_and_a_structured_event_with_one_id_are_one_event(api):
    eng, c = api
    one = c.post("/v1/cloudevents", content=json.dumps(good(id="same")), headers=STRUCTURED)
    two = c.post("/v1/cloudevents", content=b"{}", headers=binary_headers(**{"ce-id": "same"}))
    assert one.json()["status"] == "new" and two.json()["status"] == "duplicate"


def test_http_errors_are_clear_4xx(api):
    eng, c = api
    r = c.post("/v1/cloudevents", content=json.dumps(good(id=None)), headers=STRUCTURED)
    assert r.status_code == 400 and "id" in r.json()["detail"]
    r = c.post("/v1/cloudevents", content=b"{}", headers={"Authorization": "Bearer svc-token",
                                                          "Content-Type": "application/json"})
    assert r.status_code == 415
    r = c.post("/v1/cloudevents", content=b"{not json", headers=STRUCTURED)
    assert r.status_code == 400


def test_same_auth_as_events(api):
    eng, c = api
    body = json.dumps(good())
    assert c.post("/v1/cloudevents", content=body,
                  headers={"Content-Type": "application/cloudevents+json"}).status_code == 401
    assert c.post("/v1/cloudevents", content=body, headers={**STRUCTURED, "Authorization": "Bearer nope"}
                  ).status_code == 401
    assert c.post("/v1/cloudevents", content=body, headers={**STRUCTURED, "Authorization": "Bearer ravi-token"}
                  ).status_code == 403                                      # people don't ingest


def test_size_caps_apply(api):
    eng, c = api
    big = good(data={"blob": "x" * (eng.max_event_bytes + 10)})
    assert c.post("/v1/cloudevents", content=json.dumps(big), headers=STRUCTURED).status_code == 413
    huge = json.dumps(good(data={"blob": "x" * (5 * eng.max_event_bytes)}))
    assert c.post("/v1/cloudevents", content=huge, headers=STRUCTURED).status_code == 413    # the body cap


def test_the_old_format_still_works(api):
    eng, c = api
    ev = job_event(error="AUTH").model_dump(mode="json")
    r = c.post("/v1/events", json=ev, headers={"Authorization": "Bearer svc-token"})
    assert r.status_code == 200 and r.json()["status"] == "new"
