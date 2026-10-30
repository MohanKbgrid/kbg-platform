# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""B1: channel and WMS connector templates (Shopify, Amazon SP-API, Flipkart, Ajio/Myntra, WMS) end to end."""
from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

import pytest

from sentinel import connauth, connectors
from sentinel.httpactions import call
from sentinel.mcp import Connectors
from sentinel.sources import parse_sources, run_once


@pytest.fixture
def fake():
    seen = []
    replies = {
        "/admin/api/2025-01/orders.json": {"orders": [{"id": 5001, "name": "#MA1001", "processed_at": "2026-10-09T08:00:00Z",
                                                       "location_id": None}]},
        "/auth/o2/token": {"access_token": "amz-access", "expires_in": 3600},
        "/orders/v0/orders": {"payload": {"Orders": [{"AmazonOrderId": "403-1", "PurchaseDate": "2026-10-09T10:00:00Z",
                                                       "LastUpdateDate": "2026-10-10T01:00:00Z",
                                                       "LatestShipDate": "2026-10-11T18:29:59Z", "IsPrime": False}]}},
        "/oauth-service/oauth/token": {"access_token": "fk-access", "expires_in": 3600},
        "/sellers/v3/shipments/filter": {"shipments": [{"shipmentId": "S1", "orderItems": [
            {"orderItemId": "OI1", "orderId": "OD1", "orderDate": "2026-10-09T09:00:00Z", "sku": "VASE-L",
             "status": "APPROVED", "dispatchByDate": "2026-10-11"}]}]},
        "/orders/X1/priority": {"ok": True},
        "/ajio/orders": {"orders": [{"order_id": "AJ-9", "status": "confirmed", "created_at": "2026-10-09T07:00:00Z",
                                     "updated_at": "2026-10-10T00:00:00Z"}]},
    }

    class H(BaseHTTPRequestHandler):
        def _go(self, method):
            n = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(n)
            u = urlsplit(self.path)
            seen.append((method, u.path, parse_qs(u.query), dict(self.headers), body))
            data = json.dumps(replies.get(u.path, {"ok": True})).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):  # noqa: N802
            self._go("GET")

        def do_POST(self):  # noqa: N802
            self._go("POST")

        def do_PATCH(self):  # noqa: N802
            self._go("PATCH")

        def log_message(self, *a):
            pass
    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}", seen
    srv.shutdown()
    connauth.configure({})


def _local(name, base, hosts):
    text = json.dumps(connectors.merge({}, name))
    for h in hosts:
        text = text.replace(h, base)
    return Connectors(json.loads(text))


def test_shopify_poll(fake, monkeypatch):
    base, seen = fake
    monkeypatch.setenv("SENTINEL_SECRET_SHOPIFY_SHOP", "acme")
    monkeypatch.setenv("SENTINEL_SECRET_SHOPIFY_TOKEN", "shpat_x")
    conn = _local("shopify", base, ["https://{{env.SENTINEL_SECRET_SHOPIFY_SHOP}}.myshopify.com"])
    events, _ = run_once(conn.sources["shopify_unfulfilled"], {})
    assert events[0].type == "order.unfulfilled" and events[0].payload["order_id"] == "#MA1001"
    assert events[0].payload["channel"] == "shopify" and events[0].payload["hours_since_paid"] > 0
    assert seen[-1][3]["X-Shopify-Access-Token"] == "shpat_x"
    assert conn.actions["shopify.hold_fulfillment"].compensate is not None        # reversible


def test_amazon_lwa_and_orders(fake, monkeypatch):
    base, seen = fake
    for k in ("CLIENT_ID", "CLIENT_SECRET", "REFRESH_TOKEN", "SELLER_ID"):
        monkeypatch.setenv(f"SENTINEL_SECRET_AMAZON_{k}", f"v-{k.lower()}")
    conn = _local("amazon-sp", base, ["https://api.amazon.com", "https://sellingpartnerapi-eu.amazon.com"])
    events, st = run_once(conn.sources["amazon_unshipped"], {})
    login = next(s for s in seen if s[1] == "/auth/o2/token")
    assert parse_qs(login[4].decode())["grant_type"] == ["refresh_token"]       # form-encoded LWA login
    orders = next(s for s in seen if s[1] == "/orders/v0/orders")
    assert orders[3]["X-Amz-Access-Token"] == "amz-access" and orders[2]["MarketplaceIds"] == ["A21TJRUUN4KGV"]
    assert events[0].payload["order_id"] == "403-1" and st["cursor"] == "2026-10-10T01:00:00Z"
    act = conn.actions["amazon.set_quantity"]
    call(act, act.request, None, {"sku": "VASE-L", "quantity": 7})
    patch = next(s for s in seen if s[0] == "PATCH")
    assert patch[1] == "/listings/2021-08-01/items/v-seller_id/VASE-L"
    assert json.loads(patch[4])["patches"][0]["value"][0]["quantity"] == 7


def test_flipkart_and_wms_and_ajio(fake, monkeypatch):
    base, seen = fake
    monkeypatch.setenv("SENTINEL_SECRET_FLIPKART_BASIC", "YXBwOnNlY3JldA==")  # gitleaks:allow (test value)
    conn = _local("flipkart", base, ["https://api.flipkart.net"])
    events, _ = run_once(conn.sources["flipkart_pre_dispatch"], {})
    tok = next(s for s in seen if s[1] == "/oauth-service/oauth/token")
    assert tok[0] == "GET" and tok[3]["Authorization"] == "Basic YXBwOnNlY3JldA=="
    assert events[0].payload["order_item_id"] == "OI1" and events[0].payload["dispatch_by"] == "2026-10-11"
    act = conn.actions["flipkart.update_stock"]
    call(act, act.request, None, {"stock": {"VASE-L": {"product_id": "P1", "locations": [{"id": "L1",
                                                                                        "inventory": 4}]}}})
    assert json.loads(seen[-1][4]) == {"VASE-L": {"product_id": "P1", "locations": [{"id": "L1", "inventory": 4}]}}

    monkeypatch.setenv("SENTINEL_SECRET_WMS_URL", base)
    monkeypatch.setenv("SENTINEL_SECRET_WMS_TOKEN", "wms-t")
    wms = Connectors(connectors.merge({}, "wms"))
    act = wms.actions["wms.expedite_pick"]
    assert call(act, act.request, None, {"order_id": "X1"}).ok
    assert call(act, act.compensate, None, {"order_id": "X1"}, undo=True).ok
    assert [json.loads(s[4]) for s in seen if s[1] == "/orders/X1/priority"] == [{"priority": "high"},
                                                                                   {"priority": "normal"}]
    assert wms.actions["wms.cycle_count"].safe

    monkeypatch.setenv("SENTINEL_SECRET_AJIO_URL", f"{base}/ajio")
    monkeypatch.setenv("SENTINEL_SECRET_AJIO_TOKEN", "aj-t")
    src = parse_sources(connectors.load("ajio")["connectors"]["sources"])["ajio_open_orders"]
    events, st = run_once(src, {})
    assert events[0].payload["order_id"] == "AJ-9" and events[0].payload["channel"] == "ajio"
