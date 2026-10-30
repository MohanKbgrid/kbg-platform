# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""Datasets from connectors: the same finance columns read from Zoho Books (JSON, paged, OAuth) or Tally
(XML), through each connector's own lookups and a column mapping in configuration. No system is in code."""
from __future__ import annotations

import json
import threading
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

import pytest
import yaml

from sentinel import connectors
from sentinel.config import dump_yaml
from sentinel.kpi import KpiError

pytest.importorskip("duckdb")

NOW = datetime(2026, 10, 10, 9, 0, tzinfo=UTC)


def _day(d: int) -> str:
    return (NOW - timedelta(days=d)).date().isoformat()


ZOHO_TXNS = [{"transaction_id": f"T{i}", "date": _day(i % 10), "amount": 1000.0 + i, "account_name": "HDFC Current",
              "debit_or_credit": "credit" if i % 2 else "debit", "reference_number": f"UTR{i}",
              "status": "uncategorized" if i in (3, 13) else ("excluded" if i == 7 else "categorized"),
              "offset_account_name": "" if i in (3, 13) else "Sales"} for i in range(25)]
TALLY = """<ENVELOPE><BODY><DATA><COLLECTION>
<VOUCHER VCHTYPE="Receipt"><DATE>{d1}</DATE><GUID>g1</GUID><VOUCHERNUMBER>R-1</VOUCHERNUMBER><VOUCHERTYPENAME>Receipt</VOUCHERTYPENAME>
 <ALLLEDGERENTRIES.LIST><LEDGERNAME>HDFC Bank</LEDGERNAME><AMOUNT>-5000.00</AMOUNT>
   <BANKALLOCATIONS.LIST><BANKERSDATE>{d1}</BANKERSDATE><INSTRUMENTNUMBER>UTR9</INSTRUMENTNUMBER></BANKALLOCATIONS.LIST></ALLLEDGERENTRIES.LIST>
 <ALLLEDGERENTRIES.LIST><LEDGERNAME>Customer A</LEDGERNAME><AMOUNT>5000.00</AMOUNT></ALLLEDGERENTRIES.LIST></VOUCHER>
<VOUCHER VCHTYPE="Payment"><DATE>{d5}</DATE><GUID>g2</GUID><VOUCHERNUMBER>P-1</VOUCHERNUMBER><VOUCHERTYPENAME>Payment</VOUCHERTYPENAME>
 <ALLLEDGERENTRIES.LIST><LEDGERNAME>HDFC Bank</LEDGERNAME><AMOUNT>1200.00</AMOUNT>
   <BANKALLOCATIONS.LIST><BANKERSDATE/><INSTRUMENTNUMBER>CHQ1</INSTRUMENTNUMBER></BANKALLOCATIONS.LIST></ALLLEDGERENTRIES.LIST>
 <ALLLEDGERENTRIES.LIST><LEDGERNAME>Vendor B</LEDGERNAME><AMOUNT>-1200.00</AMOUNT></ALLLEDGERENTRIES.LIST></VOUCHER>
<VOUCHER VCHTYPE="Sales"><DATE>{d1}</DATE><GUID>g3</GUID><VOUCHERNUMBER>S-7</VOUCHERNUMBER><VOUCHERTYPENAME>Sales</VOUCHERTYPENAME>
 <ALLLEDGERENTRIES.LIST><LEDGERNAME>Customer A</LEDGERNAME><AMOUNT>-2360.00</AMOUNT></ALLLEDGERENTRIES.LIST></VOUCHER>
<VOUCHER VCHTYPE="Sales"><DATE>{d1}</DATE><GUID>g4</GUID><VOUCHERNUMBER>S-7</VOUCHERNUMBER><VOUCHERTYPENAME>Sales</VOUCHERTYPENAME>
 <ALLLEDGERENTRIES.LIST><LEDGERNAME>Customer C</LEDGERNAME><AMOUNT>-1180.00</AMOUNT></ALLLEDGERENTRIES.LIST></VOUCHER>
</COLLECTION></DATA></BODY></ENVELOPE>""".format(d1=(NOW - timedelta(days=1)).strftime("%Y%m%d"),
                                              d5=(NOW - timedelta(days=5)).strftime("%Y%m%d"))
TALLY_BANKS = """<ENVELOPE><BODY><DATA><COLLECTION>
<LEDGER NAME="HDFC Bank"><PARENT>Bank Accounts</PARENT><CLOSINGBALANCE>-6000000.00</CLOSINGBALANCE></LEDGER>
<LEDGER NAME="ICICI Bank"><PARENT>Bank Accounts</PARENT><CLOSINGBALANCE>-1500000.00</CLOSINGBALANCE></LEDGER>
</COLLECTION></DATA></BODY></ENVELOPE>"""


@pytest.fixture
def fake():
    seen: list[str] = []

    class H(BaseHTTPRequestHandler):
        def _send(self, body, ctype="application/json"):
            data = body.encode() if isinstance(body, str) else json.dumps(body).encode()
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):  # noqa: N802
            u = urlparse(self.path)
            q = {k: v[0] for k, v in parse_qs(u.query).items()}
            seen.append(self.path)
            if u.path.endswith("/banktransactions"):
                page, per = int(q["page"]), 10                  # pages of 10 here
                return self._send({"code": 0, "banktransactions": ZOHO_TXNS[(page - 1) * per: page * per]})
            if u.path.endswith("/bankaccounts"):
                return self._send({"code": 0, "bankaccounts": [
                    {"account_name": "HDFC Current", "account_type": "bank", "balance": 5200000.0},
                    {"account_name": "Petty cash", "account_type": "cash", "balance": 50000.0},
                    {"account_name": "Amex", "account_type": "credit_card", "balance": -80000.0}]})
            if u.path.endswith("/invoices"):
                return self._send({"code": 0, "invoices": [
                    {"invoice_id": "I1", "invoice_number": "INV-1", "date": _day(2), "total": 2360, "status": "paid"},
                    {"invoice_id": "I2", "invoice_number": "INV-1", "date": _day(1), "total": 1180, "status": "sent"},
                    {"invoice_id": "I3", "invoice_number": "INV-2", "date": _day(1), "total": 900, "status": "void"}]})
            self.send_response(404)
            self.end_headers()

        def do_POST(self):  # noqa: N802
            n = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(n).decode()
            seen.append(f"POST {self.path} {raw[:200]}")
            if "oauth" in self.path:
                return self._send({"access_token": "tok", "expires_in": 3600})
            return self._send(TALLY_BANKS if "SentinelBanks" in raw else TALLY, "text/xml")

        def log_message(self, *a):
            pass
    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_port}", seen
    srv.shutdown()


METRICS = {
    "datasets": {"bank_lines": {"kind": "overlay", "name": "x", "owner": "lead"},
                 "cash_position": {"kind": "overlay", "name": "x", "vars": {"monthly_burn": 500000}},
                 "invoices": {"kind": "overlay", "name": "x"}},
    "metrics": {
        "recon_breaks": {"title": "Recon breaks", "dataset": "bank_lines", "time": "booked_at",
                         "value": "sum(case when not matched and age_hours > 48 then 1 else 0 end)",
                         "dimensions": ["account"], "target": {"lte": 0}},
        "cash_months": {"title": "Months of cash", "dataset": "cash_position", "time": "as_of",
                        "value": "sum(balance) / nullif(sum(burn_share), 0)", "target": {"gte": 12}},
        "dup_invoices": {"title": "Invoice numbers twice", "dataset": "invoices", "time": "dispatched_at",
                         "value": "count(invoice_no) - count(distinct invoice_no)", "target": {"lte": 0}},
    },
}


def _engine(engine_factory, clock, name, base, monkeypatch, tweak=None):
    clock.now = NOW
    text = json.dumps(connectors.merge({}, name)).replace("https://www.zohoapis.in", base).replace(
        "https://accounts.zoho.in", base)
    eng = engine_factory()
    cv, probs = eng.save_config("connectors", dump_yaml(json.loads(text)), "hari")
    assert not [p for p in probs if p.severity == "error"], probs
    eng.publish_config(cv.id, "hari")
    doc = connectors.with_datasets(METRICS, name)
    if tweak:
        tweak(doc)
    cv, probs = eng.save_config("metrics", yaml.safe_dump(doc), "hari")
    assert not [p for p in probs if p.severity == "error" or "not available" in p.message], probs
    eng.publish_config(cv.id, "hari")
    return eng, doc


def test_zoho_books_through_its_own_lookups(engine_factory, clock, fake, monkeypatch):
    base, seen = fake
    for k in ("CLIENT_ID", "CLIENT_SECRET", "REFRESH_TOKEN", "ORG_ID"):
        monkeypatch.setenv(f"SENTINEL_SECRET_ZOHO_{k}", "x")
    def small_pages(doc):
        doc["datasets"]["bank_lines"]["pages"]["size"] = 10            # the fake server pages by 10, Zoho by 200
    eng, doc = _engine(engine_factory, clock, "zoho-books", base, monkeypatch, small_pages)
    assert doc["datasets"]["bank_lines"]["owner"] == "lead"                    # the business's owner is kept
    assert doc["datasets"]["cash_position"]["vars"] == {"monthly_burn": 500000}
    r = eng.kpi.query("recon_breaks", by=["account"], days=30)
    assert r["total"]["value"] == 2 and r["rows"][0]["account"] == "HDFC Current"   # T3 and T13 (T7 excluded)
    assert eng.kpi.counts["bank_lines"] == 24 and r["trusted"] is True
    assert sum("/banktransactions" in s for s in seen) == 3                       # 10 + 10 + 5: then it stops
    assert eng.kpi.query("cash_months", days=1)["total"]["value"] == pytest.approx(10.5)   # bank + cash only
    assert eng.kpi.query("dup_invoices", days=30)["total"]["value"] == 1          # INV-1 twice; the void one out


def test_tally_through_its_own_xml_lookups(engine_factory, clock, fake, monkeypatch):
    base, seen = fake
    monkeypatch.setenv("SENTINEL_SECRET_TALLY_URL", f"{base}/tally")
    monkeypatch.setenv("SENTINEL_SECRET_TALLY_COMPANY", "Acme Home & Co")
    eng, _ = _engine(engine_factory, clock, "tally", base, monkeypatch)
    rows = eng.kpi.rows("bank_lines")
    assert [(r["account"], r["direction"], r["amount"], r["matched"]) for r in rows] == [
        ("HDFC Bank", "credit", 5000.0, True), ("HDFC Bank", "debit", 1200.0, False)]
    assert eng.kpi.query("recon_breaks", days=30)["total"]["value"] == 1          # the cheque not yet in the bank
    assert eng.kpi.query("cash_months", days=1)["total"]["value"] == pytest.approx(15.0)
    assert eng.kpi.query("dup_invoices", days=30)["total"]["value"] == 1          # S-7 twice
    assert any("Acme Home &amp; Co" in s for s in seen)                          # company escaped into the XML


def test_a_mapping_can_mix_systems_and_says_what_is_missing(engine_factory, clock, fake, monkeypatch):
    doc = connectors.with_datasets(METRICS, {"bank_lines": "tally", "invoices": "zoho-books"})
    assert doc["datasets"]["bank_lines"]["lookup"] == "tally.vouchers"
    assert doc["datasets"]["invoices"]["lookup"] == "zoho.invoices"
    assert doc["datasets"]["cash_position"]["kind"] == "overlay"
    with pytest.raises(KeyError, match="has no dataset"):
        connectors.with_datasets(METRICS, {"settlements": "tally"})
    eng = engine_factory()
    _, probs = eng.check_config("metrics", yaml.safe_dump(doc))
    assert any("not available yet" in p.message for p in probs)                   # its connector is not added
    from sentinel.kpi import Warehouse, parse
    with pytest.raises(KpiError, match="not available"):
        Warehouse(eng, parse(doc)).query("recon_breaks")
