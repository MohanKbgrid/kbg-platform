# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""The five-minute demo: Sentinel for a made-up retailer, "Acme Retail", on synthetic data.

    python -m sentinel.demo            # then open http://localhost:8080/console

No Docker, no Postgres, no network and no API key. Everything here is invented: the orders, the people,
the "systems" the actions touch (an in-memory object, :class:`AcmeSystems`) and the model, which is a
labelled stub (:class:`StubModel`) that answers from a fixed rule table and never opens a socket.

What it shows, in a few dozen events:

* some cases are handled **automatically** (a paid order stuck past its SLA with stock on the shelf is
  expedited; a timed-out channel sync is retried, fails once, and lands on the second attempt);
* some **wait for a person** (a rejected channel update, an order with no stock, a large stock gap, payments
  with no order), each with a proposal and a reason;
* a person **approves a step up**: three approved proposals earn ``order_stuck_no_stock`` a promotion to the
  model route, which waits for the operations head to approve it (the seeded state leaves it pending, so
  you can approve it in the console);
* one **reversal steps back**: the stub model's stock correction turned out to be wrong, the operations head
  reversed it (the channel figure is restored) and the pattern went back to needing a person.

The data is deterministic: the same events, in the same order, with the same outcomes, on every run.
Starting twice against the same ``--db`` seeds once. Ctrl-C stops the server and removes the temporary
database.
"""
from __future__ import annotations

import argparse
import json
import shutil
import signal
import socket
import sys
import tempfile
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import templates
from .actions import ActionRegistry
from .api import Principal, token_hash
from .engine import Engine
from .models import ActionResult, Decision, DecisionKind, Event, Route
from .overlay import Overlay, load_layers
from .policy import Guardrails, LearningPolicy
from .rbac import Directory, parse_directory
from .store import SQLiteStore
from .tools import ToolRegistry

COMPANY = "Acme Retail"
DEFAULT_PORT = 8080

# ---------------------------------------------------------------------------------------------- people

# (id, display name, role, console token). The tokens are public on purpose: this is a local demo with
# invented people. The server listens on 127.0.0.1 only unless you pass --host.
PEOPLE: list[tuple[str, str, str, str]] = [
    ("nora", "Nora (Fulfilment Executive)", "fulfilment_exec", "demo-nora-fulfilment-exec"),
    ("omar", "Omar (Fulfilment Lead)", "fulfilment_lead", "demo-omar-fulfilment-lead"),
    ("ines", "Ines (Inventory Controller)", "inventory_controller", "demo-ines-inventory"),
    ("tess", "Tess (Finance Ops)", "finance_ops", "demo-tess-finance-ops"),
    ("dev", "Dev (Operations Head)", "ops_head", "demo-dev-ops-head"),
]
TOKENS: dict[str, str] = {pid: tok for pid, _n, _r, tok in PEOPLE}

PLAYBOOK_OVERRIDE = {
    # the template leaves this one to a person with no proposal; the demo gives it a suggested move so a
    # person's approvals can earn it a step up
    "id": "order_stuck_no_stock",
    "set": {
        "playbook": [{"action": "reallocate_order",
                      "params": {"order_id": "{{payload.order_id}}", "to_location": "{{payload.alt_location}}"}}],
        "playbook_disposition": "reallocated",
        "max_route": "llm",
    },
}


def _directory() -> Directory:
    base = templates.load("retail-fulfilment")["people"]
    data = {
        "roles": base["roles"],
        "people": [{"id": pid, "name": name} for pid, name, _r, _t in PEOPLE],
        "assignments": [{"person_id": pid, "role_id": role} for pid, _n, role, _t in PEOPLE],
        "authority": list(base["authority"]),
    }
    # the operations head signs off a model-route promotion, steps a pattern's route, and reverses a decision
    return parse_directory(data, "acme-retail demo people")


# ---------------------------------------------------------------------------------------------- the "systems"

@dataclass
class AcmeSystems:
    """Stands in for Acme's order, warehouse and channel systems. Records everything the actions do."""

    orders: dict[str, dict[str, Any]] = field(default_factory=dict)
    channel_stock: dict[tuple[str, str], float] = field(default_factory=dict)
    synced: set[str] = field(default_factory=set)
    log: list[str] = field(default_factory=list)
    sync_attempts: dict[str, int] = field(default_factory=dict)
    lock: threading.Lock = field(default_factory=threading.Lock)

    def note(self, line: str) -> None:
        with self.lock:
            self.log.append(line)


class StubModel:
    """A clearly-labelled stand-in for a language model. It never touches the network: it answers from a
    fixed table keyed on the case's pattern and returns the same answer for the same case every time."""

    model = "demo-stub (no network, rule table)"

    def __init__(self) -> None:
        self.calls = 0

    def complete(self, system: str, messages: list[dict[str, str]]) -> str:
        self.calls += 1
        try:
            brief = json.loads(messages[0]["content"])
        except (ValueError, KeyError, IndexError):
            return json.dumps({"final": {"action": None, "params": {}, "disposition_code": "no_action",
                                         "confidence": 0.1, "rationale": "Stub model: could not read the case."}})
        pattern = (brief.get("incident") or {}).get("pattern")
        p = ((brief.get("event") or {}).get("payload")) or {}
        if pattern == "stock_drift_small":
            final = {"action": "push_stock_to_channel",
                     "params": {"channel": p.get("channel"), "sku": p.get("sku"), "location": p.get("location")},
                     "disposition_code": "stock_corrected", "confidence": 0.93,
                     "rationale": f"Stub model: the warehouse count ({p.get('warehouse_qty')}) is the book of "
                                  "record; push it to the channel."}
        elif pattern == "order_stuck_no_stock" and p.get("alt_location"):
            final = {"action": "reallocate_order",
                     "params": {"order_id": p.get("order_id"), "to_location": p.get("alt_location")},
                     "disposition_code": "reallocated", "confidence": 0.9,
                     "rationale": f"Stub model: {p.get('alt_location')} has full stock for this order."}
        elif pattern == "order_stuck_in_stock":
            final = {"action": "expedite_pick", "params": {"order_id": p.get("order_id"),
                                                           "location": p.get("location")},
                     "disposition_code": "expedited", "confidence": 0.95,
                     "rationale": "Stub model: stock is on the shelf; move the order to the front of the pick list."}
        else:
            final = {"action": None, "params": {}, "disposition_code": "no_action", "confidence": 0.2,
                     "rationale": "Stub model: no rule for this case. A person should decide."}
        return json.dumps({"final": final})


def _actions(sys_: AcmeSystems) -> ActionRegistry:
    acts = ActionRegistry()

    @acts.action("expedite_pick", reversible=True, params={"order_id": "str", "location": "str"},
                 description="Move an order to the front of the pick list")
    def expedite_pick(ctx, p):
        sys_.orders.setdefault(p["order_id"], {})["expedited"] = True
        sys_.note(f"expedited {p['order_id']} at {p['location']}")
        return ActionResult(ok=True, detail="moved to the front of the pick list")

    @expedite_pick.compensator
    def unexpedite(ctx, p):
        sys_.orders.setdefault(p["order_id"], {})["expedited"] = False
        sys_.note(f"un-expedited {p['order_id']}")
        return ActionResult(ok=True)

    @acts.action("reallocate_order", reversible=True, params={"order_id": "str", "to_location": "str"},
                 description="Move an order to another location that has the stock")
    def reallocate_order(ctx, p):
        o = sys_.orders.setdefault(p["order_id"], {})
        o["previous_location"], o["location"] = o.get("location"), p["to_location"]
        sys_.note(f"reallocated {p['order_id']} to {p['to_location']}")
        return ActionResult(ok=True, detail=f"moved to {p['to_location']}")

    @reallocate_order.compensator
    def unreallocate(ctx, p):
        o = sys_.orders.setdefault(p["order_id"], {})
        o["location"] = o.get("previous_location")
        sys_.note(f"un-reallocated {p['order_id']}")
        return ActionResult(ok=True)

    @acts.action("notify_customer_delay", params={"order_id": "str", "note?": "str"},
                 description="Tell the customer the order is late (cannot be unsent)")
    def notify_customer_delay(ctx, p):
        sys_.note(f"delay notice for {p['order_id']}")
        return ActionResult(ok=True)

    @acts.action("cancel_order", params={"order_id": "str"}, description="Cancel an order (cannot be undone)",
                 max_attempts=1)
    def cancel_order(ctx, p):
        sys_.note(f"cancelled {p['order_id']}")
        return ActionResult(ok=True)

    @acts.action("retry_channel_sync", safe=True, max_attempts=3,
                 params={"channel": "str", "order_id": "str", "operation": "str"},
                 description="Push the order's latest status to the sales channel again")
    def retry_channel_sync(ctx, p):
        n = sys_.sync_attempts[p["order_id"]] = sys_.sync_attempts.get(p["order_id"], 0) + 1
        if p["order_id"] in FLAKY_SYNC and n == 1:
            return ActionResult(ok=False, retryable=True, detail="channel timed out again (attempt 1)")
        sys_.synced.add(p["order_id"])
        sys_.note(f"channel sync for {p['order_id']} landed on attempt {n}")
        return ActionResult(ok=True, detail=f"synced on attempt {n}")

    @acts.action("push_stock_to_channel", reversible=True,
                 params={"channel": "str", "sku": "str", "location": "str"},
                 description="Set the channel's stock figure to the warehouse count")
    def push_stock(ctx, p):
        pl = ctx.event.payload
        sys_.channel_stock[(p["channel"], p["sku"])] = pl["warehouse_qty"]
        sys_.note(f"{p['sku']} on {p['channel']} set to {pl['warehouse_qty']}")
        return ActionResult(ok=True, detail=f"channel now shows {pl['warehouse_qty']}")

    @push_stock.compensator
    def unpush_stock(ctx, p):
        pl = ctx.event.payload
        sys_.channel_stock[(p["channel"], p["sku"])] = pl["channel_qty"]
        sys_.note(f"{p['sku']} on {p['channel']} restored to {pl['channel_qty']}")
        return ActionResult(ok=True, detail=f"channel restored to {pl['channel_qty']}")

    @acts.action("request_cycle_count", safe=True, params={"sku": "str", "location": "str"},
                 description="Ask the warehouse to recount a SKU")
    def request_cycle_count(ctx, p):
        sys_.note(f"cycle count requested for {p['sku']} at {p['location']}")
        return ActionResult(ok=True)

    @acts.action("create_order_from_payment", params={"payment_id": "str"},
                 description="Create the missing order for a captured payment")
    def create_order_from_payment(ctx, p):
        sys_.note(f"order created from {p['payment_id']}")
        return ActionResult(ok=True)

    @acts.action("refund_payment", params={"payment_id": "str", "amount": "float"},
                 description="Refund a captured payment")
    def refund_payment(ctx, p):
        sys_.note(f"refunded {p['amount']} on {p['payment_id']}")
        return ActionResult(ok=True)

    return acts


# a sync that times out on its first attempt: it is retried and lands (the audit shows both attempts)
FLAKY_SYNC = {"AR-10020"}


def _tools(sys_: AcmeSystems) -> ToolRegistry:
    tools = ToolRegistry()

    @tools.tool("check_stock_all_locations", "stock for a SKU at every location (synthetic)", {"sku": "str"})
    def check_stock(args, services):
        return {"sku": args.get("sku"), "WH-NORTH": 40, "WH-SOUTH": 12, "STORE-12": 0}

    return tools


def build_overlay(systems: AcmeSystems | None = None) -> Overlay:
    """Acme Retail's overlay: the retail-fulfilment template, one override, invented actions and people."""
    sys_ = systems if systems is not None else AcmeSystems()
    doc = load_layers([("template:retail-fulfilment", templates.load("retail-fulfilment")["registry"]),
                       ("acme-retail", {"overrides": [PLAYBOOK_OVERRIDE]})])
    verifiers = {
        "order_fulfillable": lambda **kw: True,
        "sync_landed": lambda **kw: True,
        "channel_stock_matches": lambda **kw: True,
    }
    return Overlay(name="acme-retail-demo", fingerprint_rules=doc.fingerprints, patterns=doc.patterns,
                   roles=doc.roles, actions=_actions(sys_), tools=_tools(sys_), services={"acme": sys_},
                   verifiers=verifiers, directory=_directory(), case_defaults=doc.defaults,
                   capabilities=doc.capabilities)


def build_engine(db_path: str | None = None) -> tuple[Engine, AcmeSystems, StubModel]:
    """An engine on a SQLite file (or in memory), the stub model, and a quick learning policy."""
    sys_ = AcmeSystems()
    model = StubModel()
    store = SQLiteStore(db_path) if db_path else SQLiteStore()
    eng = Engine(build_overlay(sys_), store=store, llm=model, guardrails=Guardrails(),
                 learning=LearningPolicy(promote_streak={Route.HITL: 3, Route.LLM: 20}, auto_promote=False),
                 sync_config=False)
    return eng, sys_, model


def principals() -> dict[str, Principal]:
    return {token_hash(tok): Principal("person", pid) for pid, tok in TOKENS.items()}


# ---------------------------------------------------------------------------------------------- the story

def _ev(etype: str, key: str, source: str, **payload: Any) -> Event:
    return Event(type=etype, source=source, idempotency_key=key, payload=payload)


def _state(eng: Engine, res: Any) -> str:
    return eng.store.get_incident(res.incident_id).state.value


def seed(eng: Engine) -> dict[str, Any]:
    """Load the story. Idempotent: a store that already holds cases is left as it is."""
    if eng.store.incidents():
        return {"seeded": False, "events": 0}
    n = 0

    def put(ev: Event) -> Any:
        nonlocal n
        n += 1
        return eng.ingest(ev)

    # 1. a store goes dark: orders there are suppressed instead of paging anyone about each one
    put(_ev("location.outage", "out-12", "wms", location="STORE-12", kind="wms_offline"))
    for i, order in enumerate(["AR-10031", "AR-10032"]):
        put(_ev("order.unfulfilled", f"unf-{order}", "oms", order_id=order, channel="webstore",
                location="STORE-12", stock_status="in_stock", hours_since_paid=30 + i))

    # 2. paid orders stuck past their SLA with stock on the shelf: handled automatically
    for i in range(1, 11):
        order = f"AR-100{i:02d}"
        put(_ev("order.unfulfilled", f"unf-{order}", "oms", order_id=order,
                channel=("webstore", "marketplace_east", "marketplace_west")[i % 3],
                location=("WH-NORTH", "WH-SOUTH")[i % 2], stock_status="in_stock",
                hours_since_paid=26 + 2 * i))

    # 3. channel syncs: four time out and are retried (one fails once, then lands); one is rejected
    for i, (order, err) in enumerate([("AR-10018", "TIMEOUT"), ("AR-10019", "RATE_LIMITED"),
                                      ("AR-10020", "TIMEOUT"), ("AR-10021", "HTTP_5XX")]):
        put(_ev("channel.sync_failed", f"sync-{order}", "channel_api", order_id=order,
                channel=("marketplace_east", "marketplace_west")[i % 2], operation="dispatch", error_code=err))
    put(_ev("channel.sync_failed", "sync-AR-10022", "channel_api", order_id="AR-10022",
            channel="marketplace_west", operation="cancel", error_code="INVALID_STATE"))

    # 4. orders with no stock where they are: each has a suggested move to a location that has stock.
    #    Nora approves the first three as suggested -> the pattern earns a step up, pending sign-off.
    no_stock = [("AR-10101", "WH-NORTH", "WH-SOUTH"), ("AR-10102", "WH-SOUTH", "WH-NORTH"),
                ("AR-10103", "WH-NORTH", "WH-SOUTH"), ("AR-10104", "WH-SOUTH", "WH-NORTH"),
                ("AR-10105", "WH-NORTH", "WH-SOUTH")]
    results = [put(_ev("order.unfulfilled", f"unf-{o}", "oms", order_id=o, channel="webstore", location=loc,
                       stock_status="out_of_stock", hours_since_paid=40 + i, alt_location=alt))
               for i, (o, loc, alt) in enumerate(no_stock)]
    for res in results[:3]:
        rev = eng.store.open_review_for(res.incident_id)
        eng.decide(rev.id, Decision(kind=DecisionKind.APPROVE, actor="nora"))

    # 5. stock drift: two small gaps the (stub) model corrects, one that turns out wrong and is reversed
    for sku, wh, ch in [("SKU-2001", 120, 118), ("SKU-2002", 64, 62), ("SKU-2003", 30, 28)]:
        res = put(_ev("inventory.mismatch", f"drift-{sku}", "wms", sku=sku, channel="webstore",
                      location="WH-NORTH", warehouse_qty=wh, channel_qty=ch, abs_delta=abs(wh - ch)))
        if sku == "SKU-2003":
            eng.reverse(res.incident_id, "dev", "Ines recounted: the receiving figure was wrong")
    # after the reversal the pattern needs a person again: this one waits
    put(_ev("inventory.mismatch", "drift-SKU-2004", "wms", sku="SKU-2004", channel="webstore",
            location="WH-SOUTH", warehouse_qty=77, channel_qty=75, abs_delta=2))
    put(_ev("inventory.mismatch", "drift-SKU-2010", "wms", sku="SKU-2010", channel="marketplace_east",
            location="WH-NORTH", warehouse_qty=15, channel_qty=1, abs_delta=14))

    # 6. payments captured with no order: one is fixed by Tess, two wait (one is over her refund limit)
    res = put(_ev("payment.orphaned", "pay-9001", "gateway", payment_id="PAY-9001", gateway="gateway_one",
                  amount=2499.0))
    eng.decide(eng.store.open_review_for(res.incident_id).id,
               Decision(kind=DecisionKind.MODIFY, actor="tess", action="create_order_from_payment",
                        params={"payment_id": "PAY-9001"}, disposition_code="order_created"))
    put(_ev("payment.orphaned", "pay-9002", "gateway", payment_id="PAY-9002", gateway="gateway_one",
            amount=18750.0))
    put(_ev("payment.orphaned", "pay-9003", "gateway", payment_id="PAY-9003", gateway="gateway_two",
            amount=899.0))
    return {"seeded": True, "events": n}


def summary(eng: Engine) -> dict[str, Any]:
    """Counts a person (or a test) can read at a glance."""
    by_state: dict[str, int] = {}
    for inc in eng.store.incidents():
        by_state[inc.state.value] = by_state.get(inc.state.value, 0) + 1
    routes = {p.id: eng.pattern_state(p).route.value for p in eng.registry.all()}
    pending = {p.id: eng.pattern_state(p).pending_promotion.value for p in eng.registry.all()
               if eng.pattern_state(p).pending_promotion}
    return {"cases": sum(by_state.values()), "by_state": dict(sorted(by_state.items())),
            "open_reviews": len(eng.store.open_reviews()), "routes": routes, "pending_promotions": pending}


def case_table(eng: Engine) -> dict[str, tuple[str, str]]:
    """order/payment/sku reference -> (pattern, state): the seeded story in a comparable form."""
    out: dict[str, tuple[str, str]] = {}
    for inc in eng.store.incidents():
        ev = eng.store.get_event(inc.event_ids[0])
        p = ev.payload
        ref = p.get("order_id") or p.get("payment_id") or p.get("sku") or p.get("location")
        out[f"{inc.pattern_id}:{ref}"] = (inc.pattern_id, inc.state.value)
    return dict(sorted(out.items()))


# ---------------------------------------------------------------------------------------------- serving

class RunningDemo:
    """The API and console in a background thread (used by the tests and the screenshot script)."""

    def __init__(self, eng: Engine, host: str = "127.0.0.1", port: int = 0) -> None:
        import uvicorn

        from .api import create_app
        if port == 0:
            s = socket.socket()
            s.bind((host, 0))
            port = s.getsockname()[1]
            s.close()
        self.engine, self.host, self.port = eng, host, port
        app = create_app(eng, principals(), config_sync_s=0, title="Sentinel demo (Acme Retail)")
        self._server = uvicorn.Server(uvicorn.Config(app, host=host, port=port, log_config=None, access_log=False))
        self._thread = threading.Thread(target=self._server.run, daemon=True, name="demo-server")

    @property
    def base(self) -> str:
        return f"http://{self.host}:{self.port}"

    def start(self) -> RunningDemo:
        self._thread.start()
        for _ in range(500):
            if self._server.started:
                return self
            time.sleep(0.02)
        raise RuntimeError("the demo server did not start")

    def stop(self) -> None:
        self._server.should_exit = True
        self._thread.join(10)


def banner(base: str, eng: Engine, db: str | None) -> str:
    s = summary(eng)
    lines = [
        "",
        f"  Sentinel demo - {COMPANY} (synthetic data; the model is a stub, nothing leaves this machine)",
        "  " + "-" * 86,
        f"  Open:   {base}/console",
        "  Paste one of these tokens on the sign-in page:",
    ]
    for _pid, name, _role, tok in PEOPLE:
        lines.append(f"            {tok:<28} {name}")
    lines += [
        "",
        f"  {s['cases']} cases: {s['by_state'].get('dispositioned', 0) + s['by_state'].get('closed', 0)} handled, "
        f"{s['open_reviews']} waiting for a person.",
        "  Try this:",
        "    1. Sign in as dev (the operations head) -> Exceptions: 'order_stuck_no_stock' earned a step up",
        "       (three approved proposals in a row). Approve it and it moves from a person to the model.",
        "    2. Reviews: open a card (as nora, omar, ines or tess) to see the proposal, then approve it.",
        "    3. Cases: find the stock correction for SKU-2003 that was reversed, and see the audit trail.",
        "    4. People & roles: who may approve what, and the limit on refunds (Tess stops at 10,000).",
        "",
        f"  Data: {db or 'in a temporary folder, deleted on exit'}.  Stop with Ctrl-C.",
        "",
    ]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m sentinel.demo", description=__doc__.split("\n\n")[0])
    ap.add_argument("--host", default="127.0.0.1", help="interface to listen on (default 127.0.0.1)")
    ap.add_argument("--port", type=int, default=DEFAULT_PORT)
    ap.add_argument("--db", help="keep the demo data in this SQLite file (default: a temporary folder)")
    ap.add_argument("--check", action="store_true", help="build and seed, print the summary, do not serve")
    a = ap.parse_args(argv)
    try:
        import fastapi  # noqa: F401
        import uvicorn  # noqa: F401
    except ImportError:
        print("The demo needs the API extras: pip install -e \".[dev]\"  (or  pip install 'kbg-sentinel[api]')",
              file=sys.stderr)
        return 2
    tmp = None if a.db else tempfile.mkdtemp(prefix="sentinel-demo-")
    db = a.db or str(Path(tmp) / "demo.db")
    eng, _sys, _model = build_engine(db)
    seeded = seed(eng)
    if a.check:
        print(json.dumps({**seeded, **summary(eng)}, indent=2))
        eng.store.close() if hasattr(eng.store, "close") else None
        if tmp:
            shutil.rmtree(tmp, ignore_errors=True)
        return 0
    demo = RunningDemo(eng, a.host, a.port)
    try:
        demo.start()
    except OSError as e:
        print(f"could not listen on {a.host}:{a.port}: {e}", file=sys.stderr)
        return 1
    shown = f"http://localhost:{demo.port}" if a.host in ("0.0.0.0", "::") else demo.base   # noqa: S104
    print(banner(shown, eng, a.db))
    stop = threading.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):      # explicit, so Ctrl-C works even if started in the background
        signal.signal(sig, lambda *_: stop.set())
    try:
        stop.wait()
        print("\n  Stopping...")
    finally:
        demo.stop()
        if hasattr(eng.store, "close"):
            eng.store.close()
        if tmp:
            shutil.rmtree(tmp, ignore_errors=True)
    print("  Stopped. Nothing is left running.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
