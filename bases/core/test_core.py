# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""Gate for kbg-platform-core.

Every check here is a NEGATIVE one: it proves the primitive *refuses* the thing its doctrine
forbids. A suite that only proved the happy paths would pass against a version of this package
with all the guards removed, which is exactly the failure mode the canon's D7 names.

Run: python test_core.py
"""
from __future__ import annotations

import asyncio
import contextlib
import io
import sys
import uuid

sys.path.insert(0, "src")

from kbg_platform_core.outbox import RetryPolicy, decide
from kbg_platform_core import (AsyncOutbox, BLOCK_KINDS, NO_RULE, Authority, Decision, Gap, GapError, Mode, Outbox, OutboxRow,
                               PermissionDenied, Resolved, State, VersionedRecord,
                               VersionedWriter, capture_id, gaps)
from kbg_platform_core.job_run import arecord, record, write
from kbg_platform_core.rbac_shadow import (MemoryRecorder, RbacShadow, coverage_report,
                                           permission_for, route_table)
from kbg_platform_core.testkit import (ControlNotProven, assert_advanced,
                                       assert_control_controls, require_fixture_db)

_p = _f = 0


def check(label, got, want):
    global _p, _f
    ok = got == want
    _p, _f = (_p + 1, _f) if ok else (_p, _f + 1)
    print(f"  [{'PASS' if ok else 'FAIL'}] {label}: got={got!r} want={want!r}")


def check_raises(label, exc, fn):
    global _p, _f
    try:
        fn()
    except exc as e:
        _p += 1
        print(f"  [PASS] {label} — {str(e)[:74]}")
        return
    except Exception as e:  # noqa: BLE001
        _f += 1
        print(f"  [FAIL] {label} — raised {type(e).__name__}, wanted {exc.__name__}")
        return
    _f += 1
    print(f"  [FAIL] {label} — did NOT raise {exc.__name__}")


# ── D4: absence is a type, and reading it raises ────────────────────────────────────────────
print("\n[D4] missing data is a finding, never a licence to invent")
r = Resolved(42, {"rule": "exact"})
check("a resolved value reads", r.value, 42)
check("...and is not a gap", r.is_gap, False)
g = Gap("no_shelf_life", "no shelf life configured for SKU-1; set it in the config screen")
check("a gap is a gap", g.is_gap, True)
check_raises("reading .value on a Gap RAISES", GapError, lambda: g.value)
check("...but an explicit default is allowed at the call site", g.unwrap_or(0), 0)
check("gaps() collects every gap in a batch, not just the first",
      [x.code for x in gaps([r, g, Gap("no_price", "x")])], ["no_shelf_life", "no_price"])
# The bug this prevents, demonstrated: `or` would have silently invented a zero.
check("a Gap is TRUTHY, so `gap or 0` cannot silently invent a value", bool(g), True)


# ── D1: deny by default, one function for UI and API ───────────────────────────────────────
print("\n[D1] deny by default; the button and the endpoint cannot disagree")
log: list[dict] = []


class Auth(Authority):
    def __init__(self, granted):
        super().__init__(log=log.append)
        self._granted = granted

    def _evaluate(self, actor, action, obj=None):
        if action in self._granted:
            return Decision.allow()
        if action == "order.correct":
            return Decision.deny("corrections are a supervisor act", who_can="Supervisor")
        return None          # no rule matched -> must become a denial


auth = Auth({"order.read"})
check("a granted action is allowed", auth.check("ann", "order.read").allowed, True)
d = auth.check("ann", "order.correct")
check("an explicitly denied action is denied", d.allowed, False)
check("...and carries WHO CAN", d.who_can, "Supervisor")
unknown = auth.check("ann", "order.nuke")
check("an UNLISTED action is denied by default", unknown.allowed, False)
check_raises("a denial with no reason is refused at construction",
             ValueError, lambda: Decision.deny(""))
check("availability and enforcement come from one decision",
      auth.check("ann", "order.correct").as_availability(),
      {"enabled": False, "reason": "corrections are a supervisor act", "whoCan": "Supervisor",
       "kind": "AUTHORITY", "code": None})
check_raises("require() raises with the SAME reason the UI showed",
             PermissionDenied, lambda: auth.require("ann", "order.correct"))
check("allows are logged too, not only denials",
      [e["allowed"] for e in log].count(True), 1)


# ── D1 (gate 9): a denial names its KIND, and only a known one ────────────────────────────
print("\n[D1/kind] a denial carries one of seven kinds; anything else is refused")
check("the closed list has exactly the seven kinds",
      BLOCK_KINDS, ("AUTHORITY", "STATE_GATE", "CONFIG_GATE", "PRECONDITION", "READINESS",
                    "APPROVAL_PENDING", "COMPLETED"))
check("a plain denial defaults to AUTHORITY", Decision.deny("no").kind, "AUTHORITY")
for k in BLOCK_KINDS:
    dk = Decision.deny("because " + k.lower(), kind=k, code="C_" + k)
    check(f"kind {k}: carried on the decision, with reason and code",
          (dk.allowed, dk.kind, dk.code, bool(dk.reason)), (False, k, "C_" + k, True))
    check(f"kind {k}: the screen shape names it too", dk.as_availability()["kind"], k)
check_raises("an UNKNOWN kind is refused when the decision is built", ValueError,
             lambda: Decision.deny("x", kind="WHATEVER"))
check_raises("...even through the bare constructor", ValueError,
             lambda: Decision(False, "x", kind="whatever"))
check_raises("a lower-case spelling of a kind is refused (closed list, exact match)", ValueError,
             lambda: Decision.deny("x", kind="authority"))
check_raises("a denial with an empty reason is refused, via the bare constructor too",
             ValueError, lambda: Decision(False, ""))
check_raises("a denial with a None reason is refused", ValueError, lambda: Decision(False))
check_raises("an ALLOW cannot carry a denial kind", ValueError,
             lambda: Decision(True, None, None, {}, "STATE_GATE"))
check("an allow has no kind", Decision.allow().kind, None)
check("who_can stays optional", Decision.deny("x").who_can, None)
check("an allow's blocked_by is None", Decision.allow().as_blocked_by(), None)
check("a denial's blocked_by is {kind, code, reason}",
      Decision.deny("held", kind="STATE_GATE", code="POSTED").as_blocked_by(),
      {"kind": "STATE_GATE", "code": "POSTED", "reason": "held"})

klog: list[dict] = []


def authorise(actor, action, obj=None):
    if action == "doc.post":
        return Decision.deny("already posted", kind="STATE_GATE", code="POSTED")
    if action == "doc.read":
        return Decision.allow()
    if action == "doc.bad":
        return "yes"            # not a Decision: must not be treated as an allow
    return None


inj = Authority(authorise, log=klog.append)
blocked = inj.check("ann", "doc.post")
check("an INJECTED authorise drives the decision, kind and code intact",
      (blocked.allowed, blocked.kind, blocked.code), (False, "STATE_GATE", "POSTED"))
fallback = inj.check("ann", "doc.unlisted")
check("no rule matched: denied with code NO_RULE and kind AUTHORITY",
      (fallback.allowed, fallback.code, fallback.kind), (False, NO_RULE, "AUTHORITY"))
check("the button and the 403 agree on kind and reason",
      (inj.check("ann", "doc.post").as_availability()["kind"],
       inj.check("ann", "doc.post").as_availability()["reason"]), ("STATE_GATE", "already posted"))
try:
    inj.require("ann", "doc.post")
except PermissionDenied as e:
    check("require() raises carrying the same kind the UI showed", e.decision.kind, "STATE_GATE")
check("the decision log records kind and code on every entry",
      [(e["kind"], e["code"]) for e in klog][:1], [("STATE_GATE", "POSTED")])
check_raises("a non-Decision answer from authorise is refused, never read as an allow",
             TypeError, lambda: inj.check("ann", "doc.bad"))
check_raises("a non-callable authorise is refused", TypeError, lambda: Authority("yes"))
check_raises("an Authority with neither authorise nor _evaluate fails loudly",
             NotImplementedError, lambda: Authority().check("ann", "x"))


# ── D3: idempotency by client-minted id ────────────────────────────────────────────────────
print("\n[D3] idempotency by SOURCE id")
cid = uuid.uuid4()
check("a client id is used as-is", capture_id(cid), cid)
check("a client id as string parses", capture_id(str(cid)), cid)
check_raises("a MALFORMED client id is refused, not silently replaced",
             ValueError, lambda: capture_id("not-a-uuid"))
check("no client id mints one", isinstance(capture_id(None), uuid.UUID), True)


# ── Integration §10: the gate holds, and does not pretend ──────────────────────────────────
print("\n[gate] non-production HOLDS; it does not fake success")


class MemStore:
    def __init__(self):
        self.rows: dict[tuple, OutboxRow] = {}

    def get(self, topic, source_key):
        return self.rows.get((topic, source_key))

    def upsert(self, row):
        self.rows[(row.topic, row.source_key)] = row
        return row


store = MemStore()
uat = Outbox(Mode.UAT, store)
row = uat.enqueue(topic="erp.invoice.v1", source_key="INV-1", payload={"n": 1})
check("UAT holds the document", row.state, State.HELD)
check("...and a held row states WHY, naming the mode",
      row.held_reason.startswith("integration_mode=uat"), True)
check("...and says explicitly that nothing was faked or dropped",
      "faked" in row.held_reason and "dropped" in row.held_reason, True)
check("the gate reports the MODE, not a bare boolean", uat.release_check(),
      {"mode": "uat", "maySend": False})
again = uat.enqueue(topic="erp.invoice.v1", source_key="INV-1", payload={"n": 1})
check("re-enqueueing the same source key returns the SAME row (no duplicate)",
      len(store.rows), 1)
check("...and it is the same object", again is row, True)
check_raises("an outbound document with no source key is refused",
             ValueError, lambda: uat.enqueue(topic="t", source_key="", payload={}))
prod = Outbox(Mode.PRODUCTION, MemStore())
check("production may send", prod.release_check()["maySend"], True)
check("production queues rather than holds",
      prod.enqueue(topic="t", source_key="k", payload={}).state, State.QUEUED)
check_raises("marking a failure with no error is refused (no swallowed errors)",
             ValueError, lambda: uat.mark_failed(row, ""))


# ── the outbox STATE MACHINE — the rules a drain loop gets wrong ──────────────────────────
print("\n[outbox] the state machine, incl. the rule that is easy to get wrong")
d = decide(result={"ok": True}, attempts=0)
check("an accepted push confirms", (d.state.value, d.counts_as), ("confirmed", "dispatched"))
d = decide(result={"ok": False}, attempts=0)
check("a failure stays retryable", (d.state.value, d.counts_as), ("failed", "failed"))
check("...and consumes an attempt", d.increment_attempts, True)
d = decide(result={"ok": False}, attempts=4)
check("the 5th failure dead-letters", (d.state.value, d.counts_as), ("dead_letter", "dead_letter"))
d = decide(result={"ok": False}, attempts=1, policy=RetryPolicy(max_attempts=2))
check("max_attempts is POLICY, not a constant", d.state.value, "dead_letter")

# ⛔ The rule this function exists for.
h = decide(result={"held": True, "held_reason": "uat"}, attempts=3)
check("HELD does NOT consume an attempt", h.increment_attempts, False)
check("...and stays QUEUED, so the same loop re-drives it when the gate opens",
      h.state.value, "queued")
check("...and is counted as its own outcome, not as failed", h.counts_as, "held")
check("...and its response is still recorded — never a silent outcome", h.record_response, True)
check("held near the retry ceiling STILL does not dead-letter",
      decide(result={"held": True}, attempts=99).state.value, "queued")
print("      ^ if holding consumed a retry, a long UAT period would dead-letter good events")
print("        purely because time passed, discovered only after the switch flipped.")

box_uat = Outbox(Mode.UAT, MemStore())
hr = box_uat.held_result()
check("held_result feeds decide() directly", decide(result=hr, attempts=0).counts_as, "held")
check("...and names the mode for the reader", hr["mode"], "uat")


# ── Integration gate 8 (R1) + gate 9: sync and async Outbox over ONE decide() ───────────────
print("\n[R1] the first enqueue of a new key writes exactly one row, sync OR async")


class AMemStore:
    """An ASYNC in-memory store: every method is a coroutine, as with an async ORM."""

    def __init__(self):
        self.rows: dict[tuple, OutboxRow] = {}

    async def get(self, topic, source_key):
        return self.rows.get((topic, source_key))

    async def upsert(self, row):
        self.rows[(row.topic, row.source_key)] = row
        return row


def naive_enqueue(box, *, topic, source_key, payload):
    """The defect, reproduced: the sync recipe pointed at an async store. `existing` is an
    un-awaited coroutine (always truthy, never None), so the 'already exists' branch runs on the
    FIRST enqueue and nothing is written. This is what the guard in Outbox exists to stop."""
    existing = box.store.get(topic, source_key)
    if existing is not None:
        return existing
    return box.store.upsert(OutboxRow(topic, source_key, payload))


async def r1_async():
    ast = AMemStore()
    abox = AsyncOutbox(Mode.PRODUCTION, ast)
    first = await abox.enqueue(topic="t", source_key="K1", payload={"n": 1})
    check("async: the first enqueue of a new key writes EXACTLY ONE row", len(ast.rows), 1)
    check("...in the queued state", first.state, State.QUEUED)
    second = await abox.enqueue(topic="t", source_key="K1", payload={"n": 1})
    check("async: the same key again returns the SAME row", second is first, True)
    check("...and the store still holds exactly one", len(ast.rows), 1)
    await abox.enqueue(topic="t", source_key="K2", payload={})
    check("a different key is a different row", len(ast.rows), 2)
    try:
        await abox.enqueue(topic="t", source_key="", payload={})
        check("async: an empty source key is refused", "no raise", "ValueError")
    except ValueError:
        check("async: an empty source key is refused", "ValueError", "ValueError")

    # the defect itself, planted: the naive recipe loses the first enqueue
    bst = AMemStore()
    lost = naive_enqueue(Outbox(Mode.PRODUCTION, bst), topic="t", source_key="K", payload={})
    lost.close()
    check("PLANTED DEFECT: a sync recipe over an async store writes ZERO rows", len(bst.rows), 0)

    # the guard: the real sync Outbox refuses that combination instead of losing the row
    gst = AMemStore()
    try:
        Outbox(Mode.PRODUCTION, gst).enqueue(topic="t", source_key="K", payload={})
        check("sync Outbox over an async store is refused", "no raise", "TypeError")
    except TypeError as e:
        check("sync Outbox over an async store is refused, naming AsyncOutbox",
              "AsyncOutbox" in str(e), True)
    check("...and it wrote nothing, rather than pretending", len(gst.rows), 0)

    # gate 9: a held row consumes no attempt, and sends once the gate opens
    hst = AMemStore()
    uat_box = AsyncOutbox(Mode.UAT, hst)
    h = await uat_box.enqueue(topic="t", source_key="H1", payload={})
    check("UAT holds the new row", h.state, State.HELD)
    for _ in range(7):
        await uat_box.settle(h, uat_box.held_result())
    check("held through 7 drains: attempts still 0", h.attempts, 0)
    check("...and still HELD, so it can be re-driven", h.state, State.HELD)
    check("release_held is a no-op while the gate is shut",
          (await uat_box.release_held(h)).state, State.HELD)
    prod_box = AsyncOutbox(Mode.PRODUCTION, hst)
    await prod_box.release_held(h)
    check("flip the mode: the SAME row is queued", (h.state, h.attempts), (State.QUEUED, 0))
    await prod_box.settle(h, {"ok": True})
    check("a real send confirms and counts exactly one attempt",
          (h.state, h.attempts), (State.CONFIRMED, 1))
    check("the store holds that same row, still one", len(hst.rows), 1)

    # a failure is recorded with its error, then dead-letters at the policy ceiling
    fst = AMemStore()
    fbox = AsyncOutbox(Mode.PRODUCTION, fst, RetryPolicy(max_attempts=2))
    f = await fbox.enqueue(topic="t", source_key="F1", payload={})
    await fbox.settle(f, {"ok": False, "error": "502 from far side"})
    check("first failure: FAILED, error recorded, one attempt",
          (f.state, f.last_error, f.attempts), (State.FAILED, "502 from far side", 1))
    await fbox.settle(f, {"ok": False, "error": "502 again"})
    check("second failure reaches the policy ceiling: DEAD_LETTER", f.state, State.DEAD_LETTER)
    try:
        await fbox.mark_failed(f, "")
        check("async mark_failed with no error is refused", "no raise", "ValueError")
    except ValueError:
        check("async mark_failed with no error is refused", "ValueError", "ValueError")


asyncio.run(r1_async())

print("\n[one decide()] sync and async front doors give the same verdict on the same inputs")
results = [{"held": True}, {"ok": False, "error": "e1"}, {"ok": False, "error": "e2"},
           {"ok": True}]
sbox = Outbox(Mode.PRODUCTION, MemStore())
srow = sbox.enqueue(topic="t", source_key="S", payload={})


async def drive_async():
    abox = AsyncOutbox(Mode.PRODUCTION, AMemStore())
    arow = await abox.enqueue(topic="t", source_key="S", payload={})
    trail = []
    for r in results:
        await abox.settle(arow, r)
        trail.append((arow.state.value, arow.attempts))
    return trail


strail = []
for r in results:
    sbox.settle(srow, r)
    strail.append((srow.state.value, srow.attempts))
check("same state/attempt trail through held, fail, fail, ok", strail, asyncio.run(drive_async()))
check("...and the trail is the decide() trail",
      strail, [("queued", 0), ("failed", 1), ("failed", 2), ("confirmed", 3)])
check("sync settle on a HELD row leaves it held with 0 attempts",
      (lambda b: (b.settle(b.enqueue(topic="t", source_key="Z", payload={}), b.held_result())
                  .state.value))(Outbox(Mode.DEV, MemStore())), "held")


# ── RBAC shadow mode: observes, records, NEVER denies ────────────────────────────────────
print("\n[shadow] the strangler measures coverage before anything is enforced")
TABLE = route_table([
    ("GET", "/api/orders", "read", "order"),
    ("POST|PATCH", "/api/orders", "write", "order"),
    ("POST", "/api/orders/refund", "refund", "order"),
    ("GET", "/api/reports", "read", "report"),
])
check("longest prefix wins regardless of row order",
      permission_for(TABLE, "POST", "/api/orders/refund/7").permission, "order.refund")
check("a prefix matches on a path-segment boundary only",
      permission_for(TABLE, "GET", "/api/ordersfoo"), None)
check("a method outside the row's methods is unmapped, not 'no permission needed'",
      permission_for(TABLE, "DELETE", "/api/orders"), None)

held = {"ann": {"order.read", "order.write"}}
asked: list[tuple] = []


def evaluate(actor, action, object_type):
    asked.append((actor, action, object_type))
    if actor == "boom":
        raise RuntimeError("authority down")
    if actor == "mute":
        return None
    ok = f"{object_type}.{action}" in held.get(actor, set())
    return Decision.allow() if ok else Decision.deny("not granted to this role")


rec = MemoryRecorder()
shadow = RbacShadow(TABLE, evaluate, rec)
check("held permission -> allow", shadow.observe("ann", "GET", "/api/orders/1")["outcome"], "allow")
w = shadow.observe("ann", "POST", "/api/orders/refund")
check("not held -> would_deny, with the reason", (w["outcome"], w["reason"], w["kind"]),
      ("would_deny", "not granted to this role", "AUTHORITY"))
u = shadow.observe("ann", "GET", "/api/unknown")
check("no mapping -> unmapped, and the authority was NOT asked",
      (u["outcome"], ("ann", "read", "unknown") in asked), ("unmapped", False))
check("a raising authority is recorded as error, not propagated",
      shadow.observe("boom", "GET", "/api/orders")["outcome"], "error")
check("an authority answering None is an error, never an allow",
      shadow.observe("mute", "GET", "/api/orders")["outcome"], "error")
check("an observation says it is shadow and not enforced",
      (w["shadow"], w["enforced"]), (True, False))
check("every observation was recorded, would_deny and unmapped included", len(rec.observations), 5)

bad = RbacShadow(TABLE, evaluate, lambda o: 1 / 0)
check("a failing recorder never breaks the request", bad.observe("ann", "GET", "/api/orders")["outcome"], "allow")
check("...but the loss is COUNTED", bad.recorder_errors, 1)
check("a bool authority works too", RbacShadow(TABLE, lambda a, b, c: True).observe("x", "GET", "/api/reports")["outcome"], "allow")
check("a non-bool, non-Decision answer is an error",
      RbacShadow(TABLE, lambda a, b, c: "yes").observe("x", "GET", "/api/reports")["outcome"], "error")

rep = coverage_report(rec.observations, TABLE)
check("report counts by outcome", rep["byOutcome"],
      {"allow": 1, "would_deny": 1, "unmapped": 1, "error": 2})
check("unmapped routes become a worklist", rep["unmappedRoutes"], {"GET /api/unknown": 1})
check("NOT ready to enforce while unmapped / would_deny / errors remain", rep["readyToEnforce"], False)
grp = {g["permission"]: g for g in rep["groups"]}
check("a group with a would_deny is not ready", grp["order.refund"]["ready"], False)
check("a mapped group nobody exercised is not ready (no traffic is not evidence)",
      grp["report.read"]["ready"], False)
clean_rec = MemoryRecorder()
ok_shadow = RbacShadow(TABLE, lambda a, b, c: True, clean_rec)
for m, pth in (("GET", "/api/orders/1"), ("POST", "/api/orders"), ("POST", "/api/orders/refund"),
               ("GET", "/api/reports")):
    ok_shadow.observe("ann", m, pth)
clean = coverage_report(clean_rec.observations, TABLE)
check("all mapped, all allowed, all exercised -> every group ready and enforceable",
      (clean["readyToEnforce"], all(g["ready"] for g in clean["groups"])), (True, True))
check("an empty run is never 'ready'", coverage_report([], TABLE)["readyToEnforce"], False)
check("a record that is not one of ours counts as an error, not data",
      coverage_report([{"outcome": "bogus"}], TABLE)["errors"], 1)


async def shadow_async():
    arec: list = []

    async def aeval(actor, action, object_type):
        return Decision.allow()

    async def arecorder(obs):
        arec.append(obs)

    sh = RbacShadow(TABLE, aeval, arecorder)
    o = await sh.aobserve("ann", "GET", "/api/orders")
    check("async evaluate and async recorder", (o["outcome"], len(arec)), ("allow", 1))
    sync_on_async = RbacShadow(TABLE, aeval, arec.append).observe("ann", "GET", "/api/orders")
    check("the sync path refuses an async authority as an error, never an allow",
          sync_on_async["outcome"], "error")


asyncio.run(shadow_async())


# ── job_run: one record per run, on success AND failure, and the failure is re-raised ──────
print("\n[job_run] every run leaves exactly one record; a failure is recorded then re-raised")


class RunStore:
    def __init__(self, fail_open=False, fail_close=False):
        self.rows: list[dict] = []
        self.opened_as: list[str] = []
        self.fail_open, self.fail_close = fail_open, fail_close

    def open(self, run):
        if self.fail_open:
            raise ConnectionError("db down at start")
        self.opened_as.append(run.snapshot()["status"])
        self.rows.append(run.snapshot())
        return len(self.rows) - 1

    def close(self, row_id, run):
        if self.fail_close:
            raise ConnectionError("db down at end")
        if row_id is None:
            self.rows.append(run.snapshot())
        else:
            self.rows[row_id] = run.snapshot()


st = RunStore()
with record("sync", st, scope="tenant-1", expect_every_hours=6) as run:
    run.rows(41).summarize("synced   41\nrows").detail(src="a")
check("success: exactly ONE row", len(st.rows), 1)
check("...visible as 'running' while it was in flight", st.opened_as, ["running"])
r0 = st.rows[0]
check("...closed ok with its counts and one-line summary",
      (r0["status"], r0["rows_affected"], r0["summary"]), ("ok", 41, "synced 41 rows"))
check("...finished_at set, scope kept, cadence registered as data",
      (r0["finished_at"] is not None, r0["scope"], r0["detail"]["expect_every_hours"]),
      (True, "tenant-1", 6))

st = RunStore()
try:
    with record("sync", st) as run:
        raise ValueError("boom")
    check("a failing job re-raises", "no raise", "ValueError")
except ValueError:
    check("a failing job RE-RAISES (the job still exits non-zero)", "ValueError", "ValueError")
check("...and still leaves exactly one row", len(st.rows), 1)
check("...recorded failed, with the exception in detail",
      (st.rows[0]["status"], st.rows[0]["detail"]["exception"]["type"]), ("failed", "ValueError"))
check("...and a summary that says FAILED", st.rows[0]["summary"].startswith("FAILED: ValueError"), True)

st = RunStore()
try:
    with record("sync", st):
        raise KeyboardInterrupt()
except KeyboardInterrupt:
    pass
check("an interrupt is recorded as failed too (BaseException) and re-raised",
      st.rows[0]["status"], "failed")

st = RunStore()
with record("sync", st) as run:
    run.partial("stopped at cutoff")
check("partial is a distinct terminal status with its reason",
      (st.rows[0]["status"], st.rows[0]["detail"]["partial_reason"]), ("partial", "stopped at cutoff"))
st = RunStore()
with record("sync", st) as run:
    run.failed("3 of 5 units failed")
check("a failure the job detects without raising is recorded", st.rows[0]["status"], "failed")
st = RunStore()
try:
    with record("sync", st) as run:
        run.partial()
        raise RuntimeError("x")
except RuntimeError:
    pass
check("an exception after partial() is failed, not partial", st.rows[0]["status"], "failed")
check("expect_every_hours=None registers no cadence",
      "expect_every_hours" in (lambda s: (record("a", s, expect_every_hours=None).__enter__().snapshot()))(RunStore())["detail"], False)

err = io.StringIO()
st = RunStore(fail_open=True)
with contextlib.redirect_stderr(err):
    with record("sync", st) as run:
        run.rows(3)
check("open fails: the job carries on, and ONE row is still written at close",
      (len(st.rows), st.rows[0]["status"], st.rows[0]["rows_affected"]), (1, "ok", 3))
check("...loudly, on stderr, and counted", ("JOB_RUN:" in err.getvalue(), run.record_errors), (True, 1))

err = io.StringIO()
st = RunStore(fail_close=True)
with contextlib.redirect_stderr(err):
    with record("sync", st) as run:
        pass
check("close fails: the job is NOT killed, the stranded 'running' row is the evidence",
      (st.rows[0]["status"], run.record_errors, "JOB_RUN:" in err.getvalue()), ("running", 1, True))
err = io.StringIO()
st = RunStore(fail_close=True)
try:
    with contextlib.redirect_stderr(err):
        with record("sync", st):
            raise ValueError("job failed AND recorder down")
except ValueError:
    check("a job failure still surfaces when the recorder is down too", True, True)
check_raises("a run with no job name is refused", ValueError, lambda: record("", RunStore()).__enter__())
check_raises("write() with an invalid status is refused", ValueError,
             lambda: write("j", RunStore(), status="running"))
st = RunStore()
write("manual", st, status="partial", summary="did half", rows=5, why="cutoff")
check("write() records a known outcome in one call",
      (st.rows[0]["status"], st.rows[0]["rows_affected"], st.rows[0]["detail"]["why"]),
      ("partial", 5, "cutoff"))


class ARunStore:
    def __init__(self):
        self.rows: list[dict] = []

    async def open(self, run):
        self.rows.append(run.snapshot())
        return len(self.rows) - 1

    async def close(self, row_id, run):
        self.rows[row_id] = run.snapshot()


async def job_run_async():
    s = ARunStore()
    async with arecord("a", s) as run:
        run.rows(2)
    check("async: one row, closed ok", (len(s.rows), s.rows[0]["status"], s.rows[0]["rows_affected"]),
          (1, "ok", 2))
    s2 = ARunStore()
    try:
        async with arecord("a", s2):
            raise ValueError("async boom")
        check("async: a failing job re-raises", "no raise", "ValueError")
    except ValueError:
        check("async: a failure is recorded then RE-RAISED", (s2.rows[0]["status"], len(s2.rows)),
              ("failed", 1))
    e = io.StringIO()
    s3 = RunStore()
    with contextlib.redirect_stderr(e):
        async with arecord("a", s3):
            pass
    check("a sync store given to arecord still works (awaited only if awaitable)",
          (len(s3.rows), s3.rows[0]["status"]), (1, "ok"))


asyncio.run(job_run_async())
e = io.StringIO()
with contextlib.redirect_stderr(e):
    with record("a", ARunStore()) as run:
        pass
check("an ASYNC store given to the sync record is flagged loudly, never silently 'ok'",
      (run.record_errors >= 1, "async store" in e.getvalue()), (True, True))


# ── D2: supersede, never update ────────────────────────────────────────────────────────────
print("\n[D2] append-only: values supersede, they never update in place")


class VStore:
    def __init__(self):
        self.rows: list[dict] = []

    def get_active(self, key):
        for r in reversed(self.rows):
            if r["key"] == key and r["active"]:
                return VersionedRecord(key, r["value"], r["version"], id=r["n"])
        return None

    def close(self, record, actor):
        for r in self.rows:
            if r["n"] == record.id:
                r["active"] = False
                r["closed_by"] = actor

    def insert(self, key, value, version, supersedes, actor, **extra):
        n = len(self.rows) + 1
        self.rows.append({"n": n, "key": key, "value": value, "version": version,
                          "active": True, "by": actor,
                          "supersedes": supersedes.id if supersedes else None})
        return n


vs = VStore()
w = VersionedWriter(vs)
r1 = w.set(("shelf_life", "SKU-1"), 4, actor="ann")
check("first write creates v1", (r1.action, r1.version), ("created", 1))
r2 = w.set(("shelf_life", "SKU-1"), 4, actor="ann")
check("an identical write is a no-op", r2.action, "unchanged")
check("...and wrote nothing", len(vs.rows), 1)
r3 = w.set(("shelf_life", "SKU-1"), 3, actor="bob")
check("a change supersedes", r3.action, "superseded")
check("...bumping the version", r3.version, 2)
check("...naming what it replaced", r3.superseded.value, 4)
check("BOTH versions remain in the store — nothing was updated in place", len(vs.rows), 2)
check("...exactly one is active", sum(1 for r in vs.rows if r["active"]), 1)
check("the old row records who closed it", vs.rows[0]["closed_by"], "bob")
check_raises("an unattributed change is refused",
             ValueError, lambda: w.set(("shelf_life", "SKU-1"), 9, actor=""))


# ── D5 / D7: the testkit's own guards ──────────────────────────────────────────────────────
print("\n[D5/D7] the testkit refuses what it is supposed to refuse")
threshold = {"v": 200}


def observe():
    return "off" if 1228 > threshold["v"] else "on"


before, after = assert_control_controls(
    describe="off-location threshold",
    run=observe,
    change=lambda: threshold.__setitem__("v", 2000),
    restore=lambda: threshold.__setitem__("v", 200),
)
check("a real control passes, and the verdict moved", (before, after), ("off", "on"))
check("...and restore put it back", threshold["v"], 200)

check_raises("a HARDCODED value fails the control test", ControlNotProven,
             lambda: assert_control_controls(
                 describe="hardcoded", run=lambda: "always",
                 change=lambda: None, restore=None))

check_raises("a change that moves the MEASUREMENT too is caught", ControlNotProven,
             lambda: assert_control_controls(
                 describe="leaky", run=lambda: threshold["v"],
                 change=lambda: threshold.__setitem__("v", 2000),
                 restore=lambda: threshold.__setitem__("v", 200),
                 invariant=lambda: threshold["v"]))

check("a known fixture db is allowed",
      require_fixture_db("app_dev", {"app_dev", "app_test"}), "app_dev")
check_raises("an UNKNOWN db name is refused (fail closed)", SystemExit,
             lambda: require_fixture_db("app_prod", {"app_dev"}))
check_raises("'active' is not evidence — assert_advanced needs an ADVANCE",
             AssertionError, lambda: assert_advanced("restart", 100, 100))
assert_advanced("restart", 100, 101)
_p += 1
print("  [PASS] an advanced timestamp satisfies assert_advanced")

print(f"\n{'=' * 78}\n{_p}/{_p + _f} checks passed\n{'=' * 78}")
raise SystemExit(0 if _f == 0 else 1)
