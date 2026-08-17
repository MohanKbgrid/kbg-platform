"""Gate for kbg-platform-core.

Every check here is a NEGATIVE one: it proves the primitive *refuses* the thing its doctrine
forbids. A suite that only proved the happy paths would pass against a version of this package
with all the guards removed, which is exactly the failure mode the canon's D7 names.

Run: python test_core.py
"""
from __future__ import annotations

import sys
import uuid

sys.path.insert(0, "src")

from kbg_platform_core.outbox import RetryPolicy, decide
from kbg_platform_core import (Authority, Decision, Gap, GapError, Mode, Outbox, OutboxRow,
                               PermissionDenied, Resolved, State, VersionedRecord,
                               VersionedWriter, capture_id, gaps)
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
      {"enabled": False, "reason": "corrections are a supervisor act", "whoCan": "Supervisor"})
check_raises("require() raises with the SAME reason the UI showed",
             PermissionDenied, lambda: auth.require("ann", "order.correct"))
check("allows are logged too, not only denials",
      [e["allowed"] for e in log].count(True), 1)


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
