# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""Smallest useful Sentinel overlay, in one file.

Scenario: nightly bank-feed reconciliation flags unmatched transactions.
  * small, known-vendor mismatches  -> auto: re-run matching (safe)
  * everything else                 -> a person, with the playbook's suggestion

Run:  python examples/quickstart.py
"""
from __future__ import annotations

from sentinel import (ActionRegistry, ActionResult, Bucket, Decision, DecisionKind, Engine, Event,
                      FingerprintRule, Overlay, Pattern, PlaybookStep, Route)

actions = ActionRegistry()
ledger: list[str] = []


@actions.action("rematch", safe=True, params={"txn": "str"}, description="Re-run auto-matching for a transaction")
def rematch(ctx, p):
    ledger.append(f"rematched {p['txn']}")
    return ActionResult(ok=True)


@actions.action("post_to_suspense", reversible=True, params={"txn": "str"},
                description="Park the transaction in the suspense account")
def suspense(ctx, p):
    ledger.append(f"suspense {p['txn']}")
    return ActionResult(ok=True)


@suspense.compensator
def unsuspense(ctx, p):
    ledger.append(f"un-suspense {p['txn']}")
    return ActionResult(ok=True)


overlay = Overlay(
    name="quickstart",
    fingerprint_rules=[FingerprintRule(
        event_type="recon.unmatched", fields={"vendor": "vendor_known", "txn": "txn_id"},
        buckets={"size": Bucket(field="amount", edges=[1000], labels=["small", "large"])},
        group_by=["txn"])],
    patterns=[
        Pattern(id="small_known", event_types=["recon.unmatched"], match={"vendor": True, "size": "small"},
                route=Route.AUTO, playbook=[PlaybookStep(action="rematch", params={"txn": "{{payload.txn_id}}"})],
                allowed_actions=["rematch", "post_to_suspense"], owner_role="accounts"),
        Pattern(id="needs_review", event_types=["recon.unmatched"], match={"txn": "*"}, route=Route.HITL,
                playbook=[PlaybookStep(action="post_to_suspense", params={"txn": "{{payload.txn_id}}"})],
                allowed_actions=["rematch", "post_to_suspense"], owner_role="accounts"),
    ],
    actions=actions,
)

engine = Engine(overlay)  # in-memory SQLite, no LLM: HITL gets the playbook as its proposal

for txn, amount, known in [("T1", 250, True), ("T2", 48000, True), ("T3", 90, False)]:
    r = engine.ingest(Event(type="recon.unmatched", source="bank_feed", idempotency_key=txn,
                            payload={"txn_id": txn, "amount": amount, "vendor_known": known}))
    inc = engine.store.get_incident(r.incident_id)
    print(f"{txn}: pattern={inc.pattern_id:13} state={inc.state.value}")

for rev in engine.store.open_reviews():
    print(f"review {rev.id}: proposal={[s.action for s in rev.proposal.steps]} -> approving")
    engine.decide(rev.id, Decision(kind=DecisionKind.APPROVE, actor="accounts_exec"))

print("ledger:", ledger)
print("automation:", {k: v["automation_rate"] for k, v in engine.report()["patterns"].items() if v["dispositions"]})
