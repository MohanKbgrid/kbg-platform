# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""Surface 8, Runtime AI: the fourteen gate tests of canon/surfaces/08-runtime-ai.md (AI-1 .. AI-14).

AI-1 .. AI-8 gate the grounded draft. AI-9 .. AI-14 are the layer gates for a system that runs
agents (the canon's four layers); they are newer than `bases/core`, which has no agent concept, so
they are proven here against a reference subject.
"""
from __future__ import annotations

from .framework import Gate, Refused, make_gate

CANON = "canon/surfaces/08-runtime-ai.md, Gate tests"


def ai1(s) -> "list[str]":
    """NEGATIVE: no path from a draft to a posted document without a named human (gate 1)."""
    p = []
    for path in s.posting_paths():
        for actor in (None, "", "   "):
            try:
                s.attempt_post(path, "draft-1", actor)
                p.append(f"posting path {path!r} accepted a draft with actor {actor!r}")
            except Refused:
                pass
    return p


def ai2(s) -> "list[str]":
    """Grounded refusal: a field absent from the source stays empty with a reason; values are not rounded (gate 2)."""
    f = s.draft({"invoice_no": "X1", "total": "99.995"})["fields"]
    p = []
    if f["due_date"]["value"] is not None:
        p.append(f"a field absent from the source was filled with {f['due_date']['value']!r}")
    elif not (f["due_date"].get("reason") or "").strip():
        p.append("an empty field gives no stated reason")
    if f["total"]["value"] != "99.995":
        p.append(f"a value read from the source was altered: {f['total']['value']!r}")
    return p


def ai3(s) -> "list[str]":
    """Confidence exists per field and varies within one draft (gate 3)."""
    f = s.draft({"invoice_no": "X1", "total": "99.995", "note": "~~illegible~~"})["fields"]
    conf = [v.get("confidence") for v in f.values()]
    p = []
    if any(c is None for c in conf):
        p.append("some fields carry no confidence of their own")
    elif len(set(conf)) < 2:
        p.append("every field has the same confidence: it is a document-level score in disguise")
    return p


def ai4(s) -> "list[str]":
    """An edit records the diff, before and after (gate 4)."""
    d = s.create_draft({"total": "99.995"})
    s.decide(d, "pat", "edited", edits={"total": "100.00"})
    diffs = s.events(d)[-1].get("field_diffs") or []
    ok = any(x.get("field") == "total" and x.get("before") == "99.995" and x.get("after") == "100.00" for x in diffs)
    return [] if ok else [f"the decision event does not store the field, its before and its after: {diffs!r}"]


def ai5(s) -> "list[str]":
    """The stub announces itself, in the response and in the invocation record (gate 5)."""
    resp = s.invoke("extract", provider="stub")
    p = []
    if resp.get("stub") is not True:
        p.append("a stubbed provider's response is not labelled stub: true")
    if s.invocations()[-1].get("stub") is not True:
        p.append("a stubbed provider's invocation record is not labelled stub")
    return p


def ai6(s) -> "list[str]":
    """A disabled capability is absent, and no fallback quietly drafts anyway (gate 6)."""
    s.set_enabled("extract", False)
    before = s.draft_count()
    p = []
    try:
        s.request_draft("extract", {"total": "1"})
        p.append("a disabled capability still answered")
    except Refused:
        pass
    if s.draft_count() != before:
        p.append("a disabled capability created a draft through a fallback")
    return p


def ai7(s) -> "list[str]":
    """Acceptance rate is computed from real events, not from a counter that can drift (gate 7)."""
    for outcome in ("accepted", "accepted", "accepted", "rejected"):
        s.record_decision("extract", outcome)
    p = []
    if abs(s.acceptance_rate("extract") - 0.75) > 1e-9:
        p.append(f"acceptance rate is {s.acceptance_rate('extract')!r}, expected 0.75 from the events")
    s.corrupt_stored_counters()
    if abs(s.acceptance_rate("extract") - 0.75) > 1e-9:
        p.append("the rate moved when a stored counter was corrupted: it is not derived from events")
    return p


def ai8(s) -> "list[str]":
    """An expired draft cannot be accepted, and the work item it raised is handled, not orphaned (gate 8)."""
    d = s.create_draft({"total": "5"})
    s.expire(d)
    p = []
    try:
        s.decide(d, "pat", "accepted")
        p.append("an expired draft was accepted")
    except Refused:
        pass
    if s.work_item_state(d) not in ("closed", "expired"):
        p.append(f"the work item raised by the expired draft is {s.work_item_state(d)!r}: orphaned")
    return p


def ai9(s) -> "list[str]":
    """An agent can never approve: APPROVE is not grantable to an agent identity (gate 9)."""
    p = []
    if s.grantable_to_agent("APPROVE"):
        p.append("APPROVE is grantable to an agent identity")
    try:
        s.grant_to_agent("agent-1", "APPROVE")
        p.append("granting APPROVE to an agent was accepted")
    except Refused:
        pass
    return p


def ai10(s) -> "list[str]":
    """An agent never exceeds its bound role: each autonomous action is one the role could do unapproved (gate 10)."""
    return [f"agent action {a!r} is more than a person in the bound role could do without an approver"
            for a in s.agent_autonomous_actions() if not s.bound_role_can_without_approver(a)]


def ai11(s) -> "list[str]":
    """Every slot is bound: publishing a template with an unbound slot is refused, naming it (gate 11)."""
    try:
        s.publish_template(slots=["buyer", "approver"], bound={"buyer"})
        return ["a template with an unbound slot was published"]
    except Refused as e:
        return [] if "approver" in e.message else [f"the refusal does not name the unbound slot: {e.message!r}"]


def ai12(s) -> "list[str]":
    """The tree resolves: no dangling parent, no loop, and the stop list is the stopped subtree (gate 12)."""
    t = s.tree()
    parents, p = t["parents"], []
    for n, par in parents.items():
        if par is not None and par not in parents:
            p.append(f"{n} has a dangling parent {par}")
        seen, cur = set(), n
        while cur is not None and cur in parents:
            if cur in seen:
                p.append(f"the tree has a loop through {cur}")
                break
            seen.add(cur)
            cur = parents[cur]
    if p:
        return p
    root = t["stopped_root"]
    below = {n for n in parents if _under(n, root, parents)} | {root}
    return [] if set(t["stop_list"]) == below else [f"the stop list {sorted(t['stop_list'])} is not the stopped subtree {sorted(below)}"]


def _under(n, root, parents):
    cur = parents.get(n)
    while cur is not None:
        if cur == root:
            return True
        cur = parents.get(cur)
    return False


def ai13(s) -> "list[str]":
    """Oversight is independent: the role that oversees an agent is not the role that owns it (gate 13)."""
    return [f"agent {a} is overseen by the role that owns it" for a in s.agents() if s.owner_role(a) == s.overseer_role(a)]


def ai14(s) -> "list[str]":
    """Trust is pooled across scopes unless an override carries its own minimum evidence (gate 14)."""
    s.add_evidence("A", successes=90, total=100)
    s.add_evidence("B", successes=2, total=2)
    pooled = 92 / 102
    p = []
    if abs(s.trust("B") - pooled) > 0.01:
        p.append(f"a scope with two samples is trusted at {s.trust('B'):.2f}, not the pooled {pooled:.2f}")
    try:
        s.set_override("B", trust=0.5, evidence=3)
        p.append("an override with too little evidence was accepted")
    except Refused:
        pass
    s.set_override("B", trust=0.5, evidence=s.min_evidence() + 10)
    if abs(s.trust("B") - 0.5) > 1e-9:
        p.append("an override with enough evidence was not honoured")
    return p


class RefAI:
    """PROOF subject. Flaws: auto_post_path, blank_actor_ok, fills_from_world, rounds_value, silent_none,
    doc_level_only, constant_confidence, no_diff, after_only, unlabelled_response, unlabelled_record,
    fallback_drafts_anyway, stored_counter, accepts_expired, orphan_work_item, agent_grantable, exceeds,
    publishes_unbound, dangling_parent, loop, stop_list_stale, self_oversight, unpooled, override_without_evidence."""

    def __init__(self, flaws=frozenset()):
        self.f = frozenset(flaws)
        self.drafts, self.evts, self.invs, self.enabled = {}, {}, [], {"extract": True}
        self.decisions, self.counter, self.ev = [], {"acc": 99, "tot": 100}, {}
        self.overrides = {}

    def posting_paths(self):
        return ["post_invoice", "post_receipt"]

    def attempt_post(self, path, draft_id, actor):
        named = bool(actor and actor.strip())
        if not named and not ("auto_post_path" in self.f and path == "post_receipt") \
                and not ("blank_actor_ok" in self.f and actor is not None):
            raise Refused("no_named_human")
        return "posted"

    def draft(self, source):
        fields = {}
        for k in ("invoice_no", "total", "due_date", "note"):
            if k in source:
                v = source[k]
                if "rounds_value" in self.f and k == "total":
                    v = f"{float(v):.2f}"
                conf = None if "doc_level_only" in self.f else (0.5 if "constant_confidence" in self.f else
                                                                 (0.2 if "illegible" in v else 0.97))
                fields[k] = {"value": v, "confidence": conf, "source_span": k}
            elif k != "note":
                fields[k] = {"value": "2026-11-30" if "fills_from_world" in self.f else None,
                             "confidence": (0.5 if "constant_confidence" in self.f else 0.0) if "doc_level_only" not in self.f else None,
                             "reason": "" if "silent_none" in self.f else f"{k} is not present in the source"}
        return {"fields": fields}

    def create_draft(self, fields):
        d = f"d{len(self.drafts) + 1}"
        self.drafts[d] = {"fields": dict(fields), "state": "draft", "work": "open"}
        self.evts[d] = []
        return d

    def decide(self, d, actor, decision, edits=None):
        dr = self.drafts[d]
        if dr["state"] == "expired" and "accepts_expired" not in self.f:
            raise Refused("expired")
        diffs = []
        for k, after in (edits or {}).items():
            before = dr["fields"].get(k)
            if "no_diff" in self.f:
                continue
            diffs.append({"field": k, "after": after} if "after_only" in self.f else {"field": k, "before": before, "after": after})
            dr["fields"][k] = after
        dr["state"] = decision
        self.evts[d].append({"actor": actor, "decision": decision, "field_diffs": diffs})

    def events(self, d):
        return self.evts[d]

    def invoke(self, capability, provider):
        stub = provider == "stub"
        self.invs.append({"capability": capability, "stub": stub and "unlabelled_record" not in self.f})
        return {"result": "x", "stub": stub and "unlabelled_response" not in self.f}

    def invocations(self):
        return self.invs

    def set_enabled(self, cap, on):
        self.enabled[cap] = on

    def request_draft(self, cap, source):
        if not self.enabled.get(cap, False):
            if "fallback_drafts_anyway" in self.f:
                self.create_draft(source)
                return "fallback draft"
            raise Refused("capability_disabled")
        return self.create_draft(source)

    def draft_count(self):
        return len(self.drafts)

    def record_decision(self, cap, outcome):
        self.decisions.append((cap, outcome))
        self.counter["tot"] += 0

    def acceptance_rate(self, cap):
        if "stored_counter" in self.f:
            return self.counter["acc"] / self.counter["tot"] if self.counter["tot"] else 0.0
        ev = [o for c, o in self.decisions if c == cap]
        return sum(1 for o in ev if o == "accepted") / len(ev)

    def corrupt_stored_counters(self):
        self.counter = {"acc": 1, "tot": 100}
        if "stored_counter" in self.f:
            self.counter = {"acc": 1, "tot": 100}

    def expire(self, d):
        self.drafts[d]["state"] = "expired"
        self.drafts[d]["work"] = "open" if "orphan_work_item" in self.f else "closed"

    def work_item_state(self, d):
        return self.drafts[d]["work"]

    def grantable_to_agent(self, action):
        return action != "APPROVE" or "agent_grantable" in self.f

    def grant_to_agent(self, agent, action):
        if not self.grantable_to_agent(action):
            raise Refused("not_grantable")

    def agent_autonomous_actions(self):
        return ["invoice.draft", "payment.release"] if "exceeds" in self.f else ["invoice.draft"]

    def bound_role_can_without_approver(self, action):
        return action == "invoice.draft"

    def publish_template(self, slots, bound):
        missing = [x for x in slots if x not in bound]
        if missing and "publishes_unbound" not in self.f:
            raise Refused("unbound_slot", f"slot(s) not bound in this tenant: {missing}")

    def tree(self):
        parents = {"root": None, "plant": "root", "line": "plant", "cell": "line"}
        if "dangling_parent" in self.f:
            parents["cell"] = "ghost"
        if "loop" in self.f:
            parents["root"] = "cell"
        stop = {"plant", "line", "cell"}
        if "stop_list_stale" in self.f:
            stop = {"plant", "line"}
        return {"parents": parents, "stopped_root": "plant", "stop_list": stop}

    def agents(self):
        return ["agent-1", "agent-2"]

    def owner_role(self, a):
        return "OPS_LEAD"

    def overseer_role(self, a):
        return "OPS_LEAD" if "self_oversight" in self.f else "RISK_OFFICER"

    def add_evidence(self, scope, successes, total):
        self.ev[scope] = (successes, total)

    def min_evidence(self):
        return 30

    def trust(self, scope):
        if scope in self.overrides:
            return self.overrides[scope]
        s, t = self.ev[scope]
        if "unpooled" in self.f:
            return s / t
        ps, pt = sum(v[0] for v in self.ev.values()), sum(v[1] for v in self.ev.values())
        return ps / pt

    def set_override(self, scope, trust, evidence):
        if evidence < self.min_evidence() and "override_without_evidence" not in self.f:
            raise Refused("insufficient_evidence")
        self.overrides[scope] = trust


GATES: "list[Gate]" = [
    make_gate("AI-1", 8, "no path from a draft to a posted document without a named human", CANON + " 1", ai1, RefAI,
              "auto_post_path", "blank_actor_ok"),
    make_gate("AI-2", 8, "grounded refusal: gaps stay empty, values are not rounded", CANON + " 2", ai2, RefAI,
              "fills_from_world", "rounds_value", "silent_none"),
    make_gate("AI-3", 8, "field-level confidence exists and varies", CANON + " 3", ai3, RefAI,
              "doc_level_only", "constant_confidence"),
    make_gate("AI-4", 8, "an edit records the diff", CANON + " 4", ai4, RefAI, "no_diff", "after_only"),
    make_gate("AI-5", 8, "the stub announces itself", CANON + " 5", ai5, RefAI, "unlabelled_response", "unlabelled_record"),
    make_gate("AI-6", 8, "a disabled capability is absent", CANON + " 6", ai6, RefAI, "fallback_drafts_anyway"),
    make_gate("AI-7", 8, "acceptance rate is computed from real events", CANON + " 7", ai7, RefAI, "stored_counter"),
    make_gate("AI-8", 8, "an expired draft does not leak", CANON + " 8", ai8, RefAI, "accepts_expired", "orphan_work_item"),
    make_gate("AI-9", 8, "an agent can never approve", CANON + " 9", ai9, RefAI, "agent_grantable",
              note="Layer gate (W5 canon update); bases/core has no agent concept, proven on a reference subject."),
    make_gate("AI-10", 8, "an agent never exceeds its bound role", CANON + " 10", ai10, RefAI, "exceeds",
              note="Layer gate (W5 canon update); no counterpart in bases/core."),
    make_gate("AI-11", 8, "every slot is bound", CANON + " 11", ai11, RefAI, "publishes_unbound",
              note="Layer gate (W5 canon update); no counterpart in bases/core."),
    make_gate("AI-12", 8, "the tree resolves", CANON + " 12", ai12, RefAI, "dangling_parent", "loop", "stop_list_stale",
              note="Layer gate (W5 canon update); no counterpart in bases/core."),
    make_gate("AI-13", 8, "oversight is independent", CANON + " 13", ai13, RefAI, "self_oversight",
              note="Layer gate (W5 canon update); no counterpart in bases/core."),
    make_gate("AI-14", 8, "trust is pooled unless an override carries evidence", CANON + " 14", ai14, RefAI,
              "unpooled", "override_without_evidence",
              note="Layer gate (W5 canon update); no counterpart in bases/core."),
]
