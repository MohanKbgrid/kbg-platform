# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""The optional Cedar backend for ``org.authorise``: parity with the built-in engine, the ADR-003 invariants,
fail-closed behaviour, the example policy set. Skips cleanly when the ``cedar`` extra (cedarpy) is absent."""
from __future__ import annotations

import itertools
from pathlib import Path

import pytest

pytest.importorskip("cedarpy")

from sentinel.cedar_authz import BASE_POLICIES, CedarBackend, generate_policies, schema_for  # noqa: E402
from sentinel.org import APPROVE, Agent, Person, SodRule, authorise  # noqa: E402
from sentinel.rbac import AgentPolicy, AuthorityRule, Directory, DirectoryError, Role  # noqa: E402
from tests.test_rbac import make_directory  # noqa: E402

EXAMPLES = Path(__file__).resolve().parent.parent / "examples" / "cedar"
EXAMPLE_ACTIONS = ["retry", "notify", "hold", "cancel", "refund", "raise_po", "approve_po", "write_off"]


def example_directory(**kw) -> Directory:
    """The directory the example policies were written for: the shared test org plus purchase orders."""
    def add(rules):
        return rules + [AuthorityRule(role_id="ops", action="raise_po"),
                        AuthorityRule(role_id="lead", action="approve_po", max_amount=50000, needs_proposal=True),
                        AuthorityRule(role_id="ops_head", action="approve_po"),
                        AuthorityRule(role_id="lead", action="write_off", patterns=["billing"], inherit=False)]
    return make_directory(rules_override=add, sod=[SodRule(first="raise_po", second="approve_po")], **kw)


@pytest.fixture(scope="module")
def example_backend() -> CedarBackend:
    b = CedarBackend.from_path(EXAMPLES, schema_path=EXAMPLES / "schema.cedarschema")
    assert b.ready, b.load_error
    return b


ACTORS = [Person("asha"), Person("ravi"), Person("lata"), Person("hari"), Person("hema"), Person("gone"),
          Person("ghost"), "ravi",
          Agent("a-ops", bound_role="ops"), Agent("a-lead", bound_role="lead"), Agent("a-head", bound_role="ops_head"),
          Agent("a-sup", bound_role="supervisor"), Agent("a-nowhere", bound_role="no_such_role")]
SCOPES = [{}, {"system": "billing"}, {"system": "hr"}]
AMOUNTS = [None, 0, 5000, 10000, 10000.0001, 10001, -20000, 50000, 50000.01, 1e18]


def _compare(directory, backend, actions, *, actors=ACTORS, scopes=SCOPES, amounts=AMOUNTS, **kw):
    """Run the whole table through both engines. Returns (cells, allowed, mismatches)."""
    cells = allowed = 0
    bad = []
    variants = [dict(), dict(proposed_by=["lata"]), dict(proposed_by=["asha"]),
                dict(done_on_object={"hari": ["raise_po"], "lata": ["approve_po"], "a-head": ["raise_po"]})]
    for actor, action, scope, amount, var, pattern in itertools.product(
            actors, actions, scopes, amounts, variants, ["*", "billing"]):
        args = dict(scope=scope, amount=amount, pattern=pattern, **var, **kw)
        want = authorise(directory, actor, action, "obj-1", **args)
        got = authorise(directory, actor, action, "obj-1", backend=backend, **args)
        cells += 1
        allowed += want.allowed
        if want.allowed != got.allowed:
            bad.append((actor, action, scope, amount, var, pattern, want.reason, got.reason))
    return cells, allowed, bad


# ------------------------------------------------------------------------------------------------ parity
def test_example_policies_agree_with_the_builtin_engine(example_backend):
    d = example_directory()
    cells, allowed, bad = _compare(d, example_backend, EXAMPLE_ACTIONS + ["task.count", APPROVE, "__promote__",
                                                                          "__kill_switch__"])
    assert not bad, bad[:3]
    assert cells > 20000 and 2000 < allowed < cells - 2000          # the table has plenty of both outcomes


def test_generated_policies_agree_on_a_richer_directory():
    """inherit: false, patterns, needs_proposal, propose-only rules, a wildcard, meta rules, another amount param,
    and a stop list that leaves an agent with no human."""
    def rich(rules):
        return rules + [AuthorityRule(role_id="ops", action="raise_po"),
                        AuthorityRule(role_id="lead", action="approve_po", max_amount=50000, needs_proposal=True),
                        AuthorityRule(role_id="lead", action="write_off", patterns=["billing", "hr"], inherit=False),
                        AuthorityRule(role_id="ops", action="adjust", max_amount=100, amount_param="qty"),
                        AuthorityRule(role_id="ops", action="sweep", level="propose"),
                        AuthorityRule(role_id="supervisor", action="*", max_amount=300),
                        AuthorityRule(role_id="ops_head", action="adjust")]
    for stop in ([], ["ops_head"], ["ops_head", "supervisor"], ["ops_head", "lead"]):
        d = make_directory(rules_override=rich, sod=[SodRule(first="raise_po", second="approve_po"),
                                                     SodRule(first="count", second="adjust")], stop_at=stop)
        b = CedarBackend(generate_policies(d))
        assert b.ready, b.load_error
        cells, allowed, bad = _compare(d, b, ["raise_po", "approve_po", "write_off", "adjust", "sweep", "count",
                                              "retry", "__promote__", APPROVE], amounts=[None, 99, 100, 101, -300, 301],
                                       amount_param="qty")
        assert not bad, (stop, bad[:3])
        assert allowed > 500
        _, _, bad2 = _compare(d, b, ["adjust", "count"], amounts=[None, 50, 100, 101])      # default amount param
        assert not bad2, (stop, bad2[:3])


def test_a_stop_list_with_a_vacant_role_leaves_the_agent_without_a_human(example_backend):
    d = example_directory(stop_at=["ops_head", "supervisor"])
    a = Agent("a-sup", bound_role="supervisor")
    want = authorise(d, a, "retry", scope={})
    got = authorise(d, a, "retry", scope={}, backend=example_backend)
    assert not want.allowed and not got.allowed and "nobody holds" in got.reason


# ------------------------------------------------------------------------------------------------ invariants
def test_invariant_1_approve_is_never_grantable_to_an_agent(example_backend):
    d = example_directory()
    with pytest.raises(ValueError, match="APPROVE is never grantable"):
        AgentPolicy(template="p", mode="ACT", grants={APPROVE: "EDIT"})
    # even a policy set that permits everything cannot make an agent approve
    open_set = CedarBackend('@id("allow-all") permit (principal, action, resource);')
    for b in (example_backend, open_set):
        for bound in ("ops", "lead", "ops_head"):
            dec = authorise(d, Agent("a1", bound_role=bound), APPROVE, backend=b)
            assert not dec.allowed and "agent_never_approves" in dec.checks and "never granted to an agent" in dec.reason
            dec2 = authorise(d, Agent("a1", bound_role=bound), "retry", proposed_by=["lata"], backend=b)
            assert not dec2.allowed
    # and the built-in engine says the same
    assert not authorise(d, Agent("a1", bound_role="ops_head"), APPROVE).allowed


def test_invariant_2_an_agent_never_exceeds_its_bound_role(example_backend):
    d = example_directory()
    pairs = [("ops", Person("ravi")), ("lead", Person("lata")), ("ops_head", Person("hari"))]
    for bound, human in pairs:
        for action, amount, scope, pattern in itertools.product(
                EXAMPLE_ACTIONS + ["task.count"], AMOUNTS, SCOPES, ["*", "billing"]):
            agent = authorise(d, Agent("a", bound_role=bound), action, "o", scope, amount, pattern=pattern,
                              backend=example_backend)
            person = authorise(d, human, action, "o", scope, amount, pattern=pattern, backend=example_backend)
            assert person.allowed or not agent.allowed, (bound, action, amount, scope, pattern)
    # an agent bound to a junior role cannot do a senior role's action
    assert not authorise(d, Agent("a", bound_role="ops"), "refund", scope={}, amount=100, backend=example_backend)
    assert authorise(d, Agent("a", bound_role="ops_head"), "refund", scope={}, amount=100, backend=example_backend)


def test_invariants_3_to_6_do_not_depend_on_the_backend():
    """Slots bound per tenant (3), a resolvable tree (4), oversight not held by the owner (5) and pooled trust (6)
    are checked when configuration is published or learning runs, before and apart from ``authorise``; choosing the
    Cedar backend changes none of them. The two a Directory itself enforces are asserted here."""
    with pytest.raises(DirectoryError):
        Directory([Role(id="a", parent="b"), Role(id="b", parent="a")])        # 4: no loop
    with pytest.raises(DirectoryError):
        Directory([Role(id="a", parent="ghost")])                              # 4: no dangling parent
    from sentinel.rbac import OversightRule

    class Pat:
        id, owner_role, escalation_role, capability = "p", "ops", None, None
    d = make_directory(oversight=[OversightRule(role="ops", templates=["p"])])
    assert d.oversight_problems([Pat()])                                       # 5: the watched may not grade itself


# ------------------------------------------------------------------------------------------------ fail closed
def test_fail_closed(tmp_path, monkeypatch, example_backend):
    d = example_directory()
    good = authorise(d, Person("ravi"), "retry", backend=example_backend)
    assert good.allowed
    # no policy set, empty set, unparsable set, missing file, empty directory
    for b in (CedarBackend(None), CedarBackend("   "), CedarBackend("permit (principal"),
              CedarBackend.from_path(tmp_path / "nope.cedar"), CedarBackend.from_path(tmp_path)):
        assert not b.ready and b.load_error
        dec = authorise(d, Person("ravi"), "retry", backend=b)
        assert not dec.allowed and dec.reason.startswith("cedar:")
    # a policy set that fails schema validation
    bad_schema = CedarBackend('permit (principal, action == Sentinel::Action::"unknown_action", resource);',
                              schema=schema_for(["retry"]))
    assert not bad_schema.ready and "validate" in bad_schema.load_error
    assert not authorise(d, Person("ravi"), "retry", backend=bad_schema).allowed
    # a malformed amount, an infinite one, and a sod= override are refused, never guessed
    for amt in ("lots", float("nan"), float("inf")):
        assert not authorise(d, Person("hari"), "refund", amount=amt, backend=example_backend).allowed
    sod = authorise(d, Person("ravi"), "retry", sod=[SodRule(first="a", second="b")], backend=example_backend)
    assert not sod.allowed and "sod=" in sod.reason
    # an exception inside Cedar, and one while translating the request
    import cedarpy

    def boom(*a, **k):
        raise RuntimeError("engine fell over")
    monkeypatch.setattr(cedarpy, "is_authorized", boom)
    dec = authorise(d, Person("ravi"), "retry", backend=example_backend)
    assert not dec.allowed and "RuntimeError" in dec.reason
    monkeypatch.undo()
    class Unprintable:
        def __str__(self):
            raise RuntimeError("no text form")
    odd = authorise(d, Person("ravi"), "retry", scope={"system": Unprintable()}, backend=example_backend)
    assert not odd.allowed and odd.reason.startswith("cedar:")
    # a policy that errors at evaluation (amount read without a `has` guard) refuses instead of being skipped
    sloppy = CedarBackend('permit (principal, action == Sentinel::Action::"refund", resource) when '
                          '{ context.amount.lessThanOrEqual(decimal("5.0")) };\n'
                          'permit (principal, action == Sentinel::Action::"refund", resource);')
    assert sloppy.ready
    dec = authorise(d, Person("hari"), "refund", amount=None, backend=sloppy)
    assert not dec.allowed and "evaluation error" in dec.reason


def test_default_is_the_builtin_engine_unchanged():
    d = example_directory()
    a = authorise(d, Person("ravi"), "retry")
    b = authorise(d, Person("ravi"), "retry", backend=None)
    assert (a.allowed, a.reason, a.checks) == (b.allowed, b.reason, b.checks) and a.allowed
    assert "cedar" not in a.checks


# ------------------------------------------------------------------------------------------------ the example set
def test_example_files(example_backend):
    assert (EXAMPLES / "schema.cedarschema").read_text(encoding="utf-8").endswith(
        schema_for(EXAMPLE_ACTIONS))                                                # the schema file is current
    text = (EXAMPLES / "policies.cedar").read_text(encoding="utf-8")
    assert "Acme" in text and BASE_POLICIES.count("forbid") == 4
    ok = authorise(example_directory(), Person("lata"), "refund", "o", {}, 9000, backend=example_backend)
    assert ok.allowed and ok.decided_by_role == "lead" and "policy:lead-refund-up-to-10000" in ok.checks
    no = authorise(example_directory(), Person("lata"), "refund", "o", {}, 12000, backend=example_backend)
    assert not no.allowed and "no policy permits" in no.reason
    sod = authorise(example_directory(), Person("hari"), "approve_po", "o", {}, 10,
                    done_on_object={"hari": ["raise_po"]}, backend=example_backend)
    assert not sod.allowed and "sod-approve-po-after-raise-po" in sod.reason


def test_orgsync_passes_the_backend_through(example_backend):
    """A domain core's PolicySnapshot.authorise forwards keyword arguments, so it can use the backend too."""
    from sentinel.org import authorise as org_authorise
    d = example_directory()
    dec = org_authorise(d, Person("ravi"), "retry", backend=example_backend)
    assert dec.allowed and "cedar" in dec.checks
