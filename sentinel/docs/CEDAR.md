# Cedar as the authority backend (optional)

`sentinel.org.authorise(directory, actor, action, obj, scope, amount)` answers "may this actor do this, here, for this
amount?" (ADR-003 C2). By default the built-in engine answers. This page covers the **optional Cedar backend**, which
answers the same question with [Cedar](https://www.cedarpolicy.com/) policies (Apache-2.0). The built-in engine is
unchanged and stays the default; nothing imports Cedar unless you use it.

```bash
pip install "kbg-sentinel[cedar]"        # adds cedarpy
```

```python
from sentinel.cedar_authz import CedarBackend
from sentinel.org import Agent, authorise

backend = CedarBackend.from_path("examples/cedar", schema_path="examples/cedar/schema.cedarschema")
dec = authorise(directory, Agent("r06@TVM01", bound_role="store_manager"), "task.count",
                scope={"store": "TVM01"}, amount=None, backend=backend)       # backend=None: the built-in engine
```

A domain core using `PolicySnapshot.authorise` can pass `backend=` too (it forwards keyword arguments).

## Who decides what

ADR-003 splits the organisation (C1) from authority policy (C2). The split is kept:

| Stays in Sentinel (C1, the `Directory`) | Decided by your Cedar policies (C2) |
|---|---|
| the role tree and the stop list | which role may do which action |
| who holds which role now, in this scope | how much (amount limits), for which pattern |
| which human an agent stands in for | separation of duties (who may not do both of two things) |
| whether a person is active | anything else you want to forbid, with Cedar's `forbid` |

So a policy never says "asha"; it says "a principal that covers role `ops`". Sentinel resolves "asha covers `ops` in
store TVM01 today" and hands that to Cedar as data.

## The request, translated

| Sentinel | Cedar |
|---|---|
| a person | principal `Sentinel::Person::"<id>"` with `active`, `held` (roles held now in scope) and `covers` (those and every role below them: seniors inherit their team's authority) |
| an agent | principal `Sentinel::Agent::"<id>"` with `hasHuman`, and `held`/`covers` **of the human who holds its bound role** (the nearest role at or above it with someone in scope, never past the stop list), so an agent is never stronger than its human |
| roles | `Sentinel::Role::"<id>"` entities; a role is `in` each role that reports to it |
| `action` | `Sentinel::Action::"<action>"` (`__approve__` for `APPROVE`) |
| `obj` | `Sentinel::Object::"<obj>"` |
| `amount` | `context.amount`, a Cedar `decimal`: the absolute value, rounded **up** to 4 places, clamped to Cedar's range; absent when there is no amount. A string, NaN or infinity is refused. |
| `amount_param`, `pattern` | `context.amountParam`, `context.pattern` |
| `scope` | `context.scope`, a set of `"dimension=value"` strings (a list value gives several) |
| `done_on_object[actor]` | `context.done`, a set of action names the actor already did on this object |
| `proposed_by` | `context.hasProposers`, `context.isProposer` |

## The policy file format

Plain Cedar. Use `@id("...")` so a refusal names the policy. A `.cedar` file, or a directory of them (read in name
order). See `examples/cedar/policies.cedar`; in short:

```cedar
@id("ops-routine")
permit (principal, action in [Sentinel::Action::"retry", Sentinel::Action::"hold"], resource)
when { principal.covers.contains(Sentinel::Role::"ops") };

@id("lead-refund-up-to-10000")
permit (principal, action == Sentinel::Action::"refund", resource)
when { principal.covers.contains(Sentinel::Role::"lead") && context has amount &&
       context.amount.lessThanOrEqual(decimal("10000.0")) };

@id("sod-approve-po-after-raise-po")
forbid (principal, action == Sentinel::Action::"approve_po", resource)
when { context.done.contains("raise_po") };
```

* `covers` is for rules that seniors inherit; `held` for rules only the holder has (`inherit: false`).
* Always guard the amount: `context has amount && ...`. A limit with no amount to compare must not allow.
* Cedar's default is deny; a `forbid` always wins over a `permit`.
* `schema_for(actions)` writes a Cedar schema for your actions; pass it as `schema=` / `schema_path=` and a typo in a
  policy is caught when the backend loads. `examples/cedar/schema.cedarschema` is the one for the example.
* `generate_policies(directory)` writes a policy set equal to a directory's authority rules and SoD pairs, a start
  for moving an existing configuration over.

### Always on, not removable

Four `forbid` policies (`BASE_POLICIES`) are appended to every policy set, so no policy you write can loosen them:

1. an agent never approves (`__approve__`): ADR-003 invariant 1;
2. an agent never acts on a proposal;
3. nobody approves a proposal they made;
4. a principal that holds no role in scope is refused, which includes an agent with no human to stand in for.

## Fail closed

A refusal, with the reason in `Decision.reason`, never an exception and never an allow, for: no policy set, an empty
one, one that does not parse or does not validate against the schema, a missing path, `cedarpy` not installed, a
malformed amount, an exception while translating the request or inside Cedar, and a policy that errors while being
evaluated (Cedar would skip it; here it refuses). `backend.ready` and `backend.load_error` tell you at startup.

## Differences from the built-in engine

* `escalate_to` (where to send a refused request) is routing, which is organisation structure: the Cedar backend
  returns `None` for it.
* A `sod=` argument is refused; write the pair as a `forbid` (as above).
* The wording of refusal reasons differs; `allowed` is what is held equal.
* Amounts: the request rounds up and a generated limit rounds down at 4 decimal places, so the Cedar side is never
  looser. A non-finite amount is always refused (the built-in engine would allow it under an unlimited rule).
* The engine's internal paths (`Directory.authorize_steps` for reviews, unattended playbooks) still use the built-in
  rules; this backend is for the `authorise()` contract that domain cores call.

## How parity is proven

`tests/test_cedar_authz.py` runs one table through both engines: 13 actors (people, an inactive and an unknown person,
agents bound to four roles and to a role that does not exist) x the example's actions plus unruled and meta actions x 3
scopes x 10 amounts (none, zero, at and just over each limit, negative, huge) x 4 proposal / separation-of-duties
variants x 2 patterns, over 20,000 cells, and requires the same `allowed` in every cell, for the hand-written
example policies and, on a richer directory (`inherit: false`, patterns, `needs_proposal`, propose-only rules,
a wildcard, another amount parameter, three stop lists), for `generate_policies` output.

| ADR-003 invariant | In `authorise()` with Cedar |
|---|---|
| 1. APPROVE is never grantable to an agent | refused by a base policy even under a policy set that permits everything; `AgentPolicy` still rejects the grant |
| 2. an agent never exceeds its bound role | tested: wherever an agent is allowed, the person holding the bound role is |
| 3. every slot is bound per tenant | enforced when configuration is published, not by `authorise()`; unchanged |
| 4. the tree resolves | enforced by `Directory`; unchanged |
| 5. oversight is not held by the owner | `Directory.oversight_problems`; unchanged |
| 6. trust is pooled across scopes | learning, not `authorise()`; unchanged |

Run them: `pip install -e ".[dev]" && pytest tests/test_cedar_authz.py` (they skip when `cedarpy` is absent;
`tests/test_cedar_absent.py` runs either way and checks the missing-extra refusal).
