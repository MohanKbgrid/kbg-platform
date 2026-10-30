// Example Cedar authority policy for the sample organisation used in the tests (Acme Home).
//
// Sentinel supplies WHO holds WHICH ROLE, here and now (the org tree, assignments, scopes, the stop list); these
// policies decide WHAT a role may do. A principal's `covers` is the set of roles it holds plus every role below
// them (seniors inherit their team's authority); `held` is the exact roles. An agent's `held` and `covers` are those
// of the human who holds its bound role, so an agent never exceeds its human. Four base policies are always added
// and cannot be removed: an agent never approves, an agent never acts on a proposal, nobody approves their own
// proposal, and a principal holding no role in scope is refused.
//
// Context: amount (decimal, absolute value, absent when no amount), amountParam, pattern, scope (a set of
// "dimension=value"), done (actions this actor already did on the object), hasProposers, isProposer.
//
// Check it loads and validates against schema.cedarschema:
//   from sentinel.cedar_authz import CedarBackend
//   b = CedarBackend.from_path("examples/cedar", schema_path="examples/cedar/schema.cedarschema")
//   print(b.load_error or "ok")

// Routine actions: the ops role and everything above it.
@id("ops-routine")
permit (principal,
        action in [Sentinel::Action::"retry", Sentinel::Action::"notify", Sentinel::Action::"hold"],
        resource)
when { principal.covers.contains(Sentinel::Role::"ops") };

// Cancelling: the lead role and above. (ops may only PROPOSE a cancel: there is deliberately no permit for ops.)
@id("lead-cancel")
permit (principal, action == Sentinel::Action::"cancel", resource)
when { principal.covers.contains(Sentinel::Role::"lead") };

// Refunds: a lead up to 10000, the head of operations without a limit. No amount given means a limited rule
// does not apply (a limit needs an amount to compare).
@id("lead-refund-up-to-10000")
permit (principal, action == Sentinel::Action::"refund", resource)
when { principal.covers.contains(Sentinel::Role::"lead") && context.amountParam == "amount" &&
       context has amount && context.amount.lessThanOrEqual(decimal("10000.0")) };

@id("head-refund")
permit (principal, action == Sentinel::Action::"refund", resource)
when { principal.covers.contains(Sentinel::Role::"ops_head") };

// Purchase orders: ops raise them, a lead approves up to 50000 on someone else's proposal, the head without a limit.
@id("ops-raise-po")
permit (principal, action == Sentinel::Action::"raise_po", resource)
when { principal.covers.contains(Sentinel::Role::"ops") };

@id("lead-approve-po-up-to-50000")
permit (principal, action == Sentinel::Action::"approve_po", resource)
when { principal.covers.contains(Sentinel::Role::"lead") && context.amountParam == "amount" &&
       context has amount && context.amount.lessThanOrEqual(decimal("50000.0")) && context.hasProposers };

@id("head-approve-po")
permit (principal, action == Sentinel::Action::"approve_po", resource)
when { principal.covers.contains(Sentinel::Role::"ops_head") };

// Writing off stock: only people who hold the lead role themselves (not seniors), for the billing pattern.
@id("lead-writeoff-billing")
permit (principal, action == Sentinel::Action::"write_off", resource)
when { principal.held.contains(Sentinel::Role::"lead") && ["billing"].contains(context.pattern) };

// Separation of duties: whoever raised a purchase order on an object may not approve it, and the reverse.
@id("sod-approve-po-after-raise-po")
forbid (principal, action == Sentinel::Action::"approve_po", resource)
when { context.done.contains("raise_po") };

@id("sod-raise-po-after-approve-po")
forbid (principal, action == Sentinel::Action::"raise_po", resource)
when { context.done.contains("approve_po") };
