# Adoption — Retrofit (an existing codebase, surface by surface)

**Audience: the build agent for an existing KBG product.** Self-contained.
Worked example available on request.

You have a working application with real users and real data. You are not rewriting it. You are
adopting surfaces one at a time, in an order chosen so that each is useful on its own and none
requires a flag day.

## The governing constraint

**Every wave must leave the application shippable.** If a wave cannot be completed in a way that
leaves main deployable, it is too big — split it. A retrofit that requires a long-lived branch will
be abandoned when the business needs something urgent, and everything in that branch is lost.

## The order (same as greenfield, different reasons)

| Wave | Surface | Why here in a retrofit |
|---|---|---|
| 1 | **Tenancy** | If you are single-tenant today and will not change, you may **defer** this — the only wave that is genuinely optional. If you will *ever* be multi-tenant, do it first: the cost grows with every table. |
| 1 | **Config** | Highest value per hour. Pull hardcoded thresholds and env-var credentials into rows; nothing else has to change yet. |
| 1 | **RBAC** | The hard one. See the strangler pattern below. |
| 2 | **Workflow** | Replaces the `is_approved` booleans. Migrate one decision type at a time. |
| 2 | **Documents** | Usually additive — most apps have upload but not *required-blocking*. |
| 2 | **Experience** | Do it as screens are touched, not as a sweep. |
| 3 | **Integration** | Usually the most valuable after Config, because the environment gate stops a whole class of incident. |
| 3 | **Runtime AI** | Purely additive. Any time. |
| 4 | **Accounting** | **Last, and hardest.** Existing money semantics are already encoded somewhere. Decide the doctrine before writing one adapter. |

## Retrofitting RBAC without a flag day — the strangler

Do not attempt to convert every endpoint at once.

1. Build `can(actor, action, object)` alongside the existing checks. It answers, and it **logs**,
   but nothing depends on it yet.
2. Run it in **shadow mode**: every request evaluates both the old check and the new one, and
   logs disagreements. Let this run against real traffic.
3. Read the disagreements. Each is either a permission you have not modelled, or a bug in the old
   check. Both are worth knowing before you switch.
4. When disagreements reach zero for a route group, make `can()` authoritative for that group and
   delete the old check.
5. Only when all groups have flipped, turn on **deny by default** for unlisted actions.

The same shape works for pricing, posting, and anything else where an existing implementation must
be replaced without a gap: **compute both, log the divergence, flip when it is zero.**

## Retrofitting Accounting

The trap: an existing app has money semantics distributed across screens and reports. Extracting
them into a ledger *while also* changing the doctrine is two changes at once, and if the numbers
move you will not know which change moved them.

So:
1. **First, decide the control accounts and dimensions** — from the spec, with the client's finance
   owner. On paper. Before code.
2. **Build the ledger and post to it in parallel**, without changing a single existing number.
3. **Tie out.** For a closed period, the ledger must equal what the existing system reports, and you
   must state the denominator (D12): same grain, same unit, same period. Investigate every variance
   until it is explained or reconciling.
4. **Only then** switch reports to read from the ledger, one report at a time.
5. Retire the old computation last, and only for reports that have tied out for a full period.

## What "done" means for a wave

A wave is done when its **gate tests in the surface spec pass against your codebase** — not when the
code exists. Write the gates as tests in your own suite. If a gate does not apply to your domain,
record that in the divergence register with the reason; do not silently skip it.

## Common retrofit findings, so you recognise them

These recur. Finding them is progress, not bad news:

- **Two sources of truth for the same number**, disagreeing by a small amount nobody has explained.
- **A permission that exists only in the UI** — the endpoint is open.
- **An external call inside a request handler**, with a retry that silently swallows failures.
- **Financial corrections done with `UPDATE`**, so the audit trail is a table of current values.
- **A "required" field that is not enforced server-side.**
- **A scheduled job that has never actually run**, beside a comment describing its schedule.

Each is a real finding from this programme. Report them as you find them; they are usually more
valuable to the client than the wave you were sent to do.

## Reporting back

Per wave, report: what you built, **which gates ran and their counts**, what you found, what you
diverged on and why, and what you deliberately left. Never report a wave green without the gate
output — and if a gate could not run, say that instead of omitting it.
