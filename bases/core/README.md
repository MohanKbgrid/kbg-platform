# kbg-platform-core

The small, **domain-free** primitives that enforce the [KBG Platform Surfaces canon](../../canon/README.md)'s doctrines. Artifact 2 of the canon.

## What this is — and deliberately is not

The canon's thesis is that **code is cheap to port but expensive to trust, so the global asset is
the CONTRACT, not the library.** That constrains what belongs here.

**In scope** — the handful of mechanisms every project would otherwise re-implement identically,
where re-implementing it *differently* is the actual bug:

| Module | Doctrine it makes hard to violate |
|---|---|
| `result` | **D4** — missing data is a finding. A caller cannot read a value without handling its absence. |
| `authority` | **D1** deny-by-default, and *one* function drives both the disabled button and the 403. A denial carries a **kind** (one of seven, default `AUTHORITY`) and a code; wraps an injected `authorise(actor, action, obj)`. |
| `rbac_shadow` | **D1, retrofit** — shadow evaluation that never denies; records `allow` / `would_deny` / `unmapped` / `error` and says per route group when it is safe to enforce (`coverage_report()`). Reference code for [`retrofit.md`](../../canon/adoption/retrofit.md). |
| `versioned` | **D2** — append-only. Changing a value supersedes; it never updates in place. |
| `outbox` | **D1 + Integration §10** — the environment gate. Non-production **holds**, it does not pretend. `Outbox` (sync store) and `AsyncOutbox` (async store) share one `decide()`; a held row consumes no attempt; a sync `Outbox` refuses an async store instead of losing the first enqueue (gate 8). |
| `job_run` | **Integration gates 6 and 7** — one helper records a run on success *and* failure and re-raises; a broken recorder is loud but never kills the job. Injected store. |
| `idem` | **D3** — idempotency by client-minted source id. |
| `testkit` | **D5 + D7** — prove the control controls; refuse to run against a non-fixture database. |

**Out of scope, on purpose:** ORM models, migrations, GL adapters, HTTP framework glue, anything
domain-specific. Those belong to each project, built against the contract in `docs/canon/` and
proven by that surface's gates. A package that shipped them would be exactly the "expensive to
trust" code the thesis warns about.

**No third-party runtime dependencies.** Pure standard library, so it drops into any Python project
regardless of ORM, web framework, or database driver. Adapters are *callables you pass in*.

## How to use this: **VENDOR it, do not depend on it**

Copy `src/kbg_platform_core/` into your project — e.g. `app/vendor/kbg_platform_core/` — and
**own it from there.** Record the commit you copied from in a `_VENDOR.md` beside it (start from
[`templates/_VENDOR.md`](../../templates/_VENDOR.md)), and gate it with
`python tools/vendor_check.py <your vendor dir>`: it fails if a file you recorded as untouched has
changed, or a file is unrecorded.

```bash
git clone https://github.com/MohanKbgrid/kbg-platform.git /tmp/kbg
cp -r /tmp/kbg/bases/core/src/kbg_platform_core  <your-project>/app/vendor/
git -C /tmp/kbg rev-parse HEAD             # ← record this as the base commit
```

There is deliberately **no pip install instruction.** This is a base, not a dependency.

### Why

A shared dependency that spans unrelated products becomes either a
lowest-common-denominator that fits none of them, or a "shared" package with per-project branches
inside it — which is worse than two honest copies. Accounting makes it concrete: one product's
control accounts and dimensions come from a one product's finance function, another's from a hospital.
Those are different objects, and no abstraction usefully covers both.

Vendoring buys something a dependency cannot: **one product can never break another.** Not
"unlikely" — structurally impossible. No version negotiation, no upgrade ritual, no pinning
discipline, and an agent working in that repo can read the whole thing without fetching anything.

### The cost, stated plainly

**A bug fixed in one project stays live in the others.** That is real, and the mitigation is not
to re-couple the code:

> **Propagate the GATE, not the implementation.**

When a bug reveals a missing *rule*, the rule goes into the canon's surface spec and its gate-test
list. Every project then inherits the *test* while keeping its own code. The rule that proves the
point is in `outbox.decide()`: **a HELD row must not consume a retry attempt.** That was learned by
reading a live dispatcher, not by designing this base. A project that copied before it was
understood would dead-letter good events through its entire UAT period and discover it only when
production went quiet.

So: copy freely, change freely, and when you learn something the base got wrong, fix the **spec and
its gate** — then optionally send the code change back here for the next project's starting point.


## Verify before you depend on it

```bash
python test_core.py            # 163 doctrine checks, nearly all NEGATIVE cases
python verify_consumable.py    # builds, installs, imports from the INSTALL not from ./src
```

The second one is not ceremony. The sibling UI package passed its typecheck and its unit gate
while being **impossible for any consumer to import** — nothing inside a package can catch that.

## Licence

Apache-2.0 (see `LICENSE` at the repository root). Keep the `NOTICE` file when you copy this into a product.
Copied files keep their SPDX header.
