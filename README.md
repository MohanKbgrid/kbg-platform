# KBG Platform

Everything a new product needs to inherit the cross-cutting platform: the **contracts** that say
what to build, and the **bases** you copy in as a starting point.

```
canon/     the specs — 9 surfaces and 1 seam, 12 doctrines, adoption guides   ← what TRAVELS between products
bases/
  core/    domain-free Python primitives to vendor
  ui-kit/  the visual and behavioural language to vendor
```

## Start here

**[`canon/README.md`](canon/README.md)** — the thesis, the twelve doctrines, the nine surfaces (plus the CRM seam) in
adoption order, the seven questions to ask of any requirement, and the signals that the platform is
being bypassed.

Then whichever adoption guide fits:
- **[Greenfield](canon/adoption/greenfield.md)** — a new product, born on the canon.
- **[Retrofit](canon/adoption/retrofit.md)** — an existing codebase, surface by surface, no big bang.

## How to use the bases

**Vendor them. Do not depend on them.** Copy `bases/core/src/kbg_platform_core/` (or
`bases/ui-kit/src/`) into your project, record the commit you copied from, and **own it from
there.** Change it freely to fit your codebase.

There is deliberately no `pip install` or `npm install` instruction. A shared dependency spanning
unrelated products becomes either a lowest-common-denominator that fits none of them, or a "shared"
package carrying per-project branches — which is worse than two honest copies.

```bash
git clone https://github.com/MohanKbgrid/kbg-platform.git /tmp/kbg
cp -r /tmp/kbg/bases/core/src/kbg_platform_core  <your-project>/app/vendor/
git -C /tmp/kbg rev-parse HEAD    # ← record this as your base commit
```

## The rule that makes divergence survivable

Copies drift, and a bug fixed in one product would otherwise stay live in the others. The
mitigation is not to re-couple the code:

> **Propagate the GATE, not the implementation.**

When a bug reveals a missing *rule*, the rule goes into that surface's spec and its gate-test list
in `canon/`. Every product then inherits the **test** while keeping its own code.

The example that proves it is in `bases/core`'s outbox: **a HELD row must not consume a retry
attempt.** That was learned by reading a live dispatcher, not by designing the base. A product that
copied before it was understood would dead-letter good events through its whole UAT period and find
out only when production went quiet. As a shared gate, it cannot happen twice.

## What is common, and what is not

The canon covers **patterns**. Implementations are product- and tenant-specific.

| Surface | Common — the pattern | Product / tenant specific |
|---|---|---|
| Accounting | control accounts + dimensional sub-ledgers · validate before mutate · corrections are new documents | chart of accounts, the dimension list, every posting adapter, GL codes |
| Integration | outbox keyed by a source id · the environment gate · an unmapped code refuses · mappings supersede | connectors, which dimensions exist, interface contracts, code values |
| UI/UX | the eight states · the table contract · the token *roles* · denied-visible-with-reason | markup, palette values, density, language, layout |

## Licence

- **Code** (`bases/`, `tools/`, `tests/`): [Apache-2.0](LICENSE).
- **Canon and docs** (`canon/`, `docs/`): [CC BY 4.0](LICENSE-docs). Credit "KB Grid".
- Keep the [NOTICE](NOTICE) file when you redistribute. If you build on this, a "Built on KBG Platform"
  line in your README is appreciated; it is a courtesy, not a condition.
- Contributions are accepted under the same licences with a DCO sign-off (`git commit -s`); there is no CLA.

`python tools/licence_check.py` verifies the licence files and the SPDX header on every source file.
