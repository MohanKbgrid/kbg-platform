# Contributing

Thank you. This repository holds a canon (specs), a conformance kit (gates), bases you copy into your product, and
Sentinel (an agentic framework). Each layer is used differently, so each has its own reviewer (see `.github/CODEOWNERS`).

## Sign your commits (DCO). There is no CLA.

Add `Signed-off-by` with `git commit -s`. It certifies that you wrote the change or have the right to submit it
under the repository's licences (the [Developer Certificate of Origin](https://developercertificate.org/)).

## Licences

Code is Apache-2.0. The canon and docs (`canon/`, `docs/`) are CC BY 4.0. Every source file starts with an
`SPDX-License-Identifier` header. `python tools/licence_check.py` checks it.

## What we will not accept

- **Customer or internal-product names, anywhere.** Use neutral examples ("Acme Retail"). CI enforces this with a
  private pattern list; if it fails and you cannot see why, ask in the pull request.
- **Secrets**, tokens, real personal data.
- **A gate that cannot go red.** Every gate is proven red first: a planted defect turns it red, the clean subject is green.
- **A feature that is paid or licence-gated.** Nothing here is.

## How a change is made

1. Open an issue first for anything bigger than a fix, so we can say early whether it fits.
2. Branch, change, and run the checks for the layer you touched:

   | Layer | Run |
   |---|---|
   | everything | `python tools/licence_check.py` and `python -m pytest tests` |
   | `bases/core` | `python bases/core/test_core.py` |
   | `bases/ui-kit` | `cd bases/ui-kit && npm install && npm test && npm run typecheck && npm run build` |
   | `gates/` | `python -m gates --selftest` |
   | `sentinel/` | `cd sentinel && pip install -e ".[dev]" && ruff check sentinel tests examples scripts && python -m pytest` |

3. Put the **evidence in the commit message**: what you ran and the result. "Looks right" is not evidence.
4. A fixed defect gets a test that fails without the fix. Fix the class of the failure, not only the instance.
5. Open a pull request. It is reviewed by the owner of each layer it touches.

## Where a rule belongs

When a bug shows a missing rule, the rule becomes a **spec and a gate** in the canon, so every product inherits the
test while keeping its own implementation. A change to `canon/` states which surface, which doctrine, and which gate
proves it. Where the canon is wrong because a real business requirement disagrees, the business wins and the canon is
fixed here (see the canon README, "When this canon is wrong").

## Sentinel releases

Sentinel has its own version line and changelog. Classify every change (Compatible, Behavioural, Breaking) as in
`sentinel/docs/adr/ADR-004-continuous-evolution-per-client-adoption.md`. A canon edit never forces a Sentinel release.

## Good first issues

Issues labelled `good first issue` are small and have a clear definition of done. Documentation fixes, a missing
planted-defect test for an existing gate, and a neutral example for an existing doc are always welcome.

## Conduct and security

Be kind: [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). Security reports go to [SECURITY.md](SECURITY.md), not to an issue.
