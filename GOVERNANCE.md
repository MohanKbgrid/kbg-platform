# Governance

## Today: a benevolent maintainer

KB Grid started this project and its maintainer (Mohan, `@MohanKbgrid`) makes the final call. That is deliberately
simple while the project is young. It is not meant to stay a one-person decision forever.

## How decisions are made

- **Everyday changes** are decided in the pull request by the owner of the layer (see `.github/CODEOWNERS`).
- **Changes to the canon** (a surface, a doctrine, a gate) need a written reason: which real failure it prevents.
  The canon is derived from experience; a rule with no failure behind it does not go in.
- **Changes to Sentinel's contracts** (the event envelope, the overlay contract, `authorise()`, the config schema) are
  Breaking and follow the process in Sentinel ADR-004.
- **Anything that touches licensing, the NOTICE file, the release process or this document** is decided by the maintainer.

## Releases

Sentinel is released from a `sentinel-vX.Y.Z` tag by the maintainer, following [docs/RELEASING.md](docs/RELEASING.md).
The canon, gates and bases are versioned by commit: you vendor them, you record the commit.

## Becoming a maintainer

Someone who has landed several accepted changes in a layer, reviews others' changes well, and follows the code of
conduct can be invited to own that layer in `CODEOWNERS`. The maintainer decides, in the open, in an issue.

## Disagreement

Raise it in the issue or pull request, with the failure you expect. If it cannot be settled, the maintainer decides
and records why. A decision can be reopened by new evidence, not by repetition.

## Conduct

Enforced under [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## Licence changes

The licences (Apache-2.0 for code, CC BY 4.0 for the canon and docs) and the attribution in NOTICE are not changed
for contributions already accepted without the consent of their authors.
