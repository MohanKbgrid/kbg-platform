# KBG Platform

**Agents earn autonomy case by case: a person signs off every step up, and one reversal steps it back.**

KBG Platform is two things that work together:

- **The canon**: written specs for the nine cross-cutting surfaces every business application ends up needing
  (tenancy, config, access control, workflow, documents, experience, integration, runtime AI, accounting), with
  twelve doctrines and **runnable gates** that prove an implementation conforms.
- **Sentinel**: an installable agentic framework that recognises exceptions in business events, decides whether to
  resolve them automatically, ask a model or hand them to a person, and learns from what people decide.

```
canon/      the specs: 9 surfaces and 1 seam, 12 doctrines, adoption guides      (read, CC BY 4.0)
gates/      the conformance kit: runnable gate tests per canon surface            (run against your product)
bases/      code you COPY into a product and own: Python core, React UI kit      (vendor it)
sentinel/   the agentic framework                                                (pip install it)
docs/       one documentation site for every layer
tools/      licence, scrub and vendoring checks
```

## Try Sentinel in five minutes

```bash
git clone https://github.com/MohanKbgrid/kbg-platform && cd kbg-platform/sentinel
pip install -e ".[dev]"
python -m sentinel.demo          # a retailer on synthetic data; open http://localhost:8080/console
```

The demo needs no Docker, no database server and no API key. Steps, and a `docker compose` variant:
[sentinel/docs/DEMO.md](sentinel/docs/DEMO.md). Once the first release is on PyPI (see [docs/RELEASING.md](docs/RELEASING.md))
the install is `pip install "kbg-sentinel[api,postgres,analytics]"`.

## What you can rely on

| | |
|---|---|
| No event processed twice, no side effect executed twice | Inbox with a unique key; every action claims an idempotency key |
| Irreversible actions need a person | Only reversible or safe actions run unattended |
| Trust is earned slowly, lost instantly | Promotion needs a streak, an agreement rate and a person's sign-off; any reversal demotes at once |
| An agent never exceeds its human | `authorise()` on every agent-triggerable write; APPROVE is never grantable to an agent |
| Full audit | Append-only, sealed, secrets redacted |

The full table is in [sentinel/README.md](sentinel/README.md). Modes are OFF, OBSERVE, PROPOSE and ACT. Role slots
keep a template free of any one organisation. Each client keeps an adoption record of the version it runs.

## Where to start

- **Building a new product, or fixing an existing one:** [canon/README.md](canon/README.md), then
  [greenfield](canon/adoption/greenfield.md) or [retrofit](canon/adoption/retrofit.md).
- **Checking that you conform:** [gates/](gates/) (the conformance kit).
- **Starting from working code:** [bases/core](bases/core/README.md) and [bases/ui-kit](bases/ui-kit/README.md).
  **Vendor them, do not depend on them.** Copy the files in, record the commit you copied from, and own them from
  there. There is deliberately no shared dependency across unrelated products.
- **Running agents on business exceptions:** [sentinel/README.md](sentinel/README.md).

## Contributing

Read [CONTRIBUTING.md](CONTRIBUTING.md). Sign off your commits (`git commit -s`; there is no CLA). The roadmap is in
[ROADMAP.md](ROADMAP.md), how decisions are made is in [GOVERNANCE.md](GOVERNANCE.md), and security reports go to
[SECURITY.md](SECURITY.md).

## Licence

- **Code** (`bases/`, `tools/`, `tests/`): [Apache-2.0](LICENSE).
- **Canon and docs** (`canon/`, `docs/`): [CC BY 4.0](LICENSE-docs). Credit "KB Grid".
- Keep the [NOTICE](NOTICE) file when you redistribute. If you build on this, a "Built on KBG Platform"
  line in your README is appreciated; it is a courtesy, not a condition.
- Contributions are accepted under the same licences with a DCO sign-off (`git commit -s`); there is no CLA.

`python tools/licence_check.py` verifies the licence files and the SPDX header on every source file.
