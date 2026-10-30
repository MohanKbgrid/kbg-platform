# Extending Sentinel

Three levels, from smallest to largest. None of them change this repo: overlays live in their own
repos and depend on `kbg-sentinel` as a package. `examples/quickstart.py` is the smallest reference overlay.

## A. Add an exception class to an existing role (YAML only)

1. Add a fingerprint for the event type if it's new (`registry.yaml` → `fingerprints`).
2. Add a pattern. Start conservative:

```yaml
  - id: return_not_restocked
    description: Return received at the warehouse but not restocked within 48h.
    event_types: [return.pending_restock]
    match: {age: ">48h"}
    route: hitl            # always start here
    max_route: llm         # ceiling until you've seen it work
    allowed_actions: [restock_return, request_qc]
    disposition_codes: [restocked, sent_to_qc, no_action, false_positive]
    owner_role: fulfilment_exec
    escalation_role: fulfilment_lead
    sla_minutes: 240
    llm_instructions: >
      Check the return reason first. Damaged or used items go to QC, never straight to stock.
```

3. Run `python -m sentinel.cli validate` — the engine also refuses to start on an invalid registry.
   Optional fields worth knowing:
   - `sop:` the team's own procedure (Markdown). The model follows it and names the step it used; people
     see it on the review. Long procedures are cut to the sections that fit the case. Editing it keeps
     earned trust.
   - `trust_by: [channel]` earns trust separately per channel (see OPERATIONS.md).
   - `model_task: triage | investigate` sends the pattern to the small local model or a crew.
   - `llm_max_steps: 2` lets the model propose a sequence of actions (default one). `diagnose: false`
     stops the model preparing a proposal for cases a person handles (saves model cost on noisy patterns).
   - `match:` uses the same condition language as a playbook step's `when:` — a value, a list (one of),
     `"*"` (the fact is part of the fingerprint), operators (`{amount: {gt: 5000}}`; `eq ne gt gte lt lte
     in not_in contains exists empty matches`) and `all` / `any` / `not`.
   - Playbook `params` and lookup `args` are checked against what the action or tool declares: unknown
     names, missing required ones and literal values of the wrong type are refused when the registry is
     published.
   - Changing a pattern's meaning resets the trust it earned: its match, playbook, allowed actions and
     codes, and the fingerprint rules for its event types (which decide its facts). Descriptions, SOPs,
     SLAs and roles do not.
   Give people a `contact.email` (for single sign-on) and `edges` / `contact.whatsapp` (for review
   cards on Ask AI or WhatsApp) in the people configuration.
4. Run it in shadow (`shadow: true` on the pattern, or the console's Go live page) and watch its agreement
   before letting it act; take it live from the Go live page once it is ready.

## B. Add a role to an overlay (YAML + actions/tools) — e.g. your own overlay

A role is just: the patterns it owns (`owner_role`), the actions those patterns allow, and the read-only
tools its agent needs.

1. Add the role under `roles:`.
2. Add any new **actions** in the overlay's `actions.py`. Decide honestly:
   - `reversible=True` + a `@x.compensator` if it can be undone (move back, restore a value);
   - `safe=True` if it's idempotent and changes no business state (re-sync, refresh, request a count);
   - neither → it will always need a human. That's correct for refunds, cancellations, messages to customers.
   - Declare `params` so the LLM's output is type-checked. Raise `AdapterError` for retryable upstream
     failures; `KeyError`/`ValueError` become non-retryable.
3. Add **tools** (read-only) the agent needs to diagnose. Tools never write; the registry refuses
   non-read-only tools.
4. Add receivers for new sources in `receivers.py`.
5. Add scenario tests (see the demo overlay's tests for the shape): one per pattern, plus the role's promotion path.

Good next roles for ACME: Inventory Controller (stock drift patterns already exist), Returns
Executive, Finance Ops (payment patterns exist, capped at HITL), Customer Care (WISMO, address changes).

## C. Start a new project (new overlay repo)

```
northwind-sentinel/                    # its own repo
  pyproject.toml                   # depends on kbg-sentinel>=0.24 (or a git pin until the first release)
  northwind_sentinel/
    __init__.py      build_overlay() -> Overlay
    registry.yaml    roles, fingerprints, patterns
    adapters.py      interfaces to the project's systems (+ in-memory fakes for tests)
    actions.py       build_actions(), build_tools()
    receivers.py     source -> Event
  tests/test_northwind.py
```

Or start from a domain template (`sentinel template list`):

```
sentinel template show retail-fulfilment               # patterns, roles, and the actions it needs
sentinel template init retail-fulfilment --out northwind_sentinel/
```

`init` writes `registry.yaml` (a layer that says `template: retail-fulfilment`, so the template's
patterns are inherited and you change them with `overrides` / `disable`), `people.yaml`, and
`actions.py` with one stub per action the template needs. Load the registry with
`load_layers(["registry.yaml"])`. Until the real actions exist, `templates.stub_actions(registry, into=
actions)` fills the gaps with stubs that never change anything: a case that reaches one fails without
retry and goes to a person, and the audit names the stub. `sentinel --overlay ... template show <name>`
lists what the overlay still lacks.

Configuration that lives in the database (published through the console) can also be managed from the
command line, which suits change control in git:

```
sentinel --overlay ... config show registry > registry.yaml
sentinel --overlay ... config check registry registry.yaml
sentinel --overlay ... config publish registry registry.yaml --by mohan --note "SLA for timeouts"
```

`publish` refuses a file with errors and, with RBAC, needs the `__configure__` right.

Or copy `examples/quickstart.py`, delete its patterns, keep the structure. The engine, store, CLI,
guardrails and learning come for free. Run it with
`sentinel --overlay northwind_sentinel:build_overlay --db northwind.db report`.

Pin the framework to a tag (`@v0.1.0`) so a framework change never silently changes an overlay's
behaviour; upgrade deliberately and re-run the overlay's tests.

### Rules of thumb

- **Fingerprint for the unit of work a person would handle.** One ticket per order? `group_by: [order]`.
- **Every pattern starts at HITL** unless it has a deterministic playbook of safe/reversible steps.
- **Money and customer-facing irreversible actions: `max_route: hitl`.** Trust is not the point there.
- **Disposition codes are your training labels.** Keep them few, distinct and meaningful.
- **`__unmatched__` dispositions with `new_pattern_needed`** are your backlog for new patterns.


## D. Build a domain pack (reuse across customers)

A pack bundles one industry's exceptions, actions and tools so the next customer in that industry is a
configuration, not a fork. It is a directory with `sentinel-pack.yaml` (see `sentinel/packs.py` for every
field): an id and version, a `namespace` (all its actions and tools are named `<namespace>.<name>`), the
Sentinel versions it works with, the packs it needs, its registry layers, an optional `python:
module:register` that adds actions and tools through the namespaced `ctx`, what it `provides` and the
capabilities each needs (`write:sap.sales_order`), its settings (`config_schema`), and golden cases.

A site lists its packs, their settings and the capabilities it grants in a packs file, plus its own layer:

```yaml
packs:
  - {id: kbgrid.core-trunk, path: packs/core-trunk}
  - {id: kbgrid.dairy-dsd, path: packs/dairy-dsd, config: {sap_company_db: CO01},
     grant: [write:sap.sales_order, read:sap.customer]}
layers: [registry/northwind.yaml]
```

Run it with `--overlay sentinel.packs:from_env` and `SENTINEL_PACKS=packs.yaml`, or call
`sentinel.packs.build_overlay(path)` from an overlay. An action whose capabilities are not granted stays
listed but refuses to run, so its cases go to a person. Packs installed as Python packages are found through
the `sentinel.packs` entry point.

**Testing.** `sentinel pack check packs.yaml` loads the set, runs the conformance check
(`sentinel.testing.conformance`) and replays every pack's golden cases through the read-only trace. Use the
same functions in an overlay's own tests:

```python
from sentinel.testing import conformance, engine_for, run_golden
assert conformance(build_overlay()) == []
assert run_golden(engine_for(build_overlay()), "golden/") == []
```

**Role slots (ADR-003).** A pack's patterns name **slots**, never a customer's roles, so the same pack serves
any org. The pack declares its slots and uses `owner_slot` / `escalation_slot`; each tenant binds them in its own
layer:

```yaml
# pack layer                                  # tenant layer (or the console)
slots:                                        roles: {store_manager: ..., regional_manager: ...}
  accountable: Accountable for the scope      slot_bindings:
  escalation: Above the accountable one         accountable: store_manager
patterns:                                       escalation: regional_manager
- id: stock_signal
  owner_slot: accountable
  escalation_slot: escalation
```

Loading or publishing is refused while a slot a pattern uses is unbound, bound to an unknown role, or not
declared (when the pack declares slots), and a pattern may not name a slot and also write a role for the same
job (any role, even the bound one, so a stale role line can never block a later rebinding). An overlay built in
code resolves its `slots` / `slot_bindings` when the engine starts, and `sentinel.testing.conformance` reports an
unbound slot. A console rebinding is kept as a layer across pack upgrades. Rebinding changes who owns a case, not what
it means, so earned trust is kept. Patterns that still name `owner_role` work exactly as before. The R06
exemplar (`tests/packs/r06_stock_integrity`) shows one template bound by two store chains with different orgs.

**Domain bindings (ADR-005).** A pack says, in `binding.yaml`, how its domain's words map onto Sentinel's
generic capabilities (`sentinel.bindings.CATALOGUE`, written in structural terms: a subject in a scope, two sides
of a reconciliation, a request with an amount). It also says what the domain never automates:

```yaml
domain: retail
binds:
- {capability: exception_watch, map: {subject: article, scope: store}, patterns: ["r06_*"]}
never_automate: [stock.write_off]        # required; [] is a statement, a missing key is refused
slots: [accountable, shrink_owner, escalation]
```

Pass it as `Overlay(binding=load_binding(...))`. The check refuses engine start and registry publish for any of:
- an unmapped structure, or a mapping to a structure the capability does not have;
- an unknown capability;
- a pattern glob that matches nothing;
- an undeclared slot;
- any pattern that could run a never-automate action unattended.

A registry published before the binding existed that breaks it is never applied: the previous configuration keeps
running, and the refusal is audited as `config_apply_failed`. Even if the check is skipped, such patterns are held
at a person. Screens keep the domain's words. A capability
joins the catalogue only after it has worked in two or three domains, which is why demand planning is not in it
yet.

**Upgrades.** What people change in the console is stored as a layer over the packs (patterns added,
fields changed, patterns switched off). When a pack is upgraded, every process rebuilds the exceptions as
the new pack plus that layer: the console's changes stay and everything they did not touch comes from the
new version (audited as `registry_rebased`). If the layer no longer fits (it changes a pattern the new pack
removed), the published version keeps running and `registry_rebase_failed` says why.

**The catalogue.** KBGrid publishes the packs it maintains as a catalogue: `sentinel pack catalogue build
packs/ --out packs/catalogue.json` lists every pack with its version, industry, exceptions, the capabilities
its actions and tools need, its settings and a digest of its files (signed when
`SENTINEL_SECRET_CATALOGUE_KEY` is set). Keep the catalogue next to the packs. A site finds and adds packs
with `sentinel pack search dairy` and `sentinel pack add kbgrid.dairy-dsd --packs-file packs.yaml` (point
`SENTINEL_PACK_CATALOGUE` at the file, or pass `--catalogue`). `add` takes the newest version that works with
the site's Sentinel, checks the files, copies the pack and anything it needs that the site lacks, and lists
it with empty settings and nothing granted; adding a newer version later keeps the settings and grants. The
console's "Set up from a template" page shows the catalogue and what is installed.
