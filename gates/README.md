# The conformance kit (`gates/`)

The canon (`canon/surfaces/`) lists, for every surface, the gate tests a product must pass. This
package makes them runnable. One module per surface; every gate cites the canon line it enforces
and is proven to be able to fail.

```
python -m gates --selftest          # prove every gate: green on its good subject, red on each planted defect
python -m gates --list              # the gates and the canon line each enforces
python -m gates --bindings gates.bindings_bases     # judge bases/core (the worked example)
python -m gates --bindings myproduct.gates_binding  # judge your product
```

Pure standard library, Python 3.10 or later. Exit code 0 means no gate FAILED; `--strict` also fails on
GAP and DORMANT.

## LOGIC, PROOF, BINDING

The split is the whole design. A gate is three things, kept apart.

| Layer | What it is | Who owns it |
|---|---|---|
| **LOGIC** | A function over a *subject* returning the list of problems it found (`[]` means the gate holds). It knows the canon and nothing about any product. | This kit |
| **PROOF** | A good reference subject and one or more planted-defect subjects. `selftest` requires the logic to pass the good one and be red on every planted one. A gate that cannot go red is not a gate. | This kit |
| **BINDING** | How *your* code becomes a subject: your tables, names, paths, routes. | The product |

The kit ships LOGIC and PROOF. It never ships a binding to a product, because the moment it did it
would be the product's code again and stop being the canon's.

A **subject** is any object offering the calls a gate's docstring names, for example
`s.availability(actor, action)` and `s.call(actor, action)` for RBAC-5. Read the gate's docstring and
the reference class at the foot of its module to see exactly what to implement.

## How a product binds the kit

Write a module that exposes `BINDINGS`: a mapping of gate id to a zero-argument callable returning a
subject. Bind only what your product has.

```python
# myproduct/gates_binding.py
from gates import Gap

class MyTenancy:                      # wraps your own test client / service layer
    def seed(self, company, ids): ...
    def list_rows(self, ctx, role=None): ...

def _no_outbox():
    raise Gap("the product has no outbox yet",
              appeared=lambda: module_exists("myproduct.outbox"))

BINDINGS = {"TEN-2": MyTenancy, "INT-8": _no_outbox}
```

Then `python -m gates --bindings myproduct.gates_binding`. For each gate the result is:

* **PASS**: the logic found no problem in your subject.
* **FAIL**: it found one; the problems are listed.
* **GAP**: your binding raised `Gap(reason)`, or you supplied none. The product cannot be judged
  yet. A gap is reported and never turned into a pass.
* **DORMANT**: a conditional gate whose condition has not occurred (`raise Dormant(...)`).

`Gap(reason, appeared=callable)` lets you say how to tell that the missing fact now exists. When
`appeared()` returns true and the binding still says Gap, the gate is a **FAIL**: a gap cannot
outlive its cause. See `gates/bindings_bases.py` for a worked binding, including two gaps that
turn into failures the day the base grows the missing field.

## Gate ids

`SURFACE-N`, where `N` is the canon's own gate-test number: `TEN` (1 tenancy), `CFG` (2 config),
`RBAC` (3), `WF` (4 workflow), `DOC` (5 documents), `UX` (6 experience), `INT` (7 integration),
`AI` (8 runtime AI), `ACC` (9 accounting), `CRM` (10 seam), and `DST` (the eight rules of
"Distributing master data offline" in the integration spec). `tests/gates/test_gates_canon_sync.py`
fails if the canon gains a numbered gate test that has no gate here.

## Where the base does not yet conform

A gate is never weakened to suit a base. Where `bases/core` lacks something a gate needs, the gate is
proven against a small reference subject in this package and the gate's `note` says so.

* RBAC-5 (reason **and kind**) and RBAC-9: `Decision` has no `kind` (canon divergence register, W5 H2).
* AI-9 to AI-14 (agent layers): the base has no agent concept.
* INT-1 to INT-3, INT-6, tenancy, workflow, ledger: the base does not model them; they are judged on
  the product.

## Writing a new gate

1. Add the canon line first (spec and numbered gate test), then the gate.
2. Write the logic against the *smallest* subject interface that exercises the rule.
3. Write a reference subject class taking a set of `flaws`; `make_gate(id, surface, title, canon,
   logic, RefClass, "flaw_a", "flaw_b")` builds the proof. Each flaw is a planted defect the logic
   must be red on.
4. `python -m gates --selftest` must be green. If a planted defect is not caught, the gate is wrong,
   not the plant.
