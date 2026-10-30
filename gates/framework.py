# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""The conformance-kit framework: what a gate is, how it is proven, how it is run.

A gate is three things, kept apart on purpose.

    LOGIC    a function over a SUBJECT (any object that offers the calls the canon gate makes)
             returning the list of problems it found. [] means the gate holds. Logic knows the
             canon and nothing about any product.
    PROOF    a good reference subject and one or more planted-defect subjects that ship with the
             gate. `selftest` requires the logic to pass the good subject and be RED on every
             planted one. A gate that cannot go red is not a gate, and cannot be wired.
    BINDING  how a product's own code becomes a subject. The kit never ships bindings to a
             product; a product supplies a mapping of gate id to a zero-argument callable that
             returns a subject (see README.md). When the product lacks a fact the gate needs, the
             binding raises `Gap(reason)`: reported, never swallowed, never turned into a pass.

A `Gap` may carry `appeared`, a callable returning True once the missing fact exists. A gate
that still reports its Gap after the fact has appeared is a FAIL, so a gap cannot outlive its
cause. `Dormant` is the same idea for a conditional gate whose condition has not occurred.
"""
from __future__ import annotations

import argparse
import importlib
import json
import sys
from dataclasses import dataclass
from typing import Any, Callable, Mapping, Optional, Sequence

PASS, FAIL, GAP, DORMANT = "PASS", "FAIL", "GAP", "DORMANT"


class Gap(Exception):
    """The product lacks a fact this gate needs. `reason` names it (and what would resolve it)."""

    def __init__(self, reason: str, appeared: Optional[Callable[[], bool]] = None) -> None:
        super().__init__(reason)
        self.reason, self.appeared = reason, appeared


class Dormant(Exception):
    """A conditional gate whose condition has not occurred yet."""


class Refused(Exception):
    """What a subject raises when the thing under test refuses an operation.

    `code` is machine-readable, `message` is for the person. Gates assert on both, because a
    refusal that does not name its cause is not a usable refusal (doctrine D4).
    """

    def __init__(self, code: str, message: str = "") -> None:
        super().__init__(message or code)
        self.code, self.message = code, message or code


@dataclass(frozen=True)
class Gate:
    id: str                                   # SURFACE-N, where N is the canon gate-test number
    surface: int                              # 1..10
    title: str
    canon: str                                # the canon line this gate enforces
    logic: Callable[[Any], "list[str]"]
    good: Callable[[], Any]                   # -> a subject the logic must pass
    plants: Mapping[str, Callable[[], Any]]   # name -> a defective subject the logic must be RED on
    note: str = ""                            # e.g. a base that does not yet conform
    conditional: bool = False


def make_gate(id: str, surface: int, title: str, canon: str, logic: Callable[[Any], "list[str]"],
              ref: Callable[..., Any], *flaw_names: str, note: str = "",
              conditional: bool = False) -> Gate:
    """Build a gate whose proof is one reference class taking a set of flaws.

    `ref()` is the good subject; `ref(frozenset({name}))` is the subject with that one defect.
    """
    plants = {n: (lambda n=n: ref(frozenset({n}))) for n in flaw_names}
    return Gate(id, surface, title, canon, logic, lambda: ref(), plants, note, conditional)


@dataclass
class Result:
    gate: str
    status: str
    detail: "list[str]"

    def as_dict(self) -> dict:
        return {"gate": self.gate, "status": self.status, "detail": self.detail}


def run_gate(gate: Gate, bindings: Mapping[str, Callable[[], Any]]) -> Result:
    """Judge a product: bind, then run the logic. PASS, FAIL, GAP or DORMANT."""
    bind = bindings.get(gate.id)
    if bind is None:
        return Result(gate.id, GAP, ["no binding supplied for this gate"])
    try:
        subject = bind()
    except Gap as e:
        if e.appeared is not None and e.appeared():
            return Result(gate.id, FAIL, [f"the missing fact has APPEARED ({e.reason}) but the "
                                          f"binding still reports a gap: write the binding"])
        return Result(gate.id, GAP, [e.reason])
    except Dormant as e:
        return Result(gate.id, DORMANT, [str(e)])
    problems = gate.logic(subject)
    return Result(gate.id, FAIL if problems else PASS, list(problems))


def selftest(gate: Gate) -> "list[str]":
    """The proof that the gate can fail. -> problems with the PROOF itself ([] = proven)."""
    bad: "list[str]" = []
    if not gate.plants:
        return [f"{gate.id}: no planted defect, so the gate has never been seen red"]
    try:
        found = gate.logic(gate.good())
        if found:
            bad.append(f"{gate.id}: the good reference subject is red: {found[:2]}")
    except Exception as e:  # noqa: BLE001 - a crashing gate is a proof failure, say so
        bad.append(f"{gate.id}: the gate crashed on the good subject: {type(e).__name__}: {e}")
    for name, make in gate.plants.items():
        try:
            if not gate.logic(make()):
                bad.append(f"{gate.id}: planted defect {name!r} was NOT caught")
        except Exception as e:  # noqa: BLE001
            bad.append(f"{gate.id}: planted defect {name!r} crashed the gate "
                       f"({type(e).__name__}: {e}) instead of turning it red")
    return bad


def registry() -> "list[Gate]":
    """Every gate of the kit, in surface order."""
    from . import (accounting, config, crm_seam, documents, experience,  # noqa: PLC0415
                   integration, integration_distribution, rbac, runtime_ai, tenancy, workflow)
    mods = (tenancy, config, rbac, workflow, documents, experience, integration, runtime_ai,
            accounting, crm_seam, integration_distribution)
    out: "list[Gate]" = []
    for m in mods:
        out.extend(m.GATES)
    return out


def load_bindings(spec: str) -> Mapping[str, Callable[[], Any]]:
    """`package.module` or `package.module:NAME` -> the BINDINGS mapping a product supplies."""
    mod, _, attr = spec.partition(":")
    return getattr(importlib.import_module(mod), attr or "BINDINGS")


def main(argv: Optional[Sequence[str]] = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m gates", description="KBG conformance kit")
    ap.add_argument("--selftest", action="store_true",
                    help="prove every gate: green on its good subject, red on every planted defect")
    ap.add_argument("--list", action="store_true", help="list the gates and the canon line each enforces")
    ap.add_argument("--bindings", metavar="MODULE[:NAME]",
                    help="judge a product: a module exposing a mapping of gate id to a subject factory")
    ap.add_argument("--surface", type=int, action="append", help="only this surface number (repeatable)")
    ap.add_argument("--strict", action="store_true", help="a GAP or DORMANT result also fails the run")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    a = ap.parse_args(argv)

    gates = [g for g in registry() if not a.surface or g.surface in a.surface]
    ids = [g.id for g in gates]
    if len(set(ids)) != len(ids):
        print("duplicate gate ids in the registry", file=sys.stderr)
        return 2

    if a.list:
        for g in gates:
            print(f"{g.id:8} {g.title}  [{g.canon}]")
        return 0

    if a.selftest:
        rc, planted, failed_plants = 0, 0, 0
        report = []
        for g in gates:
            bad = selftest(g)
            planted += len(g.plants)
            failed_plants += sum(1 for b in bad if "NOT caught" in b or "crashed the gate" in b)
            report.append({"gate": g.id, "planted": len(g.plants), "problems": bad})
            if not a.json:
                print(f"{g.id:8} selftest {'PASS' if not bad else 'FAIL'}  ({len(g.plants)} planted "
                      f"defect{'' if len(g.plants) == 1 else 's'})")
                for b in bad:
                    print("   " + b)
            rc |= 1 if bad else 0
        if a.json:
            print(json.dumps(report, indent=1))
        else:
            print(f"{len(gates)} gates, {planted} planted defects, {planted - failed_plants} caught: "
                  f"{'ALL PROVEN' if rc == 0 else 'PROOF FAILED'}")
        return rc

    bindings = load_bindings(a.bindings) if a.bindings else {}
    results = [run_gate(g, bindings) for g in gates]
    if a.json:
        print(json.dumps([r.as_dict() for r in results], indent=1))
    else:
        titles = {g.id: g.title for g in gates}
        for r in results:
            extra = ("  -- " + "; ".join(r.detail)[:300]) if r.detail else ""
            print(f"{r.status:7} {r.gate:8} {titles[r.gate]}{extra}")
        counts = {s: sum(1 for r in results if r.status == s) for s in (PASS, FAIL, GAP, DORMANT)}
        print("  ".join(f"{s} {n}" for s, n in counts.items()))
    bad = {FAIL} | ({GAP, DORMANT} if a.strict else set())
    return 1 if any(r.status in bad for r in results) else 0
