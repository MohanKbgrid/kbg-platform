# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""Every gate of the kit is proven red-then-green: green on its good subject, red on EVERY planted defect."""
import pytest

from gates import registry, selftest

GATES = registry()
PLANTS = [(g.id, name) for g in GATES for name in g.plants]


def test_registry_is_not_empty_and_ids_are_unique():
    ids = [g.id for g in GATES]
    assert len(ids) >= 83 and len(set(ids)) == len(ids)


@pytest.mark.parametrize("gate", GATES, ids=lambda g: g.id)
def test_gate_is_green_on_its_good_subject(gate):
    assert gate.logic(gate.good()) == []


@pytest.mark.parametrize("gate_id,plant", PLANTS, ids=[f"{a}:{b}" for a, b in PLANTS])
def test_gate_is_red_on_each_planted_defect(gate_id, plant):
    g = next(x for x in GATES if x.id == gate_id)
    problems = g.logic(g.plants[plant]())
    assert problems, f"{gate_id} did not catch planted defect {plant!r}"
    assert all(isinstance(x, str) and x for x in problems)


@pytest.mark.parametrize("gate", GATES, ids=lambda g: g.id)
def test_selftest_agrees(gate):
    assert selftest(gate) == []


@pytest.mark.parametrize("gate", GATES, ids=lambda g: g.id)
def test_every_gate_cites_its_canon_line_and_has_a_plant(gate):
    assert gate.canon.startswith("canon/surfaces/") and gate.plants and gate.title


def test_planted_defects_of_one_gate_are_told_apart():
    """Where a gate checks several things, its plants trip different checks (not one catch-all complaint)."""
    g = next(x for x in GATES if x.id == "RBAC-5")
    firsts = {n: g.logic(mk())[0] for n, mk in g.plants.items()}
    assert len(set(firsts.values())) >= 3
