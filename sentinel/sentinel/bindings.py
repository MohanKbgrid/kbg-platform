# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""Generic capabilities and domain bindings (ADR-005).

Agent work is built in three tiers; only the rows relevant to a domain and client are evaluated:

  1. Generic capability (framework, this module's CATALOGUE): the method and its loop in STRUCTURAL terms only
     (a subject in a scope, a series over a grain, a resource with capacity, a source with lead time ...).
  2. Domain binding (the domain pack, ``binding.yaml``): the domain's words mapped onto those structures, its
     role slots, and what may NEVER be automated there (clinical, statutory, tax, money posting ...).
  3. Client configuration (tenant): thresholds, scopes, slot bindings, switches (already in Sentinel).

Guardrails kept here:
  * generic by structure, not by words: users and screens keep the domain's words; nothing is renamed;
  * extract, don't pre-design: a capability enters CATALOGUE after it has worked in two or three domains;
  * domain law stays in the domain: the generic loop never decides what a domain forbids automating, so a
    binding that does not say (``never_automate:`` absent) is refused, and a never-automate action can never
    run unattended (a pattern using it is held below AUTO);
  * a tier-1 change reaches every domain at once, so it follows ADR-004 classification and ships switched off.

A binding (``binding.yaml`` in a pack)::

    domain: dairy
    binds:
    - capability: exception_watch
      map: {subject: product, scope: depot}
      patterns: [dairy_*]                   # the pack's patterns that implement it (glob)
    never_automate: [credit.write_off]     # required, may be []: an explicit statement, never a default
    slots: [accountable, escalation]
"""
from __future__ import annotations

import fnmatch
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field

from .models import Pattern, Route


class CapabilitySpec(BaseModel):
    """Tier 1: a capability in structural terms. ``structures`` must all be mapped by a binding;
    ``optional`` may be."""
    model_config = ConfigDict(extra="forbid")
    title: str
    loop: list[str]                                   # the method's steps, in structural words
    structures: list[str]                             # what a domain must map
    optional: list[str] = Field(default_factory=list)
    proven_in: list[str] = Field(default_factory=list)   # domains it has worked in (extract, don't pre-design)


# Only capabilities that already run in more than one domain's packs (ADR-005 guardrail 2). Demand planning is
# deliberately absent: it is extracted after the retail exemplar works.
CATALOGUE: dict[str, CapabilitySpec] = {
    "exception_watch": CapabilitySpec(
        title="Watch for an exception and route it to whoever is accountable",
        loop=["detect", "group", "route", "propose", "decide", "verify", "learn"],
        structures=["subject", "scope"], optional=["amount", "batch"],
        proven_in=["fulfilment", "dairy", "manufacturing", "hhome"]),
    "reconciliation": CapabilitySpec(
        title="Two or more records that must agree, and the unexplained gap between them",
        loop=["collect sides", "match", "explain known items", "raise the gap", "verify cleared"],
        structures=["side_a", "side_b", "period", "scope"], optional=["tolerance"],
        proven_in=["fulfilment", "finance", "dairy"]),
    "approval": CapabilitySpec(
        title="A request above someone's authority, approved by a person who holds it",
        loop=["propose", "check authority", "approve or forward", "execute", "record"],
        structures=["request", "amount", "approver_slot"], optional=["scope"],
        proven_in=["fulfilment", "dairy", "hhome"]),
}


class Bind(BaseModel):
    model_config = ConfigDict(extra="forbid")
    capability: str
    map: dict[str, str] = Field(default_factory=dict)  # generic structure -> domain word
    patterns: list[str] = Field(default_factory=list)  # pattern ids or globs implementing it


class DomainBinding(BaseModel):
    """Tier 2. ``never_automate`` is required (possibly empty): the domain must say it, never inherit it."""
    model_config = ConfigDict(extra="forbid")
    domain: str
    binds: list[Bind] = Field(default_factory=list)
    never_automate: list[str]
    slots: list[str] = Field(default_factory=list)


def load_binding(path: str | Path) -> DomainBinding:
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    if "never_automate" not in data:
        raise ValueError(f"{path}: never_automate is required (use [] to say nothing is forbidden here); "
                         "the framework never decides what a domain may automate")
    return DomainBinding.model_validate(data)


def check_binding(binding: DomainBinding, patterns: list[Pattern], slots: dict[str, str] | None = None,
                  catalogue: dict[str, CapabilitySpec] | None = None) -> list[str]:
    """Problems that refuse publish: unknown capability; a required structure left unmapped; a mapping to a
    structure the capability does not have; a bound pattern glob that matches nothing; a slot the binding
    declares that the registry does not; a never-automate action that a pattern could run unattended."""
    cat = catalogue if catalogue is not None else CATALOGUE
    out: list[str] = []
    ids = [p.id for p in patterns]
    for b in binding.binds:
        spec = cat.get(b.capability)
        if spec is None:
            out.append(f"{binding.domain}: unknown capability {b.capability!r} (catalogue: {sorted(cat)})")
            continue
        missing = [s for s in spec.structures if s not in b.map]
        if missing:
            out.append(f"{binding.domain}/{b.capability}: structures {missing} are not mapped to domain words")
        extra = [s for s in b.map if s not in spec.structures and s not in spec.optional]
        if extra:
            out.append(f"{binding.domain}/{b.capability}: {extra} are not structures of {b.capability}")
        for g in b.patterns:
            if not fnmatch.filter(ids, g):
                out.append(f"{binding.domain}/{b.capability}: pattern {g!r} matches nothing in the registry")
    if slots is not None:
        for s in binding.slots:
            if s not in slots:
                out.append(f"{binding.domain}: slot {s!r} is not declared in the registry's slots")
    forbidden = set(binding.never_automate)
    for p in patterns:
        hits = sorted({st.action for st in p.playbook if st.action in forbidden}
                      | (set(p.allowed_actions) & forbidden if p.max_route is not Route.HITL else set()))
        if hits and p.max_route is not Route.HITL:
            out.append(f"{binding.domain}: {p.id} may run {hits} unattended (max_route {p.max_route.value}) but "
                       "the domain never automates them; set max_route: hitl")
    return out


def enforce_never_automate(binding: DomainBinding, patterns: list[Pattern]) -> list[Pattern]:
    """Patterns with any never-automate action held at HITL (belt and braces for a runtime that loads a binding
    whose check was skipped). Others unchanged."""
    forbidden = set(binding.never_automate)
    out = []
    for p in patterns:
        uses = {st.action for st in p.playbook} | set(p.allowed_actions)
        out.append(p.model_copy(update={"max_route": Route.HITL, "route": Route.HITL})
                   if uses & forbidden and p.max_route is not Route.HITL else p)
    return out


def relevant(binding: DomainBinding, catalogue: dict[str, CapabilitySpec] | None = None) -> dict[str, Any]:
    """The catalogue rows this domain uses, with its words: only these are evaluated for it."""
    cat = catalogue if catalogue is not None else CATALOGUE
    return {b.capability: {"title": cat[b.capability].title, "words": dict(b.map)}
            for b in binding.binds if b.capability in cat}


__all__ = ["CATALOGUE", "Bind", "CapabilitySpec", "DomainBinding", "check_binding", "enforce_never_automate",
           "load_binding", "relevant"]
