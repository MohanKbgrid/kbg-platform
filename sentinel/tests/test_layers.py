# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""Pattern versioning (trust resets on meaning changes) and the layered registry."""
from __future__ import annotations

import pytest

from sentinel import Engine, Guardrails, LayerError, Overlay, Pattern, Route, SQLiteStore, load_layers
from tests.conftest import Backend, job_event, make_overlay

# ------------------------------------------------------------------ versioning

def _with_pattern(backend, change):
    ov = make_overlay(backend)
    ov.patterns[0] = ov.patterns[0].model_copy(update=change)
    return ov


def test_meaning_change_resets_trust_but_cosmetics_do_not(tmp_path, clock):
    db = str(tmp_path / "v.db")
    backend = Backend()
    e1 = Engine(make_overlay(backend), store=SQLiteStore(db), clock=clock,
                guardrails=Guardrails(allow_irreversible_unattended=True))
    e1.ingest(job_event())
    e1.set_route("job_timeout", Route.HITL, actor="x")
    e1.set_route("job_timeout", Route.AUTO, actor="x")
    assert e1.store.get_pattern_state("job_timeout").route is Route.AUTO
    e1.store.close()

    # cosmetic change: description and SLA -> trust kept
    e2 = Engine(_with_pattern(backend, {"description": "reworded", "sla_minutes": 30}), store=SQLiteStore(db),
                clock=clock)
    assert e2.effective_route(e2.registry.get("job_timeout")) is Route.AUTO
    e2.store.close()

    # meaning change: the playbook now does something else -> trust resets to the pattern's default
    e3 = Engine(_with_pattern(backend, {"route": Route.HITL, "allowed_actions": ["retry", "notify", "hold"]}),
                store=SQLiteStore(db), clock=clock)
    p = e3.registry.get("job_timeout")
    assert e3.effective_route(p) is Route.HITL
    changes = [a for a in e3.store.audit_log() if a["kind"] == "pattern_changed"]
    assert len(changes) == 1 and changes[0]["data"]["route_was"] == "auto"
    e3.effective_route(p)
    assert len([a for a in e3.store.audit_log() if a["kind"] == "pattern_changed"]) == 1   # reset once


def test_definition_hash_ignores_cosmetic_fields():
    a = Pattern(id="p", event_types=["e"], description="one", sla_minutes=10, owner_role="x")
    b = a.model_copy(update={"description": "two", "sla_minutes": 99, "owner_role": "y", "severity": "high"})
    c = a.model_copy(update={"match": {"k": 1}})
    assert a.definition_hash() == b.definition_hash() != c.definition_hash()

# ------------------------------------------------------------------ layers

TRUNK = """
layer: trunk
roles: {ap_exec: AP Executive, inv_ctrl: Inventory Controller, supervisor: Supervisor}
fingerprints:
  - {event_type: po.mismatch, fields: {vendor: vendor, kind: kind}}
  - {event_type: stock.negative, fields: {location: location}}
patterns:
  - {id: po_grn_invoice_mismatch, event_types: [po.mismatch], owner_role: ap_exec, sla_minutes: 480}
  - {id: negative_stock, event_types: [stock.negative], owner_role: inv_ctrl}
  - {id: master_data_duplicate, event_types: [mdm.duplicate], owner_role: supervisor}
"""

RETAIL = """
layer: retail
roles: {fulfil_exec: Fulfilment Executive}
fingerprints:
  - {event_type: stock.negative, fields: {location: location, channel: channel}}
patterns:
  - {id: order_stuck, event_types: [order.unfulfilled], owner_role: fulfil_exec}
overrides:
  - {id: negative_stock, set: {sla_minutes: 60, severity: high}}
"""

ACME = """
layer: acme
disable: [master_data_duplicate]
overrides:
  - {id: po_grn_invoice_mismatch, set: {sla_minutes: 240}}
"""


def _write(tmp_path, **docs):
    out = []
    for name, body in docs.items():
        f = tmp_path / f"{name}.yaml"
        f.write_text(body)
        out.append(f)
    return out


def test_layers_merge_extend_override_disable(tmp_path):
    doc = load_layers(_write(tmp_path, trunk=TRUNK, retail=RETAIL, acme=ACME))
    pats = {p.id: p for p in doc.patterns}
    assert set(pats) == {"po_grn_invoice_mismatch", "negative_stock", "order_stuck"}
    assert pats["negative_stock"].layer == "trunk" and pats["negative_stock"].overridden_in == ["retail"]
    assert pats["negative_stock"].sla_minutes == 60 and pats["negative_stock"].severity == "high"
    assert pats["po_grn_invoice_mismatch"].sla_minutes == 240 and pats["order_stuck"].layer == "retail"
    fp = {f.event_type: f for f in doc.fingerprints}
    assert set(fp["stock.negative"].fields) == {"location", "channel"}       # retail replaced trunk's rule
    assert set(doc.roles) == {"ap_exec", "inv_ctrl", "supervisor", "fulfil_exec"}


def test_layer_errors(tmp_path):
    with pytest.raises(LayerError, match="use overrides"):
        load_layers(_write(tmp_path, trunk=TRUNK, again=TRUNK))
    with pytest.raises(LayerError, match="unknown pattern"):
        load_layers(_write(tmp_path, trunk=TRUNK, x="overrides: [{id: ghost, set: {sla_minutes: 1}}]\n"))
    with pytest.raises(LayerError, match="cannot disable"):
        load_layers(_write(tmp_path, trunk=TRUNK, x="disable: [ghost]\n"))
    with pytest.raises(LayerError, match="may not change id"):
        load_layers(_write(tmp_path, trunk=TRUNK, x="overrides: [{id: negative_stock, set: {id: other}}]\n"))
    with pytest.raises(LayerError, match="is invalid"):
        load_layers(_write(tmp_path, trunk=TRUNK, x="overrides: [{id: negative_stock, set: {sla_minutes: abc}}]\n"))
    with pytest.raises(LayerError, match="unknown top-level"):
        load_layers(_write(tmp_path, x="patternz: []\n"))
    with pytest.raises(LayerError, match="unknown role"):
        load_layers(_write(tmp_path, trunk=TRUNK, x="patterns: [{id: z, event_types: [e], owner_role: ghost}]\n"))


def test_layered_registry_runs_in_an_engine(tmp_path):
    doc = load_layers(_write(tmp_path, trunk=TRUNK, retail=RETAIL, acme=ACME))
    eng = Engine(Overlay(name="layered", fingerprint_rules=doc.fingerprints, patterns=doc.patterns, roles=doc.roles))
    from sentinel import Event
    r = eng.ingest(Event(type="stock.negative", source="wms", payload={"location": "WH", "channel": "shopify"}))
    inc = eng.store.get_incident(r.incident_id)
    assert inc.pattern_id == "negative_stock" and inc.facts["channel"] == "shopify"
    assert eng.store.open_review_for(inc.id).assignee_role == "inv_ctrl"
