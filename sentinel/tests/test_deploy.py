# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""The deploy bundle's example configs stay loadable as the code changes."""
from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from sentinel import ScriptedLLM, load_models

DEPLOY = Path(__file__).resolve().parent.parent / "deploy"


def test_models_example_loads():
    def factory(spec):
        c = ScriptedLLM(["{}"])
        c.model = spec["model"]
        c.embed = lambda texts: [[1.0] for _ in texts]
        return c
    r = load_models(DEPLOY / "site/config/models.yaml.example", factory=factory)
    assert set(r.routes) == {"triage", "diagnose"} and r.escalate_below == 0.75
    assert r.embedder.model == "nomic-embed-text"
    assert r.routes["triage"].primary.model == "qwen2.5:7b-instruct" and r.routes["triage"].fallback.model.startswith(
        "claude")


def test_connectors_example_checks_clean(engine):
    text = (DEPLOY / "site/config/connectors.yaml.example").read_text()
    _, probs = engine.check_config("connectors", text)
    assert not [p for p in probs if p.severity == "error"], probs


def test_gateway_example_loads():
    pytest.importorskip("fastapi")
    from sentinel.gateway import load_gateway_config
    text = (DEPLOY / "macmini/gateway.yaml.example").read_text()
    for i in range(text.count("REPLACE_WITH_64_HEX")):
        text = text.replace("REPLACE_WITH_64_HEX", str(i) * 64, 1)
    cfg = load_gateway_config(yaml.safe_load(text))
    assert {t.name for t in cfg.tenants.values()} == {"acme", "northwind-dairy"} and len(cfg.admins) == 1
    assert "~" not in cfg.usage_dir


def test_compose_dashboard_and_prometheus_are_valid():
    compose = yaml.safe_load((DEPLOY / "site/compose.yaml").read_text())
    assert {"db", "api", "worker", "prometheus", "grafana"} <= set(compose["services"])
    assert compose["services"]["db"]["image"].startswith("pgvector/pgvector:pg16")
    assert "ports" not in compose["services"]["db"]                      # database never published
    dash = json.loads((DEPLOY / "site/grafana/dashboards/sentinel.json").read_text())
    exprs = [t["expr"] for p in dash["panels"] for t in p["targets"]]
    assert len(dash["panels"]) >= 10 and all("sentinel_" in e for e in exprs)
    prom = yaml.safe_load((DEPLOY / "site/prometheus/prometheus.yml").read_text())
    assert {j["job_name"] for j in prom["scrape_configs"]} == {"sentinel-api", "sentinel-worker"}
    tokens = yaml.safe_load((DEPLOY / "site/config/tokens.yaml.example").read_text())
    assert all("sha256" in t for t in tokens["tokens"])


def test_env_example_has_no_real_secrets():
    env = (DEPLOY / "site/.env.example").read_text()
    for line in env.splitlines():
        if line.startswith(("ANTHROPIC_API_KEY=", "SENTINEL_GATEWAY_KEY=")):
            assert line.split("=", 1)[1] == ""
