# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""Operator CLI: work the review queue, inspect learning, run maintenance. No UI needed to start.

    python -m sentinel.cli --overlay acme_sentinel:build_overlay --db acme.db reviews
    python -m sentinel.cli ... approve rev_123 --by priya
    python -m sentinel.cli ... modify  rev_123 --action some_action --params "{\\"ref\\":\\"X-1\\"}" --by priya
    python -m sentinel.cli ... reject  rev_123 --code false_positive --by priya
    python -m sentinel.cli ... report | promotions | approve-promotion <pattern> --by mohan
    python -m sentinel.cli ... set-route <pattern> hitl --by mohan
    python -m sentinel.cli ... sweep | recover | validate | show <incident_id>
    python -m sentinel.cli ... trace event.json [--registry draft.yaml] [--lookups] | case <incident_id>
    python -m sentinel.cli template list | show <name> | init <name> --out ./my-project
    python -m sentinel.cli ... config show registry | check registry r.yaml | publish registry r.yaml --by mohan

Overlay: --overlay module:factory (or env SENTINEL_OVERLAY), e.g. acme_sentinel:build_overlay.
Store: --db <sqlite file>  or  --pg <dsn> (or env SENTINEL_PG).  LLM: --models models.yaml (or env SENTINEL_MODELS),
or --claude for Claude only (needs ANTHROPIC_API_KEY).
"""
from __future__ import annotations

import argparse
import importlib
import json
import os
import sys
from typing import Any

from .engine import Engine, EngineError
from .models import Decision, DecisionKind, Route


def _load(spec: str) -> Any:
    mod, _, attr = spec.partition(":")
    obj = getattr(importlib.import_module(mod), attr or "build_overlay")
    return obj() if callable(obj) else obj


def _engine(a: argparse.Namespace, *, async_mode: bool = False) -> Engine:
    if a.pg or os.environ.get("SENTINEL_PG"):
        from .pg_store import PostgresStore
        store = PostgresStore(a.pg or os.environ["SENTINEL_PG"], schema=a.schema)
    else:
        from .store import SQLiteStore
        store = SQLiteStore(a.db)
    llm = None
    if getattr(a, "models", None):
        from .providers import load_models
        llm = load_models(a.models)
    elif a.claude:
        from .llm import AnthropicClient
        llm = AnthropicClient()
    directory = None
    if getattr(a, "directory", None):
        from .rbac import load_directory
        directory = load_directory(a.directory)
    return Engine(_load(a.overlay), store=store, llm=llm, directory=directory, async_mode=async_mode)


def _secret(name: str) -> str | None:
    from .envsecrets import lookup
    return lookup(name)


def _p(obj: Any) -> None:
    print(json.dumps(obj, indent=2, default=str))


def _template(a: argparse.Namespace, eng: Engine | None) -> int:
    from pathlib import Path

    from . import templates
    if a.tcmd == "list":
        _p(templates.all_summaries())
        return 0
    try:
        if a.tcmd == "show":
            t = templates.summary(a.name)
            if eng is not None:
                t["missing"] = {"actions": [x for x in t["needs"]["actions"] if not eng.actions.has(x)],
                                "verifiers": [v for v in t["needs"]["verifiers"] if v not in eng.overlay.verifiers]}
            _p(t)
            return 0
        files = templates.scaffold(a.name)
    except KeyError as e:
        print(f"error: {e.args[0]} (known: {templates.names()})", file=sys.stderr)
        return 2
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    clash = [n for n in files if (out / n).exists()]
    if clash and not a.force:
        print(f"error: {clash} already exist in {out}; pass --force to overwrite", file=sys.stderr)
        return 1
    for n, text in files.items():
        (out / n).write_text(text, encoding="utf-8")
    _p({"written": [str(out / n) for n in files], "next": "implement the stubs in actions.py; "
        "load the registry with load_layers([registry.yaml]); validate with 'sentinel validate'"})
    return 0


def _config(a: argparse.Namespace, eng: Engine) -> int:
    from pathlib import Path

    from .config import KINDS, ApprovalNeeded, ConfigError
    if a.ccmd == "waiting":
        _p([cv.summary() for k in KINDS for cv in eng.store.config_versions(k) if cv.status == "draft"
            and cv.requested_by])
        return 0
    if a.ccmd == "replay":
        res = eng.replay(Path(a.file).read_text(encoding="utf-8"), days=a.days)
        _p(res)
        return 1 if res.get("error") else 0
    if a.ccmd == "approve":
        try:
            out = eng.approve_config(a.version_id, a.by)
        except Exception as e:  # noqa: BLE001 - shown to the operator
            print(f"error: {type(e).__name__}: {e}", file=sys.stderr)
            return 1
        _p({"published": [cv.summary() for cv in out], "still_waiting": not out})
        return 0
    if a.kind not in KINDS:
        print(f"error: kind must be one of {list(KINDS)}", file=sys.stderr)
        return 2
    if a.ccmd == "show":
        print(eng.config_text(a.kind), end="")
        return 0
    text = Path(a.file).read_text(encoding="utf-8")
    _, problems = eng.check_config(a.kind, text)
    listed = [{"severity": p.severity, "message": p.message} for p in problems]
    errors = [p for p in problems if p.severity == "error"]
    if a.ccmd == "check" or errors:
        _p({"ok": not errors, "problems": listed})
        return 1 if errors else 0
    try:
        cv, _ = eng.save_config(a.kind, text, a.by, a.note)
        pub = eng.publish_config(cv.id, actor=a.by)
    except ApprovalNeeded as e:
        _p({"waiting_for_approval": [v.summary() for v in e.versions], "detail": str(e),
            "next": "another person with __configure__ runs: sentinel config approve <version_id> --by <them>"})
        return 3
    except (ConfigError, PermissionError, EngineError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    except Exception as e:  # noqa: BLE001 - AuthorizationError and friends, shown to the operator
        print(f"error: {type(e).__name__}: {e}", file=sys.stderr)
        return 1
    _p({"published": a.kind, "version": getattr(pub, "version", None), "warnings": listed})
    return 0


def _bundle(a: argparse.Namespace, eng: Engine) -> int:
    from pathlib import Path

    from . import bundles
    from .config import ApprovalNeeded
    if a.bcmd == "export":
        doc = bundles.export(eng, [k.strip() for k in a.kinds.split(",") if k.strip()], note=a.note)
        Path(a.out).write_text(json.dumps(doc, indent=2), encoding="utf-8")
        _p({"written": a.out, "env": doc["env"], "kinds": sorted(doc["configs"]), "digest": doc["digest"],
            "signed": "signature" in doc})
        return 0
    doc = json.loads(Path(a.file).read_text(encoding="utf-8"))
    if a.bcmd == "plan":
        probs = bundles.verify(doc, os.environ.get(bundles.KEY_ENV))
        _p({"from": doc.get("env"), "to": bundles.environment(), "accepted": bundles.accepts(doc.get("env", "")),
            "problems": probs, "kinds": bundles.plan(eng, doc) if not probs else {}})
        return 1 if probs else 0
    try:
        _p(bundles.import_bundle(eng, doc, a.by, note=a.note))
        return 0
    except ApprovalNeeded as e:
        _p({"waiting_for_approval": [v.summary() for v in e.versions], "detail": str(e)})
        return 3
    except Exception as e:  # noqa: BLE001 - shown to the operator
        print(f"error: {e}", file=sys.stderr)
        return 1


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="sentinel", description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    ap.add_argument("--overlay", default=os.environ.get("SENTINEL_OVERLAY"))
    ap.add_argument("--db", default="sentinel.db")
    ap.add_argument("--pg", default=None)
    ap.add_argument("--schema", default="sentinel")
    ap.add_argument("--claude", action="store_true", help="use Claude for every LLM step (ANTHROPIC_API_KEY)")
    ap.add_argument("--models", default=os.environ.get("SENTINEL_MODELS"),
                    help="models YAML: local and frontier models, routes, fallback, escalation (overrides --claude)")
    ap.add_argument("--directory", default=os.environ.get("SENTINEL_DIRECTORY"),
                    help="people/roles/authority YAML (enables RBAC)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("reviews")
    rp = sub.add_parser("report", help="learning report; 'report owner' for the monthly owner report")
    rp.add_argument("which", nargs="?", default="learning", choices=["learning", "owner"])
    rp.add_argument("--month", default=None)
    rp.add_argument("--send", default=None, help="comma-separated person ids to send the owner report to")
    sub.add_parser("promotions")
    sub.add_parser("sweep")
    sub.add_parser("recover")
    sub.add_parser("validate")
    s = sub.add_parser("show")
    s.add_argument("incident_id")
    for name in ("approve", "reject", "modify"):
        d = sub.add_parser(name)
        d.add_argument("review_id")
        d.add_argument("--by", required=True)
        d.add_argument("--code", default=None)
        d.add_argument("--note", default="")
        if name == "modify":
            d.add_argument("--action", required=True)
            d.add_argument("--params", default="{}")
    r = sub.add_parser("reverse")
    r.add_argument("incident_id")
    r.add_argument("--by", required=True)
    r.add_argument("--note", default="")
    for name in ("approve-promotion", "reject-promotion"):
        pp = sub.add_parser(name)
        pp.add_argument("pattern")
        pp.add_argument("--by", required=True)
    sr = sub.add_parser("set-route")
    sr.add_argument("pattern")
    sr.add_argument("route", choices=[x.value for x in Route])
    sr.add_argument("--by", required=True)
    sv = sub.add_parser("serve", help="run the HTTP API (needs kbg-sentinel[api])")
    sv.add_argument("--host", default="127.0.0.1")
    sv.add_argument("--port", type=int, default=8080)
    sv.add_argument("--tokens", default=os.environ.get("SENTINEL_TOKENS_FILE"), required=False,
                    help="YAML: tokens: [{sha256, service|person}], edge_secrets_env: {edge: ENV_VAR}")
    sv.add_argument("--async", dest="async_mode", action="store_true", help="queue resolution for workers")
    wk = sub.add_parser("worker", help="run background workers")
    wk.add_argument("--threads", type=int, default=2)
    wk.add_argument("--batch", type=int, default=10)
    wk.add_argument("--metrics-port", type=int, default=int(os.environ.get("SENTINEL_WORKER_METRICS_PORT", "0")),
                    help="serve /metrics and /healthz for Prometheus on this port (0 = off)")
    th = sub.add_parser("token-hash", help="print the sha256 of a token for the tokens file")
    th.add_argument("token")
    sub.add_parser("new-token", help="generate a random token and its sha256 (give the token, configure the hash)")
    sub.add_parser("new-master-key", help="generate SENTINEL_MASTER_KEY (encrypts keys entered in the console)")
    sk = sub.add_parser("secret", help="connector keys stored encrypted: list, set (value read from stdin), clear")
    sks = sk.add_subparsers(dest="scmd", required=True)
    sks.add_parser("list")
    sks_set = sks.add_parser("set")
    sks_set.add_argument("name")
    sks_set.add_argument("--by", required=True)
    sks_clr = sks.add_parser("clear")
    sks_clr.add_argument("name")
    sks_clr.add_argument("--by", required=True)
    gw = sub.add_parser("gateway", help="run the model gateway in front of Ollama (needs kbg-sentinel[api])")
    gw.add_argument("--config", default=os.environ.get("SENTINEL_GATEWAY_CONFIG"), help="gateway YAML")
    gw.add_argument("--host", default="127.0.0.1")
    gw.add_argument("--port", type=int, default=8090)
    ev = sub.add_parser("evaluate", help="replay past decided cases through a model from --models and compare")
    ev.add_argument("--candidate", required=True, help="model name from the models file, e.g. local")
    ev.add_argument("--pattern", action="append", default=None)
    ev.add_argument("--limit", type=int, default=100)
    ev.add_argument("--min-cases", type=int, default=20)
    ev.add_argument("--threshold", type=float, default=0.9)
    ev.add_argument("--threads", type=int, default=1)
    ev.add_argument("--include-unattended", action="store_true", help="also use cases closed by auto / model")
    ev.add_argument("--json", action="store_true")
    eb = sub.add_parser("embed-backfill", help="embed closed cases that have no vector yet (needs an embedder)")
    eb.add_argument("--limit", type=int, default=1000)
    an = sub.add_parser("analytics", help="DuckDB reports over the store, read-only (needs kbg-sentinel[analytics])")
    an.add_argument("report", nargs="?", default="all",
                    choices=["all", "automation", "weekly", "trust", "service", "models", "hotspots", "evaluations"])
    an.add_argument("--days", type=int, default=None, help="only the last N days")
    an.add_argument("--fact", action="append", default=None, help="incident fact for hotspots (repeatable)")
    an.add_argument("--top", type=int, default=20)
    an.add_argument("--json", action="store_true", help="JSON instead of tables")
    an.add_argument("--parquet", default=None, help="analyse a Parquet snapshot directory instead of the store")
    an.add_argument("--snapshot", default=None, help="write every table to Parquet in this directory and exit")
    bk = sub.add_parser("backup", help="back up the database (pg_dump / SQLite backup) with a manifest")
    bk.add_argument("--out", required=True, help="directory for backups")
    bk.add_argument("--keep", type=int, default=None, help="keep only the newest N backups")
    rs = sub.add_parser("restore", help="replace the database with a backup (stop the API and workers first)")
    rs.add_argument("file")
    rs.add_argument("--yes", action="store_true", help="confirm: the current contents are replaced")
    vb = sub.add_parser("verify-backup", help="check a backup against its manifest and that it can be read")
    vb.add_argument("file")
    rt = sub.add_parser("retention", help="archive and remove closed cases older than --keep-days")
    rt.add_argument("--keep-days", type=float, default=365)
    rt.add_argument("--work-days", type=float, default=30, help="finished background jobs kept this long")
    rt.add_argument("--archive-dir", default=None)
    rt.add_argument("--apply", action="store_true", help="without it, only report what would be removed")
    mt = sub.add_parser("maintain", help="run backups (and retention) every day at a set time; for the site bundle")
    mt.add_argument("--backup-dir", required=True)
    mt.add_argument("--keep", type=int, default=14, help="backups to keep")
    mt.add_argument("--retention-days", type=float, default=None, help="archive and remove closed cases older "
                                                                       "than this (off when not set)")
    mt.add_argument("--archive-dir", default=None)
    mt.add_argument("--pii-days", type=float, default=None, help="remove personal fields (the overlay's pii_keys) "
                                                                 "from closed cases older than this (needs --overlay)")
    mt.add_argument("--at", default="02:30", help="time of day (container time, HH:MM)")
    mt.add_argument("--once", action="store_true", help="run once now and exit")
    sub.add_parser("migrate", help="bring the PostgreSQL schema up to this version (run once per upgrade)")
    vi = sub.add_parser("vectors-index", help="build an HNSW index for similar-case search (PostgreSQL + pgvector)")
    vi.add_argument("--dim", type=int, required=True, help="embedding size, e.g. 768 for nomic-embed-text")
    tr = sub.add_parser("trace", help="what would happen to an event now (read-only: nothing stored or run)")
    tr.add_argument("file", help="JSON event {type, source, payload} or just a payload with --type")
    tr.add_argument("--type", default=None)
    tr.add_argument("--source", default="trace")
    tr.add_argument("--registry", default=None, help="trace against this draft registry YAML")
    tr.add_argument("--lookups", action="store_true", help="run the playbook's read-only lookups")
    cs = sub.add_parser("case", help="one case's whole story, in time order")
    cs.add_argument("incident_id")
    ho = sub.add_parser("hosted", help="many tenants in one service: a schema, engine and tokens each")
    hos = ho.add_subparsers(dest="hcmd", required=True)
    hsv = hos.add_parser("serve")
    hsv.add_argument("--tenants", required=True)
    hsv.add_argument("--host", default="0.0.0.0")  # noqa: S104 - a server
    hsv.add_argument("--port", type=int, default=8080)
    hwk = hos.add_parser("worker")
    hwk.add_argument("--tenants", required=True)
    hwk.add_argument("--threads", type=int, default=4)
    pt = sub.add_parser("partition", help="PostgreSQL: monthly partitions for audit and model_runs (opt-in)")
    pts = pt.add_subparsers(dest="tcmd2", required=True)
    pts.add_parser("status")
    pta = pts.add_parser("apply", help="convert audit and model_runs (stop the API and workers first)")
    pta.add_argument("--table", action="append", choices=["audit", "model_runs"])
    pk = sub.add_parser("pack", help="domain packs: check (conformance + golden cases), list installed")
    pks = pk.add_subparsers(dest="kcmd", required=True)
    pkc = pks.add_parser("check")
    pkc.add_argument("packs_file")
    pks.add_parser("list")
    pkb = pks.add_parser("catalogue", help="build a catalogue from a folder of packs (KBGrid side)")
    pkb.add_argument("action", choices=["build"])
    pkb.add_argument("folder")
    pkb.add_argument("--out", required=True)
    pkf = pks.add_parser("search", help="packs in a catalogue that match")
    pkf.add_argument("text", nargs="?", default="")
    pkf.add_argument("--catalogue", default=os.environ.get("SENTINEL_PACK_CATALOGUE"))
    pkf.add_argument("--industry", default="")
    pka = pks.add_parser("add", help="copy a pack (and what it needs) from a catalogue and list it")
    pka.add_argument("pack_id")
    pka.add_argument("--catalogue", default=os.environ.get("SENTINEL_PACK_CATALOGUE"))
    pka.add_argument("--packs-file", required=True)
    pka.add_argument("--version", default="", help="a version range, e.g. '>=1.2,<2'")
    au = sub.add_parser("audit", help="tamper-evident audit trail: seal, verify, export")
    aus = au.add_subparsers(dest="acmd", required=True)
    aus.add_parser("seal", help="seal settled rows now (workers do this every minute)")
    aus.add_parser("verify", help="check every sealed row, batch and seal")
    aex = aus.add_parser("export", help="seals, rows, tombstones and redactions as gzip JSON lines")
    aex.add_argument("--out", required=True)
    aex.add_argument("--since-seal", type=int, default=0)
    avx = aus.add_parser("verify-export", help="check an export file offline")
    avx.add_argument("file")
    fl = sub.add_parser("fleet", help="every site KBGrid looks after: versions, health, backups")
    fls = fl.add_subparsers(dest="fcmd", required=True)
    fst = fls.add_parser("status", help="collect from the sites in a fleet file")
    fst.add_argument("--sites", default=os.environ.get("SENTINEL_FLEET"), help="fleet YAML")
    fls.add_parser("self", help="this site's own fleet status")
    po = sub.add_parser("policy", help="signed org and authority bundle for domain cores (offline authorise)")
    pos = po.add_subparsers(dest="ocmd", required=True)
    pok = pos.add_parser("keygen", help="site key pair: private.pem stays here, keys.json goes to every core")
    pok.add_argument("--out", required=True)
    pok.add_argument("--kid", required=True)
    poe = pos.add_parser("export", help="sign the people configuration as a bundle (needs SENTINEL_POLICY_KEY)")
    poe.add_argument("--ttl", type=float, default=24, help="hours until the bundle is stale")
    poe.add_argument("--out", default=None)
    pov = pos.add_parser("verify", help="check a bundle as a core would")
    pov.add_argument("bundle")
    pov.add_argument("--keys", required=True)
    dr = sub.add_parser("dualrun", help="ADR-004 dual run: trace events under a pin, compare two pins (read-only)")
    drs = dr.add_subparsers(dest="dcmd", required=True)
    drt = drs.add_parser("trace", help="trace events read-only under this pin; one JSON line per event")
    drt.add_argument("--events", required=True, help="JSONL of events {type, source, payload, idempotency_key}")
    drt.add_argument("--out", required=True)
    drc = drs.add_parser("compare", help="differences per pattern and the trust guard")
    drc.add_argument("production")
    drc.add_argument("candidate")
    pv = sub.add_parser("privacy", help="DPDP: a person's access request, erasure, scrub old personal fields")
    pvs = pv.add_subparsers(dest="pcmd", required=True)
    for name in ("access", "erase"):
        x = pvs.add_parser(name)
        x.add_argument("identifier", help="phone, email or customer id as it appears in events")
        x.add_argument("--by", required=True)
        if name == "erase":
            x.add_argument("--reason", default="")
            x.add_argument("--include-open", action="store_true")
            x.add_argument("--yes", action="store_true", help="confirm: personal data is overwritten")
    sc = pvs.add_parser("scrub", help="remove the overlay's pii_keys from closed cases older than --days")
    sc.add_argument("--days", type=float, required=True)
    sc.add_argument("--apply", action="store_true")
    va = sub.add_parser("value", help="time and money saved per exception")
    va.add_argument("--days", type=int, default=30)
    us = sub.add_parser("usage", help="signed monthly usage export for billing")
    us.add_argument("--month", default=None, help="YYYY-MM (default: last month)")
    us.add_argument("--reversal-days", type=int, default=7)
    us.add_argument("--out", default=None, help="write the export to this file")
    uv = sub.add_parser("usage-verify", help="check a usage export with the site's usage key")
    uv.add_argument("file")
    cn = sub.add_parser("connector", help="ready-made connectors: Shiprocket, Delhivery, Zoho Books, SAP B1, Tally")
    cns = cn.add_subparsers(dest="ncmd", required=True)
    cns.add_parser("list")
    cnw = cns.add_parser("show")
    cnw.add_argument("name")
    cna = cns.add_parser("add", help="merge a template into a connectors file")
    cna.add_argument("name")
    cna.add_argument("--into", required=True, help="connectors YAML file (created if missing)")
    bm = sub.add_parser("benchmark", help="anonymised comparison with other sites running the same exceptions")
    bms = bm.add_subparsers(dest="bmcmd", required=True)
    bsn = bms.add_parser("snapshot", help="this site's anonymised figures for a month (opt-in, to share)")
    bsn.add_argument("--month", default=None)
    bsn.add_argument("--industry", default=os.environ.get("SENTINEL_INDUSTRY", ""))
    bsn.add_argument("--out", required=True)
    bbu = bms.add_parser("build", help="percentiles from many sites' snapshots (KBGrid side)")
    bbu.add_argument("dir")
    bbu.add_argument("--k", type=int, default=5)
    bbu.add_argument("--out", required=True)
    bco = bms.add_parser("compare", help="this site against a benchmark file")
    bco.add_argument("file")
    bco.add_argument("--month", default=None)
    bco.add_argument("--industry", default=os.environ.get("SENTINEL_INDUSTRY", ""))
    gl = sub.add_parser("golive", help="go-live checklist; move exceptions live or back into shadow")
    gls = gl.add_subparsers(dest="gcmd", required=True)
    gls.add_parser("status")
    for name in ("live", "shadow"):
        g = gls.add_parser(name)
        g.add_argument("patterns", nargs="+")
        g.add_argument("--by", required=True)
        g.add_argument("--note", default="")
    tp = sub.add_parser("template", help="domain templates: list, show, or start a project from one")
    tps = tp.add_subparsers(dest="tcmd", required=True)
    tps.add_parser("list")
    tsh = tps.add_parser("show")
    tsh.add_argument("name")
    tin = tps.add_parser("init", help="write registry.yaml (a layer on the template), people.yaml and actions.py")
    tin.add_argument("name")
    tin.add_argument("--out", required=True)
    tin.add_argument("--force", action="store_true", help="overwrite files that exist")
    cf = sub.add_parser("config", help="versioned configuration: show, check or publish (registry, people, models,"
                                       " connectors)")
    cfs = cf.add_subparsers(dest="ccmd", required=True)
    csh = cfs.add_parser("show")
    csh.add_argument("kind")
    cck = cfs.add_parser("check")
    cck.add_argument("kind")
    cck.add_argument("file")
    cpb = cfs.add_parser("publish", help="save the file as a new version and publish it (refused on errors)")
    cpb.add_argument("kind")
    cpb.add_argument("file")
    cpb.add_argument("--by", required=True, help="person publishing (needs the __configure__ right with RBAC)")
    cpb.add_argument("--note", default="")
    crp = cfs.add_parser("replay", help="what a draft registry would change for recent cases (read-only)")
    crp.add_argument("file")
    crp.add_argument("--days", type=float, default=30)
    cap = cfs.add_parser("approve", help="approve a version someone else asked to publish (maker-checker)")
    cap.add_argument("version_id")
    cap.add_argument("--by", required=True)
    cfs.add_parser("waiting", help="versions waiting for approval")
    bd = sub.add_parser("bundle", help="move published configuration between environments (dev -> staging -> prod)")
    bds = bd.add_subparsers(dest="bcmd", required=True)
    bde = bds.add_parser("export")
    bde.add_argument("--kinds", default="registry,models,connectors")
    bde.add_argument("--out", required=True)
    bde.add_argument("--note", default="")
    bdp = bds.add_parser("plan", help="what importing would change here (read-only)")
    bdp.add_argument("file")
    bdi = bds.add_parser("import", help="check and publish the bundle's changed kinds together")
    bdi.add_argument("file")
    bdi.add_argument("--by", required=True)
    bdi.add_argument("--note", default="")
    a = ap.parse_args(argv)

    if a.cmd == "token-hash":
        from hashlib import sha256
        print(sha256(a.token.encode()).hexdigest())
        return 0
    if a.cmd == "new-master-key":
        from .secretstore import new_master_key
        _p({"SENTINEL_MASTER_KEY": new_master_key(),
            "keep": "in the server's environment only; never in the database, its backups or git"})
        return 0
    if a.cmd == "secret":
        from .secretstore import SecretStoreError, required
        eng = _engine(a)
        try:
            if a.scmd == "list":
                _p(required(eng))
            elif a.scmd == "set":
                value = sys.stdin.readline().rstrip("\r\n")
                _p(eng.set_secret(a.name, value, a.by))
            else:
                _p({"cleared": eng.clear_secret(a.name, a.by)})
        except (SecretStoreError, EngineError) as e:
            print(f"error: {e}", file=sys.stderr)
            return 1
        return 0
    if a.cmd == "new-token":
        import secrets
        from hashlib import sha256
        tok = "sk-" + secrets.token_urlsafe(32)
        _p({"token": tok, "sha256": sha256(tok.encode()).hexdigest()})
        return 0
    if a.cmd == "gateway":
        return _gateway(a)
    if a.cmd == "analytics":
        return _analytics(a)
    if a.cmd == "maintain":
        return _maintain(a)
    if a.cmd == "migrate":
        if not (a.pg or os.environ.get("SENTINEL_PG")):
            print("error: migrate needs --pg (SQLite needs no migration)", file=sys.stderr)
            return 2
        from .pg_store import _SCHEMA_HASH, PostgresStore
        st = PostgresStore(a.pg or os.environ["SENTINEL_PG"], schema=a.schema, migrate=True)
        _p({"schema": a.schema, "version": st.schema_version(), "expected": _SCHEMA_HASH})
        st.close()
        return 0
    if a.cmd == "fleet" and a.fcmd == "status":
        from .fleet import collect, load
        if not a.sites:
            print("error: pass --sites fleet.yaml or set SENTINEL_FLEET", file=sys.stderr)
            return 2
        res = collect(load(a.sites))
        _p(res)
        return 1 if res["summary"]["attention"] else 0
    if a.cmd == "policy" and a.ocmd in ("keygen", "verify"):
        from pathlib import Path

        from .orgsync import PolicyError, keygen, load_policy
        try:
            if a.ocmd == "keygen":
                _p(keygen(a.out, a.kid))
                return 0
            snap = load_policy(Path(a.bundle).read_text(encoding="utf-8").strip(), a.keys)
            _p({"ok": True, "version": snap.version, "site": snap.site, "issued_at": snap.issued_at.isoformat(),
                "expires_at": snap.expires_at.isoformat(), "stale": snap.stale(),
                "people": len(snap.directory.people), "roles": len(snap.directory.roles)})
            return 1 if snap.stale() else 0
        except PolicyError as e:
            _p({"ok": False, "error": str(e)})
            return 1
    if a.cmd == "dualrun" and a.dcmd == "compare":
        from .dualrun import compare, read_jsonl
        res = compare(read_jsonl(a.production), read_jsonl(a.candidate))
        _p(res)
        return 1 if res["differs"] else 0
    if a.cmd == "pack":
        from . import packs
        if a.kcmd == "list":
            _p({k: str(v) for k, v in packs.installed().items()})
            return 0
        if a.kcmd in ("catalogue", "search", "add"):
            from pathlib import Path

            from . import catalogue as cat
            try:
                if a.kcmd == "catalogue":
                    doc = cat.build(a.folder, relative_to=Path(a.out).resolve().parent)
                    Path(a.out).write_text(json.dumps(doc, indent=2), encoding="utf-8")
                    _p({"written": a.out, "packs": len(doc["packs"]), "problems": doc["problems"],
                        "signed": "signature" in doc})
                    return 1 if doc["problems"] else 0
                if not a.catalogue:
                    print("error: pass --catalogue or set SENTINEL_PACK_CATALOGUE", file=sys.stderr)
                    return 2
                c = cat.load(a.catalogue)
                if a.kcmd == "search":
                    _p([{k: e[k] for k in ("id", "version", "title", "industry", "fits", "exceptions",
                                           "capabilities", "requires")} for e in cat.search(c, a.text,
                                                                                            industry=a.industry)])
                    return 0
                _p(cat.add(c, a.pack_id, a.packs_file, version=a.version))
                return 0
            except packs.PackError as e:
                print(f"error: {e}", file=sys.stderr)
                return 1
        try:
            res = packs.check(a.packs_file)
        except packs.PackError as e:
            print(f"error: {e}", file=sys.stderr)
            return 1
        _p(res)
        return 0 if res["ok"] else 1
    if a.cmd == "audit" and a.acmd == "verify-export":
        from .auditchain import KEY_ENV, verify_export
        from .envsecrets import lookup
        probs = verify_export(a.file, lookup(KEY_ENV))
        _p({"ok": not probs, "problems": probs})
        return 1 if probs else 0
    if a.cmd == "usage-verify":
        from pathlib import Path

        from .usage import KEY_ENV, verify
        from .envsecrets import lookup
        key = lookup(KEY_ENV)
        if not key:
            print(f"error: set {KEY_ENV} to the site's usage key", file=sys.stderr)
            return 2
        probs = verify(json.loads(Path(a.file).read_text(encoding="utf-8")), key)
        _p({"ok": not probs, "problems": probs})
        return 1 if probs else 0
    if a.cmd == "connector":
        from . import connectors as ct
        try:
            if a.ncmd == "list":
                _p([{k: v for k, v in ct.summary(n).items() if k in ("name", "title", "events")} for n in ct.names()])
            elif a.ncmd == "show":
                _p(ct.summary(a.name))
            else:
                _p(ct.add_to_file(a.name, a.into))
        except (KeyError, ValueError) as e:
            print(f"error: {e}", file=sys.stderr)
            return 1
        return 0
    if a.cmd == "benchmark" and a.bmcmd == "build":
        from pathlib import Path

        from . import benchmark as bmk
        doc = bmk.build(bmk.load_dir(a.dir), k=a.k)
        Path(a.out).write_text(json.dumps(doc, indent=2), encoding="utf-8")
        _p({"written": a.out, "industries": {k: len(v) for k, v in doc["benchmarks"].items()}})
        return 0
    if a.cmd == "benchmark":
        from pathlib import Path

        from . import benchmark as bmk
        eng = _engine(a)
        month = a.month or bmk.last_month(eng)
        snap = bmk.snapshot(eng, month, industry=a.industry)
        if a.bmcmd == "snapshot":
            Path(a.out).write_text(json.dumps(snap, indent=2), encoding="utf-8")
            _p({"written": a.out, "month": month, "exceptions": len(snap["exceptions"])})
            return 0
        _p(bmk.compare(snap, json.loads(Path(a.file).read_text(encoding="utf-8")), a.industry))
        return 0
    if a.cmd == "hosted":
        from pathlib import Path

        from . import hosted
        from .observe import configure_logging
        configure_logging()
        h = hosted.build(a.tenants, async_mode=True)
        if a.hcmd == "serve":
            import uvicorn
            uvicorn.run(hosted.asgi_app(h, Path(a.tenants).parent), host=a.host, port=a.port, log_config=None)
            return 0
        import signal
        import threading
        stop = threading.Event()
        signal.signal(signal.SIGTERM, lambda *_: stop.set())
        hosted.run_workers(h, stop, threads=a.threads)
        return 0
    if a.cmd in ("backup", "restore", "verify-backup", "retention", "vectors-index", "partition"):
        return _maintenance(a)
    if a.cmd == "template":                      # with an overlay, show also says what it still lacks
        return _template(a, _engine(a) if a.tcmd == "show" and a.overlay else None)

    if not a.overlay:
        print("error: pass --overlay module:factory or set SENTINEL_OVERLAY", file=sys.stderr)
        return 2
    if a.cmd == "serve":
        return _serve(a)
    if a.cmd == "worker":
        return _worker(a)
    if a.cmd == "bundle":
        return _bundle(a, _engine(a))
    if a.cmd == "config":
        return _config(a, _engine(a))
    try:
        eng = _engine(a)
        if a.cmd == "reviews":
            rows = []
            for rv in eng.store.open_reviews():
                inc = eng.store.get_incident(rv.incident_id)
                rows.append({"review": rv.id, "incident": rv.incident_id, "pattern": inc.pattern_id if inc else None,
                             "role": rv.assignee_role, "due": rv.due_at, "escalation": rv.escalation_level,
                             "reason": rv.reason, "facts": inc.facts if inc else None,
                             "proposal": rv.proposal.model_dump() if rv.proposal else None})
            _p(rows)
        elif a.cmd == "report":
            if a.which == "owner":
                from .ownerreport import build, send
                rep = build(eng, a.month)
                if a.send:
                    _p(send(eng, rep, [x.strip() for x in a.send.split(",") if x.strip()]))
                else:
                    print(rep["text"], end="")
            else:
                _p(eng.report())
        elif a.cmd == "promotions":
            _p({pid: r["pending_promotion"] for pid, r in eng.report()["patterns"].items() if r["pending_promotion"]})
        elif a.cmd == "sweep":
            _p([r.id for r in eng.sweep()])
        elif a.cmd == "recover":
            _p(eng.recover())
        elif a.cmd == "validate":
            problems = eng.registry.validate(eng.actions, {n: t.params for n, t in eng.overlay.tools.tools.items()})
            _p({"ok": not problems, "problems": problems, "warnings": eng.coverage(),
                "patterns": len(eng.registry.all())})
            return 1 if problems else 0
        elif a.cmd == "policy":                      # export (keygen and verify run without an engine, above)
            from pathlib import Path
            token = eng.export_policy(a.ttl)
            if a.out:
                Path(a.out).write_text(token + "\n", encoding="utf-8")
                _p({"written": a.out})
            else:
                print(token)
        elif a.cmd == "dualrun":                     # trace (compare runs without an engine, above)
            from .dualrun import read_jsonl, trace_events, write_jsonl
            rows = trace_events(eng, read_jsonl(a.events))
            write_jsonl(rows, a.out)
            _p({"written": a.out, "events": len(rows)})
        elif a.cmd == "trace":
            from pathlib import Path

            from .models import Event
            raw = json.loads(Path(a.file).read_text(encoding="utf-8"))
            if a.type:
                raw = {"type": a.type, "source": a.source, "payload": raw}
            raw.setdefault("source", a.source)
            reg = Path(a.registry).read_text(encoding="utf-8") if a.registry else None
            _p(eng.trace(Event.model_validate(raw), registry_text=reg, run_lookups=a.lookups))
        elif a.cmd == "audit":
            if a.acmd == "seal":
                _p(eng.seal_audit())
            elif a.acmd == "verify":
                r = eng.verify_audit()
                _p(r)
                return 0 if r["ok"] else 1
            else:
                from .auditchain import export
                _p(export(eng.store, a.out, since_seal=a.since_seal))
        elif a.cmd == "fleet":                       # self
            from .fleet import site_status
            _p(site_status(eng))
        elif a.cmd == "privacy":
            if a.pcmd == "access":
                _p(eng.privacy_access(a.identifier, a.by))
            elif a.pcmd == "erase":
                if not a.yes:
                    from .privacy import find
                    _p({"would_erase": [i.id for i in find(eng, a.identifier)], "next": "run again with --yes"})
                    return 0
                _p(eng.privacy_erase(a.identifier, a.by, a.reason, include_open=a.include_open))
            else:
                from .privacy import scrub
                _p(scrub(eng, a.days, apply=a.apply))
        elif a.cmd == "value":
            _p(eng.value(days=a.days))
        elif a.cmd == "usage":
            from .usage import export, previous_month
            doc = export(eng, a.month or previous_month(eng.clock()), reversal_days=a.reversal_days)
            if a.out:
                from pathlib import Path
                Path(a.out).write_text(json.dumps(doc, indent=2, default=str), encoding="utf-8")
                _p({"written": a.out, "month": doc["month"], "final": doc["final"], "signed": bool(doc["signature"])})
            else:
                _p(doc)
        elif a.cmd == "golive":
            from .config import ApprovalNeeded
            if a.gcmd == "status":
                r = eng.readiness()
                _p(r)
                return 1 if r["blocking"] else 0
            try:
                cv = eng.set_shadow(a.patterns, a.gcmd == "shadow", a.by, a.note)
            except ApprovalNeeded as e:
                _p({"waiting_for_approval": [v.summary() for v in e.versions], "detail": str(e)})
                return 3
            _p({"published": cv.summary()})
        elif a.cmd == "case":
            c = eng.case(a.incident_id)
            if c is None:
                print(f"error: unknown incident {a.incident_id}", file=sys.stderr)
                return 1
            _p(c)
        elif a.cmd == "show":
            inc = eng.store.get_incident(a.incident_id)
            if inc is None:
                raise EngineError(f"unknown incident {a.incident_id}")
            d = eng.store.get_disposition(a.incident_id)
            _p({"incident": inc.model_dump(), "events": eng.store.event_ids(inc.id),
                "disposition": d.model_dump() if d else None, "audit": eng.store.audit_log(inc.id)})
        elif a.cmd in ("approve", "reject", "modify"):
            kind = DecisionKind(a.cmd)
            kw: dict[str, Any] = {"kind": kind, "actor": a.by, "disposition_code": a.code, "note": a.note}
            if a.cmd == "modify":
                kw.update(action=a.action, params=json.loads(a.params))
            inc = eng.decide(a.review_id, Decision(**kw))
            _p({"incident": inc.id, "state": inc.state.value})
        elif a.cmd == "evaluate":
            if eng.router is None or a.candidate not in eng.router.named:
                known = sorted(eng.router.named) if eng.router is not None else []
                raise ValueError(f"--candidate must name a model in the --models file (known: {known})")
            rep = eng.evaluate(eng.router.named[a.candidate], patterns=a.pattern, limit=a.limit,
                               min_cases=a.min_cases, threshold=a.threshold, threads=a.threads,
                               include_unattended=a.include_unattended)
            if a.json:
                _p(rep.to_dict(with_cases=True))
            else:
                from .analytics import render_table
                rows = [{"pattern": k, **{c: v[c] for c in ("cases", "exact", "action", "code", "agrees_with_primary",
                                                           "errors", "avg_ms", "verdict")},
                         "why": "; ".join(v["reasons"])} for k, v in rep.by_pattern.items()]
                print(f"model {rep.model}: {rep.overall['cases']} cases, exact {rep.overall['exact']}, "
                      f"ready for: {', '.join(rep.overall['ready_patterns']) or 'none yet'}")
                print(render_table(rows))
        elif a.cmd == "embed-backfill":
            if eng.embedder is None:
                raise ValueError("no embedder: add 'embedder:' to the --models file")
            _p({"embedded": eng.backfill_embeddings(limit=a.limit)})
        elif a.cmd == "reverse":
            _p(eng.reverse(a.incident_id, actor=a.by, note=a.note).model_dump())
        elif a.cmd == "approve-promotion":
            _p(eng.approve_promotion(a.pattern, actor=a.by).model_dump())
        elif a.cmd == "reject-promotion":
            _p(eng.reject_promotion(a.pattern, actor=a.by).model_dump())
        elif a.cmd == "set-route":
            _p(eng.set_route(a.pattern, Route(a.route), actor=a.by).model_dump())
    except (EngineError, KeyError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    return 0


def _store(a: argparse.Namespace) -> Any:
    if a.pg or os.environ.get("SENTINEL_PG"):
        from .pg_store import PostgresStore
        return PostgresStore(a.pg or os.environ["SENTINEL_PG"], schema=a.schema)
    from .store import SQLiteStore
    return SQLiteStore(a.db)


def _maintenance(a: argparse.Namespace) -> int:
    from . import backup, retention
    try:
        if a.cmd == "verify-backup":
            _p(backup.verify(a.file))
            return 0
        store = _store(a)
        if a.cmd == "partition":
            from . import partitions
            if a.tcmd2 == "status":
                _p(partitions.status(store))
            else:
                _p([partitions.convert(store, t) for t in (a.table or ["audit", "model_runs"])])
            return 0
        if a.cmd == "backup":
            _p(backup.backup(store, a.out, keep=a.keep))
        elif a.cmd == "restore":
            if not a.yes:
                print("error: restoring replaces everything in the database; stop the API and workers, then "
                      "run again with --yes", file=sys.stderr)
                return 2
            _p(backup.restore(store, a.file))
        elif a.cmd == "retention":
            from .models import utcnow
            _p(retention.run(store, utcnow(), a.keep_days, archive_dir=a.archive_dir, apply=a.apply,
                             work_days=a.work_days))
        elif a.cmd == "vectors-index":
            if not hasattr(store, "ensure_vector_index"):
                raise ValueError("vector indexes need PostgreSQL with pgvector (--pg)")
            _p({"index": store.ensure_vector_index(a.dim)})
    except (backup.BackupError, ValueError, RuntimeError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    return 0


def _maintain(a: argparse.Namespace) -> int:
    import logging
    import time
    from datetime import datetime, timedelta

    from . import backup, retention
    from .models import utcnow
    from .observe import configure_logging
    configure_logging()
    log = logging.getLogger("sentinel.maintain")
    hh, _, mm = a.at.partition(":")
    archive_dir = a.archive_dir or os.path.join(a.backup_dir, "archive")

    def once() -> bool:
        ok = True
        store = _store(a)
        try:
            b = backup.backup(store, a.backup_dir, keep=a.keep)
            log.info("backup made", extra={"file": b["path"], "bytes": b["bytes"], "pruned": len(b["pruned"])})
            backup.verify(b["path"])
            if os.environ.get("SENTINEL_OWNER_REPORT") and a.overlay:
                from .ownerreport import build, due, mark_sent, send
                eng_r = Engine(_load(a.overlay), store=store)
                month = due(eng_r)
                if month:
                    r = send(eng_r, build(eng_r, month), os.environ["SENTINEL_OWNER_REPORT"].split(","))
                    mark_sent(eng_r, month)
                    log.info("owner report sent", extra={"month": month, "sent": len(r["sent"])})
            if a.pii_days and a.overlay:
                from .privacy import scrub
                eng = Engine(_load(a.overlay), store=store)
                r = scrub(eng, a.pii_days, apply=True)
                log.info("personal fields scrubbed", extra={"cases": r.get("scrubbed"),
                                                            "records": r.get("records_changed")})
            from .auditchain import seal as seal_audit
            from .partitions import maintain as maintain_partitions
            seal_audit(store)
            maintain_partitions(store)
            if a.retention_days:
                r = retention.run(store, utcnow(), a.retention_days, archive_dir=archive_dir, apply=True)
                log.info("retention applied", extra={"archive": r.get("archive"), "rows": r.get("archived_rows")})
        except Exception as e:  # noqa: BLE001 - logged; the loop keeps going and the next run tries again
            log.error("maintenance failed", extra={"error": f"{type(e).__name__}: {e}"})
            ok = False
        finally:
            close = getattr(store, "close", None)
            if close:
                close()
        return ok
    if a.once:
        return 0 if once() else 1
    while True:
        now = datetime.now()
        nxt = now.replace(hour=int(hh), minute=int(mm or 0), second=0, microsecond=0)
        if nxt <= now:
            nxt += timedelta(days=1)
        time.sleep((nxt - now).total_seconds())
        once()


def _serve(a: argparse.Namespace) -> int:
    import yaml

    from .api import Principal, create_app
    from .observe import configure_logging
    if not a.tokens:
        print("error: --tokens file required for serve", file=sys.stderr)
        return 2
    cfg = yaml.safe_load(open(a.tokens, encoding="utf-8")) or {}
    tokens = {}
    for t in cfg.get("tokens") or []:
        kind = "service" if "service" in t else "person"
        tokens[t["sha256"]] = Principal(kind, t.get("service") or t["person"])
    secrets = {edge: os.environ[env] for edge, env in (cfg.get("edge_secrets_env") or {}).items()
               if env in os.environ}
    configure_logging()
    eng = _engine(a, async_mode=a.async_mode)
    import uvicorn
    sso = None
    if cfg.get("sso"):
        from .sso import SSOConfig
        sso = SSOConfig.model_validate(cfg["sso"])
    uvicorn.run(create_app(eng, tokens, edge_secrets=secrets, sso=sso), host=a.host, port=a.port, log_config=None)
    return 0


def _analytics(a: argparse.Namespace) -> int:
    from .analytics import Analytics, AnalyticsError, render_table
    pg = a.pg or os.environ.get("SENTINEL_PG")
    try:
        if a.parquet:
            an = Analytics(parquet_dir=a.parquet)
        elif pg:
            an = Analytics(pg=pg, schema=a.schema)
        else:
            an = Analytics(sqlite=a.db)
        with an:
            if a.snapshot:
                _p(an.snapshot(a.snapshot))
                return 0
            if a.report == "all":
                out = an.all(a.days, a.fact)
            elif a.report == "hotspots":
                out = {"hotspots": an.hotspots(a.fact, a.days, a.top)}
            elif a.report in ("trust", "evaluations"):
                out = {a.report: getattr(an, a.report)()}
            else:
                out = {a.report: getattr(an, a.report)(a.days)}
    except (AnalyticsError, ValueError, ImportError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    if a.json:
        _p(out)
    else:
        for name, rows in out.items():
            print(f"\n== {name} ==")
            print(render_table(rows))
    return 0


def _gateway(a: argparse.Namespace) -> int:
    if not a.config:
        print("error: --config gateway.yaml required (or SENTINEL_GATEWAY_CONFIG)", file=sys.stderr)
        return 2
    from .gateway import create_gateway, load_gateway_config
    from .observe import configure_logging
    try:
        cfg = load_gateway_config(a.config)
    except (OSError, ValueError, KeyError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    configure_logging()
    import uvicorn
    uvicorn.run(create_gateway(cfg), host=a.host, port=a.port, log_config=None, access_log=False)
    return 0


def _serve_worker_metrics(eng: Engine, port: int) -> None:
    """Workers do most of the work in async mode, so they expose their own metrics for Prometheus."""
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    class H(BaseHTTPRequestHandler):
        def log_message(self, *args: Any) -> None:
            pass

        def do_GET(self) -> None:
            if self.path == "/metrics":
                body, ctype, code = eng.metrics.render().encode(), "text/plain; version=0.0.4", 200
            elif self.path == "/healthz":
                h = eng.health()
                body, ctype = json.dumps(h, default=str).encode(), "application/json"
                code = 503 if h["status"] == "down" else 200
            else:
                body, ctype, code = b"not found\n", "text/plain", 404
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    srv = ThreadingHTTPServer(("0.0.0.0", port), H)  # noqa: S104 - inside the container network
    threading.Thread(target=srv.serve_forever, daemon=True, name="worker-metrics").start()


def _worker(a: argparse.Namespace) -> int:
    import signal
    import threading

    from .observe import configure_logging
    from .worker import Worker
    configure_logging()
    eng = _engine(a, async_mode=True)
    stop = threading.Event()
    if a.metrics_port:
        _serve_worker_metrics(eng, a.metrics_port)
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    workers = [Worker(eng, batch=a.batch) for _ in range(a.threads)]
    threads = [threading.Thread(target=w.run, args=(stop,), name=f"worker-{i}") for i, w in enumerate(workers)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    if any(w.failed for w in workers):
        return 1                 # exit non-zero: the container or service manager restarts the worker
    return 0


if __name__ == "__main__":
    sys.exit(main())
