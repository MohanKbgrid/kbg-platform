# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""The engine: event -> fingerprint -> group/inhibit -> registry -> route -> resolve -> disposition -> learn.

Durability model
  * Event intake, grouping and incident creation happen in one transaction.
  * Side effects go through idempotent action runs keyed by
    incident/run/step, so re-driving an incident after a crash never
    repeats a completed step; a step whose outcome is unknown goes to a human.
  * `recover()` re-drives incidents left mid-flight by a crash.
"""
from __future__ import annotations

import concurrent.futures as cf
import contextvars
import hashlib
import hmac
import json
import math
import os
import logging
import threading
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
from collections.abc import Callable, Iterator

from .actions import ActionContext, ActionRegistry, ParamError, render
from .edges import Delivery, ReviewCard
from .fingerprint import Fingerprinter
from .lifecycle import transition
from .observe import Metrics
from .llm import LLMClient, LLMResolver
from .routing import ModelRouter, PIIMasker
from .models import (ActionResult, CaseDefaults, Decision, DecisionKind, Disposition, Event, Hold, Incident,
                     IncidentState as S, Pattern, PatternState, PlaybookStep, Proposal, Provenance, ReviewTask, Route,
                     Silence, WorkItem, new_id, utcnow)
from .overlay import Overlay
from .policy import Guardrails, Learner, LearningPolicy
from .rbac import Directory
from .registry import Registry, ceiling
from .store import SQLiteStore, Store


class EngineError(RuntimeError):
    pass


log = logging.getLogger("sentinel.engine")


class PayloadError(ValueError):
    """Event rejected at the door: too large or too deeply nested."""


class _NotYet(Exception):
    """A background check that should simply run again later (not an error)."""


class _LeaseLost(Exception):
    """This worker no longer holds the job (its lease expired and another worker took it): stop, act on nothing."""


class AuthorizationError(EngineError):
    """The actor exists but is not allowed to do this. Carries where it should go instead."""

    def __init__(self, message: str, escalate_to: str | None = None) -> None:
        super().__init__(message)
        self.escalate_to = escalate_to


@dataclass
class IngestResult:
    status: str                   # new | grouped | suppressed | duplicate
    incident_id: str | None
    event_id: str


@dataclass
class _Exec:
    ok: bool
    detail: str = ""
    uncertain: bool = False
    results: list[dict[str, Any]] | None = None


class Engine:
    @property
    def directory(self) -> Any:
        return self.__dict__.get("_directory")

    @directory.setter
    def directory(self, d: Any) -> None:
        """Every directory the engine uses tells time by the engine's clock (time-bound assignments)."""
        if d is not None and hasattr(d, "clock"):
            d.clock = self.clock
        self.__dict__["_directory"] = d

    def __init__(self, overlay: Overlay, store: Store | None = None, llm: LLMClient | ModelRouter | None = None, *,
                 guardrails: Guardrails | None = None, learning: LearningPolicy | None = None,
                 clock: Callable[[], datetime] = utcnow, llm_timeout_s: float = 60.0,
                 raise_on_invalid: bool = True, directory: Directory | None = None,
                 async_mode: bool = False, retry_base_s: float = 5.0, retry_cap_s: float = 900.0,
                 action_pool_size: int = 16, recover_stale_s: float = 300.0,
                 masker: PIIMasker | None = PIIMasker(), card_link_base: str | None = None,
                 metrics: Metrics | None = None, max_event_bytes: int = 256_000, max_payload_depth: int = 16,
                 embedder: Any = None, similar_k: int = 5, sync_config: bool = True,
                 answer_token_days: float = 7.0, default_action_timeout_s: float | None = 120.0,
                 tool_timeout_s: float = 30.0, licence: Any = None) -> None:
        import copy
        # this engine's own copy: publishing replaces its patterns, roles and edges, and must never reach
        # another engine built from the same overlay object (hosted tenants, tests, a second worker)
        overlay = copy.copy(overlay)
        self.overlay = overlay
        from .kpi import verifier as _metric_verifier
        overlay.verifiers = {"metric": _metric_verifier(self), **overlay.verifiers}   # outcome: did the KPI move
        self.store = store or SQLiteStore()
        from .secretstore import SecretStore
        self.secrets = SecretStore(self)
        self._load_secrets()
        if any(p.owner_slot or p.escalation_slot for p in overlay.patterns):
            from .overlay import SlotError, resolve_slots
            try:                                       # an overlay built in code binds its slots here too
                overlay.patterns = resolve_slots(list(overlay.patterns), overlay.slots, overlay.slot_bindings,
                                                 overlay.roles, f"overlay {overlay.name}")
            except SlotError as e:
                raise EngineError(str(e)) from None
        if overlay.binding is not None:                  # ADR-005: the domain's never-automate list holds
            from .bindings import check_binding, enforce_never_automate
            bad = check_binding(overlay.binding, list(overlay.patterns), dict(overlay.slots or {}))
            if bad and raise_on_invalid:
                raise EngineError("domain binding: " + "; ".join(bad))
            overlay.patterns = enforce_never_automate(overlay.binding, list(overlay.patterns))
        self.registry = Registry(overlay.patterns)
        self.case_defaults = CaseDefaults.model_validate(overlay.case_defaults or {})
        from .models import Capability
        from .overlay import check_capabilities
        self.capabilities: dict[str, Capability] = {
            cid: c if isinstance(c, Capability) else Capability.model_validate(c)
            for cid, c in (overlay.capabilities or {}).items()}
        overlay.capabilities = dict(self.capabilities)
        problems = self.registry.validate(self._startup_actions(overlay),
                                          {n: t.params for n, t in overlay.tools.tools.items()})
        problems += check_capabilities(overlay.roles, self.registry.all(), self.capabilities)
        if problems and raise_on_invalid:
            raise EngineError("registry invalid:\n  " + "\n  ".join(problems))
        self.fp = Fingerprinter(overlay.fingerprint_rules)
        self._fp_hashes: dict[tuple[str, ...], str | None] = {}
        self.actions = overlay.actions
        self._base_actions = overlay.actions            # the overlay's own (code); configured ones merge on top
        self.guardrails = guardrails or Guardrails()
        self.learner = Learner(learning)
        self.clock = clock
        from .access import Access
        self.access = Access(self.store, lambda: self.clock())
        masker = masker.with_keys(*overlay.pii_keys) if (masker is not None and overlay.pii_keys) else masker
        self.masker = masker
        self.similar_k = similar_k
        self.llm_timeout_s = llm_timeout_s
        self._base_tools = overlay.tools                # the overlay's own lookup tools
        self.tools = overlay.tools                      # plus tools from connectors (MCP), once published
        self._connector_tools: Any = None
        self.kpi: Any = None                            # metrics: datasets, KPIs and monitors (kpi.Warehouse)
        self.sources: dict[str, Any] = {}               # data sources from the connectors configuration
        self._base_edges = dict(overlay.edges)          # the overlay's own; configured edges are added to these
        self.connectors: Any = None
        self.http_opener: Any = None                    # tests and proxies: urllib opener for configured actions
        if licence is None:
            from .licence import LicenceGuard
            licence = LicenceGuard.from_env()           # None on an open-source install: nothing enforced
        self.licence = licence or None                  # False: never check (tests, tools)
        self._explicit_embedder = embedder
        self.tool_timeout_s = tool_timeout_s
        self.async_mode = async_mode
        self._set_llm(llm)
        self.notify = overlay.notifier or (lambda kind, data: None)
        self.directory = directory if directory is not None else overlay.directory
        if self.directory is not None:
            missing = sorted({r for p in self.registry.all() + [self.registry.fallback]
                              for r in (p.owner_role, p.escalation_role) if r and r not in self.directory.roles})
            if missing and raise_on_invalid:
                raise EngineError(f"patterns reference roles missing from the directory: {missing}")
            bad = self.directory.oversight_problems(self.registry.all()) if hasattr(self.directory,
                                                                                    "oversight_problems") else []
            if bad and raise_on_invalid:
                raise EngineError("; ".join(bad))
        self._people_base = self.directory           # the people configuration, before provisioned people
        self._scim_rev: int | None = None
        self.refresh_directory()
        self._locks = [threading.RLock() for _ in range(4096)]   # striped: memory stays bounded
        self.async_mode = async_mode
        self.recover_stale_s = recover_stale_s
        self.answer_token_days = answer_token_days
        self.default_action_timeout_s = default_action_timeout_s     # actions that declare none
        self.retry_base_s = retry_base_s
        self.retry_cap_s = retry_cap_s
        self._action_pool = cf.ThreadPoolExecutor(max_workers=action_pool_size, thread_name_prefix="action")
        self._work_handlers: dict[str, Callable[[WorkItem], None]] = {"resolve": self._work_resolve,
                                                                      "outcome_check": self._work_outcome,
                                                                      "deliver": self._work_deliver,
                                                                      "embed": self._work_embed,
                                                                      "poll": self._work_poll,
                                                                      "shadow_eval": self._work_shadow_eval,
                                                                      "clear_check": self._work_clear_check,
                                                                      "monitor": self._work_monitor}
        from .persistence import Silences
        self.silences = Silences(self)
        self._last_expiry: datetime | None = None
        self._fence = threading.local()               # the job this thread holds, checked before acting
        self.card_link_base = card_link_base.rstrip("/") if card_link_base else None
        self.max_event_bytes, self.max_payload_depth = max_event_bytes, max_payload_depth
        self.metrics = metrics or Metrics()
        self.metrics.gauge("open_reviews", lambda: float(self.store.review_counts(self.clock())["open"]),
                           "Reviews waiting for a person")
        self.metrics.gauge("work_items", lambda: {(("status", k),): float(v) for k, v in
                                                  self.store.queue_stats(self.clock())["counts"].items()},
                           "Background work items by status")
        self.metrics.gauge("work_oldest_ready_age_seconds",
                           lambda: float(self.store.queue_stats(self.clock())["oldest_ready_age_s"]),
                           "Age of the oldest ready work item (queue lag)")
        for names in [*overlay.role_edges.values(), overlay.default_edges]:
            for n in names:
                if n not in overlay.edges and raise_on_invalid:
                    raise EngineError(f"edge {n!r} is referenced but not configured")
        for p in self.registry.all():
            oc = p.outcome_check
            if oc is not None:
                if oc.get("verifier") not in overlay.verifiers and raise_on_invalid:
                    raise EngineError(f"{p.id}: outcome verifier {oc.get('verifier')!r} is not registered")
                if int(oc.get("after_minutes", 60)) < 0 and raise_on_invalid:
                    raise EngineError(f"{p.id}: outcome after_minutes must be >= 0")
                unknown = [c for c in oc.get("codes") or [] if c not in p.disposition_codes]
                if unknown and raise_on_invalid:
                    raise EngineError(f"{p.id}: outcome codes {unknown} are not disposition codes of the pattern")
        self._applied: dict[str, str] = {}
        self._config_labels: dict[str, str] = {}
        from .config import doc_checksum, registry_doc
        # the registry as the code and packs define it: console changes are kept as a layer over this
        self._base_registry = registry_doc(overlay.roles, overlay.fingerprint_rules, self.registry.all(),
                                           overlay.case_defaults, self.capabilities,
                                           overlay.slots, overlay.slot_bindings)
        self._base_checksum = doc_checksum(self._base_registry)
        self._rebased_text: str | None = None
        if overlay.metrics:                           # the overlay's own KPIs until metrics are published
            try:
                self._apply_config("metrics", self._build_config("metrics", overlay.metrics))
            except Exception:  # noqa: BLE001 - metrics must not stop the engine starting
                log.exception("could not load the overlay's metrics")
        if sync_config:
            try:
                self.sync_config()
            except Exception:  # noqa: BLE001 - a broken stored config must not stop the engine starting
                log.exception("could not apply stored configuration")

    def _startup_actions(self, overlay: Overlay) -> ActionRegistry:
        """The overlay's actions plus any configured in the published connectors, for the start-up check
        (configured actions are installed a moment later, when stored configuration is applied)."""
        try:
            cv = self.store.published_config("connectors")
            if cv is None:
                return overlay.actions
            from .config import _load_text
            from .httpactions import parse_actions, registry_from
            return overlay.actions.merged(registry_from(parse_actions(_load_text(cv.text).get("actions") or {})))
        except Exception:  # noqa: BLE001 - a broken stored config is reported when it is applied
            return overlay.actions

    def _set_llm(self, llm: Any) -> None:
        """Install a model client or router (at start, and when a models configuration is published)."""
        explicit = self._explicit_embedder
        self.embedder = explicit if explicit is not None else (llm.embedder if isinstance(llm, ModelRouter) else None)
        router = llm if isinstance(llm, ModelRouter) else None
        if router is not None and router.sink is None:
            router.sink = self._persist_model_run
        if router is not None and router.daily_budget is not None and router.spent_today is None:
            router.spent_today = lambda: self.store.model_spend_since(time.time() - time.time() % 86400)
        self.llm = (LLMResolver(llm, self.actions, self.tools, timeout_s=self.llm_timeout_s,
                                tool_timeout_s=getattr(self, "tool_timeout_s", 30.0),
                                masker=self.masker, on_shadow=self._on_model_shadow,
                                defer_shadow=self._defer_shadow if getattr(self, "async_mode", False) else None,
                                on_escalate=self._on_model_escalate,
                                similar=self.similar_cases if self.embedder is not None else None)
                    if llm else None)
        self.router = router

    # ================================================================ configuration
    def _config_context(self) -> Any:
        from .config import Context
        return Context(actions=self.actions, verifiers=self.overlay.verifiers, edges=set(self.overlay.edges),
                       base_edges=set(self._base_edges),
                       mcp_commands=list(getattr(self.overlay, "mcp_commands", []) or []),
                       fingerprints=list(self.overlay.fingerprint_rules),
                       patterns=[*self.registry.all(), self.registry.fallback],
                       roles=dict(self.overlay.roles), directory=self.directory,
                       tools=self._base_tools.describe(),
                       code_actions={a.name for a in self._base_actions.specs()},
                       metric_names=set(self.kpi.doc.metrics) if self.kpi is not None else None,
                       capabilities=dict(self.capabilities), all_tools=set(self.tools.tools),
                       binding=self.overlay.binding)

    def config_text(self, kind: str) -> str:
        """The running configuration as YAML: the published version, or the overlay's own if none."""
        from .config import KINDS, directory_doc, dump_yaml, registry_doc
        if kind not in KINDS:
            raise ValueError(f"kind must be one of {KINDS}")
        cv = self.store.published_config(kind)
        if cv is not None:
            if kind == "registry" and self._rebased_text is not None and self._applied.get(kind) == cv.id:
                return self._rebased_text        # console changes over the current code / packs
            return cv.text
        if kind == "registry":
            return dump_yaml(registry_doc(self.overlay.roles, self.overlay.fingerprint_rules, self.registry.all(),
                                          self.overlay.case_defaults, self.capabilities,
                                          self.overlay.slots, self.overlay.slot_bindings))
        if kind == "people":
            return dump_yaml(directory_doc(self._people_base)) if self._people_base is not None else ""
        if kind == "metrics":
            return dump_yaml(self.overlay.metrics) if self.overlay.metrics else ""
        if kind == "connectors":
            return ""
        src = getattr(self.router, "source", None)
        return dump_yaml(src) if src else ""

    def check_config(self, kind: str, text: str) -> tuple[Any, list[Any]]:
        from .config import check
        return check(kind, text, self._config_context())

    def save_config(self, kind: str, text: str, author: str, note: str = "") -> tuple[Any, list[Any]]:
        """Store a draft version (even with problems: it can be fixed and saved again). Returns (version, problems)."""
        from .config import ConfigVersion
        _, problems = self.check_config(kind, text)
        layer = base = None
        if kind == "registry":
            try:
                from .config import _load_text, registry_layer
                layer, base = registry_layer(self._base_registry, _load_text(text)), self._base_checksum
            except Exception:  # noqa: BLE001,S110 - an unreadable draft is saved as text only
                pass
        cv = self.store.add_config_version(kind, lambda n: ConfigVersion(kind=kind, version=n, text=text,
                                                                         author=author, note=note[:500],
                                                                         created_at=self.clock(), layer=layer,
                                                                         base_checksum=base))
        self.store.audit(None, "config_saved", {"kind": kind, "version": cv.version, "id": cv.id, "author": author,
                                                "errors": sum(p.severity == "error" for p in problems)})
        return cv, problems

    def _build_config(self, kind: str, parsed: Any) -> Any:
        if kind == "models":
            from .providers import load_models
            return load_models(parsed)
        if kind == "connectors":
            from .mcp import Connectors
            return Connectors(parsed, allowed_commands=getattr(self.overlay, "mcp_commands", None))
        if kind == "metrics":
            from .kpi import MetricsDoc, parse
            return parsed if isinstance(parsed, MetricsDoc) else parse(parsed)
        return parsed

    def _rebuild_tools(self) -> None:
        from .tools import ToolRegistry
        tools = self._base_tools.merged(self._connector_tools or ToolRegistry())
        if self.kpi is not None and "metrics.query" not in tools.tools:
            from .kpi import tool
            tools = tools.merged(ToolRegistry({"metrics.query": tool(self)}))
        self.tools = tools
        if self.llm is not None:
            self.llm.tools = self.tools

    def _apply_config(self, kind: str, built: Any) -> None:
        if kind == "registry":
            pats = list(built.patterns)
            if self.overlay.binding is not None:          # published configuration keeps the domain's law too
                from .bindings import check_binding, enforce_never_automate
                bad = check_binding(self.overlay.binding, pats, dict(getattr(built, "slots", None) or {}))
                if bad:                                   # never applied: the previous configuration keeps running
                    raise EngineError("published registry breaks the domain binding: " + "; ".join(bad))
                pats = enforce_never_automate(self.overlay.binding, pats)
            self.registry = Registry(pats)
            self.fp = Fingerprinter(built.fingerprints)
            self.overlay.patterns = list(built.patterns)
            self.overlay.fingerprint_rules = list(built.fingerprints)
            self._fp_hashes = {}
            self.overlay.roles = dict(built.roles)
            self.overlay.case_defaults = dict(getattr(built, "defaults", {}) or {})
            self.case_defaults = CaseDefaults.model_validate(self.overlay.case_defaults)
            self.capabilities = dict(getattr(built, "capabilities", {}) or {})
            self.overlay.capabilities = dict(self.capabilities)
            for p in self.registry.all():                 # a template no longer digested: its cases get cards
                if not p.digest_above:
                    self._release_digested(p, "the template no longer sends a digest")
            known = {p.id for p in self.registry.all()}
            for rv in self.store.open_reviews():          # a template removed altogether: same, never stranded
                if not rv.digested:
                    continue
                inc = self.store.get_incident(rv.incident_id)
                if inc is not None and inc.pattern_id not in known:
                    rv.digested = False
                    self.store.put_review(rv)
                    self._schedule_deliveries(rv, inc)
                    self.store.audit(inc.id, "digest_released", {"review": rv.id,
                                                                 "why": "its template was removed"})
        elif kind == "people":
            self._people_base = built
            self._scim_rev = None
            self.refresh_directory()
        elif kind == "connectors":
            from .tools import ToolRegistry
            extra = ToolRegistry()
            for t in built.connect_tools():
                extra.register(t)
            for sev, msg in built.problems:
                log.warning("connector: %s", msg) if sev == "warning" else log.error("connector: %s", msg)
            old, self.connectors = self.connectors, built
            self._connector_tools = extra
            self._rebuild_tools()
            from .httpactions import registry_from
            self.actions = self._base_actions.merged(registry_from(getattr(built, "actions", {}) or {},
                                                                   opener=self.http_opener))
            if self.llm is not None:
                self.llm.tools = self.tools
                self.llm.actions = self.actions
            self.sources = dict(built.sources)
            self.overlay.edges = {**self._base_edges, **built.edges}
            if old is not None:
                old.close()
        elif kind == "metrics":
            from .kpi import Warehouse
            old_kpi, self.kpi = self.kpi, Warehouse(self, built)
            if old_kpi is not None:
                old_kpi.close()
            self._rebuild_tools()
        else:
            self._set_llm(built)

    def check_config_set(self, texts: dict[str, str]) -> dict[str, tuple[Any, list[Any]]]:
        """Check several kinds together, each against the others as proposed (e.g. a new template's roles
        and patterns), falling back to the running configuration for kinds not in the set."""
        from .config import _load_text, check
        from .overlay import parse_registry
        from .rbac import parse_directory
        from .registry import UNMATCHED
        ctx = self._config_context()
        if "registry" in texts:
            try:
                doc = parse_registry(_load_text(texts["registry"]))
                ctx.fingerprints, ctx.roles = list(doc.fingerprints), doc.roles
                ctx.patterns = [*doc.patterns, UNMATCHED]
            except Exception:  # noqa: BLE001,S110 - reported by its own check below
                pass
        if "people" in texts:
            try:
                ctx.directory = parse_directory(_load_text(texts["people"]))
            except Exception:  # noqa: BLE001,S110
                pass
        if "connectors" in texts:
            try:
                from .httpactions import parse_actions, registry_from
                drafted = parse_actions(_load_text(texts["connectors"]).get("actions") or {})
                ctx.actions = self._base_actions.merged(registry_from(drafted))
            except Exception:  # noqa: BLE001,S110 - reported by its own check below
                pass
        return {kind: check(kind, text, ctx) for kind, text in texts.items()}

    def publish_config(self, version_id: str, actor: str) -> Any:
        """Check, build, record and apply a version. An older version is republished as a new version."""
        return self.publish_config_set([version_id], actor)[0]

    def publish_config_set(self, version_ids: list[str], actor: str) -> list[Any]:
        """Publish several versions (at most one per kind) together: checked as a set, applied together."""
        from .config import ConfigError, ConfigVersion
        versions = []
        for vid in version_ids:
            cv = self.store.get_config_version(vid)
            if cv is None:
                raise EngineError(f"unknown configuration version {vid}")
            versions.append(cv)
        kinds = [cv.kind for cv in versions]
        if not versions or len(set(kinds)) != len(kinds):
            raise ConfigError("publish one version per kind")
        if self.directory is not None:
            for cv in versions:
                auth = self.directory.authorize_meta(actor, "__configure__", f"config:{cv.kind}")
                if not auth.allowed:
                    self.store.audit(None, "meta_denied", {"meta": "__configure__", "actor": actor,
                                                           "reason": auth.reason})
                    raise AuthorizationError(auth.reason)
        checked = self.check_config_set({cv.kind: cv.text for cv in versions})
        errors = [p for kind in kinds for p in checked[kind][1] if p.severity == "error"]
        broken = [kind for kind in kinds if checked[kind][0] is None]
        if errors or broken:
            label = ", ".join(f"{cv.kind} v{cv.version}" for cv in versions)
            raise ConfigError(f"{label}: {len(errors) or len(broken)} error(s); fix them before publishing",
                              [type(e)(e.severity, f"{k}: {e.message}") for k in kinds for e in checked[k][1]
                               if e.severity == "error"])
        built = {}
        for cv in versions:
            try:
                parsed = checked[cv.kind][0]
                if cv.kind == "registry":
                    parsed = self._rebase_registry(cv, parsed)
                built[cv.kind] = self._build_config(cv.kind, parsed)
            except Exception as e:  # noqa: BLE001 - e.g. a model key missing in this process
                raise ConfigError(f"{cv.kind} v{cv.version} cannot be applied: {e}") from None
        out = []
        for cv in versions:
            if cv.status != "draft":                   # rollback: publish a copy as the newest version
                src = cv
                cv = self.store.add_config_version(cv.kind, lambda n, src=src: ConfigVersion(
                    kind=src.kind, version=n, text=src.text, author=actor, note=f"republished v{src.version}",
                    copied_from=src.id, created_at=self.clock(), layer=src.layer, base_checksum=src.base_checksum))
            out.append(cv)
        self._approval_gate(out, actor)
        with self.store.transaction():
            for cv in out:
                prev = self.store.published_config(cv.kind)
                if prev is not None and prev.id != cv.id:
                    prev.status = "superseded"
                    self.store.put_config_version(prev)
                cv.status, cv.published_at, cv.published_by = "published", self.clock(), actor
                self.store.put_config_version(cv)
                self.store.audit(None, "config_published", {
                    "kind": cv.kind, "version": cv.version, "id": cv.id, "actor": actor, "checksum": cv.checksum,
                    "warnings": [p.message for p in checked[cv.kind][1]][:50]})
        for kind in ("people", "registry", "models", "connectors", "metrics"):
            for cv in out:
                if cv.kind == kind:
                    self._apply_config(kind, built[kind])
                    self._applied[kind] = cv.id
                    self.metrics.inc("config_published_total", help="Configuration versions published", kind=kind)
        return out

    def _approvals_needed(self, kind: str) -> int:
        pol = getattr(self.directory, "config_approval", None) if self.directory is not None else None
        return pol.approvals if pol is not None and kind in pol.kinds else 0

    def _approval_gate(self, versions: list[Any], actor: str) -> None:
        """Maker-checker: publishing someone else's version counts as approving it; a version still short of
        approvals is marked as requested (with the set it belongs to) and ApprovalNeeded is raised."""
        from .config import ApprovalNeeded
        short = []
        for cv in versions:
            need = self._approvals_needed(cv.kind)
            if not need:
                continue
            if actor != cv.author and actor not in cv.approvals:
                cv.approvals.append(actor)
            if len({a for a in cv.approvals if a != cv.author}) < need:
                short.append(cv)
        if not short:
            return
        ids = [cv.id for cv in versions]
        for cv in versions:
            cv.requested_by = cv.requested_by or actor
            cv.requested_with = ids
            self.store.put_config_version(cv)
        self.store.audit(None, "config_approval_requested", {
            "versions": [f"{cv.kind} v{cv.version}" for cv in versions], "by": actor,
            "waiting": [f"{cv.kind} v{cv.version}" for cv in short]})
        self.notify("config_approval_requested", {"versions": ids, "by": actor})
        raise ApprovalNeeded(", ".join(f"{cv.kind} v{cv.version}" for cv in short) + " waits for approval by "
                             "someone else with the __configure__ right", short)

    def approve_config(self, version_id: str, actor: str) -> list[Any]:
        """Approve a version someone else wrote. When every version requested with it has its approvals, the
        set is published (by the approver). Returns the versions published, or [] while some still wait."""
        from .config import ApprovalNeeded, ConfigError
        cv = self.store.get_config_version(version_id)
        if cv is None:
            raise EngineError(f"unknown configuration version {version_id}")
        if cv.status != "draft":
            raise ConfigError(f"{cv.kind} v{cv.version} is {cv.status}; only drafts are approved")
        if actor == cv.author:
            raise AuthorizationError("the author of a version cannot approve it")
        if self.directory is not None:
            auth = self.directory.authorize_meta(actor, "__configure__", f"config:{cv.kind}")
            if not auth.allowed:
                raise AuthorizationError(auth.reason)
        if actor not in cv.approvals:
            cv.approvals.append(actor)
            self.store.put_config_version(cv)
            self.store.audit(None, "config_approved", {"kind": cv.kind, "version": cv.version, "actor": actor})
        ids = cv.requested_with or [cv.id]
        try:
            return self.publish_config_set(ids, actor)
        except ApprovalNeeded:
            return []

    def _rebase_registry(self, cv: Any, parsed: Any) -> Any:
        """A published registry made against older code / packs is re-applied as a layer over the current
        ones, so a pack upgrade is not hidden by console changes. Falls back to the stored text on a conflict."""
        self._rebased_text = None
        if not cv.layer or not cv.base_checksum or cv.base_checksum == self._base_checksum:
            return parsed
        from .config import apply_layer, dump_yaml, registry_doc
        try:
            doc = apply_layer(self._base_registry, cv.layer)
        except Exception as e:  # noqa: BLE001 - keep what was published; say why
            key = f"registry:rebase:{cv.id}:{self._base_checksum}"
            if not self.store.get_source_state(key):
                self.store.put_source_state(key, {"error": str(e)})
                self.store.audit(None, "registry_rebase_failed", {"version": cv.version, "error": str(e)})
            return parsed
        key = f"registry:rebase:{cv.id}:{self._base_checksum}"
        if not self.store.get_source_state(key):
            self.store.put_source_state(key, {"ok": True})
            self.store.audit(None, "registry_rebased", {"version": cv.version, "from": cv.base_checksum,
                                                        "to": self._base_checksum,
                                                        "kept": {k: len(v) for k, v in cv.layer.items()
                                                                 if isinstance(v, list | dict)}})
        self._rebased_text = dump_yaml(registry_doc(doc.roles, doc.fingerprints, doc.patterns, doc.defaults,
                                                    doc.capabilities, doc.slots, doc.slot_bindings))
        return doc

    def sync_config(self) -> list[str]:
        """Apply any configuration published since this process last looked. Returns the kinds applied."""
        from .config import KINDS, _load_text
        from .overlay import parse_registry
        from .rbac import parse_directory
        applied = []
        if self._load_secrets():
            self._applied.pop("connectors", None)          # rebuild connectors and edges with the new keys
            self._applied.pop("models", None)
            applied.append("secrets")
        for kind in KINDS:
            cv = self.store.published_config(kind)
            if cv is None or self._applied.get(kind) == cv.id:
                continue
            try:
                data = _load_text(cv.text)
                parsed = (parse_registry(data) if kind == "registry" else
                          parse_directory(data) if kind == "people" else data)   # models, connectors: dict
                if kind == "registry":
                    parsed = self._rebase_registry(cv, parsed)
                self._apply_config(kind, self._build_config(kind, parsed))
            except Exception as e:  # noqa: BLE001 - keep running the previous configuration
                if self._applied.get(f"failed:{kind}") != cv.id:
                    self._applied[f"failed:{kind}"] = cv.id
                    self.store.audit(None, "config_apply_failed", {"kind": kind, "version": cv.version,
                                                                   "error": f"{type(e).__name__}: {e}"})
                    log.error("could not apply configuration", extra={"kind": kind, "version": cv.version,
                                                                      "error": str(e)})
                continue
            self._applied[kind] = cv.id
            applied.append(kind)
        if self.refresh_directory():
            applied.append("scim")
        return applied

    def _load_secrets(self) -> bool:
        """Keys entered in the console, decrypted and made visible to configuration. True when they changed."""
        from .envsecrets import use_stored
        try:
            changed = self.secrets.refresh()
        except Exception as e:  # noqa: BLE001 - keys from the environment still work
            log.error("could not load stored keys", extra={"error": str(e)})
            return False
        if changed:
            use_stored(self.secrets.cache)
        return changed

    def set_secret(self, name: str, value: str, actor: str) -> dict[str, Any]:
        self._authorize_configure(actor, "secrets")
        out = self.secrets.set(name, value, actor)
        self.sync_config()
        return out

    def clear_secret(self, name: str, actor: str) -> bool:
        self._authorize_configure(actor, "secrets")
        out = self.secrets.clear(name, actor)
        self.sync_config()
        return out

    def _authorize_configure(self, actor: str, what: str) -> None:
        if self.directory is None:
            return
        auth = self.directory.authorize_meta(actor, "__configure__", f"config:{what}")
        if not auth.allowed:
            self.store.audit(None, "meta_denied", {"meta": "__configure__", "actor": actor, "what": what})
            raise AuthorizationError(auth.reason, escalate_to=auth.escalate_to)

    def refresh_directory(self) -> bool:
        """Add the people the company directory provisioned (SCIM) to the people configuration's own.
        Returns True when the directory changed."""
        base = self._people_base
        if base is None or getattr(base, "scim", None) is None:
            changed = self.directory is not base
            self.directory = base
            return changed
        from .scim import STATE, merge
        try:
            st = self.store.get_source_state(STATE)
        except Exception:  # noqa: BLE001 - keep the directory we have
            return False
        rev = int((st or {}).get("rev", 0))
        if rev == self._scim_rev:
            return False
        self.directory = merge(base, st)
        self._scim_rev = rev
        return True

    # ================================================================ intake
    def receive(self, source: str, raw: Any) -> list[IngestResult]:
        """Normalise a raw payload - with a configured data source, else the overlay's receiver - and ingest."""
        if source in self.sources:
            from .sources import SourceError, to_events
            s = self.sources[source]
            if not s.enabled:
                raise EngineError(f"source {source!r} is disabled")
            try:
                events = to_events(s, raw, now=self.clock())
            except SourceError as e:
                raise PayloadError(str(e)) from None
            self.metrics.inc("source_events_total", float(len(events)), help="Events mapped by data sources",
                             source=source)
            return [self.ingest(e) for e in events]
        if source not in self.overlay.receivers:
            raise EngineError(f"no receiver for source {source!r}")
        out = self.overlay.receivers[source](raw)
        events = out if isinstance(out, list) else [out]
        return [self.ingest(e) for e in events]

    # ================================================================ polled sources
    def schedule_sources(self) -> int:
        """Queue a fetch for every poll / sql source whose interval has come round. Safe to call from every
        worker: one job per source per interval (dedupe key). Returns how many were queued."""
        now = self.clock()
        n = 0
        for name, s in self.sources.items():
            if s.kind in ("poll", "sql") and s.enabled:
                slot = int(now.timestamp() // s.every_s)
                if self.store.enqueue(WorkItem(kind="poll", payload={"source": name}, run_after=now,
                                               dedupe_key=f"poll:{name}:{slot}", max_attempts=3)):
                    n += 1
            elif s.kind == "expect" and s.enabled:
                from .sources import expect_due
                due, day, _ = expect_due(s, now)
                if due and self.store.enqueue(WorkItem(kind="poll", payload={"source": name}, run_after=now,
                                                       dedupe_key=f"expect:{name}:{day}", max_attempts=3)):
                    n += 1
        if self.kpi is not None:                      # analytics -> agents: KPI monitors on their interval
            for name, mon in self.kpi.doc.monitors.items():
                slot = int(now.timestamp() // (mon.every_minutes * 60))
                if mon.enabled and self.store.enqueue(WorkItem(kind="monitor", payload={"monitor": name},
                                                               run_after=now, dedupe_key=f"monitor:{name}:{slot}",
                                                               max_attempts=3)):
                    n += 1
        return n

    def run_monitor(self, name: str) -> dict[str, Any]:
        from .kpi import run_monitor
        return run_monitor(self, name)

    def _work_monitor(self, item: WorkItem) -> None:
        if self.kpi is not None and item.payload.get("monitor") in self.kpi.doc.monitors:
            self.run_monitor(item.payload["monitor"])

    def poll_source(self, name: str, *, opener: Any = None) -> dict[str, Any]:
        """Fetch one poll / sql source now, ingest what it maps to, advance its cursor."""
        from .sources import run_once
        s = self.sources.get(name)
        if s is None or s.kind not in ("poll", "sql", "expect"):
            raise EngineError(f"unknown poll, sql or expect source {name!r}")
        state = self.store.get_source_state(name) or {}
        t0 = time.perf_counter()
        try:
            events, new = run_once(s, state, now=self.clock(), opener=opener)
        except Exception as e:
            self.store.put_source_state(name, {**state, "last_error": f"{type(e).__name__}: {e}"[:500],
                                               "last_run": self.clock().isoformat()})
            self.metrics.inc("source_polls_total", source=name, ok="false")
            raise
        results = [self.ingest(e) for e in events]
        new.update(last_run=self.clock().isoformat(), last_error=None, last_events=len(events),
                   last_ms=round((time.perf_counter() - t0) * 1000, 1),
                   total_events=int(state.get("total_events", 0)) + len(events))
        self.store.put_source_state(name, new)
        self.metrics.inc("source_polls_total", help="Data source fetches", source=name, ok="true")
        return {"events": len(events), "new": sum(r.status == "new" for r in results), "cursor": new.get("cursor")}

    def _work_poll(self, item: WorkItem) -> None:
        self.poll_source(item.payload["source"])

    def ingest(self, event: Event) -> IngestResult:
        self._check_payload(event)
        with self.metrics.time("ingest_seconds"):
            res = self._ingest(event)
        self.metrics.inc("events_total", help="Events received, by outcome", status=res.status)
        if res.status == "new":
            log.info("incident created", extra={"incident": res.incident_id, "event": event.id,
                                                "event_type": event.type})
        return res

    def _check_payload(self, event: Event) -> None:
        size = len(json.dumps(event.payload, default=str))
        if size > self.max_event_bytes:
            raise PayloadError(f"event payload is {size} bytes; limit is {self.max_event_bytes}")

        def depth(o: Any, d: int = 0) -> int:
            if d > self.max_payload_depth:
                return d
            if isinstance(o, dict):
                return max([depth(v, d + 1) for v in o.values()] or [d])
            if isinstance(o, list):
                return max([depth(v, d + 1) for v in o] or [d])
            return d
        if depth(event.payload) > self.max_payload_depth:
            raise PayloadError(f"event payload nests deeper than {self.max_payload_depth} levels")

    def _ingest(self, event: Event) -> IngestResult:
        cleared = self._clear_by_event(event)
        if cleared is not None:
            return cleared
        facts = self.fp.facts(event)
        sig = self.fp.signature(event, facts)
        pattern = self.registry.match(event.type, facts)
        policy = self.agent_policy(pattern, facts)
        if policy is not None and policy.mode == "OFF":
            pattern = self.registry.fallback               # the template takes no cases here: people do
        with self._lock_for(sig):
            with self.store.transaction():
                self.store.lock(sig)          # cross-process: no two workers group/create the same incident
                if not self.store.insert_event(event):
                    return IngestResult("duplicate", None, event.id)
                now = self.clock()
                since = (now - timedelta(minutes=pattern.group_window_minutes)
                         if pattern.group_window_minutes else datetime.min.replace(tzinfo=now.tzinfo))
                existing = self.store.find_open_incident(sig, since)
                if existing is not None:
                    # link the event; never rewrite the incident row here (another thread may be resolving it)
                    count = self.store.attach_event(existing.id, event.id)
                    self.store.audit(existing.id, "grouped", {"event_id": event.id, "count": count})
                    self._refresh_facts(existing, facts, event, now)
                    review = self.store.open_review_for(existing.id)
                    if review is not None:
                        review.reported_at = now               # still happening: it does not expire
                        self.store.put_review(review)
                    if review is not None and review.hold is not None and review.hold.kind == "pause":
                        # the source reported again while we were waiting on someone: a person looks now
                        self._release(review, existing, self.registry.get(existing.pattern_id), by=None,
                                      why="the source reported it again", send=True)
                    return IngestResult("grouped", existing.id, event.id)
                inc = Incident(tenant=event.tenant, pattern_id=pattern.id, fingerprint=sig,
                               route=self.effective_route(pattern, facts),
                               shadow=self.is_shadow(pattern, facts),
                               event_ids=[event.id], first_event=event.model_dump(mode="json"), facts=facts,
                               provenance=self.provenance(pattern, facts), created_at=now, updated_at=now)
                odd = self._odd_scope_facts(pattern, event)
                if odd:                                   # a scope fact no control or core can match on
                    inc.odd_facts, inc.route = odd, Route.HITL
                    self.store.audit(inc.id, "scope_fact_not_plain", {"facts": odd, "pattern": pattern.id})
                    self.store.audit(inc.id, "agent_assertion_refused", {"facts": odd, "at": "ingest"})
                if inc.provenance is not None:
                    from .methodlearn import assign
                    cand = assign(self, pattern.id, inc.id)
                    if cand is not None:                  # a randomised trial: this case gets the candidate
                        inc.provenance.trial, inc.provenance.method = cand.id, cand.name
                        inc.route = Route.HITL           # a person decides every trial case
                parent = self._inhibitor(pattern, inc)
                if parent is not None:
                    inc.parent_id = parent.id
                    self._t(inc, S.SUPPRESSED)
                self.store.put_incident(inc)
                self.store.attach_event(inc.id, event.id)
                self.store.audit(inc.id, "created", {"pattern": pattern.id, "route": inc.route.value,
                                                     "shadow": inc.shadow, "fingerprint": sig,
                                                     "parent": inc.parent_id,
                                                     **({"provenance": inc.provenance.model_dump(exclude_none=True)}
                                                        if inc.provenance else {})})
                if self.async_mode and inc.state is S.OPEN:
                    # same transaction as the incident: a crash can never leave an incident without its job
                    self.store.enqueue(WorkItem(kind="resolve", incident_id=inc.id, run_after=now,
                                                dedupe_key=f"resolve:{inc.id}"))
            if inc.state is S.SUPPRESSED:
                return IngestResult("suppressed", inc.id, event.id)
        if not self.async_mode:
            self._drive(inc, pattern)
        return IngestResult("new", inc.id, event.id)

    def _refresh_facts(self, inc: Incident, facts: dict[str, Any], event: Event, now: datetime) -> None:
        """A repeat event may carry worse facts (an older age bucket, a larger gap). Keep the incident's facts
        current while a person or a parent holds it, and pull its review forward if the case now matches a
        more urgent pattern. The pattern itself is not changed: learning stays tied to how it was opened."""
        changed = {k: [inc.facts.get(k), v] for k, v in facts.items() if inc.facts.get(k) != v}
        if not changed:
            return
        merged = {**inc.facts, **facts}
        updated = self.store.update_facts(inc.id, merged, [S.AWAITING_HUMAN.value, S.SUPPRESSED.value])
        now_pattern = self.registry.match(event.type, merged)
        self.store.audit(inc.id, "facts_changed", {"changed": changed, "applied": updated,
                                                   "now_matches": now_pattern.id})
        if now_pattern.id == inc.pattern_id or not updated:
            return
        review = self.store.open_review_for(inc.id)
        if review is None:
            return
        due = inc.created_at + timedelta(minutes=now_pattern.sla_minutes)     # its SLA, counted from opening
        if due < review.due_at:
            review.due_at = due
            review.reason = f"{review.reason}; now looks like {now_pattern.id} - due sooner"
            self.store.put_review(review)
            self.store.audit(inc.id, "review_due_moved", {"pattern": now_pattern.id, "due": due.isoformat()})

    def _t(self, inc: Incident, dst: S) -> Incident:
        return transition(inc, dst, now=self.clock())

    def _lock_for(self, key: str) -> threading.RLock:
        return self._locks[hash(key) % len(self._locks)]  # type: ignore[return-value]

    @contextmanager
    def _guard(self, incident_id: str) -> Iterator[None]:
        """One actor at a time per incident: across threads here and across processes (API replicas,
        workers) through the store."""
        with self._lock_for(incident_id), self.store.mutex(f"incident:{incident_id}"):
            yield

    @contextmanager
    def _pattern_tx(self, pattern: Pattern) -> Iterator[None]:
        """Trust is read, changed and written back under a lock, so concurrent updates are not lost."""
        with self.store.transaction():
            self.store.lock(f"pattern_state:{pattern.id}")
            yield

    def _inhibitor(self, pattern: Pattern, inc: Incident) -> Incident | None:
        for pid in pattern.inhibited_by:
            for cand in self.store.open_incidents(pid, inc.tenant):
                if cand.state is S.SUPPRESSED:
                    continue
                if all(cand.facts.get(k) == inc.facts.get(k) for k in pattern.inhibit_on):
                    return cand
        return None

    # ================================================================ routing
    @staticmethod
    def segment_of(pattern: Pattern, facts: dict[str, Any] | None) -> str | None:
        """The trust segment of a case, e.g. "channel=ajio", for patterns with `trust_by`."""
        if not pattern.trust_by or facts is None:
            return None
        return "|".join(f"{k}={facts.get(k)}" for k in pattern.trust_by)

    def trust_states(self, pattern: Pattern, facts: dict[str, Any] | None) -> list[PatternState]:
        """The states a decision on this case teaches: its segment, and the template's pooled state when the
        pattern pools trust (``trust_pool_min``). Without pooling, just the one state, as before."""
        seg = self.segment_of(pattern, facts)
        states = [self.pattern_state(pattern, seg)]
        if seg and pattern.trust_pool_min:
            states.append(self.pattern_state(pattern))
        return states

    def trusted_state(self, pattern: Pattern, facts: dict[str, Any] | None) -> PatternState:
        """The state whose route applies to this case: the segment's own once it has ``trust_pool_min`` decisions,
        before that the template's pooled trust. Without pooling, the segment's state, as before."""
        seg = self.segment_of(pattern, facts)
        st = self.pattern_state(pattern, seg)
        if seg and pattern.trust_pool_min and st.samples < pattern.trust_pool_min:
            pool = self.pattern_state(pattern)
            if st.cap is not None and st.cap.level < pool.route.level:
                return pool.model_copy(update={"route": st.cap})   # this scope is held: the pool can't lift it
            return pool
        return st

    def _split(self, key: str) -> tuple[Pattern, str | None]:
        pid, _, seg = key.partition("@")
        try:
            return self.registry.get(pid), (seg or None)
        except KeyError:
            raise EngineError(f"unknown pattern {pid}") from None

    def _fingerprint_hash(self, pattern: Pattern) -> str | None:
        """Hash of the fingerprint rules for the pattern's event types (None when it has none)."""
        types = tuple(sorted(pattern.event_types))
        if types not in self._fp_hashes:              # cleared when fingerprint rules are published
            rules = sorted((r.model_dump(mode="json") for r in self.overlay.fingerprint_rules
                            if r.event_type in types), key=lambda r: r["event_type"])
            self._fp_hashes[types] = (hashlib.sha256(json.dumps(rules, sort_keys=True).encode()).hexdigest()[:16]
                                      if rules else None)
        return self._fp_hashes[types]

    def pattern_state(self, pattern: Pattern, segment: str | None = None) -> PatternState:
        key = f"{pattern.id}@{segment}" if segment else pattern.id
        st = self.store.get_pattern_state(key)
        current = pattern.definition_hash(self._fingerprint_hash(pattern))
        if st is None:
            # a new segment starts where the pattern stands now (lowered by a kill switch, say)
            start = self.pattern_state(pattern).route if segment else pattern.route
            return PatternState(pattern_id=key, route=start, definition_hash=current)
        if st.definition_hash is None or st.definition_hash == pattern.definition_hash():
            # state from before versioning, or from before fingerprint rules were part of the meaning: adopt,
            # and save it, so a later change to the fingerprint rules is recognised as one
            if st.definition_hash != current:
                st.definition_hash = current
                with self._pattern_tx(pattern):
                    fresh = self.store.get_pattern_state(key)
                    if fresh is not None and fresh.definition_hash in (None, pattern.definition_hash()):
                        fresh.definition_hash = current
                        self.store.put_pattern_state(fresh)
        elif st.definition_hash != current:
            # the pattern now means something else: trust earned on the old definition doesn't carry over
            old_route, old_hash = st.route, st.definition_hash
            Learner._set_route(st, pattern.route if pattern.route.level <= ceiling(pattern).level
                               else ceiling(pattern))
            st.definition_hash = current
            self.store.put_pattern_state(st)
            self.store.audit(None, "pattern_changed", {"pattern": key, "from_hash": old_hash,
                                                       "to_hash": current, "route_was": old_route.value,
                                                       "route_now": st.route.value})
            self.notify("pattern_changed", {"pattern": pattern.id, "route_now": st.route.value})
        return st

    def agent_policy(self, pattern: Pattern, facts: dict[str, Any] | None = None) -> Any:
        """The people configuration's agent policy for this template in this scope (None: none configured)."""
        if self.directory is None or pattern.id == self.registry.fallback.id:
            return None
        return self.directory.agent_policy(pattern.id, pattern.capability, facts)

    # ---- data trust per scope (Layer A caps Layer B) ----------------------------------------------------
    def set_data_trust(self, scope: dict[str, Any], score: float, source: str = "",
                       components: dict[str, Any] | None = None, *, by: str | None = None) -> dict[str, Any]:
        """Record a scope's data trust score (0..1) - one fact, e.g. {"store": "TVM01"}. Audited when its band
        (act / propose / observe) changes."""
        import math as _m
        if not isinstance(scope, dict) or len(scope) != 1:
            raise EngineError("data trust is set for one scope fact at a time, e.g. {store: TVM01}")
        (k, v), = scope.items()
        from .factrule import fact_problem
        if (why := fact_problem(k, v)) is not None or k in ("event_type", "source"):
            raise EngineError(f"data trust scope must be one fact with a value: {why or k + ' is not a scope'}")
        if isinstance(score, bool) or not isinstance(score, int | float):
            raise EngineError("data trust score must be a number from 0 to 1")
        if not isinstance(source, str):
            raise EngineError("data trust source must be text")
        dt = self.case_defaults.data_trust
        if by is None:                                    # an in-process caller is the engine's own code: trusted,
            by = "engine"                                 # and attributed as such
        elif dt is not None and dt.sources is not None and by not in dt.sources:
            raise AuthorizationError(f"{by} may not post data trust scores (defaults.data_trust.sources)")
        score = float(score)
        if not _m.isfinite(score) or not 0 <= score <= 1:
            raise EngineError("data trust score must be a number from 0 to 1")
        key = f"data_trust:{k}={v}"
        old = self.store.get_source_state(key) or {}
        row = {"scope": {str(k): v}, "score": score, "at": self.clock().timestamp(), "source": source,
               "by": by, "components": dict(components or {})}
        with self.store.transaction():                    # the score and its index entry, never one without the other
            self.store.lock("data_trust:index")
            self.store.put_source_state(key, row)
            idx = (self.store.get_source_state("data_trust:index") or {}).get("keys", [])
            if key not in idx:
                self.store.put_source_state("data_trust:index", {"keys": [*idx, key][-5000:]})
        band = self._trust_band(score)
        if band != (self._trust_band(old["score"]) if "score" in old else None):
            self.store.audit(None, "data_trust_band", {"scope": {str(k): v}, "score": score, "band": band,
                                                       "was": old.get("score"), "source": source, "by": by})
        return {**row, "band": band}

    def _trust_band(self, score: float) -> str:
        dt = self.case_defaults.data_trust
        if dt is None:
            return "ACT"
        return "ACT" if score >= dt.act_min else "PROPOSE" if score >= dt.propose_min else "OBSERVE"

    def data_trust_scores(self) -> list[dict[str, Any]]:
        out = []
        for key in (self.store.get_source_state("data_trust:index") or {}).get("keys", []):
            row = self.store.get_source_state(key)
            if row:
                out.append({**row, "band": self._trust_band(row["score"])})
        return out

    def data_trust_cap(self, pattern: Pattern, facts: dict[str, Any] | None) -> tuple[str | None, str]:
        """(cap, why): the most autonomy this case's scope data allows - None (no cap), PROPOSE or OBSERVE. The
        lowest fresh score among the case's facts (and the scopes they roll up to) decides."""
        dt = self.case_defaults.data_trust
        if dt is None or pattern.data_trust_exempt or pattern.id == self.registry.fallback.id:
            return None, ""
        facts = facts or {}
        candidates: dict[str, set[Any]] = {k: {v} for k, v in facts.items()
                                           if k not in ("event_type", "source") and not isinstance(v, dict | list)}
        if self.directory is not None and getattr(self.directory, "scopes", None):
            for k, vals in self.directory.expand_facts(facts).items():
                candidates.setdefault(k, set()).update(vals)
        now = self.clock().timestamp()
        worst: tuple[float, str] | None = None
        for k, vals in candidates.items():
            for v in vals:
                row = self.store.get_source_state(f"data_trust:{k}={v}")
                if not row or now - float(row.get("at", 0)) > dt.max_age_hours * 3600:
                    continue
                if worst is None or row["score"] < worst[0]:
                    worst = (float(row["score"]), f"{k}={v}")
        if worst is None:
            if dt.unknown == "none":
                return None, ""
            return dt.unknown, f"no fresh data trust score for this scope: {dt.unknown}"
        band = self._trust_band(worst[0])
        if band == "ACT":
            return None, ""
        limit = "act_min" if band == "PROPOSE" else "propose_min"
        return band, f"data trust {worst[0]:.2f} at {worst[1]} is below {limit}"

    def agent_identity(self, pattern: Pattern, facts: dict[str, Any] | None = None) -> str:
        """template@scope: the agent instance a case belongs to. The template is the one whose policy row decided
        (the pattern, or its capability when a capability row decided); the scope is that row's scope, with the
        case's own value where it has one (a region row matched through a store records region=south), else the
        pattern's trust_by facts."""
        facts = facts or {}
        pol = self.agent_policy(pattern, facts)
        template = pol.template if pol is not None and pol.template not in ("*", pattern.id) else pattern.id
        if pol is not None and pol.scope:
            parts = []
            for k in sorted(pol.scope):
                want = pol.scope[k]
                got = facts.get(k)
                if got is None or (isinstance(want, list) and got not in want) and str(got) not in map(str, want):
                    got = want if not isinstance(want, list) else "|".join(map(str, want))
                parts.append(f"{k}={got}")
            where = ",".join(parts)
        else:
            where = ",".join(f"{k}={facts.get(k)}" for k in pattern.trust_by if facts.get(k) is not None)
        return f"{template}@{where or '*'}"

    def is_shadow(self, pattern: Pattern, facts: dict[str, Any] | None = None) -> bool:
        """Shadow: recommend, never act without a person. Set in code (Guardrails), per pattern (``shadow:``
        in the registry, which is how a site goes live pattern by pattern) or per scope (agent mode OBSERVE)."""
        if self.guardrails.is_shadow(pattern.id) or pattern.shadow:
            return True
        pol = self.agent_policy(pattern, facts)
        if pol is not None and pol.mode in ("OBSERVE", "OFF"):
            return True
        if self.data_trust_cap(pattern, facts)[0] == "OBSERVE":
            return True
        cap = self.capabilities.get(pattern.capability) if pattern.capability else None
        return cap is not None and cap.mode == "observe"

    def provenance(self, pattern: Pattern, facts: dict[str, Any] | None = None) -> Provenance | None:
        """What will decide a case of this pattern: capability, method, definition and registry version."""
        if pattern.id == self.registry.fallback.id:
            return None
        cid = self._applied.get("registry")
        if cid and cid not in self._config_labels:
            cv = self.store.get_config_version(cid)
            self._config_labels[cid] = f"v{cv.version}" if cv is not None else cid
        pol = self.agent_policy(pattern, facts)
        return Provenance(capability=pattern.capability, method=pattern.method,
                          definition=pattern.definition_hash(self._fingerprint_hash(pattern)),
                          config=self._config_labels.get(cid) if cid else None,
                          **({"agent": self.agent_identity(pattern, facts), "agent_mode": pol.mode}
                             if pol is not None else {}))

    def effective_route(self, pattern: Pattern, facts: dict[str, Any] | None = None) -> Route:
        route = self.trusted_state(pattern, facts).route
        cap = ceiling(pattern)
        if route.level > cap.level:
            route = cap
        if route is Route.LLM and self.llm is None:
            route = Route.HITL
        if route is not Route.HITL and self.licence is not None and self.licence.degraded(self):
            route = Route.HITL                          # no valid licence: people decide; nothing stops
        pol = self.agent_policy(pattern, facts)
        if pol is not None and pol.mode == "PROPOSE":
            route = Route.HITL                          # a person approves every proposal in this scope
        if self.data_trust_cap(pattern, facts)[0] == "PROPOSE":
            route = Route.HITL                          # this scope's data is not good enough to act on alone
        return route

    def _unattended_last_hour(self, pattern_id: str) -> int:
        return self.store.count_unattended(pattern_id, self.clock() - timedelta(hours=1),
                                           cap=self.guardrails.max_unattended_per_hour)

    def _playbook_proposal(self, pattern: Pattern, inc: Incident) -> Proposal | None:
        """Walk the playbook: run lookups, skip steps whose `when` does not hold, render the actions.

        None when there is no playbook, a lookup fails, or no action / close step applies - the incident then
        goes to a person, never closed by accident."""
        playbook = pattern.playbook
        if inc.provenance is not None and inc.provenance.trial:
            from .methodlearn import trial_steps
            playbook = trial_steps(self, inc.provenance.trial) or playbook
        if not playbook:
            return None
        from .expr import ExprError, matches
        scope: dict[str, Any] = {"payload": inc.first_event.get("payload", {}), "facts": inc.facts,
                                 "incident": inc.model_dump(), "now": self.clock()}
        steps: list[PlaybookStep] = []
        code, closed = None, False
        try:
            for st in playbook:
                if st.when is not None and not matches(st.when, scope):
                    continue
                if st.kind == "lookup":
                    try:
                        scope[st.result_name] = self.tools.call(st.lookup, render(st.args, scope),
                                                                self.overlay.services)
                    except Exception as e:  # noqa: BLE001 - any failure: a person decides
                        self.store.audit(inc.id, "playbook_lookup_failed", {"tool": st.lookup,
                                                                            "error": f"{type(e).__name__}: {e}"})
                        return None
                    continue
                if st.kind == "close":
                    code, closed = st.disposition, True
                    break
                steps.append(PlaybookStep(action=st.action, params=render(st.params, scope)))
                code = st.disposition or code
        except ExprError as e:
            self.store.audit(inc.id, "playbook_failed", {"error": str(e)})
            return None
        if not steps and not closed:
            self.store.audit(inc.id, "playbook_no_branch", {"pattern": pattern.id})
            return None
        return Proposal(steps=steps, disposition_code=code or pattern.playbook_disposition, source="playbook")

    def _irreversible(self, steps: list[PlaybookStep]) -> list[str]:
        """Steps that need a human: neither reversible nor declared safe."""
        out = []
        for st in steps:
            spec = self.actions.get(st.action).spec
            if not (spec.reversible or spec.safe):
                out.append(st.action)
        return out

    def _drive(self, inc: Incident, pattern: Pattern) -> None:
        """Decide how to resolve a fresh (OPEN) incident and do it."""
        event = self.store.get_event(inc.event_ids[0])
        inc.event_ids = self.store.event_ids(inc.id) or inc.event_ids
        route = inc.route
        silence = self.silences.match(pattern.id, inc.facts)
        if silence is not None:
            # planned noise: recorded, nothing runs on its own, nobody is sent a card until it ends
            self._to_human(inc, pattern, f"silenced until {silence.ends_at:%d %b %H:%M}: {silence.reason}",
                           self._playbook_proposal(pattern, inc))
            return

        if route in (Route.AUTO, Route.LLM) and not inc.shadow:
            n = self._unattended_last_hour(pattern.id)
            if n >= self.guardrails.max_unattended_per_hour:
                self._to_human(inc, pattern, f"circuit breaker: {n} unattended resolutions in the last hour",
                               self._playbook_proposal(pattern, inc))
                return

        if route is Route.AUTO:
            proposal = self._playbook_proposal(pattern, inc)
            if proposal is None:  # registry should prevent this; be safe
                self._to_human(inc, pattern, "the playbook did not apply (no branch matched, or a lookup failed)",
                               None)
                return
            self._attempt_unattended(inc, pattern, proposal, resolver="auto")
            return

        if route is Route.LLM:
            outcome = self.llm.resolve(inc, pattern, event, self.store.recent_dispositions(pattern.id, 20),
                                       self.overlay.services) if self.llm else None
            self._check_fence()
            if outcome is None or outcome.proposal is None:
                err = outcome.error if outcome else "no LLM configured"
                self.store.audit(inc.id, "llm_failed", {"error": err})
                self._to_human(inc, pattern, f"LLM could not resolve: {err}", self._playbook_proposal(pattern, inc))
                return
            self.store.audit(inc.id, "llm_proposal", {"proposal": outcome.proposal.model_dump(),
                                                      "transcript_len": len(outcome.transcript)})
            p = outcome.proposal
            from .llm import looks_like_instructions
            injected = looks_like_instructions({"facts": inc.facts, "payload": event.payload if event else None})
            if injected:
                # someone may be steering the model through the case text: a person decides
                self.store.audit(inc.id, "possible_prompt_injection", {"excerpt": injected[:200]})
                self._to_human(inc, pattern, "the case text reads like instructions to the model; a person "
                                             "should check the proposal", p)
                return
            if p.confidence < pattern.llm_min_confidence:
                self._to_human(inc, pattern, f"LLM confidence {p.confidence:.2f} below {pattern.llm_min_confidence}", p)
                return
            self._attempt_unattended(inc, pattern, p, resolver="llm")
            return

        # HITL: arrive with a diagnosis if we can
        proposal = None
        if self.llm is not None and pattern.allowed_actions and pattern.diagnose:
            history = self.store.recent_dispositions(pattern.id, 20)
            outcome = self.llm.resolve(inc, pattern, event, history, self.overlay.services)
            self._check_fence()
            proposal = outcome.proposal
            self.store.audit(inc.id, "llm_diagnosis", {"proposal": proposal.model_dump() if proposal else None,
                                                       "error": outcome.error})
        if proposal is None:
            proposal = self._playbook_proposal(pattern, inc)
        reason = "shadow mode" if inc.shadow else "route is human-in-the-loop"
        self._to_human(inc, pattern, reason, proposal)

    def _attempt_unattended(self, inc: Incident, pattern: Pattern, proposal: Proposal, resolver: str) -> None:
        if inc.shadow:
            self._to_human(inc, pattern, f"shadow mode ({resolver} would have acted)", proposal)
            return
        irrev = self._irreversible(proposal.steps)
        if irrev and not self.guardrails.allow_irreversible_unattended:
            self._to_human(inc, pattern, f"irreversible action(s) {irrev} need human approval", proposal)
            return
        cap, why = self.data_trust_cap(pattern, inc.facts)
        if cap is not None:
            self.store.audit(inc.id, "data_trust_cap", {"cap": cap, "why": why})
            self._to_human(inc, pattern, why, proposal)
            return
        if self.directory is not None:
            pol = self.agent_policy(pattern, inc.facts)
            if pol is not None and pol.mode != "ACT":
                self._to_human(inc, pattern, f"agent mode {pol.mode} in this scope: a person decides", proposal)
                return
            ungranted = [st.action for st in proposal.steps if st.action and pol is not None and pol.grants
                         and pol.grants.get(st.action) != "EDIT"]
            if ungranted:
                self.store.audit(inc.id, "agent_grant", {"agent": self.agent_identity(pattern, inc.facts),
                                                         "missing_edit": ungranted})
                self._to_human(inc, pattern, f"the agent has no EDIT grant for {ungranted}", proposal)
                return
            auth = self.directory.authorize_unattended(resolver, pattern.id, proposal.steps)
            if not auth.allowed:
                self.store.audit(inc.id, "unattended_limit", {"resolver": resolver, "reason": auth.reason})
                self._to_human(inc, pattern, auth.reason, proposal)
                return
        inc.proposal = proposal
        held = self._claim_object(inc, pattern) if pattern.claims else None
        if held is not None:                              # another agent is acting on the same object
            why = (f"another agent ({held['pattern']}, case {held['incident']}) is acting on "
                   f"{held['object']} until {held['until']}: a person decides")
            self.store.audit(inc.id, "object_contention", {"object": held["object"], "held_by": held})
            self._to_human(inc, pattern, why, proposal)
            return
        with self.store.transaction():
            # check and take a slot together, across workers: the breaker cannot be overshot
            self.store.lock(f"breaker:{pattern.id}")
            n = self._unattended_last_hour(pattern.id)
            if n >= self.guardrails.max_unattended_per_hour:
                full = True
            else:
                full = False
                self._t(inc, S.RESOLVING)
                inc.attempts += 1
                self.store.put_incident(inc)
        if full:
            if pattern.claims and held is None:          # the claim was for an action that will not run now
                obj = self.object_key(pattern, inc.facts)
                if obj is not None:
                    with self.store.transaction():
                        self.store.lock(f"claim:{obj}")
                        cur = self.store.get_source_state(f"claim:{obj}") or {}
                        if cur.get("incident") == inc.id:
                            self.store.put_source_state(f"claim:{obj}", {})
            self._to_human(inc, pattern, f"circuit breaker: {n} unattended resolutions in the last hour", proposal)
            return
        res = self._execute(inc, proposal.steps, actor=resolver)
        self._after_exec(inc, pattern, proposal.steps, proposal.disposition_code, res,
                         resolver=resolver, actor=resolver, agreed=None, note=proposal.rationale)

    # ================================================================ execution
    def _execute(self, inc: Incident, steps: list[PlaybookStep], actor: str) -> _Exec:
        event = self.store.get_event(inc.event_ids[0])
        results: list[dict[str, Any]] = []
        for i, step in enumerate(steps):
            reg = self.actions.get(step.action)
            try:
                params = self.actions.validate_params(step.action, step.params)
            except ParamError as e:
                return _Exec(False, str(e), results=results)
            key = f"{inc.id}:{inc.attempts}:{i}:{step.action}"
            prior = self.store.claim_action_run(key, inc.id, step.action)
            if prior is not None:
                if prior["status"] == "ok":
                    results.append(prior["result"] or {})
                    continue
                if prior["status"] in ("running", "unknown"):
                    return _Exec(False, f"step {i} ({step.action}) outcome unknown after interruption",
                                 uncertain=True, results=results)
                return _Exec(False, f"step {i} ({step.action}) previously failed", results=results)
            ctx = ActionContext(incident=inc, event=event, actor=actor, idempotency_key=key,
                                services=self.overlay.services,
                                assert_for=(self._assert_for(inc) if actor in ("auto", "llm") else None))
            result = None
            for attempt in range(1, max(1, reg.spec.max_attempts) + 1):
                try:
                    limit = reg.spec.timeout_s or self.default_action_timeout_s
                    if limit:
                        # the caller's context goes along (hosted mode: the tenant whose secrets it may read)
                        fut = self._action_pool.submit(contextvars.copy_context().run, reg.handler, ctx, params)
                        try:
                            result = fut.result(timeout=limit)
                        except cf.TimeoutError:
                            # the call may still complete in the background: never retry blind
                            self.store.audit(inc.id, "action_timeout", {"step": i, "action": step.action,
                                                                        "timeout_s": limit})
                            self.store.finish_action_run(key, "unknown", {"detail": "timed out"})
                            return _Exec(False, f"step {i} ({step.action}) timed out after "
                                                f"{limit}s; outcome unknown", uncertain=True,
                                         results=results)
                    else:
                        result = reg.handler(ctx, params)
                    if not isinstance(result, ActionResult):
                        result = ActionResult(ok=False, detail=f"handler returned {type(result).__name__}",
                                              retryable=False)
                except Exception as e:  # noqa: BLE001 - handler bug or adapter failure: recorded, retried
                    result = ActionResult(ok=False, detail=f"{type(e).__name__}: {e}", retryable=True)
                self.store.audit(inc.id, "action_attempt", {"step": i, "action": step.action, "attempt": attempt,
                                                            "ok": result.ok, "detail": result.detail})
                self.metrics.inc("action_attempts_total", help="Action attempts", action=step.action,
                                 ok=str(result.ok).lower())
                if result.ok or not result.retryable:
                    break
            assert result is not None
            self.store.finish_action_run(key, "ok" if result.ok else "failed", result.model_dump())
            if not result.ok:
                return _Exec(False, f"step {i} ({step.action}) failed: {result.detail}", results=results)
            results.append(result.model_dump())
        return _Exec(True, results=results)

    def _after_exec(self, inc: Incident, pattern: Pattern, steps: list[PlaybookStep], code: str, res: _Exec, *,
                    resolver: str, actor: str, agreed: bool | None, note: str = "") -> None:
        if res.ok:
            self._t(inc, S.RESOLVED)
            self.store.put_incident(inc)
            self._disposition(inc, pattern, code, resolver, steps, actor=actor, agreed=agreed, note=note)
            return
        inc.last_error = res.detail
        self._t(inc, S.FAILED)
        self.store.put_incident(inc)
        self.store.audit(inc.id, "execution_failed", {"detail": res.detail, "uncertain": res.uncertain})
        reason = ("execution outcome uncertain; verify before acting: " if res.uncertain else "execution failed: ")
        self._to_human(inc, pattern, reason + res.detail, inc.proposal)

    # ================================================================ humans
    def _to_human(self, inc: Incident, pattern: Pattern, reason: str, proposal: Proposal | None,
                  role: str | None = None) -> ReviewTask:
        inc.proposal = proposal
        if inc.state is not S.AWAITING_HUMAN:
            self._t(inc, S.AWAITING_HUMAN)
        existing = self.store.open_review_for(inc.id)
        if existing is not None:
            existing.open = False
            self.store.put_review(existing)
        assignee = role or pattern.owner_role
        if self.directory is not None and self.directory.vacancy == "escalate":
            held, people = self.directory.holders(assignee, inc.facts)
            if held != assignee:                      # nobody in scope holds it: the nearest held role above
                self.store.audit(inc.id, "vacancy_escalated", {"role": assignee, "to": held,
                                                               "people": [p.id for p in people]})
                assignee = held
        digested = bool(pattern.digest_above
                        and self.store.count_open_reviews_of_pattern(pattern.id) >= pattern.digest_above)
        review = ReviewTask(incident_id=inc.id, assignee_role=assignee, reason=reason, digested=digested,
                            proposal=proposal,
                            due_at=self.clock() + timedelta(minutes=pattern.sla_minutes), created_at=self.clock())
        silence = self.silences.match(pattern.id, inc.facts)
        if silence is not None:
            self._hold_for_silence(review, silence, pattern)
        with self.store.transaction():
            self.store.put_incident(inc)
            self.store.put_review(review)
            self.store.audit(inc.id, "review_opened", {"review": review.id, "reason": reason,
                                                       "role": review.assignee_role,
                                                       **({"digested": True} if review.digested else {}),
                                                       "proposal": proposal.model_dump() if proposal else None})
        self.metrics.inc("reviews_opened_total", help="Reviews opened for people", pattern=pattern.id)
        log.info("review opened", extra={"incident": inc.id, "review": review.id, "role": review.assignee_role,
                                         "reason": reason})
        self.notify("review_opened", {"review": review.model_dump(mode="json"), "pattern": pattern.id,
                                      "facts": inc.facts, "severity": pattern.severity})
        self._schedule_deliveries(review, inc)
        lk = pattern.clear_when.lookup if pattern.clear_when else None
        if lk is not None:
            self.store.enqueue(WorkItem(kind="clear_check", incident_id=inc.id, max_attempts=3,
                                        run_after=self.clock() + timedelta(minutes=lk.every_minutes),
                                        payload={"n": 1, "review": review.id}, dedupe_key=f"clear:{review.id}:1"))
        return review

    # ================================================================ edges
    def _edge_for(self, person: Any, role: str) -> str | None:
        prefs = list(getattr(person, "edges", []) or []) if person is not None else []
        for name in prefs + self.overlay.role_edges.get(role, []) + self.overlay.default_edges:
            if name in self.overlay.edges:
                return name
        return None

    def _schedule_deliveries(self, review: ReviewTask, inc: Incident) -> None:
        if not self.overlay.edges or review.hold is not None or review.quiet or review.digested:
            return                                    # digested: it goes out on the template's digest
        people = (self.directory.people_in(review.assignee_role, inc.facts) if self.directory is not None
                  else [None])
        for person in people:
            edge = self._edge_for(person, review.assignee_role)
            if edge is None:
                continue
            pid = person.id if person is not None else None
            self.store.enqueue(WorkItem(kind="deliver", incident_id=inc.id, run_after=self.clock(),
                                        payload={"review_id": review.id, "person_id": pid, "edge": edge},
                                        dedupe_key=f"deliver:{review.id}:{pid}:{edge}:{review.escalation_level}"
                                                   + (f".{review.rounds}" if review.rounds else "")))

    def person_by_slack(self, member_id: str) -> str | None:
        """The active person whose ``contact.slack`` is this Slack member id."""
        if not member_id or self.directory is None:
            return None
        for p in self.directory.people.values():
            if str(p.contact.get("slack", "")).strip() == member_id:
                return p.id if p.active else None
        return None

    def person_by_number(self, number: str) -> str | None:
        """The person whose WhatsApp (or phone) number this is, from the people configuration."""
        from .edges import digits
        n = digits(number)
        if not n or self.directory is None:
            return None
        for p in self.directory.people.values():
            for key in ("whatsapp", "phone"):
                mine = digits(p.contact.get(key, ""))
                if mine and (mine == n or (len(mine) >= 10 and len(n) >= 10 and mine[-10:] == n[-10:])):
                    return p.id if p.active else None
        return None

    def build_card(self, review: ReviewTask, person_id: str | None = None, with_similar: bool = False,
                   localise: bool = False) -> ReviewCard:
        from .persistence import pause_reasons
        inc = self.store.get_incident(review.incident_id)
        assert inc is not None
        pattern = self.registry.get(inc.pattern_id)
        allowed = []
        for name in pattern.allowed_actions:
            spec = self.actions.get(name).spec
            allowed.append({"action": name, "description": spec.description, "params": spec.params_schema,
                            "risk": "reversible" if spec.reversible else "safe" if spec.safe else "irreversible"})
        p = review.proposal
        person = self.directory.people.get(person_id) if (self.directory is not None and person_id) else None
        similar: list[dict[str, Any]] = []
        if with_similar and self.embedder is not None:
            try:
                similar = [{"similarity": s["similarity"], "actions": [st["action"] for st in s["steps"]],
                            "code": s["code"], "resolver": s["resolver"], "reversed": s["reversed"],
                            "outcome": s["outcome"]} for s in self.similar_cases(inc, pattern, k=3)]
            except Exception:  # noqa: BLE001 - a card without examples is still a card
                similar = []
        card = ReviewCard(
            review_id=review.id, incident_id=inc.id, pattern_id=pattern.id,
            title=pattern.description or pattern.id, severity=pattern.severity, reason=review.reason,
            facts=inc.facts, assignee_role=review.assignee_role, escalation_level=review.escalation_level,
            due_at=review.due_at,
            proposal_steps=[{"action": s.action, "params": s.params} for s in p.steps] if p else [],
            proposal_code=p.disposition_code if p else None, proposal_confidence=p.confidence if p else None,
            proposal_rationale=p.rationale if p else "", allowed_actions=allowed,
            disposition_codes=pattern.disposition_codes, recipient_id=person_id,
            recipient_name=person.name if person else None,
            recipient_contact=dict(person.contact) if person else {},
            link=f"{self.card_link_base}/reviews/{review.id}" if self.card_link_base else None,
            answer_options=["approve", "modify", "reject"] if p and p.steps else ["modify", "reject"],
            similar_cases=similar, sop=pattern.sop, language=self._language(person),
            hold=(review.hold.model_dump(mode="json", include={"kind", "reason", "until", "by"})
                  if review.hold else None),
            quiet=review.quiet, pause_reasons=pause_reasons(pattern, self.case_defaults))
        if localise and card.language != "en":
            from .i18n import localise as _localise
            card = _localise(self, card)
        return card

    @staticmethod
    def _language(person: Any) -> str:
        from .i18n import norm
        return norm(getattr(person, "language", "") or "en")

    def _work_deliver(self, item: WorkItem) -> None:
        review = self.store.get_review(item.payload["review_id"])
        if review is None or not review.open:
            return                                    # answered or superseded before we got to it
        edge = self.overlay.edges[item.payload["edge"]]
        card = self.build_card(review, item.payload.get("person_id"), with_similar=True, localise=True)
        import secrets as _secrets
        token = _secrets.token_urlsafe(24)
        card.answer_token = token
        ref = edge.deliver(card)                      # raises -> retried by the queue
        self.store.put_delivery(Delivery(review_id=review.id, person_id=item.payload.get("person_id"),
                                         edge=edge.name, ref=str(ref), created_at=self.clock(),
                                         answer_token_hash=hashlib.sha256(token.encode()).hexdigest(),
                                         answer_expires_at=self.clock() + timedelta(days=self.answer_token_days)))
        self.store.audit(review.incident_id, "delivered", {"review": review.id, "edge": edge.name,
                                                           "person": item.payload.get("person_id"),
                                                           "ref": str(ref)})

    def answer(self, edge_name: str, review_id: str, person_id: str, decision: dict[str, Any], *,
               answer_token: str | None = None, verified_sender: bool = False) -> Incident:
        """An answer arriving from an edge (signature already checked by the API layer).

        The answer must belong to a card that was delivered to that person on that edge: it carries the
        card's single-use answer token, unless the channel itself proves who answered (``verified_sender``,
        e.g. WhatsApp, where the reply comes from the person's own number)."""
        if edge_name not in self.overlay.edges:
            raise EngineError(f"unknown edge {edge_name!r}")
        decision = dict(decision)
        answer_token = answer_token or decision.pop("answer_token", None)
        decision.pop("answer_token", None)
        now = self.clock()
        mine = [d for d in self.store.deliveries(review_id) if d.person_id == person_id and d.edge == edge_name]
        if not mine:
            raise AuthorizationError(f"no card for review {review_id} was sent to {person_id} on {edge_name}")
        if not verified_sender:
            h = hashlib.sha256((answer_token or "").encode()).hexdigest() if answer_token else None
            match = [d for d in mine if d.answer_token_hash and h and hmac.compare_digest(d.answer_token_hash, h)]
            if not match:
                raise AuthorizationError("the answer does not carry this card's answer token")
            if match[0].status != "sent":
                raise AuthorizationError("this card was already answered")
            if match[0].answer_expires_at is not None and match[0].answer_expires_at < now:
                raise AuthorizationError("this card's answer token has expired")
        dec = Decision.model_validate({**decision, "actor": person_id})
        inc = self.decide(review_id, dec)
        for d in mine:
            if d.status == "sent":
                d.status, d.answered_at = "answered", self.clock()
                self.store.put_delivery(d)
        self.store.audit(inc.id, "answered_via_edge", {"edge": edge_name, "person": person_id,
                                                       "review": review_id})
        return inc

    def decide_many(self, review_ids: list[str], kind: str, actor: str, *, disposition_code: str | None = None,
                    note: str = "") -> dict[str, Any]:
        """Approve the proposal of, or close, many reviews at once. Each is decided on its own with the same
        authority checks as one by one; a refusal or a stale review does not stop the others."""
        if kind not in ("approve", "reject"):
            raise EngineError("bulk decisions approve proposals or close cases (reject)")
        done, refused = [], []
        for rid in dict.fromkeys(review_ids):                   # once each, in the order given
            rv = self.store.get_review(rid)
            if rv is None or not rv.open:
                refused.append({"review": rid, "reason": "no longer open"})
                continue
            code = disposition_code
            if kind == "approve":
                if rv.proposal is None or not rv.proposal.steps:
                    refused.append({"review": rid, "reason": "nothing proposed to approve"})
                    continue
                code = code or rv.proposal.disposition_code
            try:
                inc = self.decide(rid, Decision(kind=DecisionKind(kind), actor=actor, disposition_code=code,
                                                note=note or "bulk"))
                done.append({"review": rid, "incident": inc.id, "state": inc.state.value})
            except (EngineError, AuthorizationError, ValueError) as e:
                refused.append({"review": rid, "reason": str(e),
                                **({"escalate_to": e.escalate_to} if getattr(e, "escalate_to", None) else {})})
        self.store.audit(None, "bulk_decision", {"actor": actor, "kind": kind, "decided": len(done),
                                                 "refused": len(refused)})
        return {"decided": done, "refused": refused}

    def _forward(self, inc: Incident, pattern: Pattern, review: ReviewTask, steps: list[PlaybookStep], code: str,
                 decision: Decision, to_role: str) -> Incident:
        """Someone who may only propose these steps (or not for this amount) approved them: their decision
        becomes the proposal of a new review for the role that may approve it (maker-checker on actions). Nothing
        runs yet."""
        if not self.store.close_review(review.id):
            raise EngineError(f"review {review.id} was just decided by someone else")
        review.open = False
        self.store.audit(inc.id, "proposal_forwarded", {"review": review.id, "actor": decision.actor, "to": to_role,
                                                        "steps": [s.model_dump() for s in steps], "code": code,
                                                        "note": decision.note})
        earlier = review.proposal.proposed_by if review.proposal is not None else []
        prop = Proposal(steps=steps, disposition_code=code, source="human",
                        proposed_by=[*earlier, decision.actor] if decision.actor not in earlier else list(earlier),
                        rationale=f"proposed by {decision.actor}" + (f": {decision.note}" if decision.note else ""))
        self._to_human(inc, pattern, f"approval needed: proposed by {decision.actor}", prop, role=to_role)
        return self.store.get_incident(inc.id) or inc

    def decide(self, review_id: str, decision: Decision) -> Incident:
        review = self.store.get_review(review_id)
        if review is None:
            raise EngineError(f"unknown review {review_id}")
        with self._guard(review.incident_id):
            review = self.store.get_review(review_id)
            if not review or not review.open:
                raise EngineError(f"review {review_id} is closed")
            inc = self.store.get_incident(review.incident_id)
            if inc is None or inc.state is not S.AWAITING_HUMAN:
                raise EngineError(f"incident not awaiting a human (state={inc.state.value if inc else None})")
            pattern = self.registry.get(inc.pattern_id)
            proposal = review.proposal

            if decision.kind is DecisionKind.APPROVE:
                if proposal is None:
                    raise EngineError("nothing to approve: review has no proposal; use modify or reject")
                steps = list(proposal.steps)
                code = decision.disposition_code or proposal.disposition_code
            elif decision.kind is DecisionKind.MODIFY:
                steps = decision.resolved_steps()
                if not steps:
                    raise EngineError("modify needs at least one step; use reject to close without action")
                code = decision.disposition_code or pattern.playbook_disposition
            else:
                steps = []
                code = decision.disposition_code or ""
                if not code:
                    raise EngineError("reject needs a disposition_code")

            self._check_human_choice(pattern, steps, code)
            # maker-checker survives role changes: nobody approves (or rewrites) a forward they proposed
            if (proposal is not None and decision.actor in proposal.proposed_by
                    and decision.kind is not DecisionKind.REJECT):
                self.store.audit(inc.id, "decision_denied", {"review": review.id, "actor": decision.actor,
                                                             "reason": "proposer cannot approve their own forward"})
                raise AuthorizationError("not authorised: you proposed this; another person must approve it", None)
            if self.directory is not None:
                # a proposal counts as someone's only when it is approved as it stands (modify = own steps)
                proposers = (proposal.proposed_by if proposal is not None and decision.kind is DecisionKind.APPROVE
                             else [])
                auth = self.directory.authorize_steps(decision.actor, pattern.id, review.assignee_role, steps,
                                                      inc.facts, proposed_by=proposers)
                if not auth.allowed:
                    if (auth.proposable and auth.escalate_to and decision.kind is not DecisionKind.REJECT
                            and auth.escalate_to != review.assignee_role):
                        return self._forward(inc, pattern, review, steps, code, decision, auth.escalate_to)
                    self.store.audit(inc.id, "decision_denied", {"review": review.id, "actor": decision.actor,
                                                                 "reason": auth.reason,
                                                                 "escalate_to": auth.escalate_to})
                    raise AuthorizationError(f"not authorised: {auth.reason}", auth.escalate_to)
            agreed = proposal.same_as(steps, code) if proposal is not None else None
            if not self.store.close_review(review.id):
                raise EngineError(f"review {review_id} was just decided by someone else")
            review.open = False
            self.store.audit(inc.id, "decision", {"review": review.id, "kind": decision.kind.value,
                                                  "actor": decision.actor, "agreed": agreed,
                                                  "steps": [s.model_dump() for s in steps], "code": code,
                                                  "note": decision.note})
            actor = f"human:{decision.actor}"
            if not steps or inc.shadow:
                # nothing to execute here (reject, or shadow mode where people act in the legacy system)
                self._disposition(inc, pattern, code, "human", steps, actor=actor, agreed=agreed, note=decision.note)
                return self.store.get_incident(inc.id)  # type: ignore[return-value]
            inc.proposal = Proposal(steps=steps, disposition_code=code, source="human", rationale=decision.note)
            self._t(inc, S.RESOLVING)
            inc.attempts += 1
            self.store.put_incident(inc)
            res = self._execute(inc, steps, actor=actor)
            self._after_exec(inc, pattern, steps, code, res, resolver="human", actor=actor, agreed=agreed,
                             note=decision.note)
            return self.store.get_incident(inc.id)  # type: ignore[return-value]

    def _check_human_choice(self, pattern: Pattern, steps: list[PlaybookStep], code: str) -> None:
        if code not in pattern.disposition_codes:
            raise EngineError(f"disposition_code {code!r} not in {pattern.disposition_codes}")
        for st in steps:
            if not self.actions.has(st.action):
                raise EngineError(f"unknown action {st.action!r}")
            if pattern.allowed_actions and st.action not in pattern.allowed_actions:
                raise EngineError(f"action {st.action!r} not allowed for {pattern.id}")
            try:
                self.actions.validate_params(st.action, st.params)
            except ParamError as e:
                raise EngineError(str(e)) from None

    # ================================================================ disposition & learning
    def _disposition(self, inc: Incident, pattern: Pattern, code: str, resolver: str, steps: list[PlaybookStep], *,
                     actor: str, agreed: bool | None, note: str = "") -> Disposition:
        d = Disposition(incident_id=inc.id, pattern_id=pattern.id, fingerprint=inc.fingerprint, code=code,
                        resolver=resolver, steps=steps,
                        proposal_source=inc.proposal.source if inc.proposal else None,
                        agreed_with_proposal=agreed, shadow=inc.shadow, actor=actor, note=note,
                        provenance=inc.provenance, created_at=self.clock())
        if resolver in ("auto", "llm") and not inc.shadow and self._sampled(pattern, inc.id):
            d.spot_check = "pending"                      # nobody looks at ACT decisions unless we sample them
        with self.store.transaction():
            self._t(inc, S.DISPOSITIONED)
            self.store.put_incident(inc)
            self.store.put_disposition(d)
            self.store.audit(inc.id, "dispositioned", {"code": code, "resolver": resolver, "agreed": agreed,
                                                       **({"spot_check": "pending"} if d.spot_check else {})})
            self.metrics.inc("dispositions_total", help="Incidents closed, by pattern and resolver",
                             pattern=pattern.id, resolver=resolver, shadow=str(inc.shadow).lower())
            for child in self.store.children(inc.id):
                if child.state is S.SUPPRESSED:
                    cp = self.registry.get(child.pattern_id)
                    self._t(child, S.DISPOSITIONED)
                    self.store.put_incident(child)
                    self.store.put_disposition(Disposition(
                        incident_id=child.id, pattern_id=cp.id, fingerprint=child.fingerprint,
                        code="resolved_by_parent", resolver="parent", shadow=child.shadow,
                        note=f"parent {inc.id}", provenance=child.provenance, created_at=self.clock()))
                    self.store.audit(child.id, "dispositioned", {"code": "resolved_by_parent", "parent": inc.id})
            # an outcome check verifies a fix: one with steps, or a close whose code says it was fixed outside
            # Sentinel (``codes``: "matched in the books" is checked against the KPI like any action)
            oc_codes = (pattern.outcome_check or {}).get("codes") or []
            if pattern.outcome_check and (steps or d.code in oc_codes) and not inc.shadow:
                self.store.enqueue(WorkItem(
                    kind="outcome_check", incident_id=inc.id, dedupe_key=f"outcome:{inc.id}",
                    max_attempts=int(pattern.outcome_check.get("max_checks", 5)),
                    run_after=self.clock() + timedelta(minutes=int(pattern.outcome_check.get("after_minutes", 60)))))
            # a trial case was proposed by a candidate method: it says nothing about the current method's trust
            if pattern.id != self.registry.fallback.id and not (inc.provenance and inc.provenance.trial):
                with self._pattern_tx(pattern):
                    st, *pooled = self.trust_states(pattern, inc.facts)
                    notes = self.learner.observe(st, d, ceiling(pattern), self.llm is not None)
                    self.store.put_pattern_state(st)
                    for pst in pooled:                      # the template's pooled trust learns from every scope
                        notes += [f"pooled: {n}" for n in
                                  self.learner.observe(pst, d, ceiling(pattern), self.llm is not None)]
                        self.store.put_pattern_state(pst)
                for n in notes:
                    self.store.audit(inc.id, "learning", {"pattern": pattern.id, "note": n})
                if st.pending_promotion is not None and any("proposed" in n for n in notes):
                    self.notify("promotion_proposed", {"pattern": st.pattern_id, "to": st.pending_promotion.value,
                                                       "streak": st.streak})
            if self.embedder is not None and self.async_mode and resolver != "system":
                self.store.enqueue(WorkItem(kind="embed", incident_id=inc.id, dedupe_key=f"embed:{inc.id}",
                                            max_attempts=10, run_after=self.clock()))
        if resolver not in ("system", "parent"):
            try:
                from .methodlearn import observe
                observe(self, inc, d)                  # candidate methods in shadow: would they have agreed?
            except Exception:  # noqa: BLE001 - measuring a candidate must never affect the case
                log.exception("method shadow failed", extra={"incident": inc.id})
        if self.embedder is not None and not self.async_mode and resolver != "system":
            try:
                self.embed_case(inc.id)
            except Exception as e:  # noqa: BLE001 - a missing vector only means one fewer example later
                log.warning("embedding failed", extra={"incident": inc.id, "error": f"{type(e).__name__}: {e}"})
        return d

    # ================================================================ similar cases
    def case_text(self, inc: Incident, pattern: Pattern, event: Event | None = None) -> str:
        from .similarity import case_text
        if event is None and inc.event_ids:
            event = self.store.get_event(inc.event_ids[0])
        return case_text(pattern.id, pattern.description, inc.facts, event.type if event else None,
                         event.payload if event else None, self.masker)

    def _embed(self, texts: list[str]) -> list[list[float]]:
        t0 = time.perf_counter()
        ok, err = False, None
        try:
            vecs = self.embedder.embed(texts)
            ok = True
            return vecs
        except Exception as e:
            err = f"{type(e).__name__}: {e}"
            raise
        finally:
            model = str(getattr(self.embedder, "model", type(self.embedder).__name__))
            self.metrics.inc("embeddings_total", float(len(texts)), help="Texts embedded", model=model,
                             ok=str(ok).lower())
            if self.router is not None:
                from .routing import ModelRun
                usage = getattr(self.embedder, "last_usage", None) or {}
                self.router._record(ModelRun(
                    id=uuid.uuid4().hex[:16], ts=time.time(), task="embed", model=model, incident_id=None, ok=ok,
                    error=err, latency_ms=round((time.perf_counter() - t0) * 1000, 1),
                    chars_in=sum(len(t) for t in texts), chars_out=0, est_cost=0.0,
                    prompt_tokens=usage.get("prompt_tokens")))

    def embed_case(self, incident_id: str) -> bool:
        """Store the vector of a closed case (masked text; only the vector is kept). True if stored."""
        if self.embedder is None:
            return False
        inc = self.store.get_incident(incident_id)
        if inc is None:
            return False
        try:
            pattern = self.registry.get(inc.pattern_id)
        except KeyError:
            return False
        vec = self._embed([self.case_text(inc, pattern)])[0]
        self.store.put_case_vector(inc.id, pattern.id, inc.tenant, str(self.embedder.model), vec)
        return True

    def _work_embed(self, item: WorkItem) -> None:
        if item.incident_id:
            self.embed_case(item.incident_id)

    def similar_cases(self, inc: Incident, pattern: Pattern, event: Event | None = None,
                      k: int | None = None, before: datetime | None = None) -> list[dict[str, Any]]:
        """The nearest closed cases of this pattern, with how they ended (for the model's brief)."""
        if self.embedder is None:
            return []
        vec = self._embed([self.case_text(inc, pattern, event)])[0]
        want = k or self.similar_k
        hits = self.store.similar_cases(pattern.id, inc.tenant, str(self.embedder.model), vec,
                                        want if before is None else want * 4, exclude=inc.id)
        out = []
        for iid, sim in hits:
            d = self.store.get_disposition(iid)
            past = self.store.get_incident(iid)
            if d is None or past is None or (before is not None and d.created_at >= before):
                continue
            if len(out) >= want:
                break
            out.append({"similarity": round(sim, 3), "facts": past.facts, "code": d.code,
                        "steps": [st.model_dump() for st in d.steps], "resolver": d.resolver,
                        "reversed": d.reversed, "outcome": d.outcome, "note": d.note[:300]})
        self.metrics.inc("similar_lookups_total", help="Similar-case lookups", found=str(bool(out)).lower())
        return out

    def evaluate(self, candidate: Any, **kw: Any) -> Any:
        """Replay known-good past cases through a model and compare (see sentinel.evaluate)."""
        from .evaluate import evaluate
        return evaluate(self, candidate, **kw)

    def backfill_embeddings(self, limit: int = 1000, batch: int = 32) -> int:
        """Embed closed cases that have no vector for the current embedder yet. Returns how many."""
        if self.embedder is None:
            return 0
        model = str(self.embedder.model)
        todo = []
        for d in self.store.dispositions():
            if len(todo) >= limit:
                break
            if d.resolver != "parent" and not self.store.has_case_vector(d.incident_id, model):
                inc = self.store.get_incident(d.incident_id)
                if inc is not None and inc.pattern_id in {p.id for p in self.registry.all()}:
                    todo.append(inc)
        done = 0
        for i in range(0, len(todo), batch):
            chunk = todo[i:i + batch]
            pats = [self.registry.get(x.pattern_id) for x in chunk]
            vecs = self._embed([self.case_text(x, p) for x, p in zip(chunk, pats, strict=True)])
            for x, p, v in zip(chunk, pats, vecs, strict=True):
                self.store.put_case_vector(x.id, p.id, x.tenant, model, v)
                done += 1
        return done

    def reverse(self, incident_id: str, actor: str, note: str = "") -> Disposition:
        """A human says the outcome was wrong. Compensate what can be undone; teach the registry."""
        with self._guard(incident_id):
            d = self.store.get_disposition(incident_id)
            inc = self.store.get_incident(incident_id)
            if d is None or inc is None:
                raise EngineError(f"incident {incident_id} has no disposition")
            if d.reversed:
                raise EngineError("already reversed")
            if d.shadow:
                raise EngineError("shadow dispositions executed nothing; nothing to reverse")
            self._require_meta(actor, "__reverse__", d.pattern_id)
            event = self.store.get_event(inc.event_ids[0])
            not_undone: list[str] = []
            for i, st in reversed(list(enumerate(d.steps))):
                reg = self.actions.get(st.action)
                if reg.compensate is None:
                    not_undone.append(st.action)
                    continue
                key = f"{inc.id}:undo:{i}:{st.action}"
                if self.store.claim_action_run(key, inc.id, f"undo:{st.action}") is not None:
                    continue
                ctx = ActionContext(incident=inc, event=event, actor=f"human:{actor}", idempotency_key=key,
                                    services=self.overlay.services)
                try:
                    r = reg.compensate(ctx, st.params)
                except Exception as e:  # noqa: BLE001 - recorded; the step is reported as not undone
                    r = ActionResult(ok=False, detail=f"{type(e).__name__}: {e}")
                self.store.audit(inc.id, "compensation_attempt", {"step": i, "action": st.action, "ok": r.ok,
                                                                  "detail": r.detail})
                self.store.finish_action_run(key, "ok" if r.ok else "failed", r.model_dump())
                if not r.ok:
                    not_undone.append(st.action)
            d.reversed = True
            d.note = (d.note + f" | reversed by {actor}: {note}").strip(" |")
            pattern = self.registry.get(d.pattern_id)
            was_check = d.spot_check
            if d.spot_check == "undo_pending":            # judged wrong and waiting for an undo: this is the undo
                d.spot_check, d.spot_checked_by = "failed", actor
            elif d.spot_check == "pending":               # reversed before anyone checked it: the check is settled
                d.spot_check, d.spot_checked_by = "reversed", actor
            with self.store.transaction():
                self._charge_trust(d, pattern, inc)          # once per decision, whichever path got here first
                self.store.put_disposition(d)
                self.store.audit(inc.id, "reversed", {"actor": actor, "note": note, "not_undone": not_undone})
                if was_check == "undo_pending":
                    self.store.audit(inc.id, "spot_check_undone", {"actor": actor, "note": note, "via": "reverse"})
            if not_undone:
                self.notify("manual_undo_needed", {"incident": inc.id, "actions": not_undone})
            return d

    def _require_meta(self, actor: str, meta: str, pattern_id: str) -> None:
        if self.directory is None:
            return
        auth = self.directory.authorize_meta(actor, meta, pattern_id)
        if not auth.allowed:
            self.store.audit(None, "meta_denied", {"actor": actor, "meta": meta, "pattern": pattern_id,
                                                   "reason": auth.reason})
            raise AuthorizationError(f"not authorised: {auth.reason}")

    def approve_promotion(self, pattern_id: str, actor: str) -> PatternState:
        """Approve a pending promotion ("pattern" or "pattern@segment"). To AUTO, a directory requires two
        different approvers."""
        pattern, seg = self._split(pattern_id)
        self._require_meta(actor, "__promote__", pattern.id)
        with self._pattern_tx(pattern):
            return self._approve_promotion(pattern, seg, pattern_id, actor)

    def _approve_promotion(self, pattern: Pattern, seg: str | None, pattern_id: str, actor: str) -> PatternState:
        st = self.pattern_state(pattern, seg)
        if st.pending_promotion is None:
            raise EngineError(f"{pattern_id} has no pending promotion")
        target = st.pending_promotion
        needed = 2 if (self.directory is not None and self.directory.two_person_auto_promotion
                       and target is Route.AUTO) else 1
        if actor in st.promotion_approvals:
            raise EngineError(f"{actor} already approved this promotion; it needs a different approver")
        st.promotion_approvals.append(actor)
        if len(st.promotion_approvals) < needed:
            self.store.put_pattern_state(st)
            self.store.audit(None, "promotion_approval_recorded", {"pattern": pattern_id, "to": target.value,
                                                                   "actor": actor, "needed": needed})
            return st
        approvers = list(st.promotion_approvals)
        Learner._set_route(st, target)
        self.store.put_pattern_state(st)
        self.store.audit(None, "promotion_approved", {"pattern": pattern_id, "to": target.value,
                                                      "approvers": approvers})
        return st

    def reject_promotion(self, pattern_id: str, actor: str, note: str = "") -> PatternState:
        pattern, seg = self._split(pattern_id)
        self._require_meta(actor, "__promote__", pattern.id)
        with self._pattern_tx(pattern):
            st = self.pattern_state(pattern, seg)
            if st.pending_promotion is None:
                raise EngineError(f"{pattern_id} has no pending promotion")
            st.pending_promotion = None
            st.promotion_approvals = []
            st.streak = 0
            self.store.put_pattern_state(st)
            self.store.audit(None, "promotion_rejected", {"pattern": pattern_id, "actor": actor, "note": note})
            return st

    OVERSIGHT_ACTIONS = ("stop", "demote", "cap")

    def oversee(self, pattern_id: str, action: str, actor: str, reason: str,
                route: Route | None = None) -> list[PatternState]:
        """Layer D's lever on an agent (ADR-003): ``stop`` (to a person), ``demote`` (one route down) or ``cap``
        (to ``route``), on a template or one scope ("pattern@segment"). Only a holder of an oversight role
        configured for the template may use it, never its owners, and a reason is required. Recorded as
        ``oversight_action``. It only lowers autonomy; raising it again is earned or promoted as usual."""
        if action not in self.OVERSIGHT_ACTIONS:
            raise EngineError(f"oversight action must be one of {self.OVERSIGHT_ACTIONS}")
        if not reason.strip():
            raise EngineError("an oversight action needs a reason")
        if action == "cap" and route is None:
            raise EngineError("cap needs the route to cap at (hitl or llm)")
        pattern, seg = self._split(pattern_id)
        d = self.directory
        roles = d.overseers(pattern.id, pattern.capability) if d is not None else []
        if not roles:
            raise EngineError(f"no oversight role is configured for {pattern.id}")
        if not set(roles) & d.roles_of(actor):
            self.store.audit(None, "meta_denied", {"meta": "oversight", "actor": actor, "pattern": pattern_id})
            raise AuthorizationError(f"{actor} holds no oversight role for {pattern.id} ({roles})")
        with self._pattern_tx(pattern):
            st = self.pattern_state(pattern, seg)
            segs = ([self.pattern_state(pattern, x.pattern_id.partition("@")[2])
                     for x in self.store.pattern_states(f"{pattern.id}@")] if pattern.trust_by and seg is None
                    else [])
            changed = []
            for x in (st, *segs):
                to = (Route.HITL if action == "stop" else
                      Route.from_level(max(0, x.route.level - 1)) if action == "demote" else
                      (route or Route.HITL))
                if to.level < x.route.level:
                    was = x.route
                    Learner._set_route(x, to)
                    if seg is not None:              # one scope stopped: pooled trust can't lift it
                        x.cap = to
                    self.store.put_pattern_state(x)
                    changed.append({"state": x.pattern_id, "from": was.value, "to": to.value})
                elif seg is not None and (x.cap is None or to.level < x.cap.level):
                    x.cap = to                       # already low on its own, but the pool may be higher
                    self.store.put_pattern_state(x)
                    changed.append({"state": x.pattern_id, "held_at": to.value})
            self.store.audit(None, "oversight_action", {"pattern": pattern_id, "action": action, "actor": actor,
                                                        "reason": reason, "changed": changed,
                                                        **({"cap": route.value} if route else {})})
        self.notify("oversight_action", {"pattern": pattern_id, "action": action, "actor": actor, "reason": reason})
        return [st, *segs]

    def set_route(self, pattern_id: str, route: Route, actor: str) -> PatternState:
        """Manual override (e.g. kill switch: force HITL). On a pattern with `trust_by`, setting the pattern's
        route sets every segment's (and new segments start there); each then earns trust back on its own.
        "pattern@segment" sets one segment's route."""
        pattern, seg = self._split(pattern_id)
        if route.level > ceiling(pattern).level:
            raise EngineError(f"{route.value} exceeds ceiling {ceiling(pattern).value} for {pattern.id}")
        with self._pattern_tx(pattern):
            return self._set_route(pattern, seg, route, actor)

    def _set_route(self, pattern: Pattern, seg: str | None, route: Route, actor: str) -> PatternState:
        pattern_id = pattern.id
        st = self.pattern_state(pattern, seg)
        segs = ([self.pattern_state(pattern, s.pattern_id.partition("@")[2])
                 for s in self.store.pattern_states(f"{pattern.id}@")] if pattern.trust_by and seg is None else [])
        states = [st, *segs]
        if any(route.level < s.route.level for s in states) and not any(route.level > s.route.level for s in states):
            # lowering autonomy is the kill switch: either right is enough
            if self.directory is not None:
                a = self.directory.authorize_meta(actor, "__kill_switch__", pattern_id)
                if not a.allowed:
                    self._require_meta(actor, "__set_route__", pattern_id)
        else:
            self._require_meta(actor, "__set_route__", pattern_id)
        for s in states:
            lowering = route.level < s.route.level
            Learner._set_route(s, route)
            if seg is not None:                      # a scope set by hand: held there (or released when raised)
                s.cap = route if lowering or s.cap is not None and route.level <= s.cap.level else None
            self.store.put_pattern_state(s)
        self.store.audit(None, "route_set", {"pattern": st.pattern_id, "route": route.value, "actor": actor,
                                             **({"segments": len(segs)} if segs else {})})
        return st

    # ================================================================ operations
    def sweep(self) -> list[ReviewTask]:
        """Escalate reviews past their SLA; release holds whose time is up; close cases that expired; send
        the daily overdue list. Run on a schedule (the worker's maintenance loop does)."""
        from .persistence import digest_due, escalation, send_digest
        now = self.clock()
        escalated = []
        for r in self.store.open_reviews(due_before=now):
            if r.quiet:
                continue                                  # on the daily list, no more cards
            inc = self.store.get_incident(r.incident_id)
            if inc is None:
                continue
            pattern = self.registry.get(inc.pattern_id)
            with self._guard(inc.id):
                r = self.store.get_review(r.id)           # type: ignore[assignment]
                if r is None or not r.open or r.quiet:
                    continue
                silence = self.silences.match(pattern.id, inc.facts, now)
                if r.hold is not None:
                    if r.hold.kind == "silence" and silence is not None:
                        self._hold_for_silence(r, silence, pattern)        # extended, or another one covers it
                        self.store.put_review(r)
                        continue
                    self._release(r, inc, pattern, by=None, why="the hold ended", send=True)
                    continue
                if silence is not None:
                    self._hold_for_silence(r, silence, pattern)
                    self.store.put_review(r)
                    self.store.audit(inc.id, "held_by_silence", {"review": r.id, "silence": silence.id,
                                                                 "until": silence.ends_at.isoformat()})
                    continue
                old_role = r.assignee_role
                new_role = old_role
                rule = escalation(pattern, self.case_defaults)
                if rule is not None and old_role in rule.stops():
                    pass                                          # the top for this exception
                elif r.escalation_level == 0 and pattern.escalation_role:
                    new_role = pattern.escalation_role
                elif self.directory is not None:
                    if old_role in getattr(self.directory, "stop_at", ()):
                        pass                                      # the people configuration's stop list
                    else:
                        new_role = self.directory.parent_of(old_role) or old_role   # at the top it stays there
                elif pattern.escalation_role:
                    new_role = pattern.escalation_role
                if new_role == old_role and r.escalation_level > 0:
                    r.top_repeats += 1
                    if rule is not None and rule.repeat is not None and r.top_repeats > rule.repeat:
                        r.quiet = True
                        self.store.put_review(r)
                        self.store.audit(inc.id, "escalation_stopped", {"review": r.id, "role": old_role,
                                                                        "level": r.escalation_level,
                                                                        "repeats": rule.repeat})
                        self.notify("review_quiet", {"review": r.model_dump(mode="json"), "pattern": pattern.id})
                        continue
                r.escalation_level += 1
                r.assignee_role = new_role
                r.due_at = now + timedelta(minutes=pattern.sla_minutes)
                self.store.put_review(r)
                self.store.audit(inc.id, "escalated", {"review": r.id, "level": r.escalation_level,
                                                       "role": r.assignee_role})
            self.notify("review_escalated", {"review": r.model_dump(mode="json"), "pattern": pattern.id})
            if r.digested and not pattern.digest_above:   # never stranded: no digest means a card
                r.digested = False
                self.store.put_review(r)
            self._schedule_deliveries(r, inc)
            escalated.append(r)
        if self._last_expiry is None or now - self._last_expiry >= timedelta(minutes=5):
            self._last_expiry = now
            self.expire_cases()
        last = (self.store.get_source_state("__method_propose__") or {}).get("day")
        if last != now.date().isoformat():                 # once a day: propose methods from what people did
            self.store.put_source_state("__method_propose__", {"day": now.date().isoformat()})
            try:
                self.propose_methods()
            except Exception:  # noqa: BLE001 - proposing is advice; it must never stop the sweep
                log.exception("proposing methods failed")
        day = digest_due(self, now)
        if day is not None and any(r.quiet for r in self.store.open_reviews(due_before=now)):
            send_digest(self, day)
        self.send_template_digests()
        return escalated

    # ================================================================ object contention between agents
    def object_key(self, pattern: Pattern, facts: dict[str, Any]) -> str | None:
        """The object an agent acts on, from the pattern's ``claims`` facts; None when a fact is missing (then no
        claim is taken and nothing is blocked: the object is not identifiable)."""
        parts = []
        for k in sorted(pattern.claims):
            v = facts.get(k)
            if v is None or isinstance(v, dict | list):
                return None
            parts.append(f"{k}={v}")
        return "|".join(parts) if parts else None

    def object_claim(self, pattern: Pattern, facts: dict[str, Any]) -> dict[str, Any] | None:
        """The live claim on this case's object by ANOTHER template (None: free, or held by this template)."""
        obj = self.object_key(pattern, facts)
        if obj is None:
            return None
        cur = self.store.get_source_state(f"claim:{obj}")
        if cur and cur.get("pattern") != pattern.id and float(cur.get("until_ts", 0)) > self.clock().timestamp():
            return cur
        return None

    def _claim_object(self, inc: Incident, pattern: Pattern) -> dict[str, Any] | None:
        """Take the claim on the case's object for ``claim_minutes``; return the other template's live claim
        instead when there is one. Checked and taken together, across workers."""
        obj = self.object_key(pattern, inc.facts)
        if obj is None:
            return None
        key = f"claim:{obj}"
        now = self.clock()
        with self.store.transaction():
            self.store.lock(key)
            cur = self.store.get_source_state(key)
            if cur and cur.get("pattern") != pattern.id and float(cur.get("until_ts", 0)) > now.timestamp():
                return cur
            until = now + timedelta(minutes=pattern.claim_minutes)
            self.store.put_source_state(key, {"object": obj, "pattern": pattern.id, "incident": inc.id,
                                              "until": until.isoformat(), "until_ts": until.timestamp()})
        return None

    # ================================================================ Layer D: spot checks and agent incidents
    @staticmethod
    def _sampled(pattern: Pattern, incident_id: str) -> bool:
        """Deterministic sampling: the same case is always in or out (replays and tests agree)."""
        rate = pattern.spot_check_rate or 0.0
        if rate <= 0:
            return False
        h = int(hashlib.sha256(f"{pattern.id}|{incident_id}".encode()).hexdigest()[:8], 16) / 0xFFFFFFFF
        return h < rate

    def _may_check(self, actor: str, pattern: Pattern, facts: dict[str, Any]) -> bool:
        d = self.directory
        if d is None:
            return True
        overseers = set(d.overseers(pattern.id, pattern.capability))
        return d.can_act(actor, pattern.owner_role, facts) or bool(overseers & d.roles_of(actor))

    def _may_reverse(self, actor: str, pattern: Pattern) -> bool:
        d = self.directory
        return True if d is None else d.authorize_meta(actor, "__reverse__", pattern.id).allowed

    def undo_holders(self, pattern: Pattern) -> dict[str, list[str]]:
        """Who may undo this template's decisions (__reverse__): roles and the active people holding them."""
        d = self.directory
        if d is None:
            return {"roles": [], "people": []}
        people = sorted(p.id for p in d.people.values() if p.active and self._may_reverse(p.id, pattern))
        roles = sorted({r.role_id for r in d.rules if r.action == "__reverse__"
                        and ("*" in r.patterns or pattern.id in r.patterns)})
        return {"roles": roles, "people": people}

    def undo_owners(self, pattern: Pattern, facts: dict[str, Any] | None = None,
                    checker: str | None = None) -> dict[str, Any]:
        """Who holds a decision judged wrong. Holders of __reverse__ undo it. If nobody active holds it, the case is
        still held, never nobody's: the template's oversight roles, else its escalation role in scope, else its
        owner role in scope, else the person who judged it. Those fallback holders can keep it with a reason (and
        see that __reverse__ must be granted to undo it). BUILDER_MISSES check 4."""
        base = self.undo_holders(pattern)
        if base["people"]:
            return {**base, "can_undo": True, "fallback": None}
        d = self.directory
        chain: list[tuple[str, list[str]]] = []
        if d is not None:
            for role in d.overseers(pattern.id, pattern.capability):
                chain.append((role, sorted(p.id for p in d.people.values()
                                           if p.active and role in d.roles_of(p.id))))
            for role in (pattern.escalation_role, pattern.owner_role):
                if role:
                    held, people = d.holders(role, facts or {})
                    chain.append((held, sorted(p.id for p in people if p.active)))
        for role, people in chain:
            if people:
                return {"roles": base["roles"], "people": people, "can_undo": False, "fallback": role}
        return {"roles": base["roles"], "people": [checker] if checker else [], "can_undo": False,
                "fallback": "checker" if checker else None}

    def _charge_trust(self, d: Disposition, pattern: Pattern, inc: Incident) -> None:
        """A wrong unattended decision lowers trust once, however many paths report it (verdict, undo, reverse).
        Call inside a transaction; the caller stores ``d``."""
        if d.trust_charged or pattern.id == self.registry.fallback.id or d.resolver == "parent":
            d.trust_charged = True
            return
        self.store.lock(f"pattern_state:{pattern.id}")
        for stt in self.trust_states(pattern, inc.facts):       # a reversal demotes the pool too
            for n in self.learner.observe_reversal(stt):
                self.store.audit(inc.id, "learning", {"pattern": stt.pattern_id, "note": n})
            self.store.put_pattern_state(stt)
        d.trust_charged = True

    def spot_checks(self, person_id: str | None = None, pattern_id: str | None = None,
                    limit: int = 200) -> list[dict[str, Any]]:
        """Unattended decisions waiting for a person: sampled ones to check (owner role in scope or above, and the
        template's oversight role), and ones judged wrong that still need undoing (holders of __reverse__)."""
        out = []
        for d in self.store.dispositions(pattern_id):
            if d.spot_check not in ("pending", "undo_pending") or (d.spot_check == "pending" and d.reversed):
                continue                                  # (a reversed decision recorded before v0.24.0 is settled)
            inc = self.store.get_incident(d.incident_id)
            try:
                pattern = self.registry.get(d.pattern_id)
            except KeyError:
                continue
            if inc is None:
                continue
            owners = (self.undo_owners(pattern, inc.facts, d.spot_checked_by) if d.spot_check == "undo_pending"
                      else None)
            if person_id is not None:
                ok = (self._may_check(person_id, pattern, inc.facts) if owners is None
                      else person_id in owners["people"])
                if not ok:
                    continue
            out.append({"incident": d.incident_id, "pattern": d.pattern_id, "resolver": d.resolver,
                        "status": d.spot_check, "code": d.code, "actions": [st.action for st in d.steps],
                        "at": d.created_at.isoformat(), "agent": d.provenance.agent if d.provenance else None,
                        "note": d.note if d.spot_check == "undo_pending" else "",
                        **({"can_undo": owners["can_undo"], "held_by": owners["fallback"]} if owners else {}),
                        "facts": {k: v for k, v in inc.facts.items()
                                  if k not in ("event_type", "source") and v is not None}})
        out.sort(key=lambda r: (r["status"] != "undo_pending", r["at"]))
        return out[:limit]

    def spot_check_verdict(self, incident_id: str, actor: str, ok: bool, note: str = "") -> dict[str, Any]:
        """A person's verdict on a sampled unattended decision. Wrong: it is reversed (what can be undone is
        undone) and the agent's trust drops; if the checker may not reverse, the trust drops anyway and the case
        says who must undo it. Right: recorded as agreement."""
        if not isinstance(ok, bool):
            raise EngineError("the verdict is true (right) or false (wrong)")
        if not isinstance(note, str):
            raise EngineError("the note must be text")
        d = self.store.get_disposition(incident_id)
        inc = self.store.get_incident(incident_id)
        if d is None or inc is None or d.spot_check is None:
            raise EngineError(f"{incident_id} is not a sampled unattended decision")
        pattern = self.registry.get(d.pattern_id)
        if d.spot_check == "undo_pending":                # judged wrong earlier; a reverse holder finishes it
            return self._finish_undo(d, inc, pattern, actor, ok, note)
        if d.spot_check == "reversed" and not ok:          # reversed before the check: agreeing changes nothing
            d.spot_check, d.spot_checked_by = "failed", actor
            with self.store.transaction():
                self.store.put_disposition(d)
                self.store.audit(inc.id, "spot_check_failed", {"actor": actor, "note": note, "already": True})
            return {"incident": incident_id, "verdict": "failed", "reversed": True, "already": True}
        if d.spot_check != "pending":
            raise EngineError(f"{incident_id} was already checked ({d.spot_check})")
        if not self._may_check(actor, pattern, inc.facts):
            raise AuthorizationError(f"{actor} may not check {pattern.id} cases in this scope",
                                     escalate_to=pattern.owner_role)
        if not ok and not note.strip():
            raise EngineError("say what was wrong: it is recorded and teaches the agent")
        result: dict[str, Any] = {"incident": incident_id, "verdict": "passed" if ok else "failed"}
        if not ok and d.reversed:                         # someone already reversed it: trust already paid for it
            result.update(reversed=True, already=True)
        elif not ok:
            try:
                self.reverse(incident_id, actor, f"spot check failed: {note}")
                result["reversed"] = True
            except (AuthorizationError, EngineError) as e:
                d = self.store.get_disposition(incident_id) or d
                with self.store.transaction():                # trust drops whoever checked, once
                    self._charge_trust(d, pattern, inc)
                    self.store.put_disposition(d)
                result.update(reversed=False, undo_by=self.undo_owners(pattern, inc.facts, actor), why=str(e))
            d = self.store.get_disposition(incident_id) or d
        d.spot_check, d.spot_checked_by = result["verdict"], actor
        if not ok and not result.get("reversed"):
            d.spot_check = "undo_pending"                 # never a dead end: it waits in the undo holders' queue
            d.note = (d.note + f" | judged wrong by {actor}: {note}").strip(" |")
        with self.store.transaction():
            self.store.put_disposition(d)
            self.store.audit(inc.id, f"spot_check_{result['verdict']}", {"actor": actor, "note": note, **result})
        if not ok:
            self.notify("spot_check_failed", {"incident": incident_id, "pattern": pattern.id, "actor": actor,
                                              **({"undo_by": result["undo_by"]} if "undo_by" in result else {})})
            if "undo_by" in result and not result["undo_by"]["can_undo"]:
                self.store.audit(inc.id, "spot_check_undo_unowned", {"pattern": pattern.id,
                                                                     "held_by": result["undo_by"]["fallback"],
                                                                     "people": result["undo_by"]["people"]})
        return result

    def _finish_undo(self, d: Disposition, inc: Incident, pattern: Pattern, actor: str, ok: bool,
                     note: str) -> dict[str, Any]:
        """A case judged wrong whose checker could not undo it: a __reverse__ holder undoes it (ok=False) or,
        with a reason, keeps it (ok=True). Trust already dropped when it was judged wrong."""
        owners = self.undo_owners(pattern, inc.facts, d.spot_checked_by)
        may_undo = self._may_reverse(actor, pattern)
        if not may_undo and not (ok and actor in owners["people"]):
            if not owners["can_undo"]:
                raise AuthorizationError(f"nobody active holds __reverse__ for {pattern.id}: grant it in the people "
                                         f"configuration to undo this, or keep it with a reason",
                                         escalate_to=owners["fallback"])
            raise AuthorizationError(f"{actor} may not undo {pattern.id} decisions (needs __reverse__)",
                                     escalate_to=(owners["roles"] or [None])[0])
        if ok:
            if not note.strip():
                raise EngineError("say why it stays as it is: it is recorded")
            d.spot_check, d.spot_checked_by = "failed_kept", actor
            with self.store.transaction():                # the state and its audit row land together
                self.store.put_disposition(d)
                self.store.audit(inc.id, "spot_check_kept", {"actor": actor, "note": note})
            return {"incident": inc.id, "verdict": "failed_kept", "reversed": False}
        try:                                              # reverse settles the check and audits it
            self.reverse(inc.id, actor, f"spot check undo: {note or 'judged wrong'}")
        except EngineError as e:
            if "already reversed" not in str(e):
                raise
            d = self.store.get_disposition(inc.id) or d   # reversed before this release: settle it here
            d.spot_check, d.spot_checked_by = "failed", actor
            with self.store.transaction():
                self.store.put_disposition(d)
                self.store.audit(inc.id, "spot_check_undone", {"actor": actor, "note": note})
        return {"incident": inc.id, "verdict": "failed", "reversed": True}

    def agent_incident(self, pattern_id: str, actor: str, reason: str, *, hours: float = 24,
                       undo: bool = False) -> dict[str, Any]:
        """When an agent has done harm, in one step (oversight roles only): stop it (template or one scope), list
        its unattended decisions of the last ``hours``, put every one on spot check, optionally undo the ones
        that can be undone, and keep a record for the post-mortem."""
        if not isinstance(reason, str) or not isinstance(pattern_id, str):
            raise EngineError("the pattern and the reason must be text")
        pattern, seg = self._split(pattern_id)
        if isinstance(hours, bool) or not isinstance(hours, int | float) or not (0 < hours <= 24 * 366):
            raise EngineError("hours must be a number above 0 and at most a year")
        self.oversee(pattern_id, "stop", actor, reason)                 # checks the oversight role and the reason
        since = self.clock() - timedelta(hours=hours)
        listed, undone, failed = [], [], []
        for d in self.store.dispositions(pattern.id):
            if d.resolver not in ("auto", "llm") or d.shadow or d.reversed or d.created_at < since:
                continue
            inc = self.store.get_incident(d.incident_id)
            if inc is None or (seg and self.segment_of(pattern, inc.facts) != seg):
                continue
            if d.spot_check in (None, "passed"):
                d.spot_check = "pending"
                self.store.put_disposition(d)
            listed.append({"incident": d.incident_id, "actions": [st.action for st in d.steps], "code": d.code,
                           "at": d.created_at.isoformat()})
            if undo:
                try:
                    self.reverse(d.incident_id, actor, f"agent incident: {reason}")
                    undone.append(d.incident_id)
                except (AuthorizationError, EngineError) as e:
                    failed.append({"incident": d.incident_id, "why": str(e)})
        rec = {"id": new_id("aginc"), "pattern": pattern_id, "actor": actor, "reason": reason,
               "at": self.clock().isoformat(), "hours": hours, "decisions": listed, "undone": undone,
               "not_undone": failed, "status": "open"}
        with self.store.transaction():
            self.store.lock("agent_incident:index")
            self.store.put_source_state(f"agent_incident:{rec['id']}", rec)
            idx = (self.store.get_source_state("agent_incident:index") or {}).get("ids", [])
            self.store.put_source_state("agent_incident:index", {"ids": [*idx, rec["id"]][-500:]})
            self.store.audit(None, "agent_incident", {k: v for k, v in rec.items() if k != "decisions"}
                             | {"decisions": len(listed)})
        self.notify("agent_incident", {"id": rec["id"], "pattern": pattern_id, "decisions": len(listed)})
        return rec

    def agent_incidents(self) -> list[dict[str, Any]]:
        ids = (self.store.get_source_state("agent_incident:index") or {}).get("ids", [])
        return [r for i in reversed(ids) if (r := self.store.get_source_state(f"agent_incident:{i}"))]

    def close_agent_incident(self, incident_id: str, actor: str, postmortem: str) -> dict[str, Any]:
        """Record the post-mortem and close it (oversight roles only)."""
        if not isinstance(postmortem, str):
            raise EngineError("the post-mortem must be text")
        rec = self.store.get_source_state(f"agent_incident:{incident_id}")
        if not rec:
            raise EngineError(f"unknown agent incident {incident_id}")
        pattern, _ = self._split(rec["pattern"])
        d = self.directory
        if d is not None and not set(d.overseers(pattern.id, pattern.capability)) & d.roles_of(actor):
            raise AuthorizationError(f"{actor} holds no oversight role for {pattern.id}")
        if rec.get("status") == "closed":
            raise EngineError(f"agent incident {incident_id} is already closed; its post-mortem stays as written")
        if not postmortem.strip():
            raise EngineError("a post-mortem is required to close it")
        rec.update(status="closed", closed_by=actor, closed_at=self.clock().isoformat(), postmortem=postmortem)
        with self.store.transaction():
            self.store.put_source_state(f"agent_incident:{incident_id}", rec)
            self.store.audit(None, "agent_incident_closed", {"id": incident_id, "actor": actor})
        return rec

    # ================================================================ org sync: bundle, assertions, receipts
    @property
    def policy_signer(self) -> Any:
        if "_policy_signer" not in self.__dict__:
            from .orgsync import PolicySigner
            self.__dict__["_policy_signer"] = PolicySigner.from_env()
        return self.__dict__["_policy_signer"]

    @policy_signer.setter
    def policy_signer(self, signer: Any) -> None:
        self.__dict__["_policy_signer"] = signer

    def export_policy(self, ttl_hours: float = 24) -> str:
        """The signed policy bundle domain cores enforce offline (see sentinel.orgsync). Each issued version is
        remembered, so receipts naming an unknown version stand out."""
        from .orgsync import PolicyError, export_policy
        if self.directory is None:
            raise EngineError("no people configuration to export")
        if self.policy_signer is None:
            raise PolicyError("no policy key: set SENTINEL_POLICY_KEY (sentinel policy keygen makes one)")
        site = os.environ.get("SENTINEL_SITE_ID") or self.overlay.name
        token, claims = export_policy(self.directory, self.policy_signer, ttl_hours=ttl_hours, now=self.clock(),
                                      site=site)
        known = (self.store.get_source_state("policy_bundles") or {}).get("issued", [])
        known = [*[k for k in known if k["version"] != claims["version"]], claims][-50:]
        self.store.put_source_state("policy_bundles", {"issued": known})
        self.store.audit(None, "policy_exported", claims)
        return token

    def _assert_for(self, inc: Incident) -> Any:
        if self.policy_signer is None:
            return None
        return lambda action, obj=None, ttl_seconds=300: self.agent_assertion(inc, action, obj, ttl_seconds)

    def relied_facts(self, pattern: Pattern) -> set[str]:
        """Facts that a control or a core scopes by: people scopes and assignments, agent policy rows, authority
        scopes, data trust scores, and the pattern's trust_by and claims. A case where one of them is no plain
        value is a person's: no per-scope control could have matched it."""
        out = set(pattern.trust_by or ()) | set(pattern.claims or ())
        d = self.directory
        if d is not None:
            out |= set(d.scopes)
            for row in (*d.assignments, *d.agents):
                out |= set(row.scope)
        for key in (self.store.get_source_state("data_trust:index") or {}).get("keys", []):
            out.add(key.split(":", 1)[1].split("=", 1)[0])
        return out

    def _odd_scope_facts(self, pattern: Pattern, event: Event) -> list[str]:
        from .factrule import is_plain
        relied = self.relied_facts(pattern)
        return sorted(k for k, v in self.fp.raw(event).items() if k in relied and v is not None
                      and not is_plain(k, v))

    def agent_assertion(self, inc: Incident, action: str, obj: str | None = None, ttl_seconds: int = 300) -> str:
        """A short-lived signed assertion for an agent's write to a domain core: who (template@scope), under
        which bound role, in which mode, for which case, action and object."""
        from .orgsync import PolicyError, sign_agent_assertion
        if self.policy_signer is None:
            raise PolicyError("no policy key: set SENTINEL_POLICY_KEY")
        try:
            pattern = self.registry.get(inc.pattern_id)
        except KeyError:
            raise EngineError(f"unknown pattern {inc.pattern_id}") from None
        pol = self.agent_policy(pattern, inc.facts)
        mode = pol.mode if pol is not None else ("OBSERVE" if self.is_shadow(pattern, inc.facts) else "ACT")
        from .factrule import as_facts, is_plain
        named = self.relied_facts(pattern)
        odd = sorted(set(inc.odd_facts) | {k for k in named if k in inc.facts and inc.facts[k] is not None
                                           and not is_plain(k, inc.facts[k])})
        if odd:                                           # a scope fact a core can't match: a person decides
            self.store.audit(inc.id, "agent_assertion_refused", {"action": action, "facts": odd})
            raise PolicyError(f"no assertion: scope facts {', '.join(odd)} are not plain values (text or whole "
                              f"numbers), so no core could match them")
        scope = as_facts({k: v for k, v in inc.facts.items() if k not in ("event_type", "source")})
        token = sign_agent_assertion(self.policy_signer, agent=self.agent_identity(pattern, inc.facts),
                                     template=pattern.id, bound_role=pattern.owner_role, mode=mode, scope=scope,
                                     action=action, obj=obj, incident=inc.id,
                                     site=os.environ.get("SENTINEL_SITE_ID") or self.overlay.name,
                                     ttl_seconds=ttl_seconds, now=self.clock(), capability=pattern.capability)
        from .jws import b64url_decode
        jti = json.loads(b64url_decode(token.split(".")[1]))["jti"]
        self.store.put_source_state(f"assertion:{jti}", {"incident": inc.id, "action": action, "obj": obj,
                                                          "agent": self.agent_identity(pattern, inc.facts),
                                                          "template": pattern.id, "scope": scope})
        self.store.audit(inc.id, "agent_assertion", {"action": action, "obj": obj, "mode": mode, "jti": jti,
                                                     "agent": self.agent_identity(pattern, inc.facts)})
        return token

    def _receipt_mismatch(self, r: Any, issued: dict[str, Any]) -> bool:
        """A receipt naming an assertion must match everything it was issued for: agent, template, case, action,
        object and scope (each receipt scope fact covered by the issued scope or what it rolls up to). Absent on
        either side is a mismatch (BUILDER_MISSES checks 1 and 12)."""
        if r.actor_kind != "agent" or r.actor != issued.get("agent") or r.action != issued["action"]:
            return True
        if r.agent_template != issued.get("template") or r.agent_incident != issued["incident"]:
            return True
        if issued["obj"] != r.obj:
            return True
        minted = issued.get("scope") or {}
        cover = self.directory.expand_facts(minted) if self.directory is not None else \
            {k: {v} for k, v in minted.items()}
        try:
            return any(v is not None and v not in cover.get(k, set()) for k, v in r.scope.items())
        except TypeError:                                 # a value that can't be compared is never a match
            return True

    def record_receipts(self, receipts: list[Any], *, by: str = "engine") -> dict[str, Any]:
        """Receipts posted back by domain cores: audited one by one (``authority_receipt``), each once (by id),
        with the bundle version checked against the versions this site issued."""
        from .orgsync import Receipt
        known = {k["version"]: k for k in (self.store.get_source_state("policy_bundles") or {}).get("issued", [])}
        out = {"received": 0, "duplicates": 0, "allowed": 0, "refused": 0, "stale": 0, "unknown_version": 0,
               "agents": 0, "flags": []}
        parsed = [raw if isinstance(raw, Receipt) else Receipt.model_validate(raw) for raw in receipts]
        for r in parsed:                                  # all valid before any is recorded: a batch never half-lands
            key = f"receipt:{r.id}"
            flags = []
            if r.bundle_version not in known:
                flags.append("unknown_bundle_version")
            else:                                         # Sentinel knows when each version it issued was valid
                from .orgsync import SKEW, _ts
                k = known[r.bundle_version]
                at = r.at if r.at.tzinfo else r.at.replace(tzinfo=UTC)
                if at >= _ts(k["expires_at"]) and not r.stale:
                    flags.append("after_bundle_expiry")
                if at < _ts(k["issued_at"]) - SKEW:
                    flags.append("before_bundle_issue")
            if r.stale:
                flags.append("stale_bundle")
            if r.actor_kind == "agent" and r.allowed and not r.assertion_id:
                flags.append("agent_write_without_assertion")
            issued = None
            if r.assertion_id:                                # binding is total: Sentinel knows what it issued
                issued = self.store.get_source_state(f"assertion:{r.assertion_id}")
                if not issued:
                    flags.append("unknown_assertion")
                elif self._receipt_mismatch(r, issued):
                    flags.append("assertion_mismatch")
            with self.store.transaction():                # once per id, even with two posts at the same time
                self.store.lock(key)
                if self.store.get_source_state(key):
                    out["duplicates"] += 1
                    continue
                if issued and r.allowed:                  # one assertion, one write, across every core
                    use_key = f"assertion_used:{r.assertion_id}"
                    self.store.lock(use_key)
                    first = self.store.get_source_state(use_key)
                    if first:
                        flags.append("assertion_reused")
                    else:
                        self.store.put_source_state(use_key, {"receipt": r.id, "core": r.core, "site": r.site})
                self.store.put_source_state(key, {"at": r.at.isoformat()})
                self.store.audit(r.agent_incident, "authority_receipt", {**r.model_dump(mode="json"),
                                                                         "flags": flags, "posted_by": by})
                if "assertion_reused" in flags:
                    self.store.audit(r.agent_incident, "assertion_reused",
                                     {"assertion": r.assertion_id, "receipt": r.id, "core": r.core,
                                      "first": first})
            out["received"] += 1                          # counted only once it is recorded
            out["allowed" if r.allowed else "refused"] += 1
            out["stale"] += int(r.stale)
            out["unknown_version"] += int("unknown_bundle_version" in flags)
            out["agents"] += int(r.actor_kind == "agent")
            if flags:
                out["flags"].append({"receipt": r.id, "flags": flags})
            if "assertion_reused" in flags:
                self.notify("assertion_reused", {"assertion": r.assertion_id, "receipt": r.id, "core": r.core})
        return out

    # ================================================================ scale: digests and the ranked queue
    def money_at_stake(self, pattern: Pattern, inc: Any) -> float:
        """The money a case puts at stake, read from ``money_fact`` in its facts or first event (0 when unknown)."""
        if not pattern.money_fact:
            return 0.0
        facts = inc.facts if hasattr(inc, "facts") else (inc.get("facts") or {})
        first = inc.first_event if hasattr(inc, "first_event") else (inc.get("first_event") or {})
        v = facts.get(pattern.money_fact, (first.get("payload") or {}).get(pattern.money_fact))
        try:
            x = abs(float(v)) if v is not None and not isinstance(v, bool) else 0.0
        except (TypeError, ValueError):
            return 0.0
        return x if math.isfinite(x) else 0.0                    # NaN / inf never outrank real money

    def _release_digested(self, pattern: Pattern, why: str, review_ids: set[str] | None = None) -> list[str]:
        """Digested cases that can't go out on a digest get their cards after all: a case never reaches nobody.
        ``review_ids`` limits it to some cases (those whose people have no way to receive a digest)."""
        released = []
        for rv, _ in self.store.open_reviews_of_pattern(pattern.id, 100_000):
            if not rv.digested or (review_ids is not None and rv.id not in review_ids):
                continue
            rv.digested = False
            self.store.put_review(rv)
            inc = self.store.get_incident(rv.incident_id)
            if inc is not None:
                self._schedule_deliveries(rv, inc)
            released.append(rv.id)
        if released:
            self.store.audit(None, "digest_released", {"pattern": pattern.id, "reviews": len(released), "why": why})
        return released

    def template_digest(self, pattern_id: str, limit: int = 1000) -> dict[str, Any]:
        """A template's open cases ranked by money at stake (then soonest due): what its digest and the console's
        bulk view show. ``digested`` marks the cases that went out on the digest instead of as cards."""
        try:
            pattern = self.registry.get(pattern_id)
        except KeyError:
            raise EngineError(f"unknown pattern {pattern_id}") from None
        rows = []
        for rv, ib in self.store.open_reviews_of_pattern(pattern_id, limit):
            rows.append({"review": rv.id, "incident": rv.incident_id, "role": rv.assignee_role,
                         "money": self.money_at_stake(pattern, ib), "due_at": rv.due_at.isoformat(),
                         "digested": rv.digested, "has_proposal": bool(rv.proposal and rv.proposal.steps),
                         "held": rv.hold is not None, "quiet": rv.quiet,
                         "facts": {k: v for k, v in (ib.get("facts") or {}).items()
                                   if k not in ("event_type", "source")}})
        rows.sort(key=lambda r: (-r["money"], r["due_at"]))
        return {"pattern": pattern_id, "open": len(rows), "money_total": round(sum(r["money"] for r in rows), 2),
                "threshold": pattern.digest_above, "cases": rows}

    def send_template_digests(self, force: bool = False) -> list[dict[str, Any]]:
        """For each template past its ``digest_above`` threshold: one message per person holding the cases' roles
        in scope, listing their cases ranked by money, every ``digest_every_minutes``. Audited."""
        out = []
        now = self.clock()
        for pattern in self.registry.all():
            if not pattern.digest_above:
                continue
            key = f"template_digest:{pattern.id}"
            last = (self.store.get_source_state(key) or {}).get("ts")
            if not force and last and (now.timestamp() - float(last)) < pattern.digest_every_minutes * 60:
                continue
            dig = self.template_digest(pattern.id)
            # paused or silenced cases wait; quiet ones are already on the daily overdue list
            mine = [c for c in dig["cases"] if c["digested"] and not c["held"] and not c["quiet"]]
            if not mine:
                continue
            per_person: dict[str | None, list[dict[str, Any]]] = {}
            for c in mine:
                people = self.directory.people_in(c["role"], c["facts"]) if self.directory is not None else []
                for person in people or [None]:
                    per_person.setdefault(person.id if person is not None else None, []).append(c)
            sent: list[dict[str, Any]] = []
            reached: set[str] = set()                    # reviews that went out to at least one person
            missed: list[str | None] = []
            for pid, cases in per_person.items():
                total = sum(c["money"] for c in cases)
                lines = [f"{i + 1}. {', '.join(f'{k}={v}' for k, v in c['facts'].items())}"
                         + (f" · {c['money']:,.0f} at stake" if c["money"] else "")
                         + (f" {self.card_link_base}/reviews/{c['review']}" if self.card_link_base else "")
                         for i, c in enumerate(cases[:50])]
                subject = (f"Sentinel: {len(cases)} open {pattern.id} case(s)"
                           + (f", {total:,.0f} at stake" if total else ""))
                text = "\n".join([f"{pattern.description or pattern.id}. Ranked by money at stake; decide them "
                                  "together on the console (bulk approve or close).", "", *lines,
                                  *([f"... and {len(cases) - 50} more"] if len(cases) > 50 else [])])
                person = self.directory.people.get(pid) if self.directory is not None and pid else None
                edge_names = (list(person.edges) + [n for n in self.overlay.edges if n not in person.edges]
                              if person is not None else [])
                delivered = False
                for name in edge_names:
                    fn = getattr(self.overlay.edges.get(name), "send_text", None)
                    if fn is None:
                        continue
                    try:
                        fn(person.contact, subject, text)
                        sent.append({"person": pid, "edge": name, "cases": len(cases)})
                        delivered = True
                        break
                    except Exception:  # noqa: BLE001,S112 - try the next edge
                        continue
                if delivered:
                    reached |= {c["review"] for c in cases}
                else:
                    missed.append(pid)
            # a case no digest reached goes out as a card instead (or at least is on record as missed)
            stranded = {c["review"] for c in mine} - reached
            released = self._release_digested(pattern, "nobody could receive the digest", stranded) if stranded \
                else []
            self.store.put_source_state(key, {"ts": now.timestamp()})
            self.store.audit(None, "template_digest_sent", {"pattern": pattern.id, "cases": len(mine),
                                                            "money": round(sum(c["money"] for c in mine), 2),
                                                            "sent": sent, "missed": missed,
                                                            "released_to_cards": len(released)})
            out.append({"pattern": pattern.id, "cases": len(mine), "sent": sent, "missed": missed,
                        "released_to_cards": len(released)})
        return out

    def ranked_reviews(self, person_id: str, pattern_id: str | None = None, limit: int = 200) -> list[dict[str, Any]]:
        """The person's open reviews ranked by money at stake, then soonest due (the console's bulk view)."""
        rows = []
        for rv in self.reviews_for(person_id, limit=max(limit, 200)):
            inc = self.store.get_incident(rv.incident_id)
            if inc is None or (pattern_id and inc.pattern_id != pattern_id):
                continue
            try:
                pattern = self.registry.get(inc.pattern_id)
            except KeyError:
                pattern = self.registry.fallback
            rows.append({"review": rv.id, "incident": inc.id, "pattern": inc.pattern_id, "role": rv.assignee_role,
                         "money": self.money_at_stake(pattern, inc), "due_at": rv.due_at.isoformat(),
                         "digested": rv.digested, "has_proposal": bool(rv.proposal and rv.proposal.steps),
                         "facts": {k: v for k, v in inc.facts.items() if k not in ("event_type", "source")}})
        rows.sort(key=lambda r: (-r["money"], r["due_at"]))
        return rows[:limit]

    # ================================================================ persistence: holds, clearing, expiry
    def _hold_for_silence(self, review: ReviewTask, silence: Silence, pattern: Pattern) -> None:
        now = self.clock()
        review.hold = Hold(kind="silence", reason=silence.reason, since=review.hold.since if review.hold else now,
                           until=silence.ends_at, silence_id=silence.id, by=silence.by,
                           remaining_s=pattern.sla_minutes * 60.0)
        review.due_at = silence.ends_at

    def _release(self, review: ReviewTask, inc: Incident, pattern: Pattern, *, by: str | None, why: str,
                 send: bool) -> None:
        """End a hold: the SLA starts again (what was left of it after a pause, all of it after a silence)."""
        hold = review.hold
        if hold is None:
            return
        sla = pattern.sla_minutes * 60.0
        left = hold.remaining_s if hold.kind == "pause" and hold.remaining_s > 0 else sla
        review.hold = None
        review.due_at = self.clock() + timedelta(seconds=left)
        review.rounds += 1
        self.store.put_review(review)
        self.store.audit(inc.id, "review_resumed", {"review": review.id, "kind": hold.kind, "reason": hold.reason,
                                                    "by": by, "why": why})
        if send:
            self._schedule_deliveries(review, inc)

    def pause_review(self, review_id: str, actor: str, reason: str, *, hours: float | None = None) -> ReviewTask:
        """Stop the clock while waiting on someone outside. The review comes back when the time is up (72 hours
        unless given) or when the source reports the problem again."""
        from .persistence import MAX_PAUSE, pause_reasons
        review = self.store.get_review(review_id)
        if review is None:
            raise EngineError(f"unknown review {review_id}")
        with self._guard(review.incident_id):
            review = self.store.get_review(review_id)
            inc = self.store.get_incident(review.incident_id) if review else None
            if review is None or not review.open or inc is None:
                raise EngineError(f"review {review_id} is closed")
            pattern = self.registry.get(inc.pattern_id)
            allowed = pause_reasons(pattern, self.case_defaults)
            if reason not in allowed:
                raise EngineError(f"{pattern.id} can be paused for {allowed}" if allowed
                                  else f"{pattern.id} has no pause reasons (pause_on)")
            self._authorize_review(actor, pattern, review, inc)
            now = self.clock()
            span = timedelta(hours=hours) if hours else timedelta(hours=72)
            if span <= timedelta(0) or span > MAX_PAUSE:
                raise EngineError(f"a pause lasts between a minute and {MAX_PAUSE.days} days")
            if review.hold is not None and review.hold.kind == "silence":
                raise EngineError("this case is held by a silence")
            left = review.hold.remaining_s if review.hold else max(0.0, (review.due_at - now).total_seconds())
            review.hold = Hold(kind="pause", reason=reason, since=now, until=now + span, remaining_s=left, by=actor)
            review.due_at = now + span
            review.quiet = False
            self.store.put_review(review)
            self.store.audit(inc.id, "review_paused", {"review": review.id, "reason": reason, "by": actor,
                                                       "until": review.due_at.isoformat()})
            return review

    def resume_review(self, review_id: str, actor: str) -> ReviewTask:
        review = self.store.get_review(review_id)
        if review is None:
            raise EngineError(f"unknown review {review_id}")
        with self._guard(review.incident_id):
            review = self.store.get_review(review_id)
            inc = self.store.get_incident(review.incident_id) if review else None
            if review is None or not review.open or inc is None:
                raise EngineError(f"review {review_id} is closed")
            if review.hold is None or review.hold.kind != "pause":
                raise EngineError("this review is not paused")
            pattern = self.registry.get(inc.pattern_id)
            self._authorize_review(actor, pattern, review, inc)
            self._release(review, inc, pattern, by=actor, why="resumed by a person", send=False)
            return review

    def _authorize_review(self, actor: str, pattern: Pattern, review: ReviewTask, inc: Incident) -> None:
        if self.directory is None:
            return
        auth = self.directory.authorize_steps(actor, pattern.id, review.assignee_role, [], inc.facts)
        if not auth.allowed:
            raise AuthorizationError(f"not authorised: {auth.reason}", auth.escalate_to)

    def add_silence(self, actor: str, *, reason: str, hours: float, pattern: str | None = None,
                    facts: dict[str, Any] | None = None, starts_at: datetime | None = None) -> Silence:
        self._authorize_silence(actor, pattern)
        start = starts_at or self.clock()
        return self.silences.add(pattern=pattern, facts=dict(facts or {}), reason=reason, by=actor,
                                 starts_at=start, ends_at=start + timedelta(hours=hours))

    def end_silence(self, silence_id: str, actor: str) -> Silence:
        s = next((x for x in self.silences.all() if x.id == silence_id), None)
        if s is None:
            raise EngineError(f"unknown silence {silence_id}")
        self._authorize_silence(actor, s.pattern)
        ended = self.silences.end(silence_id, actor)
        now = self.clock()
        for r in self.store.open_reviews():               # held cases come back now, not at the old end time
            if r.hold is not None and r.hold.silence_id == silence_id:
                r.due_at = now - timedelta(seconds=1)     # released at the next sweep
                self.store.put_review(r)
        return ended

    def _authorize_silence(self, actor: str, pattern: str | None) -> None:
        if self.directory is None:
            return
        what = pattern or "*"
        if not any(self.directory.authorize_meta(actor, m, what).allowed for m in ("__silence__", "__kill_switch__")):
            self.store.audit(None, "meta_denied", {"actor": actor, "meta": "__silence__", "pattern": what})
            raise AuthorizationError(f"not authorised: {actor} lacks __silence__ (or __kill_switch__) on {what}")

    def _close_by_system(self, incident_id: str, code: str, note: str, detail: dict[str, Any]) -> bool:
        """Close a case Sentinel found settled (the source says it is fixed, or it expired). Not a decision:
        it teaches nothing. A case being worked on (an action running) is left alone."""
        with self._guard(incident_id):
            inc = self.store.get_incident(incident_id)
            if inc is None or inc.state not in (S.OPEN, S.AWAITING_HUMAN, S.FAILED, S.SUPPRESSED):
                return False
            pattern = self.registry.get(inc.pattern_id)
            review = self.store.open_review_for(inc.id)
            if review is not None:
                self.store.close_review(review.id)
            self.store.audit(inc.id, "closed_by_sentinel", {"code": code, "note": note, **detail})
            self._disposition(inc, pattern, code, "system", [], actor="sentinel", agreed=None, note=note)
            self.metrics.inc("cases_closed_by_sentinel_total", help="Cases closed at the source or expired",
                             pattern=pattern.id, code=code)
            return True

    def _clearing(self) -> dict[str, list[tuple[Pattern, Any]]]:
        key = id(self.registry)
        if getattr(self, "_clearing_key", None) != key:
            out: dict[str, list[tuple[Pattern, Any]]] = {}
            for p in self.registry.all():
                for ce in (p.clear_when.events if p.clear_when else []):
                    out.setdefault(ce.type, []).append((p, ce))
            self._clearing_map, self._clearing_key = out, key
        return self._clearing_map

    def _clear_by_event(self, event: Event) -> IngestResult | None:
        """An event that says a problem is gone closes the open cases it names. When no exception is raised by
        that event type, it is recorded and goes no further (it is not an unmatched case)."""
        rules = self._clearing().get(event.type)
        if not rules:
            return None
        # a redelivered "it is fixed" event must not close a case opened since (no event processed twice)
        if self.store.event_seen(event.dedupe_key):
            return IngestResult("duplicate", None, event.id)
        from .persistence import event_facts
        facts = event_facts(self, event)
        closed = []
        for pattern, ce in rules:
            if any(facts.get(k) is None for k in ce.same):
                continue
            for inc in self.store.open_incidents(pattern.id, event.tenant):
                if all(inc.facts.get(k) == facts.get(k) for k in ce.same):
                    if self._close_by_system(inc.id, "resolved_in_source", f"{event.type} from {event.source}",
                                             {"event_type": event.type, "event_id": event.id}):
                        closed.append(inc.id)
        raised = any(event.type in p.event_types for p in self.registry.all())
        if raised:
            return None
        inserted = self.store.insert_event(event)
        return IngestResult("cleared" if closed else ("duplicate" if not inserted else "no_case"),
                            closed[0] if closed else None, event.id)

    def _work_clear_check(self, item: WorkItem) -> None:
        """Ask the exception's lookup whether the problem is gone; ask again later while the case is open."""
        from .expr import matches
        inc = self.store.get_incident(item.incident_id or "")
        if inc is None or inc.state not in (S.AWAITING_HUMAN, S.FAILED, S.OPEN):
            return
        rid = item.payload.get("review")
        review = self.store.get_review(rid) if rid else None
        if rid and (review is None or not review.open):
            return                                        # decided; a new review starts its own checks
        pattern = self.registry.get(inc.pattern_id)
        lk = pattern.clear_when.lookup if pattern.clear_when else None
        if lk is None:
            return
        scope: dict[str, Any] = {"payload": inc.first_event.get("payload", {}), "facts": inc.facts}
        try:
            result = self.tools.call(lk.tool, render(lk.args, scope), self.overlay.services)
            gone = matches(lk.condition, {**scope, "result": result})
        except Exception as e:  # noqa: BLE001 - a failed check only means we ask again later
            self.store.audit(inc.id, "clear_check_failed", {"tool": lk.tool, "error": f"{type(e).__name__}: {e}"[:300]})
            gone = False
        if gone:
            self._close_by_system(inc.id, "resolved_in_source", f"{lk.tool} shows it is fixed", {"tool": lk.tool})
            return
        n = int(item.payload.get("n", 1)) + 1
        self.store.enqueue(WorkItem(kind="clear_check", incident_id=inc.id, max_attempts=3,
                                    payload={"n": n, "review": rid},
                                    run_after=self.clock() + timedelta(minutes=lk.every_minutes),
                                    dedupe_key=f"clear:{rid or inc.id}:{n}"))

    def expire_cases(self) -> list[str]:
        """Close cases nobody has touched and the source has not reported again for the exception's
        ``expires_after_hours``. Paused and silenced cases do not expire."""
        from .persistence import expires_after
        now = self.clock()
        closed = []
        for r in self.store.open_reviews():
            if r.hold is not None:
                continue
            inc = self.store.get_incident(r.incident_id)
            if inc is None:
                continue
            pattern = self.registry.get(inc.pattern_id)
            hours = expires_after(pattern, self.case_defaults)
            if not hours:
                continue
            last = max(x for x in (inc.created_at, r.created_at, r.reported_at) if x is not None)
            if now - last < timedelta(hours=hours):
                continue
            if self._close_by_system(inc.id, "expired", f"untouched for {hours:g} hours",
                                     {"hours": hours, "last_activity": last.isoformat()}):
                closed.append(inc.id)
        return closed

    def _persist_model_run(self, run: Any) -> None:
        try:
            self.store.put_model_run(run)
        except Exception:  # noqa: BLE001 - metering is best effort
            log.exception("could not persist model run")
        self.metrics.inc("model_calls_total", task=run.task, model=run.model, ok=str(run.ok).lower(),
                         shadow=str(run.shadow).lower())
        if run.fallback_reason:
            self.metrics.inc("model_fallbacks_total", task=run.task, model=run.model)

    def _on_model_escalate(self, incident_id: str, task: str, from_model: str, to_model: str, reason: str,
                           error: str | None) -> None:
        self.store.audit(incident_id, "model_escalated", {"task": task, "from": from_model, "to": to_model,
                                                          "reason": reason[:500], "error": error})
        self.metrics.inc("model_escalations_total", task=task, to=to_model)

    def _on_model_shadow(self, incident_id: str, task: str, model: str, agreed: bool | None,
                         error: str | None) -> None:
        self.store.audit(incident_id, "model_shadow", {"task": task, "model": model, "agreed": agreed,
                                                       "error": error})

    def _defer_shadow(self, incident_id: str, task: str, proposal: Any) -> None:
        """In async mode a candidate model is tried as its own job, off the case's critical path."""
        self.store.enqueue(WorkItem(kind="shadow_eval", incident_id=incident_id, run_after=self.clock(),
                                    payload={"task": task, "proposal": proposal.model_dump(mode="json")
                                             if proposal is not None else None},
                                    dedupe_key=f"shadow:{incident_id}:{task}", max_attempts=2))

    def _work_shadow_eval(self, item: WorkItem) -> None:
        if self.llm is None or item.incident_id is None:
            return
        inc = self.store.get_incident(item.incident_id)
        if inc is None:
            return
        pattern = self.registry.get(inc.pattern_id)
        event = self.store.get_event(inc.event_ids[0])
        from .models import Proposal
        prop = item.payload.get("proposal")
        self.llm.shadow(inc, pattern, event, self.store.recent_dispositions(pattern.id, 20), self.overlay.services,
                        item.payload.get("task") or "diagnose", Proposal.model_validate(prop) if prop else None)

    # ================================================================ background work
    def register_work_handler(self, kind: str, handler: Callable[[WorkItem], None]) -> None:
        if kind in self._work_handlers:
            raise EngineError(f"work handler {kind!r} already registered")
        self._work_handlers[kind] = handler

    def enqueue(self, kind: str, *, incident_id: str | None = None, payload: dict[str, Any] | None = None,
                delay_s: float = 0.0, dedupe_key: str | None = None, max_attempts: int = 5) -> bool:
        return self.store.enqueue(WorkItem(kind=kind, incident_id=incident_id, payload=payload or {},
                                           run_after=self.clock() + timedelta(seconds=delay_s),
                                           dedupe_key=dedupe_key, max_attempts=max_attempts))

    def _backoff(self, attempts: int) -> float:
        return min(self.retry_cap_s, self.retry_base_s * (2 ** max(0, attempts - 1)))

    def work(self, worker_id: str, limit: int = 10, lease_seconds: float = 300.0) -> dict[str, int]:
        """Lease and run up to `limit` ready items. Call in a loop from each worker process."""
        now = self.clock()
        stats = {"done": 0, "retry": 0, "dead": 0, "lost": 0}
        for item in self.store.lease(worker_id, now, limit, lease_seconds):
            handler = self._work_handlers.get(item.kind)
            beat = self._heartbeat(item, worker_id, lease_seconds)
            self._fence.job = (item.id, worker_id, lease_seconds)
            try:
                if handler is None:
                    raise EngineError(f"no handler for work kind {item.kind!r}")
                handler(item)
            except _LeaseLost:
                stats["lost"] += 1
                self.store.audit(item.incident_id, "work_lease_lost", {"work": item.id, "kind": item.kind,
                                                                       "worker": worker_id})
                continue
            except _NotYet as e:
                self.store.fail(item.id, worker_id, str(e), now + timedelta(seconds=self._backoff(item.attempts)))
                stats["retry"] += 1
                continue
            except Exception as e:  # noqa: BLE001 - every failure is recorded and retried or dead-lettered
                err = f"{type(e).__name__}: {e}"
                retry_at = None if handler is None else now + timedelta(seconds=self._backoff(item.attempts))
                status = self.store.fail(item.id, worker_id, err, retry_at)
                self.store.audit(item.incident_id, "work_failed", {"work": item.id, "kind": item.kind,
                                                                   "attempt": item.attempts, "error": err,
                                                                   "status": status})
                self.metrics.inc("work_total", kind=item.kind, result=status or "lost")
                log.warning("work failed", extra={"work": item.id, "kind": item.kind, "attempt": item.attempts,
                                                  "error": err, "status": status})
                if status == "dead":
                    stats["dead"] += 1
                    self._on_dead(item, err)
                elif status is None:
                    stats["lost"] += 1
                else:
                    stats["retry"] += 1
                continue
            finally:
                beat.set()
                self._fence.job = None
            if self.store.complete(item.id, worker_id):
                stats["done"] += 1
                self.metrics.inc("work_total", help="Background work outcomes", kind=item.kind, result="done")
            else:
                stats["lost"] += 1     # lease expired and someone else took it; their result stands
        return stats

    def _heartbeat(self, item: WorkItem, worker_id: str, lease_seconds: float) -> threading.Event:
        """Renew the lease every third of its length while the job runs (model calls can take minutes)."""
        stop = threading.Event()
        every = max(1.0, lease_seconds / 3)

        def beat() -> None:
            while not stop.wait(every):
                try:
                    if not self.store.extend_lease(item.id, worker_id,
                                                   self.clock() + timedelta(seconds=lease_seconds)):
                        return            # lost: the fence check stops the job before it acts
                except Exception:  # noqa: BLE001,S112 - try again on the next beat
                    continue
        threading.Thread(target=beat, daemon=True, name=f"lease-{item.id}").start()
        return stop

    def _check_fence(self) -> None:
        """Before acting after a long step (a model call): do we still hold the job?"""
        job = getattr(self._fence, "job", None)
        if job is None:
            return
        item_id, worker_id, lease_seconds = job
        if not self.store.extend_lease(item_id, worker_id, self.clock() + timedelta(seconds=lease_seconds)):
            raise _LeaseLost(item_id)

    def _work_resolve(self, item: WorkItem) -> None:
        if item.incident_id is None:
            return
        with self._guard(item.incident_id):
            inc = self.store.get_incident(item.incident_id)
            if inc is None or inc.state is not S.OPEN:
                return                 # already handled (recover, a duplicate lease, a parent closing it)
            self._drive(inc, self.registry.get(inc.pattern_id))

    def _work_outcome(self, item: WorkItem) -> None:
        """Did the fix hold? Verifier returns True (held), False (failed) or None (can't tell yet: retry)."""
        assert item.incident_id is not None
        d = self.store.get_disposition(item.incident_id)
        inc = self.store.get_incident(item.incident_id)
        if d is None or inc is None or d.reversed or d.outcome is not None:
            return
        pattern = self.registry.get(d.pattern_id)
        oc = pattern.outcome_check or {}
        verifier = self.overlay.verifiers[oc["verifier"]]
        verdict = verifier(incident=inc, disposition=d, params=oc.get("params", {}), services=self.overlay.services)
        if verdict is None:
            if item.attempts < item.max_attempts:
                raise _NotYet("outcome not determinable yet")
            d.outcome, d.outcome_detail = "unknown", "verifier could not tell after all checks"
            self.store.put_disposition(d)
            self.store.audit(inc.id, "outcome", {"verdict": "unknown"})
            return
        held = bool(verdict)
        d.outcome = "held" if held else "failed"
        with self.store.transaction():
            self.store.put_disposition(d)
            self.store.audit(inc.id, "outcome", {"verdict": d.outcome, "verifier": oc["verifier"]})
            self.store.lock(f"pattern_state:{pattern.id}")
            for st in self.trust_states(pattern, inc.facts):
                for n in self.learner.observe_outcome(st, held):
                    self.store.audit(inc.id, "learning", {"pattern": st.pattern_id, "note": n})
                self.store.put_pattern_state(st)
        if not held:
            self.notify("outcome_failed", {"incident": inc.id, "pattern": pattern.id})
            # the problem is still there: it comes back as a new incident a person will see
            self.ingest(Event(type="sentinel.outcome_failed", source="sentinel", tenant=inc.tenant,
                              idempotency_key=f"outcome_failed:{inc.id}",
                              payload={"incident_id": inc.id, "pattern_id": pattern.id, "code": d.code,
                                       "steps": [s.model_dump() for s in d.steps], "facts": inc.facts}))

    def _on_dead(self, item: WorkItem, err: str) -> None:
        self.notify("work_dead", {"work": item.id, "kind": item.kind, "incident": item.incident_id, "error": err})
        if item.kind == "resolve" and item.incident_id:
            with self._guard(item.incident_id):
                inc = self.store.get_incident(item.incident_id)
                if inc is not None and inc.state is S.OPEN:
                    pattern = self.registry.get(inc.pattern_id)
                    self._to_human(inc, pattern, f"background resolution failed repeatedly: {err}",
                                   self._playbook_proposal(pattern, inc))

    def recover(self, stale_after_s: float | None = None) -> list[str]:
        """Re-drive incidents a crash left in OPEN or RESOLVING. Safe to run at startup, repeatedly.

        Only incidents untouched for `stale_after_s` (default: the engine's recover_stale_s) are
        taken: anything newer may still be in the hands of a live worker or a person's decision.
        """
        stale = self.recover_stale_s if stale_after_s is None else stale_after_s
        cutoff = self.clock() - timedelta(seconds=stale)
        touched = []
        for inc in self.store.incidents(S.OPEN):
            if inc.updated_at > cutoff:
                continue
            if self.async_mode:
                if self.store.live_work_for(inc.id, "resolve") == 0:
                    self.enqueue("resolve", incident_id=inc.id, dedupe_key=f"resolve:{inc.id}:{inc.attempts}:"
                                 f"{int(self.clock().timestamp())}")
                    touched.append(inc.id)
                continue
            with self._guard(inc.id):
                fresh = self.store.get_incident(inc.id)
                if fresh is None or fresh.state is not S.OPEN or fresh.updated_at > cutoff:
                    continue
                self._drive(fresh, self.registry.get(fresh.pattern_id))
            touched.append(inc.id)
        for stale_inc in self.store.incidents(S.RESOLVING):
            if stale_inc.updated_at > cutoff:
                continue
            with self._guard(stale_inc.id):           # another worker may be recovering it right now
                inc = self.store.get_incident(stale_inc.id)
                if inc is None or inc.state is not S.RESOLVING or inc.updated_at > cutoff:
                    continue
                pattern = self.registry.get(inc.pattern_id)
                steps = inc.proposal.steps if inc.proposal else []
                code = inc.proposal.disposition_code if inc.proposal else pattern.playbook_disposition
                resolver = {"playbook": "auto", "llm": "llm", "human": "human"}.get(
                    inc.proposal.source if inc.proposal else "", "auto")
                res = self._execute(inc, steps, actor=f"recover:{resolver}")
                self._after_exec(inc, pattern, steps, code, res, resolver=resolver, actor=f"recover:{resolver}",
                                 agreed=None, note="recovered after interruption")
                touched.append(inc.id)
        return touched

    def coverage(self) -> list[str]:
        """Configuration warnings: patterns nobody can act on. Empty list = every queue has someone."""
        from .config import coverage_warnings
        out = coverage_warnings(self.overlay.fingerprint_rules, self.registry.all(), self.directory)
        dt = self.case_defaults.data_trust
        if dt is not None and dt.sources is None:
            out.append("data_trust has no sources: any service token may post scores and lift caps")
        return out

    def health(self, max_queue_lag_s: float = 300.0) -> dict[str, Any]:
        """Liveness + the signals that mean something is stuck."""
        try:
            q = self.store.queue_stats(self.clock())
            counts = self.store.review_counts(self.clock())
        except Exception as e:  # noqa: BLE001
            return {"status": "down", "error": f"{type(e).__name__}: {e}"}
        problems = []
        if q["counts"].get("dead"):
            problems.append(f"{q['counts']['dead']} dead work items")
        if q["oldest_ready_age_s"] > max_queue_lag_s:
            problems.append(f"queue lag {q['oldest_ready_age_s']:.0f}s")
        out = {"status": "degraded" if problems else "ok", "problems": problems, "queue": q,
               "open_reviews": counts["open"], "overdue_reviews": counts["overdue"]}
        from .bundles import environment
        out["environment"] = environment()
        if self.licence is not None:
            try:
                lic = self.licence.status(self)
                out["licence"] = lic["state"]
                if lic["state"] == "degraded":          # still serving: people decide every case
                    out["problems"] = [*problems, "licence: " + "; ".join(lic["reasons"])]
            except Exception as e:  # noqa: BLE001 - the licence never takes the site down
                out["licence"] = f"unknown: {type(e).__name__}"
        return out

    def can_view_incident(self, person_id: str, inc: Incident) -> bool:
        """May this person see this case (its facts, events and audit)? Anyone in the roles that work it, or
        above them, for its scope; people who configure the system see everything."""
        d = self.directory
        if d is None:
            return True
        if d.authorize_meta(person_id, "__configure__", inc.pattern_id).allowed:
            return True
        try:
            pattern = self.registry.get(inc.pattern_id)
            roles = {pattern.owner_role, pattern.escalation_role}
        except KeyError:
            roles = set()
        roles |= {r.assignee_role for r in self.store.reviews_for_incident(inc.id)}
        return any(r and r in d.roles and d.can_see(person_id, r, inc.facts) for r in roles)

    # ================================================================ explain (read-only)
    def trace(self, event: Event, *, registry_text: str | None = None, run_lookups: bool = False,
              replay: bool = False) -> dict[str, Any]:
        """What would happen to this event now, step by step; nothing is stored or executed. ``replay`` leaves
        out what depends on open cases (grouping, suppression, duplicates, the circuit breaker)."""
        from .explain import trace
        return trace(self, event, registry_text=registry_text, run_lookups=run_lookups, replay=replay)

    def replay(self, registry_text: str, *, days: float = 30, limit: int = 2000) -> dict[str, Any]:
        """What a draft registry would change for recent cases, compared with the running one (read-only)."""
        from .explain import replay
        return replay(self, registry_text, days=days, limit=limit)

    def seal_audit(self, *, settle_s: float | None = None) -> dict[str, Any]:
        """Seal settled audit rows into the tamper-evident chain (workers do this every minute)."""
        from .auditchain import SETTLE_S, seal
        return seal(self.store, now=self.clock().timestamp(), settle_s=SETTLE_S if settle_s is None else settle_s)

    def verify_audit(self) -> dict[str, Any]:
        from .auditchain import verify
        return verify(self.store)

    def privacy_access(self, identifier: str, actor: str) -> dict[str, Any]:
        """A data principal's access request: what is held about them (needs __privacy__)."""
        self._require_meta(actor, "__privacy__", "*")
        from .privacy import access
        return access(self, identifier, actor)

    def privacy_erase(self, identifier: str, actor: str, reason: str = "", *,
                      include_open: bool = False) -> dict[str, Any]:
        """Erase a person's data from closed cases (needs __privacy__); see sentinel.privacy."""
        self._require_meta(actor, "__privacy__", "*")
        from .privacy import erase
        return erase(self, identifier, actor, reason, include_open=include_open)

    def suggest_patterns(self, days: int = 30, min_cases: int = 3) -> list[dict[str, Any]]:
        """Draft exception patterns from recent unmatched cases (see sentinel.suggest)."""
        from .suggest import suggestions
        return suggestions(self, days=days, min_cases=min_cases)

    def model_quality(self, days: int = 30) -> dict[str, Any]:
        """Model cost and quality per exception (see sentinel.quality)."""
        from .quality import report
        return report(self, days=days)

    def value(self, days: int = 30) -> dict[str, Any]:
        """Time and money saved, per exception (see sentinel.value)."""
        from .value import report
        return report(self, days=days)

    def readiness(self, **kw: Any) -> dict[str, Any]:
        """Go-live checklist and each pattern's shadow evidence (see sentinel.golive)."""
        from .golive import readiness
        return readiness(self, **kw)

    def set_shadow(self, pattern_ids: list[str], shadow: bool, actor: str, note: str = "") -> Any:
        """Publish the registry with these patterns in (or out of) shadow; maker-checker applies."""
        from .golive import set_shadow
        return set_shadow(self, pattern_ids, shadow, actor, note)

    def capability_overview(self, days: int = 30, person: str | None = None) -> dict[str, Any]:
        """Each business capability: its exceptions, outcome metrics, cases and stage (sentinel.capabilities)."""
        from .capabilities import overview
        return overview(self, days=days, person=person)

    def method_evidence(self, days: int = 90, capability: str | None = None) -> dict[str, Any]:
        """Outcomes per method version of each exception (sentinel.capabilities)."""
        from .capabilities import methods
        return methods(self, days=days, capability=capability)

    def propose_methods(self, pattern_id: str | None = None, **kw: Any) -> list[dict[str, Any]]:
        """Candidate methods of work from what people chose, backtested (sentinel.methodlearn)."""
        from .methodlearn import propose
        return propose(self, pattern_id, **kw)

    def method_trial(self, candidate_id: str) -> dict[str, Any]:
        """The two arms of a candidate method's randomised trial and the verdict (sentinel.methodlearn)."""
        from .methodlearn import trial_report
        return trial_report(self, candidate_id)

    def method_candidates(self, pattern_id: str | None = None) -> list[dict[str, Any]]:
        from .methodlearn import candidates
        return candidates(self, pattern_id)

    def decide_method(self, candidate_id: str, what: str, actor: str, note: str = "", **kw: Any) -> dict[str, Any]:
        """shadow | reject | promote | rollback a candidate method (needs __configure__)."""
        from . import methodlearn as ml
        fn = {"shadow": lambda: ml.start_shadow(self, candidate_id, actor),
              "trial": lambda: ml.start_trial(self, candidate_id, actor, **kw),
              "reject": lambda: ml.reject(self, candidate_id, actor, note),
              "promote": lambda: ml.promote(self, candidate_id, actor, **kw),
              "rollback": lambda: ml.rollback(self, candidate_id, actor, note)}.get(what)
        if fn is None:
            raise EngineError(f"unknown method decision {what!r}")
        return fn()

    def case(self, incident_id: str) -> dict[str, Any] | None:
        """One incident's whole story in time order (see sentinel.explain)."""
        from .explain import case
        return case(self, incident_id)

    def search_cases(self, person_id: str | None, *, limit: int = 50, before: tuple[float, str] | None = None,
                     **filters: Any) -> dict[str, Any]:
        """Incidents newest first, only those this person may see. ``next`` continues the list."""
        limit = max(1, min(limit, 200))
        if filters.get("text") and filters.get("since_ts") is None:
            # free text reads every case body in the window: keep the window bounded unless asked otherwise
            filters["since_ts"] = (self.clock() - timedelta(days=90)).timestamp()
        rows: list[Incident] = []
        cursor = before
        for _ in range(10):                          # pages hidden by scope are skipped, within reason
            page = self.store.search_incidents(before=cursor, limit=limit, **filters)
            if not page:
                cursor = None
                break
            cursor = (page[-1].created_at.timestamp(), page[-1].id)
            rows += [i for i in page if person_id is None or self.can_view_incident(person_id, i)]
            if len(rows) >= limit or len(page) < limit:
                if len(page) < limit and len(rows) < limit:
                    cursor = None
                break
        rows = rows[:limit]
        if len(rows) == limit:
            cursor = (rows[-1].created_at.timestamp(), rows[-1].id)
        out = []
        for i in rows:
            d = self.store.get_disposition(i.id)
            out.append({"id": i.id, "pattern": i.pattern_id, "state": i.state.value, "route": i.route.value,
                        "tenant": i.tenant, "facts": i.facts, "created_at": i.created_at.isoformat(),
                        "events": len(i.event_ids), "shadow": i.shadow,
                        "disposition": ({"code": d.code, "resolver": d.resolver, "reversed": d.reversed,
                                         "outcome": d.outcome} if d else None)})
        return {"cases": out, "next": f"{cursor[0]}:{cursor[1]}" if cursor else None}

    def reviews_for(self, person_id: str, limit: int = 200, offset: int = 0) -> list[ReviewTask]:
        """Open reviews this person can see (their roles and every role below them, plus queues they have a
        dotted line to, scope-matched), soonest due first, one page at a time. Filtered in the database; scope
        is checked on the page. Seeing is not acting: approval still needs the solid line."""
        d = self.directory
        if d is None:
            return [r for r, _ in self.store.open_reviews_for_roles(None, limit, offset)]
        p = d.people.get(person_id)
        if p is None or not p.active:
            return []
        held = {a.role_id for a in d.assignments if a.person_id == person_id}
        roles = set(held)
        for r in held:
            roles |= d.descendants(r)
        for role in d.roles.values():                 # dotted lines: the queue and everything below it
            if held & set(role.dotted):
                roles |= {role.id} | d.descendants(role.id)
        out: list[ReviewTask] = []
        page, start = max(limit, 50), offset
        while len(out) < limit:                       # scope can hide some: keep reading until the page fills
            rows = self.store.open_reviews_for_roles(sorted(roles), page, start)
            out += [r for r, facts in rows if d.can_see(person_id, r.assignee_role, facts)]
            if len(rows) < page:
                break
            start += page
        return out[:limit]

    def segments(self, pattern: Pattern) -> list[dict[str, Any]]:
        """Trust earned per segment, for patterns with `trust_by`."""
        if not pattern.trust_by:
            return []
        out = []
        for st in self.store.pattern_states(f"{pattern.id}@"):
            st = self.pattern_state(pattern, st.pattern_id.partition("@")[2])
            cap = ceiling(pattern)
            route = st.route if st.route.level <= cap.level else cap
            out.append({"id": st.pattern_id, "segment": st.pattern_id.partition("@")[2], "route": route.value,
                        "streak": st.streak, "samples": st.samples, "reversals": st.reversals,
                        "pending_promotion": st.pending_promotion.value if st.pending_promotion else None,
                        "promotion_approvals": st.promotion_approvals})
        return out

    def report(self) -> dict[str, Any]:
        out: dict[str, Any] = {"patterns": {}, "open_reviews": self.store.review_counts(self.clock())["open"],
                               "queue": self.store.queue_stats(self.clock()),
                               "models": self.router.summary() if self.router else {}}
        stats = self.store.disposition_stats()
        for p in self.registry.all() + [self.registry.fallback]:
            c = stats.get(p.id, {})
            st = self.pattern_state(p) if p.id != self.registry.fallback.id else None
            out["patterns"][p.id] = {
                "route": self.effective_route(p).value if st else "hitl",
                "ceiling": ceiling(p).value,
                "streak": st.streak if st else 0,
                "pending_promotion": st.pending_promotion.value if st and st.pending_promotion else None,
                "reversals": st.reversals if st else 0,
                "segments": self.segments(p) if st else [],
                "dispositions": c.get("n", 0),
                "by_resolver": {r: c.get(r, 0) for r in ("auto", "llm", "human", "parent")},
                "automation_rate": round(c["real_unattended"] / c["real"], 3) if c.get("real") else None,
                "shadow_agreement": round(c["shadow_agreed"] / c["shadow_n"], 3) if c.get("shadow_n") else None,
                "outcome_held_rate": round(c["outcome_held"] / c["outcome_n"], 3) if c.get("outcome_n") else None,
            }
        return out

