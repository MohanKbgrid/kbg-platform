# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""Sentinel: a portable, event-driven agentic framework.

events -> fingerprint -> group/inhibit -> registry -> route (auto | llm | hitl)
       -> resolve -> disposition -> learn (promote / demote routes)

Domain knowledge lives in an Overlay (a separate package of your own); this package stays domain-free.
"""
from .actions import ActionContext, ActionRegistry, ParamError
from .edges import Delivery, MemoryEdge, ReviewCard, WebhookEdge
from .engine import AuthorizationError, Engine, EngineError, IngestResult, PayloadError
from .observe import Metrics, configure_logging
from .fingerprint import Bucket, FingerprintRule, Fingerprinter
from .llm import AnthropicClient, LLMClient, LLMResolver, ScriptedLLM
from .models import (ActionResult, ActionSpec, Capability, Decision, DecisionKind, Disposition, Event, Incident,
                     IncidentState, Pattern, PatternState, PlaybookStep, Proposal, Provenance, ReviewTask,
                     Route)
from .overlay import LayerError, Overlay, SlotError, load_layers, load_registry
from . import bindings, dualrun, org, orgsync
from .policy import Guardrails, LearningPolicy
from .providers import (FallbackClient, ModelUnavailable, OllamaClient, OpenAICompatibleClient, build_client,
                        load_models)
from .similarity import HashingEmbedder
from .rbac import (AgentPolicy, OversightRule, Assignment, AuthorityRule, Directory,
                   Person, Role, load_directory, ScopeDimension)
from .registry import Registry
from .routing import ModelRouter, PIIMasker, Vault
from .store import SQLiteStore, Store
from .tools import Tool, ToolRegistry

__version__ = "0.24.0"

__all__ = [
    "ActionContext",
    "ActionRegistry",
    "ActionResult",
    "AgentPolicy",
    "ActionSpec",
    "AnthropicClient",
    "Assignment",
    "AuthorityRule",
    "AuthorizationError",
    "Capability",
    "Bucket",
    "Decision",
    "DecisionKind",
    "Delivery",
    "Directory",
    "Disposition",
    "Engine",
    "EngineError",
    "Event",
    "FallbackClient",
    "FingerprintRule",
    "Fingerprinter",
    "Guardrails",
    "HashingEmbedder",
    "Incident",
    "IncidentState",
    "IngestResult",
    "LLMClient",
    "LLMResolver",
    "LayerError",
    "LearningPolicy",
    "MemoryEdge",
    "Metrics",
    "ModelRouter",
    "ModelUnavailable",
    "OllamaClient",
    "OpenAICompatibleClient",
    "Overlay",
    "OversightRule",
    "ScopeDimension",
    "SlotError",
    "PIIMasker",
    "ParamError",
    "Pattern",
    "PatternState",
    "PayloadError",
    "Person",
    "PlaybookStep",
    "Proposal",
    "Provenance",
    "Registry",
    "ReviewCard",
    "ReviewTask",
    "Role",
    "Route",
    "SQLiteStore",
    "ScriptedLLM",
    "Store",
    "Tool",
    "ToolRegistry",
    "Vault",
    "WebhookEdge",
    "build_client",
    "configure_logging",
    "load_directory",
    "load_layers",
    "bindings",
    "dualrun",
    "org",
    "orgsync",
    "load_models",
    "load_registry",
]
