# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""Model routing, PII masking and metering.

* `PIIMasker` replaces personal data with stable tokens before anything reaches a model and puts it
  back in what the model returns. Overlays add the payload keys that are always personal
  (customer, address ...); free text is scanned for emails, Indian mobiles, PAN, Aadhaar and card numbers.
* `ModelRouter` picks a client per task ("diagnose", "classify", "summarize" ...), meters every call
  (latency, rough tokens, estimated cost) and can run a *candidate* model in shadow on the same task so
  agreement can be measured before switching to it.
"""
from __future__ import annotations

import re
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Protocol
from collections.abc import Callable

DEFAULT_PII_KEYS = frozenset({
    "customer", "customer_name", "name", "first_name", "last_name", "full_name", "email", "phone", "mobile",
    "whatsapp", "address", "address1", "address2", "shipping_address", "billing_address", "pan", "aadhaar",
    "account_number", "ifsc", "card_number", "dob", "date_of_birth",
})

_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_PHONE_IN = re.compile(r"(?<!\d)(?:\+?91[\s-]?)?[6-9]\d{4}[\s-]?\d{5}(?!\d)")
_PAN = re.compile(r"\b[A-Z]{5}\d{4}[A-Z]\b")
_AADHAAR = re.compile(r"(?<!\d)[2-9]\d{3}[\s-]?\d{4}[\s-]?\d{4}(?!\d)")
_CARD = re.compile(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)")
_TOKEN = re.compile(r"\[PII_\d+\]")


def _luhn(digits: str) -> bool:
    total, alt = 0, False
    for ch in reversed(digits):
        d = ord(ch) - 48
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        alt = not alt
    return total % 10 == 0


class Vault:
    """Token <-> value map for one model conversation. Same value -> same token."""

    def __init__(self) -> None:
        self.by_token: dict[str, str] = {}
        self.by_value: dict[str, str] = {}

    def token(self, value: str) -> str:
        if value in self.by_value:
            return self.by_value[value]
        tok = f"[PII_{len(self.by_token) + 1}]"
        self.by_token[tok] = value
        self.by_value[value] = tok
        return tok


@dataclass
class PIIMasker:
    keys: frozenset[str] = DEFAULT_PII_KEYS
    scan_text: bool = True

    def with_keys(self, *extra: str) -> PIIMasker:
        return PIIMasker(keys=frozenset(self.keys | set(extra)), scan_text=self.scan_text)

    def mask(self, obj: Any, vault: Vault, key: str | None = None) -> Any:
        if isinstance(obj, dict):
            return {k: self.mask(v, vault, k) for k, v in obj.items()}
        if isinstance(obj, list):
            return [self.mask(v, vault, key) for v in obj]
        if key is not None and key.lower() in self.keys and obj not in (None, "", True, False):
            return vault.token(str(obj))
        if isinstance(obj, str) and self.scan_text:
            return self.mask_text(obj, vault)
        return obj

    def mask_text(self, text: str, vault: Vault) -> str:
        text = _EMAIL.sub(lambda m: vault.token(m.group(0)), text)
        text = _PAN.sub(lambda m: vault.token(m.group(0)), text)

        def card(m: re.Match) -> str:
            digits = re.sub(r"\D", "", m.group(0))
            return vault.token(m.group(0)) if 13 <= len(digits) <= 19 and _luhn(digits) else m.group(0)
        text = _CARD.sub(card, text)
        text = _AADHAAR.sub(lambda m: vault.token(m.group(0)), text)
        text = _PHONE_IN.sub(lambda m: vault.token(m.group(0)), text)
        return text

    @staticmethod
    def unmask(obj: Any, vault: Vault) -> Any:
        if isinstance(obj, dict):
            return {k: PIIMasker.unmask(v, vault) for k, v in obj.items()}
        if isinstance(obj, list):
            return [PIIMasker.unmask(v, vault) for v in obj]
        if isinstance(obj, str) and "[PII_" in obj:
            return _TOKEN.sub(lambda m: vault.by_token.get(m.group(0), m.group(0)), obj)
        return obj


# ---- routing and metering -------------------------------------------------

class Completer(Protocol):
    def complete(self, system: str, messages: list[dict[str, str]]) -> str: ...


@dataclass
class ModelRun:
    id: str
    ts: float
    task: str
    model: str
    incident_id: str | None
    ok: bool
    error: str | None
    latency_ms: float
    chars_in: int
    chars_out: int
    est_cost: float
    shadow: bool = False
    agreed: bool | None = None
    prompt_tokens: int | None = None        # as reported by the provider, when it reports them
    completion_tokens: int | None = None
    fallback_reason: str | None = None      # set when a FallbackClient answered from its fallback
    escalated: bool = False                 # an escalation re-ask after an unsure answer


def model_name(client: Any) -> str:
    return str(getattr(client, "model", None) or getattr(client, "name", None) or type(client).__name__)


class MeteredClient:
    """Wraps a client; every call is timed, sized, priced and recorded.

    The model recorded is the one that actually answered (``inner.last_model`` for a FallbackClient), and
    provider-reported token counts (``inner.last_usage``) replace the character estimate when present.
    """

    def __init__(self, inner: Completer, task: str, sink: Callable[[ModelRun], None],
                 price_per_1k: tuple[float, float] = (0.0, 0.0), shadow: bool = False,
                 prices: dict[str, tuple[float, float]] | None = None, escalated: bool = False,
                 budget_left: Callable[[], bool] | None = None) -> None:
        self.inner, self.task, self.sink, self.price, self.shadow = inner, task, sink, price_per_1k, shadow
        self.prices = prices or {}
        self.escalated = escalated
        self.model = model_name(inner)
        self.incident_id: str | None = None
        self.runs: list[ModelRun] = []
        self.budget_left = budget_left

    def complete(self, system: str, messages: list[dict[str, str]]) -> str:
        if self.budget_left is not None and not self.budget_left():
            raise RuntimeError("the daily model budget is used up; cases go to people until tomorrow")
        chars_in = len(system) + sum(len(m.get("content", "")) for m in messages)
        t0 = time.perf_counter()
        out, err = "", None
        try:
            out = self.inner.complete(system, messages)
            return out
        except Exception as e:
            err = f"{type(e).__name__}: {e}"
            raise
        finally:
            ms = (time.perf_counter() - t0) * 1000
            model = getattr(self.inner, "last_model", None) or self.model
            usage_src = self.inner
            if getattr(self.inner, "last_model", None) is not None:   # FallbackClient: ask whoever answered
                usage_src = (self.inner.fallback if model == model_name(self.inner.fallback)
                             else self.inner.primary)
            usage = getattr(usage_src, "last_usage", None) or {}
            p_tok = usage.get("prompt_tokens") if err is None else None
            c_tok = usage.get("completion_tokens") if err is None else None
            price = self.prices.get(model, self.price)
            if p_tok is not None and c_tok is not None:
                cost = p_tok / 1000 * price[0] + c_tok / 1000 * price[1]
            else:
                cost = chars_in / 4000 * price[0] + len(out) / 4000 * price[1]   # ~4 chars per token
            run = ModelRun(id=uuid.uuid4().hex[:16], ts=time.time(), task=self.task, model=model,
                           incident_id=self.incident_id, ok=err is None, error=err, latency_ms=round(ms, 1),
                           chars_in=chars_in, chars_out=len(out), est_cost=round(cost, 6), shadow=self.shadow,
                           prompt_tokens=p_tok, completion_tokens=c_tok,
                           fallback_reason=getattr(self.inner, "last_fallback_reason", None),
                           escalated=self.escalated)
            self.runs.append(run)
            self.sink(run)


@dataclass
class ModelRouter:
    """Task -> model. `candidates` run in shadow beside the primary on the same task.

    `escalations[task]` is re-asked when the primary's answer is unusable or its confidence is below
    `escalate_below` (e.g. a local small model for triage, Claude when it is unsure).
    """

    routes: dict[str, Completer] = field(default_factory=dict)
    default: Completer | None = None
    candidates: dict[str, Completer] = field(default_factory=dict)
    prices: dict[str, tuple[float, float]] = field(default_factory=dict)   # model name -> (in, out) per 1k tokens
    sink: Callable[[ModelRun], None] | None = None
    escalations: dict[str, Completer] = field(default_factory=dict)
    escalate_below: float = 0.0
    embedder: Any = None                                    # anything with .embed(texts) and .model
    named: dict[str, Any] = field(default_factory=dict)     # models by name (from a models file)
    source: dict[str, Any] | None = None                    # the models file it was built from
    daily_budget: float | None = None                       # estimated spend per UTC day, in the prices' currency
    spent_today: Callable[[], float] | None = None          # set by the engine (reads the stored model calls)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)
    _local: list[ModelRun] = field(default_factory=list, repr=False)
    max_local_runs: int = 10_000
    _spent: tuple[float, float] = (0.0, 0.0)               # (when read, amount) - read at most every 30 s

    def budget_left(self) -> bool:
        if self.daily_budget is None:
            return True
        now = time.monotonic()
        if self.spent_today is not None and now - self._spent[0] > 30:
            try:
                self._spent = (now, float(self.spent_today()))
            except Exception:  # noqa: BLE001 - when the count cannot be read, keep the last one
                self._spent = (now, self._spent[1])
        elif self.spent_today is None:
            day = time.time() - time.time() % 86400
            self._spent = (now, sum(r.est_cost for r in self._local if r.ts >= day))
        return self._spent[1] < self.daily_budget

    def _record(self, run: ModelRun) -> None:
        with self._lock:
            self._local.append(run)
            if len(self._local) > self.max_local_runs:
                del self._local[: len(self._local) - self.max_local_runs]
        if self.sink is not None:
            try:
                self.sink(run)
            except Exception:  # noqa: BLE001,S110 - metering must never break a resolution
                pass

    def _metered(self, inner: Completer, task: str, *, shadow: bool = False,
                 escalated: bool = False) -> MeteredClient:
        return MeteredClient(inner, task, self._record, self.prices.get(model_name(inner), (0.0, 0.0)),
                             shadow=shadow, prices=self.prices, escalated=escalated,
                             budget_left=self.budget_left if self.daily_budget is not None else None)

    def client(self, task: str) -> MeteredClient:
        inner = self.routes.get(task) or self.default
        if inner is None:
            raise LookupError(f"no model routed for task {task!r} and no default")
        return self._metered(inner, task)

    def candidate(self, task: str) -> MeteredClient | None:
        inner = self.candidates.get(task)
        return None if inner is None else self._metered(inner, task, shadow=True)

    def escalation(self, task: str) -> MeteredClient | None:
        inner = self.escalations.get(task)
        return None if inner is None else self._metered(inner, task, escalated=True)

    def summary(self) -> dict[str, Any]:
        """Per task and model: calls, errors, latency, cost, and shadow agreement for candidates."""
        with self._lock:
            runs = list(self._local)
        out: dict[str, dict[str, Any]] = {}
        for r in runs:
            key = f"{r.task}:{r.model}{' (shadow)' if r.shadow else ''}"
            s = out.setdefault(key, {"calls": 0, "errors": 0, "latency_ms": 0.0, "est_cost": 0.0,
                                     "agreed": 0, "compared": 0})
            s["calls"] += 1
            s["errors"] += 0 if r.ok else 1
            s["latency_ms"] += r.latency_ms
            s["est_cost"] += r.est_cost
            if r.agreed is not None:
                s["compared"] += 1
                s["agreed"] += 1 if r.agreed else 0
        for s in out.values():
            s["avg_latency_ms"] = round(s.pop("latency_ms") / s["calls"], 1)
            s["est_cost"] = round(s["est_cost"], 6)
            s["agreement"] = round(s["agreed"] / s["compared"], 3) if s["compared"] else None
        return out
