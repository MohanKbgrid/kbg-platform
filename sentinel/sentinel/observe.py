# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""Observability without dependencies: Prometheus-format metrics, JSON logs, audit redaction."""
from __future__ import annotations

import json
import logging
import re
import threading
import time
from typing import Any
from collections.abc import Callable

# ---- metrics ---------------------------------------------------------------

_BUCKETS = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0)


def _esc(v: Any) -> str:
    return str(v).replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


def _labels(lbl: tuple[tuple[str, str], ...]) -> str:
    return "{" + ",".join(f'{k}="{_esc(v)}"' for k, v in lbl) + "}" if lbl else ""


class Metrics:
    """A small, thread-safe metrics registry rendered in the Prometheus text format."""

    def __init__(self, prefix: str = "sentinel") -> None:
        self.prefix = prefix
        self._lock = threading.Lock()
        self._counters: dict[str, dict[tuple, float]] = {}
        self._hist: dict[str, dict[tuple, list[float]]] = {}   # bucket counts..., count, sum
        self._help: dict[str, tuple[str, str]] = {}
        self._gauges: dict[str, Callable[[], dict[tuple, float] | float]] = {}

    def _name(self, n: str) -> str:
        return f"{self.prefix}_{n}"

    def inc(self, name: str, value: float = 1.0, help: str = "", **labels: Any) -> None:
        key = tuple(sorted((k, str(v)) for k, v in labels.items()))
        with self._lock:
            self._help.setdefault(name, ("counter", help))
            bucket = self._counters.setdefault(name, {})
            bucket[key] = bucket.get(key, 0.0) + value

    def observe(self, name: str, seconds: float, help: str = "", **labels: Any) -> None:
        key = tuple(sorted((k, str(v)) for k, v in labels.items()))
        with self._lock:
            self._help.setdefault(name, ("histogram", help))
            # fixed-size state per series: one count per bucket, +Inf count, sum (memory stays flat)
            h = self._hist.setdefault(name, {}).setdefault(key, [0.0] * (len(_BUCKETS) + 2))
            for i, b in enumerate(_BUCKETS):
                if seconds <= b:
                    h[i] += 1
            h[-2] += 1
            h[-1] += seconds

    def gauge(self, name: str, fn: Callable[[], dict[tuple, float] | float], help: str = "") -> None:
        """A gauge computed at scrape time (queue depth, open reviews ...)."""
        self._help[name] = ("gauge", help)
        self._gauges[name] = fn

    def time(self, name: str, **labels: Any):
        metrics = self

        class _T:
            def __enter__(self):
                self.t0 = time.perf_counter()
                return self

            def __exit__(self, *exc):
                metrics.observe(name, time.perf_counter() - self.t0, **labels)
        return _T()

    def value(self, name: str, **labels: Any) -> float:
        key = tuple(sorted((k, str(v)) for k, v in labels.items()))
        with self._lock:
            return self._counters.get(name, {}).get(key, 0.0)

    def render(self) -> str:
        out: list[str] = []
        with self._lock:
            counters = {k: dict(v) for k, v in self._counters.items()}
            hists = {k: {kk: list(vv) for kk, vv in v.items()} for k, v in self._hist.items()}
        for name, series in sorted(counters.items()):
            full = self._name(name)
            out += [f"# HELP {full} {self._help[name][1]}", f"# TYPE {full} counter"]
            out += [f"{full}{_labels(k)} {v:g}" for k, v in sorted(series.items())]
        for name, series in sorted(hists.items()):
            full = self._name(name)
            out += [f"# HELP {full} {self._help[name][1]}", f"# TYPE {full} histogram"]
            for key, h in sorted(series.items()):
                for i, b in enumerate(_BUCKETS):
                    out.append(f"{full}_bucket{_labels(key + (('le', f'{b:g}'),))} {h[i]:g}")
                out.append(f"{full}_bucket{_labels(key + (('le', '+Inf'),))} {h[-2]:g}")
                out.append(f"{full}_sum{_labels(key)} {h[-1]:g}")
                out.append(f"{full}_count{_labels(key)} {h[-2]:g}")
        for name, fn in sorted(self._gauges.items()):
            full = self._name(name)
            out += [f"# HELP {full} {self._help[name][1]}", f"# TYPE {full} gauge"]
            try:
                val = fn()
            except Exception:  # noqa: BLE001, S112  # a broken gauge must not break the scrape
                continue
            if isinstance(val, dict):
                out += [f"{full}{_labels(k)} {v:g}" for k, v in sorted(val.items())]
            else:
                out.append(f"{full} {val:g}")
        return "\n".join(out) + "\n"


# ---- logs ------------------------------------------------------------------

class JsonFormatter(logging.Formatter):
    _SKIP = set(vars(logging.LogRecord("", 0, "", 0, "", (), None))) | {"message", "asctime"}

    def format(self, record: logging.LogRecord) -> str:
        data = {"ts": round(record.created, 3), "level": record.levelname, "logger": record.name,
                "msg": record.getMessage()}
        for k, v in vars(record).items():
            if k not in self._SKIP:
                data[k] = v
        if record.exc_info:
            data["exc"] = self.formatException(record.exc_info)
        return json.dumps(redact(data), default=str)


def configure_logging(level: str = "INFO", json_logs: bool = True) -> None:
    h = logging.StreamHandler()
    plain = logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s")
    h.setFormatter(JsonFormatter() if json_logs else plain)
    root = logging.getLogger("sentinel")
    root.handlers[:] = [h]
    root.setLevel(level)
    root.propagate = False


# ---- redaction -------------------------------------------------------------

_SECRET_KEY = re.compile(r"(pass(word)?|secret|token|api[_-]?key|authori[sz]ation|credential|private[_-]?key)",
                         re.I)


def redact(obj: Any) -> Any:
    """Blank out values under secret-looking keys, recursively. Applied to audit records and logs."""
    if isinstance(obj, dict):
        return {k: ("***" if isinstance(k, str) and _SECRET_KEY.search(k) and v not in (None, "") else redact(v))
                for k, v in obj.items()}
    if isinstance(obj, list):
        return [redact(v) for v in obj]
    return obj
