# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""Similar-case search: each closed case becomes a vector; a new case is shown its nearest past cases.

* An **embedder** turns text into vectors: ``OllamaClient.embed`` (e.g. nomic-embed-text on the office Mac
  mini), ``OpenAICompatibleClient.embed``, or ``HashingEmbedder`` - a dependency-free lexical embedder that
  needs no model at all (good for tests, small sites and as a fallback; it matches words, not meaning).
* ``case_text`` is what gets embedded: the pattern, the incident facts and the event payload, **masked**
  first, so names, phones and addresses never reach the embedder and do not make two cases look alike.
* Vectors live in the customer's own store (pgvector on PostgreSQL when available), never on the
  embedding host. Only vectors are stored, not the text.
"""
from __future__ import annotations

import hashlib
import json
import math
import re
from typing import Any, Protocol

from .routing import PIIMasker, Vault


class Embedder(Protocol):
    model: str

    def embed(self, texts: list[str]) -> list[list[float]]: ...


_WORD = re.compile(r"[a-z0-9][a-z0-9_.:-]*")
_TOKEN = re.compile(r"\[PII_\d+\]")


class HashingEmbedder:
    """Signed feature hashing of words and word pairs into ``dim`` dimensions, L2-normalised."""

    def __init__(self, dim: int = 256) -> None:
        if not 16 <= dim <= 4096:
            raise ValueError("dim must be within [16, 4096]")
        self.dim = dim
        self.model = f"hashing-{dim}"

    def _vec(self, text: str) -> list[float]:
        v = [0.0] * self.dim
        words = _WORD.findall(text.lower())
        feats = words + [f"{a} {b}" for a, b in zip(words, words[1:], strict=False)]
        for f in feats:
            h = int.from_bytes(hashlib.blake2b(f.encode(), digest_size=8).digest(), "big")
            v[h % self.dim] += 1.0 if (h >> 63) & 1 else -1.0
        n = math.sqrt(sum(x * x for x in v))
        return [x / n for x in v] if n else v

    def embed(self, texts: list[str]) -> list[list[float]]:
        return [self._vec(t) for t in texts]


def cosine(a: list[float], b: list[float]) -> float:
    if len(a) != len(b):
        return 0.0
    dot = sum(x * y for x, y in zip(a, b, strict=True))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    return dot / (na * nb) if na and nb else 0.0


def _flat(obj: Any, prefix: str = "") -> list[str]:
    if isinstance(obj, dict):
        out: list[str] = []
        for k in sorted(obj):
            out += _flat(obj[k], f"{prefix}{k}.")
        return out
    if isinstance(obj, list):
        return [x for v in obj[:20] for x in _flat(v, prefix)]
    return [f"{prefix[:-1]}={obj}"] if prefix else [str(obj)]


def case_text(pattern_id: str, description: str, facts: dict[str, Any], event_type: str | None,
              payload: dict[str, Any] | None, masker: PIIMasker | None, max_chars: int = 2000) -> str:
    """Stable, masked text describing a case (no resolution: the same text is used to search)."""
    body = {"facts": facts or {}, "payload": payload or {}}
    if masker is not None:
        body = masker.mask(body, Vault())
    lines = [f"pattern {pattern_id}", description or "", f"event {event_type or ''}"]
    lines += _flat(body["facts"], "fact.") + _flat(body["payload"], "payload.")
    text = "\n".join(x for x in lines if x)
    return _TOKEN.sub("[PII]", text)[:max_chars]      # token numbers depend on order; drop them


def vector_literal(vec: list[float]) -> str:
    """pgvector text form."""
    return "[" + ",".join(f"{x:.7g}" for x in vec) + "]"


def parse_vector(raw: Any) -> list[float]:
    if isinstance(raw, list | tuple):
        return [float(x) for x in raw]
    if isinstance(raw, str):
        return [float(x) for x in json.loads(raw)]
    return [float(x) for x in raw]          # numpy array from pgvector adapters
