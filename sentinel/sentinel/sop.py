# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""Standard operating procedures attached to exceptions.

A pattern's ``sop`` is the team's own procedure for that exception, as plain text or Markdown. The model's
brief carries it (the parts most relevant to the case when it is long), the model is told to follow it and to
name the step it followed, and people see it on the review. Procedures are instructions, not case data: they
are never masked, and they are not part of what an exception *means*, so editing one keeps earned trust.

Long procedures are split at headings and paragraphs and the sections closest to the case are chosen with
the dependency-free lexical embedder, so no model call is spent on it.
"""
from __future__ import annotations

import re

from .similarity import HashingEmbedder, cosine

MAX_CHARS = 3500
_EMB = HashingEmbedder(512)


def sections(text: str, size: int = 1200) -> list[str]:
    """Split at Markdown headings, then at blank lines, keeping sections under `size` characters."""
    parts: list[str] = []
    blocks = re.split(r"\n(?=#{1,6} )", text.strip())
    for block in blocks:
        if len(block) <= size:
            parts.append(block.strip())
            continue
        heading = block.splitlines()[0] if block.startswith("#") else ""
        cur = ""
        for para in re.split(r"\n\s*\n", block):
            if cur and len(cur) + len(para) + 2 > size:
                parts.append(cur.strip())
                cur = (heading + "\n" if heading and not para.startswith("#") else "") + para
            else:
                cur = f"{cur}\n\n{para}" if cur else para
        if cur.strip():
            parts.append(cur.strip())
    return [p for p in parts if p]


def excerpt(text: str, case: str, max_chars: int = MAX_CHARS) -> str:
    """The whole procedure when it fits, else the sections most relevant to the case, in document order."""
    text = (text or "").strip()
    if len(text) <= max_chars:
        return text
    secs = sections(text)
    q = _EMB.embed([case])[0]
    scored = sorted(range(len(secs)), key=lambda i: -cosine(q, _EMB.embed([secs[i]])[0]))
    keep: list[int] = []
    used = 0
    for i in [0, *scored]:                         # always keep the opening section (scope, principles)
        if i in keep or used + len(secs[i]) > max_chars:
            continue
        keep.append(i)
        used += len(secs[i]) + 2
    return "\n\n".join(secs[i] for i in sorted(keep)) + "\n\n[... other sections of the procedure omitted]"
