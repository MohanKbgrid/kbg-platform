# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""Strict reading of JSON bodies for the HTTP layers (API and console).

One rule for every field: a value of the wrong JSON type is refused with 422, never coerced. Strings stay strings,
booleans must be JSON booleans, numbers refuse booleans, NaN and infinity. (BUILDER_MISSES check 6.)
"""
from __future__ import annotations

import math
from typing import Any

from fastapi import HTTPException
from pydantic import BaseModel, model_validator

_MISSING = object()


def text(body: dict[str, Any], key: str, *, default: str = "", max_len: int = 10_000) -> str:
    """A string field. Absent or null gives ``default``; any other non-string is refused."""
    v = body.get(key, _MISSING)
    if v is _MISSING or v is None:
        return default
    if not isinstance(v, str):
        raise HTTPException(422, f"{key} must be text")
    if len(v) > max_len:
        raise HTTPException(422, f"{key} is longer than {max_len} characters")
    return v


def boolean(body: dict[str, Any], key: str, *, default: bool | None = None) -> bool:
    v = body.get(key, _MISSING)
    if v is _MISSING and default is not None:
        return default
    if not isinstance(v, bool):
        raise HTTPException(422, f"{key} must be true or false")
    return v


def number(body: dict[str, Any], key: str, *, default: float | None = None, integer: bool = False,
           lo: float | None = None, hi: float | None = None) -> Any:
    v = body.get(key, _MISSING)
    if (v is _MISSING or v is None) and default is not None:
        return default
    kinds = int if integer else (int, float)
    if isinstance(v, bool) or not isinstance(v, kinds) or not math.isfinite(v):
        raise HTTPException(422, f"{key} must be {'a whole number' if integer else 'a number'}")
    if (lo is not None and v < lo) or (hi is not None and v > hi):
        raise HTTPException(422, f"{key} must be between {lo} and {hi}")
    return v


def facts(body: dict[str, Any], key: str) -> dict[str, Any]:
    """An object of facts under the fact rule (sentinel.factrule): an unset fact is left out, never null."""
    v = body.get(key, _MISSING)
    if v is _MISSING or v is None:
        return {}
    if not isinstance(v, dict):
        raise HTTPException(422, f"{key} must be an object")
    from .factrule import fact_problem
    for k, x in v.items():
        if (why := fact_problem(k, x)) is not None:
            raise HTTPException(422, f"{key}: {why}")
    return v


def _kinds(annotation: Any) -> set[type]:
    import types
    import typing
    args = typing.get_args(annotation)
    if typing.get_origin(annotation) in (typing.Union, types.UnionType):
        return set().union(*(_kinds(a) for a in args))
    return {annotation} if isinstance(annotation, type) else set()


class Body(BaseModel):
    """Base for request bodies: pydantic's lax mode reads "yes" or 1 as true and "24" as 24.0. Here a bool field
    takes only a JSON boolean, and a number field only a finite JSON number (never a boolean or text)."""

    @model_validator(mode="before")
    @classmethod
    def _strict_scalars(cls, data: Any) -> Any:
        if not isinstance(data, dict):
            return data
        for name, f in cls.model_fields.items():
            if name not in data or data[name] is None:
                continue
            v, kinds = data[name], _kinds(f.annotation)
            if bool in kinds and not isinstance(v, bool):
                raise ValueError(f"{name} must be true or false")
            if kinds & {int, float} and bool not in kinds:
                if isinstance(v, bool) or not isinstance(v, int | float) or not math.isfinite(v):
                    raise ValueError(f"{name} must be a number")
        return data
