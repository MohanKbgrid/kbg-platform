# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""Small, safe expressions for configuration: templates and conditions. No eval, no code.

Templates
    "{{payload.order_id}}"                    a whole-string template keeps the value's type
    "Order {{payload.order_id}} is late"      inside text, values are turned into text
    "{{body.created_at|hours_since}}"         filters, applied left to right
    "{{body.qty|int|default:0}}"

    filters: default:X  lower  upper  xml (escape for XML)  str  int  float  round:N  abs  neg  len  first  last
             join:SEP  hours_since  minutes_since  days_since   (from an ISO date-time or epoch seconds to "now")
             date:FORMAT (text in that strptime format -> ISO date, e.g. Tally's date:%Y%m%d)
             days_before:N  strftime:FORMAT   ("{{now|days_before:60|strftime:%Y%m%d}}")
             one (a list's first item, anything else as it is)   get:PATH (a part of a mapping)
             eq:X  ne:X  in:A,B  gt:N  lt:N  present  not  (true / false)   pick:A,B (A when true, else B)

Paths are dotted; numbers index lists ("stock.locations.0").

Conditions (all must hold)
    {"payload.status": "paid"}                          equals
    {"payload.qty": {"gt": 3}}                          eq ne gt gte lt lte in not_in contains
    {"payload.note": {"exists": true}}                  exists  empty  matches (regular expression)
    {"any": [{...}, {...}]}  {"all": [...]}  {"not": {...}}
"""
from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Any

_TPL = re.compile(r"\{\{\s*([a-zA-Z_][\w.]*)\s*((?:\|\s*[a-z_]+(?::[^|}]*)?)*)\s*\}\}")
_MISSING = object()


class ExprError(ValueError):
    pass


def dig(data: Any, path: str) -> Any:
    """Read 'a.b.0.c' out of nested dicts and lists. Missing -> None. A key that itself has dots wins, at the
    top or on the way (Tally's XML has elements such as ALLLEDGERENTRIES.LIST)."""
    if isinstance(data, dict) and path in data:
        return data[path]
    cur: Any = data
    parts = path.split(".")
    i = 0
    while i < len(parts):
        part = parts[i]
        if isinstance(cur, dict):
            if part not in cur:
                for j in range(len(parts), i + 1, -1):       # the longest dotted key that exists
                    k = ".".join(parts[i:j])
                    if k in cur:
                        cur, i = cur[k], j
                        break
                else:
                    return None
                continue
            cur = cur[part]
        elif isinstance(cur, list | tuple) and part.lstrip("-").isdigit():
            n = int(part)
            if not -len(cur) <= n < len(cur):
                return None
            cur = cur[n]
        else:
            return None
        i += 1
    return cur


def _to_dt(v: Any) -> datetime | None:
    if isinstance(v, datetime):
        return v if v.tzinfo else v.replace(tzinfo=UTC)
    if isinstance(v, int | float):
        return datetime.fromtimestamp(v, UTC)
    if isinstance(v, str) and v:
        try:
            d = datetime.fromisoformat(v.replace("Z", "+00:00"))
        except ValueError:
            return None
        return d if d.tzinfo else d.replace(tzinfo=UTC)
    return None


def _since(v: Any, now: datetime, unit_s: float) -> float | None:
    d = _to_dt(v)
    return None if d is None else round((now - d).total_seconds() / unit_s, 2)


def _num(v: Any, kind: type) -> Any:
    if v is None or v == "":
        return None
    try:
        return kind(float(v)) if kind is int else kind(v)
    except (TypeError, ValueError):
        return None


def _filter(v: Any, name: str, arg: str | None, now: datetime) -> Any:
    if name == "default":
        return arg if v is None or v == "" else v
    if name == "lower":
        return None if v is None else str(v).lower()
    if name == "xml":                                   # escape for a value placed inside an XML request
        from xml.sax.saxutils import escape
        return None if v is None else escape(str(v), {'"': "&quot;", "'": "&apos;"})
    if name == "upper":
        return None if v is None else str(v).upper()
    if name == "str":
        return None if v is None else str(v)
    if name == "int":
        return _num(v, int)
    if name == "float":
        return _num(v, float)
    if name == "round":
        n = _num(v, float)
        return None if n is None else round(n, int(arg or 0))
    if name == "abs":
        n = _num(v, float)
        return None if n is None else abs(n)
    if name == "len":
        return len(v) if isinstance(v, list | dict | str) else 0
    if name == "first":
        return v[0] if isinstance(v, list) and v else None
    if name == "last":
        return v[-1] if isinstance(v, list) and v else None
    if name == "join":
        return (arg if arg is not None else ",").join(str(x) for x in v) if isinstance(v, list) else v
    if name == "neg":
        n = _num(v, float)
        return None if n is None else -n
    if name == "date":
        if v in (None, ""):
            return None
        try:
            return datetime.strptime(str(v).strip(), arg or "%Y-%m-%d").date().isoformat()
        except ValueError:
            return None
    if name == "days_before":
        d = _to_dt(v) if not isinstance(v, datetime) else v
        from datetime import timedelta
        return None if d is None else d - timedelta(days=float(arg or 0))
    if name == "strftime":
        d = _to_dt(v) if not isinstance(v, datetime) else v
        return None if d is None else d.strftime(arg or "%Y-%m-%d")
    if name == "one":
        return (v[0] if v else None) if isinstance(v, list) else v
    if name == "get":
        if isinstance(v, list):
            v = v[0] if v else None
        return dig(v, arg or "") if isinstance(v, dict) else None
    if name in ("eq", "ne"):
        same = v is not None and str(v) == (arg or "")
        return same if name == "eq" else not same
    if name == "in":
        return v is not None and str(v) in [x.strip() for x in (arg or "").split(",")]
    if name in ("gt", "lt"):
        n, m = _num(v, float), _num(arg, float)
        if n is None or m is None:
            return False
        return n > m if name == "gt" else n < m
    if name == "present":
        return v not in (None, "", [], {})
    if name == "not":
        return not v
    if name == "pick":
        a, _, b = (arg or "").partition(",")
        return a if v else b
    if name == "hours_since":
        return _since(v, now, 3600)
    if name == "minutes_since":
        return _since(v, now, 60)
    if name == "days_since":
        return _since(v, now, 86400)
    raise ExprError(f"unknown filter {name!r}")


FILTERS = ("default", "lower", "upper", "xml", "str", "int", "float", "round", "abs", "neg", "len", "first", "last",
           "join", "hours_since", "minutes_since", "days_since", "date", "one", "get", "eq", "ne", "in", "gt", "lt",
           "present", "not", "pick", "days_before", "strftime")


def _value(path: str, filters: str, scope: dict[str, Any]) -> Any:
    v = dig(scope, path)
    now = scope.get("now") if isinstance(scope.get("now"), datetime) else datetime.now(UTC)
    for f in re.findall(r"\|\s*([a-z_]+)(?::([^|}]*))?", filters or ""):
        name, arg = f[0], (f[1].strip() if f[1] != "" else None)
        v = _filter(v, name, arg, now)
    return v


def render(value: Any, scope: dict[str, Any]) -> Any:
    """Render templates in strings, dicts and lists. A whole-string template keeps the raw type."""
    if isinstance(value, str):
        m = _TPL.fullmatch(value.strip())
        if m:
            return _value(m.group(1), m.group(2), scope)

        def sub(mm: re.Match) -> str:
            v = _value(mm.group(1), mm.group(2), scope)
            return "" if v is None else str(v)
        return _TPL.sub(sub, value)
    if isinstance(value, dict):
        return {k: render(v, scope) for k, v in value.items()}
    if isinstance(value, list):
        return [render(v, scope) for v in value]
    return value


def check_template(value: Any) -> list[str]:
    """Problems in templates (unknown filters), for configuration checks."""
    out: list[str] = []
    if isinstance(value, str):
        for m in _TPL.finditer(value):
            for name, _ in re.findall(r"\|\s*([a-z_]+)(?::([^|}]*))?", m.group(2) or ""):
                if name not in FILTERS:
                    out.append(f"unknown filter {name!r} in {m.group(0)}")
    elif isinstance(value, dict):
        for v in value.values():
            out += check_template(v)
    elif isinstance(value, list):
        for v in value:
            out += check_template(v)
    return out


_OPS = ("eq", "ne", "gt", "gte", "lt", "lte", "in", "not_in", "contains", "exists", "empty", "matches")


def _cmp(got: Any, op: str, want: Any) -> bool:
    if op == "eq":
        return got == want
    if op == "ne":
        return got != want
    if op == "exists":
        return (got is not None) == bool(want)
    if op == "empty":
        return (got in (None, "", [], {})) == bool(want)
    if op == "in":
        return got in (want or [])
    if op == "not_in":
        return got not in (want or [])
    if op == "contains":
        return isinstance(got, list | str | dict) and want in got
    if op == "matches":
        return isinstance(got, str) and re.search(str(want), got) is not None
    try:
        a, b = float(got), float(want)
    except (TypeError, ValueError):
        return False
    return {"gt": a > b, "gte": a >= b, "lt": a < b, "lte": a <= b}[op]


def matches(cond: dict[str, Any] | None, scope: dict[str, Any]) -> bool:
    """True when every clause of the condition holds (an empty or missing condition always holds)."""
    if not cond:
        return True
    if not isinstance(cond, dict):
        raise ExprError("a condition must be a mapping")
    for key, want in cond.items():
        if key == "all":
            if not all(matches(c, scope) for c in want):
                return False
            continue
        if key == "any":
            if not any(matches(c, scope) for c in want):
                return False
            continue
        if key == "not":
            if matches(want, scope):
                return False
            continue
        got = dig(scope, key)
        if isinstance(want, dict) and want and set(want) <= set(_OPS):
            if not all(_cmp(got, op, w) for op, w in want.items()):
                return False
        elif got != want:
            return False
    return True


def _shorthand(cond: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, want in cond.items():
        if key in ("all", "any"):
            out[key] = [_shorthand(c) if isinstance(c, dict) else c for c in want]
        elif key == "not":
            out[key] = _shorthand(want) if isinstance(want, dict) else want
        elif want == "*":
            out[key] = {"exists": True}
        elif isinstance(want, list):
            out[key] = {"in": want}
        else:
            out[key] = want
    return out


def match_facts(cond: dict[str, Any] | None, facts: dict[str, Any]) -> bool:
    """A pattern's ``match``: the condition language with the registry's shorthands ("*" = present, a list =
    one of)."""
    if not cond:
        return True
    rest = {}
    for key, want in cond.items():
        if want == "*":                      # top level: the fact is part of this event's fingerprint
            if key not in facts:
                return False
        else:
            rest[key] = want
    return matches(_shorthand(rest), facts)


def explain_match(cond: dict[str, Any] | None, facts: dict[str, Any]) -> list[dict[str, Any]]:
    """Each top-level clause of a pattern's match, what the event had, and whether it held."""
    out = []
    for key, want in (cond or {}).items():
        if key in ("all", "any", "not"):
            ok = match_facts({key: want}, facts)
            out.append({"fact": key, "want": want, "got": None, "ok": ok})
        else:
            out.append({"fact": key, "want": want, "got": facts.get(key), "present": key in facts,
                        "ok": match_facts({key: want}, facts)})
    return out


def check_match(cond: Any) -> list[str]:
    return check_condition(_shorthand(cond)) if isinstance(cond, dict) else ["match must be a mapping"]


def check_condition(cond: Any) -> list[str]:
    if cond is None:
        return []
    if not isinstance(cond, dict):
        return ["a condition must be a mapping"]
    out = []
    for key, want in cond.items():
        if key in ("all", "any"):
            if not isinstance(want, list):
                out.append(f"'{key}' needs a list of conditions")
            else:
                for c in want:
                    out += check_condition(c)
        elif key == "not":
            out += check_condition(want)
        elif isinstance(want, dict) and want and not set(want) <= set(_OPS):
            bad = sorted(set(want) - set(_OPS))
            if any(k in _OPS for k in want):
                out.append(f"{key}: unknown operators {bad} (known: {list(_OPS)})")
        elif isinstance(want, dict) and want.get("matches") is not None:
            try:
                re.compile(str(want["matches"]))
            except re.error as e:
                out.append(f"{key}: bad regular expression: {e}")
    return out
