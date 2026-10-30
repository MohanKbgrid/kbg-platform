# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""Metrics: the business's KPIs, computed next to its data, watched by monitors and asked about in Ask AI.

Analytics and agents act on each other in both directions:

* **Analytics -> agents.** A monitor watches a metric (OTIF by location, inventory accuracy by store) and
  raises a case when it breaches (``kpi.breach``). The exception for it routes to the KPI's owner role; its
  playbook, the model or a person acts (expedite the late picks, ask for a cycle count). While the breach
  lasts, every run reports it again (so the case does not expire); when the metric recovers the monitor
  sends ``kpi.recovered`` and the case closes at the source (``clear_when``).
* **Agents -> analytics.** The model and playbooks read metrics through the ``metrics.query`` lookup, and an
  outcome check (``verifier: metric``) confirms a fix moved the number - a fix that did not is a failed
  outcome, which costs the exception its trust.
* **People -> both.** Ask AI asks a metric and gets the numbers, a chart (a typed widget and A2UI), and a
  button that raises a case for the agent about what the person is looking at (``sentinel.raise``).

Configuration (kind ``metrics``)::

    datasets:
      orders:                       # sql | http | file | overlay | sentinel
        kind: sql
        dsn_env: SENTINEL_SECRET_ACME_DB
        query: select * from orders where paid_at > now() - interval '120 days'
        refresh_minutes: 15
    metrics:
      otif:
        title: On time in full
        dataset: orders
        time: promised_at             # the column periods are counted on
        value: avg(case when on_time and in_full then 1.0 else 0 end)
        filter: delivered_at is not null
        format: percent               # percent | number | hours | currency
        dimensions: [channel, location, vertical]
        target: {gte: 0.97}
        owner: OPS-07
    monitors:
      otif_by_location:
        metric: otif
        by: [location]
        window_days: 1
        every_minutes: 60
        when: {target_ok: false}      # over value, target_ok, baseline, change_pct, rows and the groups
        min_rows: 20

Data is loaded into DuckDB inside this process (no server) and queried there, never against the live
systems. The DuckDB connection has external access switched off, so a metric's SQL can only read the
loaded datasets. Dimensions and filters are checked against what the metric declares; filter values are
always parameters.
"""
from __future__ import annotations

import csv
import json
import re
import threading
from datetime import date, datetime, timedelta
from pathlib import Path
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

if TYPE_CHECKING:
    from .engine import Engine

IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,62}$")
NAME = re.compile(r"^[a-z][a-z0-9_]{0,62}$")
FORBIDDEN = re.compile(r";|--|/\*|\b(attach|copy|install|load|pragma|export|import|create|drop|insert|update|"
                       r"delete|alter|call|set)\b", re.I)
BREACH, RECOVERED, RAISED = "kpi.breach", "kpi.recovered", "kpi.raised"
UNTRUSTED, TRUSTED = "data.untrusted", "data.trusted"
GRAINS = ("day", "week", "month")


class KpiError(ValueError):
    pass


class DataChecks(BaseModel):
    """What must hold before anyone acts on a dataset: the facts are reproducible and reconciled without AI.
    While a check fails the dataset is *not trusted*: its monitors raise no breach and close no case, its
    metrics say so wherever they are shown, outcome checks on it give no verdict, and a ``data.untrusted``
    case goes to the dataset's owner until the data is right again (``data.trusted``)."""
    model_config = ConfigDict(extra="forbid")
    fresh: str | None = None            # a time column whose newest value must be recent
    max_age_hours: float = Field(default=26, gt=0)
    min_rows: int = Field(default=0, ge=0)
    unique: list[str] = Field(default_factory=list)      # a key: no two rows share it
    not_null: list[str] = Field(default_factory=list)
    invalid: dict[str, str] = Field(default_factory=dict)  # name -> SQL condition marking a wrong row
    # column -> the type its values must have; a value that does not fit is stored as null and counted, so
    # metrics never fail on it and the dataset is untrusted until the feed is right
    types: dict[str, Literal["boolean", "integer", "number", "time", "text"]] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _check(self) -> DataChecks:
        for c in [*([self.fresh] if self.fresh else []), *self.unique, *self.not_null, *self.types]:
            if not IDENT.match(c):
                raise ValueError(f"{c!r} is not a column name")
        for name, cond in self.invalid.items():
            if not NAME.match(name):
                raise ValueError(f"check {name!r}: names are lowercase letters, digits and _")
            if FORBIDDEN.search(cond):
                raise ValueError(f"check {name}: only a condition is allowed: {cond!r}")
        return self


class Pages(BaseModel):
    """Read page after page: ``{{page}}`` in the lookup's args counts from ``start``; reading stops at an empty
    page, a page shorter than ``size`` (when given) or after ``max`` pages."""
    model_config = ConfigDict(extra="forbid")
    start: int = 1
    max: int = Field(default=20, ge=1, le=500)
    size: int | None = Field(default=None, ge=1)


class Dataset(BaseModel):
    model_config = ConfigDict(extra="forbid")
    kind: Literal["sql", "http", "file", "overlay", "sentinel", "lookup"]
    description: str = ""
    owner: str | None = None            # the role that fixes the data when a check fails
    checks: DataChecks | None = None
    refresh_minutes: int = Field(default=15, ge=1)
    dsn_env: str | None = None          # sql
    query: str | None = None            # sql
    params: dict[str, str] = Field(default_factory=dict)   # sql: %(name)s values, may be {{env.X}}; always bound
    url: str | None = None              # http
    headers: dict[str, str] = Field(default_factory=dict)
    items: str | None = None            # where the list is: http body.data, lookup result.invoices
    path: str | None = None             # file: CSV or JSON lines under SENTINEL_DATA_DIR
    name: str | None = None             # overlay: the overlay's dataset; sentinel: cases | reviews
    # lookup: rows from a connector's read-only lookup (its login, paging and XML handled by the connector),
    # mapped to columns in configuration - the same columns whatever system they come from
    lookup: str | None = None           # e.g. zoho.bank_transactions
    args: dict[str, Any] = Field(default_factory=dict)       # templates over env, vars, now, page
    each: str | None = None             # a list inside each item: one row per entry (item = entry, parent = item)
    columns: dict[str, Any] = Field(default_factory=dict)    # column -> template over item, parent, vars, now
    where: dict[str, Any] | None = None  # keep only rows whose item matches
    pages: Pages | None = None
    vars: dict[str, Any] = Field(default_factory=dict)       # constants for args and columns ({{vars.x}})
    append: list[dict[str, Any]] = Field(default_factory=list)   # extra rows (templates over vars, now)
    # columns computed from the loaded rows, in order (each may use the ones before it), whatever the source:
    # business rules stay in configuration instead of in each source's query
    derive: dict[str, str] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _needs(self) -> Dataset:
        need = {"sql": ("dsn_env", "query"), "http": ("url",), "file": ("path",), "overlay": ("name",),
                "sentinel": ("name",), "lookup": ("lookup", "columns")}[self.kind]
        missing = [k for k in need if not getattr(self, k)]
        if missing:
            raise ValueError(f"a {self.kind} dataset needs {', '.join(missing)}")
        if self.kind == "sentinel" and self.name not in ("cases", "reviews"):
            raise ValueError("a sentinel dataset is cases or reviews")
        bad = [c for c in self.columns if not IDENT.match(c)]
        if bad:
            raise ValueError(f"{bad}: column names are letters, digits and _")
        for c, expr in self.derive.items():
            if not IDENT.match(c):
                raise ValueError(f"derive {c!r}: column names are letters, digits and _")
            if FORBIDDEN.search(expr):
                raise ValueError(f"derive {c}: only an expression is allowed: {expr!r}")
        return self


class Metric(BaseModel):
    model_config = ConfigDict(extra="forbid")
    title: str
    dataset: str
    value: str                          # an SQL aggregate over the dataset's columns
    time: str                           # the column periods are counted on
    description: str = ""
    filter: str | None = None           # rows that count (SQL condition)
    format: Literal["percent", "number", "hours", "currency"] = "number"
    dimensions: list[str] = Field(default_factory=list)
    target: dict[str, float] | None = None   # {gte: 0.97} or {lte: 24}
    owner: str | None = None            # the role that owns the KPI (an Agent ID in ACME's register)
    roles: list[str] = Field(default_factory=list)   # who may ask it (empty: everyone signed in)

    @model_validator(mode="after")
    def _check(self) -> Metric:
        for c in (self.time, *self.dimensions):
            if not IDENT.match(c):
                raise ValueError(f"{c!r} is not a column name")
        for sql in filter(None, (self.value, self.filter)):
            if FORBIDDEN.search(sql):
                raise ValueError(f"only an expression is allowed here: {sql!r}")
        if self.target is not None and (len(self.target) != 1 or set(self.target) - {"gte", "lte", "gt", "lt"}):
            raise ValueError("target is one of {gte: x}, {lte: x}, {gt: x}, {lt: x}")
        return self

    def ok(self, value: float | None) -> bool | None:
        if self.target is None or value is None:
            return None
        (op, x), = self.target.items()
        return {"gte": value >= x, "lte": value <= x, "gt": value > x, "lt": value < x}[op]

    def target_text(self) -> str:
        if not self.target:
            return ""
        (op, x), = self.target.items()
        return f"{ {'gte': '≥', 'lte': '≤', 'gt': '>', 'lt': '<'}[op]} {fmt(x, self.format)}"


class Monitor(BaseModel):
    model_config = ConfigDict(extra="forbid")
    metric: str
    by: list[str] = Field(default_factory=list)
    window_days: float = Field(default=1, gt=0)
    every_minutes: int = Field(default=60, ge=1)
    when: dict[str, Any] = Field(default_factory=lambda: {"target_ok": False})
    min_rows: int = Field(default=1, ge=0)
    emit: str = BREACH
    recover: bool = True
    description: str = ""
    enabled: bool = True


class MetricsDoc(BaseModel):
    model_config = ConfigDict(extra="forbid")
    version: int | None = None
    datasets: dict[str, Dataset] = Field(default_factory=dict)
    metrics: dict[str, Metric] = Field(default_factory=dict)
    monitors: dict[str, Monitor] = Field(default_factory=dict)

    def problems(self, roles: set[str] | None = None, tools: set[str] | None = None) -> list[tuple[str, str]]:
        from .expr import check_condition
        out: list[tuple[str, str]] = []
        for group in (self.datasets, self.metrics, self.monitors):
            out += [("error", f"{n!r}: names are lowercase letters, digits and _") for n in group if not NAME.match(n)]
        for name, d in self.datasets.items():
            if roles is not None and d.owner and d.owner not in roles:
                out.append(("warning", f"dataset {name}: owner {d.owner!r} is not in the people configuration"))
        for name, m in self.metrics.items():
            if m.dataset not in self.datasets:
                out.append(("error", f"metric {name}: unknown dataset {m.dataset!r}"))
            if roles is not None:
                for r in [*m.roles, *([m.owner] if m.owner else [])]:
                    if r not in roles:
                        out.append(("warning", f"metric {name}: role {r!r} is not in the people configuration"))
        for name, mon in self.monitors.items():
            m = self.metrics.get(mon.metric)
            if m is None:
                out.append(("error", f"monitor {name}: unknown metric {mon.metric!r}"))
                continue
            bad = [d for d in mon.by if d not in m.dimensions]
            if bad:
                out.append(("error", f"monitor {name}: {bad} is not a dimension of {mon.metric}"))
            out += [("error", f"monitor {name}: when: {p}") for p in check_condition(mon.when)]
            if "target_ok" in json.dumps(mon.when) and m.target is None:
                out.append(("error", f"monitor {name}: uses target_ok but {mon.metric} has no target"))
        return out


def parse(data: Any) -> MetricsDoc:
    if not isinstance(data, dict):
        raise KpiError("metrics configuration must be a mapping")
    return MetricsDoc.model_validate(data)


def fmt(v: Any, kind: str) -> str:
    if v is None:
        return "–"
    if kind == "percent":
        return f"{v * 100:.1f}%"
    if kind == "hours":
        return f"{v:.1f} h"
    if kind == "currency":
        return f"₹{v:,.0f}"
    return f"{v:,.2f}".rstrip("0").rstrip(".") if isinstance(v, float) else f"{v:,}"


# ------------------------------------------------------------------------------------------- loading data
_SQL_TYPE = {"boolean": "BOOLEAN", "integer": "BIGINT", "number": "DOUBLE", "time": "TIMESTAMP", "text": "VARCHAR"}


def _fits(v: Any, t: str) -> Any:
    """``v`` as a value of declared type ``t``, or ``_BAD``."""
    if t == "boolean":
        return v if isinstance(v, bool) else _BAD
    if t == "integer":
        return v if isinstance(v, int) and not isinstance(v, bool) else _BAD
    if t == "number":
        return float(v) if isinstance(v, int | float) and not isinstance(v, bool) else _BAD
    if t == "time":
        if isinstance(v, datetime | date):
            return _utc(v)
        return _utc(_iso(v)) if isinstance(v, str) and _iso(v) else _BAD
    return json.dumps(v) if isinstance(v, dict | list) else str(v)


_BAD = object()


def _coerce(rows: list[dict[str, Any]], declared: Mapping[str, str] | None = None,
            bad: dict[str, int] | None = None) -> tuple[list[str], list[str], list[tuple[Any, ...]]]:
    """Columns, DuckDB types and values for a list of records (ISO dates become timestamps; database
    numerics become numbers). A ``declared`` column gets its declared type; a value that does not fit is
    stored as null and counted in ``bad``. An undeclared column mixing strings with other values is counted
    in ``bad`` too (as ``-1``), since it can only be stored as text."""
    declared = declared or {}
    from decimal import Decimal
    if any(isinstance(v, Decimal) for r in rows for v in r.values()):
        rows = [{k: float(v) if isinstance(v, Decimal) else v for k, v in r.items()} for r in rows]
    cols: list[str] = []
    for r in rows:
        for k in r:
            if k not in cols and IDENT.match(str(k)):
                cols.append(str(k))
    for c in declared:
        if c not in cols and rows:
            cols.append(c)
    types: list[str] = []
    for c in cols:
        vals = [r.get(c) for r in rows if r.get(c) is not None]
        if c in declared:
            types.append(_SQL_TYPE[declared[c]])
        elif vals and all(isinstance(v, bool) for v in vals):
            types.append("BOOLEAN")
        elif vals and all(isinstance(v, int) and not isinstance(v, bool) for v in vals):
            types.append("BIGINT")
        elif vals and all(isinstance(v, int | float) and not isinstance(v, bool) for v in vals):
            types.append("DOUBLE")
        elif vals and all(isinstance(v, datetime | date) or (isinstance(v, str) and _iso(v)) for v in vals):
            types.append("TIMESTAMP")                     # naive UTC: no time-zone libraries needed
        else:
            types.append("VARCHAR")
            if bad is not None and any(isinstance(v, str) for v in vals) and \
                    any(not isinstance(v, str | dict | list) for v in vals):
                bad[c] = -1
    out = []
    for r in rows:
        row = []
        for c, t in zip(cols, types, strict=True):
            v = r.get(c)
            if v is None:
                row.append(None)
            elif c in declared:
                f = _fits(v, declared[c])
                if f is _BAD:
                    if bad is not None:
                        bad[c] = bad.get(c, 0) + 1
                    f = None
                row.append(f)
            elif t == "TIMESTAMP":
                row.append(_utc(_iso(v) if isinstance(v, str) else v))
            elif t == "VARCHAR" and not isinstance(v, str):
                row.append(json.dumps(v) if isinstance(v, dict | list) else str(v))
            else:
                row.append(v)
        out.append(tuple(row))
    return cols, types, out


def _utc(v: Any) -> Any:
    """A naive UTC datetime (DuckDB TIMESTAMP); dates become midnight."""
    from datetime import UTC
    if isinstance(v, datetime):
        return v.astimezone(UTC).replace(tzinfo=None) if v.tzinfo else v
    if isinstance(v, date):
        return datetime(v.year, v.month, v.day)
    return v


def _iso(v: str) -> datetime | None:
    if len(v) < 10 or not v[:4].isdigit() or v[4] != "-":
        return None
    try:
        d = datetime.fromisoformat(v.replace("Z", "+00:00"))
    except ValueError:
        return None
    if d.tzinfo is None:
        from datetime import UTC
        d = d.replace(tzinfo=UTC)
    return d


class Warehouse:
    """The datasets in an in-process DuckDB, refreshed when stale. One per engine; thread-safe."""

    def __init__(self, engine: Engine, doc: MetricsDoc) -> None:
        try:
            import duckdb
        except ImportError as e:  # pragma: no cover
            raise KpiError('metrics need DuckDB: pip install "kbg-sentinel[analytics]"') from e
        self.engine, self.doc = engine, doc
        self.con = duckdb.connect(":memory:")
        self.con.execute("SET TimeZone='UTC'")
        self.con.execute("SET enable_external_access=false")      # metric SQL reads loaded data only
        self.con.execute("SET threads=2")
        self.con.execute("SET memory_limit='1GB'")
        self.con.execute("SET lock_configuration=true")
        self.lock = threading.RLock()
        self.loaded: dict[str, datetime] = {}
        self.errors: dict[str, str] = {}
        self.counts: dict[str, int] = {}
        self.trust: dict[str, dict[str, Any]] = {}      # dataset -> {ok, problems, checked_at}
        self.malformed: dict[str, dict[str, int]] = {}  # dataset -> column -> values that did not fit

    def close(self) -> None:
        with self.lock:
            self.con.close()

    # loading ---------------------------------------------------------------------------------------
    def rows(self, name: str) -> list[dict[str, Any]]:
        ds = self.doc.datasets[name]
        eng = self.engine
        if ds.kind == "overlay":
            fn = (getattr(eng.overlay, "datasets", {}) or {}).get(ds.name)
            if fn is None:
                raise KpiError(f"dataset {name}: the overlay provides no dataset {ds.name!r}")
            return list(fn(eng.overlay.services, eng.clock()))
        if ds.kind == "sentinel":
            return _sentinel_rows(eng, ds.name or "cases")
        if ds.kind == "file":
            return _file_rows(ds.path or "")
        if ds.kind == "lookup":
            return _lookup_rows(eng, name, ds)
        from .sources import Source, fetch
        # a dataset only reads rows; the emit rule is never used (a Source needs one)
        src = Source(name=f"dataset:{name}", kind="poll" if ds.kind == "http" else "sql", emit=[{"type": "dataset"}],
                     url=ds.url, headers=ds.headers, items=ds.items, dsn_env=ds.dsn_env, query=ds.query,
                     params=ds.params, timeout_s=60)
        _, items = fetch(src, None, opener=eng.http_opener)
        return [x for x in items if isinstance(x, dict)]

    def refresh(self, name: str, *, force: bool = False) -> None:
        ds = self.doc.datasets[name]
        now = self.engine.clock()
        last = self.loaded.get(name)
        if not force and last is not None and now - last < timedelta(minutes=ds.refresh_minutes):
            return
        try:
            data = self.rows(name)
        except Exception as e:  # noqa: BLE001 - keep the last good copy; say why
            self.errors[name] = f"{type(e).__name__}: {e}"[:300]
            if name not in self.loaded:
                raise KpiError(f"dataset {name} could not be loaded: {self.errors[name]}") from None
            return
        bad: dict[str, int] = {}
        cols, types, values = _coerce(data, ds.checks.types if ds.checks else None, bad)
        self.malformed[name] = bad
        table = f"ds_{name}"
        with self.lock:
            if not cols:
                self.con.execute(f'CREATE OR REPLACE TABLE {table} (_empty BOOLEAN)')
            else:
                spec = ", ".join(f'"{c}" {t}' for c, t in zip(cols, types, strict=True))
                self.con.execute(f"CREATE OR REPLACE TABLE {table} ({spec})")
                if values:
                    marks = ", ".join("?" * len(cols))
                    # identifiers are checked names; values are parameters
                    self.con.executemany(f"INSERT INTO {table} VALUES ({marks})", values)  # noqa: S608
                for c, expr in ds.derive.items():
                    keep = f'* EXCLUDE ("{c}")' if c in cols else "*"
                    # the name is a checked identifier, the expression FORBIDDEN-checked (external access off)
                    sql = f'CREATE OR REPLACE TABLE {table} AS SELECT {keep}, ({expr}) AS "{c}" FROM {table}'  # noqa: S608
                    try:
                        self.con.execute(sql)
                    except Exception as e:  # noqa: BLE001 - a configuration mistake: say which column
                        self.errors[name] = f"derive {c}: {str(e).splitlines()[0][:200]}"
                        raise KpiError(f"dataset {name}: {self.errors[name]}") from None
                    cols = [*cols, c] if c not in cols else cols
        self.loaded[name] = now
        self.counts[name] = len(values)
        self.errors.pop(name, None)
        if ds.checks is not None:
            self.trust[name] = {"ok": None, "problems": [], "checked_at": now.isoformat()}
            problems = self._checks(name, ds.checks, set(cols), now)
            self.trust[name] = {"ok": not problems, "problems": problems, "checked_at": now.isoformat()}

    def _checks(self, name: str, ck: DataChecks, cols: set[str], now: datetime) -> list[str]:
        table, out = f"ds_{name}", []
        missing = [c for c in {*([ck.fresh] if ck.fresh else []), *ck.unique, *ck.not_null} if c not in cols]
        if missing and self.counts.get(name):
            return [f"columns missing: {sorted(missing)}"]
        with self.lock:
            def one(sql: str, args: list[Any] | None = None) -> Any:
                return self.con.execute(sql, args or []).fetchone()[0]
            n = self.counts.get(name, 0)
            for c, k in sorted((self.malformed.get(name) or {}).items()):
                if k < 0:
                    out.append(f"{c} mixes text with other values")
                else:
                    out.append(f"{c}: {k} rows not {ck.types[c]}")
            if n < ck.min_rows:
                out.append(f"{n} rows, at least {ck.min_rows} expected")
            if not n:
                return out
            # column names are checked identifiers; conditions are FORBIDDEN-checked with external access off
            if ck.fresh:
                newest = one(f'SELECT max("{ck.fresh}") FROM {table}')  # noqa: S608
                if newest is None:
                    out.append(f"no {ck.fresh} at all")
                elif isinstance(newest, datetime):
                    age = (_utc(now) - newest).total_seconds() / 3600
                    if age > ck.max_age_hours:
                        out.append(f"stale: newest {ck.fresh} is {age:.0f} h old (allowed {ck.max_age_hours:g} h)")
                else:
                    out.append(f"{ck.fresh} is not a time column")
            if ck.unique:
                key = ", ".join(f'"{c}"' for c in ck.unique)
                dup = one(f"SELECT count(*) FROM (SELECT {key} FROM {table} GROUP BY {key} "  # noqa: S608
                          "HAVING count(*) > 1)")
                if dup:
                    out.append(f"{dup} duplicate {'/'.join(ck.unique)}")
            for c in ck.not_null:
                nulls = one(f'SELECT count(*) FROM {table} WHERE "{c}" IS NULL')  # noqa: S608
                if nulls:
                    out.append(f"{nulls} rows without {c}")
            for cname, cond in ck.invalid.items():
                try:
                    bad = one(f"SELECT count(*) FROM {table} WHERE ({cond})")  # noqa: S608
                except Exception as e:  # noqa: BLE001 - a configuration mistake: the data is not proven
                    out.append(f"{cname}: {str(e).splitlines()[0][:200]}")
                    continue
                if bad:
                    out.append(f"{cname}: {bad} rows")
        return out

    def trusted(self, dataset: str) -> bool:
        """False only when the dataset has checks and one of them fails."""
        t = self.trust.get(dataset)
        return t is None or t["ok"] is not False

    def columns(self, dataset: str) -> list[str]:
        self.refresh(dataset)
        with self.lock:
            return [r[0] for r in self.con.execute(f"DESCRIBE ds_{dataset}").fetchall()]

    # querying --------------------------------------------------------------------------------------
    def query(self, metric: str, *, by: list[str] | None = None, filters: dict[str, Any] | None = None,
              since: datetime | None = None, until: datetime | None = None, days: float | None = None,
              grain: str | None = None, compare: bool = False) -> dict[str, Any]:
        """A metric over a period, by dimensions and/or a time grain, with the previous period to compare."""
        m = self.doc.metrics.get(metric)
        if m is None:
            raise KpiError(f"unknown metric {metric!r}")
        by = list(by or [])
        filters = dict(filters or {})
        bad = [d for d in [*by, *filters] if d not in m.dimensions]
        if bad:
            raise KpiError(f"{metric} cannot be split or filtered by {bad}; it has {m.dimensions}")
        if grain is not None and grain not in GRAINS:
            raise KpiError(f"grain is one of {GRAINS}")
        now = self.engine.clock()
        until = until or now + timedelta(seconds=1)       # include what happened this second
        since = since or (until - timedelta(days=days if days else 30))
        if since >= until:
            raise KpiError("the period must end after it starts")
        self.refresh(m.dataset)
        rows = self._run(m, by, filters, since, until, grain)
        total = self._run(m, [], filters, since, until, None)
        tv = total[0]["value"] if total else None
        out: dict[str, Any] = {
            "metric": metric, "title": m.title, "format": m.format, "description": m.description,
            "target": m.target, "target_text": m.target_text(), "owner": m.owner, "by": by, "filters": filters,
            "grain": grain, "since": since.isoformat(), "until": until.isoformat(), "rows": rows,
            "total": {"value": tv, "rows": total[0]["rows"] if total else 0, "target_ok": m.ok(tv),
                      "text": fmt(tv, m.format)},
            "loaded_at": self.loaded[m.dataset].isoformat() if m.dataset in self.loaded else None,
            "trusted": self.trusted(m.dataset),
            "trust_problems": list((self.trust.get(m.dataset) or {}).get("problems") or []),
        }
        if compare:
            span = until - since
            prev = self._run(m, [], filters, since - span, since, None)
            pv = prev[0]["value"] if prev else None
            out["previous"] = {"value": pv, "text": fmt(pv, m.format)}
            out["change_pct"] = _change(tv, pv)
            if by:
                pmap = {_key(r, by): r["value"] for r in self._run(m, by, filters, since - span, since, None)}
                for r in rows:
                    r["baseline"] = pmap.get(_key(r, by))
                    r["change_pct"] = _change(r["value"], r["baseline"])
        for r in rows:
            r["target_ok"] = m.ok(r["value"])
        return out

    def _run(self, m: Metric, by: list[str], filters: dict[str, Any], since: datetime, until: datetime,
             grain: str | None) -> list[dict[str, Any]]:
        cols = [f'"{d}"' for d in by]
        if grain:
            cols.append(f"strftime(date_trunc('{grain}', \"{m.time}\"), '%Y-%m-%d') AS period")
        where = [f'"{m.time}" >= ?', f'"{m.time}" < ?']
        args: list[Any] = [_utc(since), _utc(until)]
        for k, v in filters.items():
            if isinstance(v, list):
                where.append(f'"{k}" IN ({", ".join("?" * len(v))})')
                args += [str(x) for x in v]
            else:
                where.append(f'CAST("{k}" AS VARCHAR) = ?')
                args.append(str(v))
        if m.filter:
            where.append(f"({m.filter})")
        group = [*(f'"{d}"' for d in by), *(["period"] if grain else [])]
        # columns are checked identifiers, the value and filter are configured expressions (FORBIDDEN-checked,
        # external access off), and every filter value is a parameter
        sql = (f"SELECT {', '.join([*cols, f'({m.value}) AS value', 'count(*) AS n'])} "  # noqa: S608
               f"FROM ds_{m.dataset} WHERE {' AND '.join(where)}"
               + (f" GROUP BY {', '.join(group)} ORDER BY {', '.join(group)}" if group else ""))
        with self.lock:
            try:
                cur = self.con.execute(sql, args)
                names = [d[0] for d in cur.description]
                data = cur.fetchall()
            except Exception as e:  # noqa: BLE001 - a configuration mistake, shown to whoever asked
                raise KpiError(f"{m.title}: {str(e).splitlines()[0][:300]}") from None
        out = []
        for row in data:
            r = dict(zip(names, row, strict=True))
            if not by and not grain and r["n"] == 0:
                return []
            item = {d: r[d] for d in by}
            if grain:
                item["period"] = r["period"].isoformat() if hasattr(r["period"], "isoformat") else r["period"]
            v = r["value"]
            item["value"] = float(v) if v is not None else None
            item["rows"] = int(r["n"])
            item["text"] = fmt(item["value"], m.format)
            out.append(item)
        return out


def _key(r: dict[str, Any], by: list[str]) -> str:
    return "|".join(f"{d}={r.get(d)}" for d in by)


def _change(v: float | None, base: float | None) -> float | None:
    if v is None or base in (None, 0):
        return None
    return round((v - base) / abs(base) * 100, 2)


def _sentinel_rows(engine: Engine, name: str) -> list[dict[str, Any]]:
    """Sentinel's own cases as a dataset: exception rates and handling times are KPIs too."""
    out = []
    if name == "cases":
        disp = {d.incident_id: d for d in engine.store.dispositions()}
        for inc in engine.store.incidents():
            d = disp.get(inc.id)
            row = {"incident_id": inc.id, "pattern": inc.pattern_id, "state": inc.state.value,
                   "created_at": inc.created_at, "closed_at": d.created_at if d else None,
                   "code": d.code if d else None, "resolver": d.resolver if d else None,
                   "hours_open": round(((d.created_at if d else engine.clock()) - inc.created_at)
                                       .total_seconds() / 3600, 3)}
            row.update({k: v for k, v in inc.facts.items()
                        if IDENT.match(k) and k not in row and isinstance(v, str | int | float | bool)})
            out.append(row)
    else:
        now = engine.clock()
        for r in engine.store.open_reviews():
            out.append({"review_id": r.id, "role": r.assignee_role, "created_at": r.created_at, "due_at": r.due_at,
                        "overdue": r.due_at < now and r.hold is None, "quiet": r.quiet,
                        "escalation_level": r.escalation_level, "paused": r.hold is not None})
    return out


def _as_list(v: Any) -> list[Any]:
    if v is None:
        return []
    return v if isinstance(v, list) else [v]          # XML: one child is a mapping, several are a list


def _lookup_rows(engine: Engine, name: str, ds: Dataset) -> list[dict[str, Any]]:
    """Rows from a connector lookup, page by page, mapped to the dataset's columns."""
    from .envsecrets import scope as secret_scope
    from .expr import dig, matches, render
    tool = engine.tools.tools.get(ds.lookup or "")
    if tool is None:
        raise KpiError(f"dataset {name}: lookup {ds.lookup!r} is not available (add its connector and publish it)")
    call = tool.full or tool.fn
    now = engine.clock()
    base = {"vars": ds.vars, "now": now}
    rows: list[dict[str, Any]] = []
    page = ds.pages.start if ds.pages else 1
    for _ in range(ds.pages.max if ds.pages else 1):
        args = render(ds.args, {**base, "env": secret_scope(), "page": page})
        res = call(args, engine.overlay.services)
        if isinstance(res, dict) and res.get("error"):
            raise KpiError(f"dataset {name}: {res['error']}")
        items = _as_list(dig({"result": res}, ds.items) if ds.items else res)   # items: result.banktransactions
        for it in items:
            subs = ([{"item": e, "parent": it} for e in _as_list(dig({"item": it}, ds.each))] if ds.each
                    else [{"item": it, "parent": None}])
            for sc in subs:
                sc = {**base, **sc}
                if ds.where is not None and not matches(ds.where, sc):
                    continue
                rows.append({col: render(tpl, sc) for col, tpl in ds.columns.items()})
        if not ds.pages or not items or (ds.pages.size and len(items) < ds.pages.size):
            break
        page += 1
    rows += [render(r, base) for r in ds.append]
    return rows


def _file_rows(path: str) -> list[dict[str, Any]]:
    import os
    root = os.environ.get("SENTINEL_DATA_DIR")
    if not root:
        raise KpiError("file datasets need SENTINEL_DATA_DIR (the folder they may be read from)")
    base = Path(root).resolve()
    p = (base / path).resolve()
    if base not in p.parents and p != base:
        raise KpiError(f"{path} is outside SENTINEL_DATA_DIR")
    if p.suffix.lower() == ".csv":
        with p.open(newline="", encoding="utf-8") as f:
            return [{k: _num(v) for k, v in r.items()} for r in csv.DictReader(f)]
    if p.suffix.lower() in (".jsonl", ".ndjson"):
        return [json.loads(line) for line in p.read_text(encoding="utf-8").splitlines() if line.strip()]
    if p.suffix.lower() == ".json":
        data = json.loads(p.read_text(encoding="utf-8"))
        return data if isinstance(data, list) else []
    raise KpiError("file datasets are .csv, .json or .jsonl")


def _num(v: str | None) -> Any:
    if v is None or v == "":
        return None
    if v.lower() in ("true", "false"):
        return v.lower() == "true"
    try:
        return int(v)
    except ValueError:
        pass
    try:
        return float(v)
    except ValueError:
        return v


# ------------------------------------------------------------------------------------- monitors
def run_monitor(engine: Engine, name: str) -> dict[str, Any]:
    """Evaluate one monitor now: raise a case for each group that breaches, report again those still in
    breach, and send ``kpi.recovered`` for those that came back."""
    from .expr import matches
    from .models import Event
    kp = engine.kpi
    if kp is None or name not in kp.doc.monitors:
        raise KpiError(f"unknown monitor {name!r}")
    mon = kp.doc.monitors[name]
    m = kp.doc.metrics[mon.metric]
    now = engine.clock()
    kp.refresh(m.dataset)
    # trust is decided before the metric runs: a malformed feed must give a data case, not a failed query
    if not _trust_events(engine, m.dataset, name):
        # untrusted data neither raises a breach nor closes one: what is open stays open, the owner fixes the data
        problems = list((kp.trust.get(m.dataset) or {}).get("problems") or [])
        engine.store.audit(None, "monitor_skipped", {"monitor": name, "dataset": m.dataset, "problems": problems})
        return {"monitor": name, "raised": [], "still_breaching": [], "recovered": [],
                "skipped": f"dataset {m.dataset} is not trusted: " + "; ".join(problems)}
    res = kp.query(mon.metric, by=mon.by, days=mon.window_days, compare=True)
    groups = res["rows"] if mon.by else ([{**res["total"], "baseline": (res.get("previous") or {}).get("value"),
                                           "change_pct": res.get("change_pct")}] if res["total"]["rows"] else [])
    key_state = f"monitor:{name}"
    state = engine.store.get_source_state(key_state) or {"breaching": {}}
    breaching: dict[str, Any] = dict(state.get("breaching") or {})
    seen, raised, again, recovered = set(), [], [], []
    slot = int(now.timestamp() // (mon.every_minutes * 60))
    for g in groups:
        dims = {d: g.get(d) for d in mon.by}
        gk = _key(dims, mon.by) or "all"
        seen.add(gk)
        if g.get("rows", 0) < mon.min_rows:
            continue
        scope = {"value": g.get("value"), "target_ok": g.get("target_ok"), "baseline": g.get("baseline"),
                 "change_pct": g.get("change_pct"), "rows": g.get("rows"), **dims}
        if matches(mon.when, scope):
            since = (breaching.get(gk) or {}).get("since") or now.isoformat()
            (again if gk in breaching else raised).append(gk)
            breaching[gk] = {"since": since, "value": g.get("value"), "dims": dims}
            engine.ingest(Event(type=mon.emit, source=f"monitor:{name}",
                                idempotency_key=f"kpi:{name}:{gk}:{since}:{slot}",
                                payload={"monitor": name, "metric": mon.metric, "title": m.title,
                                         "value": g.get("value"), "value_text": fmt(g.get("value"), m.format),
                                         "target": m.target_text(), "target_ok": g.get("target_ok"),
                                         "baseline": g.get("baseline"), "change_pct": g.get("change_pct"),
                                         "rows": g.get("rows"), "window_days": mon.window_days, "owner": m.owner,
                                         "since": since, **dims}))
        elif gk in breaching:
            recovered.append(gk)
    for gk in [k for k in breaching if k not in seen and mon.by]:
        recovered.append(gk)                      # the group has no rows now: nothing left to breach
    for gk in recovered:
        prev = breaching.pop(gk)
        if mon.recover:
            engine.ingest(Event(type=RECOVERED, source=f"monitor:{name}",
                                idempotency_key=f"kpi-ok:{name}:{gk}:{prev['since']}",
                                payload={"monitor": name, "metric": mon.metric, **prev.get("dims", {})}))
    engine.store.put_source_state(key_state, {"breaching": breaching, "last_run": now.isoformat()})
    if raised or recovered:
        engine.store.audit(None, "monitor_run", {"monitor": name, "raised": raised, "recovered": recovered,
                                                 "still": again})
    return {"monitor": name, "raised": raised, "still_breaching": again, "recovered": recovered}


def _trust_events(engine: Engine, dataset: str, monitor: str) -> bool:
    """Raise ``data.untrusted`` for a dataset whose checks fail (again on every run while they do, so the case
    does not expire), and ``data.trusted`` once when they pass again. Returns whether it is trusted."""
    from .models import Event
    kp = engine.kpi
    ds = kp.doc.datasets[dataset]
    if ds.checks is None:
        return True
    key = f"dataset:{dataset}"
    st = engine.store.get_source_state(key) or {}
    now = engine.clock()
    t = kp.trust.get(dataset) or {}
    if t.get("ok") is False:
        since = st.get("untrusted_since") or now.isoformat()
        if not st.get("untrusted_since"):
            engine.store.put_source_state(key, {"untrusted_since": since})
        slot = int(now.timestamp() // 3600)
        engine.ingest(Event(type=UNTRUSTED, source=f"dataset:{dataset}",
                            idempotency_key=f"data:{dataset}:{since}:{slot}",
                            payload={"dataset": dataset, "problems": t.get("problems") or [], "owner": ds.owner,
                                     "monitor": monitor, "since": since, "description": ds.description}))
        return False
    if st.get("untrusted_since"):
        engine.ingest(Event(type=TRUSTED, source=f"dataset:{dataset}",
                            idempotency_key=f"data-ok:{dataset}:{st['untrusted_since']}",
                            payload={"dataset": dataset}))
        engine.store.put_source_state(key, {"untrusted_since": None, "trusted_at": now.isoformat()})
    return True


def raise_case(engine: Engine, person: str, metric: str, filters: dict[str, Any], note: str = "",
               days: float = 7) -> Any:
    """A person looking at a metric asks the agent to act on it: a ``kpi.raised`` event with the metric's
    current value for what they were looking at."""
    from .models import Event
    kp = engine.kpi
    if kp is None:
        raise KpiError("no metrics are configured")
    m = kp.doc.metrics.get(metric)
    if m is None:
        raise KpiError(f"unknown metric {metric!r}")
    if not can_see(engine, person, m):
        raise PermissionError(f"{person} may not see {metric}")
    res = kp.query(metric, filters=filters, days=days, compare=True)
    t = res["total"]
    now = engine.clock()
    fk = _key(filters, sorted(filters)) or "all"
    return engine.ingest(Event(type=RAISED, source=f"person:{person}",
                               idempotency_key=f"kpi-raise:{metric}:{fk}:{now.date().isoformat()}:{person}",
                               payload={"metric": metric, "title": m.title, "value": t["value"],
                                        "value_text": t["text"], "target": m.target_text(),
                                        "target_ok": t["target_ok"], "change_pct": res.get("change_pct"),
                                        "owner": m.owner, "raised_by": person, "note": note[:500],
                                        "window_days": days, **filters}))


def can_see(engine: Engine, person: str | None, m: Metric) -> bool:
    """Everyone signed in, unless the metric names roles: then those roles and the roles above them."""
    if not m.roles or engine.directory is None or person is None:
        return True
    d = engine.directory
    held = d.roles_of(person)
    return any(h == r or h in d.ancestors(r) for h in held for r in m.roles)


def catalogue(engine: Engine, person: str | None = None) -> dict[str, Any]:
    """What Ask AI may ask: metrics with dimensions and targets, as tool definitions for its model."""
    kp = engine.kpi
    metrics = []
    if kp is not None:
        for name, m in kp.doc.metrics.items():
            if can_see(engine, person, m):
                metrics.append({"name": name, "title": m.title, "description": m.description, "format": m.format,
                                "dimensions": m.dimensions, "target": m.target_text(), "owner": m.owner})
    names = [x["name"] for x in metrics]
    dims = sorted({d for x in metrics for d in x["dimensions"]})
    return {
        "metrics": metrics,
        "tools": [
            {"name": "sentinel_metric", "description": "Get a business KPI for a period, optionally split by a "
             "dimension or over time, compared with the previous period. Answer with the numbers it returns.",
             "input_schema": {"type": "object", "required": ["metric"], "properties": {
                 "metric": {"type": "string", "enum": names},
                 "by": {"type": "array", "items": {"type": "string", "enum": dims}},
                 "filters": {"type": "object", "description": "dimension -> value"},
                 "days": {"type": "number", "description": "the last N days (default 30)"},
                 "grain": {"type": "string", "enum": list(GRAINS)},
                 "compare": {"type": "boolean"}}}},
            {"name": "sentinel_raise", "description": "Ask the operations agent to act on what a metric shows "
             "(it opens a case for the KPI's owner). Only when the person asks for something to be done.",
             "input_schema": {"type": "object", "required": ["metric"], "properties": {
                 "metric": {"type": "string", "enum": names},
                 "filters": {"type": "object"}, "note": {"type": "string"}}}},
        ],
    }


# ---------------------------------------------------------------------------- widget and A2UI rendering
def widget(res: dict[str, Any]) -> dict[str, Any]:
    """The typed widget contract (one renderer per app, e.g. Recharts): kpi, line, bar or table."""
    fmt_ = res["format"]
    if not res["rows"] or (not res["by"] and not res["grain"]):
        return {"type": "kpi", "trusted": res.get("trusted", True),
                "title": res["title"], "value": res["total"]["value"], "text": res["total"]["text"],
                "format": fmt_, "target": res["target_text"], "target_ok": res["total"]["target_ok"],
                "change_pct": res.get("change_pct"), "previous": (res.get("previous") or {}).get("text")}
    if res["grain"] and not res["by"]:
        return {"type": "line", "title": res["title"], "format": fmt_, "target": res["target"],
                "x": [r["period"] for r in res["rows"]], "series": [{"name": res["title"],
                                                                    "values": [r["value"] for r in res["rows"]]}]}
    if res["grain"]:
        keys = sorted({_key(r, res["by"]) for r in res["rows"]})
        x = sorted({r["period"] for r in res["rows"]})
        series = [{"name": k.replace("|", ", "), "values": [next((r["value"] for r in res["rows"]
                   if r["period"] == p and _key(r, res["by"]) == k), None) for p in x]} for k in keys]
        return {"type": "line", "title": res["title"], "format": fmt_, "target": res["target"], "x": x,
                "series": series}
    return {"type": "bar", "title": res["title"], "format": fmt_, "target": res["target"],
            "x": [", ".join(str(r[d]) for d in res["by"]) for r in res["rows"]],
            "series": [{"name": res["title"], "values": [r["value"] for r in res["rows"]]}],
            "ok": [r.get("target_ok") for r in res["rows"]]}


def a2ui(res: dict[str, Any], surface: str) -> list[dict[str, Any]]:
    """The answer as A2UI v0.8 messages: a headline, the rows (or a ``Chart`` custom component carrying the
    widget, for surfaces that register it), and a button that asks the agent to act."""
    from .edges import A2UI_CATALOG, _button, _txt
    t = res["total"]
    head = f"{res['title']}: {t['text']}"
    if res["target_text"]:
        verdict = "" if t["target_ok"] is None else ", met" if t["target_ok"] else ", missed"
        head += f" (target {res['target_text']}{verdict})"
    comps: list[dict[str, Any]] = [_txt("head", head, "h3")]
    body = ["head"]
    if not res.get("trusted", True):
        comps.append(_txt("trust", "The data behind this number is not trusted: "
                          + "; ".join(res.get("trust_problems") or []), "caption"))
        body.append("trust")
    if res.get("change_pct") is not None:
        comps.append(_txt("change", f"{res['change_pct']:+.1f}% against the previous period "
                                    f"({(res.get('previous') or {}).get('text')})", "caption"))
        body.append("change")
    comps.append({"id": "chart", "component": {"Chart": {"widget": {"literalString": json.dumps(widget(res))}}}})
    body.append("chart")
    lines = []
    for i, r in enumerate(res["rows"][:12]):
        label = ", ".join(str(r[d]) for d in res["by"]) or r.get("period", "")
        mark = "" if r.get("target_ok") is None else (" ✓" if r["target_ok"] else " ✗")
        comps.append(_txt(f"r{i}", f"{label}: {r['text']}{mark}"))
        lines.append(f"r{i}")
    if lines:
        comps.append({"id": "rows", "component": {"Column": {"children": {"explicitList": lines}}}})
        body.append("rows")
    comps += _button("raise", "Ask the agent to act on this", "sentinel.raise",
                     {"metric": res["metric"], "filters": json.dumps(res["filters"])})
    body.append("raise")
    comps.append({"id": "col", "component": {"Column": {"children": {"explicitList": body}}}})
    comps.append({"id": "root", "component": {"Card": {"child": "col"}}})
    return [{"surfaceUpdate": {"surfaceId": surface, "components": comps}},
            {"beginRendering": {"surfaceId": surface, "root": "root", "catalogId": A2UI_CATALOG}}]


# ------------------------------------------------------------------- tool and verifier for agents
def tool(engine: Engine) -> Any:
    from .tools import Tool

    def fn(args: dict[str, Any], services: dict[str, Any]) -> Any:
        if engine.kpi is None:
            return {"error": "no metrics are configured"}
        try:
            res = engine.kpi.query(str(args.get("metric", "")), by=list(args.get("by") or []),
                                   filters=dict(args.get("filters") or {}), days=float(args.get("days") or 7),
                                   compare=True)
        except KpiError as e:
            return {"error": str(e)}
        return {k: res[k] for k in ("metric", "title", "target_text", "total", "rows", "previous", "change_pct")
                if k in res}
    names = ", ".join(sorted(engine.kpi.doc.metrics)) if engine.kpi else ""
    return Tool("metrics.query", f"Read a business KPI ({names}) for the last N days, optionally split by a "
                "dimension or filtered (filters: dimension -> value); compared with the period before.",
                {"metric": "str", "by?": "list", "filters?": "dict", "days?": "float"}, fn)


def verifier(engine: Engine) -> Any:
    """Outcome check ``{verifier: metric, params: {metric: otif, facts: [location], days: 1}}``: the metric,
    filtered to the case's facts, is back on target (None: too few rows yet, or data not trusted).

    With ``days`` it is measured over the last ``days`` up to the check, so it sees what was already wrong
    before the fix (recon breaks, stock positions). Without it, only what happened since the fix counts
    (a rate such as OTIF, where old orders would mask the change)."""
    def check(*, incident: Any, disposition: Any, params: dict[str, Any], services: Any) -> bool | None:
        kp = engine.kpi
        if kp is None:
            return None
        name = params.get("metric") or incident.facts.get("metric")
        filters = {f: incident.facts.get(f) for f in params.get("facts", []) if incident.facts.get(f) is not None}
        now = engine.clock()
        if params.get("days") is not None:
            res = kp.query(str(name), filters=filters, since=now - timedelta(days=float(params["days"])), until=now)
        else:
            res = kp.query(str(name), filters=filters, since=disposition.created_at, until=now)
        if not res.get("trusted", True):
            return None                          # no verdict on data that is not trusted
        if res["total"]["rows"] < int(params.get("min_rows", 1)):
            return None
        return res["total"]["target_ok"]
    return check
