# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""Analytics with DuckDB, next to the customer's data. `pip install "kbg-sentinel[analytics]"`.

DuckDB runs inside this process (no server). It attaches the live store READ-ONLY - PostgreSQL or the
SQLite file - or reads Parquet snapshots, and answers questions without loading the live system:

    sentinel --overlay ... --pg $SENTINEL_PG analytics             # every report
    sentinel ... analytics automation --days 30
    sentinel ... analytics hotspots --fact location --fact channel
    sentinel ... analytics --snapshot /backups/2026-10-10           # Parquet copy of every table

Reports
  automation  per pattern: how incidents were closed (auto / model / person), automation rate
  weekly      the same over time
  trust       learned state, agreement with people, reversals, outcome checks, pending promotions
  service     time to close (p50 / p90), open and overdue reviews, escalations
  models      calls, errors, fallbacks, escalations, latency, tokens and cost per model;
              shadow agreement of candidate models with the primary
  hotspots    where exceptions come from (by location, channel, product ... any incident fact)
  evaluations model evaluations (`sentinel evaluate`): agreement with people, readiness per pattern

Sites without internet: DuckDB's postgres/sqlite readers are extensions. Install them once where there
is internet into a directory and point SENTINEL_DUCKDB_EXTENSIONS at it (the Docker image does this).
"""
from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

try:  # optional dependency
    import duckdb
except ImportError:  # pragma: no cover
    duckdb = None  # type: ignore[assignment]

TABLES = ("events", "incidents", "incident_events", "reviews", "dispositions", "pattern_state", "action_runs",
          "work_items", "deliveries", "audit", "model_runs")
_IDENT = re.compile(r"^[a-z_][a-z0-9_]{0,62}$")
_FACT = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
REPORTS = ("automation", "weekly", "trust", "service", "models", "hotspots", "evaluations")


class AnalyticsError(RuntimeError):
    pass


def _q(s: str) -> str:
    return "'" + s.replace("'", "''") + "'"


class Analytics:
    """Read-only analytics over one Sentinel store. Exactly one of ``pg``, ``sqlite`` or ``parquet_dir``."""

    def __init__(self, *, pg: str | None = None, schema: str = "sentinel", sqlite: str | None = None,
                 parquet_dir: str | None = None, extension_dir: str | None = None) -> None:
        if duckdb is None:
            raise ImportError('pip install "kbg-sentinel[analytics]" to use analytics')
        if sum(x is not None for x in (pg, sqlite, parquet_dir)) != 1:
            raise ValueError("pass exactly one of pg, sqlite or parquet_dir")
        if not _IDENT.match(schema):
            raise ValueError(f"invalid schema name {schema!r}")
        self.con = duckdb.connect(":memory:")
        self.con.execute("SET TimeZone='UTC'")
        ext = extension_dir or os.environ.get("SENTINEL_DUCKDB_EXTENSIONS")
        if ext:
            self.con.execute(f"SET extension_directory={_q(ext)}")
        if pg is not None:
            self._load("postgres")
            self.con.execute(f"ATTACH {_q(pg)} AS src (TYPE postgres, READ_ONLY, SCHEMA {_q(schema)})")
            self._src = f"src.{schema}"
        elif sqlite is not None:
            if not Path(sqlite).exists():
                raise AnalyticsError(f"no such database file: {sqlite}")
            self._load("sqlite")
            self.con.execute(f"ATTACH {_q(sqlite)} AS src (TYPE sqlite, READ_ONLY)")
            self._src = "src"
        else:
            d = Path(parquet_dir)  # type: ignore[arg-type]
            if not d.is_dir():
                raise AnalyticsError(f"no such snapshot directory: {d}")
            self.con.execute("CREATE SCHEMA snap")
            for t in TABLES:
                f = d / f"{t}.parquet"
                if f.exists():
                    self.con.execute(f"CREATE VIEW snap.{t} AS SELECT * FROM read_parquet({_q(str(f))})")
            self._src = "snap"
        self._views()

    def _load(self, ext: str) -> None:
        try:
            self.con.execute(f"LOAD {ext}")
        except Exception:  # noqa: BLE001 - not installed yet: try to install it
            try:
                self.con.execute(f"INSTALL {ext}")
                self.con.execute(f"LOAD {ext}")
            except Exception as e:  # noqa: BLE001
                raise AnalyticsError(
                    f"DuckDB extension '{ext}' is not available and could not be downloaded ({e}). On sites "
                    "without internet, install it once elsewhere into a directory and set "
                    "SENTINEL_DUCKDB_EXTENSIONS to it, or analyse a Parquet snapshot instead.") from None

    def _has(self, table: str) -> bool:
        db, _, sch = self._src.partition(".")
        if self._src == "snap":
            db, sch = "memory", "snap"
        elif not sch:
            sch = "main"
        n = self.con.execute("SELECT count(*) FROM duckdb_tables() WHERE database_name=? AND schema_name=? "
                             "AND table_name=? UNION ALL SELECT count(*) FROM duckdb_views() WHERE "
                             "database_name=? AND schema_name=? AND view_name=?",
                             [db, sch, table, db, sch, table]).fetchall()
        return sum(r[0] for r in n) > 0

    def _views(self) -> None:
        s = self._src
        missing = [t for t in ("incidents", "dispositions", "reviews", "pattern_state", "audit") if not self._has(t)]
        if missing:
            raise AnalyticsError(f"not a Sentinel store (missing tables: {missing})")
        b = "CAST(json_extract({c}, '$.{k}') AS BOOLEAN)"
        st = "json_extract_string({c}, '$.{k}')"
        self.con.execute(f"""CREATE TEMP VIEW incidents AS SELECT id, tenant, pattern_id, state, parent_id,
            {st.format(c='body', k='route')} AS route, {b.format(c='body', k='shadow')} AS shadow,
            json_extract(body, '$.facts') AS facts, to_timestamp(created_ts) AS created_at,
            to_timestamp(updated_ts) AS updated_at FROM {s}.incidents""")
        self.con.execute(f"""CREATE TEMP VIEW dispositions AS SELECT d.incident_id, d.pattern_id,
            {st.format(c='d.body', k='code')} AS code, {st.format(c='d.body', k='resolver')} AS resolver,
            {b.format(c='d.body', k='shadow')} AS shadow, {b.format(c='d.body', k='reversed')} AS reversed,
            {st.format(c='d.body', k='outcome')} AS outcome,
            {b.format(c='d.body', k='agreed_with_proposal')} AS agreed,
            {st.format(c='d.body', k='proposal_source')} AS proposal_source,
            {st.format(c='d.body', k='actor')} AS actor, to_timestamp(d.created_ts) AS closed_at
            FROM {s}.dispositions d""")
        self.con.execute(f"""CREATE TEMP VIEW reviews AS SELECT id, incident_id, CAST(is_open AS BOOLEAN) AS is_open,
            to_timestamp(due_ts) AS due_at, {st.format(c='body', k='assignee_role')} AS role,
            CAST(json_extract(body, '$.escalation_level') AS INTEGER) AS escalation_level,
            {st.format(c='body', k='reason')} AS reason,
            CAST({st.format(c='body', k='created_at')} AS TIMESTAMPTZ) AS created_at FROM {s}.reviews""")
        i = "CAST(json_extract(body, '$.{k}') AS INTEGER)"
        self.con.execute(f"""CREATE TEMP VIEW pattern_state AS SELECT pattern_id,
            {st.format(c='body', k='route')} AS route, {i.format(k='streak')} AS streak,
            {i.format(k='samples')} AS samples, {i.format(k='agreements')} AS agreements,
            {i.format(k='reversals')} AS reversals,
            {st.format(c='body', k='pending_promotion')} AS pending_promotion,
            json_array_length(json_extract(body, '$.promotion_approvals')) AS promotion_approvals,
            {i.format(k='outcomes_held')} AS outcomes_held, {i.format(k='outcomes_failed')} AS outcomes_failed
            FROM {s}.pattern_state""")
        self.con.execute(f"""CREATE TEMP VIEW audit AS SELECT seq, to_timestamp(ts) AS at, incident_id, kind,
            CAST(data AS JSON) AS data FROM {s}.audit""")
        if self._has("model_runs"):
            self.con.execute(f"""CREATE TEMP VIEW model_runs AS SELECT id, to_timestamp(ts) AS at, task, model,
                incident_id, CAST(ok AS BOOLEAN) AS ok, CAST(shadow AS BOOLEAN) AS shadow,
                CAST(escalated AS BOOLEAN) AS escalated, latency_ms, prompt_tokens, completion_tokens, chars_in,
                chars_out, est_cost, fallback_reason, error FROM {s}.model_runs""")
        else:   # store from before v0.3
            self.con.execute("""CREATE TEMP VIEW model_runs AS SELECT NULL::VARCHAR AS id, NULL::TIMESTAMPTZ AS at,
                NULL::VARCHAR AS task, NULL::VARCHAR AS model, NULL::VARCHAR AS incident_id, NULL::BOOLEAN AS ok,
                NULL::BOOLEAN AS shadow, NULL::BOOLEAN AS escalated, NULL::DOUBLE AS latency_ms,
                NULL::INTEGER AS prompt_tokens,
                NULL::INTEGER AS completion_tokens, NULL::INTEGER AS chars_in, NULL::INTEGER AS chars_out,
                NULL::DOUBLE AS est_cost, NULL::VARCHAR AS fallback_reason, NULL::VARCHAR AS error WHERE false""")

    # ---- helpers ---------------------------------------------------------
    def query(self, sql: str, params: list[Any] | None = None) -> list[dict[str, Any]]:
        """Run any read-only SQL over the views (incidents, dispositions, reviews, pattern_state, audit,
        model_runs)."""
        cur = self.con.execute(sql, params or [])
        cols = [d[0] for d in cur.description]
        return [dict(zip(cols, row, strict=True)) for row in cur.fetchall()]

    @staticmethod
    def _since(days: int | None, col: str) -> str:
        if days is None:
            return "true"
        if not isinstance(days, int) or days < 1:
            raise ValueError("days must be a positive integer")
        return f"{col} >= now() - INTERVAL {days} DAY"

    # ---- reports ---------------------------------------------------------
    def automation(self, days: int | None = None) -> list[dict[str, Any]]:
        return self.query(f"""SELECT pattern_id, count(*) AS closed,
            count(*) FILTER (resolver = 'auto') AS auto, count(*) FILTER (resolver = 'llm') AS model,
            count(*) FILTER (resolver = 'human') AS person, count(*) FILTER (resolver = 'parent') AS with_parent,
            round(count(*) FILTER (resolver IN ('auto', 'llm'))
                  / nullif(count(*) FILTER (resolver <> 'parent'), 0), 3) AS automation_rate,
            count(*) FILTER (reversed) AS reversed
            FROM dispositions WHERE NOT coalesce(shadow, false) AND {self._since(days, 'closed_at')}
            GROUP BY pattern_id ORDER BY closed DESC, pattern_id""")

    def weekly(self, days: int | None = None) -> list[dict[str, Any]]:
        return self.query(f"""SELECT CAST(date_trunc('week', closed_at) AS DATE) AS week, count(*) AS closed,
            count(*) FILTER (resolver IN ('auto', 'llm')) AS unattended,
            round(count(*) FILTER (resolver IN ('auto', 'llm'))
                  / nullif(count(*) FILTER (resolver <> 'parent'), 0), 3) AS automation_rate,
            count(*) FILTER (reversed) AS reversed, count(*) FILTER (outcome = 'failed') AS outcome_failed
            FROM dispositions WHERE NOT coalesce(shadow, false) AND {self._since(days, 'closed_at')}
            GROUP BY 1 ORDER BY 1""")

    def trust(self) -> list[dict[str, Any]]:
        return self.query("""SELECT p.pattern_id, p.route, p.streak, p.samples,
            CASE WHEN p.samples > 0 THEN round(p.agreements / p.samples, 3) END AS agreement_rate,
            p.reversals, p.outcomes_held, p.outcomes_failed, p.pending_promotion,
            coalesce(p.promotion_approvals, 0) AS promotion_approvals,
            coalesce(s.shadow_closed, 0) AS shadow_closed, s.shadow_agreement
            FROM pattern_state p LEFT JOIN (
              SELECT pattern_id, count(*) AS shadow_closed,
                     round(avg(CASE WHEN agreed THEN 1.0 WHEN NOT agreed THEN 0.0 END), 3) AS shadow_agreement
              FROM dispositions WHERE shadow GROUP BY pattern_id) s USING (pattern_id)
            ORDER BY p.pattern_id""")

    def service(self, days: int | None = None) -> list[dict[str, Any]]:
        return self.query(f"""WITH closed AS (
              SELECT d.pattern_id, epoch(d.closed_at - i.created_at) / 60.0 AS minutes
              FROM dispositions d JOIN incidents i ON i.id = d.incident_id
              WHERE NOT coalesce(d.shadow, false) AND {self._since(days, 'd.closed_at')}),
            rv AS (
              SELECT i.pattern_id, count(*) FILTER (r.is_open) AS open_reviews,
                     count(*) FILTER (r.is_open AND r.due_at < now()) AS overdue,
                     count(*) FILTER (r.escalation_level > 0) AS escalated
              FROM reviews r JOIN incidents i ON i.id = r.incident_id GROUP BY 1),
            pats AS (SELECT pattern_id FROM closed UNION SELECT pattern_id FROM rv)
            SELECT p.pattern_id, count(c.minutes) AS closed,
              round(quantile_cont(c.minutes, 0.5), 1) AS p50_minutes,
              round(quantile_cont(c.minutes, 0.9), 1) AS p90_minutes,
              coalesce(any_value(rv.open_reviews), 0) AS open_reviews,
              coalesce(any_value(rv.overdue), 0) AS overdue_reviews,
              coalesce(any_value(rv.escalated), 0) AS escalated_reviews
            FROM pats p LEFT JOIN closed c USING (pattern_id) LEFT JOIN rv USING (pattern_id)
            GROUP BY p.pattern_id ORDER BY p.pattern_id""")

    def models(self, days: int | None = None) -> list[dict[str, Any]]:
        return self.query(f"""WITH runs AS (SELECT * FROM model_runs WHERE {self._since(days, 'at')}),
            agree AS (
              SELECT json_extract_string(data, '$.model') AS model, json_extract_string(data, '$.task') AS task,
                     count(*) FILTER (json_extract_string(data, '$.agreed') IN ('true', 'false')) AS compared,
                     count(*) FILTER (json_extract_string(data, '$.agreed') = 'true') AS agreed
              FROM audit WHERE kind = 'model_shadow' AND {self._since(days, 'at')} GROUP BY 1, 2)
            SELECT r.task, r.model, bool_or(r.shadow) AS shadow, count(*) AS calls,
              count(*) FILTER (NOT r.ok) AS errors,
              count(*) FILTER (r.fallback_reason IS NOT NULL) AS answered_as_fallback,
              count(*) FILTER (r.escalated) AS escalations_answered,
              round(avg(r.latency_ms), 1) AS avg_ms, round(quantile_cont(r.latency_ms, 0.95), 1) AS p95_ms,
              coalesce(sum(r.prompt_tokens), 0) AS prompt_tokens,
              coalesce(sum(r.completion_tokens), 0) AS completion_tokens,
              round(sum(r.est_cost), 4) AS est_cost,
              any_value(a.compared) AS shadow_compared,
              CASE WHEN any_value(a.compared) > 0 THEN round(any_value(a.agreed) / any_value(a.compared), 3)
              END AS shadow_agreement
            FROM runs r LEFT JOIN agree a ON a.model = r.model AND a.task = r.task AND r.shadow
            GROUP BY r.task, r.model, r.shadow ORDER BY r.task, calls DESC""")

    def hotspots(self, facts: list[str] | None = None, days: int | None = None, top: int = 20
                 ) -> list[dict[str, Any]]:
        facts = facts or ["location", "site", "channel"]
        bad = [f for f in facts if not _FACT.match(f)]
        if bad:
            raise ValueError(f"invalid fact names: {bad}")
        if not isinstance(top, int) or top < 1:
            raise ValueError("top must be a positive integer")
        parts = [f"""SELECT {_q(f)} AS fact, json_extract_string(facts, {_q('$.' + f)}) AS value, pattern_id,
                     count(*) AS incidents, count(*) FILTER (state <> 'dispositioned') AS still_open
                 FROM incidents WHERE json_extract_string(facts, {_q('$.' + f)}) IS NOT NULL
                   AND NOT coalesce(shadow, false) AND {self._since(days, 'created_at')}
                 GROUP BY 1, 2, 3""" for f in facts]
        return self.query(f"SELECT * FROM ({' UNION ALL '.join(parts)}) ORDER BY incidents DESC, fact, value "
                          f"LIMIT {top}")

    def evaluations(self) -> list[dict[str, Any]]:
        """Model evaluations run with `sentinel evaluate`, newest first."""
        return self.query("""SELECT strftime("at", '%Y-%m-%d %H:%M UTC') AS "when",
            json_extract_string(data, '$.model') AS model,
            CAST(json_extract(data, '$.overall.cases') AS INTEGER) AS cases,
            CAST(json_extract(data, '$.overall.exact') AS DOUBLE) AS exact,
            CAST(json_extract(data, '$.overall.agrees_with_primary') AS DOUBLE) AS agrees_with_primary,
            CAST(json_extract(data, '$.overall.error_rate') AS DOUBLE) AS error_rate,
            array_to_string(CAST(json_extract(data, '$.overall.ready_patterns') AS VARCHAR[]), ', ') AS ready_for
            FROM audit WHERE kind = 'model_evaluation' ORDER BY seq DESC""")

    def all(self, days: int | None = None, facts: list[str] | None = None) -> dict[str, list[dict[str, Any]]]:
        return {"automation": self.automation(days), "weekly": self.weekly(days), "trust": self.trust(),
                "service": self.service(days), "models": self.models(days), "hotspots": self.hotspots(facts, days),
                "evaluations": self.evaluations()}

    # ---- snapshots ---------------------------------------------------------
    def snapshot(self, out_dir: str) -> dict[str, int]:
        """Copy every store table to Parquet (``<out_dir>/<table>.parquet``); returns row counts."""
        if self._src == "snap":
            raise AnalyticsError("already reading a snapshot")
        d = Path(out_dir)
        d.mkdir(parents=True, exist_ok=True)
        counts = {}
        for t in TABLES:
            if not self._has(t):
                continue
            target = d / f"{t}.parquet"
            self.con.execute(f"COPY (SELECT * FROM {self._src}.{t}) TO {_q(str(target))} (FORMAT parquet)")
            counts[t] = self.con.execute(f"SELECT count(*) FROM read_parquet({_q(str(target))})").fetchone()[0]
        return counts

    def close(self) -> None:
        self.con.close()

    def __enter__(self) -> Analytics:
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()


def render_table(rows: list[dict[str, Any]]) -> str:
    """Plain-text table for the terminal."""
    if not rows:
        return "(no data)"
    cols = list(rows[0])

    def fmt(v: Any) -> str:
        if v is None:
            return "-"
        if isinstance(v, float):
            return f"{v:g}"
        return str(v)
    cells = [[fmt(r.get(c)) for c in cols] for r in rows]
    widths = [max(len(c), *(len(row[i]) for row in cells)) for i, c in enumerate(cols)]
    line = "  ".join(c.ljust(w) for c, w in zip(cols, widths, strict=True))
    out = [line, "  ".join("-" * w for w in widths)]
    out += ["  ".join(v.ljust(w) for v, w in zip(row, widths, strict=True)) for row in cells]
    return "\n".join(out)
