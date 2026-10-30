# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""Fleet view: every Sentinel site KBGrid looks after, on one page.

Each site answers ``GET /v1/fleet/status`` (a service token whose principal is ``fleet``, or a person with
__configure__) with its version, health, licence, last backup, last usage export and what is published. A
fleet file lists the sites to collect from::

    sites:
      acme-prod:  {url: "https://sentinel.acme.example", token_env: SENTINEL_SECRET_FLEET_ACME}
      northwind-pilot: {url: "https://sentinel.northwind.example", token_env: SENTINEL_SECRET_FLEET_NORTHWIND}
    target_version: "0.10.0"          # sites behind it are flagged, with the command that upgrades them
    support_window: 2                 # minor releases supported: current + previous (ADR-004 §5)

Each client adopts versions under support (ADR-004): a site's own ``target_version`` comes from its
``SENTINEL_ADOPTION.md`` and overrides the fleet-wide one. A site more than ``support_window`` minor releases
behind the newest release is flagged ``outside support window``.

Upgrades are pulled by the site, never pushed: the fleet view says which sites are behind and gives the
exact commands to run there (or in the site's CI). No site accepts code from the fleet.
"""
from __future__ import annotations

import concurrent.futures as cf
import json
import os
import urllib.error
import urllib.request
from datetime import UTC
from pathlib import Path
from typing import TYPE_CHECKING, Any

import yaml
from pydantic import BaseModel, Field

if TYPE_CHECKING:
    from .engine import Engine


class Site(BaseModel):
    url: str
    token_env: str
    notes: str = ""
    target_version: str | None = None     # this client's agreed target (its SENTINEL_ADOPTION.md); overrides
    adoption: str = ""                    # where its support record lives


class FleetFile(BaseModel):
    sites: dict[str, Site] = Field(default_factory=dict)
    target_version: str | None = None
    image: str = "kbg-sentinel"
    support_window: int = Field(default=2, ge=1)    # minor releases supported (current + previous by default)
    latest_version: str | None = None                # newest release; default: this Sentinel's version

    def target_for(self, name: str) -> str | None:
        site = self.sites.get(name)
        return (site.target_version if site is not None and site.target_version else None) or self.target_version

    def latest(self) -> str:
        from . import __version__
        return self.latest_version or __version__


def minors_behind(version: str | None, latest: str) -> int:
    """Minor releases between a version and the newest (a different major counts as outside any window)."""
    v, l_ = _vt(version), _vt(latest)
    if (v[:1] or (0,)) != (l_[:1] or (0,)):
        return 10_000
    return max(0, (l_[1] if len(l_) > 1 else 0) - (v[1] if len(v) > 1 else 0))


def load(path: str) -> FleetFile:
    return FleetFile.model_validate(yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {})


def site_status(engine: Engine) -> dict[str, Any]:
    """This site's own status, as the fleet sees it."""
    from . import __version__
    store = engine.store
    h = engine.health()
    lic = None
    if engine.licence is not None:
        st = engine.licence.status(engine)
        lic = {"state": st["state"], "reasons": st["reasons"],
               "valid_until": (st.get("licence") or {}).get("valid_until"),
               "tier": (st.get("licence") or {}).get("tier")}
    backups = store.recent_audit(1, ["backup_made"])
    usage = store.recent_audit(1, ["usage_exported"])
    sv = getattr(store, "schema_version", None)
    cfg = {}
    for kind in ("registry", "people", "models", "connectors"):
        cv = store.published_config(kind)
        cfg[kind] = {"version": cv.version, "checksum": cv.checksum,
                     "published_at": cv.published_at.isoformat() if cv.published_at else None} if cv else None
    return {"site": os.environ.get("SENTINEL_SITE_ID") or engine.overlay.name, "overlay": engine.overlay.name,
            "version": __version__, "schema": sv() if callable(sv) else None,
            "store": type(store).__name__, "now": engine.clock().astimezone(UTC).isoformat(),
            "health": h.get("status"), "problems": h.get("problems", []), "open_reviews": h.get("open_reviews"),
            "overdue_reviews": h.get("overdue_reviews"), "licence": lic,
            "last_backup": backups[0]["ts"] if backups else None,
            "last_usage_export": (usage[0]["data"] | {"ts": usage[0]["ts"]}) if usage else None,
            "config": cfg, "patterns": len(engine.registry.all()),
            "live": sum(1 for p in engine.registry.all() if not engine.is_shadow(p))}


def _vt(v: str | None) -> tuple[int, ...]:
    out = []
    for part in (v or "0").split("."):
        digits = "".join(ch for ch in part if ch.isdigit())
        out.append(int(digits or 0))
    return tuple(out)


def collect(fleet: FleetFile, *, opener: Any = None, timeout_s: float = 10.0) -> dict[str, Any]:
    from . import egress

    def one(name: str, site: Site) -> dict[str, Any]:
        token = os.environ.get(site.token_env)
        if not token:
            return {"name": name, "reachable": False, "error": f"{site.token_env} is not set"}
        req = urllib.request.Request(site.url.rstrip("/") + "/v1/fleet/status",  # noqa: S310 - egress checks
                                     headers={"Authorization": f"Bearer {token}", "Accept": "application/json"})
        try:
            status, _, raw = egress.open_url(req, timeout_s, base_opener=opener)
            data = json.loads(raw)
        except urllib.error.HTTPError as e:
            return {"name": name, "reachable": False, "error": f"HTTP {e.code}"}
        except (egress.EgressError, urllib.error.URLError, OSError, ValueError) as e:
            return {"name": name, "reachable": False, "error": str(getattr(e, "reason", e))[:300]}
        return {"name": name, "reachable": True, **data}

    with cf.ThreadPoolExecutor(max_workers=8) as pool:
        rows = list(pool.map(lambda kv: one(*kv), fleet.sites.items()))
    for r in rows:
        flags = []
        if not r.get("reachable"):
            flags.append("unreachable")
        else:
            if r.get("health") != "ok" or r.get("problems"):
                flags.append("unhealthy")
            if (r.get("licence") or {}).get("state") in ("degraded", "grace"):
                flags.append(f"licence {r['licence']['state']}")
            if r.get("last_backup") is None:
                flags.append("no backup")
            target = fleet.target_for(r["name"])
            r["target_version"] = target
            if target and _vt(r.get("version")) < _vt(target):
                flags.append("behind")
                r["upgrade"] = upgrade_commands(fleet, r, target)
            r["minors_behind"] = minors_behind(r.get("version"), fleet.latest())
            if r["minors_behind"] >= fleet.support_window:
                flags.append("outside support window")
        site = fleet.sites.get(r["name"])
        if site is not None and site.adoption:
            r["adoption"] = site.adoption
        r["flags"] = flags
    return {"target_version": fleet.target_version, "latest_version": fleet.latest(),
            "support_window": fleet.support_window, "sites": rows,
            "summary": {"sites": len(rows), "attention": sum(bool(r["flags"]) for r in rows)}}


def upgrade_commands(fleet: FleetFile, row: dict[str, Any], target: str | None = None) -> list[str]:
    """What to run on the site (in deploy/site) to move it to its target version."""
    v = target or fleet.target_for(row.get("name", "")) or fleet.target_version
    return ["docker compose run --rm maintenance backup --out /backups     # a fresh, verified backup first",
            f"sed -i 's|image: {fleet.image}:.*|image: {fleet.image}:{v}|' compose.yaml",
            "docker compose build && docker compose run --rm api migrate",
            "docker compose up -d && docker compose ps"]
