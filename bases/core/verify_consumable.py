"""The gate that matters for a LIBRARY: build the wheel, install it into a clean target, and
import it with `src/` NOT on the path.

Running the unit gate from the package root proves the CODE works. It does not prove the package
is installable — a wrong `packages.find` root, a missing `__init__`, or a module left out of the
distribution all pass the unit gate and fail every consumer. The sibling UI package failed
exactly that way in this same build: it type-checked, it unit-tested, and no consumer could
import it.

Run: python verify_consumable.py
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

ok = bad = 0


def t(label: str, cond: bool, detail: str = "") -> None:
    global ok, bad
    ok, bad = (ok + 1, bad) if cond else (ok, bad + 1)
    print(f"  [{'PASS' if cond else 'FAIL'}] {label}{' — ' + detail if detail else ''}")


print("\n[library] build the wheel and import from the INSTALLED copy")
with tempfile.TemporaryDirectory() as work:
    target = Path(work) / "site"
    r = subprocess.run([sys.executable, "-m", "pip", "install", ".", "--target", str(target),
                        "--quiet", "--no-deps", "--no-build-isolation"],
                       capture_output=True, text=True)
    t("pip install of the package succeeds", r.returncode == 0, r.stderr.strip()[:70])
    t("the package directory is installed", (target / "kbg_platform_core").is_dir())
    dist = list(target.glob("kbg_platform_core-*.dist-info"))
    t("dist-info is present (a real distribution, not a copied folder)", bool(dist),
      dist[0].name if dist else "")

    # Import in a SUBPROCESS whose path contains only the install target — so nothing can
    # accidentally resolve back to ./src and give a false pass.
    probe = r"""
import json, sys
import kbg_platform_core as k
from kbg_platform_core import Gap, Outbox, Mode, State, Authority, Decision, VersionedWriter
g = Gap("no_price", "not configured")
raised = False
try:
    g.value
except Exception:
    raised = True
out = {
    "file": k.__file__,
    "version": k.__version__,
    "exports": len(k.__all__),
    "gap_raises": raised,
    "held": Outbox(Mode.UAT, type("S", (), {"get": lambda s, a, b: None,
                                            "upsert": lambda s, r: r})()).enqueue(
        topic="t", source_key="k", payload={}).state.value,
    "deny_by_default": not type("A", (Authority,), {"_evaluate": lambda s, a, b, c=None: None})()
                         .check("x", "anything").allowed,
}
print(json.dumps(out))
"""
    r2 = subprocess.run([sys.executable, "-c", probe], capture_output=True, text=True,
                        cwd=work, env={"PYTHONPATH": str(target), "PATH": "",
                                       r"SYSTEMROOT": r"C:\Windows"})
    t("importing from the installed copy succeeds", r2.returncode == 0, r2.stderr.strip()[:70])
    if r2.returncode == 0:
        info = json.loads(r2.stdout.strip())
        here = str(Path(__file__).resolve().parent).replace("\\", "/")
        t("...and it resolved to the INSTALL, not to ./src",
          here not in info["file"].replace("\\", "/"), info["file"][-52:])
        t("version is exposed", info["version"] == "0.1.0", info["version"])
        t("every public symbol is importable", info["exports"] == 20, str(info["exports"]))
        t("D4 survives packaging: Gap.value still raises", info["gap_raises"])
        t("the environment gate survives packaging: UAT holds", info["held"] == "held")
        t("deny-by-default survives packaging", info["deny_by_default"])

print(f"\n{'=' * 70}\n{ok}/{ok + bad} consumability checks passed\n{'=' * 70}")
raise SystemExit(0 if bad == 0 else 1)
