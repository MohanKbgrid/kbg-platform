# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""Fail if a vendored copy of a KBG base no longer matches the record that describes it.

    python tools/vendor_check.py DIR                 # DIR holds the vendored files and _VENDOR.md
    python tools/vendor_check.py DIR --base BASEDIR  # also compare against a checkout of the base
    python tools/vendor_check.py DIR --print-table   # print table rows for the files now in DIR

A base is VENDORED (copied and owned), so the only protection against a silent edit is a record
that says what each file was when it was taken. That record is `DIR/_VENDOR.md` (start from
`templates/_VENDOR.md`). This tool turns the record into a gate. It fails when:

  1. a file recorded as `byte-for-byte` has changed (the whole point: an "untouched" file that
     was edited is exactly the drift nobody sees), or a recorded hash is stale for an
     `adapted`/`trimmed` file (change it, then re-record it and log why);
  2. a file in DIR is not in the record, or a declined file is present;
  3. a recorded file is missing;
  4. a state is not one of `byte-for-byte`, `adapted`, `trimmed`; an `adapted`/`trimmed` row has
     no local change id, or names one that the "Local changes" section does not log; a
     `byte-for-byte` row claims a local change or a base hash that differs from its own;
  5. the base commit is not a 40-hex id, or a required header line is missing or still a
     `<placeholder>`;
  6. a declined file has no reason;
  7. with `--base`: a recorded base hash is not what the base actually has.

Hashes are taken over the raw bytes, so line-ending conversion counts as a change (mark the
directory `-text` in .gitattributes so git never does it for you).
"""
from __future__ import annotations

import argparse
import hashlib
import re
import sys
from pathlib import Path

RECORD = "_VENDOR.md"
STATES = ("byte-for-byte", "adapted", "trimmed")
IGNORED_NAMES = {RECORD, ".DS_Store"}
IGNORED_PARTS = {"__pycache__"}
HEX64 = re.compile(r"^[0-9a-f]{64}$")
HEX40 = re.compile(r"^[0-9a-f]{40}$")
REQUIRED_HEADER = ("source repository", "base commit", "vendored on")


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def present_files(directory: Path) -> list[str]:
    out = []
    for p in sorted(directory.rglob("*")):
        rel = p.relative_to(directory)
        if not p.is_file() or p.name in IGNORED_NAMES or IGNORED_PARTS & set(rel.parts):
            continue
        if p.suffix == ".pyc":
            continue
        out.append(rel.as_posix())
    return out


def _cell(text: str) -> str:
    return text.strip().strip("`").strip()


def parse_record(text: str) -> dict:
    """Read the header lines, the files table, the declined list and the logged change ids."""
    rec: dict = {"header": {}, "files": [], "declined": {}, "changes": set(), "errors": []}
    section = ""
    for line in text.splitlines():
        if line.startswith("## "):
            section = line[3:].strip().lower()
            continue
        if not section:
            m = re.match(r"^- ([a-z ]+?):\s*(.*)$", line)
            if m:
                rec["header"][m.group(1).strip()] = m.group(2).strip().strip("`")
            continue
        if section.startswith("files taken") and line.startswith("|"):
            cells = [_cell(c) for c in line.strip().strip("|").split("|")]
            if set(line) <= set("|-: "):
                continue                       # the |---|---| separator
            if cells and cells[0].lower() == "file":
                continue                       # the header row
            if len(cells) != 5:
                rec["errors"].append(f"malformed table row: {line[:60]!r}")
                continue
            rec["files"].append(dict(zip(("file", "state", "change", "sha", "base"), cells)))
        elif section.startswith("files deliberately not taken"):
            m = re.match(r"^- `([^`]+)`\s*:?\s*(.*)$", line)
            if m:
                rec["declined"][m.group(1)] = m.group(2).strip()
        elif section.startswith("local changes"):
            m = re.match(r"^- \*\*(L\d+)\b", line)
            if m:
                rec["changes"].add(m.group(1))
    return rec


def check(directory: Path, base: Path | None = None) -> list[str]:
    problems: list[str] = []
    record_path = directory / RECORD
    if not record_path.is_file():
        return [f"{RECORD} is missing from {directory}: a vendored copy needs its record"]
    rec = parse_record(record_path.read_text(encoding="utf-8"))
    problems += rec["errors"]

    for key in REQUIRED_HEADER:
        value = rec["header"].get(key, "")
        if not value or "<" in value:
            problems.append(f"{RECORD}: header line '{key}' is missing or still a placeholder")
    commit = rec["header"].get("base commit", "")
    if commit and "<" not in commit and not HEX40.match(commit.split()[0]):
        problems.append(f"{RECORD}: base commit {commit!r} is not a 40-character commit id")

    recorded: set[str] = set()
    for row in rec["files"]:
        name, state = row["file"], row["state"].lower()
        if name in recorded:
            problems.append(f"{name}: listed twice in {RECORD}")
        recorded.add(name)
        if state not in STATES:
            problems.append(f"{name}: state {row['state']!r} is not one of {', '.join(STATES)}")
            continue
        if not HEX64.match(row["sha"]):
            problems.append(f"{name}: recorded sha256 is not a 64-character hex digest")
        change = row["change"]
        if state == "byte-for-byte":
            if change not in ("", "-", "none"):
                problems.append(f"{name}: recorded byte-for-byte but names local change {change}")
            if row["base"] not in ("same", row["sha"]):
                problems.append(f"{name}: recorded byte-for-byte but its base hash differs from its own")
        else:
            if not re.fullmatch(r"L\d+", change):
                problems.append(f"{name}: state {state} needs a local change id (L1, L2, ...)")
            elif change not in rec["changes"]:
                problems.append(f"{name}: {change} is not logged under 'Local changes'")
            if not HEX64.match(row["base"]):
                problems.append(f"{name}: state {state} needs the base file's sha256")
            elif row["base"] == row["sha"]:
                problems.append(f"{name}: recorded {state} but identical to the base: record it as byte-for-byte")

        path = directory / name
        if not path.is_file():
            problems.append(f"{name}: recorded but missing from {directory}")
            continue
        actual = sha256(path)
        if HEX64.match(row["sha"]) and actual != row["sha"]:
            if state == "byte-for-byte":
                problems.append(f"{name}: recorded as byte-for-byte but has CHANGED "
                                f"(recorded {row['sha'][:12]}, now {actual[:12]})")
            else:
                problems.append(f"{name}: changed since it was recorded "
                                f"(recorded {row['sha'][:12]}, now {actual[:12]}): re-record it and log why")
        if base is not None:
            bfile = base / name
            if not bfile.is_file():
                problems.append(f"{name}: not present in the base checkout {base}")
            else:
                want = row["sha"] if row["base"] == "same" else row["base"]
                if sha256(bfile) != want:
                    problems.append(f"{name}: the base's sha256 is not what {RECORD} records")

    for name in present_files(directory):
        if name in rec["declined"]:
            problems.append(f"{name}: recorded as deliberately not taken but present")
        elif name not in recorded:
            problems.append(f"{name}: present but not listed in {RECORD}")
    for name, reason in rec["declined"].items():
        if not reason or "<" in reason:
            problems.append(f"{name}: declined file has no reason")
    return problems


def table_rows(directory: Path) -> str:
    """Rows to paste into the files table; state and change columns are for you to fill in."""
    return "\n".join(f"| `{n}` | byte-for-byte | - | `{sha256(directory / n)}` | same |"
                     for n in present_files(directory))


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("directory", type=Path)
    ap.add_argument("--base", type=Path, default=None, help="a checkout of the base's package directory")
    ap.add_argument("--print-table", action="store_true")
    args = ap.parse_args(argv)
    if args.print_table:
        print(table_rows(args.directory))
        return 0
    problems = check(args.directory, args.base)
    for p in problems:
        print("FAIL", p)
    print(f"vendor check: {'FAILED, %d problem(s)' % len(problems) if problems else 'ok'}")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
