# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""Planted-defect tests for tools/vendor_check.py: every rule is shown red, then the clean copy green."""
import hashlib
import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("vendor_check", ROOT / "tools" / "vendor_check.py")
vc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vc)

COMMIT = "a" * 40


def h(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def make(tmp: Path, files: dict[str, bytes], rows: str, declined: str = "", changes: str = "",
         commit: str = COMMIT) -> Path:
    d = tmp / "vendor"
    d.mkdir()
    for name, data in files.items():
        (d / name).write_bytes(data)
    (d / "_VENDOR.md").write_text(
        f"# record\n\n- source repository: a clone\n- base commit: `{commit}`\n- vendored on: 2026-01-01\n\n"
        f"## Files taken\n\n| file | state | local change | sha256 (this copy) | sha256 (base) |\n|---|---|---|---|---|\n{rows}\n\n"
        f"## Files deliberately not taken\n\n{declined}\n\n## Local changes (every one is logged here)\n\n{changes}\n",
        encoding="utf-8")
    return d


def row(name, state, data, change="-", base="same"):
    return f"| `{name}` | {state} | {change} | `{h(data)}` | {base if base == 'same' else '`' + base + '`'} |"


A = b"alpha\r\n"
B = b"beta\n"


def clean(tmp: Path) -> Path:
    return make(tmp, {"a.py": A, "b.py": B},
                row("a.py", "byte-for-byte", A) + "\n" + row("b.py", "adapted", B, "L1", h(b"orig")),
                declined="- `c.py`: does not fit this product",
                changes="- **L1, `b.py`**: renamed a field")


def test_clean_record_passes(tmp_path):
    assert vc.check(clean(tmp_path)) == []


def test_untouched_file_that_changed_fails(tmp_path):
    d = clean(tmp_path)
    (d / "a.py").write_bytes(A + b"# edited\n")
    assert any("a.py" in p and "byte-for-byte but has CHANGED" in p for p in vc.check(d))


def test_line_ending_conversion_counts_as_a_change(tmp_path):
    d = clean(tmp_path)
    (d / "a.py").write_bytes(A.replace(b"\r\n", b"\n"))
    assert any("CHANGED" in p for p in vc.check(d))


def test_adapted_file_edited_without_rerecording_fails(tmp_path):
    d = clean(tmp_path)
    (d / "b.py").write_bytes(B + b"x")
    assert any("b.py: changed since it was recorded" in p for p in vc.check(d))


def test_unlisted_file_fails(tmp_path):
    d = clean(tmp_path)
    (d / "extra.py").write_bytes(b"x")
    assert any("extra.py: present but not listed" in p for p in vc.check(d))


def test_declined_file_present_fails(tmp_path):
    d = clean(tmp_path)
    (d / "c.py").write_bytes(b"x")
    assert any("c.py: recorded as deliberately not taken but present" in p for p in vc.check(d))


def test_declined_file_without_reason_fails(tmp_path):
    d = make(tmp_path, {"a.py": A}, row("a.py", "byte-for-byte", A), declined="- `c.py`:")
    assert any("c.py: declined file has no reason" in p for p in vc.check(d))


def test_recorded_but_missing_fails(tmp_path):
    d = clean(tmp_path)
    (d / "a.py").unlink()
    assert any("a.py: recorded but missing" in p for p in vc.check(d))


def test_unknown_state_fails(tmp_path):
    d = make(tmp_path, {"a.py": A}, row("a.py", "mostly-the-same", A))
    assert any("not one of" in p for p in vc.check(d))


def test_adapted_without_change_id_fails(tmp_path):
    d = make(tmp_path, {"a.py": A}, row("a.py", "adapted", A, "-", h(b"o")))
    assert any("needs a local change id" in p for p in vc.check(d))


def test_adapted_naming_an_unlogged_change_fails(tmp_path):
    d = make(tmp_path, {"a.py": A}, row("a.py", "trimmed", A, "L9", h(b"o")), changes="- **L1, x**: y")
    assert any("L9 is not logged" in p for p in vc.check(d))


def test_adapted_identical_to_base_must_be_byte_for_byte(tmp_path):
    d = make(tmp_path, {"a.py": A}, row("a.py", "adapted", A, "L1", h(A)), changes="- **L1, a.py**: none")
    assert any("record it as byte-for-byte" in p for p in vc.check(d))


def test_byte_for_byte_with_a_different_base_hash_fails(tmp_path):
    d = make(tmp_path, {"a.py": A}, row("a.py", "byte-for-byte", A, "-", h(b"other")))
    assert any("base hash differs" in p for p in vc.check(d))


def test_byte_for_byte_naming_a_change_fails(tmp_path):
    d = make(tmp_path, {"a.py": A}, row("a.py", "byte-for-byte", A, "L1"))
    assert any("names local change" in p for p in vc.check(d))


def test_bad_or_placeholder_base_commit_fails(tmp_path):
    assert any("40-character" in p for p in vc.check(make(tmp_path, {"a.py": A}, row("a.py", "byte-for-byte", A), commit="abc123")))
    (tmp_path / "x").mkdir()
    d2 = make(tmp_path / "x", {"a.py": A}, row("a.py", "byte-for-byte", A), commit="<40-character commit id>")
    assert any("base commit" in p and "placeholder" in p for p in vc.check(d2))


def test_missing_record_fails(tmp_path):
    (tmp_path / "v").mkdir()
    assert any("_VENDOR.md is missing" in p for p in vc.check(tmp_path / "v"))


def test_against_the_base_checkout(tmp_path):
    d = clean(tmp_path)
    base = tmp_path / "base"
    base.mkdir()
    (base / "a.py").write_bytes(A)
    (base / "b.py").write_bytes(b"orig")
    assert vc.check(d, base) == []
    (base / "a.py").write_bytes(b"upstream moved on")
    assert any("a.py: the base's sha256 is not what" in p for p in vc.check(d, base))


def test_pycache_is_ignored(tmp_path):
    d = clean(tmp_path)
    (d / "__pycache__").mkdir()
    (d / "__pycache__" / "a.cpython-311.pyc").write_bytes(b"x")
    assert vc.check(d) == []


def test_print_table_rows_round_trip(tmp_path):
    d = make(tmp_path, {"a.py": A, "b.py": B}, "")
    rows = vc.table_rows(d)
    (d / "_VENDOR.md").write_text((d / "_VENDOR.md").read_text().replace("|---|---|---|---|---|\n", "|---|---|---|---|---|\n" + rows + "\n"), encoding="utf-8")
    assert vc.check(d) == []


def test_the_shipped_template_parses_and_keeps_its_columns():
    rec = vc.parse_record((ROOT / "templates" / "_VENDOR.md").read_text(encoding="utf-8"))
    assert [r["file"] for r in rec["files"]] == ["example.py"]
    assert "example_declined.py" in rec["declined"] and "L1" in rec["changes"]


def test_main_exit_codes(tmp_path):
    d = clean(tmp_path)
    assert vc.main([str(d)]) == 0
    (d / "a.py").write_bytes(b"changed")
    assert vc.main([str(d)]) == 1
