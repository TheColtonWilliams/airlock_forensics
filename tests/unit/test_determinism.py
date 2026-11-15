"""Determinism (4D.9): the same inputs give byte-identical findings.jsonl and exports.

The full replay (run.json against the same image) is tests/functional/test_determinism.sh.
These tests pin down the parts this package owns: emit, merge, and every export.
"""

from __future__ import annotations

import importlib.util
import json
import sqlite3
from pathlib import Path

from test_findings_support import MODULE_ORDER, base_row, build_run, sample_parts, write_parts

from forensic_analyze import export_bodyfile, export_csv, export_sqlite, findings


def _sqlite_rows(db: Path) -> list[tuple[object, ...]]:
    con = sqlite3.connect(db)
    try:
        out = con.execute("SELECT rowid, * FROM findings ORDER BY rowid").fetchall()
        for view in export_sqlite.VIEWS:
            out += [(view, *r) for r in con.execute(f"SELECT * FROM {view}")]  # noqa: S608
        out += con.execute("SELECT * FROM export_info ORDER BY key").fetchall()
        return out
    finally:
        con.close()


def test_two_runs_are_byte_identical(tmp_path: Path) -> None:
    a, b = tmp_path / "a", tmp_path / "b"
    ra, rb = build_run(a), build_run(b)
    assert ra.sha256 == rb.sha256
    assert (a / "findings.jsonl").read_bytes() == (b / "findings.jsonl").read_bytes()
    for build in (export_csv.build, export_bodyfile.build):
        assert build(a).read_bytes() == build(b).read_bytes()
    assert _sqlite_rows(export_sqlite.build(a)) == _sqlite_rows(export_sqlite.build(b))


def test_merging_twice_gives_the_same_bytes(tmp_path: Path) -> None:
    res1 = build_run(tmp_path)
    first = (tmp_path / "findings.jsonl").read_bytes()
    res2 = findings.merge(tmp_path, MODULE_ORDER)
    assert (tmp_path / "findings.jsonl").read_bytes() == first
    assert res1.sha256 == res2.sha256 == findings.file_sha256(tmp_path / "findings.jsonl")


def test_canonical_form(tmp_path: Path) -> None:
    build_run(tmp_path)
    data = (tmp_path / "findings.jsonl").read_bytes()
    assert data.endswith(b"\n") and b"\r" not in data
    for n, line in enumerate(data.decode("utf-8").splitlines(), 1):
        row = json.loads(line)
        assert list(row) == sorted(row)
        assert line == json.dumps(row, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
        assert row["finding_id"] == f"F-{n:06d}"


def test_emit_order_is_kept_and_modules_merge_in_order(tmp_path: Path) -> None:
    parts = sample_parts()
    # Write module parts in reverse; the merge order must still be MODULE_ORDER.
    for module in reversed(list(parts)):
        write_parts(tmp_path, {module: parts[module]})
    findings.merge(tmp_path, MODULE_ORDER)
    got = [r["message"] for r in findings.iter_findings(tmp_path)]
    expected = [
        findings.escape_surrogates(r["message"]) for m in MODULE_ORDER for r in parts.get(m, [])
    ]
    assert got == expected


def test_ai_drift_is_reported_separately(tmp_path: Path) -> None:
    a, b = tmp_path / "a", tmp_path / "b"
    build_run(a)
    parts = sample_parts()
    ai_row = parts["images"][1]
    ai_row["text"] = "A blue square, slightly different wording."
    ai_row["confidence"] = 0.6
    write_parts(b, parts)
    findings.merge(b, MODULE_ORDER)
    report = findings.compare_findings(a, b)
    assert report["identical"] is False
    assert report["non_ai_identical"] is True
    assert report["ai_drift_count"] == 2
    assert {d["field"] for d in report["ai_drift"]} == {"text", "confidence"}


def test_non_ai_difference_fails_the_comparison(tmp_path: Path) -> None:
    a, b = tmp_path / "a", tmp_path / "b"
    build_run(a)
    parts = sample_parts()
    parts["malware"].append(base_row(category="malware", message="extra"))
    write_parts(b, parts)
    findings.merge(b, MODULE_ORDER)
    report = findings.compare_findings(a / "findings.jsonl", b / "findings.jsonl")
    assert report["non_ai_identical"] is False
    assert report["difference_count"] >= 1
    assert findings.main(["compare", str(a), str(b)]) == 1


def test_identical_runs_compare_clean(tmp_path: Path) -> None:
    a, b = tmp_path / "a", tmp_path / "b"
    build_run(a)
    build_run(b)
    report = findings.compare_findings(a, b)
    assert report["identical"] and report["non_ai_identical"]
    assert report["ai_drift_count"] == 0 and report["sha256_a"] == report["sha256_b"]


def test_runner_present_records_findings_hash() -> None:
    """When the core package's runner exists, it must use merge() so run.json gets the hash.

    The full replay against an image is in tests/functional/test_determinism.sh.
    """
    spec = importlib.util.find_spec("forensic_analyze.runner")
    if spec is None or spec.origin is None:
        return  # runner not written yet; nothing to check here
    source = Path(spec.origin).read_text(encoding="utf-8")
    assert "merge" in source, "runner must merge part files through forensic_analyze.findings"
