"""Tests for case.sqlite (4D.5): table, indexes, and the seven views."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest
from test_findings_support import base_row, build_run, write_parts

from forensic_analyze import export_sqlite, findings


def query(db: Path, sql: str) -> list[tuple[object, ...]]:
    con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    try:
        return con.execute(sql).fetchall()
    finally:
        con.close()


def ids(db: Path, view: str) -> list[str]:
    return [r[0] for r in query(db, f"SELECT finding_id FROM {view}")]  # noqa: S608


def test_table_has_one_column_per_field_in_order(tmp_path: Path) -> None:
    build_run(tmp_path)
    db = export_sqlite.build(tmp_path)
    cols = [r[1] for r in query(db, "PRAGMA table_info(findings)")]
    assert cols == list(findings.FIELDS)
    indexes = {r[1] for r in query(db, "PRAGMA index_list(findings)")}
    assert {"idx_findings_datetime", "idx_findings_category"} <= indexes
    views = {r[0] for r in query(db, "SELECT name FROM sqlite_master WHERE type = 'view'")}
    assert views == set(export_sqlite.VIEWS)
    assert query(db, "PRAGMA user_version") == [(findings.SCHEMA_VERSION,)]
    assert query(db, "PRAGMA application_id") == [(export_sqlite.APPLICATION_ID,)]


def test_rows_match_findings_exactly(tmp_path: Path) -> None:
    res = build_run(tmp_path)
    db = export_sqlite.build(tmp_path)
    con = sqlite3.connect(db)
    con.row_factory = sqlite3.Row
    got = con.execute("SELECT rowid, * FROM findings ORDER BY rowid").fetchall()
    con.close()
    rows = list(findings.iter_findings(tmp_path))
    assert len(got) == len(rows) == res.count
    for n, (sql_row, row) in enumerate(zip(got, rows, strict=True), 1):
        assert sql_row["rowid"] == n
        for name in findings.FIELDS:
            value = row.get(name)
            if isinstance(value, bool):
                value = int(value)
            assert sql_row[name] == value, (row["finding_id"], name)
    info = dict(query(db, "SELECT key, value FROM export_info"))
    assert info["findings_sha256"] == res.sha256
    assert info["row_count"] == str(res.count)


def test_views(tmp_path: Path) -> None:
    write_parts(
        tmp_path,
        {
            "inventory": [
                base_row(message="t-late", datetime="2024-01-01T00:00:01Z", allocated=True),
                base_row(message="t-whole", datetime="2024-01-01T00:00:00Z", allocated=False),
                base_row(message="t-half", datetime="2024-01-01T00:00:00.5Z"),
                base_row(message="t-tenth", datetime="2024-01-01T00:00:00.05Z"),
                base_row(message="t-zeros", datetime="2024-01-01T00:00:00.000Z"),
                base_row(message="no-time"),
            ],
            "recycle_bin": [base_row(category="recycle_bin", message="rb")],
            "deletion_history": [base_row(category="deletion", message="del")],
            "malware": [
                base_row(category="malware", message="mw"),
                base_row(category="hash", message="hs"),
            ],
            "images": [
                base_row(category="images", message="img", label="flagged", score=0.9),
                base_row(category="video", message="vid", sensitive_flag=True),
                base_row(category="audio", message="aud", sensitive_flag=False),
                base_row(category="documents", message="doc", label="yara-rule"),
            ],
            "xval": [
                base_row(category="xval", message="dis", xval_status="disagree"),
                base_row(category="xval", message="agr", xval_status="agree"),
            ],
        },
    )
    findings.merge(
        tmp_path, ["inventory", "recycle_bin", "deletion_history", "malware", "images", "xval"]
    )
    db = export_sqlite.build(tmp_path)

    def msgs(view: str) -> list[str]:
        return [r[0] for r in query(db, f"SELECT message FROM {view}")]  # noqa: S608

    assert msgs("v_timeline") == ["t-whole", "t-zeros", "t-tenth", "t-half", "t-late"]
    assert msgs("v_deleted") == ["t-whole", "del"]
    assert msgs("v_recycle_bin") == ["rb"]
    assert msgs("v_media") == ["img", "vid", "aud"]
    assert msgs("v_hash_hits") == ["mw", "hs"]
    assert msgs("v_flags") == ["img", "vid"]
    assert msgs("v_disagreements") == ["dis"]


def test_hostile_text_round_trips(tmp_path: Path) -> None:
    res = build_run(tmp_path)
    db = export_sqlite.build(tmp_path)
    rows = {r["finding_id"]: r for r in findings.iter_findings(tmp_path)}
    for fid, path, b64, message in query(
        db, "SELECT finding_id, path, path_b64, message FROM findings"
    ):
        assert path == rows[fid].get("path")
        assert b64 == rows[fid].get("path_b64")
        assert message == rows[fid]["message"]
    assert res.count == len(rows)


def test_rebuild_replaces_file_and_cleans_up(tmp_path: Path) -> None:
    build_run(tmp_path)
    export_sqlite.build(tmp_path)
    db = export_sqlite.build(tmp_path)
    assert db == tmp_path / "case.sqlite"
    assert not list(tmp_path.glob(".case.sqlite.*"))


def test_invalid_findings_leave_no_database(tmp_path: Path) -> None:
    (tmp_path / "findings.jsonl").write_text('{"message":"x"}\n', encoding="utf-8")
    with pytest.raises(findings.SchemaError):
        export_sqlite.build(tmp_path)
    assert not (tmp_path / "case.sqlite").exists()
    assert not list(tmp_path.glob(".case.sqlite*"))
    assert export_sqlite.main([str(tmp_path)]) == 1
    assert export_sqlite.main([]) == 2
