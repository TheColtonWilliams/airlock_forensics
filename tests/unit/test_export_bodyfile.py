"""Tests for the Sleuth Kit bodyfile export (4D.10)."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest
from test_findings_support import base_row, build_run, write_parts

from forensic_analyze import export_bodyfile, findings

T0 = "2024-03-01T10:00:00Z"  # 1709287200
T1 = "2024-03-01T10:00:01.9Z"  # 1709287201 (floored)


@pytest.mark.parametrize(
    ("desc", "slot"),
    [
        ("Content Modification Time", "m"),
        ("Last Written", "m"),
        ("Last Access Time", "a"),
        ("Metadata Modification Time", "c"),
        ("Entry Modified", "c"),
        ("Status Change Time", "c"),
        ("Creation Time", "b"),
        ("Birth Time", "b"),
        ("Creation Time ($FILE_NAME)", "b"),
        ("Deletion Time", None),
        ("Recycle Time", None),
    ],
)
def test_macb_slot(desc: str, slot: str | None) -> None:
    assert export_bodyfile.macb_slot(desc) == slot


def test_bodyfile_inode() -> None:
    assert export_bodyfile.bodyfile_inode("v0:64-1") == "64-1"
    assert export_bodyfile.bodyfile_inode("v2:5") == "5"
    assert export_bodyfile.bodyfile_inode("64-128-1") == "64-128-1"
    assert export_bodyfile.bodyfile_inode("") == "0"
    assert export_bodyfile.bodyfile_inode("odd|ref") == "0"


def test_split_desc_and_epoch() -> None:
    assert export_bodyfile.split_desc("Creation Time ($FILE_NAME)") == (
        "Creation Time",
        "$FILE_NAME",
    )
    assert export_bodyfile.split_desc("Creation Time") == ("Creation Time", "")
    assert export_bodyfile.epoch_seconds(T0) == 1709287200
    assert export_bodyfile.epoch_seconds(T1) == 1709287201
    assert export_bodyfile.epoch_seconds("1969-12-31T23:59:59Z") is None
    assert export_bodyfile.epoch_seconds("garbage") is None


def _file_rows(path: str, inode: str, **extra: object) -> list[dict[str, object]]:
    common = {"path": path, "inode_ref": inode, "tz_basis": "utc", **extra}
    return [
        base_row(datetime=T0, timestamp_desc="Content Modification Time", **common),
        base_row(datetime=T1, timestamp_desc="Last Access Time", **common),
        base_row(datetime=T0, timestamp_desc="Metadata Modification Time", **common),
        base_row(datetime=T0, timestamp_desc="Creation Time", **common),
        base_row(datetime=T1, timestamp_desc="Creation Time ($FILE_NAME)", **common),
    ]


def test_bodyfile_lines(tmp_path: Path) -> None:
    rows = _file_rows("/a|b.txt", "v0:64-1", size_bytes=12, md5="0" * 31 + "1")
    rows += _file_rows("/gone.txt", "v0:65-2", allocated=False)
    rows += [
        base_row(path="/x", datetime=T0, timestamp_desc="Deletion Time"),
        base_row(
            path="/y", datetime=T0, timestamp_desc="Creation Time", tz_basis="local_unknown_offset"
        ),
        base_row(datetime=T0, timestamp_desc="Creation Time"),  # no path or inode
        base_row(path="/z", timestamp_desc="Creation Time"),  # no time
        # A second, different creation time for the same file starts a further line.
        base_row(
            path="/a|b.txt",
            inode_ref="v0:64-1",
            datetime=T1,
            timestamp_desc="Creation Time",
            tz_basis="utc",
        ),
    ]
    write_parts(tmp_path, {"inventory": rows})
    findings.merge(tmp_path, ["inventory"])
    out = export_bodyfile.build(tmp_path)
    assert out == tmp_path / "findings.bodyfile"
    lines = out.read_text(encoding="utf-8").splitlines()
    assert all(len(line.split("|")) == 11 for line in lines)
    md5 = "0" * 31 + "1"
    t0, t1 = "1709287200", "1709287201"
    assert lines == [
        f"{md5}|/a\\u007cb.txt|64-1|0|0|0|12|{t1}|{t0}|{t0}|{t0}",
        f"{md5}|/a\\u007cb.txt ($FILE_NAME)|64-1|0|0|0|12|0|0|0|{t1}",
        f"0|/gone.txt (deleted)|65-2|0|0|0|0|{t1}|{t0}|{t0}|{t0}",
        f"0|/gone.txt ($FILE_NAME) (deleted)|65-2|0|0|0|0|0|0|0|{t1}",
        f"0|/a\\u007cb.txt|64-1|0|0|0|0|0|0|0|{t1}",
    ]


def test_bodyfile_from_sample_run_is_valid(tmp_path: Path) -> None:
    build_run(tmp_path)
    lines = export_bodyfile.build(tmp_path).read_text(encoding="utf-8").splitlines()
    assert lines
    for line in lines:
        cols = line.split("|")
        assert len(cols) == 11
        assert all(c.lstrip("-").isdigit() for c in cols[6:])


@pytest.mark.skipif(shutil.which("mactime") is None, reason="needs mactime (sleuthkit)")
def test_mactime_reads_bodyfile(tmp_path: Path) -> None:
    write_parts(tmp_path, {"inventory": _file_rows("/a.txt", "v0:64-1", size_bytes=5)})
    findings.merge(tmp_path, ["inventory"])
    body = export_bodyfile.build(tmp_path)
    cp = subprocess.run(
        ["mactime", "-b", str(body), "-z", "UTC", "-d"],
        capture_output=True,
        text=True,
        check=True,
    )
    assert "/a.txt" in cp.stdout
    assert "2024" in cp.stdout


def test_main(tmp_path: Path) -> None:
    assert export_bodyfile.main([]) == 2
    assert export_bodyfile.main([str(tmp_path / "missing")]) == 1
