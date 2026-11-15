"""Built-in parsers for $I (recycle.py), LNK (lnk.py), $SDS (sds.py), bodyfiles, tool CSV, and
Dissect JSON, on bytes built in the test (generated values only)."""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from forensic_analyze.parsers import bodyfile, dissect_json, ezcsv, filetime, lnk, recycle, sds

T = 134_000_000_001_234_567


# -- $I --------------------------------------------------------------------------------------


@pytest.mark.parametrize("version", [1, 2])
def test_i_file_round_trip(version: int) -> None:
    path = "C:\\Users\\Test\\Documents\\naïve.txt"
    data = recycle.build(path, 1234, T, version=version)
    assert len(data) == (544 if version == 1 else 28 + 2 * (len(path) + 1))
    rec = recycle.parse(data)
    assert rec.version == version
    assert rec.file_size == 1234
    assert rec.original_path == "C:\\Users\\Test\\Documents\\naïve.txt"
    assert rec.original_name == "naïve.txt"
    assert rec.deleted_iso == filetime.to_iso(T)


@pytest.mark.parametrize(
    ("data", "why"),
    [
        (b"\x01" * 10, "too short"),
        (struct.pack("<QQQ", 3, 1, T) + b"\0" * 8, r"unknown \$I version"),
        (struct.pack("<QQQ", 1, 1, T) + b"\0" * 10, "version 1"),
        (struct.pack("<QQQI", 2, 1, T, 500) + b"a\0", "does not fit"),
        (struct.pack("<QQQI", 2, 1, 5, 1) + b"\0\0", "1980..2100"),
    ],
)
def test_i_file_errors(data: bytes, why: str) -> None:
    with pytest.raises(recycle.RecycleError, match=why):
        recycle.parse(data)


def test_bin_path_helpers() -> None:
    assert recycle.split_bin_path("/$Recycle.Bin/S-1-5-21-1-2-3-1001/$IAB12.txt") == (
        "S-1-5-21-1-2-3-1001",
        "$IAB12.txt",
    )
    assert recycle.split_bin_path("/$Recycle.Bin/S-1-5-21-1/$RAB12.txt") is None
    assert recycle.r_name_for("$IAB12.txt") == "$RAB12.txt"
    assert recycle.is_sid("S-1-5-18") and not recycle.is_sid("Administrator")


# -- LNK -------------------------------------------------------------------------------------


def test_lnk_round_trip() -> None:
    data = lnk.build(
        "C:\\Users\\Test\\report.txt",
        created=T,
        accessed=T + 5,
        modified=T + 10**7,
        size=99,
        serial=0xDEADBEEF,
        label="DATA",
        relative_path="..\\report.txt",
    )
    info = lnk.parse(data)
    assert info.target_path == "C:\\Users\\Test\\report.txt"
    assert info.volume_serial == "DEADBEEF"
    assert info.volume_label == "DATA"
    assert info.drive_type == "fixed"
    assert info.target_size == 99
    assert info.relative_path == "..\\report.txt"
    assert dict(info.times()) == {
        "Creation Time (LNK target)": filetime.to_iso(T),
        "Content Modification Time (LNK target)": filetime.to_iso(T + 10**7),
        "Last Access Time (LNK target)": filetime.to_iso(T + 5),
    }


def test_lnk_rejects_other_files() -> None:
    with pytest.raises(lnk.LnkError):
        lnk.parse(b"\x4c\0\0\0" + b"\0" * 80)
    with pytest.raises(lnk.LnkError):
        lnk.parse(b"short")


# -- $SDS ------------------------------------------------------------------------------------


def test_sds_owner_by_security_id_and_mirror_skipped() -> None:
    a = sds.build_entry(256, "S-1-5-18", "S-1-5-32-544", 0)
    b_off = (len(a) + 15) & ~15
    b = sds.build_entry(257, "S-1-5-21-1-2-3-1001", "S-1-5-21-1-2-3-513", b_off)
    block = (a.ljust(b_off, b"\0") + b).ljust(sds.BLOCK, b"\0")
    mirror = sds.build_entry(256, "S-1-1-0", "S-1-1-0", 0).ljust(sds.BLOCK, b"\0")
    table = sds.parse(block + mirror)
    assert {k: v.owner_sid for k, v in table.items()} == {
        256: "S-1-5-18",
        257: "S-1-5-21-1-2-3-1001",
    }
    assert table[257].group_sid == "S-1-5-21-1-2-3-513"


def test_sid_text_round_trip() -> None:
    for sid in ("S-1-5-18", "S-1-5-21-3623811015-3361044348-30300820-1013", "S-1-1-0"):
        assert sds.sid_to_str(sds.sid_to_bytes(sid), 0) == sid
    with pytest.raises(sds.SdsError):
        sds.sid_to_str(b"\x02\x01" + b"\0" * 10, 0)


# -- Bodyfile ----------------------------------------------------------------------------------


def test_bodyfile_markers_and_pipes() -> None:
    e = bodyfile.parse_line("0|/a|b.txt ($FILE_NAME) (deleted)|68-48-3|-/rrwx|0|0|5|1|2|3|4", 7)
    assert (e.name, e.deleted, e.realloc, e.file_name_attr) == ("/a|b.txt", True, False, True)
    assert (e.entry, e.attr_type, e.size, e.crtime, e.line_no) == (68, 48, 5, 4, 7)
    r = bodyfile.parse_line("0|/x (deleted-realloc)|70-128-2|r/rrwx|0|0|None|0|0|0|0")
    assert r.realloc and r.allocated and r.size == 0
    with pytest.raises(bodyfile.BodyfileError):
        bodyfile.parse_line("not|a|bodyfile")


# -- Tool CSV and Dissect JSON -----------------------------------------------------------------


def test_ezcsv_lookups(tmp_path: Path) -> None:
    p = tmp_path / "x.csv"
    p.write_text(
        "\ufeffEntryNumber,InUse,Created0x10,ParentPath\n7,True,2024-01-02 03:04:05.1234567,"
        ".\\Users\\x\n",
        encoding="utf-8",
    )
    ((n, row),) = list(ezcsv.read_rows(p))
    assert n == 2
    assert ezcsv.get_int(row, "entrynumber") == 7
    assert ezcsv.get_bool(row, "InUse") is True
    assert ezcsv.get_time(row, "Created0x10") == "2024-01-02T03:04:05.1234567Z"
    assert ezcsv.windows_to_posix(ezcsv.get(row, "ParentPath")) == "/Users/x"
    assert ezcsv.windows_to_posix("C:\\") == "/"


@pytest.mark.parametrize(
    ("raw", "want"),
    [
        ("\\\\Docs\\gone.txt\\", ("", "/Docs/gone.txt")),
        ("fs1\\file2.txt", ("fs1", "/file2.txt")),
        ("c:\\$Recycle.Bin\\S-1-5-18\\$I1.txt", ("c:", "/$Recycle.Bin/S-1-5-18/$I1.txt")),
        ("\\\\.", ("", "/")),
    ],
)
def test_dissect_paths(raw: str, want: tuple[str, str]) -> None:
    assert dissect_json.split_path(raw) == want


def test_dissect_records_skip_descriptors(tmp_path: Path) -> None:
    p = tmp_path / "d.jsonl"
    p.write_text(
        '{"_type": "recorddescriptor", "_data": []}\nnot json\n'
        '{"segment": 1, "_recorddescriptor": ["filesystem/ntfs/mft/std/compact", 1]}\n'
    )
    assert [(n, t) for n, t, _r in dissect_json.iter_records(p)] == [
        (3, "filesystem/ntfs/mft/std/compact")
    ]


def test_filetime_helpers() -> None:
    assert filetime.to_iso(0) is None
    assert filetime.to_iso(filetime.UNIX_EPOCH_TICKS) == "1970-01-01T00:00:00.0000000Z"
    assert filetime.normalise_iso("1601-01-01T00:00:00+00:00") is None
    assert filetime.normalise_iso("2024-02-30 00:00:00") is None
    assert filetime.iso_from_unix(86400) == "1970-01-02T00:00:00Z"
