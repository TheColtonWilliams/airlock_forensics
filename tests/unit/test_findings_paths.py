"""Tests for hostile file-name handling: findings.safe_path and normalise_row (4D.7)."""

from __future__ import annotations

import base64

import pytest
from test_findings_support import HOSTILE_NAMES, full_row

from forensic_analyze import findings
from forensic_analyze.csvsafe import is_safe_display


@pytest.mark.parametrize(
    ("raw", "display"),
    [
        ("plain.txt", "plain.txt"),
        ("a\nb", "a\\nb"),
        ("a\rb\tc", "a\\rb\\tc"),
        ("invoice\u202etxt.exe", "invoice\\u202etxt.exe"),
        ("x\u2066y\u2069", "x\\u2066y\\u2069"),
        ("zero\u200bwidth", "zero\\u200bwidth"),
        ("bom\ufeff", "bom\\ufeff"),
        ("nul\x00", "nul\\u0000"),
        ("c1\x85", "c1\\u0085"),
        ("ls\u2028ps\u2029", "ls\\u2028ps\\u2029"),
        ("tag\U000e0041", "tag\\U000e0041"),
        ("bad\ud800", "bad\\ud800"),
        ("caf\u00e9", "caf\u00e9"),
        (b"raw\xff", "raw\\xff"),
        (b"ok-\xc3\xa9", "ok-\u00e9"),
        (b"cut\xc3", "cut\\xc3"),
        (b"\xed\xa0\x80", "\\xed\\xa0\\x80"),
    ],
)
def test_safe_path_display(raw: str | bytes, display: str) -> None:
    shown, b64 = findings.safe_path(raw)
    assert shown == display
    assert is_safe_display(shown)
    shown.encode("utf-8")  # always storable
    if isinstance(raw, bytes):
        assert base64.b64decode(b64) == raw


def test_safe_path_keeps_raw_bytes_of_str_input() -> None:
    # os.fsdecode-style surrogate escapes become the original bytes.
    assert base64.b64decode(findings.safe_path("x\udcff")[1]) == b"x\xff"
    # Unpaired UTF-16 surrogates (NTFS) are kept in generalised UTF-8.
    assert base64.b64decode(findings.safe_path("x\ud800")[1]) == b"x\xed\xa0\x80"
    assert base64.b64decode(findings.safe_path("x\u202e")[1]) == "x\u202e".encode()


@pytest.mark.parametrize("name", HOSTILE_NAMES, ids=range(len(HOSTILE_NAMES)))
def test_every_hostile_name_normalises_to_a_valid_row(name: str | bytes) -> None:
    row = findings.normalise_row(full_row(path=name, filename=name))
    assert findings.validate_row(row) == []
    assert is_safe_display(row["path"])
    if "path_b64" in row:
        raw = name if isinstance(name, bytes) else findings._str_to_raw(name)
        assert findings.decode_path_b64(row["path_b64"]) == raw


def test_backslash_paths_carry_raw_copy() -> None:
    row = findings.normalise_row(full_row(path="C:\\x\\41"))
    assert row["path"] == "C:\\x\\41"
    assert findings.decode_path_b64(row["path_b64"]) == b"C:\\x\\41"


def test_module_supplied_path_b64_is_kept() -> None:
    raw_b64 = base64.b64encode(b"original").decode()
    row = findings.normalise_row(full_row(path=b"\xff", path_b64=raw_b64))
    assert row["path_b64"] == raw_b64


def test_decode_path_b64_ignores_csv_neutraliser() -> None:
    value = base64.b64encode(b"\xfb\xff").decode()
    assert value.startswith("+")
    assert findings.decode_path_b64("'" + value) == b"\xfb\xff"


def test_lone_surrogates_in_other_text_fields_are_escaped() -> None:
    row = findings.normalise_row(full_row(message="Deleted bad\ud800.txt", text="x\udcff\nkeep"))
    assert row["message"] == "Deleted bad\\ud800.txt"
    assert row["text"] == "x\\xff\nkeep"
    assert findings.validate_row(row) == []
    assert findings.escape_surrogates("plain\u202e") == "plain\u202e"


def test_clean_bytes_paths_need_no_raw_copy() -> None:
    row = findings.normalise_row(full_row(path=b"/Users/u/caf\xc3\xa9.txt", filename=b"ok"))
    assert row["path"] == "/Users/u/café.txt"
    assert row["filename"] == "ok"
    assert "path_b64" not in row
