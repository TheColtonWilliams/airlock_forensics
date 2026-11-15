"""CSV safety tests (4G.13, 4D.6, 4D.7): hostile names must parse cleanly with no live formula."""

from __future__ import annotations

import csv
import io
import re
from pathlib import Path

import pytest
from test_findings_support import HOSTILE_NAMES, base_row, build_run, write_parts

from forensic_analyze import csvsafe, export_csv, findings

FORMULA_CHARS = (*tuple("=+-@"), "\uff1d", "\uff0b", "\uff0d", "\uff20")
NUMBER_RE = re.compile(r"^-?[0-9]+(\.[0-9]+)?(e[+-]?[0-9]+)?$")


def read_csv(path: Path) -> list[list[str]]:
    raw = path.read_bytes()
    assert raw.startswith(b"\xef\xbb\xbf"), "UTF-8 BOM missing"
    text = raw.decode("utf-8-sig")  # strict: fails on any invalid byte or surrogate
    return list(csv.reader(io.StringIO(text, newline=""), strict=True))


def assert_no_live_formula(rows: list[list[str]]) -> None:
    for r, row in enumerate(rows):
        for c, cell in enumerate(row):
            if NUMBER_RE.match(cell):
                continue
            assert not cell.startswith(("\t", "\r")), (r, c, cell)
            assert not cell.lstrip().startswith(FORMULA_CHARS), (r, c, cell)
            assert csvsafe.is_safe_display(cell), (r, c, cell)


# ---------------------------------------------------------------------------- 4G.13


def test_hostile_names_parse_cleanly_with_no_live_formula(tmp_path: Path) -> None:
    rows = []
    for i, name in enumerate(HOSTILE_NAMES):
        path = (b"/h/" + name) if isinstance(name, bytes) else "/h/" + name
        text_name = name if isinstance(name, str) else "raw bytes"
        rows.append(
            base_row(
                path=path,
                filename=name,
                message=text_name,
                text=text_name,
                label=text_name if i % 2 else None,
                hashset_name=text_name if i % 3 == 0 else None,
                inode_ref=f"v0:{i}-1",
            )
        )
    write_parts(tmp_path, {"inventory": rows})
    findings.merge(tmp_path, ["inventory"])
    out = export_csv.build(tmp_path)
    parsed = read_csv(out)

    assert parsed[0] == list(export_csv.COLUMNS)
    assert len(parsed) == len(HOSTILE_NAMES) + 1
    assert all(len(r) == len(export_csv.COLUMNS) for r in parsed)
    # Embedded newlines are escaped, so each record is exactly one physical line.
    assert out.read_bytes().count(b"\r\n") == len(HOSTILE_NAMES) + 1
    assert b"\n" not in out.read_bytes().replace(b"\r\n", b"")
    assert_no_live_formula(parsed)

    col = {name: i for i, name in enumerate(export_csv.COLUMNS)}
    for i, name in enumerate(HOSTILE_NAMES):
        cells = parsed[i + 1]
        raw = (b"/h/" + name) if isinstance(name, bytes) else findings._str_to_raw("/h/" + name)
        if cells[col["path_b64"]]:
            assert findings.decode_path_b64(cells[col["path_b64"]]) == raw
        else:
            assert cells[col["path"]] == raw.decode("utf-8")


@pytest.mark.parametrize(
    ("value", "cell"),
    [
        ("=1+1", "'=1+1"),
        ("+1", "'+1"),
        ("-1", "'-1"),
        ("@A1", "'@A1"),
        ("\t=x", "'\\t=x"),
        ("\rx", "'\\rx"),
        ("  =x", "'  =x"),
        ("\n=x", "'\\n=x"),
        ("\uff1dSUM(1)", "'\uff1dSUM(1)"),
        ("a=b", "a=b"),
        ("x\u202ey", "x\\u202ey"),
        ("a\nb", "a\\nb"),
        ("", ""),
        (None, ""),
        (True, "true"),
        (False, "false"),
        (-1.5, "-1.5"),
        (0.91, "0.91"),
        (42, "42"),
    ],
)
def test_csv_cell(value: object, cell: str) -> None:
    assert csvsafe.csv_cell(value) == cell


def test_csv_cell_refuses_non_finite() -> None:
    with pytest.raises(ValueError, match="non-finite"):
        csvsafe.csv_cell(float("nan"))


def test_escape_char_forms() -> None:
    assert csvsafe.escape_char("\n") == "\\n"
    assert csvsafe.escape_char("\u202e") == "\\u202e"
    assert csvsafe.escape_char("\U000e0001") == "\\U000e0001"
    assert csvsafe.display_escape("plain \\ text") == "plain \\ text"


# ---------------------------------------------------------------------------- 4D.6 layout


def test_csv_columns_start_with_timesketch_fields() -> None:
    assert export_csv.COLUMNS[:3] == ("datetime", "timestamp_desc", "message")
    assert set(export_csv.COLUMNS) == set(findings.FIELDS)
    assert len(export_csv.COLUMNS) == len(findings.FIELDS)


def test_full_export_layout(tmp_path: Path) -> None:
    res = build_run(tmp_path)
    out = export_csv.build(tmp_path)
    assert out == tmp_path / "findings.csv"
    parsed = read_csv(out)
    assert len(parsed) == res.count + 1
    assert_no_live_formula(parsed)
    col = {name: i for i, name in enumerate(export_csv.COLUMNS)}
    by_id = {r[col["finding_id"]]: r for r in parsed[1:]}
    rows = list(findings.iter_findings(tmp_path))
    for row in rows:
        cells = by_id[row["finding_id"]]
        assert cells[col["datetime"]] == row.get("datetime", "")
        if row["derivation"] == "ai_generated":
            assert cells[col["message"]].startswith("AI-generated: ")
        if "allocated" in row:
            assert cells[col["allocated"]] == ("true" if row["allocated"] else "false")
        if "score" in row:
            assert float(cells[col["score"]]) == row["score"]
    assert not list(tmp_path.glob(".findings.csv.*"))


def test_export_csv_refuses_invalid_findings(tmp_path: Path) -> None:
    (tmp_path / "findings.jsonl").write_text('{"message":"x"}\n', encoding="utf-8")
    with pytest.raises(findings.SchemaError):
        export_csv.build(tmp_path)
    assert not (tmp_path / "findings.csv").exists()
    assert export_csv.main([str(tmp_path)]) == 1
    assert export_csv.main([]) == 2
