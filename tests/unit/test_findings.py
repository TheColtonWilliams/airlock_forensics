"""Tests for forensic_analyze.findings: schema, validator, writer, merge (4D.1-4D.4, 4G.1)."""

from __future__ import annotations

import datetime as dt
import json
from pathlib import Path

import pytest
from test_findings_support import (
    EVIDENCE_ID,
    EVIDENCE_SHA256,
    MODEL_SHA,
    PROMPT_SHA,
    RUN_ID,
    base_row,
    full_row,
    writer,
)

from forensic_analyze import findings

# ---------------------------------------------------------------------------- schema file


def test_schema_lists_exactly_the_documented_fields() -> None:
    schema = findings.load_schema()
    assert set(schema["properties"]) == set(findings.FIELDS)
    assert len(findings.FIELDS) == len(set(findings.FIELDS))
    assert schema["required"] == list(findings.REQUIRED_FIELDS)
    assert schema["additionalProperties"] is False


def test_schema_uses_only_supported_keywords() -> None:
    assert findings.check_schema_keywords(findings.load_schema()) == []


def test_unsupported_keyword_is_reported() -> None:
    problems = findings.check_schema_keywords({"type": "object", "oneOf": []})
    assert problems and "oneOf" in problems[0]
    assert findings.check_schema_keywords({"format": "email"})


def test_schema_documented_in_docs() -> None:
    doc = (Path(__file__).resolve().parents[2] / "docs" / "schema.md").read_text("utf-8")
    for name in findings.FIELDS:
        assert f"`{name}`" in doc, name


# ---------------------------------------------------------------------------- validator


def test_valid_full_row() -> None:
    assert findings.validate_row(full_row()) == []


def test_every_required_field_is_required() -> None:
    for name in findings.REQUIRED_FIELDS:
        row = full_row()
        del row[name]
        errors = findings.validate_row(row)
        assert errors == [f"missing required field {name!r}"], name


def test_unknown_field_rejected() -> None:
    errors = findings.validate_row(full_row(person_name="x"))
    assert errors == ["unknown field 'person_name'"]


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("category", "browser"),
        ("derivation", "guessed"),
        ("tz_basis", "local"),
        ("xval_status", "maybe"),
        ("finding_id", "F-12"),
        ("finding_id", "G-000001"),
        ("run_id", "R-2026-bad"),
        ("evidence_sha256", "A" * 64),
        ("sha256", "abc"),
        ("md5", "z" * 32),
        ("model_sha256", "a" * 63),
        ("owner_sid", "Administrator"),
        ("owner_sid", "S-1-"),
        ("size_bytes", -1),
        ("size_bytes", 1.5),
        ("size_bytes", True),
        ("size_bytes", "10"),
        ("allocated", 1),
        ("allocated", "false"),
        ("sensitive_flag", 0),
        ("confidence", 1.01),
        ("confidence", -0.1),
        ("score", "0.5"),
        ("score", float("nan")),
        ("threshold", float("inf")),
        ("message", ""),
        ("message", 5),
        ("datetime", "2024-01-01 00:00:00"),
        ("datetime", "2024-01-01T00:00:00+00:00"),
        ("datetime", "2024-02-30T00:00:00Z"),
        ("datetime", "2024-01-01T24:00:00Z"),
        ("datetime", "2024-01-01T00:00:00.1234567890Z"),
        ("path", "a\nb"),
        ("path", "invoice\u202etxt.exe"),
        ("filename", "x\x00y"),
        ("path", "bad\ud800"),
        ("path_b64", "not base64!"),
        ("source_record", "/etc/passwd#1"),
        ("source_record", "../outside.csv#L1"),
        ("source_record", "modules/../../x#1"),
    ],
)
def test_bad_values_rejected(field: str, value: object) -> None:
    errors = findings.validate_row(full_row(**{field: value}))
    assert errors, f"{field}={value!r} was accepted"
    assert errors[0].startswith(field), errors


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("datetime", "2024-01-01T00:00:00Z"),
        ("datetime", "2024-01-01T00:00:00.1234567Z"),
        ("datetime", "2024-02-29T23:59:59.5Z"),
        ("tz_basis", "local_unknown_offset"),
        ("size_bytes", 0),
        ("confidence", 0),
        ("confidence", 1),
        ("score", -3),
        ("score", 0.25),
        ("owner_sid", "S-1-5-18"),
        ("owner_sid", "S-1-5-21-1-2-3-1001"),
        ("finding_id", "F-1234567"),
        ("path", "C:\\Users\\u\\x.txt"),
        ("path", "/Users/u/caf\u00e9 \u65e5\u672c.txt"),
        ("source_record", "modules/inventory/MFTECmd.csv#L12"),
        ("source_record", "modules/recycle_bin/rbcmd.csv"),
        ("text", "line one\nline two"),
        ("message", "Name with \u202e inside is data"),
    ],
)
def test_good_values_accepted(field: str, value: object) -> None:
    assert findings.validate_row(full_row(**{field: value})) == []


def test_ai_rows_need_model_and_prompt_hashes() -> None:
    row = full_row(derivation="ai_generated")
    errors = findings.validate_row(row)
    assert "missing required field 'model_sha256' (required when derivation is ai_generated)" in (
        errors
    )
    assert any("prompt_sha256" in e for e in errors)
    row.update(model_sha256=MODEL_SHA, prompt_sha256=PROMPT_SHA)
    assert findings.validate_row(row) == []
    # Other derivations do not need them.
    assert findings.validate_row(full_row(derivation="inferred")) == []


def test_part_rows_have_no_finding_id() -> None:
    row = full_row()
    assert findings.validate_row(row, part=True)[0].startswith("finding_id: assigned at merge")
    del row["finding_id"]
    assert findings.validate_row(row, part=True) == []
    assert findings.validate_row(row) == ["missing required field 'finding_id'"]


def test_non_object_row() -> None:
    assert findings.validate_row(["x"]) == ["row: expected an object, got list"]


def test_validator_keywords_directly() -> None:
    v = findings.validate_instance
    assert v(3, {"type": "integer", "minimum": 5}) == ["row: 3 is below 5"]
    assert v(9, {"type": "number", "maximum": 5}) == ["row: 9 is above 5"]
    assert v("x", {"const": "y"}) == ["row: must be 'y'"]
    assert v("ab", {"type": "string", "maxLength": 1}) == ["row: longer than 1 characters"]
    assert v("a", {"type": "string", "minLength": 2}) == ["row: shorter than 2 characters"]
    assert v(None, {"type": ["string", "null"]}) == []
    assert v({"a": 1}, {"type": "object", "additionalProperties": {"type": "string"}}) == [
        "a: expected string, got int"
    ]
    cond = {"if": {"properties": {"k": {"const": 1}}}, "then": {"required": ["x"]}}
    assert v({"k": 1}, cond) == ["missing required field 'x' (required when k is 1)"]
    assert v({"k": 2}, cond) == []
    with pytest.raises(ValueError, match="unsupported type"):
        v(1, {"type": "decimal"})


def test_error_messages_escape_evidence_text() -> None:
    errors = findings.validate_row(full_row(category="x\u202e\nmsg"))
    assert "\u202e" not in errors[0] and "\n" not in errors[0]


# ---------------------------------------------------------------------------- writer


def test_writer_fills_run_fields_and_sorts_keys(tmp_path: Path) -> None:
    part = findings.part_path(tmp_path, "inventory")
    with writer(tmp_path, "inventory") as w:
        w.emit(base_row(path="/a.txt", size_bytes=1))
        w.emit(base_row(path="/b.txt"))
        assert w.count == 2
    lines = part.read_bytes().split(b"\n")
    assert lines[-1] == b""
    first = json.loads(lines[0])
    assert first["run_id"] == RUN_ID
    assert first["evidence_id"] == EVIDENCE_ID
    assert first["evidence_sha256"] == EVIDENCE_SHA256
    assert "finding_id" not in first
    assert list(first) == sorted(first)
    assert b", " not in lines[0] and b": " not in lines[0]


def test_writer_rejects_bad_rows_and_writes_nothing_for_them(tmp_path: Path) -> None:
    w = writer(tmp_path, "inventory")
    with pytest.raises(findings.SchemaError) as exc:
        w.emit(base_row(category="nope"))
    assert exc.value.errors and "inventory" in str(exc.value)
    with pytest.raises(findings.SchemaError, match="assigned at merge"):
        w.emit(base_row(finding_id="F-000001"))
    with pytest.raises(findings.SchemaError, match="set by the writer"):
        w.emit(base_row(run_id="R-20990101T000000Z-ffffff"))
    with pytest.raises(findings.SchemaError):
        w.emit("not a dict")  # type: ignore[arg-type]
    w.emit(base_row(run_id=RUN_ID))  # same value is fine
    w.close()
    assert w.closed
    assert len(findings.part_path(tmp_path, "inventory").read_text().splitlines()) == 1
    with pytest.raises(RuntimeError, match="closed"):
        w.emit(base_row())
    w.close()  # idempotent


def test_writer_checks_its_own_run_fields(tmp_path: Path) -> None:
    with pytest.raises(findings.SchemaError, match="run_id"):
        findings.FindingsWriter(
            tmp_path / "p.jsonl",
            run_id="bad",
            evidence_id=EVIDENCE_ID,
            evidence_sha256=EVIDENCE_SHA256,
            module="m",
        )


def test_writer_restarts_part_file(tmp_path: Path) -> None:
    with writer(tmp_path, "inventory") as w:
        w.emit(base_row())
        w.emit(base_row())
    with writer(tmp_path, "inventory") as w:
        w.emit(base_row())
    assert len(findings.part_path(tmp_path, "inventory").read_text().splitlines()) == 1


def test_writer_normalises_paths_and_datetimes(tmp_path: Path) -> None:
    when = dt.datetime(2024, 5, 1, 14, 0, 0, 250000, tzinfo=dt.timezone(dt.timedelta(hours=2)))
    with writer(tmp_path, "inventory") as w:
        w.emit(base_row(path=b"/x/\xffname\n", filename=b"\xffname\n", datetime=when, md5=None))
        w.emit(base_row(path="/plain/ok.txt"))
        with pytest.raises(findings.SchemaError, match="naive"):
            w.emit(base_row(datetime=dt.datetime(2024, 1, 1)))
    rows = [
        json.loads(x) for x in findings.part_path(tmp_path, "inventory").read_text().splitlines()
    ]
    assert rows[0]["path"] == "/x/\\xffname\\n"
    assert rows[0]["filename"] == "\\xffname\\n"
    assert findings.decode_path_b64(rows[0]["path_b64"]) == b"/x/\xffname\n"
    assert rows[0]["datetime"] == "2024-05-01T12:00:00.250000Z"
    assert "md5" not in rows[0]
    assert "path_b64" not in rows[1]


# ---------------------------------------------------------------------------- merge


def test_merge_orders_by_module_and_assigns_ids(tmp_path: Path) -> None:
    with writer(tmp_path, "malware") as w:
        w.emit(base_row(category="malware", message="m1"))
    with writer(tmp_path, "inventory") as w:
        w.emit(base_row(message="i1"))
        w.emit(base_row(message="i2"))
    res = findings.merge(tmp_path, ["inventory", "recycle_bin", "malware"])
    rows = list(findings.iter_findings(tmp_path))
    assert [r["message"] for r in rows] == ["i1", "i2", "m1"]
    assert [r["finding_id"] for r in rows] == ["F-000001", "F-000002", "F-000003"]
    assert res.count == 3
    assert res.per_module == {"inventory": 2, "malware": 1}
    assert res.sha256 == findings.file_sha256(res.path)
    assert res.to_dict()["path"] == "findings.jsonl"
    for r in rows:
        assert findings.validate_row(r) == []
    assert findings.merge_parts(tmp_path, ["inventory"]) == tmp_path / "findings.jsonl"
    assert len(list(findings.iter_findings(tmp_path))) == 2
    assert not list(tmp_path.glob(".findings.jsonl.*"))


def test_merge_accepts_module_objects(tmp_path: Path) -> None:
    class M:
        def __init__(self, name: str) -> None:
            self.name = name

    with writer(tmp_path, "users") as w:
        w.emit(base_row(category="users"))
    assert findings.merge(tmp_path, [M("inventory"), M("users")]).count == 1


def test_merge_with_no_parts_writes_empty_file(tmp_path: Path) -> None:
    res = findings.merge(tmp_path, ["inventory"])
    assert res.path.read_bytes() == b""
    assert res.count == 0


def test_merge_rejects_duplicate_modules(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="twice"):
        findings.merge(tmp_path, ["inventory", "inventory"])


@pytest.mark.parametrize(
    ("content", "match"),
    [
        (b'{"a":1}', "no line end"),
        (b"\n", "empty line"),
        (b"[1]\n", "not a JSON object"),
        (b"{bad\n", "not valid JSON"),
        (b"\xff\n", "not valid JSON"),
    ],
)
def test_merge_rejects_damaged_part_files(tmp_path: Path, content: bytes, match: str) -> None:
    part = findings.part_path(tmp_path, "inventory")
    part.parent.mkdir(parents=True)
    part.write_bytes(content)
    with pytest.raises(findings.SchemaError, match=match):
        findings.merge(tmp_path, ["inventory"])
    assert not (tmp_path / "findings.jsonl").exists()
    assert not list(tmp_path.glob(".findings.jsonl.*"))


def test_merge_revalidates_rows(tmp_path: Path) -> None:
    part = findings.part_path(tmp_path, "inventory")
    part.parent.mkdir(parents=True)
    row = full_row()
    del row["finding_id"]
    row["category"] = "made_up"
    part.write_text(json.dumps(row) + "\n")
    with pytest.raises(findings.SchemaError, match=r"findings\.part\.jsonl:1"):
        findings.merge(tmp_path, ["inventory"])


# ---------------------------------------------------------------------------- command line


def test_cli_validate_merge_compare(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    with writer(tmp_path, "inventory") as w:
        w.emit(base_row())
    part = str(findings.part_path(tmp_path, "inventory"))
    assert findings.main(["validate", part, "--part"]) == 0
    assert findings.main(["validate", part]) == 1
    assert "finding_id" in capsys.readouterr().err
    assert findings.main(["merge", str(tmp_path), "inventory"]) == 0
    out = capsys.readouterr().out
    assert json.loads(out)["count"] == 1
    f = str(tmp_path / "findings.jsonl")
    assert findings.main(["compare", f, f]) == 0
    assert findings.main([]) == 2
    assert findings.main(["compare", f]) == 2
    assert findings.main(["validate", str(tmp_path / "missing.jsonl")]) == 1
    assert "cannot read" in capsys.readouterr().err
