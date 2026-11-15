"""ModuleContext plumbing: tool records, redaction, versions, findings writer (contract 8, 8a)."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from airlock_common import proc
from forensic_analyze import context
from forensic_analyze import sandbox as sb
from forensic_analyze.api import Target, Volume

SHA = "a" * 64


def _recorder(tmp_path: Path) -> context.ToolRecorder:
    return context.ToolRecorder(sb.Sandbox(method="none"), tmp_path / "logs" / "run.jsonl")


def test_tool_records_command_version_hash_and_redacts(tmp_path: Path) -> None:
    rec = _recorder(tmp_path)
    wd = tmp_path / "w"
    echo = shutil.which("echo")
    assert echo
    cp = rec.run("m", [echo, "hello", "SECRET-KEY"], workdir=wd, redact=["SECRET-KEY"])
    assert cp.returncode == 0 and "hello" in cp.stdout
    r = rec.records[-1]
    assert r["argv"][-1] == "<redacted>" and "SECRET-KEY" not in r["command_line"]
    assert len(r["binary_sha256"]) == 64 and r["version"]
    assert r["sandbox"]["method"] == "none"
    assert "SECRET-KEY" not in (tmp_path / "logs" / "run.jsonl").read_text()
    out = tmp_path / "out.txt"
    rec.run("m", [echo, "to-file"], workdir=wd, stdout_path=out, sandbox=False)
    assert out.read_text().strip() == "to-file"
    assert rec.records[-1]["sandbox"] == {"method": "unsandboxed"}
    versions = rec.versions()
    assert any(v["sha256"] for v in versions.values())


def test_missing_tool_is_recorded_and_raises(tmp_path: Path) -> None:
    rec = _recorder(tmp_path)
    with pytest.raises(proc.ToolError, match="not installed"):
        rec.run("m", ["no-such-tool-airlock"], workdir=tmp_path)
    assert rec.records[-1]["error"] == "not installed"
    assert rec.version("no-such-tool-airlock") == "not installed"


def test_time_limit_becomes_tool_error(tmp_path: Path) -> None:
    rec = _recorder(tmp_path)
    sleep = shutil.which("sleep")
    assert sleep
    with pytest.raises(proc.ToolError, match="limit"):
        rec.run("m", [sleep, "10"], workdir=tmp_path, timeout=1)
    assert rec.records[-1]["returncode"] == -9


def test_build_context_emits_through_the_writer(tmp_path: Path, airlock_env: Path) -> None:
    target = Target(Path("/x.img"), "image", "EX-1", sha256=SHA, volumes=(Volume(0, 0, 1, "ntfs"),))
    handles = context.build_context(
        run_id="R-20261115T000000Z-abcdef",
        module="inventory",
        target=target,
        run_dir=tmp_path,
        options={"preset": "quick"},
        recorder=_recorder(tmp_path),
        shared={},
        evidence_sha256=SHA,
        run_log=tmp_path / "logs" / "run.jsonl",
    )
    ctx = handles.ctx
    assert ctx.workdir == tmp_path / "modules" / "inventory" and ctx.workdir.is_dir()
    ctx.emit(
        {
            "category": "inventory",
            "artifact_type": "file_entry",
            "message": "m",
            "derivation": "observed",
            "source_tool": "t",
            "tool_version": "1",
            "parser": "p",
        }
    )
    ctx.log("note", detail="x")
    handles.writer.close()
    row = json.loads((ctx.workdir / "findings.part.jsonl").read_text())
    assert row["evidence_sha256"] == SHA and row["evidence_id"] == "EX-1"
    assert handles.log_events[0]["event"] == "note"


def test_fallback_writer(tmp_path: Path) -> None:
    w = context._FallbackWriter(
        tmp_path / "p.jsonl", run_id="R", evidence_id="E", evidence_sha256=SHA, module="m"
    )
    w.emit({"b": 1, "a": 2})
    w.close()
    line = (tmp_path / "p.jsonl").read_text()
    assert line.startswith('{"a":2,"b":1,"evidence_id":"E"') and w.count == 1
