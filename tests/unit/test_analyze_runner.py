"""Runner and CLI without root: an image-file target, the "none" sandbox, test modules.

Tasks 4C.1, 4C.17, 4C.18, 4C.20, 4C.22, 4C.25, 4C.26, 2B.17, 4G.1. The same flow against a
real read-only loop device runs in tests/functional/test_analyze_quick.sh.
"""

from __future__ import annotations

import errno
import json
import os
import shutil
import stat
from pathlib import Path
from typing import Any

import pytest

from forensic_analyze import cli, fsdetect, runner, signing
from forensic_analyze import modules as modules_pkg
from forensic_analyze import sandbox as sb
from forensic_analyze.api import Volume

needs_openssl = pytest.mark.skipif(shutil.which("openssl") is None, reason="needs openssl")

MODULES = """
import os
from forensic_analyze.api import Module, ModuleResult

class Rows(Module):
    name = "inventory"
    title = "Rows"
    fs_types = frozenset({"ntfs"})
    order = 10
    def run(self, ctx):
        for i in range(3):
            ctx.emit({
                "category": "inventory", "artifact_type": "file_entry", "message": f"entry {i}",
                "derivation": "observed", "source_tool": "test", "tool_version": "1",
                "parser": "test", "path": f"/f{i}.txt",
            })
        (ctx.workdir / "export").mkdir(exist_ok=True)
        (ctx.workdir / "export" / "copy.bin").write_bytes(b"copy")
        ctx.log("model_used", model_id="none", model_sha256="0" * 64)
        return ModuleResult("ok", counts={"entries": 3})

class Boom(Module):
    name = "recycle_bin"
    title = "Boom"
    order = 20
    def run(self, ctx):
        if os.environ.get("TEST_BOOM") == "interrupt":
            raise KeyboardInterrupt
        if os.environ.get("TEST_BOOM") == "full":
            raise OSError(28, "No space left on device")
        if os.environ.get("TEST_BOOM") == "escalate":
            assert (ctx.run_dir / "forensic-analyze.pid").read_text().strip() == str(os.getpid())
            (ctx.run_dir / "ESCALATED").write_text("{}")
            return ModuleResult("ok")
        if os.environ.get("TEST_BOOM"):
            raise RuntimeError("parser crashed")
        return ModuleResult("ok")

class Later(Module):
    name = "deletion_history"
    title = "Later"
    order = 30
    def run(self, ctx):
        counter = ctx.run_dir.parent / "later.count"
        counter.write_text(str(int(counter.read_text()) + 1 if counter.exists() else 1))
        return ModuleResult("ok")
"""


@pytest.fixture
def env(airlock_env: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    mods = airlock_env / "mods"
    mods.mkdir()
    files = []
    for cls in ("Rows", "Boom", "Later"):
        f = mods / f"m_{cls.lower()}.py"
        f.write_text(MODULES + f"\nMODULE = {cls}()\n")
        files.append(str(f))
    monkeypatch.setenv("AIRLOCK_EXTRA_MODULES", ":".join(files))
    # Only the test modules: hide the real modules so these tests do not need TSK.
    monkeypatch.setattr(modules_pkg, "__path__", [])
    monkeypatch.delenv("TEST_BOOM", raising=False)
    img = airlock_env / "evidence.img"
    img.write_bytes(b"\x11" * 65536)
    fs = {"type": "ntfs"}

    def fake_open(source: str, *, raw: bool, sandbox: Any = None) -> sb.EvidenceHandle:
        return sb.EvidenceHandle(source, source, "path", "test")

    def fake_detect(path: Any, **kw: Any) -> list[Volume]:
        return [Volume(0, 0, 65536, fs["type"], "EVID")]

    monkeypatch.setattr(sb, "open_evidence", fake_open)
    monkeypatch.setattr(fsdetect, "detect", fake_detect)
    monkeypatch.setattr(runner.shutil, "which", lambda name: None)  # no evidence-report
    return {"root": airlock_env, "img": img, "fs": fs, "out": airlock_env / "output"}


def _args(env: dict[str, Any], *extra: str) -> list[str]:
    return [
        "--authority-ack",
        "--target",
        str(env["img"]),
        "--output",
        str(env["out"]),
        "--examiner",
        "Unit Examiner",
        "--case-id",
        "U-1",
        "--preset",
        "quick",
        "--sandbox",
        "none",
        "--yes",
        *extra,
    ]


def _runs(env: dict[str, Any], case_id: str = "U-1") -> list[Path]:
    return sorted((env["out"] / "cases" / case_id).glob("R-*"))


@needs_openssl
def test_full_run_via_cli(env: dict[str, Any], capsys: pytest.CaptureFixture[str]) -> None:
    rc = cli.main(
        _args(
            env,
            "--reference-time",
            "2026-11-15T00:00:00Z",
            "--write-blocker",
            "yes",
            "--blocker-make",
            "Make",
            "--blocker-report-url",
            "https://example.org/r",
        )
    )
    out = capsys.readouterr().out
    assert rc == 0, out
    assert "Read-directly mode" in out
    (rd,) = _runs(env)
    doc = json.loads((rd / "run.json").read_text())
    assert doc["status"] == "complete"
    assert doc["config"]["preset"] == "quick" and doc["config"]["target"] == str(env["img"])
    assert doc["hashes"]["before"]["sha256"] == doc["hashes"]["after"]["sha256"]
    assert doc["write_requests"]["analysis_copy"]["method"] == "not_applicable"
    assert doc["write_requests_total"] is None  # an image file is checked by hash instead
    assert doc["write_blocker"]["in_use"] == "yes" and doc["write_blocker"]["make"] == "Make"
    assert doc["authority_ack"]["acknowledged"] is True
    assert doc["clock"]["clock_offset_seconds"] is not None
    assert [m["name"] for m in doc["modules"]][:3] == [
        "inventory",
        "recycle_bin",
        "deletion_history",
    ]
    assert doc["modules"][3]["status"] == "not_available"  # malware not on this build
    assert doc["summary"]["modules"][0]["status"] == "not_available"  # skipped/failed first
    assert doc["summary"]["findings_total"] == 3
    assert doc["models"] and doc["models"][0]["model_id"] == "none"
    rows = [json.loads(x) for x in (rd / "findings.jsonl").read_text().splitlines()]
    assert [r["finding_id"] for r in rows] == ["F-000001", "F-000002", "F-000003"]
    assert all(r["evidence_sha256"] == doc["hashes"]["before"]["sha256"] for r in rows)
    assert (rd / "modules" / "inventory" / ".done").exists()
    assert signing.verify(rd) == []
    assert doc["signing"]["public_key_sha256"]
    assert not list((env["out"] / "cases" / "U-1").glob(".*.lock"))


@needs_openssl
def test_module_failure_is_shown_and_run_continues(
    env: dict[str, Any], monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("TEST_BOOM", "1")
    rc = cli.main(_args(env))
    out = capsys.readouterr().out
    assert rc == 0
    assert "Module recycle_bin failed: RuntimeError: parser crashed. The run continues." in out
    (rd,) = _runs(env)
    doc = json.loads((rd / "run.json").read_text())
    status = {m["name"]: m["status"] for m in doc["modules"]}
    assert status == {
        "inventory": "ok",
        "recycle_bin": "failed",
        "deletion_history": "ok",
        "malware": "not_available",
    }
    assert doc["summary"]["failed"] == ["recycle_bin"]
    assert doc["summary"]["modules"][0]["name"] == "recycle_bin"
    assert not (rd / "modules" / "recycle_bin" / ".done").exists()
    assert any(e["where"] == "recycle_bin" for e in doc["errors"])


@needs_openssl
def test_ntfs_module_skipped_on_exfat(env: dict[str, Any]) -> None:
    env["fs"]["type"] = "exfat"
    assert cli.main(_args(env)) == 0
    (rd,) = _runs(env)
    doc = json.loads((rd / "run.json").read_text())
    inv = next(m for m in doc["modules"] if m["name"] == "inventory")
    assert inv["status"] == "skipped" and "needs a ntfs volume; found: exfat" in inv["reason"]


@needs_openssl
def test_interrupted_run_resumes_without_rerunning_done_modules(
    env: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("TEST_BOOM", "interrupt")
    assert cli.main(_args(env)) == 130
    (rd,) = _runs(env)
    doc = json.loads((rd / "run.json").read_text())
    assert doc["status"] == "running"
    assert (rd / "modules" / "inventory" / ".done").exists()
    monkeypatch.delenv("TEST_BOOM")
    assert cli.main(["--resume", str(rd), "--sandbox", "none"]) == 0
    doc = json.loads((rd / "run.json").read_text())
    assert doc["status"] == "complete" and len(doc["resumes"]) == 1
    log = (rd / "logs" / "run.jsonl").read_text()
    assert '"event":"module_skipped_done","module":"inventory"' in log
    assert (rd.parent / "later.count").read_text() == "1"
    assert signing.verify(rd) == []
    assert cli.main(["--resume", str(rd)]) == 1  # already complete


def test_escalate_marker_stops_the_run_and_blocks_resume(
    env: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("TEST_BOOM", "escalate")
    assert cli.main(_args(env)) == 1
    (rd,) = _runs(env)
    doc = json.loads((rd / "run.json").read_text())
    assert doc["status"] == "escalated"
    assert not (rd / "findings.jsonl").exists()  # no merge, export or signing after the marker
    assert not (rd / "outputs.sha256").exists()
    assert not (rd / "modules" / "deletion_history" / ".done").exists()  # next module never ran
    assert not (rd / "forensic-analyze.pid").exists()
    monkeypatch.delenv("TEST_BOOM")
    assert cli.main(["--resume", str(rd), "--sandbox", "none"]) == 1


@needs_openssl
def test_output_full_stops_with_resume_hint(
    env: dict[str, Any], monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("TEST_BOOM", "full")
    assert cli.main(_args(env)) == 1
    out = capsys.readouterr().out
    assert "output drive is full" in out and "--resume" in out
    (rd,) = _runs(env)
    assert json.loads((rd / "run.json").read_text())["status"] == "incomplete"
    assert errno.ENOSPC == 28


@needs_openssl
def test_config_replay_and_purge(env: dict[str, Any]) -> None:
    assert cli.main(_args(env, "--purge-exports")) == 0
    (rd,) = _runs(env)
    assert not (rd / "modules" / "inventory" / "export").exists()
    doc = json.loads((rd / "run.json").read_text())
    assert doc["purge"]["removed_files"] == 1
    assert signing.verify(rd) == []
    rc = cli.main(["--config", str(rd / "run.json"), "--authority-ack", "--yes"])
    assert rc == 0
    rd1, rd2 = sorted(_runs(env), key=lambda p: p.stat().st_mtime)
    d1 = json.loads((rd1 / "run.json").read_text())
    d2 = json.loads((rd2 / "run.json").read_text())
    assert d1["config"] == d2["config"]
    assert d1["plan"]["planned"] == d2["plan"]["planned"]


@needs_openssl
def test_report_command_is_called(env: dict[str, Any], monkeypatch: pytest.MonkeyPatch) -> None:
    bindir = env["root"] / "bin"
    bindir.mkdir()
    rep = bindir / "evidence-report"
    rep.write_text('#!/bin/sh\necho "<html>report</html>" > "$1/report.html"\n')
    rep.chmod(rep.stat().st_mode | stat.S_IXUSR)
    monkeypatch.setattr(
        runner.shutil, "which", lambda name: str(rep) if name == "evidence-report" else None
    )
    assert cli.main(_args(env)) == 0
    (rd,) = _runs(env)
    doc = json.loads((rd / "run.json").read_text())
    assert doc["report"]["status"] == "ok"
    assert "report.html" in (rd / "outputs.sha256").read_text()


def test_cli_needs_flags_when_not_interactive(
    env: dict[str, Any], capsys: pytest.CaptureFixture[str]
) -> None:
    assert cli.main(["--target", str(env["img"]), "--yes"]) == 2
    assert "--authority-ack" in capsys.readouterr().out
    assert cli.main(["--authority-ack", "--yes", "--examiner", "x"]) == 2
    assert "--target" in capsys.readouterr().out
    args = [a for a in _args(env) if a != "--yes"]
    assert cli.main(args) == 2
    assert "pass --yes with --target" in capsys.readouterr().out
    assert cli.main([*_args(env), "--reference-time", "2026-11-15 10:00"]) == 2
    assert cli.main([*_args(env), "--preset", "custom"]) == 2


def test_dry_run_writes_nothing(env: dict[str, Any], capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main([*_args(env), "--dry-run"]) == 0
    plan = json.loads(capsys.readouterr().out.split("\n", 1)[1])
    assert [m["name"] for m in plan["modules"]] == ["inventory", "recycle_bin", "deletion_history"]
    assert plan["not_available"] == ["malware"]
    assert not (env["out"] / "cases").exists()


def test_every_prompt_has_a_flag() -> None:
    parser = cli.build_parser()
    flags = {o for a in parser._actions for o in a.option_strings}
    for needed in (
        "--target",
        "--mode",
        "--output",
        "--preset",
        "--modules",
        "--case-id",
        "--exhibit-id",
        "--examiner",
        "--authority-ref",
        "--notes",
        "--authority-ack",
        "--write-blocker",
        "--blocker-make",
        "--blocker-model",
        "--blocker-firmware",
        "--blocker-report-url",
        "--reference-time",
        "--reference-source",
        "--bitlocker-key-file",
        "--purge-exports",
        "--yes",
        "--config",
        "--resume",
        "--dry-run",
        "--imager",
        "--images-dir",
    ):
        assert needed in flags, needed


def test_wrapper_script_is_the_contract_pattern() -> None:
    wrapper = Path(cli.__file__).parents[2] / "bin" / "forensic-analyze"
    text = wrapper.read_text()
    assert text.startswith("#!/usr/bin/python3\n")
    assert 'os.environ.get("AIRLOCK_PYLIB", "/opt/airlock/lib/python")' in text
    assert "from forensic_analyze.cli import main" in text
    assert os.access(wrapper, os.X_OK)


@needs_openssl
def test_bitlocker_unlock_feeds_the_modules(
    env: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    def detect(path: Any, **kw: Any) -> list[Volume]:
        if str(path).endswith("decrypted.raw"):
            return [Volume(0, 0, 65536, "ntfs", "DECRYPTED")]
        return [Volume(0, 0, 65536, "bitlocker", "", bitlocker=True)]

    def unlock(path: str, key: Path | None, out_dir: Path, *, tool: Any) -> Any:
        assert key is not None and key.read_text().startswith("111111")
        out_dir.mkdir(parents=True, exist_ok=True)
        img = out_dir / "decrypted.raw"
        img.write_bytes(b"plain")
        img.chmod(0o444)
        return fsdetect.UnlockResult(img, ["fve-dd", "-r", "<redacted>", "-o", str(img), path])

    monkeypatch.setattr(fsdetect, "detect", detect)
    monkeypatch.setattr(fsdetect, "unlock", unlock)
    key = env["root"] / "key.txt"
    key.write_text("111111-222222-333333-444444-555555-666666-777777-888888\n")
    assert cli.main(_args(env, "--bitlocker-key-file", str(key))) == 0
    (rd,) = _runs(env)
    doc = json.loads((rd / "run.json").read_text())
    assert doc["bitlocker"]["unlocked"] is True
    assert doc["volumes"][0]["label"] == "DECRYPTED"
    assert any("decrypted working copy" in d for d in doc["deviations"])
    assert "111111" not in (rd / "run.json").read_text()
    inv = next(m for m in doc["modules"] if m["name"] == "inventory")
    assert inv["status"] == "ok"


def test_bitlocker_without_key_stops(env: dict[str, Any], monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        fsdetect, "detect", lambda path, **kw: [Volume(0, 0, 1, "bitlocker", "", bitlocker=True)]
    )
    assert cli.main(_args(env)) == 1
    (rd,) = _runs(env)
    doc = json.loads((rd / "run.json").read_text())
    assert doc["status"] == "stopped" and doc["bitlocker"]["found"] is True
