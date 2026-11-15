"""forensic-escalate: halt, freeze, record only path, finding ID, hash (4B.18, 4G.12)."""

from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
import time
from pathlib import Path

import pytest

from airlock_ai import escalate

FAKE_ANALYZER = """
import subprocess, sys, time
child = subprocess.Popen(["sleep", "300"])
open(sys.argv[1], "w").write(str(child.pid))
while True:
    time.sleep(0.1)
"""


def _run_dir(root: Path) -> Path:
    run = root / "output" / "cases" / "CASE-1" / "R-20261115T000000Z-abcdef"
    for sub in ("modules/images/export", "modules/video/export/.pending", "extract/v0"):
        (run / sub).mkdir(parents=True, exist_ok=True)
    (run / "modules/images/export/v0_68-128-2.jpg").write_bytes(b"x")
    (run / "extract/v0/$MFT").write_bytes(b"y")
    row = {
        "finding_id": "F-000042",
        "path": "/Users/a/pic.jpg",
        "sha256": "b" * 64,
        "category": "images",
    }
    (run / "findings.jsonl").write_text(json.dumps(row) + "\n", encoding="utf-8")
    (run / "run.json").write_text(
        json.dumps({"run_id": run.name, "status": "running"}), encoding="utf-8"
    )
    return run


def _start_analyzer(tmp: Path, run: Path) -> tuple[subprocess.Popen, int]:
    script = tmp / "forensic-analyze"
    script.write_text(FAKE_ANALYZER, encoding="utf-8")
    child_pid_file = tmp / "child.pid"
    proc = subprocess.Popen([sys.executable, str(script), str(child_pid_file)])
    for _ in range(100):
        if child_pid_file.exists() and child_pid_file.read_text():
            break
        time.sleep(0.05)
    (run / escalate.PID_FILE).write_text(str(proc.pid), encoding="ascii")
    return proc, int(child_pid_file.read_text())


def _alive(pid: int) -> bool:
    try:
        st = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[-1].split()[0]
    except OSError:
        return False
    return st not in {"Z", "X"}


def test_escalate_halts_freezes_and_records(airlock_env: Path, tmp_path: Path):
    run = _run_dir(airlock_env)
    proc, child = _start_analyzer(tmp_path, run)
    assert escalate.running_runs() == [run]
    esc = escalate.escalate(run, finding_id="F-000042", grace_s=2)
    proc.wait(timeout=10)
    assert not _alive(proc.pid) and not _alive(child)
    assert esc.process_found and proc.pid in esc.stopped_pids
    # Recorded: only path, finding ID, and hash (from the findings row, not the file).
    assert (esc.finding_id, esc.path, esc.sha256) == ("F-000042", "/Users/a/pic.jpg", "b" * 64)
    marker = json.loads((run / escalate.MARKER).read_text(encoding="utf-8"))
    assert set(marker) == {"utc", "finding_id", "path", "sha256"}
    assert escalate.is_escalated(run)
    rec = json.loads((run / escalate.RECORD).read_text(encoding="utf-8"))
    assert rec["sha256"] == "b" * 64
    doc = json.loads((run / "run.json").read_text(encoding="utf-8"))
    assert doc["status"] == "escalated"
    # Exports frozen: no write bits anywhere under the export folders.
    assert sorted(esc.frozen_dirs) == ["extract", "modules/images/export", "modules/video/export"]
    for d in esc.frozen_dirs:
        for dirpath, dirs, files in os.walk(run / d):
            for name in [*dirs, *files, "."]:
                mode = (Path(dirpath) / name).stat().st_mode
                assert not mode & (stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH), (dirpath, name)
    log = (airlock_env / "session" / "current.log").read_text(encoding="utf-8")
    assert '"event":"escalated"' in log and "F-000042" in log


def test_escalate_never_reads_the_file(airlock_env: Path, monkeypatch: pytest.MonkeyPatch):
    run = _run_dir(airlock_env)
    opened: list[str] = []
    real_open = open

    def watch(path, *a, **kw):  # every open() made by escalate goes through here
        opened.append(str(path))
        return real_open(path, *a, **kw)

    monkeypatch.setattr("builtins.open", watch)
    escalate.escalate(run, path="/Users/a/pic.jpg", grace_s=0.1)
    assert not any(p.endswith("pic.jpg") or "/export/" in p for p in opened), opened


def test_pid_reuse_guard(airlock_env: Path, tmp_path: Path):
    """A pid file naming some other process is never signalled."""
    run = _run_dir(airlock_env)
    other = subprocess.Popen(["sleep", "30"])
    try:
        (run / escalate.PID_FILE).write_text(str(other.pid), encoding="ascii")
        esc = escalate.escalate(run, finding_id="F-000042", grace_s=0.1)
        assert not esc.process_found
        assert other.poll() is None
        assert escalate.is_escalated(run)
    finally:
        other.kill()
        other.wait()


def test_cli(airlock_env: Path, capsys: pytest.CaptureFixture[str]):
    run = _run_dir(airlock_env)
    assert escalate.main(["--run", str(run), "--sha256", "zz", "--yes"]) == 2
    rc = escalate.main(["--run", str(run), "--finding", "F-000042", "--yes", "--grace", "0"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "tips.fbi.gov" in out and "ICAC" in out and "national police" in out
    assert "b" * 64 in out
    assert "write blocker" not in out.lower()
    # No run found and no --run: the escalation is still recorded in the session log.
    assert escalate.main(["--yes", "--path", "/x"]) == 0


def test_runbook_states_the_rules():
    """4B.14: the media-screening runbook carries the stop-and-report rule and the wording."""
    repo = Path(__file__).resolve().parents[2]
    text = (repo / "docs" / "workflows" / "media-screening.md").read_text(encoding="utf-8")
    for needed in (
        "forensic-escalate",
        "tips.fbi.gov",
        "ICAC",
        "national police",
        "not flagged by this model at this threshold",
        "does **not** estimate age",
        "What a threshold means",
        "What a flag does and does not prove",
    ):
        assert needed in text, needed
    assert "write blocker" not in text.lower()
    assert 'safe"' not in text.replace('never "safe"', "")
