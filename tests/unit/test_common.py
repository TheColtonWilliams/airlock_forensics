from __future__ import annotations

import json
from pathlib import Path

from airlock_common import hashing, jsonio, sessionlog


def test_session_log_lines_are_sorted_json(airlock_env: Path) -> None:
    path = sessionlog.new_session("forensic-session-start", operator_ack=True)
    sessionlog.log_event("evidence-hash", "hashed", device="/dev/sdb", sha256="ab" * 32)
    lines = path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    for line in lines:
        rec = json.loads(line)
        assert list(rec) == sorted(rec)
        assert rec["ts"].endswith("Z")
    assert json.loads(lines[1])["event"] == "hashed"
    assert (airlock_env / "session" / "current.log").resolve() == path


def test_implicit_session(airlock_env: Path) -> None:
    sessionlog.log_event("evidence-mount", "mounted", image="x.img")
    events = [json.loads(x)["event"] for x in sessionlog.current_path().read_text().splitlines()]
    assert events == ["session_start", "session_implicit", "mounted"]


def test_hash_file(tmp_path: Path) -> None:
    f = tmp_path / "a.bin"
    f.write_bytes(b"abc")
    h = hashing.hash_file(f)
    assert h["sha256"] == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    assert h["md5"] == "900150983cd24fb0d6963f7d28e17f72"


def test_dump_json_sorted(tmp_path: Path) -> None:
    p = tmp_path / "x.json"
    jsonio.dump_json(p, {"b": 1, "a": 2})
    assert p.read_text().startswith('{\n  "a": 2')
