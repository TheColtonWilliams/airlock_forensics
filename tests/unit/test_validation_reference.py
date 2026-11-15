"""validation/reference (task 4F.2): sets.json is well formed; fetch.py verifies by hash."""

from __future__ import annotations

import bz2
import hashlib
import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

import pytest

REPO = Path(__file__).resolve().parents[2]


def _load(name: str, rel: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, REPO / rel)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


fetch = _load("airlock_validation_fetch", "validation/reference/fetch.py")
SETS = REPO / "validation" / "reference" / "sets.json"


def test_committed_sets_are_valid() -> None:
    doc = json.loads(SETS.read_text())
    assert fetch.check_sets(doc) == []
    ids = {s["id"] for s in doc["sets"]}
    publishers = {s["publisher"] for s in doc["sets"]}
    assert {"NIST CFReDS", "Digital Corpora"} <= publishers
    assert any("carving" in s["classes"] for s in doc["sets"])
    assert any("deleted_files" in s["classes"] for s in doc["sets"])
    assert len(ids) == len(doc["sets"])
    for s in doc["sets"]:
        # Never an invented hash: either a real 64-hex value or null with a reason.
        assert s["sha256"] is None or len(s["sha256"]) == 64
        if s["sha256"] is None:
            assert s.get("url_checked")
        assert s["url"].startswith("https://")


def test_check_sets_finds_problems() -> None:
    bad = {
        "schema": 1,
        "sets": [
            {
                "id": "a",
                "url": "http://x/a",
                "image_name": "../a",
                "archive": "rar",
                "classes": ["x"],
                "ground_truth": {"scoring_truth": "/tmp/t.json"},
                "license": "x",
                "sha256": "ABC",
            },
            {"id": "a"},
        ],
    }
    text = "; ".join(fetch.check_sets(bad))
    for part in (
        "duplicate id",
        "url must be https",
        "archive must be",
        "sha256 must be",
        "scoring_truth",
        "image_name must be",
    ):
        assert part in text


def _set(tmp_path: Path, payload: bytes, sha: str | None) -> Path:
    src = tmp_path / "src" / "img.dd.bz2"
    src.parent.mkdir()
    src.write_bytes(bz2.compress(payload))
    doc = {
        "schema": 1,
        "sets": [
            {
                "id": "t1",
                "url": src.as_uri(),
                "image_name": "img.dd",
                "archive": "bz2",
                "classes": ["deleted_files"],
                "ground_truth": {"scoring_truth": "validation/reference/truth/t1.json"},
                "license": "test",
                "sha256": sha,
                "size": None,
                "fs_type": "ntfs",
            }
        ],
    }
    sets = tmp_path / "sets.json"
    sets.write_text(json.dumps(doc))
    return sets


@pytest.fixture(autouse=True)
def _not_on_drive(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AIRLOCK_ETC_DIR", str(tmp_path / "no-etc"))


def test_fetch_verifies_and_unpacks(tmp_path: Path) -> None:
    payload = b"generated image bytes" * 100
    sha = hashlib.sha256(bz2.compress(payload)).hexdigest()
    sets = _set(tmp_path, payload, sha)
    out = tmp_path / "out"
    assert fetch.main(["--sets", str(sets), "--out", str(out)]) == 0
    fetched = json.loads((out / "fetched.json").read_text())
    assert [s["id"] for s in fetched["sets"]] == ["t1"]
    image = Path(fetched["sets"][0]["image"])
    assert image.read_bytes() == payload
    assert fetched["sets"][0]["image_sha256"] == hashlib.sha256(payload).hexdigest()


def test_fetch_refuses_a_wrong_hash(tmp_path: Path) -> None:
    sets = _set(tmp_path, b"data", "0" * 64)
    out = tmp_path / "out"
    assert fetch.main(["--sets", str(sets), "--out", str(out)]) == 1
    fetched = json.loads((out / "fetched.json").read_text())
    assert fetched["sets"] == [] and "expected" in fetched["skipped"][0]["reason"]
    assert not list((out / "downloads").glob("t1--*"))  # the bad download is deleted


def test_unpinned_set_is_skipped_unless_recorded(tmp_path: Path) -> None:
    payload = b"x" * 50
    sets = _set(tmp_path, payload, None)
    out = tmp_path / "out"
    assert fetch.main(["--sets", str(sets), "--out", str(out)]) == 0
    assert json.loads((out / "fetched.json").read_text())["sets"] == []
    assert fetch.main(["--sets", str(sets), "--out", str(out), "--record"]) == 0
    recorded = json.loads(sets.read_text())["sets"][0]
    assert recorded["sha256"] == hashlib.sha256(bz2.compress(payload)).hexdigest()
    assert "trust on first use" in recorded["hash_recorded"]["by"]


def test_refuses_to_run_on_an_airlock_drive(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    etc = tmp_path / "etc"
    etc.mkdir()
    (etc / "build-info.json").write_text("{}")
    monkeypatch.setenv("AIRLOCK_ETC_DIR", str(etc))
    sets = _set(tmp_path, b"x", "0" * 64)
    assert fetch.main(["--sets", str(sets), "--out", str(tmp_path / "o")]) == 1
    assert not (tmp_path / "o").exists()


def test_check_mode(capsys: pytest.CaptureFixture[str]) -> None:
    assert fetch.main(["--sets", str(SETS), "--check"]) == 0
    assert "is valid" in capsys.readouterr().out
