"""Screening verdicts, thresholds, backends, and screen.csv (tasks 4B.5, 4B.6, 4G.10)."""

from __future__ import annotations

import csv
import json
import subprocess
from pathlib import Path

import pytest

from airlock_ai import config as cfgmod
from airlock_ai import screen

REPO = Path(__file__).resolve().parents[2]
NEUTRAL = REPO / "tests" / "fixtures" / "ai" / "neutral"
STUB = REPO / "tests" / "fixtures" / "ai" / "stub-scores.json"
THRESHOLDS_FILE = REPO / "ansible/roles/session_tools/files/etc/screen-thresholds.json"


def _thr() -> cfgmod.Thresholds:
    return cfgmod.thresholds_from_dict({})


def _neutral_labels(**over: float) -> dict[str, float]:
    labels = {label: 0.01 for label in cfgmod.LABELS}
    labels["neutral"] = 0.9
    labels.update(over)
    return labels


def test_shipped_thresholds_file_equals_defaults():
    data = json.loads(THRESHOLDS_FILE.read_text(encoding="utf-8"))
    assert data == json.loads(json.dumps(cfgmod.DEFAULT_THRESHOLDS))
    t = cfgmod.load_thresholds(THRESHOLDS_FILE)
    assert len(t.sha256) == 64
    assert set(t.labels) == set(cfgmod.LABELS) - {"neutral"}


def test_thresholds_reject_bad_values(tmp_path: Path):
    bad = tmp_path / "t.json"
    bad.write_text(json.dumps({"nudity": 1.5}), encoding="utf-8")
    with pytest.raises(cfgmod.ConfigError):
        cfgmod.load_thresholds(bad)
    bad.write_text(json.dumps({"labels": {"cats": 0.2}}), encoding="utf-8")
    with pytest.raises(cfgmod.ConfigError):
        cfgmod.load_thresholds(bad)
    with pytest.raises(cfgmod.ConfigError):
        cfgmod.load_thresholds(tmp_path / "missing.json")


def test_decide_cleared_flagged_error():
    thr = _thr()
    ok = screen.RawScore(nudity=0.05, labels=_neutral_labels())
    assert screen.decide(ok, thr)[0] == "cleared"
    nude = screen.RawScore(nudity=0.30, labels=_neutral_labels())  # exactly at the threshold
    v, cat, reasons = screen.decide(nude, thr)
    assert (v, cat) == ("flagged", "sexual")
    assert "nudity detector" in reasons[0]
    violent = screen.RawScore(nudity=0.0, labels=_neutral_labels(gore=0.5))
    assert screen.decide(violent, thr)[:2] == ("flagged", "violent")
    both = screen.RawScore(nudity=0.9, labels=_neutral_labels(weapon=0.9))
    assert screen.decide(both, thr)[1] == "sexual+violent"
    # Neutral never flags, however high.
    assert screen.decide(screen.RawScore(0.0, labels=_neutral_labels(neutral=1.0)), thr)[0] == (
        "cleared"
    )


def test_missing_scores_are_never_cleared():
    thr = _thr()
    assert screen.decide(screen.RawScore(nudity=None, labels=_neutral_labels()), thr)[0] == "error"
    labels = _neutral_labels()
    del labels["blood"]
    assert screen.decide(screen.RawScore(nudity=0.0, labels=labels), thr)[0] == "error"
    assert screen.decide(screen.RawScore(error="boom"), thr)[0] == "error"


def test_stub_backend_and_csv(airlock_env: Path, tmp_path: Path):
    files = sorted(NEUTRAL.glob("*.png"))
    out = tmp_path / "screen.csv"
    results = screen.screen_paths(files, out, _thr(), backend=f"stub:{STUB}")
    by_name = {Path(r.path).name: r for r in results}
    assert by_name["shapes-squares.png"].verdict == "flagged"
    assert by_name["text-render.png"].verdict == "error"
    assert by_name["landscape.png"].verdict == "cleared"
    assert screen.summarise(results) == {"screened": 5, "cleared": 3, "flagged": 1, "error": 1}
    with open(out, encoding="utf-8-sig", newline="") as fh:
        rows = list(csv.DictReader(fh))
    assert [r["verdict"] for r in rows] == [r.verdict for r in results]
    assert all(len(r["siglip_model_sha256"]) == 64 for r in rows)
    assert all(r["label"].startswith("AI-generated") for r in rows)
    assert screen.read_verdicts(out)[by_name["landscape.png"].sha256] == "cleared"


def test_csv_neutralises_formula_paths(airlock_env: Path, tmp_path: Path):
    evil = tmp_path / "=HYPERLINK(1).png"
    evil.write_bytes((NEUTRAL / "landscape.png").read_bytes())
    out = tmp_path / "s.csv"
    screen.screen_paths([evil], out, _thr(), backend=f"stub:{STUB}")
    with open(out, encoding="utf-8-sig", newline="") as fh:
        row = next(csv.DictReader(fh))
    assert not row["path"].startswith("=")
    assert "=HYPERLINK" in row["path"]


def test_read_verdicts_keeps_most_cautious(tmp_path: Path):
    p = tmp_path / "s.csv"
    sha = "a" * 64
    p.write_text(f"sha256,verdict\r\n{sha},flagged\r\n{sha},cleared\r\n", encoding="utf-8")
    assert screen.read_verdicts(p) == {sha: "flagged"}


def _fake_runner(response: dict | None, calls: list):
    def run(argv, **kw):
        calls.append((argv, kw))
        req = json.loads(Path(argv[3]).read_text(encoding="utf-8"))
        if response is not None:
            doc = dict(response)
            doc["results"] = [
                {"path": p, "nudity": 0.0, "labels": _neutral_labels()} for p in req["images"]
            ]
            Path(argv[4]).write_text(json.dumps(doc), encoding="utf-8")
        return subprocess.CompletedProcess(argv, 0 if response else 1, "", "runner crashed")

    return run


def _stage_siglip(assets: Path) -> None:
    d = assets / "files" / "models" / "siglip-base-patch16-224"
    d.mkdir(parents=True)
    (d / "model.onnx").write_bytes(b"onnx")
    (d / "tokenizer.json").write_text("{}", encoding="utf-8")


def test_triage_backend_request_and_parse(airlock_env: Path, tmp_path: Path, monkeypatch):
    _stage_siglip(airlock_env / "assets")
    py = tmp_path / "venv" / "bin" / "python"
    py.parent.mkdir(parents=True)
    py.write_text("", encoding="utf-8")
    monkeypatch.setenv("AIRLOCK_TRIAGE_PYTHON", str(py))
    calls: list = []
    resp = {
        "model_ids": {"nudenet": "nn", "siglip": "sg"},
        "model_sha256": {"nudenet": "1" * 64, "siglip": "2" * 64},
    }
    files = sorted(NEUTRAL.glob("*.png"))
    results = screen.screen_paths(
        files,
        None,
        _thr(),
        backend="triage",
        run_tool=_fake_runner(resp, calls),
        workdir=tmp_path / "w",
    )
    assert all(r.cleared for r in results)
    assert results[0].model_sha256 == {"nudenet": "1" * 64, "siglip": "2" * 64}
    argv, kw = calls[0]
    assert argv[1] == "-I" and argv[2].endswith("triage_runner.py")
    req_labels = cfgmod.LABELS
    assert len(req_labels) == 8
    assert str(NEUTRAL) in kw["extra_ro"]
    # Request and response files are removed after use.
    assert not list((tmp_path / "w").glob("screen-*.json"))


def test_triage_backend_runner_failure_is_an_error(airlock_env: Path, tmp_path: Path, monkeypatch):
    _stage_siglip(airlock_env / "assets")
    py = tmp_path / "python"
    py.write_text("", encoding="utf-8")
    monkeypatch.setenv("AIRLOCK_TRIAGE_PYTHON", str(py))
    with pytest.raises(screen.ScreenError, match="runner failed"):
        screen.screen_paths(
            [NEUTRAL / "landscape.png"],
            None,
            _thr(),
            backend="triage",
            run_tool=_fake_runner(None, []),
            workdir=tmp_path / "w",
        )


def test_triage_backend_refuses_without_siglip(airlock_env: Path, tmp_path: Path, monkeypatch):
    py = tmp_path / "python"
    py.write_text("", encoding="utf-8")
    monkeypatch.setenv("AIRLOCK_TRIAGE_PYTHON", str(py))
    with pytest.raises(screen.ScreenError, match="SigLIP"):
        screen.screen_paths(
            [NEUTRAL / "landscape.png"],
            None,
            _thr(),
            backend="triage",
            run_tool=_fake_runner({}, []),
            workdir=tmp_path / "w",
        )


def test_env_selects_stub_backend(airlock_env: Path, tmp_path: Path, monkeypatch):
    monkeypatch.setenv(screen.BACKEND_ENV, f"stub:{STUB}")
    res = screen.screen_paths(
        [NEUTRAL / "shapes-squares.png"], None, _thr(), workdir=tmp_path / "w"
    )
    assert res[0].flagged
    assert res[0].backend == "stub"


def test_label_prompts_hash_tracks_template():
    a = screen.label_prompts_sha256(_thr())
    b = screen.label_prompts_sha256(cfgmod.thresholds_from_dict({"label_template": "{label}"}))
    assert a != b and len(a) == 64


def test_cli_exit_codes(airlock_env: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]):
    out = tmp_path / "s.csv"
    rc = screen.main([str(NEUTRAL), "-o", str(out), "--backend", f"stub:{STUB}"])
    assert rc == 4  # one file could not be screened
    text = capsys.readouterr().out
    assert "1 flagged" in text and "forensic-escalate" in text
    assert (
        screen.main(
            [str(tmp_path / "empty-dir-missing"), "-o", str(out), "--backend", f"stub:{STUB}"]
        )
        == 2
    )
