"""validation/scoring.py (task 4F.3): each artifact class scored against ground truth."""

from __future__ import annotations

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


scoring = _load("airlock_validation_scoring", "validation/scoring.py")

IMG_SHA = "ab" * 32


def truth() -> dict[str, Any]:
    return {
        "schema": 1,
        "set": "unit-set",
        "kind": "synthetic",
        "fs_type": "ntfs",
        "image_sha256": IMG_SHA,
        "tolerance_s": 2,
        "thresholds": {"recall_min": 1.0, "false_positives_max": 0},
        "classes": list(scoring.CLASS_ORDER),
        "files": [
            {
                "path": "/Data/live.txt",
                "state": "live",
                "times": {
                    "created": "2026-03-02T09:10:00.0004000Z",
                    "modified": "2026-04-10T16:30:00.5000000Z",
                },
            },
            {"path": "/Data/gone.txt", "state": "deleted", "times": None},
            {"path": "/Data/stomp.txt", "state": "live", "times": None},
        ],
        "recycle_bin": [
            {
                "i_path": "/$Recycle.Bin/S-1-5-21-1-2-3-1001/$IA.txt",
                "r_path": "/$Recycle.Bin/S-1-5-21-1-2-3-1001/$RA.txt",
                "r_state": "present",
                "original_path": "C:\\Users\\T\\draft.txt",
                "deleted": "2026-04-15T12:00:00.1234567Z",
                "size": 42,
            }
        ],
        "timestomp": [
            {
                "path": "/Data/stomp.txt",
                "method": "si_raw_whole",
                "detectable": True,
                "expected_patterns": ["ntfs_si_before_fn", "ntfs_si_zero_fraction"],
            },
            {
                "path": "/Data/xattr.txt",
                "method": "ntfs3g_xattr",
                "detectable": False,
                "expected_patterns": [],
            },
        ],
        "carve": [{"sha256": "cd" * 32, "size": 900, "type": "png", "from": "/Pics/a.png"}],
        "usn_records": [
            {"name": "u-del.txt", "deleted": True, "timestamp": "2026-04-12T10:00:00.1111111Z"},
            {"name": "u-new.txt", "deleted": False, "timestamp": "2026-04-12T10:00:09Z"},
        ],
    }


def entry(path: str, allocated: bool, parser: str = "tsk") -> dict[str, Any]:
    return {
        "category": "inventory",
        "artifact_type": "file_entry",
        "path": path,
        "allocated": allocated,
        "parser": parser,
    }


def good_rows() -> list[dict[str, Any]]:
    rb = "/$Recycle.Bin/S-1-5-21-1-2-3-1001"
    return [
        entry("/Data/live.txt", True),
        entry("/data/LIVE.txt", True, "dissect"),
        entry("/Data/stomp.txt", True),
        entry(f"{rb}/$IA.txt", True),
        entry(f"{rb}/$RA.txt", True),
        entry("/Data/gone.txt", False),
        {
            "category": "recycle_bin",
            "artifact_type": "recycle_bin_entry",
            "path": "C:\\Users\\T\\draft.txt",
            "datetime": "2026-04-15T12:00:00.1234567Z",
            "size_bytes": 42,
            "parser": "airlock.recycle",
        },
        {
            "category": "timeline",
            "artifact_type": "fs_time",
            "path": "/Data/live.txt",
            "datetime": "2026-03-02T09:10:00Z",
            "timestamp_desc": "Creation Time",
        },
        {
            "category": "timeline",
            "artifact_type": "fs_time",
            "path": "/Data/live.txt",
            "datetime": "2026-04-10T16:30:00Z",
            "timestamp_desc": "Content Modification Time",
        },
        {
            "category": "timeline",
            "artifact_type": "fs_time",
            "path": "/Data/live.txt",
            "datetime": "2020-01-01T00:00:00Z",
            "timestamp_desc": "Creation Time ($FILE_NAME)",
        },
        {
            "category": "inventory",
            "artifact_type": "ntfs_si_before_fn",
            "derivation": "inferred",
            "path": "/Data/stomp.txt",
        },
        {
            "category": "inventory",
            "artifact_type": "ntfs_si_zero_fraction",
            "derivation": "inferred",
            "path": "/Data/stomp.txt",
        },
        {"category": "carve", "artifact_type": "carved_file", "sha256": "cd" * 32},
        {"category": "carve", "artifact_type": "carved_file", "sha256": "ef" * 32},
        {
            "category": "deletion",
            "artifact_type": "usn_delete_carved",
            "filename": "u-del.txt",
            "datetime": "2026-04-12T10:00:00.1111111Z",
        },
        {
            "category": "xval",
            "artifact_type": "xval_summary",
            "message": "Cross-check of MFT file entries: 3 agree, 0 disagree.",
        },
    ]


def make_run(tmp_path: Path, rows: list[dict[str, Any]], **over: Any) -> Path:
    run = tmp_path / "R-1"
    run.mkdir()
    modules = [
        {"name": n, "status": "ok", "duration_s": 1.0}
        for n in ("inventory", "recycle_bin", "deletion_history", "timeline", "carve")
    ]
    doc = {
        "run_id": "R-1",
        "status": "complete",
        "config": {"preset": "full"},
        "hashes": {"before": {"sha256": IMG_SHA}, "after": {"sha256": IMG_SHA}},
        "integrity": {"ok": True, "problems": []},
        "write_requests_total": 0,
        "findings": {"rows": len(rows)},
        "modules": modules,
        "tool_versions": {"fls": {"version": "sleuthkit 4.12.1"}},
    }
    doc.update(over)
    (run / "run.json").write_text(json.dumps(doc))
    (run / "findings.jsonl").write_text("".join(json.dumps(r) + "\n" for r in rows))
    return run


def test_every_class_passes_on_matching_rows(tmp_path: Path) -> None:
    res = scoring.score(truth(), make_run(tmp_path, good_rows()), exit_code=0)
    statuses = {k: v["status"] for k, v in res["classes"].items()}
    assert statuses == {k: "pass" for k in scoring.CLASS_ORDER}, res["classes"]
    assert res["overall"] == "pass"
    assert res["classes"]["live_files"]["expected"] == 4  # live + stomp + $I + $R
    assert res["classes"]["timestamps"]["found"] == 2
    assert res["classes"]["timestomp"]["known_undetected_methods"][0]["method"] == "ntfs3g_xattr"
    assert res["classes"]["carving"]["carved_total"] == 2
    assert res["versions"]["tools"] == {"fls": "sleuthkit 4.12.1"}
    assert res["disagreements"]["summaries"]


@pytest.mark.parametrize(
    ("drop", "cls"),
    [
        (lambda r: r.get("path") == "/Data/gone.txt", "deleted_files"),
        (lambda r: r.get("artifact_type") == "recycle_bin_entry", "recycle_bin"),
        (lambda r: r.get("timestamp_desc") == "Creation Time", "timestamps"),
        (lambda r: r.get("artifact_type") == "ntfs_si_zero_fraction", "timestomp"),
        (lambda r: r.get("sha256") == "cd" * 32, "carving"),
        (lambda r: r.get("filename") == "u-del.txt", "usn_carved"),
    ],
)
def test_missing_row_fails_its_class(tmp_path: Path, drop: Any, cls: str) -> None:
    rows = [r for r in good_rows() if not drop(r)]
    res = scoring.score(truth(), make_run(tmp_path, rows))
    assert res["classes"][cls]["status"] == "fail"
    assert res["overall"] == "fail"


def test_false_positives_fail(tmp_path: Path) -> None:
    rows = [
        *good_rows(),
        entry("/Data/live.txt", False),  # a live file reported deleted
        {
            "artifact_type": "ntfs_si_before_fn",
            "derivation": "inferred",
            "path": "/Data/live.txt",
        },
        {"artifact_type": "recycle_bin_entry", "path": "C:\\other.txt", "datetime": None},
        {"artifact_type": "usn_delete_carved", "filename": "u-new.txt", "datetime": None},
    ]
    res = scoring.score(truth(), make_run(tmp_path, rows))
    for cls in ("deleted_files", "timestomp", "recycle_bin", "usn_carved"):
        assert res["classes"][cls]["false_positives"] == 1, cls
        assert res["classes"][cls]["status"] == "fail", cls


def test_wrong_time_and_size_fail_recycle_bin(tmp_path: Path) -> None:
    rows = good_rows()
    for r in rows:
        if r.get("artifact_type") == "recycle_bin_entry":
            r["datetime"] = "2026-04-15T12:00:09Z"
    res = scoring.score(truth(), make_run(tmp_path, rows))
    rb = res["classes"]["recycle_bin"]
    assert rb["found"] == 1 and rb["deletion_time_correct"] == 0
    assert rb["status"] == "fail"


def test_module_states_gate_classes(tmp_path: Path) -> None:
    modules = [
        {"name": "inventory", "status": "skipped", "reason": "needs a ntfs volume; found: exfat"},
        {"name": "recycle_bin", "status": "failed", "reason": "boom"},
        {"name": "carve", "status": "not_available", "reason": "not installed"},
        {"name": "timeline", "status": "ok"},
    ]
    res = scoring.score(truth(), make_run(tmp_path, good_rows(), modules=modules))
    c = res["classes"]
    assert c["live_files"]["status"] == "unsupported"
    assert c["recycle_bin"]["status"] == "fail"
    assert c["carving"]["status"] == "not_run"
    assert c["usn_carved"]["status"] == "not_run"  # deletion_history not in the run
    assert c["timestamps"]["status"] == "pass"


def test_timestamps_fall_back_to_inventory_index(tmp_path: Path) -> None:
    rows = [r for r in good_rows() if r.get("category") != "timeline"]
    modules = [{"name": "inventory", "status": "ok"}]
    run = make_run(tmp_path, rows, modules=modules)
    idx = run / "modules" / "inventory"
    idx.mkdir(parents=True)
    (idx / "files.jsonl").write_text(
        json.dumps(
            {
                "path": "/Data/live.txt",
                "crtime": "2026-03-02T09:10:01Z",
                "mtime": "2026-04-10T16:30:00Z",
            }
        )
        + "\n"
    )
    res = scoring.score(truth(), run)
    ts = res["classes"]["timestamps"]
    assert ts["status"] == "pass" and ts["source"].endswith("files.jsonl")
    assert ts["module"] == "inventory"


def test_integrity_problems_fail_the_set(tmp_path: Path) -> None:
    run = make_run(
        tmp_path,
        good_rows(),
        write_requests_total=3,
        hashes={"before": {"sha256": IMG_SHA}, "after": {"sha256": "00" * 32}},
        integrity={"ok": False, "problems": ["the target's hash changed"]},
    )
    res = scoring.score(truth(), run)
    assert res["overall"] == "fail"
    assert any("write requests" in p for p in res["problems"])
    assert res["run"]["hash_unchanged"] is False


def test_other_image_is_flagged(tmp_path: Path) -> None:
    run = make_run(
        tmp_path,
        good_rows(),
        hashes={"before": {"sha256": "11" * 32}, "after": {"sha256": "11" * 32}},
    )
    res = scoring.score(truth(), run)
    assert res["overall"] == "fail"
    assert "not the one the truth describes" in res["problems"][0]


def test_to_ticks_handles_precisions() -> None:
    a = scoring.to_ticks("2026-04-15T12:00:00.1234567Z")
    b = scoring.to_ticks("2026-04-15T12:00:00Z")
    assert a is not None and b is not None and a - b == 1_234_567
    assert scoring.to_ticks("2026-04-15T12:00:00.123456+00:00") == b + 1_234_560
    assert scoring.to_ticks("yesterday") is None
    assert scoring.close("2026-01-01T00:00:01Z", "2026-01-01T00:00:00.5Z", 1)
    assert not scoring.close("2026-01-01T00:00:03Z", "2026-01-01T00:00:00Z", 2)


def test_cli_score_and_summary(tmp_path: Path) -> None:
    run = make_run(tmp_path, good_rows())
    t = tmp_path / "t.json"
    t.write_text(json.dumps(truth()))
    out = tmp_path / "out"
    rc = scoring.main(
        ["score", "--truth", str(t), "--run", str(run), "--out", str(out / "a" / "score.json")]
    )
    assert rc == 0
    assert scoring.main(["summary", str(out)]) == 0
    summary = json.loads((out / "summary.json").read_text())
    assert summary["overall"] == "ok" and summary["sets"][0]["overall"] == "pass"
    bad = json.loads((out / "a" / "score.json").read_text())
    bad["overall"] = "fail"
    (out / "b").mkdir()
    (out / "b" / "score.json").write_text(json.dumps(bad))
    assert scoring.main(["summary", str(out)]) == 1


def test_cli_reports_a_missing_run(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    t = tmp_path / "t.json"
    t.write_text(json.dumps(truth()))
    rc = scoring.main(
        [
            "score",
            "--truth",
            str(t),
            "--run",
            str(tmp_path / "nope"),
            "--out",
            str(tmp_path / "s.json"),
        ]
    )
    assert rc == 1
    assert "run.json is missing" in capsys.readouterr().err
