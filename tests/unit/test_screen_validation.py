"""validation/classifiers/score.py: FP/FN rates from a labelled screen.csv (task 4B.16).
Uses only synthetic CSV rows: hashes and scores, no media."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

from airlock_ai import config as cfgmod
from airlock_ai import screen

REPO = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location(
    "airlock_score", REPO / "validation" / "classifiers" / "score.py"
)
score = importlib.util.module_from_spec(spec)
spec.loader.exec_module(score)


def _result(sha: str, nudity: float, violence: float, error: str = "") -> screen.ScreenResult:
    labels = {label: 0.0 for label in cfgmod.LABELS}
    labels["violence"] = violence
    thr = cfgmod.thresholds_from_dict({})
    raw = screen.RawScore(nudity=nudity, labels=labels, error=error)
    verdict, category, reasons = screen.decide(raw, thr)
    return screen.ScreenResult(
        f"/b/{sha[:4]}",
        sha,
        verdict,
        category,
        raw.nudity,
        labels,
        reasons,
        "stub",
        {"nudenet": "n"},
        {"nudenet": "1" * 64, "siglip": "2" * 64},
    )


def test_rates_and_sweep(tmp_path: Path):
    rows = [
        # (sha, truth, nudity, violence)
        ("a" * 64, "sexual", 0.9, 0.0),  # TP sexual
        ("b" * 64, "sexual", 0.1, 0.0),  # FN sexual
        ("c" * 64, "violent", 0.0, 0.8),  # TP violent
        ("d" * 64, "neutral", 0.5, 0.0),  # FP sexual
        ("e" * 64, "neutral", 0.0, 0.0),  # TN
        ("f" * 64, "sexual+violent", 0.95, 0.9),  # TP both
    ]
    results = [_result(sha, n, v) for sha, _, n, v in rows]
    results.append(_result("9" * 64, 0.0, 0.0, error="boom"))
    screen.write_csv(tmp_path / "screen.csv", results, cfgmod.thresholds_from_dict({}))
    labels = tmp_path / "labels.csv"
    labels.write_text(
        "sha256,truth\n" + "".join(f"{s},{t}\n" for s, t, _, _ in rows) + "9" * 64 + ",neutral\n",
        encoding="utf-8",
    )
    out = tmp_path / "r.json"
    assert (
        score.main(
            ["--screen", str(tmp_path / "screen.csv"), "--labels", str(labels), "--out", str(out)]
        )
        == 0
    )
    res = json.loads(out.read_text())
    assert res["items"] == 7 and res["not_scored"] == 1
    sexual = res["at_shipped_thresholds"]["sexual"]
    assert (sexual["tp"], sexual["fp"], sexual["tn"], sexual["fn"]) == (2, 1, 2, 1)
    assert sexual["false_positive_rate"] == pytest.approx(1 / 3, abs=1e-4)
    assert sexual["false_negative_rate"] == pytest.approx(1 / 3, abs=1e-4)
    violent = res["at_shipped_thresholds"]["violent"]
    assert (violent["tp"], violent["fn"], violent["fp"]) == (2, 0, 0)
    sweep = {r["threshold"]: r for r in res["sweep"]["nudity_score"]}
    assert sweep[0.95]["tp"] == 1 and sweep[0.05]["fp"] == 1
    assert res["models"] == [{"nudenet_sha256": "1" * 64, "siglip_sha256": "2" * 64}]


def test_bad_labels_are_refused(tmp_path: Path):
    screen.write_csv(
        tmp_path / "s.csv", [_result("a" * 64, 0.0, 0.0)], cfgmod.thresholds_from_dict({})
    )
    labels = tmp_path / "l.csv"
    labels.write_text("sha256,truth\n" + "a" * 64 + ",child\n", encoding="utf-8")
    assert score.main(["--screen", str(tmp_path / "s.csv"), "--labels", str(labels)]) == 1
    labels.write_text("sha256,truth\n" + "b" * 64 + ",neutral\n", encoding="utf-8")
    assert score.main(["--screen", str(tmp_path / "s.csv"), "--labels", str(labels)]) == 1
