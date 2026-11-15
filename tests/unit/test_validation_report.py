"""validation/report/build.py (task 4F.4): per-release report, inputs, signature."""

from __future__ import annotations

import importlib.util
import json
import re
import shutil
import subprocess
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


report = _load("airlock_validation_report", "validation/report/build.py")


def score(name: str, overall: str, *, carving: str = "pass") -> dict[str, Any]:
    return {
        "set": name,
        "kind": "synthetic",
        "fs_type": "ntfs",
        "overall": overall,
        "run": {
            "run_id": "R-1",
            "run_dir": "/secret/host/path",
            "preset": "full",
            "exit_code": 0,
            "hash_unchanged": True,
            "write_requests_total": 0,
            "findings_rows": 10,
        },
        "classes": {
            "deleted_files": {
                "status": "pass",
                "expected": 2,
                "found": 2,
                "recall": 1.0,
                "false_positives": 0,
                "missing": [],
            },
            "carving": {
                "status": carving,
                "expected": 1,
                "found": 0 if carving == "fail" else 1,
                "recall": 0.0 if carving == "fail" else 1.0,
                "false_positives": 0,
                "missing": ["/Pics/a|b.png (cd)"] if carving == "fail" else [],
            },
            "timestomp": {
                "status": "pass",
                "expected": 1,
                "found": 1,
                "recall": 1.0,
                "false_positives": 0,
                "known_undetected_methods": [{"method": "ntfs3g_xattr", "detected": []}],
            },
        },
        "disagreements": {
            "rows_marked_disagree": 1,
            "by_category": {"inventory": 1},
            "summaries": ["Cross-check: 1 disagree."],
        },
        "versions": {"tools": {"fls": "sleuthkit 4.12.1"}, "parsers": []},
        "problems": [],
    }


@pytest.fixture
def results(tmp_path: Path) -> Path:
    out = tmp_path / "out"
    for name, overall in (("ntfs-synthetic", "pass"), ("exfat-synthetic", "incomplete")):
        (out / name).mkdir(parents=True)
        (out / name / "score.json").write_text(json.dumps(score(name, overall)))
    (out / "ref-a").mkdir()
    (out / "ref-a" / "not-scored.json").write_text(
        json.dumps({"set": "ref-a", "reason": "no truth"})
    )
    return out


def args(results: Path, *extra: str) -> list[str]:
    return ["--results", str(results), "--release", "v9.9.9-test", *extra]


def test_report_without_optional_inputs(results: Path) -> None:
    assert report.main(args(results)) == 0
    md = (results / "report" / "validation-report.md").read_text()
    doc = json.loads((results / "report" / "validation-report.json").read_text())
    assert doc["verdict"] == "pass"
    assert doc["classifiers"]["note"] == "Not measured - see 4B.16"
    assert doc["write_policy_tests"]["status"] == "not run"
    assert doc["scale"]["status"] == "not run"
    assert doc["known_limitations"] == "docs/known-limitations.md"
    assert "Not measured - see 4B.16" in md and "Not run - see 3A.8" in md
    assert "docs/known-limitations.md" in md and "NIST IR 8354" in md
    assert "Not scored: ref-a" in md
    assert "known limit, not counted: ntfs3g\\_xattr" in md
    assert "/secret/host/path" not in md + json.dumps(doc)  # host paths stay out
    assert "write blocker" not in md.replace("hardware write blocker", "")
    sums = (results / "report" / "validation-report.sha256").read_text().splitlines()
    assert [ln.split("  ")[1] for ln in sums] == list(report.NAMES)


def test_failed_class_fails_the_verdict_and_names_are_escaped(results: Path) -> None:
    (results / "ntfs-synthetic" / "score.json").write_text(
        json.dumps(score("ntfs-synthetic", "fail", carving="fail"))
    )
    assert report.main(args(results)) == 0
    assert report.main(args(results, "--require-pass")) == 1
    md = (results / "report" / "validation-report.md").read_text()
    assert "Overall verdict: **fail**" in md
    assert "/Pics/a\\|b.png" in md  # a pipe in a name cannot break the table


def test_classifier_cftt_and_scale_inputs(results: Path, tmp_path: Path) -> None:
    cls = tmp_path / "cls.json"
    cls.write_text(
        json.dumps(
            {
                "items": 100,
                "not_scored": 2,
                "thresholds": ["t"],
                "models": [],
                "at_shipped_thresholds": {
                    "sexual": {
                        "tp": 40,
                        "fp": 5,
                        "tn": 50,
                        "fn": 3,
                        "false_positive_rate": 0.0909,
                        "false_negative_rate": 0.0698,
                    }
                },
            }
        )
    )
    cftt_doc = json.loads((REPO / "validation" / "cftt" / "results-template.json").read_text())
    cftt_doc.update(tested_by="lab tester", date="2026-12-01", hash_before="aa", hash_after="aa")
    for case in cftt_doc["cases"]:
        case["id"] = case["id"] or "FT-WB-01"
        case["result"] = "pass"
    cftt_doc["cases"][1]["result"] = "fail"
    cftt = tmp_path / "cftt.json"
    cftt.write_text(json.dumps(cftt_doc))
    scale = tmp_path / "scale.json"
    scale.write_text(
        json.dumps(
            {
                "verdict": "pass",
                "files": 300000,
                "preset": "standard",
                "total_s": 10,
                "peak_rss_kib": 5,
                "baseline_key": "k",
                "regressions": [],
            }
        )
    )
    rc = report.main(
        args(results, "--classifiers", str(cls), "--cftt", str(cftt), "--scale", str(scale))
    )
    assert rc == 0
    doc = json.loads((results / "report" / "validation-report.json").read_text())
    assert doc["classifiers"]["rates"]["sexual"]["false_positive_rate"] == 0.0909
    w = doc["write_policy_tests"]
    assert w["status"] == "fail" and w["failed_cases"] == ["AIRLOCK-TRACER"]
    assert w["counts"] == {"fail": 1, "not_run": 0, "pass": 3} and w["hash_unchanged"]
    assert doc["scale"]["files"] == 300000
    md = (results / "report" / "validation-report.md").read_text()
    assert "Failed cases: AIRLOCK-TRACER" in md


def test_bad_cftt_file_is_refused(results: Path, tmp_path: Path) -> None:
    bad = tmp_path / "cftt.json"
    bad.write_text(json.dumps({"schema": 1, "title": "write blocker test", "cases": []}))
    assert report.main(args(results, "--cftt", str(bad))) == 1
    tmpl = json.loads((REPO / "validation" / "cftt" / "results-template.json").read_text())
    problems = report.check_cftt(tmpl)
    assert any("tested_by" in p for p in problems)  # the template itself is not a result


def test_require_signature_without_key_fails(results: Path) -> None:
    assert report.main(args(results, "--require-signature")) == 1


@pytest.mark.skipif(not shutil.which("openssl"), reason="needs openssl")
def test_signed_report_verifies_and_tampering_is_caught(
    results: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    key, pub = tmp_path / "k.pem", tmp_path / "pub.pem"
    subprocess.run(["openssl", "genpkey", "-algorithm", "ed25519", "-out", str(key)], check=True)
    subprocess.run(["openssl", "pkey", "-in", str(key), "-pubout", "-out", str(pub)], check=True)
    monkeypatch.setenv("TEST_RELEASE_KEY", key.read_text())
    assert report.main(args(results, "--key-env", "TEST_RELEASE_KEY", "--pub", str(pub))) == 0
    out = results / "report"
    assert (out / "validation-report.sha256.sig").is_file()
    assert report.main(["--verify", str(out), "--pub", str(pub)]) == 0
    md = out / "validation-report.md"
    md.write_text(md.read_text() + "\nedited\n")
    assert report.main(["--verify", str(out), "--pub", str(pub)]) == 1
    # A key that does not match the expected public key is refused.
    other = tmp_path / "other.pem"
    subprocess.run(["openssl", "genpkey", "-algorithm", "ed25519", "-out", str(other)], check=True)
    assert report.main(args(results, "--key", str(other), "--pub", str(pub))) == 1


def test_empty_results_say_so(tmp_path: Path) -> None:
    empty = tmp_path / "empty"
    empty.mkdir()
    assert report.main(args(empty)) == 0
    doc = json.loads((empty / "report" / "validation-report.json").read_text())
    assert doc["verdict"] == "no sets scored"
    assert report.main(args(empty, "--require-pass")) == 1


def test_known_limitations_page_states_the_required_limits() -> None:
    text = (REPO / "docs" / "known-limitations.md").read_text()
    assert "NIST IR 8354" in text
    for limit in (
        "Not all evidence may be found",
        "Recovered deleted files may include material that did not belong to them",
        "What an artifact means can change between operating system versions",
    ):
        assert limit in text
        assert any(limit.rstrip(".") in s for s in report.NIST_LIMITS)
    # Surviving risks that change what a result means (decision log, Surviving risks).
    flat = " ".join(text.split())
    cited = {
        int(n)
        for group in re.findall(r"\(risks? ([0-9][0-9 and,]*)", flat)
        for n in re.findall(r"[0-9]+", group)
    }
    assert {1, 2, 9, 10, 11, 15, 22, 26, 27, 28, 29, 30, 31, 32} <= cited
    assert "not a write blocker" in text
