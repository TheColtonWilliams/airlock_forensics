"""validation/scale/scale.py (task 4G.15): attribution, baseline comparison, regression."""

from __future__ import annotations

import importlib.util
import json
import os
import sys
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[2]


def _load(name: str, rel: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, REPO / rel)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


scale = _load("airlock_validation_scale", "validation/scale/scale.py")


def result(total: float = 10.0, peak: int = 100_000, inv_s: float = 6.0) -> dict[str, Any]:
    return {
        "files": 300,
        "preset": "quick",
        "exit_code": 0,
        "run_status": "complete",
        "total_s": total,
        "peak_rss_kib": peak,
        "modules": {
            "inventory": {"status": "ok", "duration_s": inv_s, "peak_tree_rss_kib": 90_000},
            "recycle_bin": {"status": "ok", "duration_s": 0.1, "peak_tree_rss_kib": None},
        },
    }


def test_attribute_assigns_samples_to_the_running_module() -> None:
    modules = [
        {
            "name": "inventory",
            "status": "ok",
            "started_utc": "2026-11-15T00:00:00.000000Z",
            "duration_s": 2.0,
        },
        {
            "name": "timeline",
            "status": "ok",
            "started_utc": "2026-11-15T00:00:02.500000Z",
            "duration_s": 1.0,
        },
        {"name": "carve", "status": "skipped", "started_utc": "", "duration_s": 0.0},
    ]
    t0 = scale._epoch("2026-11-15T00:00:00Z")
    samples = [(t0 + 0.5, 100), (t0 + 1.5, 300), (t0 + 2.2, 999), (t0 + 3.0, 50)]
    got = scale.attribute(samples, modules)
    assert got["inventory"]["peak_tree_rss_kib"] == 300
    assert got["timeline"]["peak_tree_rss_kib"] == 50
    assert got["carve"]["peak_tree_rss_kib"] is None


def test_compare_flags_time_memory_and_status_regressions() -> None:
    tol = dict(scale.DEFAULT_TOL)
    base = result()
    assert scale.compare(result(), base, tol) == []
    assert scale.compare(result(total=17.0), base, tol) == []  # inside 50 % + 5 s
    slow = scale.compare(result(total=30.0, inv_s=20.0), base, tol)
    assert any("total run time" in s for s in slow)
    assert any("module inventory" in s for s in slow)
    big = scale.compare(result(peak=400_000), base, tol)
    assert any("single process" in s for s in big)
    assert any("peak memory" in s for s in big)
    broken = result()
    broken["modules"]["inventory"]["status"] = "failed"
    assert any("status failed" in s for s in scale.compare(broken, base, tol))
    assert scale.compare(result(total=999), None, tol) == []


def test_finish_records_then_detects_regression(tmp_path: Path) -> None:
    bl = tmp_path / "baseline.json"
    first = result()
    assert scale.finish(first, bl, "quick-300", update=True) == 0
    assert first["verdict"] == "baseline recorded"
    stored = json.loads(bl.read_text())
    assert stored["baselines"]["quick-300"]["total_s"] == 10.0
    assert "regressions" not in stored["baselines"]["quick-300"]
    same = result(total=11.0)
    assert scale.finish(same, bl, "quick-300", update=False) == 0
    assert same["verdict"] == "pass"
    worse = result(total=60.0)
    assert scale.finish(worse, bl, "quick-300", update=False) == 1
    assert worse["verdict"] == "fail" and worse["regressions"]
    unknown = result()
    assert scale.finish(unknown, bl, "standard-300000", update=False) == 0
    assert unknown["verdict"] == "no baseline"
    failed = result()
    failed["exit_code"] = 1
    assert scale.finish(failed, bl, "quick-300", update=False) == 1


def test_compare_cli(tmp_path: Path) -> None:
    bl = tmp_path / "baseline.json"
    scale.finish(result(), bl, "quick-300", update=True)
    res = tmp_path / "result.json"
    res.write_text(json.dumps(result(total=100.0)))
    assert scale.main(["compare", "--result", str(res), "--baseline", str(bl)]) == 1


def test_tree_rss_counts_this_process() -> None:
    assert scale.tree_rss_kib(os.getpid()) > 1000
    assert scale.tree_rss_kib(2**22 + 12345) == 0  # no such process


def test_file_plan_mixes_sizes() -> None:
    plans = [scale.file_plan(i) for i in range(200)]
    assert {e for e, _ in plans} == {".bin", ".txt"}
    assert any(s > 4096 for _, s in plans) and any(s < 700 for _, s in plans)


def test_committed_baseline_is_well_formed() -> None:
    doc = json.loads((REPO / "validation" / "scale" / "baseline.json").read_text())
    assert doc["schema"] == 1
    assert set(scale.DEFAULT_TOL) <= set(doc["tolerance"])
    for key, base in doc["baselines"].items():
        assert key == f"{base['preset']}-{base['files']}"
        assert base["total_s"] > 0 and base["modules"]
