#!/usr/bin/env python3
"""Build a run folder for evidence-report tests from a rows file (task 4E.10, 4G.14).

The folder looks like one ``forensic-analyze`` leaves behind just before it calls
``evidence-report``: ``run.json`` (the runner's fields), ``modules/<name>/findings.part.jsonl``,
``findings.jsonl`` (merged by ``forensic_analyze.findings.merge_parts``), and ``case.sqlite``
(``forensic_analyze.export_sqlite.build``). Text only; no evidence media.

    python3 make_run.py OUTPUT_ROOT [--rows rows.json] [--case T-INJ] [--mode direct|image]

Prints the run folder (``OUTPUT_ROOT/cases/<case>/<run_id>``).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
PYLIB = HERE.parents[2] / "ansible" / "roles" / "session_tools" / "files" / "pylib"
RUN_ID = "R-20261115T090000Z-abc123"
EVIDENCE_SHA256 = "5" * 64
EVIDENCE_MD5 = "6" * 32


def run_doc(case_id: str, mode: str, modules: list[str], counts: dict[str, int]) -> dict[str, Any]:
    order = {name: (i + 1) * 10 for i, name in enumerate(modules)}
    mods = [
        {
            "name": m,
            "title": m.replace("_", " ").capitalize(),
            "order": order[m],
            "status": "ok",
            "reason": "",
            "counts": {},
            "findings": counts.get(m, 0),
        }
        for m in modules
    ]
    mods.append({"name": "carve", "status": "skipped", "reason": "not chosen for this run"})
    mods.append({"name": "malware", "status": "failed", "reason": "ClamAV database missing"})
    limits = (
        ["The drive was read directly; no forensic copy was made (documented triage)."]
        if mode == "direct"
        else ["The drive was copied first and the analysis ran on the copy."]
    )
    return {
        "schema": 1,
        "tool": "forensic-analyze",
        "run_id": RUN_ID,
        "status": "complete",
        "argv": ["forensic-analyze", "--target", "/dev/sdz", "--preset", "standard"],
        "config": {"mode": mode, "preset": "standard", "imager": "ewf", "target": "/dev/sdz"},
        "case": {
            "case_id": case_id,
            "exhibit_id": "EX-7",
            "examiner": "Examiner One",
            "authority_ref": "Warrant 2026/0042",
            "notes": "",
            "agency": "Test Agency",
        },
        "authority_ack": {
            "acknowledged": True,
            "ts": "2026-11-15T09:00:00Z",
            "via": "flag",
            "text": "Only examine a drive when you have the legal authority to do so.",
            "text_sha256": "0" * 64,
        },
        "clock": {
            "started_utc": "2026-11-15T09:00:00Z",
            "finished_utc": "2026-11-15T09:10:00Z",
            "duration_s": 600.0,
            "system_utc_at_entry": "2026-11-15T09:00:00Z",
            "reference_time": "2026-11-15T09:00:01Z",
            "reference_source": "test clock",
            "clock_offset_seconds": -1.0,
        },
        "write_blocker": {
            "in_use": "yes",
            "make": "ExampleMake",
            "model": "EB-1",
            "firmware": "1.0",
            "report_url": "cftt report reference",
        },
        "target": {
            "evidence_id": "EX-7",
            "kind": "device",
            "path": "/dev/sdz",
            "model": "Generic Disk",
            "serial": "SN0001",
            "size_bytes": 41943040,
            "readonly_flag": True,
        },
        "hashes": {
            "before": {"sha256": EVIDENCE_SHA256, "md5": EVIDENCE_MD5, "complete": True},
            "after": {"sha256": EVIDENCE_SHA256, "md5": EVIDENCE_MD5, "complete": True},
            "match": True,
        },
        "handle": {"method": "ro_loop"},
        "write_requests": {"target": {"method": "block_stat", "write_requests": 0}},
        "write_requests_total": 0,
        "integrity": {"ok": True, "problems": []},
        "mode_record": {"mode": mode, "imager": "", "warning": "", "limits": limits},
        "sandbox": {"method": "bwrap", "network": "none", "user": "nobody"},
        "volumes": [
            {
                "index": 0,
                "fs_type": "ntfs",
                "label": "FIX",
                "offset_bytes": 0,
                "size_bytes": 41943040,
                "bitlocker": False,
            }
        ],
        "plan": {"preset": "standard", "planned": modules, "not_available": []},
        "modules": mods,
        "tool_versions": {"fls": {"path": "/usr/bin/fls", "sha256": "1" * 64, "version": "4.12.1"}},
        "deviations": [],
        "warnings": [],
        "errors": [
            {"where": "malware", "error": "ClamAV database missing", "utc": "2026-11-15T09:05:00Z"}
        ],
        "models": [],
        "resumes": [],
        "finished_utc": "2026-11-15T09:10:00Z",
    }


def build(out_root: Path, rows_file: Path, case_id: str = "T-INJ", mode: str = "direct") -> Path:
    if str(PYLIB) not in sys.path:
        sys.path.insert(0, str(PYLIB))
    from airlock_common import hashing, jsonio  # noqa: PLC0415
    from forensic_analyze import export_sqlite, findings  # noqa: PLC0415

    spec = json.loads(rows_file.read_text(encoding="utf-8"))
    run_dir = out_root / "cases" / case_id / RUN_ID
    (run_dir / "logs").mkdir(parents=True, exist_ok=True)
    names: list[str] = []
    counts: dict[str, int] = {}
    for mod in spec["modules"]:
        name = mod["name"]
        names.append(name)
        part = findings.part_path(run_dir, name)
        with findings.FindingsWriter(
            part, run_id=RUN_ID, evidence_id="EX-7", evidence_sha256=EVIDENCE_SHA256, module=name
        ) as writer:
            for row in mod["rows"]:
                writer.emit(row)
            counts[name] = writer.count
    path = findings.merge_parts(run_dir, names)
    export_sqlite.build(run_dir)
    doc = run_doc(case_id, mode, names, counts)
    doc["findings"] = {
        "path": path.name,
        "sha256": hashing.sha256_file(path),
        "rows": sum(counts.values()),
    }
    doc["summary"] = {
        "modules": [
            {k: m.get(k) for k in ("name", "status", "reason", "findings", "counts")}
            for m in sorted(
                doc["modules"], key=lambda m: {"failed": 0, "skipped": 1}.get(m["status"], 2)
            )
        ]
    }
    jsonio.dump_json(run_dir / "run.json", doc)
    return run_dir


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("out_root")
    p.add_argument("--rows", default=str(HERE / "rows.json"))
    p.add_argument("--case", default="T-INJ")
    p.add_argument("--mode", default="direct", choices=["direct", "image"])
    a = p.parse_args()
    print(build(Path(a.out_root), Path(a.rows), a.case, a.mode))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
