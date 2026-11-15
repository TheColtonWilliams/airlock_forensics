#!/usr/bin/env python3
"""Score one forensic-analyze run against a ground-truth manifest (task 4F.3).

Host side, standard library only. Reads ``findings.jsonl`` (the system of record), ``run.json``
and, as a fallback for times, the inventory index ``modules/inventory/files.jsonl``.

Artifact classes (each scored only when the truth lists it):

* ``live_files``: every live file is listed as allocated.
* ``deleted_files``: every deleted file is listed as not allocated; a live file listed as
  deleted is a false positive.
* ``recycle_bin``: every ``$I`` record is reported with its original path, deletion time
  (within the truth's tolerance) and size; a record not in the truth is a false positive.
* ``timestamps``: creation and modification times of live files, from the timeline rows
  (``$STANDARD_INFORMATION`` or the only times the file system has), else from the inventory
  index.
* ``timestomp``: every expected inferred pattern is reported for every detectable stomp; an
  inferred ``ntfs_si_*`` row on an untouched file is a false positive. Stomps the truth marks
  ``detectable: false`` are listed as known limits, never counted either way.
* ``carving``: carved files whose SHA-256 matches a deleted file in the truth (recall).
* ``usn_carved``: carved USN delete records with the right name and time; a carved delete row
  for a name the truth does not list as deleted is a false positive.

Class status: ``pass``, ``fail``, ``unsupported`` (the module does not read this file system),
or ``not_run`` (the module was not in the preset, not installed, or the run had no rows).

Usage::

    scoring.py score --truth T.json --run RUN_DIR --out score.json [--exit-code N]
    scoring.py summary OUT_DIR        # summary.json over every */score.json; exit 1 on a fail
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import re
import sys
from collections import Counter
from collections.abc import Iterable, Iterator
from pathlib import Path
from typing import Any

SCHEMA = 1
VERSION = "validation scoring 1"
TICKS = 10_000_000
EPOCH_1601 = dt.datetime(1601, 1, 1, tzinfo=dt.UTC)
MAX_LIST = 50
CLASS_MODULE = {
    "live_files": "inventory",
    "deleted_files": "inventory",
    "recycle_bin": "recycle_bin",
    "timestamps": "timeline",
    "timestomp": "inventory",
    "carving": "carve",
    "usn_carved": "deletion_history",
}
CLASS_ORDER = tuple(CLASS_MODULE)
SI_CREATED = {"Creation Time", "Creation Time ($STANDARD_INFORMATION)"}
SI_MODIFIED = {"Content Modification Time", "Content Modification Time ($STANDARD_INFORMATION)"}
_ISO = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{1,9}))?(Z|[+-]00:?00)?$")


class ScoreError(RuntimeError):
    """The run or the truth cannot be read."""


# -- helpers -----------------------------------------------------------------------------------


def to_ticks(text: Any) -> int | None:
    """ISO 8601 UTC (any number of fraction digits) to FILETIME ticks; None if not a time."""
    if not isinstance(text, str):
        return None
    m = _ISO.match(text.strip())
    if not m:
        return None
    base = dt.datetime.strptime(m.group(1), "%Y-%m-%dT%H:%M:%S").replace(tzinfo=dt.UTC)
    delta = base - EPOCH_1601
    frac = (m.group(2) or "").ljust(7, "0")[:7]
    return (delta.days * 86400 + delta.seconds) * TICKS + int(frac)


def close(a: Any, b: Any, tolerance_s: float) -> bool:
    ta, tb = to_ticks(a), to_ticks(b)
    return ta is not None and tb is not None and abs(ta - tb) <= tolerance_s * TICKS


def norm_path(path: Any) -> str:
    """NTFS and exFAT names are case-insensitive; compare folded, ``/`` separated."""
    return str(path or "").replace("\\", "/").casefold()


def read_jsonl(path: Path) -> Iterator[dict[str, Any]]:
    with open(path, encoding="utf-8") as fh:
        for raw in fh:
            text = raw.strip()
            if text:
                yield json.loads(text)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def _clip(items: Iterable[Any]) -> list[Any]:
    out = list(items)
    return out[:MAX_LIST] + ([f"... {len(out) - MAX_LIST} more"] if len(out) > MAX_LIST else [])


def _recall(found: int, expected: int) -> float | None:
    return round(found / expected, 4) if expected else None


# -- module status -----------------------------------------------------------------------------


def module_states(run_doc: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {str(m.get("name")): m for m in run_doc.get("modules", []) if isinstance(m, dict)}


def gate(states: dict[str, dict[str, Any]], module: str) -> tuple[str, str] | None:
    """None when ``module`` ran; else (class status, reason)."""
    m = states.get(module)
    if m is None:
        return "not_run", f"module {module} was not in the run's preset"
    status = m.get("status")
    if status == "ok":
        return None
    reason = str(m.get("reason") or "")
    if status == "skipped" and reason.startswith("needs a "):
        return "unsupported", f"module {module} does not read this file system ({reason})"
    if status == "failed":
        return "fail", f"module {module} failed: {reason}"
    return "not_run", f"module {module} {status}: {reason}".rstrip(": ")


# -- classes -----------------------------------------------------------------------------------


class Scorer:
    def __init__(self, truth: dict[str, Any], rows: list[dict[str, Any]], run_dir: Path) -> None:
        self.truth = truth
        self.rows = rows
        self.run_dir = run_dir
        self.tol = float(truth.get("tolerance_s", 2))
        thresholds = truth.get("thresholds") or {}
        self.recall_min = float(thresholds.get("recall_min", 1.0))
        self.fp_max = int(thresholds.get("false_positives_max", 0))
        self.per_class = {
            k: v for k, v in thresholds.items() if isinstance(v, dict) and k in CLASS_MODULE
        }
        self.files = list(truth.get("files", []))
        self.stomped = {norm_path(s["path"]) for s in truth.get("timestomp", [])}

    def limits(self, cls: str) -> tuple[float, int]:
        own = self.per_class.get(cls, {})
        return float(own.get("recall_min", self.recall_min)), int(
            own.get("false_positives_max", self.fp_max)
        )

    def verdict(self, cls: str, found: int, expected: int, fps: int, extra_ok: bool = True) -> str:
        rmin, fmax = self.limits(cls)
        rec = _recall(found, expected)
        if expected == 0:
            return "pass" if fps <= fmax and extra_ok else "fail"
        return "pass" if rec is not None and rec >= rmin and fps <= fmax and extra_ok else "fail"

    def _entries(self) -> list[dict[str, Any]]:
        return [r for r in self.rows if r.get("artifact_type") == "file_entry"]

    def live_files(self) -> dict[str, Any]:
        expected = [f["path"] for f in self.files if f.get("state") == "live"]
        for rb in self.truth.get("recycle_bin", []):
            if rb.get("r_state") == "present":
                expected.append(rb["r_path"])
            expected.append(rb["i_path"])
        alloc: dict[str, set[str]] = {}
        for r in self._entries():
            if r.get("allocated") is True:
                alloc.setdefault(norm_path(r.get("path")), set()).add(str(r.get("parser")))
        missing = [p for p in expected if norm_path(p) not in alloc]
        by_parser: Counter[str] = Counter()
        for p in expected:
            for parser in alloc.get(norm_path(p), ()):
                by_parser[parser] += 1
        found = len(expected) - len(missing)
        return {
            "expected": len(expected),
            "found": found,
            "recall": _recall(found, len(expected)),
            "false_positives": 0,
            "missing": _clip(sorted(missing)),
            "found_by_parser": dict(sorted(by_parser.items())),
            "status": self.verdict("live_files", found, len(expected), 0),
        }

    def deleted_files(self) -> dict[str, Any]:
        expected = [f["path"] for f in self.files if f.get("state") == "deleted"]
        live = {norm_path(f["path"]) for f in self.files if f.get("state") == "live"}
        deleted: dict[str, set[str]] = {}
        for r in self._entries():
            if r.get("allocated") is False:
                deleted.setdefault(norm_path(r.get("path")), set()).add(str(r.get("parser")))
        missing = [p for p in expected if norm_path(p) not in deleted]
        fps = sorted(p for p in deleted if p in live)
        by_parser: Counter[str] = Counter()
        for p in expected:
            for parser in deleted.get(norm_path(p), ()):
                by_parser[parser] += 1
        found = len(expected) - len(missing)
        return {
            "expected": len(expected),
            "found": found,
            "recall": _recall(found, len(expected)),
            "false_positives": len(fps),
            "false_positive_paths": _clip(fps),
            "missing": _clip(sorted(missing)),
            "found_by_parser": dict(sorted(by_parser.items())),
            "status": self.verdict("deleted_files", found, len(expected), len(fps)),
        }

    def recycle_bin(self) -> dict[str, Any]:
        expected = list(self.truth.get("recycle_bin", []))
        rows = [r for r in self.rows if r.get("artifact_type") == "recycle_bin_entry"]
        by_path: dict[str, list[dict[str, Any]]] = {}
        for r in rows:
            by_path.setdefault(norm_path(r.get("path")), []).append(r)
        found = time_ok = size_ok = 0
        problems: list[str] = []
        parsers: Counter[str] = Counter()
        for e in expected:
            cand = by_path.get(norm_path(e["original_path"]), [])
            if not cand:
                problems.append(f"missing: {e['original_path']}")
                continue
            found += 1
            for r in cand:
                parsers[str(r.get("parser"))] += 1
            if any(close(r.get("datetime"), e["deleted"], self.tol) for r in cand):
                time_ok += 1
            else:
                got = sorted({str(r.get("datetime")) for r in cand})
                problems.append(f"wrong deletion time: {e['original_path']}: {got}")
            if any(r.get("size_bytes") == e.get("size") for r in cand):
                size_ok += 1
            else:
                problems.append(f"wrong size: {e['original_path']}")
        truth_paths = {norm_path(e["original_path"]) for e in expected}
        extra = sorted(p for p in by_path if p not in truth_paths)
        ok = time_ok == found and size_ok == found
        return {
            "expected": len(expected),
            "found": found,
            "recall": _recall(found, len(expected)),
            "deletion_time_correct": time_ok,
            "size_correct": size_ok,
            "false_positives": len(extra),
            "false_positive_paths": _clip(extra),
            "problems": _clip(problems),
            "rows_by_parser": dict(sorted(parsers.items())),
            "status": self.verdict("recycle_bin", found, len(expected), len(extra), ok),
        }

    def _time_sources(self, use_timeline: bool) -> tuple[str, dict[str, dict[str, list[str]]]]:
        out: dict[str, dict[str, list[str]]] = {}
        if use_timeline:
            for r in self.rows:
                if r.get("category") != "timeline" or not r.get("datetime"):
                    continue
                desc = str(r.get("timestamp_desc") or "")
                kind = (
                    "created" if desc in SI_CREATED else "modified" if desc in SI_MODIFIED else ""
                )
                if kind:
                    slot = out.setdefault(norm_path(r.get("path")), {})
                    slot.setdefault(kind, []).append(str(r["datetime"]))
            return "findings.jsonl timeline rows", out
        index = self.run_dir / "modules" / "inventory" / "files.jsonl"
        if index.is_file():
            for e in read_jsonl(index):
                slot = out.setdefault(norm_path(e.get("path")), {})
                for key, kind in (("crtime", "created"), ("mtime", "modified")):
                    if e.get(key):
                        slot.setdefault(kind, []).append(str(e[key]))
        return "modules/inventory/files.jsonl", out

    def timestamps(self, use_timeline: bool) -> dict[str, Any]:
        source, seen = self._time_sources(use_timeline)
        checks = found = 0
        problems: list[str] = []
        for f in self.files:
            if f.get("state") != "live" or norm_path(f["path"]) in self.stomped:
                continue
            want = f.get("times") or f.get("planned") or {}
            for kind in ("created", "modified"):
                if not want.get(kind):
                    continue
                checks += 1
                got = seen.get(norm_path(f["path"]), {}).get(kind, [])
                if any(close(g, want[kind], self.tol) for g in got):
                    found += 1
                elif got:
                    problems.append(f"wrong {kind}: {f['path']}: {sorted(set(got))[:3]}")
                else:
                    problems.append(f"no {kind} time: {f['path']}")
        return {
            "expected": checks,
            "found": found,
            "recall": _recall(found, checks),
            "false_positives": 0,
            "source": source,
            "tolerance_s": self.tol,
            "problems": _clip(problems),
            "status": self.verdict("timestamps", found, checks, 0),
        }

    def timestomp(self) -> dict[str, Any]:
        inferred = [
            r
            for r in self.rows
            if r.get("derivation") == "inferred"
            and str(r.get("artifact_type")).startswith("ntfs_si_")
        ]
        have: dict[str, set[str]] = {}
        for r in inferred:
            have.setdefault(norm_path(r.get("path")), set()).add(str(r["artifact_type"]))
        expected = found = 0
        missing: list[str] = []
        known: list[dict[str, Any]] = []
        for s in self.truth.get("timestomp", []):
            got = have.get(norm_path(s["path"]), set())
            if not s.get("detectable"):
                known.append({"path": s["path"], "method": s["method"], "detected": sorted(got)})
                continue
            for pattern in s.get("expected_patterns", []):
                expected += 1
                if pattern in got:
                    found += 1
                else:
                    missing.append(f"{s['path']}: {pattern} ({s['method']})")
        controls = {
            norm_path(f["path"]) for f in self.files if f.get("state") == "live"
        } - self.stomped
        fps = sorted(f"{p}: {', '.join(sorted(have[p]))}" for p in have if p in controls)
        other = sorted(p for p in have if p not in controls and p not in self.stomped)
        return {
            "expected": expected,
            "found": found,
            "recall": _recall(found, expected),
            "false_positives": len(fps),
            "false_positive_paths": _clip(fps),
            "missing": _clip(missing),
            "known_undetected_methods": known,
            "inferred_rows_on_other_files": _clip(other),
            "status": self.verdict("timestomp", found, expected, len(fps)),
        }

    def carving(self) -> dict[str, Any]:
        expected = list(self.truth.get("carve", []))
        carved = {
            str(r.get("sha256"))
            for r in self.rows
            if r.get("artifact_type") == "carved_file" and r.get("sha256")
        }
        missing = [
            f"{c['from']} ({c['sha256'][:12]})" for c in expected if c["sha256"] not in carved
        ]
        found = len(expected) - len(missing)
        return {
            "expected": len(expected),
            "found": found,
            "recall": _recall(found, len(expected)),
            "false_positives": 0,
            "carved_total": len(carved),
            "missing": _clip(missing),
            "status": self.verdict("carving", found, len(expected), 0),
        }

    def usn_carved(self) -> dict[str, Any]:
        records = list(self.truth.get("usn_records", []))
        deletes = [u for u in records if u.get("deleted")]
        rows = [
            r for r in self.rows if r.get("artifact_type") in {"usn_delete_carved", "usn_delete"}
        ]
        missing: list[str] = []
        found = 0
        for u in deletes:
            hit = [r for r in rows if r.get("filename") == u["name"]]
            if any(close(r.get("datetime"), u["timestamp"], self.tol) for r in hit):
                found += 1
            else:
                missing.append(u["name"] if not hit else f"{u['name']} (wrong time)")
        delete_names = {u["name"] for u in deletes}
        fps = sorted(
            {
                str(r.get("filename"))
                for r in rows
                if r.get("artifact_type") == "usn_delete_carved"
                and r.get("filename") not in delete_names
            }
        )
        return {
            "expected": len(deletes),
            "found": found,
            "recall": _recall(found, len(deletes)),
            "false_positives": len(fps),
            "false_positive_names": _clip(fps),
            "missing": _clip(missing),
            "status": self.verdict("usn_carved", found, len(deletes), len(fps)),
        }


# -- whole run ---------------------------------------------------------------------------------


def disagreements(rows: list[dict[str, Any]]) -> dict[str, Any]:
    by_cat: Counter[str] = Counter()
    for r in rows:
        if r.get("xval_status") == "disagree":
            by_cat[str(r.get("category"))] += 1
    detail = [r for r in rows if r.get("artifact_type") == "xval_disagreement"]
    summaries = sorted(
        str(r.get("message")) for r in rows if r.get("artifact_type") == "xval_summary"
    )
    return {
        "rows_marked_disagree": sum(by_cat.values()),
        "by_category": dict(sorted(by_cat.items())),
        "disagreement_rows": len(detail),
        "examples": _clip(
            sorted(f"{r.get('path') or r.get('inode_ref')}: {r.get('text') or ''}" for r in detail)
        ),
        "summaries": summaries,
    }


def parser_versions(run_doc: dict[str, Any], rows: list[dict[str, Any]]) -> dict[str, Any]:
    tools = {
        str(k): (v.get("version") if isinstance(v, dict) else v)
        for k, v in (run_doc.get("tool_versions") or {}).items()
    }
    seen = sorted({(str(r.get("parser")), str(r.get("tool_version"))) for r in rows})
    return {
        "tools": dict(sorted(tools.items())),
        "parsers": [{"parser": p, "tool_version": v} for p, v in seen],
    }


def run_record(
    run_doc: dict[str, Any], run_dir: Path, truth: dict[str, Any], rc: int | None
) -> dict[str, Any]:
    hashes = run_doc.get("hashes") or {}
    before = (hashes.get("before") or {}).get("sha256")
    after = (hashes.get("after") or {}).get("sha256")
    return {
        "run_id": run_doc.get("run_id"),
        "run_dir": str(run_dir),
        "status": run_doc.get("status"),
        "preset": (run_doc.get("config") or {}).get("preset"),
        "exit_code": rc,
        "integrity_ok": (run_doc.get("integrity") or {}).get("ok"),
        "integrity_problems": (run_doc.get("integrity") or {}).get("problems", []),
        "write_requests_total": run_doc.get("write_requests_total"),
        "hash_before": before,
        "hash_after": after,
        "hash_unchanged": bool(before) and before == after,
        "hash_matches_truth": bool(before) and before == truth.get("image_sha256"),
        "findings_rows": (run_doc.get("findings") or {}).get("rows"),
        "modules": [
            {k: m.get(k) for k in ("name", "status", "reason", "duration_s", "findings")}
            for m in run_doc.get("modules", [])
        ],
    }


def score(truth: dict[str, Any], run_dir: Path, *, exit_code: int | None = None) -> dict[str, Any]:
    run_json = run_dir / "run.json"
    if not run_json.is_file():
        raise ScoreError(f"{run_json} is missing: the run did not start")
    run_doc = json.loads(run_json.read_text(encoding="utf-8"))
    findings = run_dir / "findings.jsonl"
    rows = list(read_jsonl(findings)) if findings.is_file() else []
    states = module_states(run_doc)
    scorer = Scorer(truth, rows, run_dir)
    classes: dict[str, Any] = {}
    for cls in CLASS_ORDER:
        if cls not in truth.get("classes", []):
            continue
        module = CLASS_MODULE[cls]
        use_timeline = True
        blocked = gate(states, module)
        if cls == "timestamps" and blocked and blocked[0] != "unsupported":
            fallback = gate(states, "inventory")
            if fallback is None:
                blocked, use_timeline, module = None, False, "inventory"
        if blocked:
            classes[cls] = {"status": blocked[0], "reason": blocked[1], "module": module}
            continue
        res = scorer.timestamps(use_timeline) if cls == "timestamps" else getattr(scorer, cls)()
        res["module"] = module
        classes[cls] = res
    run = run_record(run_doc, run_dir, truth, exit_code)
    problems = []
    if not run["integrity_ok"]:
        problems.append("integrity: " + "; ".join(run["integrity_problems"] or ["not recorded"]))
    if run["write_requests_total"] not in (0, None):
        problems.append(f"write requests seen: {run['write_requests_total']}")
    if truth.get("image_sha256") and not run["hash_matches_truth"]:
        problems.append("the analysed image is not the one the truth describes")
    statuses = [c["status"] for c in classes.values()]
    if problems or "fail" in statuses:
        overall = "fail"
    elif all(s == "pass" for s in statuses):
        overall = "pass"
    else:
        overall = "incomplete"
    return {
        "schema": SCHEMA,
        "scorer": VERSION,
        "set": truth.get("set"),
        "kind": truth.get("kind"),
        "fs_type": truth.get("fs_type"),
        "truth_generator": truth.get("generator"),
        "run": run,
        "classes": classes,
        "disagreements": disagreements(rows),
        "versions": parser_versions(run_doc, rows),
        "problems": problems,
        "overall": overall,
    }


def summarise(out_dir: Path) -> dict[str, Any]:
    sets = []
    for path in sorted(out_dir.glob("*/score.json")):
        s = json.loads(path.read_text(encoding="utf-8"))
        sets.append(
            {
                "set": s.get("set"),
                "overall": s.get("overall"),
                "classes": {k: v.get("status") for k, v in s.get("classes", {}).items()},
                "score": str(path.relative_to(out_dir)),
            }
        )
    for path in sorted(out_dir.glob("*/not-scored.json")):
        s = json.loads(path.read_text(encoding="utf-8"))
        sets.append({"set": s.get("set"), "overall": "not_scored", "reason": s.get("reason")})
    overall = "fail" if any(s["overall"] == "fail" for s in sets) else "ok" if sets else "empty"
    return {"schema": SCHEMA, "sets": sets, "overall": overall}


def dump(path: Path, doc: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(doc, sort_keys=True, indent=2, ensure_ascii=False) + "\n", "utf-8")
    tmp.replace(path)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Score forensic-analyze runs against ground truth.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("score", help="score one run")
    s.add_argument("--truth", type=Path, required=True)
    s.add_argument("--run", type=Path, required=True, help="the run folder (holds run.json)")
    s.add_argument("--out", type=Path, required=True)
    s.add_argument("--exit-code", type=int, help="forensic-analyze's exit code, for the record")
    m = sub.add_parser("summary", help="summarise every */score.json under a folder")
    m.add_argument("out_dir", type=Path)
    args = ap.parse_args(argv)
    try:
        if args.cmd == "score":
            truth = json.loads(args.truth.read_text(encoding="utf-8"))
            doc = score(truth, args.run, exit_code=args.exit_code)
            doc["truth_sha256"] = sha256_file(args.truth)
            dump(args.out, doc)
            cls = ", ".join(f"{k} {v['status']}" for k, v in doc["classes"].items())
            print(f"{doc['set']}: {doc['overall']} ({cls})")
            return 0
        doc = summarise(args.out_dir)
        dump(args.out_dir / "summary.json", doc)
        for s_ in doc["sets"]:
            print(f"{s_['set']}: {s_['overall']}")
        return 1 if doc["overall"] == "fail" else 0
    except (ScoreError, OSError, ValueError, KeyError) as exc:
        print(f"scoring: {exc}. Check the run folder and the truth file.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
