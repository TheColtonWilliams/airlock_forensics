#!/usr/bin/env python3
"""Per-release validation report (task 4F.4): Markdown + JSON, hashed and signed.

Host side or CI. Collects:

* ``OUT/<set>/score.json`` from ``validation/run.sh`` (pass or fail per artifact class, parser
  versions, cross-parser disagreements) and ``OUT/<set>/not-scored.json``;
* classifier error rates from ``validation/classifiers/results-<release>.json`` (task 4B.16),
  else "not measured - see 4B.16";
* software read-only policy test results from ``validation/cftt/results-<release>.json``
  (task 3A.8), else "not run - see 3A.8";
* the scale run from ``OUT/scale/result.json`` (task 4G.15) when present.

Writes ``validation-report.md``, ``validation-report.json`` and ``validation-report.sha256``
(sha256sum format). With ``--key FILE`` or ``--key-env VAR`` (the release Ed25519 key, a CI
secret, never committed) it signs ``validation-report.sha256`` with ``scripts/sign-manifest.sh``
into ``validation-report.sha256.sig``. ``--verify DIR --pub FILE`` checks a published report.

Exit status: 0 written (or verified), 1 failed (or ``--require-signature`` with no key, or
``--require-pass`` and the verdict is not pass), 2 usage error.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[2]
SCHEMA = 1
SIGNER = REPO / "scripts" / "sign-manifest.sh"
KNOWN_LIMITS = "docs/known-limitations.md"
NAMES = ("validation-report.md", "validation-report.json")
SUMS = "validation-report.sha256"
CLASS_TITLES = {
    "live_files": "Live files listed",
    "deleted_files": "Deleted files found",
    "recycle_bin": "Recycle bin entries",
    "timestamps": "Timestamps",
    "timestomp": "Timestomp inferred rows",
    "carving": "Carving recall",
    "usn_carved": "Carved USN delete records",
}
CFTT_RESULTS = {"pass", "fail", "not_run"}
NIST_LIMITS = (
    "Not all evidence may be found.",
    "Recovered deleted files may include material that did not belong to them.",
    "What an artifact means can change between operating system versions.",
)


class ReportError(RuntimeError):
    """The report cannot be built or verified."""


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def cell(value: Any) -> str:
    """Text safe inside a Markdown table cell (names from test sets are data, not markup)."""
    text = "" if value is None else str(value)
    for ch in ("\\", "|", "`", "*", "_", "<", ">", "[", "]"):
        text = text.replace(ch, "\\" + ch)
    return " ".join(text.split())


def git_release() -> str:
    try:
        res = subprocess.run(
            ["git", "-C", str(REPO), "describe", "--tags", "--always", "--dirty"],
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
    except OSError:
        return "unreleased"
    return res.stdout.strip() or "unreleased"


def read_json(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ReportError(f"cannot read {path}: {exc}") from exc


# -- inputs ------------------------------------------------------------------------------------


def load_sets(results: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    scored = [read_json(p) for p in sorted(results.glob("*/score.json"))]
    unscored = [read_json(p) for p in sorted(results.glob("*/not-scored.json"))]
    return scored, unscored


def load_classifiers(path: Path | None) -> dict[str, Any]:
    if path is None or not path.is_file():
        return {"status": "not measured", "note": "Not measured - see 4B.16"}
    doc = read_json(path)
    rates = doc.get("at_shipped_thresholds")
    if not isinstance(rates, dict):
        raise ReportError(f"{path} has no at_shipped_thresholds section (validation/classifiers)")
    return {
        "status": "measured",
        "source": path.name,
        "items": doc.get("items"),
        "not_scored": doc.get("not_scored"),
        "thresholds": doc.get("thresholds", []),
        "models": doc.get("models", []),
        "rates": {
            k: {
                "false_positive_rate": v.get("false_positive_rate"),
                "false_negative_rate": v.get("false_negative_rate"),
                "tp": v.get("tp"),
                "fp": v.get("fp"),
                "tn": v.get("tn"),
                "fn": v.get("fn"),
            }
            for k, v in sorted(rates.items())
        },
    }


def check_cftt(doc: dict[str, Any]) -> list[str]:
    problems = []
    if doc.get("schema") != 1:
        problems.append("schema must be 1")
    if doc.get("title") != "software read-only policy test results":
        problems.append("title must be 'software read-only policy test results'")
    cases = doc.get("cases")
    if not isinstance(cases, list) or not cases:
        problems.append("cases must be a non-empty list")
        return problems
    for c in cases:
        if not c.get("id"):
            problems.append("a case has no id")
        if c.get("result") not in CFTT_RESULTS:
            problems.append(f"case {c.get('id')}: result must be pass, fail or not_run")
    for key in ("tested_by", "date", "suite"):
        if not doc.get(key):
            problems.append(f"{key} is missing")
    return problems


def load_cftt(path: Path | None) -> dict[str, Any]:
    if path is None or not path.is_file():
        return {"status": "not run", "note": "Not run - see 3A.8 (validation/cftt/README.md)"}
    doc = read_json(path)
    problems = check_cftt(doc)
    if problems:
        raise ReportError(f"{path}: " + "; ".join(problems))
    counts = {r: sum(1 for c in doc["cases"] if c["result"] == r) for r in sorted(CFTT_RESULTS)}
    return {
        "status": "fail" if counts["fail"] else "pass" if not counts["not_run"] else "partial",
        "source": path.name,
        "suite": doc["suite"],
        "tested_by": doc["tested_by"],
        "date": doc["date"],
        "release_tested": doc.get("release"),
        "counts": counts,
        "failed_cases": [c["id"] for c in doc["cases"] if c["result"] == "fail"],
        "hash_unchanged": bool(doc.get("hash_before"))
        and doc.get("hash_before") == doc.get("hash_after"),
    }


def load_scale(path: Path | None) -> dict[str, Any]:
    if path is None or not path.is_file():
        return {"status": "not run", "note": "Not run - see 4G.15 (validation/scale/)"}
    doc = read_json(path)
    return {
        "status": doc.get("verdict", "unknown"),
        "source": path.name,
        "files": doc.get("files"),
        "preset": doc.get("preset"),
        "total_s": doc.get("total_s"),
        "peak_rss_kib": doc.get("peak_rss_kib"),
        "peak_tree_rss_kib": doc.get("peak_tree_rss_kib"),
        "baseline": doc.get("baseline_key"),
        "regressions": doc.get("regressions", []),
    }


# -- assembly ----------------------------------------------------------------------------------


def verdict(sets: list[dict[str, Any]]) -> str:
    if not sets:
        return "no sets scored"
    if any(s.get("overall") == "fail" for s in sets):
        return "fail"
    return "pass"


def build_doc(args: argparse.Namespace) -> dict[str, Any]:
    scored, unscored = load_sets(args.results)
    tools: dict[str, set[str]] = {}
    for s in scored:
        for name, ver in (s.get("versions", {}).get("tools") or {}).items():
            tools.setdefault(name, set()).add(str(ver))
    classes = sorted(
        {c for s in scored for c in s.get("classes", {})}, key=list(CLASS_TITLES).index
    )
    release = args.release or git_release()
    cls_path = args.classifiers or REPO / "validation" / "classifiers" / f"results-{release}.json"
    cftt_path = args.cftt or REPO / "validation" / "cftt" / f"results-{release}.json"
    scale_path = args.scale or args.results / "scale" / "result.json"
    doc = {
        "schema": SCHEMA,
        "title": "AIRLOCK validation report",
        "release": release,
        "generated_utc": dt.datetime.now(dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "known_limitations": KNOWN_LIMITS,
        "verdict": verdict(scored),
        "classes": classes,
        "sets": [
            {
                "set": s.get("set"),
                "kind": s.get("kind"),
                "fs_type": s.get("fs_type"),
                "overall": s.get("overall"),
                "run": {k: v for k, v in s.get("run", {}).items() if k != "run_dir"},
                "classes": s.get("classes", {}),
                "disagreements": s.get("disagreements", {}),
                "problems": s.get("problems", []),
                "parsers": s.get("versions", {}).get("parsers", []),
            }
            for s in scored
        ],
        "not_scored": [{"set": u.get("set"), "reason": u.get("reason")} for u in unscored],
        "parser_versions": {k: sorted(v) for k, v in sorted(tools.items())},
        "classifiers": load_classifiers(cls_path),
        "write_policy_tests": load_cftt(cftt_path),
        "scale": load_scale(scale_path),
    }
    if args.build_info and args.build_info.is_file():
        doc["image_build_info"] = read_json(args.build_info)
    return doc


def render_md(doc: dict[str, Any]) -> str:  # noqa: PLR0912, PLR0915 - one linear document
    out = [
        f"# AIRLOCK validation report: {cell(doc['release'])}",
        "",
        f"Generated {doc['generated_utc']}. Overall verdict: **{doc['verdict']}**.",
        "",
        f"Read `{KNOWN_LIMITS}` in the AIRLOCK source first: it states what these results do "
        "not show. The three limitations from NIST IR 8354 apply to every result here:",
        "",
        *(f"{i}. {text}" for i, text in enumerate(NIST_LIMITS, 1)),
        "",
        "Results are measured against synthetic images built by `validation/synthetic/` and, "
        "when fetched, public reference sets (`validation/reference/`). A pass means AIRLOCK "
        "found what the ground truth lists, on these images, with this build. It is not a "
        "legal validation.",
        "",
        "## Results per artifact class",
        "",
    ]
    classes = doc["classes"]
    if doc["sets"]:
        out.append("| Set | " + " | ".join(CLASS_TITLES[c] for c in classes) + " | Overall |")
        out.append("|---" * (len(classes) + 2) + "|")
        for s in doc["sets"]:
            cells = []
            for c in classes:
                r = s["classes"].get(c)
                if not r:
                    cells.append("-")
                elif r.get("expected") is not None:
                    cells.append(f"{r['status']} ({r.get('found')}/{r.get('expected')})")
                else:
                    cells.append(r["status"])
            out.append(f"| {cell(s['set'])} | " + " | ".join(cells) + f" | {s['overall']} |")
    else:
        out.append("No set was scored.")
    out += [
        "",
        "`unsupported`: the module does not read that file system. `not_run`: the module was "
        "not part of the run.",
        "",
    ]
    for s in doc["not_scored"]:
        out.append(f"* Not scored: {cell(s['set'])}: {cell(s['reason'])}")
    for s in doc["sets"]:
        run = s["run"]
        out += [
            "",
            f"## Set {cell(s['set'])} ({cell(s['fs_type'])}, {cell(s['kind'])})",
            "",
            f"Run {cell(run.get('run_id'))}, preset {cell(run.get('preset'))}, exit code "
            f"{run.get('exit_code')}. Target hash unchanged: {run.get('hash_unchanged')}. "
            f"Write requests seen: {run.get('write_requests_total')}. "
            f"Findings rows: {run.get('findings_rows')}.",
            "",
            "| Class | Status | Expected | Found | Recall | False positives | Notes |",
            "|---|---|---|---|---|---|---|",
        ]
        for c in classes:
            r = s["classes"].get(c)
            if not r:
                continue
            notes = r.get("reason") or "; ".join(
                str(x) for x in (r.get("missing") or r.get("problems") or [])[:5]
            )
            if c == "timestomp" and r.get("known_undetected_methods"):
                known = ", ".join(
                    f"{k['method']} ({'seen' if k['detected'] else 'not seen'})"
                    for k in r["known_undetected_methods"]
                )
                notes = (notes + "; " if notes else "") + f"known limit, not counted: {known}"
            out.append(
                f"| {CLASS_TITLES[c]} | {r['status']} | {r.get('expected', '-')} | "
                f"{r.get('found', '-')} | {r.get('recall', '-')} | "
                f"{r.get('false_positives', '-')} | {cell(notes)} |"
            )
        for p in s["problems"]:
            out.append(f"\nProblem: {cell(p)}")
    out += ["", "## Parser and tool versions", ""]
    if doc["parser_versions"]:
        out += ["| Tool | Version |", "|---|---|"]
        for name, vers in doc["parser_versions"].items():
            out.append(f"| {cell(name)} | {cell(', '.join(vers))} |")
    else:
        out.append("No tool versions recorded.")
    out += ["", "## Cross-parser disagreements", ""]
    for s in doc["sets"]:
        d = s["disagreements"]
        out.append(
            f"* {cell(s['set'])}: {d.get('rows_marked_disagree', 0)} rows marked disagree "
            f"({cell(json.dumps(d.get('by_category', {}), sort_keys=True))})."
        )
        for line in d.get("summaries", []):
            out.append(f"  * {cell(line)}")
    c = doc["classifiers"]
    out += ["", "## Classifier error rates (task 4B.16)", ""]
    if c["status"] != "measured":
        out.append(f"{c['note']}. Flag counts from media screening are unvalidated.")
    else:
        out += [
            f"From {cell(c['source'])}: {c['items']} items, {c['not_scored']} not scored.",
            "",
            "| Category | False-positive rate | False-negative rate |",
            "|---|---|---|",
        ]
        for k, v in c["rates"].items():
            out.append(f"| {cell(k)} | {v['false_positive_rate']} | {v['false_negative_rate']} |")
    w = doc["write_policy_tests"]
    out += ["", "## Software read-only policy test results (task 3A.8)", ""]
    if w["status"] == "not run":
        out.append(f"{w['note']}.")
    else:
        out.append(
            f"{cell(w['suite'])}, run by {cell(w['tested_by'])} on {cell(w['date'])}: "
            f"{w['counts']['pass']} passed, {w['counts']['fail']} failed, "
            f"{w['counts']['not_run']} not run. Test drive hash unchanged: {w['hash_unchanged']}."
        )
        if w["failed_cases"]:
            out.append(f"Failed cases: {cell(', '.join(w['failed_cases']))}.")
    out.append(
        "The software read-only policy is a second line of defence. Use a hardware write "
        "blocker with a NIST CFTT report on real evidence."
    )
    sc = doc["scale"]
    out += ["", "## Scale (task 4G.15)", ""]
    if sc["status"] == "not run":
        out.append(f"{sc['note']}.")
    else:
        out.append(
            f"{sc['files']} files, preset {cell(sc['preset'])}: {sc['total_s']} s, peak memory "
            f"{sc['peak_tree_rss_kib']} KiB (whole process tree), against baseline "
            f"{cell(sc['baseline'])}: {sc['status']}."
        )
        for r in sc["regressions"]:
            out.append(f"* Regression: {cell(r)}")
    out += [
        "",
        "## How to check this report",
        "",
        f"`{SUMS}` lists the SHA-256 of this file and its JSON twin. When signed, "
        f"`{SUMS}.sig` is a raw Ed25519 signature over it, made with the release key:",
        "",
        "```",
        f"openssl pkeyutl -verify -pubin -inkey manifest-signing.pub.pem -rawin -in {SUMS} "
        f"-sigfile {SUMS}.sig",
        "sha256sum -c " + SUMS,
        "```",
        "",
    ]
    return "\n".join(out)


def write_outputs(doc: dict[str, Any], out: Path) -> Path:
    out.mkdir(parents=True, exist_ok=True)
    md, js = (out / n for n in NAMES)
    md.write_text(render_md(doc), encoding="utf-8")
    js.write_text(json.dumps(doc, sort_keys=True, indent=2, ensure_ascii=False) + "\n", "utf-8")
    sums = out / SUMS
    sums.write_text("".join(f"{sha256_file(out / n)}  {n}\n" for n in NAMES), encoding="ascii")
    (out / f"{SUMS}.sig").unlink(missing_ok=True)
    return sums


def sign(sums: Path, *, key: Path | None, key_env: str | None, pub: Path | None) -> Path:
    argv = [str(SIGNER), "--manifest", str(sums), "--out", f"{sums}.sig"]
    argv += ["--key", str(key)] if key else ["--key-env", str(key_env)]
    if pub:
        argv += ["--pub", str(pub)]
    res = subprocess.run(argv, capture_output=True, text=True, check=False)
    if res.returncode != 0:
        raise ReportError(f"signing failed: {(res.stderr or res.stdout).strip()}")
    return Path(f"{sums}.sig")


def verify(out: Path, pub: Path) -> None:
    sums = out / SUMS
    if not sums.is_file():
        raise ReportError(f"{sums} is missing")
    for line in sums.read_text(encoding="ascii").splitlines():
        digest, _, name = line.partition("  ")
        if "/" in name or sha256_file(out / name) != digest:
            raise ReportError(f"{name} does not match {SUMS}")
    res = subprocess.run(
        [
            str(SIGNER),
            "--verify",
            "--pub",
            str(pub),
            "--manifest",
            str(sums),
            "--sig",
            f"{sums}.sig",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if res.returncode != 0:
        raise ReportError((res.stderr or res.stdout).strip())


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Build the per-release validation report (4F.4).")
    ap.add_argument("--results", type=Path, default=REPO / "validation" / "out")
    ap.add_argument("--out", type=Path, help="default: RESULTS/report")
    ap.add_argument("--release", help="release name (default: git describe)")
    ap.add_argument("--classifiers", type=Path, help="validation/classifiers results JSON")
    ap.add_argument("--cftt", type=Path, help="software read-only policy test results JSON")
    ap.add_argument("--scale", type=Path, help="scale run result JSON")
    ap.add_argument("--build-info", type=Path, help="the image's build-info.json")
    ap.add_argument("--key", type=Path, help="release Ed25519 private key PEM")
    ap.add_argument("--key-env", help="environment variable holding the key PEM (CI secret)")
    ap.add_argument("--pub", type=Path, help="public key: checked when signing, used by --verify")
    ap.add_argument("--require-signature", action="store_true", help="fail when no key is given")
    ap.add_argument("--require-pass", action="store_true", help="fail unless the verdict is pass")
    ap.add_argument("--verify", type=Path, metavar="DIR", help="verify a built report folder")
    args = ap.parse_args(argv)
    try:
        if args.verify:
            if not args.pub:
                ap.error("--verify needs --pub")
            verify(args.verify, args.pub)
            print(f"report: {args.verify / SUMS} and its signature verify")
            return 0
        if args.key and args.key_env:
            ap.error("pass --key or --key-env, not both")
        if args.key_env and not os.environ.get(args.key_env):
            raise ReportError(f"environment variable {args.key_env} is empty; set the key secret")
        out = args.out or args.results / "report"
        doc = build_doc(args)
        sums = write_outputs(doc, out)
        signed = ""
        if args.key or args.key_env:
            signed = f", signed: {sign(sums, key=args.key, key_env=args.key_env, pub=args.pub)}"
        elif args.require_signature:
            raise ReportError(
                "no signing key given (--key or --key-env) and a signature is required"
            )
        print(f"report: {out / NAMES[0]} written, verdict {doc['verdict']}{signed}")
        if args.require_pass and doc["verdict"] != "pass":
            return 1
        return 0
    except ReportError as exc:
        print(f"report: {exc}. Fix that and build the report again.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
