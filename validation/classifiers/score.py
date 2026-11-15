#!/usr/bin/env python3
"""Score the screening classifiers against a lawful labelled benchmark (task 4B.16).

No media is in this repository. A person with lawful access to a labelled adult-content and
violence benchmark runs ``evidence-screen`` over it on an AIRLOCK drive, writes a labels file,
and runs this script. It prints and writes the false-positive and false-negative rates at the
shipped thresholds, plus a threshold sweep per score, for the release notes and the validation
report (4F.4).

Inputs:

``--screen screen.csv``
    the file ``evidence-screen`` wrote (columns ``sha256``, ``verdict``, ``category``,
    ``nudity_score``, ``score_<label>``...).
``--labels labels.csv``
    one row per benchmark item: ``sha256`` and ``truth``, where truth is ``sexual``,
    ``violent``, ``sexual+violent``, or ``neutral``. Nothing else (no file names, no content).

Output: ``--out results.json`` (sorted keys) and a Markdown table on stdout.

Rates: false-positive rate = FP / (FP + TN) over items whose truth lacks the category;
false-negative rate = FN / (FN + TP) over items whose truth has it. Items the classifiers could
not score (verdict ``error``) are counted separately and never as negatives.

    python3 validation/classifiers/score.py --screen screen.csv --labels labels.csv \\
        --out results.json
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path
from typing import Any

CATEGORIES = ("sexual", "violent")
TRUTHS = {"sexual", "violent", "sexual+violent", "neutral"}
SWEEP_SCORES = {
    "nudity_score": "sexual",
    "score_nudity": "sexual",
    "score_sexual_activity": "sexual",
    "score_violence": "violent",
    "score_weapon": "violent",
    "score_gore": "violent",
    "score_blood": "violent",
    "score_injury": "violent",
}
SWEEP = [round(0.05 * i, 2) for i in range(1, 20)]


class ScoreError(ValueError):
    pass


def _read(path: Path) -> list[dict[str, str]]:
    with open(path, encoding="utf-8-sig", newline="") as fh:
        return list(csv.DictReader(fh))


def _clean(cell: str) -> str:
    # screen.csv neutralises cells that look like formulas with a leading quote.
    return (cell or "").strip().lstrip("'")


def load(screen_csv: Path, labels_csv: Path) -> list[dict[str, Any]]:
    screen = {_clean(r["sha256"]): r for r in _read(screen_csv) if _clean(r.get("sha256", ""))}
    items: list[dict[str, Any]] = []
    for row in _read(labels_csv):
        sha = _clean(row.get("sha256", "")).lower()
        truth = _clean(row.get("truth", "")).lower()
        if truth not in TRUTHS:
            raise ScoreError(f"labels: unknown truth {truth!r} for {sha[:12]}")
        s = screen.get(sha)
        if s is None:
            raise ScoreError(f"labels: {sha[:12]} is not in the screen file")
        items.append({"sha256": sha, "truth": set(truth.split("+")) - {"neutral"}, "screen": s})
    if not items:
        raise ScoreError("labels: no rows")
    return items


def rates(tp: int, fp: int, tn: int, fn: int) -> dict[str, Any]:
    return {
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "false_positive_rate": round(fp / (fp + tn), 4) if fp + tn else None,
        "false_negative_rate": round(fn / (fn + tp), 4) if fn + tp else None,
    }


def evaluate(items: list[dict[str, Any]]) -> dict[str, Any]:
    scored = [i for i in items if _clean(i["screen"].get("verdict", "")) != "error"]
    out: dict[str, Any] = {"items": len(items), "not_scored": len(items) - len(scored)}
    any_tp = any_fp = any_tn = any_fn = 0
    per: dict[str, Any] = {}
    for cat in CATEGORIES:
        tp = fp = tn = fn = 0
        for i in scored:
            pred = cat in _clean(i["screen"].get("category", "")).split("+")
            truth = cat in i["truth"]
            tp += pred and truth
            fp += pred and not truth
            tn += not pred and not truth
            fn += not pred and truth
        per[cat] = rates(tp, fp, tn, fn)
    for i in scored:
        pred = _clean(i["screen"].get("verdict", "")) == "flagged"
        truth = bool(i["truth"])
        any_tp += pred and truth
        any_fp += pred and not truth
        any_tn += not pred and not truth
        any_fn += not pred and truth
    out["at_shipped_thresholds"] = {"any_sensitive": rates(any_tp, any_fp, any_tn, any_fn), **per}
    sweep: dict[str, Any] = {}
    for col, cat in SWEEP_SCORES.items():
        vals = [(i, _clean(i["screen"].get(col, ""))) for i in scored]
        vals = [(i, float(v)) for i, v in vals if v]
        if not vals:
            continue
        table = []
        for t in SWEEP:
            tp = sum(1 for i, v in vals if v >= t and cat in i["truth"])
            fp = sum(1 for i, v in vals if v >= t and cat not in i["truth"])
            tn = sum(1 for i, v in vals if v < t and cat not in i["truth"])
            fn = sum(1 for i, v in vals if v < t and cat in i["truth"])
            table.append({"threshold": t, **rates(tp, fp, tn, fn)})
        sweep[col] = table
    out["sweep"] = sweep
    thresholds = {_clean(i["screen"].get("thresholds", "")) for i in scored}
    out["thresholds"] = sorted(t for t in thresholds if t)
    models = {
        (
            _clean(i["screen"].get("nudenet_model_sha256", "")),
            _clean(i["screen"].get("siglip_model_sha256", "")),
        )
        for i in scored
    }
    out["models"] = [{"nudenet_sha256": a, "siglip_sha256": b} for a, b in sorted(models)]
    return out


def markdown(res: dict[str, Any]) -> str:
    lines = [
        f"Items: {res['items']} ({res['not_scored']} could not be scored and are not counted).",
        "",
        "| Category | TP | FP | TN | FN | False-positive rate | False-negative rate |",
        "|---|---|---|---|---|---|---|",
    ]
    for cat, r in res["at_shipped_thresholds"].items():
        lines.append(
            f"| {cat} | {r['tp']} | {r['fp']} | {r['tn']} | {r['fn']} | "
            f"{r['false_positive_rate']} | {r['false_negative_rate']} |"
        )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--screen", required=True, type=Path)
    ap.add_argument("--labels", required=True, type=Path)
    ap.add_argument("--out", type=Path)
    args = ap.parse_args(argv)
    try:
        res = evaluate(load(args.screen, args.labels))
    except (OSError, ScoreError, KeyError, ValueError) as exc:
        print(f"score: {exc}. Check the two CSV files.", file=sys.stderr)
        return 1
    if args.out:
        args.out.write_text(json.dumps(res, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(markdown(res))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
