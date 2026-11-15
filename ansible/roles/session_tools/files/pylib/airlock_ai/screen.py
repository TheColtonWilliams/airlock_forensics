"""``evidence-screen``: sexual and violent content screening of images (task 4B.6).

Each image is scored by two classifiers that run on the CPU in the ``/opt/triage`` venv, in a
sandboxed child process with no network (``triage_runner.py``):

* NudeNet: a detector; the nudity score is its highest confidence for an exposed-body-part
  class (``nudenet_classes`` in the thresholds file);
* SigLIP zero-shot: one score per label (nudity, sexual activity, violence, weapon, gore,
  blood, injury, neutral), a softmax over the label prompts.

A file is **flagged** when the nudity score or any label score (except neutral) is at or above
its threshold, **cleared** when every score is below, and **error** when it could not be
scored. Only cleared files may go to the description model; flagged and error files never do.
"Cleared" means "not flagged by these models at these thresholds", never "safe".

Test backend: ``AIRLOCK_SCREEN_BACKEND=stub:<file.json>`` returns fixed scores from a JSON
file (``tests/fixtures/ai/stub-scores.json`` shows the format). Real detection rates come
from task 4B.16, never from the repository's fixtures (there are no sensitive fixtures).
"""

from __future__ import annotations

import argparse
import contextlib
import csv
import json
import os
import sys
import tempfile
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from airlock_ai import AI_LABEL
from airlock_ai import config as cfgmod
from airlock_ai.tools import RunTool, sandbox_runner, tool_dir
from airlock_common import hashing, jsonio, proc, sessionlog

TOOL = "evidence-screen"
BACKEND_ENV = "AIRLOCK_SCREEN_BACKEND"
RUNNER_SCRIPT = Path(__file__).resolve().parent / "triage_runner.py"
BATCH = 256
IMAGE_EXTENSIONS = frozenset(
    {".jpg", ".jpeg", ".jpe", ".png", ".gif", ".bmp", ".tif", ".tiff", ".webp", ".ppm", ".pgm"}
)

CSV_COLUMNS: tuple[str, ...] = (
    "path",
    "sha256",
    "verdict",
    "category",
    "nudity_score",
    *(f"score_{label.replace(' ', '_')}" for label in cfgmod.LABELS),
    "reasons",
    "backend",
    "nudenet_model_id",
    "nudenet_model_sha256",
    "siglip_model_id",
    "siglip_model_sha256",
    "label_prompts_sha256",
    "thresholds_sha256",
    "thresholds",
    "error",
    "label",
)


class ScreenError(RuntimeError):
    """Screening could not run at all (backend missing, models not staged)."""


@dataclass
class RawScore:
    """What a backend returns for one image."""

    nudity: float | None = None
    nudenet_classes: dict[str, float] = field(default_factory=dict)
    labels: dict[str, float] = field(default_factory=dict)
    error: str = ""
    # Set when part of the file was not scored (more frames or pages than the limit). A file
    # with this set is never cleared: it is flagged if a scored part flags, else an error.
    incomplete: str = ""


@dataclass
class BackendOutput:
    scores: dict[str, RawScore]
    model_ids: dict[str, str]
    model_sha256: dict[str, str]
    name: str


@dataclass
class ScreenResult:
    path: str
    sha256: str
    verdict: str  # cleared | flagged | error
    category: str = ""  # "" | sexual | violent | sexual+violent
    nudity_score: float | None = None
    label_scores: dict[str, float] = field(default_factory=dict)
    reasons: list[str] = field(default_factory=list)
    backend: str = ""
    model_ids: dict[str, str] = field(default_factory=dict)
    model_sha256: dict[str, str] = field(default_factory=dict)
    label_prompts_sha256: str = ""
    thresholds_sha256: str = ""
    error: str = ""

    @property
    def flagged(self) -> bool:
        return self.verdict == "flagged"

    @property
    def cleared(self) -> bool:
        return self.verdict == "cleared"

    def top_label(self) -> tuple[str, float]:
        """The highest-scoring sensitive label (never neutral), or ("", 0.0)."""
        best = ("", 0.0)
        for label, score in sorted(self.label_scores.items()):
            if label != cfgmod.NEUTRAL_LABEL and score > best[1]:
                best = (label, score)
        return best

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "sha256": self.sha256,
            "verdict": self.verdict,
            "category": self.category,
            "nudity_score": self.nudity_score,
            "label_scores": dict(sorted(self.label_scores.items())),
            "reasons": list(self.reasons),
            "backend": self.backend,
            "model_ids": dict(sorted(self.model_ids.items())),
            "model_sha256": dict(sorted(self.model_sha256.items())),
            "label_prompts_sha256": self.label_prompts_sha256,
            "thresholds_sha256": self.thresholds_sha256,
            "error": self.error,
        }


# ---------------------------------------------------------------------------------------------
# Verdict
# ---------------------------------------------------------------------------------------------


def label_prompts(thresholds: cfgmod.Thresholds) -> list[str]:
    return [thresholds.label_template.format(label=label) for label in cfgmod.LABELS]


def label_prompts_sha256(thresholds: cfgmod.Thresholds) -> str:
    """SHA-256 of the zero-shot label prompts, one per line (the screening "prompt")."""
    return hashing.sha256_bytes(("\n".join(label_prompts(thresholds)) + "\n").encode())


def decide(raw: RawScore, thresholds: cfgmod.Thresholds) -> tuple[str, str, list[str]]:
    """(verdict, category, reasons) for one image. Missing scores are never "cleared"."""
    if raw.error:
        return "error", "", [raw.error]
    missing = [label for label in thresholds.labels if label not in raw.labels]
    if raw.nudity is None or missing:
        what = ["nudity score"] if raw.nudity is None else []
        what += [f"label {m}" for m in missing]
        return "error", "", [f"missing {', '.join(what)}"]
    reasons: list[str] = []
    sexual = violent = False
    if raw.nudity >= thresholds.nudity:
        reasons.append(f"nudity detector {raw.nudity:.3f} >= {thresholds.nudity:.3f}")
        sexual = True
    for label, limit in sorted(thresholds.labels.items()):
        score = raw.labels[label]
        if score >= limit:
            reasons.append(f"label {label} {score:.3f} >= {limit:.3f}")
            if label in cfgmod.SEXUAL_LABELS:
                sexual = True
            if label in cfgmod.VIOLENT_LABELS:
                violent = True
    if not reasons:
        if raw.incomplete:
            return "error", "", [f"not fully screened: {raw.incomplete}"]
        return "cleared", "", []
    if raw.incomplete:
        reasons.append(f"not fully screened: {raw.incomplete}")
    category = "+".join(c for c, on in (("sexual", sexual), ("violent", violent)) if on)
    return "flagged", category, reasons


# ---------------------------------------------------------------------------------------------
# Backends
# ---------------------------------------------------------------------------------------------


class StubBackend:
    """Fixed scores from a JSON file, for tests only (4G.10). Never used on real evidence.

    Format: ``{"model_id": "...", "default": SCORE, "files": {"<sha256 or file name>": SCORE}}``
    where ``SCORE`` is ``{"nudity": 0.1, "labels": {"violence": 0.9, ...}}`` or
    ``{"error": "text"}``. Labels left out score 0. ``"incomplete": "why"`` marks a file
    whose frames were not all scored.
    """

    def __init__(self, spec_path: Path) -> None:
        try:
            self.spec = json.loads(spec_path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise ScreenError(f"stub backend: cannot read {spec_path} ({exc})") from exc
        self.sha256 = hashing.sha256_file(spec_path)
        self.model_id = str(self.spec.get("model_id", "stub classifier (test only)"))

    def _score(self, entry: dict[str, Any]) -> RawScore:
        if "error" in entry:
            return RawScore(error=str(entry["error"]))
        labels = {label: 0.0 for label in cfgmod.LABELS}
        labels.update({k: float(v) for k, v in entry.get("labels", {}).items()})
        return RawScore(
            nudity=float(entry.get("nudity", 0.0)),
            labels=labels,
            incomplete=str(entry.get("incomplete") or ""),
        )

    def score(
        self, items: Sequence[tuple[Path, str]], thresholds: cfgmod.Thresholds
    ) -> BackendOutput:
        del thresholds
        files = self.spec.get("files", {})
        default = self.spec.get("default", {"nudity": 0.0, "labels": {"neutral": 1.0}})
        out: dict[str, RawScore] = {}
        for p, digest in items:
            entry = files.get(digest) or files.get(p.name) or default
            out[str(p)] = self._score(entry)
        ids = {"nudenet": self.model_id, "siglip": self.model_id}
        shas = {"nudenet": self.sha256, "siglip": self.sha256}
        return BackendOutput(out, ids, shas, "stub")


class TriageBackend:
    """NudeNet + SigLIP in the ``/opt/triage`` venv, run through ``triage_runner.py``."""

    def __init__(self, run_tool: RunTool, workdir: Path, ai_config: dict[str, Any]) -> None:
        self.run_tool = run_tool
        self.workdir = workdir
        self.cfg = ai_config
        self.python = cfgmod.venv_python("triage", ai_config)

    def _models(self) -> dict[str, Any]:
        cls = self.cfg["classifiers"]
        sig = cls["siglip"]
        nn = cls["nudenet"]
        nn_model = cfgmod.asset_file(nn.get("model_target"))
        out = {
            "nudenet": {"model": str(nn_model) if nn_model else None, "id": nn.get("id", "")},
            "siglip": {
                "model": str(cfgmod.asset_file(sig["model_target"])),
                "tokenizer": str(cfgmod.asset_file(sig["tokenizer_target"])),
                "preprocessor": str(cfgmod.asset_file(sig.get("preprocessor_target")) or ""),
                "id": sig.get("id", ""),
            },
        }
        if not Path(out["siglip"]["model"]).is_file():
            raise ScreenError(
                "the SigLIP classifier is not staged on ASSETS; restage with a profile that "
                "includes classifiers"
            )
        if not Path(out["siglip"]["tokenizer"]).is_file():
            raise ScreenError("the SigLIP tokenizer is not staged on ASSETS; restage it")
        return out

    def score(
        self, items: Sequence[tuple[Path, str]], thresholds: cfgmod.Thresholds
    ) -> BackendOutput:
        if not self.python.exists():
            raise ScreenError(
                f"the classifier environment {self.python.parent.parent} is not installed; "
                "provision the drive with a profile that includes classifiers"
            )
        models = self._models()
        scores: dict[str, RawScore] = {}
        ids: dict[str, str] = {}
        shas: dict[str, str] = {}
        extra_ro = sorted(
            {str(p.parent) for p, _ in items}
            | {str(Path(m).parent) for m in _model_files(models)}
            | {str(RUNNER_SCRIPT.parent)}
        )
        for start in range(0, len(items), BATCH):
            chunk = list(items[start : start + BATCH])
            n = start // BATCH
            req_path = self.workdir / f"screen-request-{n:04d}.json"
            resp_path = self.workdir / f"screen-response-{n:04d}.json"
            jsonio.dump_json(
                req_path,
                {
                    "images": [str(p) for p, _ in chunk],
                    "labels": list(cfgmod.LABELS),
                    "prompts": label_prompts(thresholds),
                    "nudenet_classes": list(thresholds.nudenet_classes),
                    "max_image_frames": thresholds.max_image_frames,
                    "models": models,
                },
            )
            req_path.chmod(0o644)  # the sandbox user reads it; it holds paths, not content
            cp = self.run_tool(
                [str(self.python), "-I", str(RUNNER_SCRIPT), str(req_path), str(resp_path)],
                timeout=120 + 10 * len(chunk),
                memory_bytes=8 * 1024**3,
                extra_ro=extra_ro,
            )
            data = _load_response(resp_path, cp)
            ids = {k: str(v) for k, v in data.get("model_ids", {}).items()}
            shas = {k: str(v) for k, v in data.get("model_sha256", {}).items()}
            by_path = {r.get("path"): r for r in data.get("results", [])}
            for p, _ in chunk:
                r = by_path.get(str(p))
                if r is None:
                    scores[str(p)] = RawScore(error="classifier returned no result")
                    continue
                scores[str(p)] = RawScore(
                    nudity=r.get("nudity"),
                    nudenet_classes={k: float(v) for k, v in r.get("nudenet", {}).items()},
                    labels={k: float(v) for k, v in r.get("labels", {}).items()},
                    error=str(r.get("error") or ""),
                    incomplete=str(r.get("incomplete") or ""),
                )
            for f in (req_path, resp_path):
                f.unlink(missing_ok=True)
        return BackendOutput(scores, ids, shas, "nudenet+siglip")


def _model_files(models: dict[str, Any]) -> list[str]:
    out = [models["siglip"]["model"], models["siglip"]["tokenizer"]]
    if models["siglip"].get("preprocessor"):
        out.append(models["siglip"]["preprocessor"])
    if models["nudenet"].get("model"):
        out.append(models["nudenet"]["model"])
    return out


def _load_response(path: Path, cp: Any) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        last = ((cp.stderr or "").strip().splitlines() or ["no output"])[-1]
        raise ScreenError(f"the classifier runner failed (exit {cp.returncode}): {last}") from None
    if data.get("fatal"):
        raise ScreenError(f"the classifier runner stopped: {data['fatal']}")
    return data


def make_backend(
    spec: str | None, *, run_tool: RunTool | None, workdir: Path, ai_config: dict[str, Any]
) -> StubBackend | TriageBackend:
    """``spec`` is ``triage`` (default) or ``stub:<json file>``; env ``AIRLOCK_SCREEN_BACKEND``."""
    chosen = spec or os.environ.get(BACKEND_ENV) or "triage"
    if chosen.startswith("stub:"):
        return StubBackend(Path(chosen[5:]))
    if chosen != "triage":
        raise ScreenError(f"unknown screening backend {chosen!r} (use triage or stub:FILE)")
    return TriageBackend(run_tool or sandbox_runner(workdir), workdir, ai_config)


# ---------------------------------------------------------------------------------------------
# Screening
# ---------------------------------------------------------------------------------------------


def screen_paths(
    paths_in: Iterable[str | os.PathLike[str]],
    out_csv: str | os.PathLike[str] | None,
    thresholds: cfgmod.Thresholds | None = None,
    *,
    backend: str | None = None,
    run_tool: RunTool | None = None,
    workdir: Path | None = None,
    ai_config: dict[str, Any] | None = None,
    known_sha256: dict[str, str] | None = None,
) -> list[ScreenResult]:
    """Screen images and write ``out_csv`` (when given). One result per input path, in order.

    ``known_sha256`` maps a path to a SHA-256 already computed by the caller.
    """
    thr = thresholds or cfgmod.load_thresholds()
    cfg = ai_config or cfgmod.load_ai_config()
    if workdir is None:
        if out_csv is None:
            raise ScreenError("screen_paths needs out_csv or workdir")
        workdir = Path(out_csv).parent / ".screen-work"
    work = workdir
    tool_dir(work)
    items: list[tuple[Path, str]] = []
    results: dict[str, ScreenResult] = {}
    order: list[str] = []
    for raw in paths_in:
        p = Path(os.path.abspath(raw))  # the runner's working folder is its sandbox folder
        order.append(str(p))
        digest = (known_sha256 or {}).get(str(p), "")
        if not digest:
            try:
                digest = hashing.sha256_file(p)
            except OSError as exc:
                results[str(p)] = ScreenResult(str(p), "", "error", error=f"cannot read: {exc}")
                continue
        items.append((p, digest))
    prompts_sha = label_prompts_sha256(thr)
    if items:
        be = make_backend(backend, run_tool=run_tool, workdir=work, ai_config=cfg)
        out = be.score(items, thr)
        for p, digest in items:
            raw_score = out.scores.get(str(p), RawScore(error="no score"))
            verdict, category, reasons = decide(raw_score, thr)
            results[str(p)] = ScreenResult(
                path=str(p),
                sha256=digest,
                verdict=verdict,
                category=category,
                nudity_score=raw_score.nudity,
                label_scores=dict(raw_score.labels),
                reasons=reasons,
                backend=out.name,
                model_ids=out.model_ids,
                model_sha256=out.model_sha256,
                label_prompts_sha256=prompts_sha,
                thresholds_sha256=thr.sha256,
                error=raw_score.error or ("; ".join(reasons) if verdict == "error" else ""),
            )
    ordered = [results[k] for k in order]
    if out_csv is not None:
        write_csv(Path(out_csv), ordered, thr)
    return ordered


def _fmt(value: float | None) -> str:
    return "" if value is None else f"{value:.6f}"


def write_csv(path: Path, results: Sequence[ScreenResult], thr: cfgmod.Thresholds) -> None:
    """``screen.csv``: one row per file, spreadsheet-safe, UTF-8 with BOM, CRLF line ends."""
    from forensic_analyze.csvsafe import csv_cell  # noqa: PLC0415 - shared CSV safety rules

    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.tmp")
    with open(tmp, "w", encoding="utf-8-sig", newline="") as fh:
        w = csv.writer(fh, lineterminator="\r\n")
        w.writerow(CSV_COLUMNS)
        for r in results:
            row: dict[str, Any] = {
                "path": r.path,
                "sha256": r.sha256,
                "verdict": r.verdict,
                "category": r.category,
                "nudity_score": _fmt(r.nudity_score),
                "reasons": "; ".join(r.reasons),
                "backend": r.backend,
                "nudenet_model_id": r.model_ids.get("nudenet", ""),
                "nudenet_model_sha256": r.model_sha256.get("nudenet", ""),
                "siglip_model_id": r.model_ids.get("siglip", ""),
                "siglip_model_sha256": r.model_sha256.get("siglip", ""),
                "label_prompts_sha256": r.label_prompts_sha256,
                "thresholds_sha256": r.thresholds_sha256 or thr.sha256,
                "thresholds": thr.compact(),
                "error": r.error,
                "label": f"{AI_LABEL} triage, not evidence",
            }
            for label in cfgmod.LABELS:
                row[f"score_{label.replace(' ', '_')}"] = _fmt(r.label_scores.get(label))
            w.writerow([csv_cell(row[c]) for c in CSV_COLUMNS])
    tmp.replace(path)


def read_verdicts(csv_path: str | os.PathLike[str]) -> dict[str, str]:
    """``{sha256: verdict}`` from a ``screen.csv``. Used to gate ``evidence-describe``."""
    out: dict[str, str] = {}
    with open(csv_path, encoding="utf-8-sig", newline="") as fh:
        for row in csv.DictReader(fh):
            digest = (row.get("sha256") or "").strip().lstrip("'")
            verdict = (row.get("verdict") or "").strip()
            if len(digest) == 64:
                # The most cautious verdict wins if a hash appears twice.
                if out.get(digest) in {"flagged", "error"}:
                    continue
                out[digest] = verdict
    return out


def summarise(results: Sequence[ScreenResult]) -> dict[str, int]:
    counts = {"screened": len(results), "cleared": 0, "flagged": 0, "error": 0}
    for r in results:
        counts[r.verdict] = counts.get(r.verdict, 0) + 1
    return counts


# ---------------------------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------------------------


def _screenable(p: Path) -> bool:
    from airlock_ai.video import VIDEO_EXTENSIONS  # noqa: PLC0415 - avoid an import cycle

    return p.suffix.lower() in IMAGE_EXTENSIONS | VIDEO_EXTENSIONS


def screen_files(
    files: Sequence[Path],
    out_csv: Path,
    thr: cfgmod.Thresholds,
    *,
    backend: str | None,
    workdir: Path,
    run_tool: RunTool | None = None,
) -> list[ScreenResult]:
    """Images in one batch, then each video frame by frame; one CSV for all of them."""
    from airlock_ai import video  # noqa: PLC0415 - avoid an import cycle

    tool = run_tool or sandbox_runner(workdir)
    vids = [p for p in files if p.suffix.lower() in video.VIDEO_EXTENSIONS]
    imgs = [p for p in files if p not in vids]
    results = screen_paths(imgs, None, thr, backend=backend, run_tool=tool, workdir=workdir)
    for v in vids:
        vp = Path(os.path.abspath(v))
        try:
            digest = hashing.sha256_file(vp)
        except OSError as exc:
            results.append(ScreenResult(str(vp), "", "error", error=f"cannot read: {exc}"))
            continue
        results.append(video.screen_video(vp, digest, tool, workdir, thr, backend=backend).result)
    write_csv(out_csv, results, thr)
    return results


def _collect(inputs: Sequence[str], recursive: bool) -> list[Path]:
    found: list[Path] = []
    for raw in inputs:
        p = Path(raw)
        if p.is_dir():
            walker = p.rglob("*") if recursive else p.iterdir()
            found += sorted(f for f in walker if f.is_file() and _screenable(f))
        else:
            found.append(p)
    return found


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog=TOOL,
        description=(
            "Score images and videos for sexual and violent content with local classifiers. Writes "
            "screen.csv with scores and a verdict; never shows the images."
        ),
    )
    ap.add_argument("inputs", nargs="+", help="image or video files, or folders")
    ap.add_argument("-o", "--output", required=True, help="where to write screen.csv")
    ap.add_argument("-r", "--recursive", action="store_true", help="look inside sub-folders")
    ap.add_argument("--thresholds", help="thresholds file (default /etc/airlock/...)")
    ap.add_argument("--backend", help="triage (default) or stub:FILE (tests only)")
    args = ap.parse_args(argv)
    missing = [p for p in args.inputs if not Path(p).exists()]
    if missing:
        print(f"evidence-screen: not found: {missing[0]}. Check the path.", file=sys.stderr)
        return 2
    try:
        thr = cfgmod.load_thresholds(args.thresholds)
        files = _collect(args.inputs, args.recursive)
        if not files:
            print(
                "evidence-screen: no image or video files found. Check the folder.",
                file=sys.stderr,
            )
            return 2
        out = Path(args.output)
        work = Path(tempfile.mkdtemp(prefix="airlock-screen-"))
        try:
            results = screen_files(files, out, thr, backend=args.backend, workdir=work)
        finally:
            _rmtree_quiet(work)
    except (cfgmod.ConfigError, ScreenError, proc.ToolError) as exc:
        print(f"evidence-screen: {exc}.", file=sys.stderr)
        return 1
    counts = summarise(results)
    with contextlib.suppress(OSError):
        sessionlog.log_event(
            TOOL, "screen_done", csv=str(out), thresholds_sha256=thr.sha256, **counts
        )
    print(
        f"Screened {counts['screened']} files: {counts['cleared']} not flagged by these models "
        f"at these thresholds, {counts['flagged']} flagged, {counts['error']} not screened. "
        f"Results: {out}"
    )
    if counts["flagged"]:
        print(
            "Flagged files are not described and must not be opened. If you suspect child "
            "sexual abuse material, stop and run forensic-escalate."
        )
    return 0 if counts["error"] == 0 else 4


def _rmtree_quiet(path: Path) -> None:
    import shutil  # noqa: PLC0415

    shutil.rmtree(path, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
