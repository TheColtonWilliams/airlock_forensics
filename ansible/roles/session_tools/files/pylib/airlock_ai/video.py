"""Video screening and description (task 4B.7).

Screening: ``ffmpeg`` takes one frame every ``frame_interval_s`` seconds (default 2) plus every
scene-change frame (``select=gt(scene,0.4)``), up to ``max_frames``. Each frame goes through
the same classifiers as an image. Any flagged frame flags the whole video, with the timestamps
of the flagged frames. A video with no readable frame, or with a frame that could not be
scored, is not cleared. Frames are temporary copies: they are deleted as soon as they are
scored, flagged or not, and are never shown or kept.

Description: only a cleared video, through ``llama-mtmd-cli`` with native video input, the
fixed ``describe_video`` prompt, temperature 0, and a fixed seed.

Audio: ``extract_audio`` writes a 16 kHz mono WAV for ``airlock_ai.audio``.
"""

from __future__ import annotations

import re
import shutil
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from airlock_ai import config as cfgmod
from airlock_ai import llm, probe
from airlock_ai.screen import RawScore, ScreenResult, decide, label_prompts_sha256, screen_paths
from airlock_ai.tools import RunTool, tool_dir
from airlock_common import proc

VIDEO_EXTENSIONS = frozenset(
    {
        ".mp4",
        ".m4v",
        ".mov",
        ".avi",
        ".mkv",
        ".webm",
        ".wmv",
        ".mpg",
        ".mpeg",
        ".3gp",
        ".flv",
        ".ts",
        ".mts",
        ".m2ts",
    }
)
_SHOWINFO = re.compile(r"\bn:\s*(\d+)\s+pts:\s*-?\d+\s+pts_time:\s*(-?[0-9.]+)")
NO_AS_LIMIT_BYTES = 256 * 1024**3  # model runtimes reserve large address ranges


@dataclass
class Frame:
    path: Path
    t_seconds: float
    source: str  # interval | scene


@dataclass
class VideoScreen:
    result: ScreenResult
    frames_screened: int = 0
    flagged_times: list[float] = field(default_factory=list)
    frame_errors: int = 0


def _ffmpeg_frames(  # noqa: PLR0917
    run_tool: RunTool, video: Path, out_dir: Path, vf: str, prefix: str, limit: int
) -> list[tuple[Path, float]]:
    tool_dir(out_dir)
    cp = run_tool(
        [
            "ffmpeg",
            "-nostdin",
            "-hide_banner",
            "-loglevel",
            "info",
            "-i",
            str(video),
            "-an",
            "-sn",
            "-dn",
            "-vf",
            vf,
            "-fps_mode",
            "vfr",
            "-frames:v",
            str(limit),
            "-f",
            "image2",
            str(out_dir / f"{prefix}_%06d.png"),
        ],
        timeout=3600,
        extra_ro=[str(video.parent)],
    )
    times = [float(m.group(2)) for m in _SHOWINFO.finditer(cp.stderr or "")]
    files = sorted(out_dir.glob(f"{prefix}_*.png"))
    if cp.returncode != 0 and not files:
        last = ((cp.stderr or "").strip().splitlines() or ["no output"])[-1]
        raise proc.ToolError(f"ffmpeg could not read the video: {last[:200]}")
    out: list[tuple[Path, float]] = []
    for i, f in enumerate(files):
        out.append((f, times[i] if i < len(times) else -1.0))
    return out


def sample_frames(
    video: Path, out_dir: Path, run_tool: RunTool, thresholds: cfgmod.Thresholds
) -> list[Frame]:
    """Interval frames plus scene-change frames, at most ``max_frames`` in all."""
    limit = max(1, thresholds.max_frames)
    interval = thresholds.frame_interval_s
    every = _ffmpeg_frames(run_tool, video, out_dir, f"fps=1/{interval:g},showinfo", "i", limit)
    frames = [Frame(p, t, "interval") for p, t in every]
    left = limit - len(frames)
    if left > 0:
        scene = thresholds.scene_threshold
        vf = f"select=gt(scene\\,{scene:g}),showinfo"
        frames += [
            Frame(p, t, "scene") for p, t in _ffmpeg_frames(run_tool, video, out_dir, vf, "s", left)
        ]
    return frames


def screen_video(
    video: Path,
    sha256: str,
    run_tool: RunTool,
    workdir: Path,
    thresholds: cfgmod.Thresholds | None = None,
    *,
    backend: str | None = None,
    ai_config: dict[str, Any] | None = None,
) -> VideoScreen:
    thr = thresholds or cfgmod.load_thresholds()
    frames_dir = workdir / f"frames-{sha256[:16]}"
    try:
        try:
            frames = sample_frames(video, frames_dir, run_tool, thr)
        except proc.ToolError as exc:
            return VideoScreen(
                ScreenResult(
                    str(video), sha256, "error", error=str(exc), thresholds_sha256=thr.sha256
                )
            )
        if not frames:
            return VideoScreen(
                ScreenResult(
                    str(video),
                    sha256,
                    "error",
                    error="no frame could be read",
                    thresholds_sha256=thr.sha256,
                )
            )
        per_frame = screen_paths(
            [f.path for f in frames],
            None,
            thr,
            backend=backend,
            run_tool=run_tool,
            workdir=workdir / "screen",
            ai_config=ai_config,
        )
    finally:
        shutil.rmtree(frames_dir, ignore_errors=True)
    return aggregate(video, sha256, frames, per_frame, thr)


def aggregate(
    video: Path,
    sha256: str,
    frames: Sequence[Frame],
    per_frame: Sequence[ScreenResult],
    thr: cfgmod.Thresholds,
) -> VideoScreen:
    """Combine frame verdicts: any flag flags the video; any error keeps it from clearing."""
    nudity = 0.0
    labels: dict[str, float] = {}
    reasons: list[str] = []
    flagged_times: list[float] = []
    errors = 0
    categories: set[str] = set()
    for frame, res in zip(frames, per_frame, strict=True):
        if res.verdict == "error":
            errors += 1
            continue
        nudity = max(nudity, res.nudity_score or 0.0)
        for k, v in res.label_scores.items():
            labels[k] = max(labels.get(k, 0.0), v)
        if res.flagged:
            flagged_times.append(round(frame.t_seconds, 3))
            categories.update(c for c in res.category.split("+") if c)
            reasons += [f"at {frame.t_seconds:.1f} s: {r}" for r in res.reasons]
    first = next((r for r in per_frame if r.verdict != "error"), per_frame[0])
    if flagged_times:
        verdict = "flagged"
        category = "+".join(c for c in ("sexual", "violent") if c in categories)
    elif errors:
        verdict, category = "error", ""
        reasons = [f"{errors} of {len(frames)} frames could not be scored"]
    else:
        verdict, category, _ = decide(RawScore(nudity=nudity, labels=labels), thr)
        if verdict != "cleared":  # cannot happen when no frame flagged; stay cautious
            verdict = "flagged"
    result = ScreenResult(
        path=str(video),
        sha256=sha256,
        verdict=verdict,
        category=category,
        nudity_score=nudity if per_frame else None,
        label_scores=labels,
        reasons=reasons,
        backend=first.backend,
        model_ids=first.model_ids,
        model_sha256=first.model_sha256,
        label_prompts_sha256=label_prompts_sha256(thr),
        thresholds_sha256=thr.sha256,
        error="" if verdict != "error" else "; ".join(reasons),
    )
    return VideoScreen(result, len(frames), sorted(flagged_times), errors)


# ---------------------------------------------------------------------------------------------
# Description through llama-mtmd-cli
# ---------------------------------------------------------------------------------------------


def tier_models(choice: dict[str, Any] | None = None) -> tuple[str, str, int, str]:
    """(model path, mmproj path, GPU layers, tier) from ``ai-probe --write`` or a fresh probe."""
    doc = choice or probe.load_choice()
    if doc is None:
        doc = probe.choose_tier().to_dict()
    model = mmproj = ""
    for m in doc.get("models", []):
        if m.get("role") == "mmproj":
            mmproj = str(m.get("path", ""))
        elif m.get("role", "model") == "model":
            model = str(m.get("path", ""))
    if not model or not mmproj:
        raise llm.LlmError("no model tier is staged for video description (run ai-probe)")
    return model, mmproj, int(doc.get("n_gpu_layers", 0)), str(doc.get("tier", ""))


def describe_video(
    video: Path,
    sha256: str,
    run_tool: RunTool,
    describer: Any,
    workdir: Path,
    *,
    choice: dict[str, Any] | None = None,
) -> Any:
    """Describe one cleared video. Returns a ``describe.DescribeResult``."""
    from airlock_ai.describe import DescribeResult  # noqa: PLC0415 - avoid an import cycle

    cfg = describer.cfg
    model, mmproj, ngl, tier = tier_models(choice)
    prompt = describer.prompt("describe_video")
    exe = str(Path(cfg["llama"]["prefix"]) / "bin" / "llama-mtmd-cli")
    tool_dir(workdir)
    cp = run_tool(
        [
            exe,
            "-m",
            model,
            "--mmproj",
            mmproj,
            str(cfg["llama"].get("video_flag", "--video")),
            str(video),
            "-p",
            prompt.text,
            "--temp",
            "0",
            "--top-k",
            "1",
            "--seed",
            str(describer.seed),
            "-n",
            str(describer.max_tokens),
            "-ngl",
            str(ngl),
        ],
        timeout=3600,
        memory_bytes=NO_AS_LIMIT_BYTES,
        extra_ro=sorted({str(video.parent), str(Path(model).parent), str(Path(mmproj).parent)}),
    )
    base = DescribeResult(
        path=str(video),
        sha256=sha256,
        kind="video",
        status="error",
        model_id=Path(model).name,
        model_sha256=llm.file_sha256(model),
        mmproj_sha256=llm.file_sha256(mmproj),
        prompt_id=prompt.prompt_id,
        prompt_sha256=prompt.sha256,
        tier=tier,
        seed=describer.seed,
    )
    if cp.returncode != 0:
        last = ((cp.stderr or "").strip().splitlines() or ["no output"])[-1]
        base.detail = f"llama-mtmd-cli exited {cp.returncode}: {last[:200]}"
        return base
    text = (cp.stdout or "").strip()
    if llm.is_refusal(text):
        base.status = "model_declined"
        base.detail = f"model reply: {text[:200]!r}" if text else "empty reply"
        return base
    base.status = "described"
    base.description = text
    return base


def extract_audio(video: Path, out_wav: Path, run_tool: RunTool) -> Path | None:
    """The first audio track as 16 kHz mono WAV, or None if the video has no audio."""
    tool_dir(out_wav.parent)
    cp = run_tool(
        [
            "ffmpeg",
            "-nostdin",
            "-hide_banner",
            "-loglevel",
            "error",
            "-i",
            str(video),
            "-vn",
            "-sn",
            "-dn",
            "-ac",
            "1",
            "-ar",
            "16000",
            "-f",
            "wav",
            "-y",
            str(out_wav),
        ],
        timeout=3600,
        extra_ro=[str(video.parent)],
    )
    if cp.returncode != 0 or not out_wav.exists() or out_wav.stat().st_size <= 44:
        out_wav.unlink(missing_ok=True)
        return None
    return out_wav
