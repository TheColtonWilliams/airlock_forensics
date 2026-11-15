"""Video screening and description (task 4B.7).

Screening covers the whole video or the video is not cleared. ``ffprobe`` reads the duration
and the streams first. ``ffmpeg`` then takes one frame every ``interval`` seconds from the
video stream, where ``interval`` is ``frame_interval_s`` (default 2) or, for a video too long
for ``max_frames`` frames at that rate, the duration divided by the frame budget: a two-hour
video at the default 900 frames is sampled every 8 s, from start to end. Scene-change frames
(``select=gt(scene,0.4)``) fill what is left of the budget. Attached pictures (cover art) are
screened as frames too.

Each frame goes through the same classifiers as an image. Any flagged frame flags the whole
video, with the timestamps of the flagged frames. The video is **not cleared** (verdict
``error``) when no frame could be read, a frame could not be scored, or the frames do not
cover the whole video: ``ffmpeg`` stopped with an error, the video holds more frames than its
recorded duration allows (it would need more than ``max_frames``), the last frame is more
than one interval short of the end, the duration is unknown and the frame budget ran out, or
the file has more than one video stream. The covered time span goes in the screening row.
Frames are temporary copies: they are deleted as soon as they are scored, flagged or not, and
are never shown or kept.

Description: only a cleared video, through ``llama-mtmd-cli`` with native video input, the
fixed ``describe_video`` prompt, temperature 0, and a fixed seed.

Audio: ``extract_audio`` writes a 16 kHz mono WAV for ``airlock_ai.audio``.
"""

from __future__ import annotations

import json
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
MAX_ATTACHED_PICTURES = 16
# Slack for the end-of-video check: frame times are rounded to the input's frame grid.
END_TOLERANCE_S = 1.0


@dataclass
class Frame:
    path: Path
    t_seconds: float
    source: str  # interval | scene


@dataclass
class Probe:
    """What ``ffprobe`` says about a file's video content."""

    duration_s: float | None = None
    video_streams: list[int] = field(default_factory=list)  # moving-picture stream indexes
    attached_pics: list[int] = field(default_factory=list)  # cover art stream indexes
    error: str = ""


@dataclass
class Coverage:
    """Which part of the video the interval frames cover; ``complete`` False = not cleared."""

    interval_s: float
    duration_s: float | None
    start_s: float = 0.0
    end_s: float = 0.0
    frames: int = 0
    complete: bool = True
    reason: str = ""

    def describe(self) -> str:
        if not self.frames:
            return "no moving-picture stream"
        dur = f"{self.duration_s:.1f} s" if self.duration_s is not None else "unknown length"
        return (
            f"one frame every {self.interval_s:g} s, covering {self.start_s:.1f} to "
            f"{self.end_s:.1f} s of {dur}"
        )


@dataclass
class Sampling:
    frames: list[Frame]
    coverage: Coverage


@dataclass
class VideoScreen:
    result: ScreenResult
    frames_screened: int = 0
    flagged_times: list[float] = field(default_factory=list)
    frame_errors: int = 0
    coverage: Coverage | None = None

    def note(self) -> str:
        """Frames screened, covered span, flagged times: text for the screening row."""
        note = f"{self.frames_screened} frames screened"
        if self.coverage is not None:
            note += f" ({self.coverage.describe()})"
            if not self.coverage.complete:
                note += f"; not fully screened: {self.coverage.reason}"
        if self.flagged_times:
            note += "; flagged at " + ", ".join(f"{t:.1f} s" for t in self.flagged_times)
        if self.frame_errors:
            note += f"; {self.frame_errors} frames could not be scored"
        return note


def probe_video(video: Path, run_tool: RunTool) -> Probe:
    """Duration and video streams from ``ffprobe``; ``error`` set when it cannot read them."""
    cp = run_tool(
        [
            "ffprobe",
            "-v",
            "error",
            "-print_format",
            "json",
            "-show_format",
            "-show_streams",
            str(video),
        ],
        timeout=600,
        extra_ro=[str(video.parent)],
    )
    try:
        data = json.loads(cp.stdout or "") if cp.returncode == 0 else None
    except ValueError:
        data = None
    if not isinstance(data, dict):
        last = ((cp.stderr or "").strip().splitlines() or ["no output"])[-1]
        return Probe(error=f"ffprobe could not read the file: {last[:200]}")
    return probe_from_json(data)


def _seconds(value: Any) -> float | None:
    try:
        v = float(value)
    except (TypeError, ValueError):
        return None
    return v if v > 0 else None


def probe_from_json(data: dict[str, Any]) -> Probe:
    """:class:`Probe` from ``ffprobe -show_format -show_streams`` JSON."""
    out = Probe()
    durations: list[float] = []
    for s in data.get("streams") or []:
        if not isinstance(s, dict) or s.get("codec_type") != "video":
            continue
        idx = int(s.get("index", 0))
        disp = s.get("disposition") if isinstance(s.get("disposition"), dict) else {}
        if int(disp.get("attached_pic", 0) or 0) == 1:
            out.attached_pics.append(idx)
            continue
        out.video_streams.append(idx)
        d = _seconds(s.get("duration"))
        if d is not None:
            durations.append(d)
    fmt = data.get("format") if isinstance(data.get("format"), dict) else {}
    # The video stream's own length when known (an audio track can run longer); else the file's.
    out.duration_s = durations[0] if durations else _seconds(fmt.get("duration"))
    return out


def plan_interval(duration_s: float | None, thresholds: cfgmod.Thresholds) -> float:
    """Seconds between interval frames: the configured rate, or slower so the whole duration
    fits in the frame budget (two frames are kept back for rounding at the ends)."""
    interval = float(thresholds.frame_interval_s)
    if duration_s is None:
        return interval
    budget = max(1, thresholds.max_frames - 2)
    return max(interval, duration_s / budget)


def check_coverage(
    times: Sequence[float],
    limit: int,
    interval: float,
    duration_s: float | None,
    *,
    overflow: bool,
    ffmpeg_error: str = "",
) -> Coverage:
    """Whether the interval frames (their times, in order) cover the whole video.

    ``overflow``: ffmpeg produced more frames than ``limit``, so the video goes on past the
    point where screening stopped. Fails closed: anything not shown to be covered is not.
    """
    n = len(times)
    known = [t for t in times if t >= 0]
    if n and len(known) == n:
        start, end = min(known), max(known)
    else:
        start, end = 0.0, max(0, n - 1) * interval
    cov = Coverage(interval, duration_s, start, end, n)
    why = ""
    if ffmpeg_error:
        why = f"ffmpeg stopped with an error after {n} frames ({ffmpeg_error})"
    elif overflow and duration_s is None:
        why = f"the length is unknown and the {limit}-frame limit ran out at {end:.1f} s"
    elif overflow:
        why = (
            f"the video runs past its recorded length of {duration_s:.1f} s: the "
            f"{limit}-frame limit ran out at {end:.1f} s"
        )
    elif duration_s is not None and duration_s - (end - start) > interval + END_TOLERANCE_S:
        why = f"frames stop at {end - start:.1f} s of {duration_s:.1f} s"
    if why:
        cov.complete, cov.reason = False, why
    return cov


def _ffmpeg_frames(  # noqa: PLR0917
    run_tool: RunTool,
    video: Path,
    out_dir: Path,
    vf: str,
    prefix: str,
    limit: int,
    stream: int | None = None,
) -> tuple[list[tuple[Path, float]], str]:
    """Frames written by one ffmpeg pass and ffmpeg's error (empty when it exited 0)."""
    tool_dir(out_dir)
    mapping = ["-map", f"0:{stream}"] if stream is not None else []
    cp = run_tool(
        [
            "ffmpeg",
            "-nostdin",
            "-hide_banner",
            "-loglevel",
            "info",
            "-i",
            str(video),
            *mapping,
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
    err = ""
    if cp.returncode != 0:
        lines = [ln for ln in (cp.stderr or "").strip().splitlines() if not _SHOWINFO.search(ln)]
        err = f"exit {cp.returncode}: {(lines or ['no output'])[-1][:200]}"
        if not files:
            raise proc.ToolError(f"ffmpeg could not read the video: {err}")
    out: list[tuple[Path, float]] = []
    for i, f in enumerate(files):
        out.append((f, times[i] if i < len(times) else -1.0))
    return out, err


def _attached_pictures(
    run_tool: RunTool, video: Path, out_dir: Path, streams: Sequence[int]
) -> list[Frame]:
    frames: list[Frame] = []
    for idx in streams:
        got, err = _ffmpeg_frames(run_tool, video, out_dir, "showinfo", f"a{idx}", 1, idx)
        if err or not got:
            raise proc.ToolError(f"ffmpeg could not read attached picture {idx}: {err}")
        frames.append(Frame(got[0][0], -1.0, "attached_pic"))
    return frames


def sample_frames(
    video: Path,
    out_dir: Path,
    run_tool: RunTool,
    thresholds: cfgmod.Thresholds,
    probed: Probe | None = None,
) -> Sampling:
    """Interval frames over the whole video, then scene-change frames, at most ``max_frames``
    in all, plus each attached picture. ``coverage`` says whether the whole video was covered.
    """
    info = probed if probed is not None else probe_video(video, run_tool)
    limit = max(1, thresholds.max_frames)
    interval = plan_interval(info.duration_s, thresholds)
    frames: list[Frame] = []
    problems: list[str] = []
    if info.error:
        problems.append(info.error)
    if len(info.attached_pics) > MAX_ATTACHED_PICTURES:
        problems.append(
            f"{len(info.attached_pics)} attached pictures (limit {MAX_ATTACHED_PICTURES})"
        )
    if len(info.video_streams) > 1:
        problems.append(f"{len(info.video_streams)} video streams; only the first is screened")
    if info.attached_pics:
        frames += _attached_pictures(
            run_tool, video, out_dir, info.attached_pics[:MAX_ATTACHED_PICTURES]
        )
    if info.video_streams or info.error:
        stream = info.video_streams[0] if info.video_streams else None
        vf = f"fps=1/{interval:.6g},showinfo"
        # Ask for one frame more than the limit: getting it proves the video goes on.
        every, err = _ffmpeg_frames(run_tool, video, out_dir, vf, "i", limit + 1, stream)
        if not every and not err:
            # A clip shorter than about half the interval gives the fps filter no frame at all;
            # take its first frame instead, so a short clip is screened rather than dropped.
            vf0 = "select=eq(n\\,0),showinfo"
            every, err = _ffmpeg_frames(run_tool, video, out_dir, vf0, "f", 1, stream)
        overflow = len(every) > limit
        for extra, _t in every[limit:]:
            extra.unlink(missing_ok=True)
        every = every[:limit]
        cov = check_coverage(
            [t for _p, t in every],
            limit,
            interval,
            info.duration_s,
            overflow=overflow,
            ffmpeg_error=err,
        )
        frames += [Frame(p, t, "interval") for p, t in every]
        left = limit - len(every)
        if left > 0 and every:
            scene = thresholds.scene_threshold
            vf = f"select=gt(scene\\,{scene:g}),showinfo"
            got, _err = _ffmpeg_frames(run_tool, video, out_dir, vf, "s", left, stream)
            frames += [Frame(p, t, "scene") for p, t in got]
    else:
        cov = Coverage(interval, info.duration_s)  # cover art only: nothing moves
    if problems:
        cov.complete = False
        cov.reason = "; ".join([*problems, *([cov.reason] if cov.reason else [])])
    return Sampling(frames, cov)


def screen_video(
    video: Path,
    sha256: str,
    run_tool: RunTool,
    workdir: Path,
    thresholds: cfgmod.Thresholds | None = None,
    *,
    backend: str | None = None,
    ai_config: dict[str, Any] | None = None,
    probed: Probe | None = None,
) -> VideoScreen:
    """Screen one video (see the module docstring). ``probed``: ffprobe output already read."""
    thr = thresholds or cfgmod.load_thresholds()
    frames_dir = workdir / f"frames-{sha256[:16]}"
    try:
        try:
            sampling = sample_frames(video, frames_dir, run_tool, thr, probed)
            frames = sampling.frames
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
                    error="no frame could be read"
                    + ("" if sampling.coverage.complete else f"; {sampling.coverage.reason}"),
                    thresholds_sha256=thr.sha256,
                ),
                coverage=sampling.coverage,
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
    return aggregate(video, sha256, frames, per_frame, thr, sampling.coverage)


def aggregate(  # noqa: PLR0917
    video: Path,
    sha256: str,
    frames: Sequence[Frame],
    per_frame: Sequence[ScreenResult],
    thr: cfgmod.Thresholds,
    coverage: Coverage | None = None,
) -> VideoScreen:
    """Combine frame verdicts: any flag flags the video; any frame error, or frames that do
    not cover the whole video, keep it from clearing."""
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
    elif errors or (coverage is not None and not coverage.complete):
        verdict, category = "error", ""
        reasons = [f"{errors} of {len(frames)} frames could not be scored"] if errors else []
        if coverage is not None and not coverage.complete:
            reasons.append(f"not fully screened: {coverage.reason}")
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
    if verdict == "flagged" and coverage is not None and not coverage.complete:
        result.reasons.append(f"not fully screened: {coverage.reason}")
    return VideoScreen(result, len(frames), sorted(flagged_times), errors, coverage)


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
