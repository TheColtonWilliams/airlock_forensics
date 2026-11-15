"""Video screening covers the whole video or the video is not cleared (finding 7).

Test videos are generated here from plain colour fields; the "flag" is a stub score keyed to
the colour red, a test value and not a property of the picture.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

from airlock_ai import config as cfgmod
from airlock_ai import video
from airlock_ai.screen import RawScore, ScreenResult, decide

NEEDS_FFMPEG = pytest.mark.skipif(
    shutil.which("ffmpeg") is None or shutil.which("ffprobe") is None, reason="needs ffmpeg"
)
NEUTRAL = Path(__file__).resolve().parents[1] / "fixtures" / "ai" / "neutral"


def _thr(**video_over: Any) -> cfgmod.Thresholds:
    return cfgmod.thresholds_from_dict({"video": video_over} if video_over else {})


# --- pure coverage arithmetic --------------------------------------------------------------


def test_interval_stretches_to_cover_a_long_video():
    thr = _thr()
    assert video.plan_interval(None, thr) == 2
    assert video.plan_interval(60.0, thr) == 2  # short videos keep one frame every 2 s
    two_hours = video.plan_interval(7200.0, thr)
    assert two_hours == pytest.approx(7200 / 898)
    # The planned frames reach the end of the video within the budget.
    n = int(7200 // two_hours) + 1
    assert n <= thr.max_frames and (n - 1) * two_hours >= 7200 - two_hours


def test_old_sampling_of_a_two_hour_video_is_not_complete():
    # What the old sampler did: 900 frames, one every 2 s, so it stopped at about 30 minutes.
    times = [2.0 * i for i in range(900)]
    cov = video.check_coverage(times, 900, 2.0, 7200.0, overflow=True)
    assert not cov.complete and "runs past" in cov.reason
    cov = video.check_coverage(times, 900, 2.0, 7200.0, overflow=False)
    assert not cov.complete and "frames stop at 1798.0 s of 7200.0 s" in cov.reason


def test_coverage_rules():
    full = video.check_coverage([0.0, 8.0, 16.0], 900, 8.0, 24.0, overflow=False)
    assert full.complete and (full.start_s, full.end_s) == (0.0, 16.0)
    assert "covering 0.0 to 16.0 s of 24.0 s" in full.describe()
    err = video.check_coverage([0.0, 2.0], 900, 2.0, 4.0, overflow=False, ffmpeg_error="exit 1")
    assert not err.complete and "ffmpeg stopped" in err.reason
    unknown = video.check_coverage([0.0, 2.0, 4.0], 3, 2.0, None, overflow=True)
    assert not unknown.complete and "length is unknown" in unknown.reason
    ended = video.check_coverage([0.0, 2.0], 3, 2.0, None, overflow=False)
    assert ended.complete  # ffmpeg reached the end of the stream before the limit
    # Missing frame times fall back to the planned spacing.
    est = video.check_coverage([-1.0, -1.0], 900, 2.0, 30.0, overflow=False)
    assert not est.complete


def test_probe_from_json_separates_cover_art():
    data = {
        "format": {"duration": "180.0", "format_name": "mov,mp4,m4a"},
        "streams": [
            {"index": 0, "codec_type": "audio", "duration": "180.0"},
            {"index": 1, "codec_type": "video", "disposition": {"attached_pic": 1}},
            {"index": 2, "codec_type": "video", "duration": "60.0"},
        ],
    }
    p = video.probe_from_json(data)
    assert (p.video_streams, p.attached_pics, p.duration_s) == ([2], [1], 60.0)
    p = video.probe_from_json({"format": {"duration": "12.5"}, "streams": []})
    assert (p.video_streams, p.duration_s) == ([], 12.5)


def _res(verdict: str, **kw: Any) -> ScreenResult:
    return ScreenResult("f", "0" * 64, verdict, nudity_score=0.0, **kw)


def test_aggregate_never_clears_incomplete_coverage():
    thr = _thr()
    frames = [video.Frame(Path("a"), 0.0, "interval"), video.Frame(Path("b"), 2.0, "interval")]
    labels = dict.fromkeys(cfgmod.LABELS, 0.01)
    ok = [_res("cleared", label_scores=labels), _res("cleared", label_scores=labels)]
    cov = video.Coverage(2.0, 3600.0, 0.0, 2.0, 2, complete=False, reason="frames stop at 2 s")
    vs = video.aggregate(Path("v.mp4"), "1" * 64, frames, ok, thr, cov)
    assert vs.result.verdict == "error" and "not fully screened" in vs.result.error
    assert "not fully screened" in vs.note()
    flagged = [_res("cleared", label_scores=labels), _res("flagged", category="violent")]
    vs = video.aggregate(Path("v.mp4"), "1" * 64, frames, flagged, thr, cov)
    assert vs.result.verdict == "flagged"  # a flag found in the screened part still flags
    whole = video.Coverage(2.0, 3.0, 0.0, 2.0, 2)
    assert video.aggregate(Path("v.mp4"), "1" * 64, frames, ok, thr, whole).result.cleared


# --- real ffmpeg -----------------------------------------------------------------------------


def _runner(argv: list[str], **kw: Any) -> subprocess.CompletedProcess[str]:
    del kw
    return subprocess.run([str(a) for a in argv], capture_output=True, text=True, check=False)


def _colour_video(out: Path, *segments: tuple[str, int]) -> Path:
    args = ["ffmpeg", "-nostdin", "-loglevel", "error", "-y"]
    for colour, seconds in segments:
        args += ["-f", "lavfi", "-i", f"color=c={colour}:s=64x64:d={seconds}:r=5"]
    n = len(segments)
    chain = "".join(f"[{i}:v]" for i in range(n)) + f"concat=n={n}:v=1:a=0,format=yuv420p[v]"
    args += ["-filter_complex", chain, "-map", "[v]", "-c:v", "libx264", str(out)]
    subprocess.run(args, check=True)
    return out


def _red_screener(paths, out_csv, thr, **kw) -> list[ScreenResult]:
    """Stub classifier: a mostly red frame scores violence 0.9 (a test value)."""
    from PIL import Image  # noqa: PLC0415

    del out_csv, kw
    out = []
    for p in paths:
        with Image.open(p) as im:
            r, g, b = im.convert("RGB").resize((1, 1)).getpixel((0, 0))
        labels = dict.fromkeys(cfgmod.LABELS, 0.01)
        if r > 150 and g < 80 and b < 80:
            labels["violence"] = 0.9
        verdict, category, reasons = decide(RawScore(nudity=0.0, labels=labels), thr)
        out.append(ScreenResult(str(p), "0" * 64, verdict, category, 0.0, labels, reasons, "stub"))
    return out


@NEEDS_FFMPEG
def test_content_after_the_frame_budget_is_screened(tmp_path: Path, monkeypatch):
    pytest.importorskip("PIL")
    monkeypatch.setattr(video, "screen_paths", _red_screener)
    # 12 s blue then 8 s red. With 5 frames at one every 2 s the old sampler stopped at 8 s
    # and cleared it. Scene-change frames are off so only the interval frames count.
    clip = _colour_video(tmp_path / "late.mp4", ("blue", 12), ("red", 8))
    thr = _thr(max_frames=5, scene_threshold=1.0)
    vs = video.screen_video(clip, "a" * 64, _runner, tmp_path / "w", thr)
    assert vs.result.verdict == "flagged", vs.result
    assert vs.coverage is not None and vs.coverage.complete
    assert vs.coverage.interval_s == pytest.approx(20 / 3)
    assert vs.coverage.end_s >= 13.0
    assert "of 20.0 s" in vs.note() and "flagged at 13.3 s" in vs.note()
    assert not (tmp_path / "w" / f"frames-{'a' * 16}").exists()  # frames are temporary


@NEEDS_FFMPEG
def test_video_longer_than_its_recorded_length_is_not_cleared(tmp_path: Path, monkeypatch):
    pytest.importorskip("PIL")
    monkeypatch.setattr(video, "screen_paths", _red_screener)
    clip = _colour_video(tmp_path / "calm.mp4", ("blue", 20))
    thr = _thr(max_frames=5, scene_threshold=1.0)
    honest = video.screen_video(clip, "b" * 64, _runner, tmp_path / "w", thr)
    assert honest.result.cleared, honest.result
    lying = video.probe_video(clip, _runner)
    lying.duration_s = 4.0  # a header that understates the length
    vs = video.screen_video(clip, "b" * 64, _runner, tmp_path / "w", thr, probed=lying)
    assert vs.result.verdict == "error"
    assert "runs past its recorded length" in vs.result.error
    two = video.probe_video(clip, _runner)
    two.video_streams = [0, 5]
    vs = video.screen_video(clip, "b" * 64, _runner, tmp_path / "w", thr, probed=two)
    assert vs.result.verdict == "error" and "2 video streams" in vs.result.error


@NEEDS_FFMPEG
def test_cover_art_is_screened(tmp_path: Path, monkeypatch):
    pytest.importorskip("PIL")
    monkeypatch.setattr(video, "screen_paths", _red_screener)
    m4a = tmp_path / "song.m4a"
    subprocess.run(
        [
            "ffmpeg", "-nostdin", "-loglevel", "error", "-y",
            "-i", str(NEUTRAL / "tone-440hz.wav"), "-i", str(NEUTRAL / "landscape.png"),
            "-map", "0:a", "-map", "1:v", "-c:a", "aac", "-c:v", "png",
            "-disposition:v:0", "attached_pic", str(m4a),
        ],
        check=True,
    )  # fmt: skip
    info = video.probe_video(m4a, _runner)
    assert info.attached_pics and not info.video_streams
    vs = video.screen_video(m4a, "c" * 64, _runner, tmp_path / "w", _thr())
    assert vs.frames_screened == 1 and vs.result.cleared, vs.result


@NEEDS_FFMPEG
def test_clip_shorter_than_the_interval_is_still_screened(tmp_path: Path, monkeypatch):
    """A 0.5 s clip gets no frame from fps=1/2; its first frame is screened instead."""
    pytest.importorskip("PIL")
    monkeypatch.setattr(video, "screen_paths", _red_screener)
    thr = _thr(scene_threshold=1.0)
    red = video.screen_video(
        _colour_video(tmp_path / "red.mp4", ("red", 0.5)), "b" * 64, _runner, tmp_path / "w", thr
    )
    assert red.result.verdict == "flagged", red.result
    blue = video.screen_video(
        _colour_video(tmp_path / "blue.mp4", ("blue", 0.5)), "c" * 64, _runner, tmp_path / "w", thr
    )
    assert blue.result.cleared, blue.result
    assert blue.coverage is not None and blue.coverage.complete
