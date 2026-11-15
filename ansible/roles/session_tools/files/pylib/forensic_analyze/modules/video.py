"""Module ``video`` (task 4C.9): export, mediainfo and ffprobe metadata, frame screening,
and for cleared videos a transcript of the audio track and a description.

Frame screening (``airlock_ai.video``): frames over the whole length (one every 2 s, or
further apart for a video too long for the frame limit) plus scene-change frames and attached
pictures, each scored like an image; any flagged frame flags the video, and the flagged
timestamps and the covered span go in the screening row. A video whose frames do not cover its
whole length is not cleared. Flagged and unscreened videos are deleted from the export folder
at once; they are never transcribed or described. Frames are temporary and deleted right after
scoring.
"""

from __future__ import annotations

from collections import Counter
from typing import Any

from airlock_ai import audio as aiaudio
from airlock_ai import config as aicfg
from airlock_ai import llm
from airlock_ai import video as aivideo
from airlock_ai.describe import Describer, DescribeResult, ProcessOutput
from forensic_analyze import media
from forensic_analyze.api import ModuleContext


class VideoModule(media.MediaModule):
    name = "video"
    title = "Video"
    order = 70
    category = "video"
    kind = "video"
    extensions = aivideo.VIDEO_EXTENSIONS
    max_bytes = 8 * 1024**3
    description = "Video metadata, frame screening, transcripts, and descriptions."

    def metadata(self, ctx: ModuleContext, item: media.MediaItem) -> None:
        media.mediainfo_ffprobe(ctx, item, "video")

    def metadata_rows(self, ctx: ModuleContext, item: media.MediaItem) -> list[dict[str, Any]]:
        if not item.meta_record:
            return []
        name, dur, streams = media.av_summary(item.meta)
        length = f", {dur:.1f} s" if dur is not None else ""
        return [
            media.metadata_row(
                ctx,
                item,
                self.category,
                self.kind,
                f"Video metadata: {name}{length}; {streams}.",
                "ffprobe",
            )
        ]

    def screen_batch(
        self, ctx: ModuleContext, items: list[media.MediaItem], thr: aicfg.Thresholds
    ) -> None:
        run_tool = media.ctx_runner(ctx)
        for item in items:
            media.check_escalated(ctx)
            media.need_path(item)
            fp = item.meta.get("ffprobe") if item.meta else None
            vs = aivideo.screen_video(
                item.path.resolve(),
                item.sha256,
                run_tool,
                ctx.workdir / "screen",
                thr,
                probed=aivideo.probe_from_json(fp) if isinstance(fp, dict) else None,
            )
            item.screen = vs.result
            item.screen_note = vs.note()

    def kept_extras(
        self, ctx: ModuleContext, item: media.MediaItem, counts: Counter[str]
    ) -> list[dict[str, Any] | DescribeResult]:
        """Transcript of a cleared video's audio track (speech model only, no server)."""
        path = media.need_path(item)
        work = ctx.workdir / "ai-work"
        wav = aivideo.extract_audio(path, work / f"{path.name}.wav", media.ctx_runner(ctx))
        if wav is None:
            return []
        try:
            tr = aiaudio.transcribe(wav, media.ctx_runner(ctx), work)
        finally:
            wav.unlink(missing_ok=True)
        item.meta["_transcript"] = tr
        counts["transcripts"] += 1 if tr.text else 0
        res = aiaudio.transcript_results(path, item.sha256, tr, None, DescribeResult, ProcessOutput)
        return list(res.results)

    def describe(
        self, ctx: ModuleContext, item: media.MediaItem, d: Describer, counts: Counter[str]
    ) -> list[DescribeResult]:
        path = media.need_path(item)
        out: list[DescribeResult] = []
        tr = item.meta.get("_transcript")
        if tr is not None and tr.text:
            out.append(
                d.text(
                    tr.text,
                    str(path),
                    item.sha256,
                    kind="audio_summary",
                    prompt_id="summarize_transcript",
                    data_kind="transcript",
                )
            )
        try:
            out.append(
                aivideo.describe_video(
                    path, item.sha256, media.ctx_runner(ctx, gpu=True), d, ctx.workdir / "ai-work"
                )
            )
        except llm.LlmError as exc:
            out.append(
                DescribeResult(
                    str(path), item.sha256, "video", "error", tier=d.tier, detail=str(exc)
                )
            )
        return out


MODULE = VideoModule()
