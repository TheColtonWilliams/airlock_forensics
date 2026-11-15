"""Module ``audio`` (task 4C.10): export, metadata, faster-whisper transcript, text summary.

Audio is not screened by the image classifiers (they see pictures, not sound). Each file is
exported read-only and read by mediainfo and ffprobe, and its content type decides what
happens next (:func:`forensic_analyze.media.av_route`):

* sound only: kept, transcribed;
* sound with embedded pictures (ID3 APIC or MP4 ``covr`` cover art): each picture is
  extracted and screened (route ``embedded``, row text "embedded picture screened"). The file
  is kept only if every picture clears; a picture that cannot be extracted or scored keeps
  the whole file from being kept ("Not screened (embedded picture could not be screened)"),
  since the sound cannot be kept apart from the picture without changing the file;
* a moving-picture stream (a video renamed ``.m4a``): screened like any video, frames over
  its whole length, and kept only if cleared ("content type mismatch"). A cleared one is then
  handled like any cleared sound file: its sound is transcribed and the transcript
  summarised, as the ``video`` module does for a cleared video. Its pictures are never
  described here;
* a still picture under an audio name: screened like an image, kept only if cleared, and
  neither transcribed nor described;
* ffprobe cannot read it: not kept, unless its first bytes show a picture, which is then
  screened.

A kept file is transcribed by faster-whisper ``small`` on the CPU (``airlock_ai.audio``,
sandboxed, no network), and the transcript is summarised by the local model with the fixed
``summarize_transcript`` prompt.
Transcript and summary are AI-generated; the transcript is evidence-derived text and reaches
the model only inside a delimited data block.
"""

from __future__ import annotations

from collections import Counter
from typing import Any

from airlock_ai import audio as aiaudio
from airlock_ai.describe import Describer, DescribeResult, ProcessOutput
from airlock_common import proc
from forensic_analyze import media
from forensic_analyze.api import ModuleContext


class AudioModule(media.MediaModule):
    name = "audio"
    title = "Audio"
    order = 80
    category = "audio"
    kind = "audio"
    extensions = aiaudio.AUDIO_EXTENSIONS
    max_bytes = 2 * 1024**3
    screened = False
    description = "Audio metadata, transcripts, and summaries."

    def metadata(self, ctx: ModuleContext, item: media.MediaItem) -> None:
        media.mediainfo_ffprobe(ctx, item, "audio")

    def content_route(self, ctx: ModuleContext, item: media.MediaItem) -> tuple[str, str]:
        fp = item.meta.get("ffprobe") if item.meta else None
        if isinstance(fp, dict):
            return media.av_route(fp)
        if media.sniff(media.need_path(item)) == "image":
            return "image", "ffprobe could not read it and its first bytes are a picture format"
        return "unknown", "ffprobe could not read it, so it could not be confirmed as sound only"

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
                f"Audio metadata: {name}{length}; {streams}.",
                "ffprobe",
            )
        ]

    def kept_extras(
        self, ctx: ModuleContext, item: media.MediaItem, counts: Counter[str]
    ) -> list[dict[str, Any] | DescribeResult]:
        """The transcript needs only the speech model, not the description server.

        Every kept file with sound is transcribed: plain sound, sound whose embedded pictures
        cleared, and a cleared video under an audio name (the same as the video module does
        for a cleared video). Only a still picture under an audio name has nothing to hear.
        """
        path = media.need_path(item)
        if item.route == "image":
            return []  # a picture under an audio name: screened and kept, nothing to transcribe
        work = ctx.workdir / "ai-work"
        wav = work / f"audio-{item.sha256[:16]}.wav"
        try:
            aiaudio.to_wav(path, wav, media.ctx_runner(ctx))
            tr = aiaudio.transcribe(wav, media.ctx_runner(ctx), work)
        except proc.ToolError as exc:
            tr = aiaudio.Transcript("", error=str(exc))
        finally:
            wav.unlink(missing_ok=True)
        item.meta["_transcript"] = tr
        if tr.text:
            counts["transcripts"] += 1
            out = ctx.workdir / "transcripts" / f"{path.name}.txt"
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(tr.text + "\n", encoding="utf-8")
        res = aiaudio.transcript_results(path, item.sha256, tr, None, DescribeResult, ProcessOutput)
        return list(res.results)

    def describe(
        self, ctx: ModuleContext, item: media.MediaItem, d: Describer, counts: Counter[str]
    ) -> list[DescribeResult]:
        tr = item.meta.get("_transcript") if item.meta else None
        if tr is None or not tr.text:
            return []
        return [
            d.text(
                tr.text,
                str(media.need_path(item)),
                item.sha256,
                kind="audio_summary",
                prompt_id="summarize_transcript",
                data_kind="transcript",
            )
        ]


MODULE = AudioModule()
