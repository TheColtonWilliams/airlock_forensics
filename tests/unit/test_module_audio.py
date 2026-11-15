"""Module ``audio`` (4C.10): metadata, faster-whisper transcript, summary as data."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest
from test_module_images import NEUTRAL, media_ctx, stage_inventory
from test_module_video import ai_setup, run_dir  # noqa: F401 - pytest fixtures

from airlock_ai import config as cfgmod
from forensic_analyze.modules import audio

pytestmark = pytest.mark.skipif(shutil.which("ffmpeg") is None, reason="needs ffmpeg")


def test_audio_transcript_and_summary(run_dir: Path, monkeypatch, ai_setup):  # noqa: F811
    stage_inventory(run_dir, {"/Music/tone.wav": NEUTRAL / "tone-440hz.wav"}, monkeypatch)
    ctx, rows = media_ctx(run_dir, "audio")
    res = audio.MODULE.run(ctx)
    assert res.status == "ok", res.reason
    assert res.counts["kept"] == 1 and res.counts["transcripts"] == 1
    tr = next(r for r in rows if r["artifact_type"] == "ai_audio_transcript")
    assert tr["derivation"] == "ai_generated" and tr["text"] == "A test tone."
    assert tr["model_sha256"] == "7" * 64
    assert tr["prompt_sha256"] == cfgmod.load_prompt("whisper_settings").sha256
    summ = next(r for r in rows if r["artifact_type"] == "ai_audio_summary")
    assert summ["prompt_sha256"] == cfgmod.load_prompt("summarize_transcript").sha256
    assert summ["message"].startswith("AI-generated")
    req = ai_setup.requests()[0]
    assert req["user_text"].startswith("<<<DATA ") and "kind=transcript" in req["user_text"]
    assert (ctx.workdir / "transcripts" / "v0_100-128-1.wav.txt").read_text() == "A test tone.\n"
    assert not list(ctx.workdir.rglob("audio-*.wav"))  # the converted WAV is temporary


def test_audio_without_speech_model(run_dir: Path, monkeypatch, ai_setup):  # noqa: F811
    monkeypatch.setenv("AIRLOCK_WHISPER_PYTHON", "/nonexistent/python")
    stage_inventory(run_dir, {"/Music/tone.wav": NEUTRAL / "tone-440hz.wav"}, monkeypatch)
    ctx, rows = media_ctx(run_dir, "audio")
    assert audio.MODULE.run(ctx).status == "ok"
    nd = [r for r in rows if r["artifact_type"] == "ai_not_described"]
    assert nd and "not installed" in nd[0]["message"]


def test_transcript_without_description_server(run_dir: Path, monkeypatch, ai_setup):  # noqa: F811
    from airlock_ai import llm  # noqa: PLC0415

    monkeypatch.setenv(llm.URL_ENV, "http://127.0.0.1:9")  # the speech model is local; no server
    stage_inventory(run_dir, {"/Music/tone.wav": NEUTRAL / "tone-440hz.wav"}, monkeypatch)
    ctx, rows = media_ctx(run_dir, "audio")
    assert audio.MODULE.run(ctx).status == "ok"
    kinds = [r["artifact_type"] for r in rows]
    assert "ai_audio_transcript" in kinds and "ai_audio_summary" not in kinds
    assert ai_setup.requests() == []


def test_pictures_and_video_under_audio_names_are_screened(
    run_dir: Path,  # noqa: F811
    monkeypatch,
    ai_setup,  # noqa: F811
    tmp_path: Path,
):
    """Finding 9: content type, not extension, decides whether a file is screened."""
    from test_module_video import make_video  # noqa: PLC0415

    clip = make_video(tmp_path / "clip.mp4", NEUTRAL / "landscape.png", seconds=2)
    blob = tmp_path / "blob.bin"
    blob.write_bytes(bytes(range(256)) * 16)  # no audio, no picture: type cannot be confirmed
    stage_inventory(
        run_dir,
        {
            "/Music/tone.wav": NEUTRAL / "tone-440hz.wav",
            "/Music/clip.m4a": clip,  # a video renamed: screened as a video, cleared
            "/Music/squares.mp3": NEUTRAL / "shapes-squares.png",  # a picture; stub: flagged
            "/Music/blob.mp3": blob,
        },
        monkeypatch,
    )
    ctx, rows = media_ctx(run_dir, "audio")
    res = audio.MODULE.run(ctx)
    assert res.status == "ok", res.reason
    assert res.counts["content_mismatch"] == 3
    assert (res.counts["kept"], res.counts["cleared"]) == (1, 1)
    assert (res.counts["flagged"], res.counts["not_screened"]) == (1, 1)
    kept = sorted(p.name for p in (ctx.workdir / "export").iterdir() if p.is_file())
    assert len(kept) == 2  # the tone and the cleared video; the picture and the blob are gone
    errs = {r["path"]: r for r in rows if r["artifact_type"] == "screen_error"}
    assert set(errs) == {"/Music/blob.mp3"}
    assert "content type mismatch" in errs["/Music/blob.mp3"]["message"]
    labels = {r["path"]: r for r in rows if r["artifact_type"] == "screen_labels"}
    assert labels["/Music/clip.m4a"]["sensitive_flag"] is False
    assert "content type mismatch" in labels["/Music/clip.m4a"]["text"]
    assert "covering" in labels["/Music/clip.m4a"]["text"]
    nud = {r["path"]: r for r in rows if r["artifact_type"] == "screen_nudity"}
    assert nud["/Music/squares.mp3"]["sensitive_flag"] is True
    # Nothing flagged or unscreened was transcribed or summarised.
    ai_paths = {r["path"] for r in rows if r["artifact_type"].startswith("ai_audio")}
    assert ai_paths <= {"/Music/tone.wav", "/Music/clip.m4a"}
    assert "/Music/tone.wav" in ai_paths


def tone_with_cover(out: Path, colour: str = "0x3060a0") -> Path:
    """A generated 2 s sine tone with a solid-colour cover picture (ID3 APIC for .mp3, an
    MP4 ``covr`` atom for .m4a)."""
    codec = (
        ["-c:a", "libmp3lame", "-id3v2_version", "3"] if out.suffix == ".mp3" else ["-c:a", "aac"]
    )
    subprocess.run(
        [
            "ffmpeg",
            "-nostdin",
            "-loglevel",
            "error",
            "-y",
            "-f",
            "lavfi",
            "-i",
            "sine=frequency=440:duration=2",
            "-f",
            "lavfi",
            "-i",
            f"color=c={colour}:s=32x32:d=1",
            "-map",
            "0:a",
            "-map",
            "1:v",
            "-frames:v",
            "1",
            *codec,
            "-c:v",
            "png",
            "-disposition:v:0",
            "attached_pic",
            str(out),
        ],
        check=True,
    )
    return out


def broken_cover(src: Path, out: Path) -> Path:
    """``src`` with the cover picture's compressed pixel data overwritten: ffprobe still lists
    the picture, ffmpeg cannot decode it."""
    data = bytearray(src.read_bytes())
    at = data.find(b"IDAT")
    assert at > 0
    data[at + 4 : at + 40] = b"A" * 36
    out.write_bytes(bytes(data))
    return out


def test_cover_art_is_screened_as_an_embedded_picture(
    run_dir: Path,  # noqa: F811
    monkeypatch,
    ai_setup,  # noqa: F811
    tmp_path: Path,
):
    """Finding 9 / item B: cover art is its own case, not a content type mismatch. The picture
    is extracted and screened; the file is kept (and transcribed) only if it clears. A cover
    that cannot be extracted keeps the whole file from being kept, with an accurate reason."""
    good_mp3 = tone_with_cover(tmp_path / "good.mp3")
    good_m4a = tone_with_cover(tmp_path / "good.m4a")
    bad = broken_cover(good_mp3, tmp_path / "bad.mp3")
    stage_inventory(
        run_dir,
        {
            "/Music/album.mp3": good_mp3,
            "/Music/album.m4a": good_m4a,
            "/Music/broken.mp3": bad,
        },
        monkeypatch,
    )
    ctx, rows = media_ctx(run_dir, "audio")
    res = audio.MODULE.run(ctx)
    assert res.status == "ok", res.reason
    assert res.counts["embedded_pictures"] == 3
    assert res.counts.get("content_mismatch", 0) == 0
    assert (res.counts["cleared"], res.counts["not_screened"]) == (2, 1)
    kept = sorted(p.name for p in (ctx.workdir / "export").iterdir() if p.is_file())
    assert len(kept) == 2
    labels = {r["path"]: r for r in rows if r["artifact_type"] == "screen_labels"}
    for path in ("/Music/album.mp3", "/Music/album.m4a"):
        assert labels[path]["sensitive_flag"] is False
        assert "embedded picture screened" in labels[path]["text"]
        assert "content type mismatch" not in labels[path]["text"]
        assert "1 frames screened" in labels[path]["text"]
    err = next(r for r in rows if r["artifact_type"] == "screen_error")
    assert err["path"] == "/Music/broken.mp3"
    assert err["message"].startswith("Not screened (embedded picture could not be screened:")
    assert "content type mismatch" not in err["message"]
    assert "ffmpeg could not read" in err["text"]  # ffmpeg's own failure is recorded
    assert "embedded picture screened" not in err["text"]
    transcribed = {r["path"] for r in rows if r["artifact_type"] == "ai_audio_transcript"}
    assert transcribed == {"/Music/album.mp3", "/Music/album.m4a"}


def test_flagged_cover_art_deletes_the_file(
    run_dir: Path,  # noqa: F811
    monkeypatch,
    ai_setup,  # noqa: F811
    tmp_path: Path,
):
    """A cover picture the classifiers flag keeps the sound file from being kept or heard."""
    scores = tmp_path / "scores.json"
    scores.write_text(
        json.dumps(
            {
                "default": {"labels": {"neutral": 0.95}, "nudity": 0.01},
                # Test value only: the extracted cover (stream 1) is a flat colour square.
                "files": {"a1_000001.png": {"labels": {"neutral": 0.2}, "nudity": 0.91}},
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("AIRLOCK_SCREEN_BACKEND", f"stub:{scores}")
    stage_inventory(run_dir, {"/Music/album.mp3": tone_with_cover(tmp_path / "a.mp3")}, monkeypatch)
    ctx, rows = media_ctx(run_dir, "audio")
    res = audio.MODULE.run(ctx)
    assert res.status == "ok", res.reason
    assert (res.counts["embedded_pictures"], res.counts["flagged"]) == (1, 1)
    assert not [p for p in (ctx.workdir / "export").glob("*") if p.is_file()]
    nud = next(r for r in rows if r["artifact_type"] == "screen_nudity")
    assert nud["sensitive_flag"] is True and "not kept" in nud["message"]
    assert not [r for r in rows if r["artifact_type"].startswith("ai_audio")]


def test_cleared_video_under_audio_name_is_transcribed(
    run_dir: Path,  # noqa: F811
    monkeypatch,
    ai_setup,  # noqa: F811
    tmp_path: Path,
):
    """Item C: a video renamed .m4a that clears is handled like any cleared sound file and
    like a cleared video in the video module: its sound is transcribed and the transcript
    summarised. Its pictures are never sent to the description model from here."""
    from test_module_video import make_video  # noqa: PLC0415

    clip = make_video(tmp_path / "clip.mp4", NEUTRAL / "landscape.png", seconds=2)
    stage_inventory(run_dir, {"/Music/clip.m4a": clip}, monkeypatch)
    ctx, rows = media_ctx(run_dir, "audio")
    res = audio.MODULE.run(ctx)
    assert res.status == "ok", res.reason
    assert (res.counts["content_mismatch"], res.counts["cleared"]) == (1, 1)
    assert res.counts["transcripts"] == 1
    kinds = {r["artifact_type"] for r in rows if r["path"] == "/Music/clip.m4a"}
    assert {"screen_labels", "ai_audio_transcript", "ai_audio_summary"} <= kinds
    assert "ai_video" not in kinds and "ai_image" not in kinds
    reqs = ai_setup.requests()
    assert len(reqs) == 1 and "kind=transcript" in reqs[0]["user_text"]
    assert not reqs[0].get("images")
