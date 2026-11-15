"""Module ``audio`` (4C.10): metadata, faster-whisper transcript, summary as data."""

from __future__ import annotations

import shutil
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
