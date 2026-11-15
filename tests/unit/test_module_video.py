"""Module ``video`` (4C.9, 4B.7): frame screening flags with timestamps, cleared videos are
transcribed and described; flagged videos are never kept, transcribed, or described."""

from __future__ import annotations

import json
import shutil
import subprocess
from collections.abc import Iterator
from pathlib import Path

import pytest
from test_module_images import NEUTRAL, LlamaStub, llama_stub, media_ctx, stage_inventory

from airlock_ai import config as cfgmod
from forensic_analyze.modules import video

pytestmark = pytest.mark.skipif(shutil.which("ffmpeg") is None, reason="needs ffmpeg")

WHISPER_STUB = """#!/usr/bin/env python3
import json, sys
req = json.load(open(sys.argv[3]))
assert sys.argv[1] == "-I" and sys.argv[2].endswith("whisper_runner.py")
assert req["audio"].endswith(".wav")
json.dump({"language": "en", "language_probability": 0.9, "duration": 4.0,
           "segments": [{"start": 0.0, "end": 2.0, "text": "A test tone."}],
           "model_sha256": "7" * 64}, open(sys.argv[4], "w"))
"""

MTMD_STUB = """#!/usr/bin/env python3
import json, sys
open(sys.argv[0] + ".calls", "a").write(json.dumps(sys.argv[1:]) + "\\n")
print("A short clip of a landscape with a sun over hills.")
"""


def make_video(out: Path, *images: Path, seconds: int = 4) -> Path:
    args = ["ffmpeg", "-nostdin", "-loglevel", "error", "-y"]
    for img in images:
        args += ["-loop", "1", "-t", str(seconds), "-i", str(img)]
    args += [
        "-f",
        "lavfi",
        "-t",
        str(seconds * len(images)),
        "-i",
        "sine=frequency=300:sample_rate=16000",
    ]
    n = len(images)
    chain = "".join(f"[{i}:v]" for i in range(n)) + f"concat=n={n}:v=1:a=0,format=yuv420p[v]"
    args += [
        "-filter_complex",
        chain,
        "-map",
        "[v]",
        "-map",
        f"{n}:a",
        "-r",
        "10",
        "-c:v",
        "libx264",
        "-c:a",
        "aac",
        "-shortest",
        str(out),
    ]
    subprocess.run(args, check=True)
    return out


@pytest.fixture
def ai_setup(airlock_env: Path, tmp_path: Path, monkeypatch) -> Iterator[LlamaStub]:
    prefix = tmp_path / "llama"
    (prefix / "bin").mkdir(parents=True)
    mtmd = prefix / "bin" / "llama-mtmd-cli"
    mtmd.write_text(MTMD_STUB, encoding="utf-8")
    mtmd.chmod(0o755)
    cfg = json.loads(json.dumps(cfgmod.DEFAULT_AI_CONFIG))
    cfg["llama"]["prefix"] = str(prefix)
    (airlock_env / "etc" / "ai-tiers.json").write_text(json.dumps(cfg), encoding="utf-8")
    models = tmp_path / "models"
    models.mkdir()
    (models / "m.gguf").write_bytes(b"model")
    (models / "mm.gguf").write_bytes(b"mmproj")
    (airlock_env / "state" / "ai-tier.json").write_text(
        json.dumps(
            {
                "tier": "tier0",
                "n_gpu_layers": 0,
                "models": [
                    {"role": "model", "path": str(models / "m.gguf")},
                    {"role": "mmproj", "path": str(models / "mm.gguf")},
                ],
            }
        ),
        encoding="utf-8",
    )
    wdir = airlock_env / "assets" / "files" / "models" / "faster-whisper-small"
    wdir.mkdir(parents=True)
    (wdir / "model.bin").write_bytes(b"ct2")
    wpy = tmp_path / "whisper-python"
    wpy.write_text(WHISPER_STUB, encoding="utf-8")
    wpy.chmod(0o755)
    monkeypatch.setenv("AIRLOCK_WHISPER_PYTHON", str(wpy))
    d = tmp_path / "llm"
    d.mkdir()
    yield from llama_stub(d, monkeypatch)


@pytest.fixture
def run_dir(airlock_env: Path, monkeypatch) -> Path:
    from test_module_images import RUN_ID, STUB_SCORES  # noqa: PLC0415

    monkeypatch.setenv("AIRLOCK_SCREEN_BACKEND", f"stub:{STUB_SCORES}")
    d = airlock_env / "output" / "cases" / "C1" / RUN_ID
    (d / "modules").mkdir(parents=True)
    return d


def test_video_flag_with_timestamps_and_cleared_described(
    run_dir: Path, tmp_path: Path, monkeypatch, ai_setup: LlamaStub
):
    # Scene change at 4 s: the stub flags the first scene-change frame (s_000001.png).
    flagged = make_video(
        tmp_path / "cut.mp4", NEUTRAL / "landscape.png", NEUTRAL / "shapes-circle.png"
    )
    calm = make_video(tmp_path / "calm.mp4", NEUTRAL / "landscape.png")
    stage_inventory(run_dir, {"/Videos/cut.mp4": flagged, "/Videos/calm.mp4": calm}, monkeypatch)
    ctx, rows = media_ctx(run_dir, "video")
    res = video.MODULE.run(ctx)
    assert res.status == "ok", res.reason
    assert (res.counts["cleared"], res.counts["flagged"]) == (1, 1)
    kept = [p.name for p in (ctx.workdir / "export").iterdir() if p.is_file()]
    assert len(kept) == 1  # only the cleared video stays
    assert not list(ctx.workdir.rglob("*.png"))  # frames are never kept
    lab = {r["path"]: r for r in rows if r["artifact_type"] == "screen_labels"}
    f = lab["/Videos/cut.mp4"]
    assert f["sensitive_flag"] is True and f["label"] == "violence"
    assert "flagged at 4." in f["text"] or "flagged at 3." in f["text"]
    assert "frames screened" in lab["/Videos/calm.mp4"]["text"]
    meta = [r for r in rows if r["artifact_type"] == "video_metadata"]
    assert {r["path"] for r in meta} == {"/Videos/cut.mp4", "/Videos/calm.mp4"}
    ai = [
        r
        for r in rows
        if r["derivation"] == "ai_generated"
        and r["artifact_type"].startswith(("ai_", "model_declined"))
    ]
    assert {r["path"] for r in ai} == {"/Videos/calm.mp4"}
    kinds = sorted(r["artifact_type"] for r in ai)
    assert kinds == ["ai_audio_summary", "ai_audio_transcript", "ai_video"]
    vid = next(r for r in ai if r["artifact_type"] == "ai_video")
    assert vid["prompt_sha256"] == cfgmod.load_prompt("describe_video").sha256
    calls = (tmp_path / "llama/bin/llama-mtmd-cli.calls").read_text().splitlines()
    assert len(calls) == 1
    argv = json.loads(calls[0])
    assert argv[argv.index("--temp") + 1] == "0" and "--video" in argv
    # The transcript summary went to the model as data, and only for the cleared video.
    reqs = ai_setup.requests()
    assert len(reqs) == 1 and reqs[0]["user_text"].startswith("<<<DATA ")
    assert "A test tone." in reqs[0]["user_text"]
