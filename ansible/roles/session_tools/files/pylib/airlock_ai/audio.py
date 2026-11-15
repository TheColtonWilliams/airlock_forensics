"""Audio: speech-to-text with faster-whisper ``small`` and a summary of the transcript (4B.7).

``ffmpeg`` first converts the recording (or a video's audio track) to 16 kHz mono WAV in the
work folder; ``whisper_runner.py`` then transcribes it in the ``/opt/whisper`` venv, sandboxed,
with no network and fixed decoding settings (``prompts/whisper_settings.txt``, whose SHA-256
stands in for a prompt hash on transcript rows). The transcript is model output: it is
labelled AI-generated and it is evidence-derived text, so it reaches the description model
only inside a delimited data block.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from airlock_ai import config as cfgmod
from airlock_ai.tools import RunTool, tool_dir
from airlock_common import jsonio, proc

AUDIO_EXTENSIONS = frozenset(
    {
        ".wav",
        ".mp3",
        ".m4a",
        ".aac",
        ".flac",
        ".ogg",
        ".oga",
        ".opus",
        ".wma",
        ".amr",
        ".aiff",
        ".aif",
        ".3ga",
    }
)
RUNNER_SCRIPT = Path(__file__).resolve().parent / "whisper_runner.py"
SETTINGS_PROMPT = "whisper_settings"
MAX_CSV_TRANSCRIPT = 8000


@dataclass
class Transcript:
    text: str
    segments: list[dict[str, Any]] = field(default_factory=list)
    language: str = ""
    duration: float = 0.0
    model_id: str = ""
    model_sha256: str = ""
    settings_sha256: str = ""
    error: str = ""


def to_wav(src: Path, out_wav: Path, run_tool: RunTool) -> Path:
    tool_dir(out_wav.parent)
    cp = run_tool(
        [
            "ffmpeg",
            "-nostdin",
            "-hide_banner",
            "-loglevel",
            "error",
            "-i",
            str(src),
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
        extra_ro=[str(src.parent)],
    )
    if cp.returncode != 0 or not out_wav.exists():
        last = ((cp.stderr or "").strip().splitlines() or ["no output"])[-1]
        raise proc.ToolError(f"ffmpeg could not read the audio: {last[:200]}")
    return out_wav


def transcribe(
    wav: Path, run_tool: RunTool, workdir: Path, ai_config: dict[str, Any] | None = None
) -> Transcript:
    cfg = ai_config or cfgmod.load_ai_config()
    settings = cfgmod.load_prompt(SETTINGS_PROMPT)
    wcfg = cfg["whisper"]
    python = cfgmod.venv_python("whisper", cfg)
    if not python.exists():
        return Transcript(
            "",
            error="the speech-to-text environment is not installed",
            settings_sha256=settings.sha256,
        )
    model_dir = cfgmod.asset_file(wcfg["model_dir_target"])
    if model_dir is None or not (model_dir / wcfg.get("model_file", "model.bin")).is_file():
        return Transcript(
            "", error="the speech model is not staged on ASSETS", settings_sha256=settings.sha256
        )
    tool_dir(workdir)
    req = workdir / "whisper-request.json"
    resp = workdir / "whisper-response.json"
    jsonio.dump_json(
        req,
        {
            "audio": str(wav),
            "model_dir": str(model_dir),
            "model_file": wcfg.get("model_file", "model.bin"),
            "language": None,
            "compute_type": "int8",
        },
    )
    req.chmod(0o644)  # read by the sandbox user
    try:
        cp = run_tool(
            [str(python), "-I", str(RUNNER_SCRIPT), str(req), str(resp)],
            timeout=6 * 3600,
            memory_bytes=8 * 1024**3,
            extra_ro=sorted({str(wav.parent), str(model_dir), str(RUNNER_SCRIPT.parent)}),
        )
        try:
            data = json.loads(resp.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            last = ((cp.stderr or "").strip().splitlines() or ["no output"])[-1]
            return Transcript(
                "", error=f"speech-to-text failed: {last[:200]}", settings_sha256=settings.sha256
            )
    finally:
        req.unlink(missing_ok=True)
        resp.unlink(missing_ok=True)
    if data.get("fatal"):
        return Transcript("", error=str(data["fatal"]), settings_sha256=settings.sha256)
    segs = list(data.get("segments", []))
    return Transcript(
        text="\n".join(str(s.get("text", "")) for s in segs).strip(),
        segments=segs,
        language=str(data.get("language", "")),
        duration=float(data.get("duration", 0.0)),
        model_id=str(wcfg.get("id", "faster-whisper small")),
        model_sha256=str(data.get("model_sha256", "")),
        settings_sha256=settings.sha256,
    )


def process(path: Path, sha256: str, run_tool: RunTool, describer: Any, workdir: Path) -> Any:
    """Transcribe one audio file and summarise the transcript. Returns ``ProcessOutput``."""
    from airlock_ai.describe import DescribeResult, ProcessOutput  # noqa: PLC0415

    wav = workdir / f"audio-{sha256[:16]}.wav"
    try:
        to_wav(path, wav, run_tool)
        tr = transcribe(wav, run_tool, workdir, describer.cfg if describer else None)
    finally:
        wav.unlink(missing_ok=True)
    return transcript_results(path, sha256, tr, describer, DescribeResult, ProcessOutput)


def transcript_results(  # noqa: PLR0917
    path: Path, sha256: str, tr: Transcript, describer: Any, result_cls: Any, out_cls: Any
) -> Any:
    tier = describer.tier if describer else ""
    if tr.error:
        return out_cls(
            [result_cls(str(path), sha256, "audio", "error", tier=tier, detail=tr.error)],
            {"transcript": tr},
        )
    transcript = result_cls(
        path=str(path),
        sha256=sha256,
        kind="audio_transcript",
        status="described" if tr.text else "model_declined",
        description=tr.text[:MAX_CSV_TRANSCRIPT],
        model_id=tr.model_id,
        model_sha256=tr.model_sha256,
        prompt_id=SETTINGS_PROMPT,
        prompt_sha256=tr.settings_sha256,
        tier="cpu",
        seed=0,
        detail=(
            f"language {tr.language}, {tr.duration:.1f} s" if tr.text else "no speech recognised"
        ),
    )
    results = [transcript]
    if tr.text and describer is not None:
        results.append(
            describer.text(
                tr.text,
                str(path),
                sha256,
                kind="audio_summary",
                prompt_id="summarize_transcript",
                data_kind="transcript",
            )
        )
    return out_cls(results, {"transcript": tr})
