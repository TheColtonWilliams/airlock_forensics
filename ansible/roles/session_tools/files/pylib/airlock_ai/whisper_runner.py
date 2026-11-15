"""Speech-to-text runner. Runs only inside the ``/opt/whisper`` venv (faster-whisper, MIT).

The decision log (2026-11-15) allows third-party packages in that venv only. The caller runs
it sandboxed with no network:

    /opt/whisper/bin/python -I whisper_runner.py REQUEST.json RESPONSE.json

REQUEST: ``{"audio": path, "model_dir": path, "model_file": "model.bin", "language": null,
"compute_type": "int8"}``. RESPONSE: ``{"language", "language_probability", "duration",
"segments": [{"start", "end", "text"}], "model_sha256", "versions"}`` or ``{"fatal": reason}``.
Decoding is greedy (beam 1, temperature 0) and does not condition on earlier text, so a
replay gives the same transcript on the same CPU.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Any


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(4 * 1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def run(req: dict[str, Any]) -> dict[str, Any]:
    # Never let the hub library look for a network; the model folder is local.
    os.environ["HF_HUB_OFFLINE"] = "1"
    os.environ["HF_HUB_DISABLE_TELEMETRY"] = "1"
    model_dir = Path(req["model_dir"])
    model_file = model_dir / str(req.get("model_file", "model.bin"))
    if not model_file.is_file():
        return {"fatal": f"speech model not staged: {model_file}"}
    try:
        from faster_whisper import WhisperModel  # noqa: PLC0415 - venv-only import

        model = WhisperModel(
            str(model_dir),
            device="cpu",
            compute_type=str(req.get("compute_type", "int8")),
            local_files_only=True,
        )
        segments, info = model.transcribe(
            req["audio"],
            language=req.get("language"),
            beam_size=1,
            temperature=0.0,
            condition_on_previous_text=False,
            vad_filter=False,
        )
        segs = [
            {"start": round(s.start, 3), "end": round(s.end, 3), "text": s.text.strip()}
            for s in segments
        ]
    except Exception as exc:  # report and stop
        return {"fatal": f"{type(exc).__name__}: {exc}"[:400]}
    versions: dict[str, str] = {}
    try:
        from importlib import metadata  # noqa: PLC0415

        for pkg in ("faster-whisper", "ctranslate2", "av"):
            versions[pkg] = metadata.version(pkg)
    except Exception:  # noqa: S110 - informational
        pass
    return {
        "language": info.language,
        "language_probability": round(float(info.language_probability), 4),
        "duration": round(float(info.duration), 3),
        "segments": segs,
        "model_sha256": _sha256(model_file),
        "versions": versions,
    }


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print("usage: whisper_runner.py REQUEST.json RESPONSE.json", file=sys.stderr)
        return 2
    with open(argv[1], encoding="utf-8") as fh:
        req = json.load(fh)
    out = run(req)
    with open(argv[2], "w", encoding="utf-8") as fh:
        json.dump(out, fh, sort_keys=True, ensure_ascii=False)
        fh.write("\n")
    return 3 if "fatal" in out else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
