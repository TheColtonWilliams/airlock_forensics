"""Classifier runner for ``evidence-screen``. Runs only inside the ``/opt/triage`` venv.

This file is the one place in ``airlock_ai`` that imports third-party packages (numpy, Pillow,
onnxruntime, NudeNet, tokenizers): the decision log (2026-11-15) allows them in that venv
only. The caller runs it as a sandboxed child process (no network, seccomp, limits):

    /opt/triage/bin/python -I triage_runner.py REQUEST.json RESPONSE.json

REQUEST: ``{"images": [paths], "labels": [...], "prompts": [one per label],
"nudenet_classes": [...], "models": {"nudenet": {"model": path|null, "id"},
"siglip": {"model", "tokenizer", "preprocessor", "id"}}}``.

RESPONSE: ``{"results": [{"path", "nudity", "nudenet": {class: score}, "labels": {label:
score}, "error"}], "model_ids": {...}, "model_sha256": {...}, "versions": {...}}`` or
``{"fatal": "reason"}``. Scores are rounded to 6 decimals. Nothing is written but RESPONSE.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Any

MAX_PIXELS = 100_000_000
DEFAULT_SIZE = 224
DEFAULT_MEAN = (0.5, 0.5, 0.5)
DEFAULT_STD = (0.5, 0.5, 0.5)
MAX_TOKENS = 64


def _sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(4 * 1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def _write(path: str, data: dict[str, Any]) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, sort_keys=True, ensure_ascii=False)
        fh.write("\n")


class SigLIP:
    """Zero-shot scores from a combined SigLIP ONNX export (``logits_per_image`` output)."""

    def __init__(self, spec: dict[str, Any], prompts: list[str]) -> None:
        import numpy as np  # noqa: PLC0415 - venv-only imports
        import onnxruntime as ort  # noqa: PLC0415
        from tokenizers import Tokenizer  # noqa: PLC0415

        self.np = np
        opts = ort.SessionOptions()
        opts.intra_op_num_threads = max(1, min(4, os.cpu_count() or 1))
        self.session = ort.InferenceSession(
            spec["model"], sess_options=opts, providers=["CPUExecutionProvider"]
        )
        names = {i.name for i in self.session.get_inputs()}
        outputs = [o.name for o in self.session.get_outputs()]
        if "logits_per_image" not in outputs:
            raise RuntimeError("SigLIP model has no logits_per_image output (wrong export)")
        if not {"input_ids", "pixel_values"} <= names:
            raise RuntimeError("SigLIP model needs input_ids and pixel_values inputs")
        self.input_names = names
        size, mean, std = DEFAULT_SIZE, DEFAULT_MEAN, DEFAULT_STD
        pre = spec.get("preprocessor")
        if pre and Path(pre).is_file():
            cfg = json.loads(Path(pre).read_text(encoding="utf-8"))
            s = cfg.get("size", {})
            size = int(s.get("height", size)) if isinstance(s, dict) else int(s or size)
            mean = tuple(cfg.get("image_mean", mean))
            std = tuple(cfg.get("image_std", std))
        self.size = size
        self.mean = np.array(mean, dtype=np.float32).reshape(3, 1, 1)
        self.std = np.array(std, dtype=np.float32).reshape(3, 1, 1)
        tok = Tokenizer.from_file(spec["tokenizer"])
        pad_id = tok.token_to_id("</s>")
        if pad_id is None:
            pad_id = tok.token_to_id("<pad>") or 0
        tok.enable_truncation(MAX_TOKENS)
        tok.enable_padding(length=MAX_TOKENS, pad_id=pad_id)
        enc = tok.encode_batch([p.lower() for p in prompts])
        self.input_ids = np.array([e.ids for e in enc], dtype=np.int64)
        self.attention = np.array([e.attention_mask for e in enc], dtype=np.int64)

    def scores(self, rgb: Any) -> list[float]:
        np = self.np
        from PIL import Image  # noqa: PLC0415

        img = rgb.resize((self.size, self.size), Image.Resampling.BICUBIC)
        arr = np.asarray(img, dtype=np.float32).transpose(2, 0, 1) / 255.0
        arr = ((arr - self.mean) / self.std)[None, ...].astype(np.float32)
        feeds = {"input_ids": self.input_ids, "pixel_values": arr}
        if "attention_mask" in self.input_names:
            feeds["attention_mask"] = self.attention
        logits = self.session.run(["logits_per_image"], feeds)[0][0].astype(np.float64)
        exp = np.exp(logits - logits.max())
        probs = exp / exp.sum()
        return [round(float(p), 6) for p in probs]


def _nudenet(spec: dict[str, Any]) -> tuple[Any, str]:
    import nudenet  # noqa: PLC0415

    model = spec.get("model") or str(Path(nudenet.__file__).resolve().parent / "320n.onnx")
    if not Path(model).is_file():
        raise RuntimeError(f"NudeNet model not found: {model}")
    resolution = 640 if "640" in Path(model).name else 320
    return nudenet.NudeDetector(model_path=model, inference_resolution=resolution), model


def _load_rgb(path: str) -> Any:
    from PIL import Image  # noqa: PLC0415

    Image.MAX_IMAGE_PIXELS = MAX_PIXELS
    with Image.open(path) as im:
        im.seek(0)
        return im.convert("RGB")


def run(request: dict[str, Any]) -> dict[str, Any]:
    import numpy as np  # noqa: PLC0415

    models = request["models"]
    labels: list[str] = request["labels"]
    prompts: list[str] = request["prompts"]
    exposed = set(request.get("nudenet_classes", []))
    if len(labels) != len(prompts):
        return {"fatal": "labels and prompts differ in length"}
    try:
        detector, nn_path = _nudenet(models.get("nudenet", {}))
        siglip = SigLIP(models["siglip"], prompts)
    except Exception as exc:  # report and stop: nothing may be cleared without both models
        return {"fatal": f"{type(exc).__name__}: {exc}"}
    results: list[dict[str, Any]] = []
    for path in request["images"]:
        rec: dict[str, Any] = {"path": path}
        try:
            rgb = _load_rgb(path)
            bgr = np.asarray(rgb)[:, :, ::-1].copy()
            dets = detector.detect(bgr)
            per_class: dict[str, float] = {}
            for d in dets:
                cls, score = str(d.get("class")), float(d.get("score", 0.0))
                per_class[cls] = round(max(per_class.get(cls, 0.0), score), 6)
            rec["nudenet"] = per_class
            rec["nudity"] = max((s for c, s in per_class.items() if c in exposed), default=0.0)
            rec["labels"] = dict(zip(labels, siglip.scores(rgb), strict=True))
        except Exception as exc:  # one bad file must not stop the batch
            rec = {"path": path, "error": f"{type(exc).__name__}: {exc}"[:300]}
        results.append(rec)
    versions: dict[str, str] = {}
    try:
        from importlib import metadata  # noqa: PLC0415

        for pkg in ("nudenet", "onnxruntime", "numpy", "pillow", "tokenizers"):
            versions[pkg] = metadata.version(pkg)
    except Exception:  # noqa: S110 - versions are informational
        pass
    return {
        "results": results,
        "model_ids": {
            "nudenet": models.get("nudenet", {}).get("id") or Path(nn_path).name,
            "siglip": models["siglip"].get("id") or Path(models["siglip"]["model"]).name,
        },
        "model_sha256": {"nudenet": _sha256(nn_path), "siglip": _sha256(models["siglip"]["model"])},
        "tokenizer_sha256": _sha256(models["siglip"]["tokenizer"]),
        "versions": versions,
    }


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print("usage: triage_runner.py REQUEST.json RESPONSE.json", file=sys.stderr)
        return 2
    os.environ.setdefault("OMP_NUM_THREADS", "4")
    with open(argv[1], encoding="utf-8") as fh:
        request = json.load(fh)
    response = run(request)
    _write(argv[2], response)
    return 3 if "fatal" in response else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
