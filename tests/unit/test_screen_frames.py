"""Every frame or page of an image is screened (finding 8): animated GIF, multi-page TIFF.

The pictures are generated here: plain coloured shapes, nothing else. The "flag" is a stub
score keyed to the colour red, a test value and not a property of the picture.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

PIL = pytest.importorskip("PIL")
np = pytest.importorskip("numpy")

from PIL import Image, ImageDraw  # noqa: E402

from airlock_ai import config as cfgmod  # noqa: E402
from airlock_ai import screen, triage_runner  # noqa: E402

LABELS = list(cfgmod.LABELS)
EXPOSED = set(cfgmod.NUDENET_EXPOSED_CLASSES)


def _frame(shape: str, colour: str) -> Image.Image:
    im = Image.new("RGB", (64, 64), "white")
    d = ImageDraw.Draw(im)
    if shape == "square":
        d.rectangle((8, 8, 56, 56), fill=colour)
    else:
        d.ellipse((8, 8, 56, 56), fill=colour)
    return im


def _animated(path: Path, *frames: Image.Image, fmt: str = "GIF") -> Path:
    first, *rest = frames
    kw = {"duration": 100, "loop": 0} if fmt == "GIF" else {}
    first.save(path, format=fmt, save_all=True, append_images=rest, **kw)
    return path


class FakeDetector:
    """No detections: the stub flag comes from the label scores."""

    def detect(self, bgr: object) -> list[dict]:
        del bgr
        return []


class FakeSigLIP:
    """``violence`` 0.9 for a frame that is mostly red, else ``neutral`` 0.95 (stub values)."""

    def __init__(self) -> None:
        self.calls = 0

    def scores(self, rgb: Image.Image) -> list[float]:
        self.calls += 1
        arr = np.asarray(rgb, dtype=np.float32)
        red = float(((arr[:, :, 0] > 200) & (arr[:, :, 1] < 60)).mean())
        out = dict.fromkeys(LABELS, 0.005)
        if red > 0.2:
            out["violence"] = 0.9
        else:
            out["neutral"] = 0.95
        return [out[label] for label in LABELS]


def _score(path: Path, max_frames: int = 64) -> tuple[dict, FakeSigLIP]:
    sig = FakeSigLIP()
    rec = triage_runner.score_file(str(path), FakeDetector(), sig, LABELS, EXPOSED, max_frames)
    return rec, sig


def _verdict(rec: dict) -> str:
    raw = screen.RawScore(
        nudity=rec["nudity"], labels=rec["labels"], incomplete=rec.get("incomplete", "")
    )
    return screen.decide(raw, cfgmod.thresholds_from_dict({}))[0]


def test_two_frame_gif_flags_on_second_frame(tmp_path: Path):
    gif = _animated(tmp_path / "a.gif", _frame("square", "blue"), _frame("circle", "red"))
    # The first frame alone is cleared: screening only frame 0 would clear the whole file.
    first = tmp_path / "first.png"
    with Image.open(gif) as im:
        im.seek(0)
        im.convert("RGB").save(first)
    rec0, _ = _score(first)
    assert _verdict(rec0) == "cleared"
    rec, sig = _score(gif)
    assert (rec["frames"], rec["frames_total"], sig.calls) == (2, 2, 2)
    assert "incomplete" not in rec
    assert rec["labels"]["violence"] == pytest.approx(0.9)
    assert _verdict(rec) == "flagged"


def test_multi_page_tiff_flags_on_second_page(tmp_path: Path):
    tif = _animated(
        tmp_path / "a.tif", _frame("square", "green"), _frame("circle", "red"), fmt="TIFF"
    )
    rec, _ = _score(tif)
    assert rec["frames"] == 2 and _verdict(rec) == "flagged"


def test_more_frames_than_the_limit_is_never_cleared(tmp_path: Path):
    gif = _animated(
        tmp_path / "b.gif",
        _frame("square", "blue"),
        _frame("circle", "green"),
        _frame("square", "red"),
    )
    rec, sig = _score(gif, max_frames=2)
    assert (rec["frames"], rec["frames_total"], sig.calls) == (2, 3, 2)
    assert "only the first 2" in rec["incomplete"]
    assert _verdict(rec) == "error"  # the unscreened third frame keeps it from clearing
    # A screened frame that flags still flags the file when the rest was not screened.
    gif2 = _animated(tmp_path / "c.gif", _frame("square", "red"), *[_frame("circle", "blue")] * 2)
    rec2, _ = _score(gif2, max_frames=1)
    assert rec2.get("incomplete") and _verdict(rec2) == "flagged"


def test_single_frame_image_unchanged(tmp_path: Path):
    png = tmp_path / "one.png"
    _frame("square", "blue").save(png)
    rec, sig = _score(png)
    assert (rec["frames"], rec["frames_total"], sig.calls) == (1, 1, 1)
    assert _verdict(rec) == "cleared"


def test_runner_passes_the_frame_limit(tmp_path: Path, monkeypatch):
    gif = _animated(
        tmp_path / "d.gif",
        _frame("square", "blue"),
        _frame("circle", "green"),
        _frame("square", "red"),
    )
    model = tmp_path / "m.onnx"
    model.write_bytes(b"x")
    monkeypatch.setattr(triage_runner, "_nudenet", lambda spec: (FakeDetector(), str(model)))
    monkeypatch.setattr(triage_runner, "SigLIP", lambda spec, prompts: FakeSigLIP())
    req = {
        "images": [str(gif)],
        "labels": LABELS,
        "prompts": LABELS,
        "nudenet_classes": sorted(EXPOSED),
        "max_image_frames": 2,
        "models": {"nudenet": {}, "siglip": {"model": str(model), "tokenizer": str(model)}},
    }
    out = triage_runner.run(req)
    (res,) = out["results"]
    assert res["frames"] == 2 and res["frames_total"] == 3 and res["incomplete"]


def test_thresholds_carry_the_image_frame_limit(tmp_path: Path):
    assert cfgmod.thresholds_from_dict({}).max_image_frames == 64
    assert cfgmod.thresholds_from_dict({"image": {"max_frames": 3}}).max_image_frames == 3
    for bad in (0, -1, 2.5, True):
        with pytest.raises(cfgmod.ConfigError):
            cfgmod.thresholds_from_dict({"image": {"max_frames": bad}})
    with pytest.raises(cfgmod.ConfigError):
        cfgmod.thresholds_from_dict({"video": {"max_frames": 0}})


def test_triage_backend_sends_limit_and_never_clears_incomplete(
    airlock_env: Path, tmp_path: Path, monkeypatch
):
    d = airlock_env / "assets" / "files" / "models" / "siglip-base-patch16-224"
    d.mkdir(parents=True)
    (d / "model.onnx").write_bytes(b"onnx")
    (d / "tokenizer.json").write_text("{}", encoding="utf-8")
    py = tmp_path / "python"
    py.write_text("", encoding="utf-8")
    monkeypatch.setenv("AIRLOCK_TRIAGE_PYTHON", str(py))
    seen: list[dict] = []

    def run(argv, **kw):
        req = json.loads(Path(argv[3]).read_text(encoding="utf-8"))
        seen.append(req)
        labels = dict.fromkeys(LABELS, 0.01)
        doc = {
            "model_ids": {"nudenet": "nn", "siglip": "sg"},
            "model_sha256": {"nudenet": "1" * 64, "siglip": "2" * 64},
            "results": [
                {
                    "path": p,
                    "nudity": 0.0,
                    "labels": labels,
                    "frames": 4,
                    "frames_total": 9,
                    "incomplete": "the file has 9 frames or pages; only the first 4 were screened",
                }
                for p in req["images"]
            ],
        }
        Path(argv[4]).write_text(json.dumps(doc), encoding="utf-8")
        return subprocess.CompletedProcess(argv, 0, "", "")

    img = tmp_path / "x.gif"
    _animated(img, _frame("square", "blue"), _frame("circle", "green"))
    thr = cfgmod.thresholds_from_dict({"image": {"max_frames": 4}})
    (res,) = screen.screen_paths(
        [img], None, thr, backend="triage", run_tool=run, workdir=tmp_path / "w"
    )
    assert seen[0]["max_image_frames"] == 4
    assert res.verdict == "error" and "not fully screened" in res.error


def test_stub_backend_incomplete_entry_is_an_error(airlock_env: Path, tmp_path: Path):
    spec = tmp_path / "stub.json"
    spec.write_text(
        json.dumps({"files": {"x.gif": {"incomplete": "too many frames"}}}), encoding="utf-8"
    )
    img = tmp_path / "x.gif"
    _animated(img, _frame("square", "blue"), _frame("circle", "green"))
    (res,) = screen.screen_paths([img], None, backend=f"stub:{spec}", workdir=tmp_path / "w")
    assert res.verdict == "error" and "too many frames" in res.error
