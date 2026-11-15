"""Configuration for the AI helpers: screening thresholds and the AI config file.

Two files, both under ``/etc/airlock/`` (``AIRLOCK_ETC_DIR`` in tests):

``screen-thresholds.json``
    Verdict thresholds for ``evidence-screen`` (task 4B.6). Source:
    ``ansible/roles/session_tools/files/etc/screen-thresholds.json``, installed by the
    ``tools_ai`` role. ``DEFAULT_THRESHOLDS`` below holds the same values and is used when the
    file is missing; a unit test keeps the two equal.
``ai-tiers.json``
    Model tiers, model file locations on ASSETS, classifier and speech model locations, and the
    llama.cpp settings, rendered by the ``tools_ai`` role from ``group_vars/all/ai_models.yml``
    and ``pins.yml``. ``DEFAULT_AI_CONFIG`` is the fallback with the same shape.

The meaning of a threshold is in docs/workflows/media-screening.md.
"""

from __future__ import annotations

import copy
import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from airlock_common import hashing, paths

THRESHOLDS_FILE = "screen-thresholds.json"
AI_CONFIG_FILE = "ai-tiers.json"
TIER_STATE_FILE = "ai-tier.json"

# Zero-shot labels for SigLIP (task 4B.5). "neutral" is the catch-all and never flags.
LABELS: tuple[str, ...] = (
    "nudity",
    "sexual activity",
    "violence",
    "weapon",
    "gore",
    "blood",
    "injury",
    "neutral",
)
NEUTRAL_LABEL = "neutral"
SEXUAL_LABELS: frozenset[str] = frozenset({"nudity", "sexual activity"})
VIOLENT_LABELS: frozenset[str] = frozenset({"violence", "weapon", "gore", "blood", "injury"})

# NudeNet detector classes that count towards the nudity score. Covered body parts, faces,
# feet, armpits, and bellies do not.
NUDENET_EXPOSED_CLASSES: tuple[str, ...] = (
    "ANUS_EXPOSED",
    "BUTTOCKS_EXPOSED",
    "FEMALE_BREAST_EXPOSED",
    "FEMALE_GENITALIA_EXPOSED",
    "MALE_GENITALIA_EXPOSED",
)

# Conservative defaults: low thresholds, so more files are held back from the model. A false
# flag costs a file that is not described; a missed flag puts a file in front of the model and,
# later, the examiner. Calibrated per release by task 4B.16 (validation/classifiers/).
DEFAULT_THRESHOLDS: dict[str, Any] = {
    "schema": 1,
    "nudity": 0.30,
    "labels": {
        "nudity": 0.25,
        "sexual activity": 0.25,
        "violence": 0.30,
        "weapon": 0.35,
        "gore": 0.25,
        "blood": 0.30,
        "injury": 0.30,
    },
    "nudenet_classes": list(NUDENET_EXPOSED_CLASSES),
    "label_template": "a photo of {label}.",
    "video": {"frame_interval_s": 2, "scene_threshold": 0.4, "max_frames": 900},
    "image": {"max_frames": 64},
    "note": (
        "Scores at or above a threshold flag the file. Lower is more cautious. "
        "See docs/workflows/media-screening.md."
    ),
}

DEFAULT_AI_CONFIG: dict[str, Any] = {
    "schema": 1,
    "integrated_ram_margin_gib": 8,
    "tiers_on_image": ["tier0", "tier1", "tier2"],
    "tiers": {
        "tier0": {"min_vram_gib": 0, "max_vram_gib": 4, "cpu_ok": True, "models": []},
        "tier1": {"min_vram_gib": 4, "max_vram_gib": 6, "cpu_ok": False, "models": []},
        "tier2": {"min_vram_gib": 6, "max_vram_gib": 10, "cpu_ok": False, "models": []},
        "tier3": {"min_vram_gib": 10, "max_vram_gib": 20, "cpu_ok": False, "models": []},
        "tier4": {"min_vram_gib": 20, "max_vram_gib": None, "cpu_ok": False, "models": []},
    },
    "classifiers": {
        "nudenet": {"id": "NudeNet 320n (in the nudenet wheel)", "model_target": None},
        "siglip": {
            "id": "SigLIP base patch16-224 (ONNX)",
            "model_target": "models/siglip-base-patch16-224/model.onnx",
            "tokenizer_target": "models/siglip-base-patch16-224/tokenizer.json",
            "preprocessor_target": "models/siglip-base-patch16-224/preprocessor_config.json",
        },
    },
    "whisper": {
        "id": "faster-whisper small (CTranslate2)",
        "model_dir_target": "models/faster-whisper-small",
        "model_file": "model.bin",
    },
    "llama": {
        "prefix": "/opt/llama",
        "listen": "127.0.0.1:8088",
        "backend_port": 8089,
        "seed": 42,
        "ctx_size": 8192,
        "max_tokens": 384,
        "video_flag": "--video",
    },
    "venvs": {"triage": "/opt/triage", "whisper": "/opt/whisper"},
}


class ConfigError(ValueError):
    """A configuration file is missing a value or holds a wrong one."""


@dataclass(frozen=True)
class Thresholds:
    """Screening thresholds with their provenance (file path and SHA-256)."""

    nudity: float
    labels: dict[str, float]
    nudenet_classes: tuple[str, ...]
    label_template: str
    frame_interval_s: float
    scene_threshold: float
    max_frames: int
    max_image_frames: int = 64
    source: str = "built-in defaults"
    sha256: str = ""
    raw: dict[str, Any] = field(default_factory=dict)

    def threshold_for(self, label: str) -> float:
        return self.labels[label]

    def to_dict(self) -> dict[str, Any]:
        return {
            "nudity": self.nudity,
            "labels": dict(sorted(self.labels.items())),
            "nudenet_classes": list(self.nudenet_classes),
            "label_template": self.label_template,
            "video": {
                "frame_interval_s": self.frame_interval_s,
                "scene_threshold": self.scene_threshold,
                "max_frames": self.max_frames,
            },
            "image": {"max_frames": self.max_image_frames},
            "source": self.source,
            "sha256": self.sha256,
        }

    def compact(self) -> str:
        """One-line JSON of the values (for the CSV ``thresholds`` column)."""
        values = {"nudity": self.nudity, **{f"label:{k}": v for k, v in self.labels.items()}}
        return json.dumps(values, sort_keys=True, separators=(",", ":"))


def _unit(value: Any, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise ConfigError(f"{name}: expected a number from 0 to 1, got {value!r}")
    v = float(value)
    if not 0.0 <= v <= 1.0:
        raise ConfigError(f"{name}: expected a number from 0 to 1, got {v}")
    return v


def _count(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ConfigError(f"{name}: expected a whole number of 1 or more, got {value!r}")
    return value


def thresholds_from_dict(
    data: dict[str, Any], *, source: str = "built-in defaults", sha256: str = ""
) -> Thresholds:
    """Validate a thresholds document. Missing labels take their default value."""
    if not isinstance(data, dict):
        raise ConfigError("thresholds: expected a JSON object")
    merged = copy.deepcopy(DEFAULT_THRESHOLDS)
    for key, value in data.items():
        if key in {"labels", "video", "image"} and isinstance(value, dict):
            merged[key].update(value)
        else:
            merged[key] = value
    labels: dict[str, float] = {}
    for label in LABELS:
        if label == NEUTRAL_LABEL:
            continue
        labels[label] = _unit(merged["labels"].get(label), f"labels.{label}")
    unknown = set(merged["labels"]) - set(labels)
    if unknown:
        raise ConfigError(f"labels: unknown label(s) {', '.join(sorted(unknown))}")
    video = merged["video"]
    interval = float(video.get("frame_interval_s", 2))
    if interval <= 0:
        raise ConfigError("video.frame_interval_s: must be above 0")
    max_frames = _count(video.get("max_frames", 900), "video.max_frames")
    max_image_frames = _count(merged["image"].get("max_frames", 64), "image.max_frames")
    template = str(merged.get("label_template", ""))
    if "{label}" not in template:
        raise ConfigError("label_template: must contain {label}")
    return Thresholds(
        nudity=_unit(merged["nudity"], "nudity"),
        labels=labels,
        nudenet_classes=tuple(str(c) for c in merged.get("nudenet_classes", [])),
        label_template=template,
        frame_interval_s=interval,
        scene_threshold=_unit(video.get("scene_threshold", 0.4), "video.scene_threshold"),
        max_frames=max_frames,
        max_image_frames=max_image_frames,
        source=source,
        sha256=sha256,
        raw=merged,
    )


def thresholds_path() -> Path:
    return paths.etc_dir() / THRESHOLDS_FILE


def load_thresholds(path: str | os.PathLike[str] | None = None) -> Thresholds:
    """Load thresholds from ``path`` (default ``/etc/airlock/screen-thresholds.json``).

    A missing default file gives the built-in defaults. A missing file that was named
    explicitly, or a file that does not parse, is an error: screening never runs on a guess.
    """
    explicit = path is not None
    p = Path(path) if path is not None else thresholds_path()
    if not p.exists():
        if explicit:
            raise ConfigError(f"{p}: thresholds file not found")
        return thresholds_from_dict({})
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ConfigError(f"{p}: cannot read thresholds ({exc})") from exc
    return thresholds_from_dict(data, source=str(p), sha256=hashing.sha256_file(p))


def ai_config_path() -> Path:
    return paths.etc_dir() / AI_CONFIG_FILE


def load_ai_config(path: str | os.PathLike[str] | None = None) -> dict[str, Any]:
    """The AI config (tiers, model locations). Falls back to ``DEFAULT_AI_CONFIG``."""
    p = Path(path) if path is not None else ai_config_path()
    merged = copy.deepcopy(DEFAULT_AI_CONFIG)
    if not p.exists():
        if path is not None:
            raise ConfigError(f"{p}: AI config not found")
        return merged
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ConfigError(f"{p}: cannot read the AI config ({exc})") from exc
    if not isinstance(data, dict):
        raise ConfigError(f"{p}: expected a JSON object")
    for key, value in data.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict) and key != "tiers":
            merged[key].update(value)
        else:
            merged[key] = value
    return merged


def asset_file(target: str | None) -> Path | None:
    """Path of a staged file on ASSETS (``files/<target>``), or None when no target is set."""
    if not target:
        return None
    rel = Path(target)
    if rel.is_absolute() or ".." in rel.parts:
        raise ConfigError(f"{target}: asset targets are relative paths under ASSETS/files")
    return paths.assets_files_dir() / rel


def tier_state_path() -> Path:
    return paths.state_dir() / TIER_STATE_FILE


def venv_python(name: str, config: dict[str, Any] | None = None) -> Path:
    """The Python interpreter of a venv (``triage`` or ``whisper``). Env override for tests."""
    override = os.environ.get(f"AIRLOCK_{name.upper()}_PYTHON")
    if override:
        return Path(override)
    cfg = config or load_ai_config()
    return Path(cfg["venvs"][name]) / "bin" / "python"


def prompts_dir() -> Path:
    return Path(__file__).resolve().parent / "prompts"


@dataclass(frozen=True)
class Prompt:
    """A fixed prompt file, read once, with its SHA-256 (recorded with every AI row)."""

    prompt_id: str
    text: str
    sha256: str
    path: str


def load_prompt(prompt_id: str) -> Prompt:
    p = prompts_dir() / f"{prompt_id}.txt"
    try:
        data = p.read_bytes()
    except OSError as exc:
        raise ConfigError(f"prompt {prompt_id}: {exc.strerror}") from exc
    return Prompt(prompt_id, data.decode("utf-8"), hashing.sha256_bytes(data), str(p))
