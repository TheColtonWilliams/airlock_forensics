"""Presets (task 4C.4) and rough time and space estimates.

Quick, Standard, and Full are fixed module lists (docs/dev/contract.md section 8a). Custom is a
checklist of the modules that exist on this build. The estimates are rough planning numbers for
the output picker and the docs, not promises.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass

QUICK: tuple[str, ...] = ("inventory", "recycle_bin", "deletion_history", "malware")
STANDARD: tuple[str, ...] = (*QUICK, "users", "images", "video", "audio", "documents", "timeline")
FULL: tuple[str, ...] = (*STANDARD, "carve")

PRESETS: dict[str, tuple[str, ...]] = {"quick": QUICK, "standard": STANDARD, "full": FULL}
PRESET_NAMES: tuple[str, ...] = ("quick", "standard", "full", "custom")

PRESET_HELP: dict[str, str] = {
    "quick": "File list, recycle bin, deletion history, hash triage",
    "standard": "Quick plus users, images, video, audio, documents, timeline",
    "full": "Standard plus carving of unallocated space (slow)",
    "custom": "Pick the categories yourself",
}

GIB = 1024**3

# Rough minutes per 100 GiB of target for each module on a USB 3 SSD at about 150 MB/s.
MINUTES_PER_100GIB: dict[str, float] = {
    "inventory": 10,
    "recycle_bin": 1,
    "deletion_history": 5,
    "users": 5,
    "malware": 30,
    "images": 30,
    "video": 60,
    "audio": 60,
    "documents": 20,
    "timeline": 120,
    "carve": 180,
}

# Rough share of the target size each module may write to the output drive.
OUTPUT_SHARE: dict[str, float] = {
    "inventory": 0.002,
    "recycle_bin": 0.0005,
    "deletion_history": 0.005,
    "users": 0.001,
    "malware": 0.001,
    "images": 0.05,
    "video": 0.10,
    "audio": 0.03,
    "documents": 0.03,
    "timeline": 0.02,
    "carve": 0.20,
}

HASH_MB_PER_S = 150.0
BASE_OUTPUT_BYTES = 64 * 1024**2


class PresetError(ValueError):
    """An unknown preset or module name."""


def modules_for(
    preset: str, available: Sequence[str], custom: Iterable[str] | None = None
) -> tuple[list[str], list[str]]:
    """Return (planned, missing): modules of ``preset`` in run order, and those not on this build.

    ``available`` is the registry's module names in run order. For ``custom``, ``custom`` lists
    the wanted names; unknown names raise ``PresetError``.
    """
    if preset == "custom":
        wanted = [m.strip() for m in (custom or []) if m.strip()]
        if not wanted:
            raise PresetError("custom preset needs --modules a,b,c")
        unknown = [m for m in wanted if m not in FULL and m not in available]
        if unknown:
            raise PresetError(f"unknown module(s): {', '.join(unknown)}")
    elif preset in PRESETS:
        wanted = list(PRESETS[preset])
    else:
        raise PresetError(f"unknown preset {preset!r}; use quick, standard, full, or custom")
    planned = [m for m in available if m in wanted]
    missing = [m for m in wanted if m not in available]
    return planned, missing


@dataclass(frozen=True)
class Estimate:
    minutes: float
    output_bytes: int

    def describe(self) -> str:
        hours, mins = divmod(round(self.minutes), 60)
        span = f"{hours} h {mins} min" if hours else f"{mins} min"
        return f"about {span}, about {self.output_bytes / GIB:.1f} GiB of output"


def estimate(modules: Iterable[str], target_bytes: int, *, image_mode: bool = False) -> Estimate:
    """Rough run time and output size for ``modules`` on a target of ``target_bytes``."""
    size_100g = target_bytes / (100 * GIB)
    mods = list(modules)
    minutes = sum(MINUTES_PER_100GIB.get(m, 10) for m in mods) * size_100g
    # Before and after hashes are two full read passes; image mode adds a copy and a verify.
    passes = 4 if image_mode else 2
    minutes += passes * (target_bytes / (HASH_MB_PER_S * 1e6)) / 60
    out = BASE_OUTPUT_BYTES + int(sum(OUTPUT_SHARE.get(m, 0.01) for m in mods) * target_bytes)
    if image_mode:
        out += target_bytes
    return Estimate(minutes=minutes, output_bytes=out)
