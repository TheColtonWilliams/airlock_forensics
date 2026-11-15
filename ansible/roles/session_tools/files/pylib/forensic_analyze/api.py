"""The contract between the runner and analysis modules. See docs/dev/contract.md section 8.

Modules live in ``forensic_analyze/modules/<name>.py`` and expose ``MODULE``, an instance of a
``Module`` subclass. The runner builds a ``ModuleContext`` for each and calls ``run``.
"""

from __future__ import annotations

import json
import subprocess
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

Derivation = Literal["observed", "inferred", "ai_generated"]
Status = Literal["ok", "skipped", "failed"]


@dataclass(frozen=True)
class Volume:
    """One filesystem found on the target (from mmls/fsstat)."""

    index: int
    offset_bytes: int
    size_bytes: int
    fs_type: str  # lower-case: "ntfs", "exfat", "fat32", "fat16", "ext4", "unknown", ...
    label: str = ""
    bitlocker: bool = False


@dataclass(frozen=True)
class Target:
    """What is being analysed. ``path`` is a read-only block device or an image file."""

    path: Path
    kind: Literal["device", "image"]
    evidence_id: str
    sha256: str = ""
    md5: str = ""
    size_bytes: int = 0
    model: str = ""
    serial: str = ""
    volumes: tuple[Volume, ...] = ()

    def volumes_of(self, *fs_types: str) -> list[Volume]:
        wanted = {t.lower() for t in fs_types}
        return [v for v in self.volumes if v.fs_type in wanted]


@dataclass
class ModuleResult:
    status: Status
    reason: str = ""
    counts: dict[str, int] = field(default_factory=dict)


# Signature of ModuleContext.tool: argv -> CompletedProcess-like result.
ToolRunner = Callable[..., subprocess.CompletedProcess[str]]


@dataclass
class ModuleContext:
    """Everything a module may use. Modules must not reach around it."""

    run_id: str
    module: str
    target: Target
    workdir: Path
    options: Mapping[str, Any]
    emit: Callable[[dict[str, Any]], None]
    tool: ToolRunner
    log: Callable[..., None]
    tool_version: Callable[[str], str]
    shared: dict[str, Any] = field(default_factory=dict)
    """Results other modules published for reuse (e.g. extracted $MFT path). Keys are documented
    by the producing module; read-only for consumers."""


class Module:
    """Base class. Subclasses set the class attributes and implement ``run``."""

    name: str = ""
    title: str = ""
    fs_types: frozenset[str] | None = None
    order: int = 100
    description: str = ""

    def applicable(self, target: Target) -> tuple[bool, str]:
        """Return (True, "") if the module can run on this target, else (False, reason)."""
        if self.fs_types is None:
            return True, ""
        if target.volumes_of(*self.fs_types):
            return True, ""
        found = ", ".join(sorted({v.fs_type for v in target.volumes})) or "none"
        need = ", ".join(sorted(self.fs_types))
        return False, f"needs a {need} volume; found: {found}"

    def run(self, ctx: ModuleContext) -> ModuleResult:  # pragma: no cover - abstract
        raise NotImplementedError


def sorted_rows(rows: Sequence[dict[str, Any]], *keys: str) -> list[dict[str, Any]]:
    """Sort rows deterministically by the given keys (missing values sort first), then by JSON."""

    def key(row: dict[str, Any]) -> tuple[Any, ...]:
        parts: list[Any] = []
        for k in keys:
            v = row.get(k)
            parts.append((0, "") if v is None else (1, str(v)))
        parts.append(json.dumps(row, sort_keys=True, default=str))
        return tuple(parts)

    return sorted(rows, key=key)
