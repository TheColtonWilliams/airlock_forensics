"""End-of-run purge of exported file copies (task 4C.19).

After a run, the examiner can delete every copy of a file taken from the drive and keep only
findings, CSVs, transcripts, descriptions, logs, and the report. Nothing from the drive is then
kept beyond the findings.

What counts as an exported copy (the convention every module follows):

* ``modules/<name>/export/`` and ``modules/<name>/exports/``: files exported from the target;
* ``modules/<name>/carved/``: files carved from unallocated space;
* ``extract/``: system files copied out for parsing (``$MFT``, ``$UsnJrnl:$J``, ...);
* ``decrypted/``: a decrypted BitLocker working copy.

The forensic copy made in copy-first mode (``image/``) is evidence, not an export, and is kept.
``outputs.sha256`` and its signature are rewritten afterwards by the caller.
"""

from __future__ import annotations

import contextlib
import os
import shutil
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from airlock_common import timeutil

MODULE_EXPORT_DIRS = ("export", "exports", "carved")
RUN_EXPORT_DIRS = ("extract", "decrypted")


@dataclass
class PurgeResult:
    removed_files: int = 0
    removed_bytes: int = 0
    folders: list[str] = field(default_factory=list)
    ts: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def export_dirs(run_dir: Path) -> list[Path]:
    found: list[Path] = []
    modules = run_dir / "modules"
    if modules.is_dir():
        for mod in sorted(p for p in modules.iterdir() if p.is_dir()):
            for name in MODULE_EXPORT_DIRS:
                cand = mod / name
                if cand.is_dir() and not cand.is_symlink():
                    found.append(cand)
    for name in RUN_EXPORT_DIRS:
        cand = run_dir / name
        if cand.is_dir() and not cand.is_symlink():
            found.append(cand)
    return found


def purge_exports(run_dir: Path) -> PurgeResult:
    """Delete every exported file copy under ``run_dir``. Returns what was removed."""
    res = PurgeResult(ts=timeutil.iso())
    root = run_dir.resolve()
    for folder in export_dirs(run_dir):
        if root not in folder.resolve().parents:
            continue  # never follow anything out of the run folder
        for dirpath, _dirs, files in os.walk(folder):
            for name in files:
                p = Path(dirpath) / name
                with contextlib.suppress(OSError):
                    res.removed_bytes += p.lstat().st_size
                res.removed_files += 1
        _make_writable(folder)
        shutil.rmtree(folder)
        res.folders.append(folder.relative_to(run_dir).as_posix())
    return res


def _make_writable(folder: Path) -> None:
    """Read-only copies (e.g. a decrypted image made 0444) need the folder writable to delete."""
    for dirpath, dirs, _files in os.walk(folder):
        for d in dirs:
            with contextlib.suppress(OSError):
                os.chmod(Path(dirpath) / d, 0o700)
    with contextlib.suppress(OSError):
        os.chmod(folder, 0o700)
