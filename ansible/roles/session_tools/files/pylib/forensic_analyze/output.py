"""Output picker (task 4C.3).

The default is the drive's own ``OUTPUT`` partition. Another drive can be used once it has been
made writable with ``evidence-unlock-output``. The picker checks that the folder is writable, is
not on the evidence drive, and has room for a rough estimate of the chosen modules and mode.
"""

from __future__ import annotations

import os
import shutil
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from airlock_common import paths
from forensic_analyze import presets
from forensic_analyze.target import human_size


class OutputError(RuntimeError):
    """The output folder cannot be used. The message says why and what to do."""


@dataclass
class OutputCheck:
    root: str
    free_bytes: int
    needed_bytes: int
    estimate: str
    enough_space: bool
    hard_requirement: bool  # image mode: the copy must fit

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def default_root() -> Path:
    return paths.output_dir()


def _top_disk(sys_dir: Path) -> str:
    """Disk name for a /sys block folder; a partition's folder sits inside its disk's folder."""
    if not sys_dir.exists():
        return ""
    if (sys_dir / "partition").exists():
        return sys_dir.parent.name
    return sys_dir.name


def disk_of(path: Path) -> str:
    """The top-level block device name holding ``path`` (e.g. ``sdb``), or "" if unknown."""
    try:
        dev = os.stat(path).st_dev
        return _top_disk(Path(f"/sys/dev/block/{os.major(dev)}:{os.minor(dev)}").resolve())
    except OSError:
        return ""


def disk_of_device(dev_path: str) -> str:
    """The top-level disk name of a device node (``/dev/sdb1`` gives ``sdb``)."""
    name = Path(os.path.realpath(dev_path)).name
    try:
        return _top_disk((Path("/sys/class/block") / name).resolve()) or name
    except OSError:
        return name


def check_writable(root: Path) -> None:
    if not root.is_dir():
        raise OutputError(
            f"Output folder {root} does not exist. Plug in the output drive and unlock it with "
            "evidence-unlock-output, or pass --output with an existing folder."
        )
    try:
        fd, name = tempfile.mkstemp(prefix=".airlock-write-test.", dir=root)
        os.close(fd)
        os.unlink(name)
    except OSError as exc:
        raise OutputError(
            f"Output folder {root} is not writable ({exc.strerror}). "
            "Unlock the drive with evidence-unlock-output, or pick another folder."
        ) from exc


def check_not_target(root: Path, target_path: str, target_kind: str) -> None:
    if target_kind != "device":
        return
    target_disk = disk_of_device(target_path)
    holder = disk_of(root)
    if holder and target_disk and holder == target_disk:
        raise OutputError(
            f"Output folder {root} is on the evidence drive {target_path}. "
            "Choose a folder on another drive."
        )


def check_space(
    root: Path, modules: list[str], target_bytes: int, *, image_mode: bool
) -> OutputCheck:
    est = presets.estimate(modules, target_bytes, image_mode=image_mode)
    free = shutil.disk_usage(root).free
    needed = est.output_bytes
    return OutputCheck(
        root=str(root),
        free_bytes=free,
        needed_bytes=needed,
        estimate=est.describe(),
        enough_space=free >= needed,
        hard_requirement=image_mode,
    )


def space_message(chk: OutputCheck) -> str:
    return (
        f"The output drive has {human_size(chk.free_bytes)} free; this run needs "
        f"about {human_size(chk.needed_bytes)}."
    )


def prepare(
    root: Path,
    *,
    target_path: str,
    target_kind: str,
    target_bytes: int,
    modules: list[str],
    image_mode: bool,
) -> OutputCheck:
    """All output checks. Raises ``OutputError`` for a hard failure; returns the space check."""
    check_writable(root)
    check_not_target(root, target_path, target_kind)
    chk = check_space(root, modules, target_bytes, image_mode=image_mode)
    if image_mode and not chk.enough_space:
        raise OutputError(
            space_message(chk) + " Copy-first mode needs room for a full copy. "
            "Use a larger output drive or --mode direct."
        )
    return chk
