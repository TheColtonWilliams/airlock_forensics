"""Shared pieces of the session helpers: errors, root checks, config, target description.

Paths come from :mod:`airlock_common.paths`. Three test-only overrides are read here because
they name kernel interfaces, not AIRLOCK folders: ``AIRLOCK_SYSFS`` (default ``/sys``),
``AIRLOCK_PROCFS`` (default ``/proc``), and ``AIRLOCK_RUN_DIR`` (default ``/run/airlock``, the
folder ``airlock-setro`` reads its ``rw-allow`` markers from).
"""

from __future__ import annotations

import contextlib
import os
import re
import stat
import sys
from collections.abc import Callable
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from airlock_common import devices, jsonio, paths, proc, sessionlog, ui

OUTPUT_CAP = 256 * 1024  # bytes of tool output kept per session-log line
_ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")

CONFIG_NAME = "airlock.conf.json"


class CommandError(RuntimeError):
    """A command cannot go on. The message says what failed and what to do next."""


def sysfs() -> Path:
    return Path(os.environ.get("AIRLOCK_SYSFS") or "/sys")


def procfs() -> Path:
    return Path(os.environ.get("AIRLOCK_PROCFS") or "/proc")


def run_dir() -> Path:
    return Path(os.environ.get("AIRLOCK_RUN_DIR") or "/run/airlock")


def is_root() -> bool:
    return os.geteuid() == 0


def require_root(command: str) -> None:
    if not is_root():
        raise CommandError(f"{command} needs root. Run it again with sudo in front: sudo {command}")


def open_session_log(tool: str) -> Path:
    """The current session file (created if needed); fails early if it cannot be written."""
    try:
        path = sessionlog.session_path(tool)
        with open(path, "a", encoding="utf-8"):
            pass
    except PermissionError as exc:
        raise CommandError(
            f"cannot write the session log in {paths.session_dir()}. "
            "Run the command again with sudo in front."
        ) from exc
    return path


_RESERVED = frozenset({"ts", "event", "tool", "pid"})


def log(tool: str, event: str, /, **fields: Any) -> dict[str, Any]:
    """Append one event. Field names that clash with the required keys get a ``field_`` prefix."""
    safe = {(f"field_{k}" if k in _RESERVED else k): v for k, v in fields.items()}
    return sessionlog.log_event(tool, event, **safe)


def run_main(tool: str, body: Callable[[], int]) -> int:
    """Run a command body; turn known errors into one line on stderr and a non-zero exit."""
    try:
        return body()
    except CommandError as exc:
        return _report(tool, str(exc), 1)
    except ui.NonInteractiveError as exc:
        return _report(tool, f"{exc}. Run it in a terminal or pass the flag.", 2)
    except proc.ToolError as exc:
        return _report(tool, f"{exc}. Check that the tool is installed, then run again.", 1)
    except KeyboardInterrupt:
        return _report(tool, "stopped by the operator. Run the command again to start over.", 130)


def _report(tool: str, message: str, code: int) -> int:
    print(f"{tool}: {message}", file=sys.stderr)
    with contextlib.suppress(OSError):
        sessionlog.log_event(tool, "failed", reason=message, exit_code=code)
    return code


# ------------------------------------------------------------------ config


def config_defaults() -> dict[str, Any]:
    out = paths.output_dir()
    return {
        "schema": 1,
        "image_max_age_days": 90,
        "nsrl_path": "",
        "output_dir": str(out),
        "cases_dir": str(out / "cases"),
        "mount_base": "/mnt/airlock",
    }


def load_config() -> dict[str, Any]:
    """``/etc/airlock/airlock.conf.json`` over the built-in defaults. A bad file is ignored."""
    cfg = config_defaults()
    path = paths.etc_dir() / CONFIG_NAME
    try:
        data = jsonio.load_json(path)
    except FileNotFoundError:
        return cfg
    except (OSError, ValueError) as exc:
        cfg["config_error"] = f"{path}: {exc}"
        return cfg
    if isinstance(data, dict):
        cfg.update({k: v for k, v in data.items() if v is not None})
    else:
        cfg["config_error"] = f"{path}: not a JSON object"
    return cfg


# ------------------------------------------------------------------ targets


@dataclass
class TargetInfo:
    path: str
    kind: str  # "device" | "image"
    size_bytes: int
    name: str = ""
    model: str = ""
    serial: str = ""
    readonly: bool | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def readonly_flag(name: str) -> bool | None:
    """The kernel read-only flag of a block device from sysfs; None if unknown."""
    try:
        return (sysfs() / "class" / "block" / name / "ro").read_text().strip() == "1"
    except OSError:
        return None


def _device_size(path: Path) -> int:
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
    try:
        return os.lseek(fd, 0, os.SEEK_END)
    finally:
        os.close(fd)


def find_device(path: str) -> devices.BlockDevice | None:
    """The lsblk entry for a device path (or kernel name), searching disks and partitions."""
    want = {path, Path(path).name}
    try:
        tree = devices.lsblk()
    except (proc.ToolError, OSError, ValueError):
        return None
    for top in tree:
        for d in top.walk():
            if d.path in want or d.name in want:
                return d
    return None


def describe_target(arg: str) -> TargetInfo:
    """Work out whether ``arg`` is a block device or an image file. Never opens it for writing."""
    p = Path(arg)
    if not p.exists():
        raise CommandError(
            f"{arg} does not exist. List drives with lsblk, or check the image file name with ls."
        )
    real = p.resolve()
    st = real.stat()
    if stat.S_ISBLK(st.st_mode):
        info = TargetInfo(str(real), "device", _device_size(real), name=real.name)
        dev = find_device(str(real))
        if dev is not None:
            info.model, info.serial = dev.model, dev.serial
        info.readonly = readonly_flag(real.name)
        return info
    if stat.S_ISREG(st.st_mode):
        return TargetInfo(str(real), "image", st.st_size, name=real.name)
    raise CommandError(f"{arg} is not a drive or an image file. Name a device such as /dev/sdb.")


# ------------------------------------------------------------------ text helpers


def clean_output(text: str, cap: int = OUTPUT_CAP) -> tuple[str, bool]:
    """Tool output for the log: colour codes removed, cut at ``cap`` bytes."""
    text = _ANSI.sub("", text)
    raw = text.encode("utf-8", "replace")
    if len(raw) <= cap:
        return text, False
    return raw[:cap].decode("utf-8", "ignore"), True


def human_size(n: int) -> str:
    size = float(n)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if size < 1024 or unit == "TiB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{n} B"  # pragma: no cover
