"""Write tracer (task 3A.5): count write and discard requests sent to the target during a run.

Primary method: the kernel's per-device block-layer counters in ``/sys/block/<dev>/stat``
(``/sys/class/block/<part>/stat`` for a partition, the loop device's own file for an image on a
loop device). They count every write, discard, and flush request the block layer completed for
that device, from any process. The tracer samples them before and after the run; the
difference is the write-request count. The expected value is 0.

Optional detail: when ``blktrace`` is installed and debugfs is available, the tracer also
records each write or discard request (sector, size, process) to the run's log folder.

A plain image file with no loop device is ``not_applicable``: its before and after hashes are
the check.
"""

from __future__ import annotations

import os
import shutil
import signal
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

SYS_CLASS_BLOCK = Path("/sys/class/block")

# Field positions in the block stat file (Documentation/block/stat.rst).
FIELDS: dict[str, int] = {
    "read_ios": 0,
    "read_sectors": 2,
    "write_ios": 4,
    "write_merges": 5,
    "write_sectors": 6,
    "discard_ios": 11,
    "discard_merges": 12,
    "discard_sectors": 13,
    "flush_ios": 15,
}
WRITE_KEYS = ("write_ios", "write_sectors", "discard_ios", "discard_sectors", "flush_ios")


def stat_path(device: str | os.PathLike[str], *, sys_root: Path = SYS_CLASS_BLOCK) -> Path | None:
    """The stat file for a block device path such as ``/dev/sdb``, ``/dev/sdb1``, ``/dev/loop3``."""
    name = Path(os.path.realpath(device)).name
    candidate = sys_root / name / "stat"
    return candidate if candidate.exists() else None


def parse_stat(text: str) -> dict[str, int]:
    parts = text.split()
    out: dict[str, int] = {}
    for key, idx in FIELDS.items():
        out[key] = int(parts[idx]) if idx < len(parts) else 0
    return out


def read_counters(path: Path) -> dict[str, int]:
    return parse_stat(path.read_text(encoding="ascii"))


@dataclass
class TraceResult:
    method: str  # block_stat | not_applicable | unavailable
    device: str = ""
    stat_file: str = ""
    before: dict[str, int] = field(default_factory=dict)
    after: dict[str, int] = field(default_factory=dict)
    delta: dict[str, int] = field(default_factory=dict)
    write_requests: int | None = None
    reason: str = ""
    blktrace: dict[str, Any] = field(default_factory=dict)

    @property
    def clean(self) -> bool | None:
        """True when the count is 0, False when writes were seen, None when not measured."""
        if self.write_requests is None:
            return None
        return self.write_requests == 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "method": self.method,
            "device": self.device,
            "stat_file": self.stat_file,
            "before": self.before,
            "after": self.after,
            "delta": self.delta,
            "write_requests": self.write_requests,
            "expected": 0,
            "clean": self.clean,
            "reason": self.reason,
            "blktrace": self.blktrace,
        }


class WriteTracer:
    """Sample a device's write counters at ``start()`` and ``stop()``."""

    def __init__(
        self,
        device: str | os.PathLike[str] | None,
        *,
        sys_root: Path = SYS_CLASS_BLOCK,
        blktrace_dir: Path | None = None,
        reason_if_none: str = "",
    ) -> None:
        self.device = str(device) if device else ""
        self.sys_root = sys_root
        self.stat: Path | None = stat_path(self.device, sys_root=sys_root) if device else None
        self.result = TraceResult(method="block_stat" if self.stat else "unavailable")
        self.result.device = self.device
        self.blktrace_dir = blktrace_dir
        self._bt: subprocess.Popen[bytes] | None = None
        if not device:
            self.result.method = "not_applicable"
            self.result.reason = reason_if_none or "file target, checked by hash"
        elif self.stat is None:
            self.result.reason = f"no block stat file for {self.device}"
        else:
            self.result.stat_file = str(self.stat)

    def start(self) -> None:
        if self.stat is not None:
            self.result.before = read_counters(self.stat)
        self._start_blktrace()

    def stop(self) -> TraceResult:
        self._stop_blktrace()
        if self.stat is not None:
            self.result.after = read_counters(self.stat)
            delta = {
                k: max(0, self.result.after.get(k, 0) - self.result.before.get(k, 0))
                for k in FIELDS
            }
            self.result.delta = delta
            self.result.write_requests = (
                delta["write_ios"] + delta["discard_ios"] + delta["flush_ios"]
            )
        return self.result

    # Optional blktrace detail ---------------------------------------------------------------

    def _start_blktrace(self) -> None:
        if self.stat is None or self.blktrace_dir is None:
            return
        bt = shutil.which("blktrace")
        if not bt or not Path("/sys/kernel/debug/block").is_dir():
            self.result.blktrace = {"status": "not available"}
            return
        self.blktrace_dir.mkdir(parents=True, exist_ok=True)
        dev = os.path.realpath(self.device)
        argv = [bt, "-d", dev, "-a", "write", "-a", "discard", "-D", str(self.blktrace_dir)]
        try:
            self._bt = subprocess.Popen(
                argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True
            )
            self.result.blktrace = {"status": "running", "argv": argv}
        except OSError as exc:
            self.result.blktrace = {"status": f"failed to start: {exc}"}

    def _stop_blktrace(self) -> None:
        if self._bt is None:
            return
        self._bt.send_signal(signal.SIGINT)
        try:
            self._bt.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self._bt.kill()
            self._bt.wait()
        self.result.blktrace["status"] = "stopped"
        self.result.blktrace["files"] = sorted(
            p.name for p in (self.blktrace_dir or Path()).glob("*.blktrace.*")
        )
        self._bt = None


def trace_device_for(target_path: str, kind: str, loop_device: str | None) -> str | None:
    """Which device to trace: the device itself, or the loop device an image sits on."""
    if kind == "device":
        return target_path
    return loop_device
