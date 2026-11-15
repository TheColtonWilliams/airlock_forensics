"""Checks before provisioning, and the hardware and tool summary written after it.

Provisioning refuses to start while the machine could reach a network (a non-loopback
interface is up, or a default route exists) or while any disk other than the boot drive is
attached (it must never run with evidence attached). Paths under /sys and /proc can be moved
for tests with ``AIRLOCK_SYSFS_DIR`` and ``AIRLOCK_PROC_DIR``.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from airlock_common import devices, jsonio, paths, proc

IFF_UP = 0x1
RTF_REJECT = 0x0200
# Packages whose versions go into the provisioning manifest (when installed).
TOOL_PACKAGES: tuple[str, ...] = (
    "ansible",
    "bulk-extractor",
    "clamav",
    "dc3dd",
    "dotnet-runtime-9.0",
    "ewf-tools",
    "exiv2",
    "ffmpeg",
    "foremost",
    "gddrescue",
    "guymager",
    "hashdeep",
    "libimage-exiftool-perl",
    "mediainfo",
    "ntfs-3g",
    "plaso",
    "python3",
    "python3-plaso",
    "scalpel",
    "sleuthkit",
    "ssdeep",
    "testdisk",
    "yara",
)


def sysfs_dir() -> Path:
    return Path(os.environ.get("AIRLOCK_SYSFS_DIR") or "/sys")


def proc_dir() -> Path:
    return Path(os.environ.get("AIRLOCK_PROC_DIR") or "/proc")


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        return ""


def network_problems() -> list[str]:
    """Reasons the machine is not offline: interfaces up, default routes. Empty when offline."""
    problems: list[str] = []
    net = sysfs_dir() / "class" / "net"
    for iface in sorted(net.iterdir()) if net.is_dir() else []:
        if iface.name == "lo":
            continue
        flags_text = _read(iface / "flags")
        try:
            flags = int(flags_text, 16) if flags_text else 0
        except ValueError:
            flags = 0
        oper = _read(iface / "operstate")
        if flags & IFF_UP or oper == "up":
            problems.append(f"network interface {iface.name} is up")
    for line in _read(proc_dir() / "net" / "route").splitlines()[1:]:
        cols = line.split()
        if len(cols) >= 8 and cols[1] == "00000000" and cols[7] == "00000000":
            problems.append(f"an IPv4 default route exists (via {cols[0]})")
    for line in _read(proc_dir() / "net" / "ipv6_route").splitlines():
        cols = line.split()
        if len(cols) < 10 or cols[9] == "lo":
            continue
        try:
            flags = int(cols[8], 16)
        except ValueError:
            flags = 0
        if cols[0] == "0" * 32 and cols[1] == "00" and not flags & RTF_REJECT:
            problems.append(f"an IPv6 default route exists (via {cols[9]})")
    return problems


def disk_problems() -> list[str]:
    """Every disk other than the boot drive, described for the refusal message."""
    try:
        disks = devices.attached_disks()
    except (proc.ToolError, OSError, ValueError) as exc:
        return [f"could not list the disks ({exc}); refusing to run blind"]
    out = []
    for d in disks:
        gb = d.size / 1_000_000_000
        out.append(f"{d.path} ({gb:.1f} GB{', ' + d.tran if d.tran else ''}) is attached")
    return out


def root_problem() -> str | None:
    if os.geteuid() == 0 or os.environ.get("AIRLOCK_ALLOW_NONROOT") == "1":
        return None
    return "must run as root"


def firmware() -> str:
    return "uefi" if (sysfs_dir() / "firmware" / "efi").is_dir() else "bios"


def has_nic() -> bool:
    net = sysfs_dir() / "class" / "net"
    return net.is_dir() and any(p.name != "lo" for p in net.iterdir())


def hardware_summary() -> dict[str, Any]:
    """Capacities only (no decision depends on a vendor): CPU, memory, firmware, GPUs, drive."""
    cpu_model = ""
    for line in _read(proc_dir() / "cpuinfo").splitlines():
        if line.startswith("model name"):
            cpu_model = line.split(":", 1)[1].strip()
            break
    mem = 0
    for line in _read(proc_dir() / "meminfo").splitlines():
        if line.startswith("MemTotal:"):
            parts = line.split()
            mem = int(parts[1]) * 1024 if len(parts) > 1 and parts[1].isdigit() else 0
            break
    gpus = []
    drm = sysfs_dir() / "class" / "drm"
    for card in sorted(drm.glob("card[0-9]*")) if drm.is_dir() else []:
        if "-" in card.name:
            continue  # connectors such as card0-HDMI-A-1
        vendor = _read(card / "device" / "vendor").removeprefix("0x")
        device = _read(card / "device" / "device").removeprefix("0x")
        if vendor:
            gpus.append({"card": card.name, "pci_id": f"{vendor}:{device}"})
    boot: dict[str, Any] = {}
    try:
        disk = devices.boot_disk()
    except (proc.ToolError, OSError, ValueError):
        disk = None
    if disk is not None:
        boot = {"path": disk.path, "size_bytes": disk.size, "tran": disk.tran}
    ai_tier = {}
    try:
        data = jsonio.load_json(paths.state_dir() / "ai-tier.json")
        ai_tier = data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        pass
    return {
        "ai_tier": ai_tier,
        "boot_disk": boot,
        "cpu_model": cpu_model,
        "cpus": os.cpu_count() or 0,
        "firmware": firmware(),
        "gpus": gpus,
        "memory_bytes": mem,
    }


def tool_versions() -> dict[str, str]:
    """Installed versions of the main tool packages, from dpkg (empty where dpkg is absent)."""
    if proc.which("dpkg-query") is None:
        return {}
    try:
        res = proc.run(
            ["dpkg-query", "-W", "-f", "${Package}\t${Version}\t${db:Status-Status}\n",
             *TOOL_PACKAGES],
            check=False,
            timeout=120,
        )  # fmt: skip
    except proc.ToolError:
        return {}
    out: dict[str, str] = {}
    for line in res.stdout.splitlines():
        cols = line.split("\t")
        if len(cols) == 3 and cols[2] == "installed":
            out[cols[0]] = cols[1]
    return dict(sorted(out.items()))


def build_info() -> dict[str, Any]:
    try:
        data = jsonio.load_json(paths.build_info())
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}
