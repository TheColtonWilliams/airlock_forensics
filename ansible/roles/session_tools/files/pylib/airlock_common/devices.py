"""Block device discovery from ``lsblk -J -b``. Read-only: nothing here changes a device.

``AIRLOCK_LSBLK_JSON`` (a file path) replaces the lsblk call in tests.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from airlock_common import proc

LSBLK_COLUMNS = (
    "NAME,KNAME,PKNAME,PATH,TYPE,SIZE,RO,RM,TRAN,MODEL,SERIAL,FSTYPE,LABEL,UUID,MOUNTPOINTS"
)


@dataclass
class BlockDevice:
    name: str
    path: str
    type: str  # disk | part | loop | rom | lvm | crypt ...
    size: int
    ro: bool
    rm: bool
    tran: str = ""
    model: str = ""
    serial: str = ""
    fstype: str = ""
    label: str = ""
    uuid: str = ""
    pkname: str = ""
    mountpoints: list[str] = field(default_factory=list)
    children: list[BlockDevice] = field(default_factory=list)

    def walk(self) -> list[BlockDevice]:
        out = [self]
        for c in self.children:
            out += c.walk()
        return out

    @property
    def mounted(self) -> bool:
        return any(m for m in self.mountpoints) or any(c.mounted for c in self.children)


def _bool(v: Any) -> bool:
    if isinstance(v, bool):
        return v
    return str(v).strip() in {"1", "true", "True"}


def _parse(node: dict[str, Any], parent: str = "") -> BlockDevice:
    mps = node.get("mountpoints") or ([node["mountpoint"]] if node.get("mountpoint") else [])
    dev = BlockDevice(
        name=str(node.get("name") or node.get("kname") or ""),
        path=str(node.get("path") or f"/dev/{node.get('name', '')}"),
        type=str(node.get("type") or ""),
        size=int(node.get("size") or 0),
        ro=_bool(node.get("ro", False)),
        rm=_bool(node.get("rm", False)),
        tran=str(node.get("tran") or ""),
        model=str(node.get("model") or "").strip(),
        serial=str(node.get("serial") or "").strip(),
        fstype=str(node.get("fstype") or ""),
        label=str(node.get("label") or ""),
        uuid=str(node.get("uuid") or ""),
        pkname=str(node.get("pkname") or parent),
        mountpoints=[m for m in mps if m],
    )
    dev.children = [_parse(c, dev.name) for c in node.get("children") or []]
    return dev


def lsblk() -> list[BlockDevice]:
    """Top-level block devices with their partitions as children."""
    fixture = os.environ.get("AIRLOCK_LSBLK_JSON")
    if fixture:
        data = json.loads(Path(fixture).read_text(encoding="utf-8"))
    else:
        res = proc.run(["lsblk", "-J", "-b", "-o", LSBLK_COLUMNS])
        data = json.loads(res.stdout)
    return [_parse(n) for n in data.get("blockdevices", [])]


def boot_disk(devices: list[BlockDevice] | None = None) -> BlockDevice | None:
    """The top-level disk that holds ``/`` (the AIRLOCK drive itself)."""
    for disk in devices if devices is not None else lsblk():
        for d in disk.walk():
            if "/" in d.mountpoints:
                return disk
    return None


def attached_disks(devices: list[BlockDevice] | None = None) -> list[BlockDevice]:
    """Every top-level disk except the boot disk, loop, rom, and zram devices."""
    devs = devices if devices is not None else lsblk()
    boot = boot_disk(devs)
    out = []
    for d in devs:
        if d.type != "disk" or d.name.startswith(("zram", "ram")):
            continue
        if boot is not None and d.name == boot.name:
            continue
        out.append(d)
    return out


def is_readonly(dev_path: str) -> bool:
    """Kernel read-only flag (``blockdev --getro``): software read-only policy only."""
    sysfs = Path("/sys/class/block") / Path(dev_path).name / "ro"
    if sysfs.exists():
        return sysfs.read_text().strip() == "1"
    res = proc.run(["blockdev", "--getro", dev_path])
    return res.stdout.strip() == "1"
