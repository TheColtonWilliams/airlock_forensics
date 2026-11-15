"""Target picker and target checks (tasks 4C.2, 4C.22, 3A.6, 3A.7; surviving risk 15).

* Lists attached disks (never the boot drive) and image files (E01, raw) with model, serial,
  size, and filesystem.
* Refuses a device whose kernel read-only flag is not set, a mounted device, and the boot drive.
  Image files are always opened read-only.
* HPA and DCO: ``hdparm -N`` and ``hdparm --dco-identify`` are read-only queries; the result is
  logged and nothing is ever set or removed. Skipped on drives that are not ATA.
* SSDs and flash (``rotational`` 0) get a warning that the drive's own garbage collection can
  change the before and after hashes.
* SMART: before a Full run that reads the device directly, ``smartctl -H -A`` (a read-only query)
  warns about a failing drive. Skipped silently when the bridge does not pass SMART through.
* Hardware write blocker record: make, model, firmware, and a link to its test report.
"""

from __future__ import annotations

import json
import os
import re
import stat
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from airlock_common import devices, proc
from forensic_analyze import fsdetect

ADVISORY_TEXT = (
    "Connect the evidence drive through a hardware write blocker if you have one, "
    "ideally one with a published NIST CFTT or DHS test report.\n\n"
    "AIRLOCK also sets a software read-only policy on every attached drive. That policy is a "
    "second layer of protection. It is not a substitute for a hardware write blocker."
)
SSD_WARNING = (
    "This drive is an SSD or flash drive. Its own firmware can move or erase data "
    "(garbage collection, TRIM) while powered, so the before and after hashes may differ even "
    "though AIRLOCK wrote nothing."
)
IMAGE_SUFFIXES = (*fsdetect.EWF_SUFFIXES, *fsdetect.RAW_SUFFIXES)
ATA_TRANSPORTS = frozenset({"sata", "ata", "pata", "ide"})
BLOCKER_ANSWERS = ("yes", "no", "unknown")


class TargetError(RuntimeError):
    """The chosen target cannot be used. The message says why and what to do."""


@dataclass
class Candidate:
    path: str
    kind: str  # "device" | "image"
    name: str
    size_bytes: int
    model: str = ""
    serial: str = ""
    filesystems: list[str] = field(default_factory=list)
    readonly: bool = True
    mounted: bool = False
    transport: str = ""
    removable: bool = False

    def label(self) -> str:
        size = human_size(self.size_bytes)
        fs = ",".join(self.filesystems) or "no filesystem seen"
        if self.kind == "device":
            ro = "read-only" if self.readonly else "WRITABLE"
            ident = " ".join(x for x in (self.model, self.serial) if x) or "unknown model"
            return f"{size}  {ident}  [{fs}]  {ro}"
        return f"{size}  image file  [{fs}]"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def human_size(n: int) -> str:
    size = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1000 or unit == "TB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1000
    return f"{n} B"  # pragma: no cover


def device_candidates() -> list[Candidate]:
    out: list[Candidate] = []
    for disk in devices.attached_disks():
        fss = sorted({d.fstype for d in disk.walk() if d.fstype})
        out.append(
            Candidate(
                path=disk.path,
                kind="device",
                name=disk.name,
                size_bytes=disk.size,
                model=disk.model,
                serial=disk.serial,
                filesystems=fss,
                readonly=disk.ro and all(c.ro for c in disk.children),
                mounted=disk.mounted,
                transport=disk.tran,
                removable=disk.rm,
            )
        )
    return out


def image_candidates(images_dir: Path | None) -> list[Candidate]:
    if images_dir is None or not images_dir.is_dir():
        return []
    out: list[Candidate] = []
    for p in sorted(images_dir.iterdir()):
        if not p.is_file() or not p.name.lower().endswith(IMAGE_SUFFIXES):
            continue
        out.append(Candidate(path=str(p), kind="image", name=p.name, size_bytes=p.stat().st_size))
    return out


def candidates(images_dir: Path | None = None) -> list[Candidate]:
    return [*device_candidates(), *image_candidates(images_dir)]


def _find_device(path: str) -> tuple[devices.BlockDevice | None, devices.BlockDevice | None]:
    """(top-level disk, exact node) for a device path, from lsblk."""
    real = os.path.realpath(path)
    for disk in devices.lsblk():
        for node in disk.walk():
            if os.path.realpath(node.path) == real or node.name == Path(real).name:
                return disk, node
    return None, None


def resolve(path: str) -> Candidate:
    """Check a target given by path and describe it. Raises ``TargetError`` with what to do."""
    p = Path(path)
    if not p.exists():
        raise TargetError(f"{path} does not exist. Check the name with lsblk and try again.")
    st = p.stat()
    if stat.S_ISREG(st.st_mode):
        if not p.name.lower().endswith(IMAGE_SUFFIXES):
            raise TargetError(
                f"{path} is not a known image type (E01, raw, dd, img). Rename or convert it."
            )
        return Candidate(path=str(p), kind="image", name=p.name, size_bytes=st.st_size)
    if not stat.S_ISBLK(st.st_mode):
        raise TargetError(f"{path} is neither a block device nor an image file.")
    disk, node = _find_device(path)
    if disk is None or node is None:
        raise TargetError(f"{path} is not listed by lsblk. Reconnect the drive and try again.")
    boot = devices.boot_disk()
    if boot is not None and disk.name == boot.name:
        raise TargetError(f"{path} is the AIRLOCK drive itself. Pick the evidence drive.")
    if node.mounted:
        raise TargetError(
            f"{path} is mounted. AIRLOCK never analyses a mounted drive. "
            "Unplug it, plug it in again, and do not open it in the file manager."
        )
    ro_ok = devices.is_readonly(node.path)
    if node is not disk:
        ro_ok = ro_ok and devices.is_readonly(disk.path)
    fss = sorted({d.fstype for d in node.walk() if d.fstype})
    return Candidate(
        path=node.path,
        kind="device",
        name=node.name,
        size_bytes=node.size,
        model=disk.model,
        serial=disk.serial,
        filesystems=fss,
        readonly=ro_ok,
        mounted=False,
        transport=disk.tran,
        removable=disk.rm,
    )


def require_readonly(cand: Candidate) -> None:
    if cand.kind == "device" and not cand.readonly:
        raise TargetError(
            f"{cand.path} is not read-only. The software read-only policy should have set it. "
            f"Unplug and replug the drive, or run 'sudo blockdev --setro {cand.path}', then retry."
        )


def evidence_id(cand: Candidate, exhibit_id: str = "") -> str:
    if exhibit_id:
        return exhibit_id
    if cand.kind == "device":
        return "_".join(x for x in (cand.model, cand.serial) if x).replace(" ", "_") or cand.name
    return cand.name


# -- device facts -------------------------------------------------------------------------------


def _sys_block(path: str) -> Path:
    return Path("/sys/class/block") / Path(os.path.realpath(path)).name


def rotational(path: str) -> bool | None:
    """True for a spinning disk, False for SSD or flash, None when unknown."""
    try:
        real = _sys_block(path).resolve()
    except OSError:
        return None
    # A partition has no queue folder of its own; its parent folder is the disk.
    for folder in (real, real.parent):
        flag = folder / "queue" / "rotational"
        if flag.exists():
            return flag.read_text(encoding="ascii").strip() == "1"
    return None


_HPA_RE = re.compile(r"max sectors\s*=\s*(\d+)/(\d+),\s*HPA is (\w+)")


def parse_hdparm_n(text: str) -> dict[str, Any]:
    m = _HPA_RE.search(text)
    if not m:
        return {"parsed": False}
    visible, native = int(m.group(1)), int(m.group(2))
    return {
        "parsed": True,
        "visible_sectors": visible,
        "native_sectors": native,
        "hpa_enabled": m.group(3).lower() == "enabled" or visible < native,
        "hidden_sectors": max(0, native - visible),
    }


def parse_dco(text: str) -> dict[str, Any]:
    m = re.search(r"Real max sectors:\s*(\d+)", text)
    return {"parsed": bool(m), "dco_max_sectors": int(m.group(1)) if m else None}


def hpa_dco(cand: Candidate) -> dict[str, Any]:
    """Read-only HPA and DCO queries. Nothing is set, frozen, or removed."""
    if cand.kind != "device":
        return {"status": "skipped", "reason": "image file"}
    if cand.transport.lower() not in ATA_TRANSPORTS:
        return {"status": "skipped", "reason": f"not an ATA drive (transport {cand.transport!r})"}
    if not proc.which("hdparm"):
        return {"status": "skipped", "reason": "hdparm not installed"}
    out: dict[str, Any] = {"status": "queried", "commands": []}
    hpa = proc.run(["hdparm", "-N", cand.path], check=False, timeout=60)
    out["commands"].append(hpa.command_line)
    out["hpa"] = parse_hdparm_n(hpa.stdout)
    out["hpa_raw"] = hpa.stdout.strip()[-400:]
    dco = proc.run(["hdparm", "--dco-identify", cand.path], check=False, timeout=60)
    out["commands"].append(dco.command_line)
    out["dco"] = parse_dco(dco.stdout)
    out["dco_raw"] = dco.stdout.strip()[-400:]
    native = out["hpa"].get("native_sectors")
    dco_max = out["dco"].get("dco_max_sectors")
    out["dco_hidden"] = bool(native and dco_max and dco_max > native)
    return out


def smart_check(cand: Candidate) -> dict[str, Any]:
    """Read-only SMART health query. Returns ``available: False`` when it cannot be read."""
    if cand.kind != "device" or not proc.which("smartctl"):
        return {"available": False}
    res = proc.run(["smartctl", "-H", "-A", "-j", cand.path], check=False, timeout=60)
    try:
        data = json.loads(res.stdout or "{}")
    except ValueError:
        return {"available": False}
    status = data.get("smart_status")
    if not isinstance(status, dict) or "passed" not in status:
        return {"available": False}
    attrs = {}
    table = (data.get("ata_smart_attributes") or {}).get("table") or []
    for row in table:
        if row.get("id") in (5, 187, 197, 198):
            attrs[str(row.get("name") or row.get("id"))] = int(
                (row.get("raw") or {}).get("value", 0)
            )
    failing = (not status.get("passed")) or any(v > 0 for v in attrs.values())
    return {
        "available": True,
        "passed": bool(status.get("passed")),
        "attributes": attrs,
        "warning": failing,
        "command": res.command_line,
    }


def smart_warning_text(smart: dict[str, Any]) -> str:
    bits = [f"{k}={v}" for k, v in sorted(smart.get("attributes", {}).items()) if v]
    health = "FAILED" if not smart.get("passed") else "passed, with warning signs"
    return (
        f"SMART health: {health} ({', '.join(bits) or 'no counters'}). A Full run reads this "
        "drive several times and can finish off a failing drive. Consider "
        "--mode image --imager ddrescue to copy it once first."
    )


@dataclass
class BlockerRecord:
    in_use: str = "unknown"  # yes | no | unknown
    make: str = ""
    model: str = ""
    firmware: str = ""
    report_url: str = ""
    answered_via: str = "default"
    advisory_shown: bool = True
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def blocker_record(
    in_use: str | None,
    *,
    make: str = "",
    model: str = "",
    firmware: str = "",
    report_url: str = "",
    via: str = "flag",
) -> BlockerRecord:
    answer = (in_use or "unknown").lower()
    if answer not in BLOCKER_ANSWERS:
        raise TargetError("--write-blocker must be yes, no, or unknown")
    rec = BlockerRecord(answer, make.strip(), model.strip(), firmware.strip(), report_url.strip())
    rec.answered_via = via if in_use else "default"
    if report_url and not re.match(r"^https?://\S+$", report_url.strip()):
        raise TargetError("--blocker-report-url must be a web address (http or https)")
    if answer == "yes" and not report_url:
        rec.notes.append("no test report link recorded for this blocker")
    if answer != "yes" and (make or model or firmware):
        rec.notes.append("blocker details given but the answer was not 'yes'")
    return rec
