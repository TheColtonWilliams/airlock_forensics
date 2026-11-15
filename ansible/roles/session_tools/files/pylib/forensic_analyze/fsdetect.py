"""Filesystem awareness (task 4C.16).

``mmls`` finds the partitions and ``fsstat -t`` names each filesystem, both read-only and offset
aware. Every volume is also checked for a BitLocker signature (``-FVE-FS-`` at byte 3, or the
BitLocker To Go metadata GUID at byte 160). Modules that need NTFS are skipped on exFAT, FAT, or
ext volumes, and the run records why (``api.Module.applicable``).

A BitLocker volume needs the recovery key (``--bitlocker-key-file``). With it, Dissect's
``fve-dd`` writes a decrypted working copy into the run folder, which is made read-only and
analysed in place of the target. Without it, the run stops with a clear message.
"""

from __future__ import annotations

import os
import re
import subprocess
import tempfile
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path

from airlock_common import proc
from forensic_analyze.api import Volume

ToolFn = Callable[..., subprocess.CompletedProcess[str]]

BITLOCKER_SIG = b"-FVE-FS-"
BITLOCKER_TOGO_GUID = bytes.fromhex("3bd66749292ed84a8399f6a339e3d001")
RECOVERY_RE = re.compile(r"^\d{6}(-\d{6}){7}$")
EWF_SUFFIXES = (".e01", ".ex01", ".s01", ".l01")
RAW_SUFFIXES = (".raw", ".dd", ".img", ".001", ".bin", ".iso")

_SLOT_RE = re.compile(
    r"^\s*\d+:\s+(?P<slot>\d+(?::\d+)?|Meta|-+)\s+(?P<start>\d+)\s+(?P<end>\d+)\s+"
    r"(?P<length>\d+)\s*(?P<desc>.*)$"
)
_UNITS_RE = re.compile(r"Units are in (\d+)-byte sectors")
_CONTAINER_DESC = re.compile(r"\((0x05|0x0f|0x0F|0x85)\)|Extended", re.IGNORECASE)

FS_NAMES = {
    "ntfs": "ntfs",
    "exfat": "exfat",
    "fat12": "fat12",
    "fat16": "fat16",
    "fat32": "fat32",
    "fat": "fat",
    "ext2": "ext2",
    "ext3": "ext3",
    "ext4": "ext4",
    "hfs": "hfs",
    "hfsp": "hfs",
    "apfs": "apfs",
    "iso9660": "iso9660",
    "ufs": "ufs",
    "yaffs2": "yaffs2",
    "xfs": "xfs",
    "btrfs": "btrfs",
}


class BitLockerLocked(RuntimeError):
    """A BitLocker volume was found and no usable key was given."""


def image_type(path: str | os.PathLike[str]) -> str:
    """TSK image type for ``-i``: ``ewf`` for E01 sets, else ``raw``."""
    return "ewf" if str(path).lower().endswith(EWF_SUFFIXES) else "raw"


def _default_tool(argv: Sequence[str], **kw: object) -> subprocess.CompletedProcess[str]:
    stdout_path = kw.get("stdout_path")
    res = proc.run(
        list(argv),
        check=False,
        timeout=600,
        stdout_path=str(stdout_path) if stdout_path else None,
    )
    return subprocess.CompletedProcess(res.argv, res.returncode, res.stdout, res.stderr)


@dataclass(frozen=True)
class Partition:
    slot: str
    start: int  # sectors
    length: int  # sectors
    description: str


def parse_mmls(text: str) -> tuple[int, list[Partition]]:
    """Return (sector size, data partitions) from ``mmls`` output."""
    sector = 512
    m = _UNITS_RE.search(text)
    if m:
        sector = int(m.group(1))
    parts: list[Partition] = []
    for line in text.splitlines():
        mm = _SLOT_RE.match(line)
        if not mm:
            continue
        slot = mm.group("slot")
        if slot == "Meta" or slot.startswith("-"):
            continue
        desc = mm.group("desc").strip()
        if _CONTAINER_DESC.search(desc):
            continue
        parts.append(Partition(slot, int(mm.group("start")), int(mm.group("length")), desc))
    return sector, parts


def normalise_fs(name: str) -> str:
    key = name.strip().lower().replace(" ", "")
    return FS_NAMES.get(key, key or "unknown")


def parse_label(fsstat_text: str) -> str:
    for line in fsstat_text.splitlines():
        for prefix in ("Volume Name:", "Volume Label (from root directory):", "Volume Label:"):
            if line.startswith(prefix):
                return line.split(":", 1)[1].strip()
    return ""


def is_bitlocker(boot_sector: bytes) -> bool:
    if boot_sector[3:11] == BITLOCKER_SIG:
        return True
    return boot_sector[160:176] == BITLOCKER_TOGO_GUID


def read_boot_sector(
    path: str, offset_bytes: int, *, itype: str, sector: int, tool: ToolFn, workdir: Path
) -> bytes:
    """First 512 bytes of a volume, read-only."""
    if itype == "raw":
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
        try:
            return os.pread(fd, 512, offset_bytes)
        finally:
            os.close(fd)
    workdir.mkdir(parents=True, exist_ok=True)
    out = workdir / f"sector-{offset_bytes}.bin"
    first = offset_bytes // sector
    tool(
        ["img_cat", "-i", itype, "-s", str(first), "-e", str(first), path],
        stdout_path=out,
    )
    data = out.read_bytes()[:512] if out.exists() else b""
    out.unlink(missing_ok=True)
    return data


def detect(
    path: str | os.PathLike[str],
    *,
    tool: ToolFn | None = None,
    workdir: Path | None = None,
    size_bytes: int = 0,
) -> list[Volume]:
    """Every volume on ``path`` (device or image) with its filesystem type and label."""
    run = tool or _default_tool
    p = str(path)
    itype = image_type(p)
    scratch = workdir or Path(tempfile.gettempdir())
    res = run(["mmls", "-i", itype, p])
    sector, parts = parse_mmls(res.stdout) if res.returncode == 0 else (512, [])
    if not parts:
        # No partition table: the whole target is one volume.
        parts = [Partition("whole", 0, size_bytes // sector if size_bytes else 0, "whole target")]
    volumes: list[Volume] = []
    for index, part in enumerate(parts):
        offset = part.start * sector
        boot = read_boot_sector(p, offset, itype=itype, sector=sector, tool=run, workdir=scratch)
        if is_bitlocker(boot):
            volumes.append(
                Volume(index, offset, part.length * sector, "bitlocker", "", bitlocker=True)
            )
            continue
        typ = run(["fsstat", "-i", itype, "-t", "-o", str(part.start), p])
        fs_type = normalise_fs(typ.stdout.splitlines()[0]) if typ.returncode == 0 else "unknown"
        label = ""
        if fs_type != "unknown":
            info = run(["fsstat", "-i", itype, "-o", str(part.start), p])
            label = parse_label(info.stdout) if info.returncode == 0 else ""
        volumes.append(Volume(index, offset, part.length * sector, fs_type, label))
    return volumes


def bitlocker_volumes(volumes: Sequence[Volume]) -> list[Volume]:
    return [v for v in volumes if v.bitlocker]


def key_args(key_file: Path) -> tuple[list[str], list[str]]:
    """``fve-dd`` arguments for a key file, and the secret strings to redact from records.

    A file holding the 48-digit recovery password gives ``-r``; anything else is treated as a
    ``.BEK`` startup key file and given with ``-f``.
    """
    raw = key_file.read_bytes()
    try:
        text = raw.decode("ascii").strip()
    except UnicodeDecodeError:
        text = ""
    if RECOVERY_RE.match(text):
        return ["-r", text], [text]
    return ["-f", str(key_file)], []


@dataclass
class UnlockResult:
    image: Path
    tool_argv: list[str]


def unlock(
    path: str,
    key_file: Path | None,
    out_dir: Path,
    *,
    tool: ToolFn,
) -> UnlockResult:
    """Write a decrypted, read-only working copy with Dissect's ``fve-dd`` or raise."""
    if key_file is None:
        raise BitLockerLocked(
            "The target has a BitLocker volume. Give the recovery key with "
            "--bitlocker-key-file FILE, or stop here."
        )
    if not key_file.is_file():
        raise BitLockerLocked(f"Key file not found: {key_file}. Check the path and try again.")
    if not proc.which("fve-dd"):
        raise BitLockerLocked(
            "The BitLocker unlock tool (Dissect fve-dd) is not installed on this build. "
            "Image the drive with --mode image and unlock it on another workstation."
        )
    out_dir.mkdir(parents=True, exist_ok=True)
    out = out_dir / "decrypted.raw"
    args, _secrets = key_args(key_file)
    argv = ["fve-dd", *args, "-o", str(out), path]
    res = tool(argv, redact=_secrets)
    if res.returncode != 0 or not out.exists() or out.stat().st_size == 0:
        out.unlink(missing_ok=True)
        raise BitLockerLocked(
            "The BitLocker volume could not be unlocked with that key. "
            "Check the recovery key and try again."
        )
    os.chmod(out, 0o444)
    return UnlockResult(out, [a if a not in _secrets else "<redacted>" for a in argv])
