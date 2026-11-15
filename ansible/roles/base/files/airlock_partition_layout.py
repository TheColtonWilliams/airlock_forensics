#!/usr/bin/python3
"""Check and set the AIRLOCK drive layout on the boot disk (tasks 2B.9 and 2B.17).

Layout (docs/dev/contract.md section 3), GPT:

    1 BIOSBOOT      BIOS boot (EF02)
    2 EFI           EFI system (EF00), FAT32
    3 ASSETS        Microsoft basic data (0700), exFAT, label ASSETS
    4 OUTPUT        Microsoft basic data (0700), exFAT, label OUTPUT
    5 AIRLOCK_ROOT  Linux filesystem (8300), ext4, label AIRLOCK_ROOT

The autoinstall creates the partitions; curtin cannot make exFAT or set partition names,
so this helper sets names and types and, with --format-empty, makes the two exFAT
filesystems. It only ever works on the disk that holds the root filesystem, refuses a
disk that does not have exactly these five partitions with root on number 5, and never
formats a partition that already has a filesystem.

Installed by the base role as /opt/airlock/libexec/airlock-partition-layout. It runs before
the session_tools role installs airlock_common, so it calls subprocess directly, always
with argument lists.

Exit status: 0 layout correct (after any fixes); 1 a problem remains (one line on stderr
says what and what to do next); 2 bad usage.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
from dataclasses import asdict, dataclass, field

BIOS_BOOT = "21686148-6449-6E6F-744E-656564454649"
EFI_SYSTEM = "C12A7328-F81F-11D2-BA4B-00A0C93EC93B"
BASIC_DATA = "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7"
LINUX_FS = "0FC63DAF-8483-4772-8E79-3D69D8477DE4"


@dataclass(frozen=True)
class Want:
    number: int
    name: str
    type_guid: str
    fstype: str | None  # None: not checked (BIOS boot has no filesystem)
    label: str | None


LAYOUT: tuple[Want, ...] = (
    Want(1, "BIOSBOOT", BIOS_BOOT, None, None),
    Want(2, "EFI", EFI_SYSTEM, "vfat", None),
    Want(3, "ASSETS", BASIC_DATA, "exfat", "ASSETS"),
    Want(4, "OUTPUT", BASIC_DATA, "exfat", "OUTPUT"),
    Want(5, "AIRLOCK_ROOT", LINUX_FS, "ext4", "AIRLOCK_ROOT"),
)
FORMATTABLE = {3, 4}


@dataclass
class Partition:
    number: int
    path: str
    name: str = ""
    type_guid: str = ""
    fstype: str = ""
    label: str = ""
    uuid: str = ""


@dataclass
class Report:
    disk: str
    changed: bool = False
    actions: list[str] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)
    partitions: list[Partition] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        return {
            "actions": self.actions,
            "changed": self.changed,
            "disk": self.disk,
            "ok": not self.problems,
            "partitions": [asdict(p) for p in self.partitions],
            "problems": self.problems,
        }


class LayoutError(Exception):
    """A refusal: the disk is not one this helper may touch."""


def run(argv: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(argv, check=check, capture_output=True, text=True)


def root_source() -> str:
    return run(["findmnt", "-n", "-o", "SOURCE", "--target", "/"]).stdout.strip()


def parent_disk(partition: str) -> str:
    name = run(["lsblk", "-n", "-d", "-o", "PKNAME", partition]).stdout.strip()
    if not name:
        raise LayoutError(f"{partition} is not a partition of a disk")
    return f"/dev/{name}"


def partition_paths(disk: str, sysfs: str = "/sys/class/block") -> dict[int, str]:
    """Partition number -> device path, from sysfs (works without udev)."""
    base = os.path.join(sysfs, os.path.basename(os.path.realpath(disk)))
    out: dict[int, str] = {}
    for entry in sorted(os.listdir(base)):
        number_file = os.path.join(base, entry, "partition")
        if os.path.isfile(number_file):
            with open(number_file, encoding="ascii") as fh:
                out[int(fh.read().strip())] = f"/dev/{entry}"
    return out


_GUID_RE = re.compile(r"Partition GUID code:\s*([0-9A-Fa-f-]{36})")
_NAME_RE = re.compile(r"Partition name:\s*'(.*)'")


def gpt_entry(disk: str, number: int) -> tuple[str, str]:
    """Return (type GUID upper case, name) read straight from the GPT with sgdisk."""
    out = run(["sgdisk", "-i", str(number), disk]).stdout
    guid = _GUID_RE.search(out)
    name = _NAME_RE.search(out)
    return (guid.group(1).upper() if guid else "", name.group(1) if name else "")


def probe(path: str) -> dict[str, str]:
    """Low-level filesystem probe (blkid -p reads the device, not the udev cache)."""
    res = run(["blkid", "-p", "-o", "export", path], check=False)
    if res.returncode == 2:  # nothing found
        return {}
    if res.returncode != 0:
        raise LayoutError(f"blkid could not read {path}: {res.stderr.strip()}")
    info: dict[str, str] = {}
    for line in res.stdout.splitlines():
        key, sep, value = line.partition("=")
        if sep:
            info[key] = value
    return info


def read_layout(disk: str) -> list[Partition]:
    parts = []
    for number, path in sorted(partition_paths(disk).items()):
        type_guid, name = gpt_entry(disk, number)
        fs = probe(path)
        parts.append(
            Partition(
                number=number,
                path=path,
                name=name,
                type_guid=type_guid,
                fstype=fs.get("TYPE", ""),
                label=fs.get("LABEL", ""),
                uuid=fs.get("UUID", ""),
            )
        )
    return parts


def same_device(a: str, b: str) -> bool:
    try:
        return os.stat(a).st_rdev == os.stat(b).st_rdev
    except OSError:
        return os.path.realpath(a) == os.path.realpath(b)


def check_shape(disk: str, root: str, parts: list[Partition]) -> None:
    numbers = [p.number for p in parts]
    if numbers != [1, 2, 3, 4, 5]:
        raise LayoutError(
            f"{disk} has partitions {numbers}, not the five AIRLOCK partitions; "
            "refusing to touch it"
        )
    if not same_device(parts[4].path, root):
        raise LayoutError(
            f"the root filesystem {root} is not partition 5 of {disk}; refusing to touch the disk"
        )


def _plan_gpt(want: Want, have: Partition, *, fix: bool) -> tuple[list[str], list[str]]:
    """GPT name and type: sgdisk arguments when fixing, else problems."""
    args: list[str] = []
    problems: list[str] = []
    n = want.number
    if have.name != want.name:
        if fix:
            args += ["-c", f"{n}:{want.name}"]
        else:
            problems.append(f"partition {n} is named {have.name!r}, expected {want.name!r}")
    if have.type_guid != want.type_guid:
        if fix:
            args += ["-t", f"{n}:{want.type_guid}"]
        else:
            problems.append(f"partition {n} has type {have.type_guid}, expected {want.type_guid}")
    return args, problems


def _plan_fs(
    want: Want, have: Partition, *, fix: bool, format_empty: bool
) -> tuple[list[list[str]], list[str]]:
    """Filesystem type and label: commands to run, else problems. Never reformats."""
    n = want.number
    commands: list[list[str]] = []
    problems: list[str] = []
    relabel = {"exfat": "exfatlabel", "ext4": "e2label"}.get(str(want.fstype))
    if want.fstype is None:
        pass
    elif not have.fstype:
        if n in FORMATTABLE and format_empty:
            commands.append(["mkfs.exfat", "-L", str(want.label), have.path])
        else:
            problems.append(f"partition {n} ({want.name}) has no filesystem")
    elif have.fstype != want.fstype:
        problems.append(
            f"partition {n} ({want.name}) holds {have.fstype}, expected {want.fstype}; "
            "it was not changed"
        )
    elif want.label is not None and have.label != want.label:
        if fix and relabel:
            commands.append([relabel, have.path, want.label])
        else:
            problems.append(f"partition {n} is labelled {have.label!r}, expected {want.label!r}")
    return commands, problems


def plan(
    parts: list[Partition], *, fix: bool, format_empty: bool
) -> tuple[list[str], list[list[str]], list[str]]:
    """Return (sgdisk arguments, other commands, problems) for the current layout."""
    sgdisk_args: list[str] = []
    commands: list[list[str]] = []
    problems: list[str] = []
    for want, have in zip(LAYOUT, parts, strict=True):
        args, gpt_problems = _plan_gpt(want, have, fix=fix)
        cmds, fs_problems = _plan_fs(want, have, fix=fix, format_empty=format_empty)
        sgdisk_args += args
        commands += cmds
        problems += gpt_problems + fs_problems
    return sgdisk_args, commands, problems


def settle(disk: str, paths: dict[int, str], timeout: float = 10.0) -> None:
    """Wait for the partition device nodes after a partition-table write.

    udev normally recreates them. Where udev is absent (containers, some test hosts) the
    kernel may have dropped them on re-read, so ask it to add them back with partx.
    """
    run(["udevadm", "trigger", "--action=change", disk], check=False)
    run(["udevadm", "settle"], check=False)
    deadline = time.monotonic() + timeout
    asked = False
    while not all(os.path.exists(path) for path in paths.values()):
        if not asked:
            run(["partx", "-a", disk], check=False)
            asked = True
        if time.monotonic() > deadline:
            missing = [p for p in paths.values() if not os.path.exists(p)]
            raise LayoutError(f"partition devices {missing} did not come back after the update")
        time.sleep(0.2)


def apply(disk: str, root: str, *, fix: bool, format_empty: bool) -> Report:
    parts = read_layout(disk)
    check_shape(disk, root, parts)
    report = Report(disk=disk)
    sgdisk_args, commands, problems = plan(parts, fix=fix, format_empty=format_empty)
    if sgdisk_args:
        run(["sgdisk", *sgdisk_args, disk])
        report.actions.append(" ".join(["sgdisk", *sgdisk_args, disk]))
        settle(disk, {p.number: p.path for p in parts})
    for argv in commands:
        run(argv)
        report.actions.append(" ".join(argv))
    report.changed = bool(report.actions)
    report.partitions = read_layout(disk) if report.changed else parts
    if report.changed:
        _, _, problems = plan(report.partitions, fix=False, format_empty=False)
    report.problems = problems
    return report


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="airlock-partition-layout",
        description="Check and set the AIRLOCK drive layout on the disk that holds /.",
    )
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true", help="read only; exit 1 on any difference")
    mode.add_argument(
        "--format-empty",
        action="store_true",
        help="also make exFAT on ASSETS and OUTPUT when they have no filesystem (image build)",
    )
    ap.add_argument("--root-source", help="device holding / (default: from findmnt)")
    ap.add_argument("--disk", help="disk to work on; must be the parent of the root device")
    ap.add_argument("--json", action="store_true", help="print the result as JSON")
    args = ap.parse_args(argv)

    try:
        root = args.root_source or root_source()
        disk = parent_disk(root)
        if args.disk and not same_device(args.disk, disk):
            raise LayoutError(
                f"{args.disk} does not hold the root filesystem ({root} is on {disk})"
            )
        report = apply(disk, root, fix=not args.check, format_empty=args.format_empty)
    except LayoutError as exc:
        print(f"airlock-partition-layout: {exc}. Check the drive with lsblk.", file=sys.stderr)
        return 1
    except (subprocess.CalledProcessError, OSError) as exc:
        detail = getattr(exc, "stderr", "") or str(exc)
        print(
            f"airlock-partition-layout: a disk command failed: {str(detail).strip()}. "
            "Run it again by hand to see why.",
            file=sys.stderr,
        )
        return 1

    if args.json:
        print(json.dumps(report.to_dict(), sort_keys=True))
    else:
        for action in report.actions:
            print(f"changed: {action}")
    if report.problems:
        print(
            "airlock-partition-layout: "
            + "; ".join(report.problems)
            + ". The drive does not match the AIRLOCK layout; reflash it.",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
