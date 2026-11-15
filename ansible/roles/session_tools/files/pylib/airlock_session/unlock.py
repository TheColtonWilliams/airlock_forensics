"""evidence-unlock-output: make one named drive writable for case output (task 4.10).

AIRLOCK's software read-only policy sets every attached drive read-only. This command clears
the flag on one whole drive and its partitions so it can hold case output. It refuses the
AIRLOCK drive itself, refuses partitions, and refuses unless the operator types the drive's
name back (or passes ``--confirm NAME``). ``--yes`` never skips that confirmation.

It writes a marker ``<run dir>/rw-allow/<kernel name of the disk>`` (``airlock_common.paths``
``rw_allow_dir()``: ``AIRLOCK_RUN_DIR``, default ``/run/airlock``) so a later udev ``change``
event, which re-runs ``airlock-setro`` from the harden_storage role, leaves the drive and its
partitions writable. The marker is bound to the drive, not only its name: it records
``identity_sha256``, the SHA-256 of the disk's sysfs ``diskseq``, ``wwid``, ``serial`` and
``size`` (:func:`drive_identity`). ``airlock-setro`` works the hash out again and ignores and
deletes a marker that does not match, so a drive that later gets the same kernel name (the
next one plugged in) starts read-only. ``diskseq`` is new each time a disk is attached, so the
same drive plugged in again is read-only too. The udev rule also deletes the marker when the
disk is removed, and ``/run`` is a tmpfs, so nothing survives a reboot. A drive with none of
``diskseq``, ``wwid`` or ``serial`` cannot be told apart from the next one and is refused.
Then it runs ``blockdev --setrw`` and logs model, serial, and size. If the drive stays
read-only the marker is removed again (fail closed). Surviving risk 1: the log records the
change; it does not prevent a mistake. ``--lock`` undoes it: the marker goes first, then
``blockdev --setro`` runs again.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import re
from pathlib import Path
from typing import Any

from airlock_common import devices, jsonio, paths, proc, timeutil, ui
from airlock_session.common import (
    CommandError,
    human_size,
    log,
    open_session_log,
    readonly_flag,
    require_root,
    run_main,
    sysfs,
)

TOOL = "evidence-unlock-output"

WARNING = (
    "WARNING: this makes {path} ({desc}) WRITABLE.\n"
    "Anything on this PC can then change it. Use this only for a drive that will hold case "
    "output, never for an evidence drive.\n"
    "The change is recorded in the session log. The log records it; it does not prevent "
    "mistakes.\n"
    "The unlock belongs to this drive only while it stays plugged in: once it is unplugged, "
    "it and any drive that later gets the name {path} start read-only. "
    "evidence-unlock-output --lock {path} makes it read-only now."
)

# Identity fields, in hash order, and the sysfs files each is read from (first readable wins).
# airlock-setro (harden_storage role) reads the same files the same way; keep them in step.
IDENTITY_FIELDS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("diskseq", ("diskseq",)),
    ("wwid", ("wwid", "device/wwid")),
    ("serial", ("serial", "device/serial")),
    ("size", ("size",)),
)
_STRIP = b"\x00\t\n\x0b\x0c\r "
_MARKER_ID = re.compile(r'^\s*"identity_sha256":\s*"([0-9a-f]{64})",?\s*$', re.M)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=TOOL,
        description="Make one named drive writable for case output, and log it.",
    )
    p.add_argument("device", help="the whole drive, for example /dev/sdb (not a partition)")
    p.add_argument(
        "--confirm",
        metavar="NAME",
        help="the drive's name typed back (sdb or /dev/sdb); needed when not asked on screen",
    )
    p.add_argument(
        "-y",
        "--yes",
        action="store_true",
        help="do not ask; still needs --confirm NAME",
    )
    p.add_argument(
        "--lock",
        action="store_true",
        help="undo: make the drive read-only again and remove the unlock marker",
    )
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return run_main(TOOL, lambda: run(args))


def resolve_disk(arg: str) -> tuple[devices.BlockDevice, list[devices.BlockDevice]]:
    """The lsblk entry for a whole drive named by path or kernel name, and the full tree."""
    path = Path(arg)
    candidates = {arg, path.name}
    if path.exists():
        real = path.resolve()
        candidates |= {str(real), real.name}
    tree = devices.lsblk()
    for top in tree:
        for d in top.walk():
            if d.path in candidates or d.name in candidates:
                if d is not top:
                    raise CommandError(
                        f"{arg} is a partition. Name the whole drive instead, "
                        f"for example /dev/{top.name}."
                    )
                if top.type not in {"disk", "loop"}:
                    raise CommandError(f"{arg} is a {top.type} device, not a drive.")
                return top, tree
    raise CommandError(f"there is no drive called {arg}. List the drives with lsblk.")


def describe(dev: devices.BlockDevice) -> str:
    parts = [dev.model or "unknown model"]
    if dev.serial:
        parts.append(f"serial {dev.serial}")
    parts.append(human_size(dev.size))
    return ", ".join(parts)


def _names_match(answer: str, dev: devices.BlockDevice) -> bool:
    a = answer.strip()
    return bool(a) and a in {dev.name, dev.path}


def _blockdev(flag: str, dev_path: str) -> None:
    proc.run(["blockdev", flag, dev_path], timeout=30)


def _id_field(base: Path, rels: tuple[str, ...]) -> bytes:
    for rel in rels:
        path = base / rel
        if os.access(path, os.R_OK):
            try:
                data = path.read_bytes()
            except OSError:
                data = b""
            return data.translate(None, _STRIP)
    return b""


def drive_identity(name: str) -> tuple[dict[str, str], str | None]:
    """The identity fields of whole disk ``name`` from sysfs, and their SHA-256.

    The hash is over ``diskseq=..\\nwwid=..\\nserial=..\\nsize=..\\n`` with white space and
    NUL bytes removed from each value, exactly as ``airlock-setro`` computes it. It is None when
    the disk has no ``diskseq``, ``wwid`` or ``serial``: nothing would tell it apart from the
    next drive given the same name.
    """
    base = sysfs() / "class" / "block" / name
    raw = {field: _id_field(base, rels) for field, rels in IDENTITY_FIELDS}
    fields = {k: v.decode("utf-8", "replace") for k, v in raw.items()}
    if not (raw["diskseq"] or raw["wwid"] or raw["serial"]):
        return fields, None
    canon = b"".join(k.encode() + b"=" + raw[k] + b"\n" for k, _ in IDENTITY_FIELDS)
    return fields, hashlib.sha256(canon).hexdigest()


def marker_valid(name: str) -> bool:
    """True when ``rw-allow/<name>`` exists and was written for the drive now called ``name``.

    The same test ``airlock-setro`` applies; a marker left by another drive does not count.
    """
    if not name or "/" in name or name in {".", ".."}:
        return False
    marker = paths.rw_allow_dir() / name
    if marker.is_symlink() or not marker.is_file():
        return False
    try:
        text = marker.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return False
    match = _MARKER_ID.search(text)
    current = drive_identity(name)[1]
    return bool(match) and current is not None and match.group(1) == current


def run(args: argparse.Namespace) -> int:
    require_root(TOOL)
    open_session_log(TOOL)
    disk, tree = resolve_disk(args.device)
    boot = devices.boot_disk(tree)
    if boot is not None and boot.name == disk.name:
        log(TOOL, "unlock_refused", device=disk.path, reason="boot_disk")
        raise CommandError(
            f"{disk.path} is the AIRLOCK drive itself. Its OUTPUT partition is already writable; "
            "nothing to do."
        )
    record: dict[str, Any] = {
        "device": disk.path,
        "name": disk.name,
        "model": disk.model,
        "serial": disk.serial,
        "size_bytes": disk.size,
        "transport": disk.tran,
        "partitions": [c.path for c in disk.walk() if c is not disk],
    }
    if args.lock:
        return _lock(disk, record)

    print(WARNING.format(path=disk.path, desc=describe(disk)))
    print()
    if args.confirm is not None:
        answer, via = args.confirm, "flag"
    elif ui.interactive() and not args.yes:
        answer = ui.ask_text(
            "Unlock an output drive",
            f"Type {disk.name} to make {disk.path} writable:",
            flag="--confirm",
        )
        via = "prompt"
    else:
        log(TOOL, "unlock_refused", reason="no_confirmation", **record)
        raise CommandError(
            f"not unlocked: no confirmation. Pass --confirm {disk.name} to make {disk.path} "
            "writable."
        )
    if not _names_match(answer, disk):
        log(TOOL, "unlock_refused", reason="confirmation_mismatch", typed=answer, **record)
        raise CommandError(
            f"not unlocked: you typed {answer!r}, not {disk.name}. Nothing was changed."
        )

    marker = marker_path(disk)
    id_fields, identity = drive_identity(disk.name)
    if identity is None:
        log(TOOL, "unlock_refused", reason="no_drive_identity", drive_identity=id_fields, **record)
        raise CommandError(
            f"not unlocked: {disk.path} reports no disk sequence number, WWN, or serial, so a "
            "drive plugged in later under the same name could not be told apart from it. "
            "Nothing was changed. Use a different drive for output."
        )
    marker.parent.mkdir(parents=True, exist_ok=True)
    # The marker goes first: a udev "change" event during --setrw must not re-lock the drive.
    jsonio.dump_json(
        marker,
        {
            "ts": timeutil.iso(),
            "tool": TOOL,
            "identity_sha256": identity,
            "drive_identity": id_fields,
            **record,
        },
    )
    members = disk.walk()
    try:
        for d in members:
            _blockdev("--setrw", d.path)
    except (proc.ToolError, OSError):
        marker.unlink(missing_ok=True)
        raise
    still_ro = [d.path for d in members if readonly_flag(d.name)]
    if still_ro:
        marker.unlink(missing_ok=True)
        log(TOOL, "unlock_failed", still_readonly=still_ro, **record)
        raise CommandError(
            f"blockdev --setrw ran but {', '.join(still_ro)} is still read-only. Unplug the "
            "drive, plug it in again, and rerun; or use a different drive for output."
        )
    log(
        TOOL,
        "output_unlocked",
        confirmed_via=via,
        marker=str(marker),
        identity_sha256=identity,
        drive_identity=id_fields,
        note="Logging is not enforcement (surviving risk 1).",
        **record,
    )
    print(f"{disk.path} is now writable. This is in the session log.")
    print("To make it read-only again: evidence-unlock-output --lock " + disk.path)
    return 0


def marker_path(disk: devices.BlockDevice) -> Path:
    """``<run dir>/rw-allow/<kernel name>``, the file ``airlock-setro`` checks (e.g. ``sdc``)."""
    name = disk.name
    if not name or "/" in name or name in {".", ".."}:
        raise CommandError(f"{disk.path} has no usable kernel name; nothing was changed.")
    return paths.rw_allow_dir() / name


def _lock(disk: devices.BlockDevice, record: dict[str, Any]) -> int:
    marker_path(disk).unlink(missing_ok=True)
    members = disk.walk()
    for d in members:
        _blockdev("--setro", d.path)
    still_rw = [d.path for d in members if readonly_flag(d.name) is False]
    if still_rw:
        log(TOOL, "lock_failed", still_writable=still_rw, **record)
        raise CommandError(
            f"blockdev --setro ran but {', '.join(still_rw)} is still writable. Unplug the drive."
        )
    log(TOOL, "output_locked", **record)
    print(f"{disk.path} is read-only again.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
