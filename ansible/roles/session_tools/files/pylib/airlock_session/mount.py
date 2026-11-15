"""evidence-mount: read-only mount of an image file, for a quick look (tasks 4.10, 3A.3).

AIRLOCK never mounts a target by default: analysis reads the raw device or image with The
Sleuth Kit and Dissect. This helper stays for image files only (surviving risk 2: mounting
exposes the kernel's filesystem parsers to a possibly hostile filesystem).

What it does, in order:

1. refuses anything that is not a regular file (drives, partitions, other devices) and E01
   containers (expose those as a raw file with ``ewfmount`` first);
2. hashes the image (SHA-256 and MD5);
3. finds the filesystem: the whole image, or one partition from the image's partition table
   (``--partition N``), read with ``blkid -p`` and ``sfdisk -J`` (both open the file read-only);
4. attaches a kernel read-only loop device (``losetup --read-only``) limited to that
   filesystem's byte range, and checks the loop's read-only flag;
5. mounts it ``ro,noexec,nosuid,nodev`` plus ``noload`` (ext2/3/4), ``norecovery`` (XFS),
   ``rescue=nologreplay`` (Btrfs); NTFS goes through ``ntfs-3g -o ro``;
6. hashes the image again and fails loudly if it changed.

``--unmount`` unmounts, detaches the loop device, hashes a third time, and fails loudly if the
image changed. ``--list`` shows the mounts this helper made.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
from pathlib import Path
from typing import Any

from airlock_common import hashing, jsonio, paths, proc, timeutil
from airlock_session.common import (
    CommandError,
    human_size,
    load_config,
    log,
    open_session_log,
    readonly_flag,
    require_root,
    run_main,
)

TOOL = "evidence-mount"

WARNING = (
    "Mounting lets the Linux kernel read a filesystem that may be hostile. A damaged or "
    "crafted filesystem can crash or attack the kernel. The safer path is to read the image "
    "without mounting it: forensic-analyze, The Sleuth Kit (fls, icat), or Dissect "
    "(target-shell). Use this mount for a quick look only."
)
WARNING_SHA256 = hashing.sha256_bytes(WARNING.encode("utf-8"))

BASE_OPTIONS = "ro,noexec,nosuid,nodev"
# blkid TYPE -> (kernel filesystem type, extra options that stop journal or log replay)
KERNEL_FS: dict[str, tuple[str, str]] = {
    "ext2": ("ext4", "noload"),
    "ext3": ("ext4", "noload"),
    "ext4": ("ext4", "noload"),
    "xfs": ("xfs", "norecovery"),
    "btrfs": ("btrfs", "rescue=nologreplay"),
    "vfat": ("vfat", ""),
    "exfat": ("exfat", ""),
    "iso9660": ("iso9660", ""),
    "udf": ("udf", ""),
    "hfsplus": ("hfsplus", ""),
}
FUSE_FS = {"ntfs": "ntfs-3g"}
EWF_MAGIC = b"EVF\x09\x0d\x0a\xff\x00"
_SAFE = re.compile(r"[^A-Za-z0-9._-]+")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=TOOL,
        description=(
            "Mount an image file read-only for a quick look. Drives are never mounted; "
            "use forensic-analyze to read them."
        ),
    )
    p.add_argument("image", nargs="?", help="image file (with --unmount: mount point or image)")
    p.add_argument(
        "mountpoint", nargs="?", help="empty folder to mount on (default /mnt/airlock/NAME)"
    )
    p.add_argument("--partition", type=int, metavar="N", help="partition number inside the image")
    p.add_argument("--unmount", action="store_true", help="unmount, detach, and re-check the hash")
    p.add_argument("--list", action="store_true", help="list mounts made by evidence-mount")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return run_main(TOOL, lambda: run(args))


def run(args: argparse.Namespace) -> int:
    if args.list:
        return list_mounts()
    if not args.image:
        raise CommandError("name an image file. Example: evidence-mount disk.raw")
    require_root(TOOL)
    open_session_log(TOOL)
    if args.unmount:
        return unmount(args.image)
    return mount(args.image, args.mountpoint, args.partition)


# ------------------------------------------------------------------ state records


def state_dir() -> Path:
    return paths.state_dir() / "mounts"


def _record_path(mountpoint: Path) -> Path:
    key = hashlib.sha256(str(mountpoint).encode()).hexdigest()[:16]
    return state_dir() / f"{key}.json"


def records() -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    folder = state_dir()
    for f in sorted(folder.glob("*.json")) if folder.is_dir() else []:
        try:
            data = jsonio.load_json(f)
        except (OSError, ValueError):
            continue
        if isinstance(data, dict):
            data["_record"] = str(f)
            out.append(data)
    return out


def list_mounts() -> int:
    recs = records()
    if not recs:
        print("No mounts made by evidence-mount.")
        return 0
    for r in recs:
        print(f"{r['mountpoint']}  {r['fstype']}  {r['loop']}  {r['image']}")
    return 0


# ------------------------------------------------------------------ checks


def check_image(arg: str) -> Path:
    path = Path(arg)
    if not path.exists():
        raise CommandError(f"{arg} does not exist. Check the image file name.")
    real = path.resolve()
    mode = real.stat().st_mode
    if stat.S_ISBLK(mode):
        raise CommandError(
            f"{arg} is a drive or partition. evidence-mount mounts image files only; "
            "read drives with forensic-analyze, which never mounts them."
        )
    if not stat.S_ISREG(mode):
        raise CommandError(f"{arg} is not an image file.")
    fd = os.open(real, os.O_RDONLY | os.O_CLOEXEC)
    try:
        head = os.read(fd, len(EWF_MAGIC))
    finally:
        os.close(fd)
    if head == EWF_MAGIC:
        raise CommandError(
            f"{arg} is an E01 (EWF) container. Expose it as a raw image first with "
            "ewfmount, then run evidence-mount on the ewf1 file it shows."
        )
    return real


def default_mountpoint(image: Path) -> Path:
    base = Path(str(load_config().get("mount_base") or "/mnt/airlock"))
    name = _SAFE.sub("_", image.stem).strip("._") or "image"
    return base / name


def prepare_mountpoint(arg: str | None, image: Path) -> tuple[Path, bool]:
    mp = Path(arg).resolve() if arg else default_mountpoint(image)
    if os.path.ismount(mp):
        raise CommandError(f"{mp} is already a mount point. Choose another folder.")
    if mp.exists():
        if not mp.is_dir():
            raise CommandError(f"{mp} is not a folder. Choose an empty folder.")
        if any(mp.iterdir()):
            raise CommandError(f"{mp} is not empty. Choose an empty folder.")
        return mp, False
    mp.mkdir(parents=True, mode=0o755)
    return mp, True


# ------------------------------------------------------------------ probing


def probe(path: str) -> dict[str, str]:
    """``blkid -p`` low-level probe (read-only). Empty dict when nothing is recognised."""
    res = proc.run(["blkid", "-p", "-o", "export", path], check=False, timeout=60)
    out: dict[str, str] = {}
    for line in res.stdout.splitlines():
        key, sep, value = line.partition("=")
        if sep:
            out[key] = value
    return out


def partitions(image: Path) -> list[dict[str, Any]]:
    """Partitions from ``sfdisk -J`` (read-only), with byte offsets."""
    res = proc.run(["sfdisk", "-J", str(image)], check=False, timeout=60)
    if res.returncode != 0 or not res.stdout.strip():
        return []
    table = json.loads(res.stdout).get("partitiontable", {})
    sector = int(table.get("sectorsize") or 512)
    device = str(table.get("device") or image)
    out: list[dict[str, Any]] = []
    for i, part in enumerate(table.get("partitions") or [], 1):
        node = str(part.get("node") or "")
        suffix = node[len(device) :] if node.startswith(device) else ""
        number = int(suffix) if suffix.isdigit() else i
        out.append(
            {
                "number": number,
                "offset_bytes": int(part["start"]) * sector,
                "size_bytes": int(part["size"]) * sector,
                "type": str(part.get("type") or ""),
            }
        )
    return out


def choose_volume(image: Path, number: int | None) -> dict[str, Any]:
    """The byte range to mount: the whole image or one partition."""
    whole = probe(str(image))
    size = image.stat().st_size
    if whole.get("TYPE") and not whole.get("PTTYPE"):
        if number is not None:
            raise CommandError(
                f"{image} holds one filesystem and no partition table. Run it without --partition."
            )
        return {"number": None, "offset_bytes": 0, "size_bytes": size, "type": whole["TYPE"]}
    parts = partitions(image)
    if not parts:
        raise CommandError(
            f"no filesystem or partition table found in {image}. Read it with forensic-analyze "
            "or The Sleuth Kit (mmls, fls) instead."
        )
    if number is None:
        if len(parts) == 1:
            return parts[0]
        listing = "; ".join(
            f"{p['number']}: {human_size(p['size_bytes'])} at byte {p['offset_bytes']}"
            for p in parts
        )
        raise CommandError(
            f"{image} has {len(parts)} partitions ({listing}). Choose one with --partition N."
        )
    for p in parts:
        if p["number"] == number:
            return p
    raise CommandError(
        f"{image} has no partition {number}. Its partitions are "
        + ", ".join(str(p["number"]) for p in parts)
        + "."
    )


def mount_command(fstype: str, loop: str, mountpoint: Path) -> tuple[list[str], str]:
    """The mount argv and the option string for a blkid filesystem type."""
    if fstype in FUSE_FS:
        return [FUSE_FS[fstype], "-o", BASE_OPTIONS, loop, str(mountpoint)], BASE_OPTIONS
    if fstype in KERNEL_FS:
        kernel_type, extra = KERNEL_FS[fstype]
        opts = f"{BASE_OPTIONS},{extra}" if extra else BASE_OPTIONS
        return ["mount", "-t", kernel_type, "-o", opts, loop, str(mountpoint)], opts
    raise CommandError(
        f"evidence-mount does not mount {fstype or 'this'} filesystems. Read it with "
        "forensic-analyze or The Sleuth Kit instead."
    )


# ------------------------------------------------------------------ hashing


def hash_image(image: Path, when: str) -> dict[str, str]:
    print(f"Hashing {image} {when} (reads the whole file) ...", flush=True)
    return hashing.hash_file(image, ("sha256", "md5"))


def _changed_banner(image: Path, before: dict[str, str], after: dict[str, str], when: str) -> str:
    return (
        "\n" + "!" * 72 + "\n"
        f"THE IMAGE CHANGED {when.upper()}.\n"
        f"{image}\n"
        f"SHA-256 before: {before['sha256']}\n"
        f"SHA-256 now:    {after['sha256']}\n"
        "Stop using this image. Go back to the original evidence or a verified copy, and "
        "record this in your case notes.\n" + "!" * 72
    )


# ------------------------------------------------------------------ mount / unmount


def _detach(loop: str) -> None:
    proc.run(["losetup", "-d", loop], check=False, timeout=30)


def mount(image_arg: str, mountpoint_arg: str | None, number: int | None) -> int:
    image = check_image(image_arg)
    for r in records():
        if r.get("image") == str(image):
            raise CommandError(
                f"{image} is already mounted at {r['mountpoint']}. "
                f"Unmount it first: evidence-mount --unmount {r['mountpoint']}"
            )
    volume = choose_volume(image, number)
    print(f"WARNING: {WARNING}\n")
    before = hash_image(image, "before mounting")
    mountpoint, created = prepare_mountpoint(mountpoint_arg, image)
    argv = ["losetup", "--read-only", "--find", "--show"]
    if volume["offset_bytes"] or volume["size_bytes"] != image.stat().st_size:
        argv += ["--offset", str(volume["offset_bytes"]), "--sizelimit", str(volume["size_bytes"])]
    loop = ""
    mounted = False
    try:
        loop = proc.run([*argv, str(image)], timeout=60).stdout.strip()
        if readonly_flag(Path(loop).name) is not True:
            raise CommandError(
                f"the loop device {loop} is not read-only. Nothing was mounted. Report this."
            )
        fstype = probe(loop).get("TYPE", "")
        mount_argv, options = mount_command(fstype, loop, mountpoint)
        res = proc.run(mount_argv, check=False, timeout=120)
        if res.returncode != 0:
            first = (res.stderr.strip().splitlines() or ["no message"])[0].strip()
            raise CommandError(
                f"could not mount the {fstype} filesystem: {first} Nothing is mounted. Read the "
                "image with forensic-analyze or The Sleuth Kit instead."
            )
        mounted = True
        after = hash_image(image, "after mounting")
        if after != before:
            proc.run(["umount", str(mountpoint)], check=False, timeout=120)
            mounted = False
            log(
                TOOL,
                "image_changed",
                image=str(image),
                when="after_mount",
                before=before,
                after=after,
            )
            print(_changed_banner(image, before, after, "after mounting"), file=sys.stderr)
            raise CommandError("the image hash changed after mounting. It has been unmounted.")
    except BaseException:
        if mounted:
            proc.run(["umount", str(mountpoint)], check=False, timeout=120)
        if loop:
            _detach(loop)
        if created:
            mountpoint.rmdir()
        raise
    record = {
        "image": str(image),
        "mountpoint": str(mountpoint),
        "created_mountpoint": created,
        "loop": loop,
        "partition": volume["number"],
        "offset_bytes": volume["offset_bytes"],
        "size_bytes": volume["size_bytes"],
        "fstype": fstype,
        "options": options,
        "mount_argv": mount_argv,
        "hashes_before": before,
        "hashes_after_mount": after,
        "mounted_at": timeutil.iso(),
        "warning_sha256": WARNING_SHA256,
    }
    jsonio.dump_json(_record_path(mountpoint), record)
    log(TOOL, "evidence_mounted", **record)
    print(f"\nMounted read-only at {mountpoint} ({fstype}, {options}).")
    print(f"SHA-256 {before['sha256']} (unchanged after mounting).")
    print(f"When you are done: sudo evidence-mount --unmount {mountpoint}")
    return 0


def _find_record(target: str) -> dict[str, Any]:
    want = {target, str(Path(target).resolve())}
    for r in records():
        if r.get("mountpoint") in want or r.get("image") in want:
            return r
    raise CommandError(
        f"{target} is not a mount made by evidence-mount. List them with evidence-mount --list."
    )


def unmount(target: str) -> int:
    rec = _find_record(target)
    mountpoint = Path(rec["mountpoint"])
    image = Path(rec["image"])
    if os.path.ismount(mountpoint):
        res = proc.run(["umount", str(mountpoint)], check=False, timeout=120)
        if res.returncode != 0:
            raise CommandError(
                f"could not unmount {mountpoint}: {res.stderr.strip()}. Close every window and "
                "terminal using it, then run this again."
            )
    if rec.get("loop") and Path(rec["loop"]).exists():
        _detach(rec["loop"])
    before = rec["hashes_before"]
    after = hash_image(image, "after unmounting")
    unchanged = after == before
    log(
        TOOL,
        "evidence_unmounted",
        image=str(image),
        mountpoint=str(mountpoint),
        loop=rec.get("loop", ""),
        hashes_before=before,
        hashes_after=after,
        unchanged=unchanged,
    )
    Path(rec["_record"]).unlink(missing_ok=True)
    if rec.get("created_mountpoint") and mountpoint.is_dir() and not any(mountpoint.iterdir()):
        mountpoint.rmdir()
    if not unchanged:
        log(
            TOOL,
            "image_changed",
            image=str(image),
            when="after_unmount",
            before=before,
            after=after,
        )
        print(_changed_banner(image, before, after, "while it was mounted"), file=sys.stderr)
        raise CommandError("the image hash changed while it was mounted.")
    print(f"Unmounted {mountpoint}. SHA-256 unchanged: {after['sha256']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
