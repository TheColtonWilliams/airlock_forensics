#!/usr/bin/env bash
# Build the shared NTFS test fixture (task 4.14): a 64 MiB NTFS volume (no partition table) with
# known live files, known deleted files (resident and non-resident, a deleted folder), a
# $Recycle.Bin folder holding a Windows 10 $I/$R pair (and an emptied pair), and files with
# hostile names (leading '=', '+', '-', '@', and a right-to-left override character).
# Every file is generated text or a generated shape: no real user data, no media of people.
#
# Output (in --out-dir, default: the folder holding this script):
#   ntfs-basic.img.zst       the image, zstd-compressed
#   ntfs-basic.truth.json    ground truth: every file, its deleted flag, size, SHA-256, MFT
#                            entry, controlled times, and the recycle-bin entries
#   ntfs-basic.sha256        sha256sum lines for ntfs-basic.img and ntfs-basic.img.zst
#
# Needs root, /dev/fuse, mkfs.ntfs, ntfs-3g, ntfslabel, fls (The Sleuth Kit), python3, zstd.
# Usage: sudo tests/fixtures/build-ntfs-fixture.sh [--out-dir DIR] [--keep-raw]
set -euo pipefail

NAME="ntfs-basic"
SIZE_MIB=64
LABEL="AIRLOCK_NTFS"
SERIAL="1A2B3C4D5E6F7081"
SID="S-1-5-21-1111111111-2222222222-3333333333-1001"

out_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
keep_raw=0

die() {
  echo "build-ntfs-fixture: $*" >&2
  exit 1
}

usage() {
  sed -n '2,19p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --out-dir)
      [[ $# -ge 2 ]] || die "--out-dir needs a folder. Run with --help for usage."
      out_dir="$2"
      shift 2
      ;;
    --keep-raw)
      keep_raw=1
      shift
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    *) die "unknown option '$1'. Run with --help for usage." ;;
  esac
done

[[ "$(id -u)" -eq 0 ]] || die "needs root for the ntfs-3g FUSE mount. Run it with sudo."
[[ -e /dev/fuse ]] || die "/dev/fuse is missing. Load the fuse module (modprobe fuse) and retry."
for tool in mkfs.ntfs ntfs-3g ntfslabel fls python3 zstd sha256sum; do
  command -v "$tool" >/dev/null 2>&1 ||
    die "'$tool' is not installed. Install ntfs-3g, sleuthkit, python3 and zstd, then retry."
done
[[ -d "$out_dir" ]] || die "output folder '$out_dir' does not exist. Create it or pass --out-dir."

work="$(mktemp -d "${TMPDIR:-/tmp}/airlock-ntfs-fixture.XXXXXX")"
mnt="$work/mnt"
img="$work/$NAME.img"
mounted=0
cleanup() {
  if [[ "$mounted" -eq 1 ]]; then umount "$mnt" 2>/dev/null || true; fi
  rm -rf -- "$work"
}
trap cleanup EXIT

truncate -s "${SIZE_MIB}M" "$img"
# -T: system files get a zero time stamp, so the empty volume is the same on every build.
mkfs.ntfs --quick --force --zero-time --label "$LABEL" "$img" >"$work/mkfs.log" 2>&1 ||
  die "mkfs.ntfs failed on $img: $(tail -n 1 "$work/mkfs.log")"
ntfslabel --new-serial="$SERIAL" "$img" >/dev/null || die "ntfslabel could not set the serial."

mkdir -p "$mnt"
ntfs-3g -o streams_interface=windows "$img" "$mnt" || die "ntfs-3g could not mount $img."
mounted=1

# Populate the volume and print the ground truth (without MFT entries) as JSON.
python3 -I - "$mnt" "$SID" >"$work/truth.partial.json" <<'PY'
"""Write the fixture's files through the ntfs-3g mount, then delete the deleted ones."""

import datetime as dt
import hashlib
import json
import os
import struct
import sys
import zlib
from pathlib import Path

mnt = Path(sys.argv[1])
sid = sys.argv[2]
EPOCH = dt.datetime(1601, 1, 1, tzinfo=dt.UTC)


def filetime(when: dt.datetime) -> int:
    delta = when - EPOCH
    return (delta.days * 86400 + delta.seconds) * 10_000_000 + delta.microseconds * 10


def iso(when: dt.datetime) -> str:
    return when.strftime("%Y-%m-%dT%H:%M:%SZ")


def utc(text: str) -> dt.datetime:
    return dt.datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.UTC)


def text_bytes(seed: str, size: int) -> bytes:
    """Deterministic readable text of exactly ``size`` bytes."""
    out = bytearray()
    n = 0
    while len(out) < size:
        out += f"{seed} line {n:05d}: generated fixture text, no real data.\n".encode()
        n += 1
    return bytes(out[:size])


def pattern_bytes(seed: str, size: int) -> bytes:
    """Deterministic binary data: 4 KiB blocks, each a SHA-256 header plus filler (compresses)."""
    out = bytearray()
    n = 0
    while len(out) < size:
        head = hashlib.sha256(f"{seed}:{n}".encode()).digest()
        out += head + bytes([n % 251]) * (4096 - len(head))
        n += 1
    return bytes(out[:size])


def png_square(side: int, rgb: tuple[int, int, int]) -> bytes:
    """A plain coloured square as PNG: a generated shape."""
    raw = b"".join(b"\x00" + bytes(rgb) * side for _ in range(side))

    def chunk(kind: bytes, data: bytes) -> bytes:
        return (
            struct.pack(">I", len(data))
            + kind
            + data
            + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)
        )

    ihdr = struct.pack(">IIBBBBB", side, side, 8, 2, 0, 0, 0)
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", ihdr)
        + chunk(b"IDAT", zlib.compress(raw, 9))
        + chunk(b"IEND", b"")
    )


def recycle_i_v2(original: str, size: int, deleted: dt.datetime) -> bytes:
    """Windows 10 $I file, version 2: version, size, FILETIME, length in chars, UTF-16LE path."""
    name = (original + "\0").encode("utf-16-le")
    return struct.pack("<qqqi", 2, size, filetime(deleted), len(name) // 2) + name


U = "Users/test-user"
RB = f"$Recycle.Bin/{sid}"
R_TEXT = text_bytes("quarterly summary", 1500)
R2_TEXT = text_bytes("draft letter", 900)
I_DELETED = utc("2026-02-03T04:05:06Z")
I2_DELETED = utc("2026-02-10T11:12:14Z")
I_ORIGINAL = "C:\\Users\\test-user\\Documents\\quarterly-summary.txt"
I2_ORIGINAL = "C:\\Users\\test-user\\Desktop\\draft-letter.docx"

# (path, content, deleted, hostile, times: crtime, mtime, atime)
FILES = [
    (f"{U}/Documents/readme.txt", text_bytes("readme", 120), False, False,
     ("2026-01-10T08:00:00Z", "2026-01-15T09:30:00Z", "2026-01-16T10:00:00Z")),
    (f"{U}/Documents/notes-2026.txt", text_bytes("notes", 12_288), False, False,
     ("2026-01-11T08:00:00Z", "2026-01-20T17:45:30Z", "2026-01-21T07:00:00Z")),
    (f"{U}/Pictures/red-square.png", png_square(32, (200, 30, 30)), False, False,
     ("2026-01-12T12:00:00Z", "2026-01-12T12:00:00Z", "2026-01-12T12:00:00Z")),
    (f"{U}/Desktop/=1+1.txt", text_bytes("formula equals", 40), False, True,
     ("2026-01-13T08:00:00Z", "2026-01-13T08:01:00Z", "2026-01-13T08:02:00Z")),
    (f"{U}/Desktop/+SUM(1,2).txt", text_bytes("formula plus", 40), False, True,
     ("2026-01-13T09:00:00Z", "2026-01-13T09:01:00Z", "2026-01-13T09:02:00Z")),
    (f"{U}/Desktop/-2+3.txt", text_bytes("formula minus", 40), False, True,
     ("2026-01-13T10:00:00Z", "2026-01-13T10:01:00Z", "2026-01-13T10:02:00Z")),
    (f"{U}/Desktop/@cmd.txt", text_bytes("formula at", 40), False, True,
     ("2026-01-13T11:00:00Z", "2026-01-13T11:01:00Z", "2026-01-13T11:02:00Z")),
    (f"{U}/Downloads/invoice\u202etxt.exe", text_bytes("bidi override", 64), False, True,
     ("2026-01-14T08:00:00Z", "2026-01-14T08:01:00Z", "2026-01-14T08:02:00Z")),
    (f"{RB}/desktop.ini", text_bytes("desktop ini", 129), False, False,
     ("2026-01-09T08:00:00Z", "2026-01-09T08:00:00Z", "2026-01-09T08:00:00Z")),
    (f"{RB}/$IR8K2QF.txt", recycle_i_v2(I_ORIGINAL, len(R_TEXT), I_DELETED), False, False,
     ("2026-02-03T04:05:06Z", "2026-02-03T04:05:06Z", "2026-02-03T04:05:06Z")),
    (f"{RB}/$RR8K2QF.txt", R_TEXT, False, False,
     ("2026-01-05T08:00:00Z", "2026-01-30T16:00:00Z", "2026-02-01T09:00:00Z")),
    # Deleted files: resident (small), non-resident, hostile name, a folder and its file, and an
    # emptied recycle-bin pair.
    (f"{U}/Documents/deleted-resident.txt", text_bytes("deleted resident", 80), True, False,
     ("2026-01-17T08:00:00Z", "2026-01-18T09:15:00Z", "2026-01-19T10:30:00Z")),
    (f"{U}/Documents/deleted-report.txt", text_bytes("deleted report", 20_000), True, False,
     ("2026-01-17T09:00:00Z", "2026-01-22T14:20:00Z", "2026-01-23T08:00:00Z")),
    (f"{U}/Downloads/deleted-archive.bin", pattern_bytes("deleted archive", 300_000), True,
     False, ("2026-01-17T10:00:00Z", "2026-01-24T18:00:00Z", "2026-01-25T07:30:00Z")),
    (f"{U}/Desktop/=deleted-formula.txt", text_bytes("deleted formula", 48), True, True,
     ("2026-01-17T11:00:00Z", "2026-01-26T12:00:00Z", "2026-01-26T12:30:00Z")),
    (f"{U}/Downloads/old-project/plan.txt", text_bytes("old project plan", 3_000), True, False,
     ("2026-01-17T12:00:00Z", "2026-01-27T15:00:00Z", "2026-01-27T15:30:00Z")),
    (f"{RB}/$IX7Y2ZA.docx", recycle_i_v2(I2_ORIGINAL, len(R2_TEXT), I2_DELETED), True, False,
     ("2026-02-10T11:12:14Z", "2026-02-10T11:12:14Z", "2026-02-10T11:12:14Z")),
    (f"{RB}/$RX7Y2ZA.docx", R2_TEXT, True, False,
     ("2026-01-06T08:00:00Z", "2026-02-09T16:00:00Z", "2026-02-10T09:00:00Z")),
]
DELETED_DIRS = [f"{U}/Downloads/old-project"]

files = []
for rel, data, deleted, hostile, (crt, mtm, atm) in FILES:
    path = mnt / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
for rel, data, deleted, hostile, (crt, mtm, atm) in FILES:
    path = mnt / rel
    c, m, a = utc(crt), utc(mtm), utc(atm)
    # utime first: ntfs-3g drops a utime that follows the crtime attribute write.
    os.utime(path, ns=(int(a.timestamp()) * 10**9, int(m.timestamp()) * 10**9))
    os.setxattr(path, "system.ntfs_crtime", struct.pack("<Q", filetime(c)))
    files.append(
        {
            "path": "/" + rel,
            "name": rel.rsplit("/", 1)[-1],
            "deleted": deleted,
            "hostile_name": hostile,
            "kind": "file",
            "size": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
            "crtime": iso(c),
            "mtime": iso(m),
            "atime": iso(a),
            "crtime_filetime": filetime(c),
            "mtime_filetime": filetime(m),
            "atime_filetime": filetime(a),
        }
    )
os.sync()
for rel, _data, deleted, _hostile, _times in FILES:
    if deleted:
        (mnt / rel).unlink()
for rel in DELETED_DIRS:
    (mnt / rel).rmdir()
    files.append(
        {"path": "/" + rel, "name": rel.rsplit("/", 1)[-1], "deleted": True,
         "hostile_name": False, "kind": "dir"}
    )
os.sync()

recycle = [
    {
        "sid": sid,
        "i_name": "$IR8K2QF.txt",
        "r_name": "$RR8K2QF.txt",
        "i_path": f"/{RB}/$IR8K2QF.txt",
        "r_path": f"/{RB}/$RR8K2QF.txt",
        "format_version": 2,
        "original_path": I_ORIGINAL,
        "original_size": len(R_TEXT),
        "deleted_time": iso(I_DELETED),
        "deleted_filetime": filetime(I_DELETED),
        "i_deleted": False,
        "r_deleted": False,
    },
    {
        "sid": sid,
        "i_name": "$IX7Y2ZA.docx",
        "r_name": "$RX7Y2ZA.docx",
        "i_path": f"/{RB}/$IX7Y2ZA.docx",
        "r_path": f"/{RB}/$RX7Y2ZA.docx",
        "format_version": 2,
        "original_path": I2_ORIGINAL,
        "original_size": len(R2_TEXT),
        "deleted_time": iso(I2_DELETED),
        "deleted_filetime": filetime(I2_DELETED),
        "i_deleted": True,
        "r_deleted": True,
    },
]
json.dump({"files": files, "recycle_bin": recycle}, sys.stdout, ensure_ascii=False,
          sort_keys=True)
PY

sync
umount "$mnt"
mounted=0

# Add MFT entry numbers from The Sleuth Kit and write the final ground truth.
fls -r -p -- "$img" >"$work/fls.txt" || die "fls could not read the new image."
raw_sha="$(sha256sum -- "$img" | cut -d' ' -f1)"
python3 -I - "$work/truth.partial.json" "$work/fls.txt" "$out_dir/$NAME.truth.json" \
  "$NAME" "$raw_sha" "$SIZE_MIB" "$LABEL" "$SERIAL" <<'PY'
"""Merge the MFT entries listed by fls into the ground truth and write it with sorted keys."""

import json
import re
import sys
from pathlib import Path

partial, fls_txt, out, name, raw_sha, size_mib, label, serial = sys.argv[1:9]
truth = json.loads(Path(partial).read_text(encoding="utf-8"))
entries: dict[tuple[str, bool], int] = {}
line_re = re.compile(r"^(\S+/\S+) (\* )?(\d+)(?:-\d+-\d+)?(?:\(realloc\))?:\t(.*)$")
for line in Path(fls_txt).read_bytes().decode("utf-8", "surrogateescape").splitlines():
    m = line_re.match(line)
    if m:
        entries.setdefault(("/" + m.group(4), bool(m.group(2))), int(m.group(3)))
missing = []
for f in truth["files"]:
    entry = entries.get((f["path"], f["deleted"]))
    if entry is None:
        missing.append(f["path"])
    f["mft_entry"] = entry
if missing:
    sys.exit("build-ntfs-fixture: fls did not list " + ", ".join(sorted(missing)))
truth["files"].sort(key=lambda f: f["path"])
plain = [
    f for f in truth["files"]
    if f["deleted"] and f["kind"] == "file" and not f["hostile_name"]
    and not f["path"].startswith("/$Recycle.Bin/")
    and "/old-project/" not in f["path"]
]
doc = {
    "schema": 1,
    "fixture": name,
    "image": f"{name}.img",
    "image_sha256": raw_sha,
    "size_bytes": int(size_mib) * 1024 * 1024,
    "filesystem": "ntfs",
    "partition_table": None,
    "volume_label": label,
    "volume_serial": serial.lower(),
    "built_by": "tests/fixtures/build-ntfs-fixture.sh",
    "notes": (
        "Times are $STANDARD_INFORMATION times set through ntfs-3g; $FILE_NAME times are the "
        "build time. ntfs-3g keeps no USN journal, so the volume has no $UsnJrnl. 'deleted' "
        "lists the plainly named deleted files whose folder still exists; 'files' has every "
        "file, including hostile names, the deleted folder and the emptied recycle-bin pair."
    ),
    "files": truth["files"],
    "deleted": [{k: f[k] for k in ("path", "size", "sha256", "mft_entry")} for f in plain],
    "deleted_names": sorted({f["name"] for f in truth["files"] if f["deleted"]}),
    "live": sorted(f["path"] for f in truth["files"] if not f["deleted"]),
    "hostile_names": sorted(f["name"] for f in truth["files"] if f["hostile_name"]),
    "recycle_bin": truth["recycle_bin"],
}
Path(out).write_text(
    json.dumps(doc, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8"
)
PY

zstd -q -19 -f -o "$out_dir/$NAME.img.zst" -- "$img" || die "zstd could not compress the image."
zst_sha="$(sha256sum -- "$out_dir/$NAME.img.zst" | cut -d' ' -f1)"
printf '%s  %s\n%s  %s\n' "$raw_sha" "$NAME.img" "$zst_sha" "$NAME.img.zst" >"$out_dir/$NAME.sha256"
if [[ "$keep_raw" -eq 1 ]]; then
  cp -- "$img" "$out_dir/$NAME.img"
fi
echo "build-ntfs-fixture: wrote $out_dir/$NAME.img.zst, $NAME.truth.json and $NAME.sha256 (image sha256 $raw_sha)"
