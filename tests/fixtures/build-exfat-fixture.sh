#!/usr/bin/env bash
# Build the shared exFAT test fixture (task 4.14): an 8 MiB exFAT volume (no partition table),
# the file system Windows and cameras use on removable drives, with known live files, known
# deleted files (small and multi-cluster), and hostile names (leading '=', '+', and a
# right-to-left override character). Every file is generated text: no real user data.
#
# Output (in --out-dir, default: the folder holding this script):
#   exfat-basic.img.zst       the image, zstd-compressed
#   exfat-basic.truth.json    ground truth: every file, its deleted flag, size, SHA-256,
#                             directory entry number and modified time
#   exfat-basic.sha256        sha256sum lines for exfat-basic.img and exfat-basic.img.zst
#
# Needs root, a free loop device, /dev/fuse, mkfs.exfat and tune.exfat (exfatprogs),
# mount.exfat-fuse (exfat-fuse), fls (The Sleuth Kit), python3, zstd.
# Usage: sudo tests/fixtures/build-exfat-fixture.sh [--out-dir DIR] [--keep-raw]
set -euo pipefail

NAME="exfat-basic"
SIZE_MIB=8
LABEL="AIRLOCKEXF"
SERIAL="0x1a2b3c4d"

out_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
keep_raw=0

die() {
  echo "build-exfat-fixture: $*" >&2
  exit 1
}

usage() {
  sed -n '2,17p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
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

[[ "$(id -u)" -eq 0 ]] || die "needs root for the loop device and FUSE mount. Run it with sudo."
[[ -e /dev/fuse ]] || die "/dev/fuse is missing. Load the fuse module (modprobe fuse) and retry."
for tool in mkfs.exfat tune.exfat mount.exfat-fuse losetup fls python3 zstd sha256sum; do
  command -v "$tool" >/dev/null 2>&1 ||
    die "'$tool' is not installed. Install exfatprogs, exfat-fuse, sleuthkit, python3 and zstd."
done
[[ -d "$out_dir" ]] || die "output folder '$out_dir' does not exist. Create it or pass --out-dir."

work="$(mktemp -d "${TMPDIR:-/tmp}/airlock-exfat-fixture.XXXXXX")"
mnt="$work/mnt"
img="$work/$NAME.img"
loop=""
mounted=0
cleanup() {
  if [[ "$mounted" -eq 1 ]]; then umount "$mnt" 2>/dev/null || true; fi
  if [[ -n "$loop" ]]; then losetup -d "$loop" 2>/dev/null || true; fi
  rm -rf -- "$work"
}
trap cleanup EXIT

truncate -s "${SIZE_MIB}M" "$img"
mkfs.exfat -q -L "$LABEL" "$img" >"$work/mkfs.log" 2>&1 ||
  die "mkfs.exfat failed on $img: $(tail -n 1 "$work/mkfs.log")"
tune.exfat -I "$SERIAL" "$img" >/dev/null 2>&1 || die "tune.exfat could not set the serial."

loop="$(losetup -f --show -- "$img")" || die "no free loop device. Free one (losetup -D) and retry."
mkdir -p "$mnt"
mount.exfat-fuse "$loop" "$mnt" >/dev/null 2>&1 || die "mount.exfat-fuse could not mount $loop."
mounted=1

python3 -I - "$mnt" >"$work/truth.partial.json" <<'PY'
"""Write the fixture's files through the exFAT FUSE mount, then delete the deleted ones."""

import datetime as dt
import hashlib
import json
import os
import sys
from pathlib import Path

mnt = Path(sys.argv[1])


def text_bytes(seed: str, size: int) -> bytes:
    out = bytearray()
    n = 0
    while len(out) < size:
        out += f"{seed} line {n:05d}: generated fixture text, no real data.\n".encode()
        n += 1
    return bytes(out[:size])


def utc(text: str) -> dt.datetime:
    return dt.datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.UTC)


# (path, content, deleted, hostile, mtime). exFAT keeps modified times to 2 seconds here,
# so every time is on an even second.
FILES = [
    ("DCIM/notes/readme.txt", text_bytes("camera readme", 200), False, False,
     "2026-03-01T10:00:00Z"),
    ("DCIM/notes/log-2026.txt", text_bytes("camera log", 40_000), False, False,
     "2026-03-02T11:30:00Z"),
    ("=HYPERLINK(1).txt", text_bytes("exfat formula", 30), False, True, "2026-03-03T12:00:00Z"),
    ("+cmd.txt", text_bytes("exfat plus", 30), False, True, "2026-03-03T12:02:00Z"),
    ("photo‮gpj.exe", text_bytes("exfat bidi", 30), False, True, "2026-03-03T12:04:00Z"),
    ("DCIM/notes/deleted-small.txt", text_bytes("exfat deleted small", 300), True, False,
     "2026-03-04T08:00:00Z"),
    ("DCIM/notes/deleted-large.txt", text_bytes("exfat deleted large", 100_000), True, False,
     "2026-03-04T09:00:00Z"),
    ("=deleted-sum.txt", text_bytes("exfat deleted formula", 30), True, True,
     "2026-03-04T10:00:00Z"),
]

files = []
for rel, data, deleted, hostile, mtime in FILES:
    path = mnt / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    m = utc(mtime)
    os.utime(path, ns=(int(m.timestamp()) * 10**9, int(m.timestamp()) * 10**9))
    files.append(
        {
            "path": "/" + rel,
            "name": rel.rsplit("/", 1)[-1],
            "deleted": deleted,
            "hostile_name": hostile,
            "kind": "file",
            "size": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
            "mtime": mtime,
        }
    )
os.sync()
for rel, _data, deleted, _hostile, _mtime in FILES:
    if deleted:
        (mnt / rel).unlink()
os.sync()
json.dump({"files": files}, sys.stdout, ensure_ascii=False, sort_keys=True)
PY

sync
umount "$mnt"
mounted=0
losetup -d "$loop"
loop=""

fls -r -p -- "$img" >"$work/fls.txt" || die "fls could not read the new image."
raw_sha="$(sha256sum -- "$img" | cut -d' ' -f1)"
python3 -I - "$work/truth.partial.json" "$work/fls.txt" "$out_dir/$NAME.truth.json" \
  "$NAME" "$raw_sha" "$SIZE_MIB" "$LABEL" "$SERIAL" <<'PY'
"""Merge the directory entry numbers listed by fls into the ground truth."""

import json
import re
import sys
from pathlib import Path

partial, fls_txt, out, name, raw_sha, size_mib, label, serial = sys.argv[1:9]
truth = json.loads(Path(partial).read_text(encoding="utf-8"))
entries: dict[tuple[str, bool], int] = {}
line_re = re.compile(r"^(\S+/\S+) (\* )?(\d+)(?:\(realloc\))?:\t(.*)$")
for line in Path(fls_txt).read_bytes().decode("utf-8", "surrogateescape").splitlines():
    m = line_re.match(line)
    if m:
        entries.setdefault(("/" + m.group(4), bool(m.group(2))), int(m.group(3)))
missing = []
for f in truth["files"]:
    entry = entries.get((f["path"], f["deleted"]))
    if entry is None:
        missing.append(f["path"])
    f["dir_entry"] = entry
if missing:
    sys.exit("build-exfat-fixture: fls did not list " + ", ".join(sorted(missing)))
truth["files"].sort(key=lambda f: f["path"])
plain = [f for f in truth["files"] if f["deleted"] and not f["hostile_name"]]
doc = {
    "schema": 1,
    "fixture": name,
    "image": f"{name}.img",
    "image_sha256": raw_sha,
    "size_bytes": int(size_mib) * 1024 * 1024,
    "filesystem": "exfat",
    "partition_table": None,
    "volume_label": label,
    "volume_serial": serial.lower(),
    "built_by": "tests/fixtures/build-exfat-fixture.sh",
    "notes": (
        "Modified times were set through exfat-fuse (2-second resolution); other times are the "
        "build time. 'deleted' lists the plainly named deleted files; 'files' has every file."
    ),
    "files": truth["files"],
    "deleted": [{k: f[k] for k in ("path", "size", "sha256", "dir_entry")} for f in plain],
    "deleted_names": sorted(f["name"] for f in truth["files"] if f["deleted"]),
    "live": sorted(f["path"] for f in truth["files"] if not f["deleted"]),
    "hostile_names": sorted(f["name"] for f in truth["files"] if f["hostile_name"]),
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
echo "build-exfat-fixture: wrote $out_dir/$NAME.img.zst, $NAME.truth.json and $NAME.sha256 (image sha256 $raw_sha)"
