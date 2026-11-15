#!/usr/bin/env bash
# Write an AIRLOCK image to a removable drive, then prove it was written (tasks 2.1 to 2.5).
#
# Usage:
#   scripts/flash.sh --list [--json]
#   scripts/flash.sh --image FILE --target /dev/sdX [--confirm sdX] [--yes] [options]
#
#   --list              list removable drives (the only drives this script will write)
#   --json              with --list: print the list as JSON (used by make-usb.sh)
#   --image FILE        airlock-<version>.raw or airlock-<version>.raw.zst
#   --sums FILE         SHA256SUMS to check the image against (default: next to the image)
#   --target DEV        the whole drive to erase, for example /dev/sdb (not a partition)
#   --confirm NAME      the drive's kernel name typed back (for example sdb); needed with --yes
#                       or when there is no terminal to type it in
#   --yes               ask nothing; refuses unless --confirm matches the target
#   --headroom-gb N     the drive must be at least image size + N GB (default 8)
#   --expect-serial S   refuse unless the drive reports this serial number
#   -h, --help          this help
#
# Refuses (exit 3, nothing written): a drive that is not removable, the drive holding '/',
# a drive with any mounted filesystem or in use by LVM, RAID or encryption, a drive smaller
# than the image plus headroom, an image whose SHA-256 does not match SHA256SUMS, and a wrong
# or missing typed confirmation.
# Writes with dd (bs=4M conv=fsync status=progress oflag=direct; a .zst image is
# decompressed into dd), then reads back exactly the written range and compares its SHA-256
# with the uncompressed image's.
#
# AIRLOCK_FLASH_TEST=1 (tests only) also accepts a regular file or a loop device as the
# target. Every other check still applies; the tests feed lsblk, findmnt and blockdev stubs.
#
# Exit status: 0 written and verified; 1 failed while writing or verifying; 2 bad usage;
# 3 refused, nothing written.
# Test: tests/functional/test_flash.sh
set -euo pipefail

prog="flash.sh"
test_mode=0
[[ "${AIRLOCK_FLASH_TEST:-0}" == "1" ]] && test_mode=1

usage() { sed -n '2,/^set -euo pipefail$/p' "${BASH_SOURCE[0]}" | sed '$d' | sed 's/^# \{0,1\}//'; }
die() {
  printf '%s: %s\n' "$prog" "$*" >&2
  exit 1
}
refuse() {
  printf '%s: refused: %s\n' "$prog" "$*" >&2
  exit 3
}
bad_usage() {
  printf '%s: %s Run scripts/flash.sh --help.\n' "$prog" "$*" >&2
  exit 2
}
log() { printf '%s: %s\n' "$prog" "$*" >&2; }
have() { command -v "$1" >/dev/null 2>&1; }

# ---------------------------------------------------------------------------- JSON helper
# lsblk output is parsed by Python (always on Ubuntu). Model and serial strings come from the
# device itself, so every field is reduced to printable characters without tabs.
read -r -d '' PY_LSBLK <<'PY' || true
import json
import sys

mode = sys.argv[1]


def clean(value):
    # Empty fields become "-": bash's read merges consecutive tabs.
    if value is None:
        return "-"
    text = "".join(ch if ch.isprintable() and ch != "\t" else "?" for ch in str(value))
    return text.strip()[:80] or "-"


def flag(value):
    if isinstance(value, bool):
        return "1" if value else "0"
    return "1" if str(value).strip().lower() in ("1", "true") else "0"


def walk(nodes):
    for node in nodes or []:
        yield node
        yield from walk(node.get("children"))


if mode == "tojson":
    rows = []
    for line in sys.stdin.read().splitlines():
        name, path, rm, hotplug, tran, size, model, serial, problem = line.split("\t")
        def text(v):
            return "" if v == "-" else v

        rows.append({"hotplug": hotplug == "1", "model": text(model), "name": name, "path": path,
                     "problem": text(problem), "rm": rm == "1", "serial": text(serial),
                     "size": int(size), "tran": text(tran)})
    print(json.dumps(rows, indent=2, sort_keys=True))
    sys.exit(0)

data = json.load(sys.stdin)
devices = data.get("blockdevices") or []
if mode == "disks":
    for d in devices:
        size = d.get("size") or 0
        try:
            size = int(size)
        except ValueError:
            size = 0
        print("\t".join([clean(d.get("name")), clean(d.get("type")), flag(d.get("rm")),
                         flag(d.get("hotplug")), clean(d.get("tran")), str(size),
                         clean(d.get("model")), clean(d.get("serial"))]))
elif mode == "tree":
    for node in walk(devices):
        points = node.get("mountpoints")
        if points is None:
            points = [node.get("mountpoint")]
        for point in points:
            if point:
                print("mount\t" + clean(node.get("name")) + "\t" + clean(point))
        kind = clean(node.get("type"))
        if kind not in ("disk", "part", "loop"):
            print("holder\t" + clean(node.get("name")) + "\t" + kind)
elif mode == "rootdisks":
    for node in walk(devices):
        if node.get("type") in ("disk", "loop"):
            print(clean(node.get("name")))
else:
    sys.exit(f"unknown mode {mode}")
PY

py_lsblk() { python3 -c "$PY_LSBLK" "$@"; }

# ---------------------------------------------------------------------------- helpers
human() { awk -v b="$1" 'BEGIN { printf "%.1f GB", b / 1000000000 }'; }

valid_name() { [[ "$1" =~ ^[A-Za-z0-9._-]+$ ]]; }

# disk_rows: one TSV row per whole disk: name type rm hotplug tran size model serial
disk_rows() {
  local json
  json="$(lsblk -J -b -d -o NAME,MODEL,SIZE,RM,HOTPLUG,TRAN,SERIAL,TYPE 2>/dev/null)" ||
    die "lsblk could not list the drives. Install util-linux and rerun."
  printf '%s' "$json" | py_lsblk disks || die "could not read the lsblk output."
}

# removable RM HOTPLUG TRAN: a drive counts as removable when the kernel says so (RM=1), or
# when it is a hot-plugged USB drive: USB SSDs report RM=0 (decision log 2026-11-15).
removable() { [[ "$1" == "1" || ("$2" == "1" && "$3" == "usb") ]]; }

# root_disks: kernel names of the disks that hold '/'. Fails if they cannot be worked out.
root_disks() {
  local src majmin name json=""
  src="$(findmnt -n -o SOURCE --target / 2>/dev/null | head -n1 || true)"
  src="${src%%\[*}"
  if [[ "$src" == /dev/* ]]; then
    json="$(lsblk -J -s -o NAME,TYPE -- "$src" 2>/dev/null || true)"
  fi
  if [[ -z "$json" ]]; then
    majmin="$(findmnt -n -o MAJ:MIN --target / 2>/dev/null | head -n1 | tr -d '[:space:]' || true)"
    if [[ "$majmin" =~ ^[0-9]+:[0-9]+$ && -e "/sys/dev/block/$majmin" ]]; then
      name="$(basename -- "$(readlink -f -- "/sys/dev/block/$majmin")")"
      json="$(lsblk -J -s -o NAME,TYPE -- "/dev/$name" 2>/dev/null || true)"
    fi
  fi
  [[ -n "$json" ]] || return 1
  printf '%s' "$json" | py_lsblk rootdisks
}

# usage_problems NAME: prints one line per mounted filesystem or holder on the disk or its
# partitions. Empty output means not in use.
usage_problems() {
  local name="$1" json kind dev what src
  json="$(lsblk -J -o NAME,TYPE,MOUNTPOINTS -- "/dev/$name" 2>/dev/null ||
    lsblk -J -o NAME,TYPE,MOUNTPOINT -- "/dev/$name" 2>/dev/null || true)"
  if [[ -n "$json" ]]; then
    while IFS=$'\t' read -r kind dev what; do
      case "$kind" in
        mount) printf '%s is mounted at %s\n' "$dev" "$what" ;;
        holder) printf '%s is in use (%s)\n' "$dev" "$what" ;;
      esac
    done < <(printf '%s' "$json" | py_lsblk tree)
  fi
  # Second source: the kernel's mount table. Partitions of a name ending in a digit
  # (nvme0n1, loop0, mmcblk0) carry a 'p' before the number.
  local part_re='[0-9]+'
  [[ "$name" =~ [0-9]$ ]] && part_re='p[0-9]+'
  while IFS= read -r src; do
    src="${src%%\[*}"
    if [[ "$src" =~ ^/dev/${name}(${part_re})?$ ]]; then
      printf '%s is mounted\n' "${src#/dev/}"
    fi
  done < <(findmnt -rn -o SOURCE 2>/dev/null || true)
}

# list_rows: TSV rows for --list: name path rm hotplug tran size model serial problem
list_rows() {
  local roots name kind rm hotplug tran size model serial problem
  roots="$(root_disks || true)"
  while IFS=$'\t' read -r name kind rm hotplug tran size model serial; do
    [[ -n "$name" ]] || continue
    valid_name "$name" || continue
    if [[ "$kind" != "disk" ]] && ! { ((test_mode)) && [[ "$kind" == "loop" ]]; }; then
      continue
    fi
    removable "$rm" "$hotplug" "$tran" || continue
    problem="-"
    if [[ -z "$roots" ]]; then
      problem="cannot tell which drive holds the running system"
    elif grep -qxF -- "$name" <<<"$roots"; then
      problem="holds the running system"
    elif [[ -n "$(usage_problems "$name")" ]]; then
      problem="in use: unmount it first"
    fi
    printf '%s\t/dev/%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$name" "$name" "$rm" "$hotplug" "$tran" \
      "$size" "$model" "$serial" "$problem"
  done < <(disk_rows)
}

do_list() {
  local rows
  rows="$(list_rows)"
  if ((json_out)); then
    printf '%s' "$rows" | py_lsblk tojson
    return 0
  fi
  if [[ -z "$rows" ]]; then
    echo "No removable drives found. Plug in the USB drive and run this again."
    return 0
  fi
  printf '%-10s %-10s %-6s %-28s %-20s %s\n' DEVICE SIZE BUS MODEL SERIAL NOTE
  local name path rm hotplug tran size model serial problem
  while IFS=$'\t' read -r name path rm hotplug tran size model serial problem; do
    [[ "$problem" == "-" ]] && problem="ok"
    printf '%-10s %-10s %-6s %-28s %-20s %s\n' "$path" "$(human "$size")" "$tran" "$model" "$serial" "$problem"
  done <<<"$rows"
}

# ---------------------------------------------------------------------------- arguments
list=0
json_out=0
image=""
sums=""
target=""
confirm=""
yes=0
headroom_gb=8
expect_serial=""
expect_serial_set=0

while (($#)); do
  case "$1" in
    --list) list=1; shift ;;
    --json) json_out=1; shift ;;
    --image) image="${2:-}"; shift 2 || bad_usage "--image needs a file." ;;
    --sums) sums="${2:-}"; shift 2 || bad_usage "--sums needs a file." ;;
    --target) target="${2:-}"; shift 2 || bad_usage "--target needs a device." ;;
    --confirm) confirm="${2:-}"; shift 2 || bad_usage "--confirm needs the device name." ;;
    --yes) yes=1; shift ;;
    --headroom-gb) headroom_gb="${2:-}"; shift 2 || bad_usage "--headroom-gb needs a number." ;;
    --expect-serial)
      expect_serial="${2:-}"
      expect_serial_set=1
      shift 2 || bad_usage "--expect-serial needs a serial number."
      ;;
    -h | --help) usage; exit 0 ;;
    *) bad_usage "unknown option '$1'." ;;
  esac
done

have python3 || die "python3 is missing. Install it (apt install python3) and rerun."
for c in lsblk findmnt; do
  have "$c" || die "$c is missing. Install util-linux and rerun."
done
((test_mode)) && log "test mode (AIRLOCK_FLASH_TEST=1): regular files and loop devices are accepted as targets"

if ((list)); then
  do_list
  exit 0
fi

[[ -n "$image" ]] || bad_usage "--image is required."
[[ -n "$target" ]] || bad_usage "--target is required."
[[ "$headroom_gb" =~ ^[0-9]+$ ]] || bad_usage "--headroom-gb must be a whole number of GB."
for c in dd sha256sum blockdev; do
  have "$c" || die "$c is missing. Install coreutils and util-linux and rerun."
done

# ---------------------------------------------------------------------------- image
[[ -f "$image" ]] || refuse "image $image not found. Check the path, or build it with scripts/build.sh."
image="$(cd -- "$(dirname -- "$image")" && pwd)/$(basename -- "$image")"
image_name="$(basename -- "$image")"
[[ -n "$sums" ]] || sums="$(dirname -- "$image")/SHA256SUMS"
[[ -f "$sums" ]] ||
  refuse "no SHA256SUMS found at $sums. Download SHA256SUMS from the same release into the image's folder, or pass --sums FILE."

is_zstd=0
if [[ "$(head -c4 -- "$image" | od -An -tx1 | tr -d ' \n')" == "28b52ffd" ]]; then
  is_zstd=1
  have zstd || die "zstd is missing. Install it (apt install zstd) and rerun."
elif [[ "$image_name" == *.zst ]]; then
  refuse "$image_name ends in .zst but is not a zstd file. Download it again."
fi

# sums_lookup NAME: the SHA-256 listed for NAME in the sums file, lower case.
sums_lookup() {
  local want="$1" hash name
  while read -r hash name; do
    name="${name#\*}"
    name="${name#./}"
    if [[ "$name" == "$want" ]]; then
      hash="${hash,,}"
      [[ "$hash" =~ ^[0-9a-f]{64}$ ]] && printf '%s\n' "$hash"
      return 0
    fi
  done <"$sums"
  return 0
}

image_sha_expected="$(sums_lookup "$image_name")"
[[ -n "$image_sha_expected" ]] ||
  refuse "$sums has no SHA-256 line for $image_name. Use the SHA256SUMS that came with this image."
raw_sha_expected=""
raw_name="$image_name"
if ((is_zstd)); then
  raw_name="${image_name%.zst}"
  [[ "$raw_name" != "$image_name" ]] && raw_sha_expected="$(sums_lookup "$raw_name")"
else
  raw_sha_expected="$image_sha_expected"
fi

# Uncompressed image size: a .size file written by the build, the zstd frame header, or the
# raw file's own size.
image_bytes=""
if ((is_zstd)); then
  for side in "$image.size" "$(dirname -- "$image")/$raw_name.size"; do
    if [[ -f "$side" ]]; then
      image_bytes="$(tr -d '[:space:]' <"$side")"
      [[ "$image_bytes" =~ ^[0-9]+$ ]] || refuse "$side does not hold a byte count. Download it again."
      break
    fi
  done
  if [[ -z "$image_bytes" ]]; then
    image_bytes="$(zstd -lv -- "$image" 2>/dev/null | sed -n 's/^Decompressed Size:.*(\([0-9][0-9]*\) B)$/\1/p' | head -n1)"
  fi
  [[ "$image_bytes" =~ ^[0-9]+$ ]] ||
    refuse "cannot tell how big $image_name is once decompressed. Put a $raw_name.size file (the byte count) next to it, or decompress it first (zstd -d)."
else
  image_bytes="$(stat -c %s -- "$image")"
fi
((image_bytes > 0)) || refuse "$image_name is empty. Download or build it again."
((image_bytes % 512 == 0)) || refuse "$image_name is not a whole number of 512-byte sectors, so it is not a disk image."

# ---------------------------------------------------------------------------- target
target_in="$target"
if [[ -L "$target" ]]; then
  target="$(readlink -f -- "$target")"
fi
if [[ -b "$target" ]]; then
  target_kind="block"
elif ((test_mode)) && [[ -f "$target" ]]; then
  target_kind="file"
elif [[ -e "$target" ]]; then
  refuse "$target_in is not a drive (block device). Run scripts/flash.sh --list to see the drives."
else
  refuse "$target_in does not exist. Plug in the drive and run scripts/flash.sh --list to find its name."
fi
name="$(basename -- "$target")"
valid_name "$name" || refuse "$target_in has an unexpected name. Use the /dev name shown by --list."

row=""
while IFS=$'\t' read -r r_name r_rest; do
  if [[ "$r_name" == "$name" ]]; then
    row="$r_name"$'\t'"$r_rest"
    break
  fi
done < <(disk_rows)
[[ -n "$row" ]] ||
  refuse "$target_in is not a whole drive (it may be a partition such as sdb1). Pick the drive itself; run scripts/flash.sh --list."
IFS=$'\t' read -r _ t_type t_rm t_hotplug t_tran _ t_model t_serial <<<"$row"
[[ "$t_tran" == "-" ]] && t_tran=""
[[ "$t_model" == "-" ]] && t_model=""
[[ "$t_serial" == "-" ]] && t_serial=""

if [[ "$t_type" != "disk" ]] && ! { ((test_mode)) && [[ "$t_type" == "loop" ]]; }; then
  refuse "$target_in is a $t_type, not a drive. Pick the whole USB drive; run scripts/flash.sh --list."
fi
removable "$t_rm" "$t_hotplug" "$t_tran" ||
  refuse "$target_in is not a removable drive (RM=0${t_tran:+, bus $t_tran}). This script only writes USB and other removable drives; run scripts/flash.sh --list."

roots="$(root_disks || true)"
[[ -n "$roots" ]] ||
  refuse "could not work out which drive holds the running system, so no drive is safe to erase. Run this from a normal Linux install (not a container)."
if grep -qxF -- "$name" <<<"$roots"; then
  refuse "$target_in holds the running system (/). Pick the USB drive instead; run scripts/flash.sh --list."
fi

problems="$(usage_problems "$name")"
if [[ -n "$problems" ]]; then
  refuse "$target_in is in use: $(paste -sd ';' <<<"$problems" | sed 's/;/; /g'). Unmount it (or eject it in the file manager without unplugging) and rerun."
fi

if [[ "$target_kind" == "block" ]]; then
  target_bytes="$(blockdev --getsize64 "$target" 2>/dev/null || true)"
else
  target_bytes="$(stat -c %s -- "$target")"
fi
[[ "$target_bytes" =~ ^[0-9]+$ ]] || refuse "could not read the size of $target_in. Replug the drive and rerun."
need_bytes=$((image_bytes + headroom_gb * 1000000000))
if ((target_bytes < need_bytes)); then
  refuse "$target_in holds $(human "$target_bytes"); the image needs $(human "$image_bytes") plus $headroom_gb GB headroom ($(human "$need_bytes")). Use a bigger drive (64 GB or more)."
fi

if ((expect_serial_set)) && [[ "$t_serial" != "$expect_serial" ]]; then
  refuse "$target_in reports serial '${t_serial:-none}', not '$expect_serial'. The drive may have been swapped; choose it again."
fi

[[ -w "$target" ]] || refuse "cannot write to $target_in. Run with sudo."

# ---------------------------------------------------------------------------- image hash
log "checking the SHA-256 of $image_name against $(basename -- "$sums")"
image_sha="$(sha256sum -- "$image" | cut -d' ' -f1)"
[[ "$image_sha" == "$image_sha_expected" ]] ||
  refuse "$image_name does not match its SHA256SUMS line (got $image_sha). The download is damaged or altered; download it again."

# ---------------------------------------------------------------------------- confirmation
target_shown="$target_in"
[[ "$target_in" != "$target" ]] && target_shown="$target_in ($target)"
cat >&2 <<EOF

  Drive:     $target_shown
  Model:     ${t_model:-unknown}
  Serial:    ${t_serial:-unknown}
  Size:      $(human "$target_bytes")
  Bus:       ${t_tran:-unknown}
  Image:     $image_name ($(human "$image_bytes") when written)

  EVERYTHING ON THIS DRIVE WILL BE ERASED.

EOF
answer=""
if [[ -n "$confirm" ]]; then
  answer="$confirm"
elif ((yes)); then
  refuse "--yes also needs --confirm $name (the drive's name typed back). Nothing was written."
elif [[ -t 0 ]]; then
  read -r -p "Type the drive name ($name) to erase it, or press Enter to stop: " answer || answer=""
else
  refuse "there is no terminal to type the confirmation in. Pass --confirm $name. Nothing was written."
fi
answer="${answer#/dev/}"
if [[ "$answer" != "$name" ]]; then
  [[ -z "$answer" ]] && refuse "stopped: no confirmation was typed. Nothing was written."
  refuse "the confirmation does not match $name. Nothing was written."
fi

# ---------------------------------------------------------------------------- write
work="$(mktemp -d "${TMPDIR:-/tmp}/airlock-flash.XXXXXX")"
hash_pid=""
writing=0
# shellcheck disable=SC2317,SC2329 # called by traps
cleanup() {
  if [[ -n "$hash_pid" ]] && kill -0 "$hash_pid" 2>/dev/null; then kill "$hash_pid" 2>/dev/null || true; fi
  rm -rf -- "$work"
}
# shellcheck disable=SC2317,SC2329 # called by traps
on_signal() {
  if ((writing)); then
    printf '%s: interrupted while writing; %s is incomplete and will not boot. Run flash.sh again.\n' "$prog" "$target_in" >&2
  fi
  exit 1
}
trap cleanup EXIT
trap on_signal INT TERM HUP

read_flags="count_bytes"
if [[ "$target_kind" == "block" ]]; then
  dd_out=(of="$target" bs=4M conv=fsync status=progress oflag=direct)
  read_flags="count_bytes,direct"
else
  # Test mode only: a regular file must not be truncated, so the tests can see that bytes
  # past the image are untouched.
  dd_out=(of="$target" bs=4M "conv=fsync,notrunc" status=progress)
fi

log "writing $image_name to $target_in. This takes a while; do not unplug the drive."
writing=1
if ((is_zstd)); then
  mkfifo -- "$work/stream"
  sha256sum <"$work/stream" >"$work/stream.sha256" &
  hash_pid=$!
  set +e
  zstd -d -c -q --long=31 -- "$image" | tee -- "$work/stream" | dd iflag=fullblock "${dd_out[@]}"
  status=("${PIPESTATUS[@]}")
  set -e
  wait "$hash_pid" || die "could not hash the decompressed stream. Run flash.sh again."
  hash_pid=""
  ((status[0] == 0)) || die "zstd could not decompress $image_name (exit ${status[0]}); $target_in is incomplete. Download the image again and rerun."
  ((status[1] == 0 && status[2] == 0)) ||
    die "writing to $target_in failed (dd exit ${status[2]}); the drive is incomplete. Replug it or try another drive, then rerun."
  stream_sha="$(cut -d' ' -f1 <"$work/stream.sha256")"
  if [[ -n "$raw_sha_expected" && "$stream_sha" != "$raw_sha_expected" ]]; then
    die "the decompressed image does not match the SHA-256 listed for $raw_name; $target_in is not usable. Download the image again and rerun."
  fi
  [[ -n "$raw_sha_expected" ]] || raw_sha_expected="$stream_sha"
else
  dd if="$image" "${dd_out[@]}" ||
    die "writing to $target_in failed; the drive is incomplete. Replug it or try another drive, then rerun."
fi
sync
writing=0

# ---------------------------------------------------------------------------- read back
log "reading back $(human "$image_bytes") from $target_in to verify"
if [[ "$target_kind" == "block" ]]; then
  blockdev --flushbufs "$target" 2>/dev/null || true
fi
readback_sha="$(dd if="$target" bs=4M iflag="$read_flags" count="$image_bytes" status=none | sha256sum | cut -d' ' -f1)" ||
  die "could not read $target_in back. Replug it and run flash.sh again."
if [[ "$readback_sha" != "$raw_sha_expected" ]]; then
  die "read-back check failed: $target_in does not hold what was written (got $readback_sha, expected $raw_sha_expected). The drive may be faulty or fake-capacity; try another drive."
fi
log "done: $target_in holds $raw_name and reads back correctly (SHA-256 $readback_sha)."
log "next: stage tools and models with scripts/fetch-assets.sh, or boot the drive."
printf 'readback_sha256=%s\n' "$readback_sha"
