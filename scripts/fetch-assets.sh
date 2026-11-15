#!/usr/bin/env bash
# fetch-assets.sh: stage tools, hash sets, signatures and models onto the ASSETS partition of
# a flashed AIRLOCK drive, on a Linux host with internet access (tasks 2B.11, 4A.4, 4A.7, 4B.15).
# The drive itself never goes online: everything it needs offline is put on ASSETS here.
#
# Usage:
#   scripts/fetch-assets.sh [--profile NAME|FILE] [--manifest FILE] [--target-volume DEV|DIR]
#                           [--cache DIR] [--refresh] [--abuse-key-file FILE] [--yes]
#                           [--examiner TEXT] [--agency TEXT] [--case-prefix TEXT] [--dry-run]
#
#   --profile NAME|FILE   profile from the manifest (default, minimal, full, ...) or a JSON/YAML
#                         profile file; asked for when not given (default: "default")
#   --manifest FILE       manifest.json (default: assets/manifest.json of this checkout, made
#                         with scripts/gen-manifest.py when missing; or manifest.json beside
#                         this script in a release download). manifest.json.sig is copied too.
#   --target-volume X     the ASSETS partition (/dev/sdX3) or the folder it is mounted on.
#                         Default: the one partition labelled ASSETS (mounted here if needed).
#   --assets DIR          same as --target-volume DIR
#   --cache DIR           download cache, resumable (default ~/.cache/airlock/assets)
#   --refresh             download the daily-changing sets (ClamAV, MalwareBazaar) again and
#                         restage changed models; files that did not change are kept
#   --abuse-key-file F    abuse.ch Auth-Key for the MalwareBazaar list (also read from the
#                         AIRLOCK_ABUSECH_KEY environment variable, or asked for). Used for that
#                         one download only and never written anywhere.
#   --yes                 ask nothing (no key prompt: MalwareBazaar is skipped without a key)
#
# Exit status: 0 staged, 1 a file failed or the run was refused, 2 usage error.
# Tests: tests/functional/test_fetch_assets.sh, tests/functional/test_refresh.sh
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/.." && pwd)"
core="$script_dir/fetch_assets.py"

die() {
  printf 'fetch-assets: %s\n' "$1" >&2
  exit "${2:-1}"
}
say() { printf 'fetch-assets: %s\n' "$*"; }
have() { command -v "$1" >/dev/null 2>&1; }

usage() {
  sed -n '2,/^# Exit status/p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

target=""
manifest=""
pass=()
while (($#)); do
  case "$1" in
    --target-volume | --assets)
      [[ $# -ge 2 && -n "$2" ]] || die "$1 needs a value (a block device or a folder)" 2
      target="$2"
      shift 2
      ;;
    --target-volume=* | --assets=*)
      target="${1#*=}"
      shift
      ;;
    --manifest)
      [[ $# -ge 2 && -n "$2" ]] || die "--manifest needs a file" 2
      manifest="$2"
      shift 2
      ;;
    --manifest=*)
      manifest="${1#*=}"
      shift
      ;;
    --profile | --cache | --abuse-key-file | --examiner | --agency | --case-prefix)
      [[ $# -ge 2 ]] || die "$1 needs a value" 2
      pass+=("$1" "$2")
      shift 2
      ;;
    --profile=* | --cache=* | --abuse-key-file=* | --examiner=* | --agency=* | --case-prefix=*)
      pass+=("$1")
      shift
      ;;
    --refresh | --yes | --dry-run)
      pass+=("$1")
      shift
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    *) die "unknown option '$1'. Run scripts/fetch-assets.sh --help." 2 ;;
  esac
done

have python3 || die "python3 is missing. Install it (sudo apt-get install python3) and rerun."
[[ -f "$core" ]] || die "$core is missing. Use a complete copy of the scripts folder."

# ---------------------------------------------------------------------------- manifest
if [[ -z "$manifest" ]]; then
  if [[ -f "$repo_root/assets/manifest.json" ]]; then
    manifest="$repo_root/assets/manifest.json"
  elif [[ -f "$script_dir/manifest.json" ]]; then
    manifest="$script_dir/manifest.json"
  elif [[ -f "$script_dir/gen-manifest.py" && -f "$repo_root/ansible/group_vars/all/pins.yml" ]]; then
    say "no assets/manifest.json yet: making it with scripts/gen-manifest.py"
    python3 "$script_dir/gen-manifest.py" ||
      die "scripts/gen-manifest.py failed. Fix the error above and rerun."
    manifest="$repo_root/assets/manifest.json"
  else
    die "no manifest.json found. Pass --manifest with the manifest.json from the release." 2
  fi
fi
[[ -f "$manifest" ]] || die "the manifest $manifest does not exist. Check the path." 2

# ---------------------------------------------------------------------------- ASSETS volume
mounted_here=""
mount_dir=""
# shellcheck disable=SC2317 # called by the EXIT trap
cleanup() {
  if [[ -n "$mounted_here" ]]; then
    sync
    umount -- "$mount_dir" 2>/dev/null || say "could not unmount $mount_dir; unmount it before removing the drive"
    rmdir -- "$mount_dir" 2>/dev/null || true
  fi
}
trap cleanup EXIT

# Prints the partitions labelled ASSETS (filesystem or GPT label), one path per line. lsblk
# reads udev's records; blkid probes the devices itself (needs root) when udev has none.
find_assets_partitions() {
  {
    lsblk -J -o PATH,LABEL,PARTLABEL,TYPE 2>/dev/null | python3 -c '
import json
import sys

def walk(nodes):
    for n in nodes or []:
        if n.get("type") == "part" and "ASSETS" in (n.get("label"), n.get("partlabel")):
            print(n.get("path"))
        walk(n.get("children"))

walk(json.load(sys.stdin).get("blockdevices"))
' || true
    if have blkid; then
      blkid -o device -t LABEL=ASSETS 2>/dev/null || true
      blkid -o device -t PARTLABEL=ASSETS 2>/dev/null || true
    fi
  } | sort -u
}

# Filesystem label or type of a device: blkid probes it, lsblk falls back to udev's records.
probe() { # FIELD(LABEL|TYPE) DEV
  local value=""
  if have blkid; then value="$(blkid -p -o value -s "$1" -- "$2" 2>/dev/null || true)"; fi
  if [[ -z "$value" ]]; then
    local col="$1"
    [[ "$col" == TYPE ]] && col=FSTYPE
    value="$(lsblk -n -d -o "$col" -- "$2" 2>/dev/null | head -n1 || true)"
  fi
  printf '%s' "$value"
}

# Mount point of a block device, if it is mounted.
mount_point_of() {
  { findmnt -n -o TARGET --source "$1" 2>/dev/null || true; } | head -n1
}

use_block_device() {
  local dev="$1" label fstype mp
  label="$(probe LABEL "$dev")"
  fstype="$(probe TYPE "$dev")"
  if [[ "$label" != "ASSETS" ]]; then
    die "$dev is not labelled ASSETS (label '${label:-none}'). Give the ASSETS partition of the flashed drive."
  fi
  mp="$(mount_point_of "$dev")"
  if [[ -n "$mp" ]]; then
    target_dir="$mp"
    return 0
  fi
  [[ "$(id -u)" == "0" ]] || die "$dev is not mounted. Mount it, or rerun with sudo so this script can mount it."
  mount_dir="$(mktemp -d "${TMPDIR:-/tmp}/airlock-assets.XXXXXX")"
  if ! mount -t "${fstype:-exfat}" -o nosuid,nodev,noexec -- "$dev" "$mount_dir" 2>/dev/null; then
    if ! { have mount.exfat-fuse && mount.exfat-fuse -o nosuid,nodev,noexec "$dev" "$mount_dir" </dev/null >/dev/null 2>&1; }; then
      rmdir -- "$mount_dir"
      die "could not mount $dev (exFAT). Install exFAT support (sudo apt-get install exfatprogs exfat-fuse) and rerun."
    fi
  fi
  mounted_here=1
  target_dir="$mount_dir"
  say "mounted $dev at $mount_dir"
}

use_directory() {
  local dir="$1" label
  label="$(findmnt -n -o LABEL --mountpoint "$dir" 2>/dev/null | head -n1 || true)"
  if [[ "$label" == "ASSETS" || -f "$dir/profile.json" || -f "$dir/manifest.json" ]]; then
    target_dir="$dir"
    return 0
  fi
  if [[ -z "$(find "$dir" -mindepth 1 -maxdepth 1 -print -quit 2>/dev/null)" ]]; then
    target_dir="$dir"
    return 0
  fi
  die "$dir is not the ASSETS partition (no ASSETS label, no profile.json) and is not empty. Give the folder the ASSETS partition is mounted on."
}

target_dir=""
if [[ -z "$target" ]]; then
  mapfile -t found < <(find_assets_partitions || true)
  case "${#found[@]}" in
    0) die "no partition labelled ASSETS found. Plug in the flashed AIRLOCK drive, or pass --target-volume." ;;
    1) say "found the ASSETS partition: ${found[0]}" ;;
    *) die "more than one partition is labelled ASSETS (${found[*]}). Pass --target-volume with the right one." ;;
  esac
  use_block_device "${found[0]}"
elif [[ -b "$target" ]]; then
  use_block_device "$target"
elif [[ -d "$target" ]]; then
  use_directory "$target"
else
  die "$target is neither a block device nor a folder. Pass the ASSETS partition or its mount point." 2
fi

# The abuse.ch key, if any, stays in this process's environment (AIRLOCK_ABUSECH_KEY) and the
# core removes it from its own environment as soon as it has read it.
rc=0
python3 "$core" --assets "$target_dir" --manifest "$manifest" --fetcher-name fetch-assets.sh \
  "${pass[@]+"${pass[@]}"}" || rc=$?
exit "$rc"
