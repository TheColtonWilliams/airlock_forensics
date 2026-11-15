#!/usr/bin/env bash
# build.sh: build the synthetic NTFS and exFAT validation images and their ground-truth
# manifests (task 4F.1). Host side or CI only, never on the USB system.
#
# Usage: validation/synthetic/build.sh [--out DIR] [--only ntfs|exfat]
#
#   --out DIR   where <set>.img and <set>.truth.json go (default: validation/out/synthetic)
#   --only K    build one set
#
# Needs root, /dev/fuse, mkfs.ntfs + ntfs-3g (ntfs-3g package), mkfs.exfat (exfatprogs),
# mount.exfat-fuse (exfat-fuse) and libfaketime (faketime). The FUSE drivers run under
# libfaketime so every file gets a planned time; see synth.py for what is in each image.
#
# Exit status: 0 built, 1 failed, 2 usage error, 77 a prerequisite is missing.
# Test: tests/functional/test_validation.sh, tests/unit/test_validation_synth.py
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
die() {
  printf 'synthetic/build.sh: %s\n' "$1" >&2
  exit "${2:-1}"
}

out="$here/../out/synthetic"
only=()
while (($#)); do
  case "$1" in
    --out | --only)
      [[ $# -ge 2 && -n "$2" ]] || die "$1 needs a value" 2
      if [[ "$1" == --out ]]; then out="$2"; else only=(--only "$2"); fi
      shift 2
      ;;
    -h | --help)
      sed -n '2,/^# Test:/p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *) die "unknown option '$1'. Run build.sh --help." 2 ;;
  esac
done

[[ "$(id -u)" -eq 0 ]] || die "needs root (FUSE mounts and loop devices). Run it with sudo." 77
[[ -e /dev/fuse ]] || die "/dev/fuse is missing. Load the fuse module (sudo modprobe fuse)." 77
need() { # COMMAND PACKAGE
  command -v "$1" >/dev/null 2>&1 || die "'$1' is missing. Install it (sudo apt-get install $2)." 77
}
need python3 python3
need mkfs.ntfs ntfs-3g
need ntfs-3g ntfs-3g
need mkfs.exfat exfatprogs
need mount.exfat-fuse exfat-fuse
need losetup util-linux
need blockdev util-linux
need faketime faketime

mkdir -p "$out"
python3 "$here/synth.py" --out "$out" "${only[@]+"${only[@]}"}"
