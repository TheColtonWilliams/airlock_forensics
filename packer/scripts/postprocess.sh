#!/usr/bin/env bash
# Packer post-processor (task 1.6), runs on the build host: refuses an image whose finalize
# step did not finish, compresses the raw image with zstd, tests the archive, and writes
# SHA256SUMS with both the raw image (flash.sh compares the written range with it) and the
# .zst archive.
# Usage: postprocess.sh [--output-dir DIR] [--image NAME] [--serial-log FILE]
#                       [--zstd-level N] [--no-marker-check]
# (serial log default: DIR/serial.log)
# Defaults come from AIRLOCK_PP_* variables, which the Packer template sets.
# Test: tests/functional/test_build_packer_scripts.sh
set -euo pipefail

out_dir="${AIRLOCK_PP_OUTPUT_DIR:-}"
image="${AIRLOCK_PP_IMAGE:-}"
serial_log="${AIRLOCK_PP_SERIAL_LOG:-}"
level="${AIRLOCK_PP_ZSTD_LEVEL:-15}"
marker_check=1

die() {
  printf 'postprocess: %s\n' "$*" >&2
  exit 1
}
log() { printf 'postprocess: %s\n' "$*"; }

while (($#)); do
  case "$1" in
    --output-dir) out_dir="${2:?}"; shift 2 ;;
    --image) image="${2:?}"; shift 2 ;;
    --serial-log) serial_log="${2:?}"; shift 2 ;;
    --zstd-level) level="${2:?}"; shift 2 ;;
    --no-marker-check) marker_check=0; shift ;;
    -h | --help)
      sed -n '2,10p' "$0"
      exit 0
      ;;
    *) die "unknown option '$1'. Run with --help." ;;
  esac
done

[[ -n "$out_dir" && -n "$image" ]] || die "missing --output-dir or --image."
serial_log="${serial_log:-$out_dir/serial.log}"
if ! [[ "$level" =~ ^[0-9]+$ ]] || ((level < 1 || level > 19)); then
  die "--zstd-level must be 1 to 19, got '$level'."
fi
command -v zstd >/dev/null 2>&1 || die "zstd is not installed. Install it (apt install zstd) and rerun."
[[ -f "$out_dir/$image" ]] || die "image $out_dir/$image not found. The Packer build did not produce it."

if ((marker_check)); then
  [[ -n "$serial_log" && -f "$serial_log" ]] ||
    die "serial log not found, so the finalize step cannot be confirmed. Rebuild; do not publish this image."
  grep -q 'AIRLOCK-FINALIZE-FAILED' -- "$serial_log" &&
    die "the finalize step reported a failure (see $serial_log). Build access may remain; do not publish this image."
  grep -q 'AIRLOCK-FINALIZE-OK' -- "$serial_log" ||
    die "the finalize step did not report success (no AIRLOCK-FINALIZE-OK in $serial_log). Do not publish this image."
fi

cd -- "$out_dir"
log "compressing $image (zstd -$level, all cores)"
zstd -T0 -q -f "-$level" --long=27 -o "$image.zst.tmp" -- "$image"
zstd -q -t --long=27 -- "$image.zst.tmp" || die "the compressed image failed its own test. Rerun the build."
mv -f -- "$image.zst.tmp" "$image.zst"

log "hashing"
sha256sum -- "$image" "$image.zst" >SHA256SUMS.tmp
mv -f -- SHA256SUMS.tmp SHA256SUMS
sha256sum --quiet -c SHA256SUMS || die "SHA256SUMS does not verify. Rerun the build."
log "ok: $out_dir/$image.zst and $out_dir/SHA256SUMS"
