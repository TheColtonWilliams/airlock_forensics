#!/usr/bin/env bash
# Task 3A.10 (storage part): a disk carrying LVM, mdraid, and swap signatures stays untouched.
# Runs inside the booted AIRLOCK guest as root (by tests/run-qemu-tests.sh). The harness builds
# the signature disk, attaches it with a known serial (default airlock-sig), hashes the
# image on the host before boot, and passes that hash with --expect-sha256. The harness should
# hash the image again on the host after shutdown and compare.
#
# Checks, after boot and again after the automatic activation paths are poked:
#   * the disk and its partitions carry the kernel read-only flag;
#   * no device-mapper (LVM) or md (RAID) device is built on top of it;
#   * no swap on it is active and nothing from it is mounted;
#   * the SHA-256 of the whole disk equals the host's hash and does not change.
# The pokes are what boot does on its own: udev add/change events, "vgchange -aay" (honours
# auto_activation_volume_list), "mdadm --assemble --scan" (honours AUTO -all), "swapon -a".
#
# Usage: test_storage_untouched.sh [--serial SERIAL | --device /dev/X] [--expect-sha256 HEX]
# Exit: 0 pass, 1 fail, 77 skip (not root, signature disk not attached).
set -euo pipefail

SERIAL="${AIRLOCK_SIGDISK_SERIAL:-airlock-sig}"
DEVICE="${AIRLOCK_SIGDISK_DEVICE:-${AIRLOCK_TEST_DISK_SIG:-}}"  # run-qemu-tests.sh sets AIRLOCK_TEST_DISK_SIG
EXPECT="${AIRLOCK_SIGDISK_SHA256:-}"

usage() { sed -n '2,/^set -euo/{/^set -euo/d;s/^# \{0,1\}//;p}' "$0"; }
while (($#)); do
  case "$1" in
    --serial) SERIAL="${2:?--serial needs a value}"; shift 2 ;;
    --device) DEVICE="${2:?--device needs a path}"; shift 2 ;;
    --expect-sha256) EXPECT="${2:?--expect-sha256 needs a hash}"; shift 2 ;;
    -h | --help) usage; exit 0 ;;
    *) echo "test_storage_untouched: unknown option '$1'. Run with --help." >&2; exit 2 ;;
  esac
done

skip() { echo "skip: $*"; exit 77; }
fail() { echo "FAIL: $*" >&2; exit 1; }

[[ "$(id -u)" -eq 0 ]] || skip "needs root"
for tool in lsblk findmnt blockdev sha256sum swapon udevadm; do
  command -v "$tool" >/dev/null 2>&1 || fail "'$tool' is missing from the image"
done
if [[ -n "$EXPECT" && ! "$EXPECT" =~ ^[0-9a-f]{64}$ ]]; then
  fail "--expect-sha256 must be 64 lowercase hex characters"
fi

if [[ -z "$DEVICE" ]]; then
  name="$(lsblk -n -d -o NAME,SERIAL | awk -v s="$SERIAL" '$2 == s {print $1; exit}')"
  [[ -n "$name" ]] || skip "no disk with serial $SERIAL attached; the harness attaches it with -drive ...,serial=$SERIAL"
  DEVICE="/dev/$name"
fi
[[ -b "$DEVICE" ]] || fail "$DEVICE is not a block device"
DEVICE="$(readlink -f -- "$DEVICE")" # /dev/disk/by-id/... -> /dev/vdX
disk="${DEVICE##*/}"
echo "signature disk: $DEVICE"

mapfile -t members < <(lsblk -n -l -o NAME "$DEVICE")

holders_check() {
  local label="$1" m holder
  for m in "${members[@]}"; do
    for holder in /sys/class/block/"$m"/holders/*; do
      [[ -e "$holder" ]] || continue
      fail "$label: /dev/$m is in use by ${holder##*/} (LVM, RAID, or device-mapper assembled it)"
    done
  done
  if [[ -r /proc/mdstat ]] && grep -Eq "(^|[[:space:]])${disk}[a-z0-9]*\[" /proc/mdstat; then
    fail "$label: a RAID array is running on $DEVICE (see /proc/mdstat)"
  fi
}

state_check() {
  local label="$1" m mounts
  for m in "${members[@]}"; do
    [[ "$(blockdev --getro "/dev/$m")" == 1 ]] || fail "$label: /dev/$m is writable (task 3.2)"
    mounts="$(findmnt -rn -S "/dev/$m" -o TARGET || true)"
    [[ -z "$mounts" ]] || fail "$label: /dev/$m is mounted at $mounts"
    if swapon --show=NAME --noheadings | grep -qx "/dev/$m"; then
      fail "$label: swap is active on /dev/$m"
    fi
  done
  holders_check "$label"
  echo "  $label: read-only, nothing assembled, no swap, no mount"
}

disk_hash() { sha256sum <"$DEVICE" | cut -d' ' -f1; }

state_check "after boot"
first="$(disk_hash)"
echo "  sha256 after boot: $first"
if [[ -n "$EXPECT" ]]; then
  [[ "$first" == "$EXPECT" ]] || fail "the disk changed between the host hash ($EXPECT) and boot ($first)"
  echo "  matches the host hash taken before boot"
fi

echo "poking the automatic activation paths:"
udevadm trigger --action=add --sysname-match="${disk}*" --subsystem-match=block
udevadm trigger --action=change --sysname-match="${disk}*" --subsystem-match=block
udevadm settle --timeout=30 || true
if command -v vgchange >/dev/null 2>&1; then vgchange -aay >/dev/null 2>&1 || true; fi
if command -v mdadm >/dev/null 2>&1; then mdadm --assemble --scan >/dev/null 2>&1 || true; fi
swapon -a >/dev/null 2>&1 || true
udevadm settle --timeout=30 || true
sleep 5

state_check "after pokes"
second="$(disk_hash)"
echo "  sha256 after pokes: $second"
[[ "$second" == "$first" ]] || fail "the disk changed during the test ($first -> $second)"

echo "pass: the LVM/mdraid/swap signature disk was not activated, assembled, mounted, or changed"
exit 0
