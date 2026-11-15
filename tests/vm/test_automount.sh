#!/usr/bin/env bash
# Tasks 3.1, 3.2, 3.8: no auto-mount and the software read-only policy, tested by behaviour.
# Runs inside the booted AIRLOCK guest as root (by tests/run-qemu-tests.sh), which attaches at
# least one extra virtual disk with a filesystem (and one with a swap-type partition).
#
# For every disk other than the boot disk, and each of its partitions:
#   * the kernel read-only flag is set (blockdev --getro is 1), unless evidence-unlock-output
#     has unlocked it (/run/airlock/rw-allow/NAME);
#   * nothing from it is mounted (findmnt) and no swap on it is active;
#   * a write of the bytes already on the device fails (so a wrong pass cannot damage it).
# Then each disk is re-announced to udev ("add" and "change" events, as a hot-plug would be)
# and the checks are repeated, and no udisks2 or gvfs volume monitor may be running.
#
# Exit: 0 pass, 1 fail, 77 skip (not root, no extra disk).
set -euo pipefail

skip() { echo "skip: $*"; exit 77; }
fail() { echo "FAIL: $*" >&2; exit 1; }

[[ "$(id -u)" -eq 0 ]] || skip "needs root"
for tool in lsblk findmnt blockdev udevadm swapon dd; do
  command -v "$tool" >/dev/null 2>&1 || fail "'$tool' is missing from the image"
done

TMP="$(mktemp -d)"
trap 'rm -rf -- "$TMP"' EXIT

root_src="$(findmnt -n -o SOURCE --mountpoint /)"
root_src="${root_src%%\[*}"
boot_disk="$(lsblk -n -d -o PKNAME "$root_src" 2>/dev/null | head -n1)"
[[ -n "$boot_disk" ]] || boot_disk="$(lsblk -n -d -o NAME "$root_src" | head -n1)"
[[ -n "$boot_disk" ]] || fail "cannot work out the disk that holds / ($root_src)"

mapfile -t disks < <(lsblk -n -d -o NAME,TYPE | awk -v b="$boot_disk" '$2 == "disk" && $1 != b && $1 ~ /^(sd|nvme|mmcblk|vd)/ {print $1}')
((${#disks[@]})) || skip "needs at least one extra virtual disk attached besides the boot disk"
echo "boot disk: $boot_disk; checking: ${disks[*]}"

# Members of a disk: the disk and each of its partitions.
members() { lsblk -n -l -o NAME "/dev/$1"; }

# A disk counts as unlocked only when airlock-setro itself says so (marker bound to this drive).
unlocked() { airlock-setro --check 2>/dev/null | grep -qx "unlocked $1 disk=$2"; }

check_disk() {
  local disk="$1" label="$2" dev mounts
  while IFS= read -r dev; do
    [[ -b "/dev/$dev" ]] || continue
    if unlocked "$dev" "$disk"; then
      echo "  $label: /dev/$dev unlocked by evidence-unlock-output, skipped"
      continue
    fi
    [[ "$(blockdev --getro "/dev/$dev")" == 1 ]] \
      || fail "$label: /dev/$dev is writable; the software read-only policy did not apply (task 3.2)"
    mounts="$(findmnt -rn -S "/dev/$dev" -o TARGET || true)"
    [[ -z "$mounts" ]] || fail "$label: /dev/$dev is mounted at $mounts (task 3.1)"
    if swapon --show=NAME --noheadings | grep -qx "/dev/$dev"; then
      fail "$label: swap is active on /dev/$dev (task 3.3)"
    fi
  done < <(members "$disk")
  echo "  $label: $disk and its partitions are read-only, unmounted, and not used as swap"
}

write_must_fail() {
  local disk="$1" block="$TMP/block"
  if unlocked "$disk" "$disk"; then return 0; fi
  dd if="/dev/$disk" of="$block" bs=4096 count=1 iflag=direct status=none
  # Write back the same bytes: if the policy failed, the disk content is still unchanged.
  if dd if="$block" of="/dev/$disk" bs=4096 count=1 oflag=direct conv=notrunc status=none 2>/dev/null; then
    fail "a write to /dev/$disk succeeded; the software read-only policy did not stop it (task 3.2)"
  fi
  echo "  write to /dev/$disk refused"
}

no_mount_daemons() {
  if systemctl is-active --quiet udisks2.service; then fail "udisks2 is running (task 3.1)"; fi
  if pgrep -f 'gvfs-[a-z0-9]+-volume-monitor' >/dev/null 2>&1; then
    fail "a gvfs volume monitor is running (task 5.1)"
  fi
}

echo "after boot:"
no_mount_daemons
for disk in "${disks[@]}"; do
  check_disk "$disk" "after boot"
  write_must_fail "$disk"
done

echo "after hot-plug events:"
for disk in "${disks[@]}"; do
  udevadm trigger --action=add --sysname-match="${disk}*" --subsystem-match=block
  udevadm trigger --action=change --sysname-match="${disk}*" --subsystem-match=block
done
udevadm settle --timeout=30 || true
sleep 5 # give any desktop automounter time to act
no_mount_daemons
for disk in "${disks[@]}"; do
  check_disk "$disk" "after hot-plug"
  write_must_fail "$disk"
done

if [[ -r /var/log/forensic-session/current.log ]]; then
  grep -q '"event":"ro_policy"' /var/log/forensic-session/current.log \
    || fail "the session log has no ro_policy decisions (airlock-setro did not log)"
  echo "  session log records the read-only policy decisions"
fi

echo "pass: no auto-mount; every non-boot disk and partition is read-only and refuses writes"
exit 0
