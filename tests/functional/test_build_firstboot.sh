#!/usr/bin/env bash
# airlock-firstboot (task 1.10) on a loop disk that is larger than the image it holds:
# commits a machine ID, moves the backup GPT, grows partition 5 to the end of the disk,
# grows ext4 to fill it, and writes its done-marker. A second run changes nothing.
# (Online resize of a mounted root is checked in the booted image: tests/goss/base.yaml root-grown.)
# shellcheck source=tests/functional/lib.sh
. "$(dirname "$0")/lib.sh"
# shellcheck source=tests/vm/lib/disks.sh
. "$REPO_ROOT/tests/vm/lib/disks.sh"
require_loop
require_cmd sgdisk partx growpart resize2fs e2fsck dumpe2fs mkfs.ext4

fb="$REPO_ROOT/ansible/roles/base/files/airlock-firstboot"
img="$TEST_TMP/disk.raw"
airlock_mini_layout_disk "$img" 128
truncate -s +96M "$img" # flashed onto a bigger drive: free space after the root partition
dev="$(airlock_loop_attach "$img")" || fail "could not attach $img"
# shellcheck disable=SC2317 # run by on_exit
detach() { airlock_loop_detach "$dev"; }
on_exit detach
mkfs.ext4 -q -F -L AIRLOCK_ROOT "${dev}p5"
fs_bytes() { dumpe2fs -h "${dev}p5" 2>/dev/null | awk -F: '/^Block count/ {c=$2} /^Block size/ {s=$2} END {print c*s}'; }
before_fs="$(fs_bytes)"
end_before="$(sgdisk -i 5 "$img" | awk '/^Last sector/ {print $3}')"

# Machine ID: empty file in a fake root, as the published image ships it.
sysroot="$TEST_TMP/sysroot"
mkdir -p "$sysroot/etc"
: >"$sysroot/etc/machine-id"
if ! command -v systemd-machine-id-setup >/dev/null 2>&1; then
  # shellcheck disable=SC2016 # expanded by the stub, not here
  stub systemd-machine-id-setup 'root=${1#--root=}; printf "%032x\n" 42 >"$root/etc/machine-id"'
fi

AIRLOCK_SYSROOT="$sysroot" AIRLOCK_STATE_DIR="$TEST_TMP/state" run "$fb" --root-source "${dev}p5" --no-disable
assert_eq "$RC" 0 "first boot: $OUT"
grep -Eq '^[0-9a-f]{32}$' "$sysroot/etc/machine-id" || fail "machine ID not written"
assert_file "$TEST_TMP/state/firstboot.done"
end_after="$(sgdisk -i 5 "$img" | awk '/^Last sector/ {print $3}')"
last_usable="$(sgdisk -p "$img" | awk '/last usable sector is/ {print $NF}')"
((end_after > end_before)) || fail "partition 5 did not grow ($end_before -> $end_after)"
assert_eq "$end_after" "$last_usable" "partition 5 ends at the last usable sector"
after_fs="$(fs_bytes)"
((after_fs > before_fs + 64 * 1024 * 1024)) || fail "filesystem did not grow ($before_fs -> $after_fs)"
part_bytes="$(blockdev --getsize64 "${dev}p5")"
(((part_bytes - after_fs) < 4 * 1024 * 1024)) || fail "filesystem does not fill the partition"
sgdisk -v "$img" 2>&1 | grep -q 'No problems found' || fail "GPT has problems after growing"

# Second boot (if the unit ever ran again): nothing to do, still succeeds.
id_before="$(cat "$sysroot/etc/machine-id")"
AIRLOCK_SYSROOT="$sysroot" AIRLOCK_STATE_DIR="$TEST_TMP/state" run "$fb" --root-source "${dev}p5" --no-disable
assert_eq "$RC" 0 "second run"
assert_contains "$OUT" "already fills the drive"
assert_eq "$(cat "$sysroot/etc/machine-id")" "$id_before" "machine ID kept"

# Not a partition: refused with a clear line.
run "$fb" --root-source "$dev" --skip-machine-id --no-disable
assert_eq "$RC" 1 "whole disk refused"
assert_contains "$OUT" "is not a partition"

# The unit runs once: the done-marker condition and the program path match the role.
unit="$REPO_ROOT/ansible/roles/base/files/airlock-firstboot.service"
assert_contains "$(cat "$unit")" "ConditionPathExists=!/var/lib/airlock/firstboot.done"
assert_contains "$(cat "$unit")" "ExecStart=/opt/airlock/libexec/airlock-firstboot"

pass "first boot"
