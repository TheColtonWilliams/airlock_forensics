#!/usr/bin/env bash
# airlock-partition-layout (tasks 2B.9, 2B.17) on a real loop disk: names and types the
# five partitions, makes ASSETS and OUTPUT exFAT once, is idempotent, refuses any disk
# that does not hold the root device, and never reformats a partition that has data.
# shellcheck source=tests/functional/lib.sh
. "$(dirname "$0")/lib.sh"
# shellcheck source=tests/vm/lib/disks.sh
. "$REPO_ROOT/tests/vm/lib/disks.sh"
require_loop
require_cmd sgdisk partx blkid mkfs.ext4 mkfs.vfat mkfs.exfat python3

helper=(python3 "$REPO_ROOT/ansible/roles/base/files/airlock_partition_layout.py")
img="$TEST_TMP/disk.raw"
airlock_mini_layout_disk "$img" 128 plain
dev="$(airlock_loop_attach "$img")" || fail "could not attach $img"
# shellcheck disable=SC2317 # run by on_exit
detach() { airlock_loop_detach "$dev"; }
on_exit detach
mkfs.vfat -n EFI "${dev}p2" >/dev/null
mkfs.ext4 -q -F -L AIRLOCK_ROOT "${dev}p5"
root_uuid="$(blkid -p -s UUID -o value "${dev}p5")"

# Fresh install state: wrong types, no names, no exFAT. --check reports it, changes nothing.
run "${helper[@]}" --root-source "${dev}p5" --check --json
assert_eq "$RC" 1 "check on the installer layout"
assert_contains "$OUT" "partition 3 (ASSETS) has no filesystem"
assert_contains "$OUT" "expected 'BIOSBOOT'"
assert_eq "$(sgdisk -i 3 "$img" | grep -c 'EBD0A0A2')" 0 "--check changed nothing"

# Image build: fix names and types, make exFAT.
run "${helper[@]}" --root-source "${dev}p5" --format-empty --json
assert_eq "$RC" 0 "format-empty: $OUT"
json="$(printf '%s\n' "$OUT" | grep '^{')"
assert_eq "$(jq -r .changed <<<"$json")" true "first run changes the disk"
assert_eq "$(jq -r '[.partitions[].name] | join(",")' <<<"$json")" "BIOSBOOT,EFI,ASSETS,OUTPUT,AIRLOCK_ROOT"
assert_eq "$(jq -r '[.partitions[].fstype] | join(",")' <<<"$json")" ",vfat,exfat,exfat,ext4"
assert_eq "$(jq -r '.partitions[2].label + "," + .partitions[3].label' <<<"$json")" "ASSETS,OUTPUT"
assert_eq "$(sgdisk -i 3 "$img" | grep -c 'EBD0A0A2-B9E5-4433-87C0-68B6B72699C7')" 1 "ASSETS is basic data"
assert_eq "$(sgdisk -i 4 "$img" | grep -c 'EBD0A0A2-B9E5-4433-87C0-68B6B72699C7')" 1 "OUTPUT is basic data"
assert_eq "$(blkid -p -s TYPE -o value "${dev}p3")" exfat
assert_eq "$(blkid -p -s LABEL -o value "${dev}p4")" OUTPUT
assert_eq "$(blkid -p -s UUID -o value "${dev}p5")" "$root_uuid" "root filesystem untouched"
assets_uuid="$(blkid -p -s UUID -o value "${dev}p3")"

# Idempotent, and --check now passes.
run "${helper[@]}" --root-source "${dev}p5" --format-empty --json
assert_eq "$RC" 0 "second run"
assert_eq "$(printf '%s\n' "$OUT" | grep '^{' | jq -r .changed)" false "second run changes nothing"
assert_eq "$(blkid -p -s UUID -o value "${dev}p3")" "$assets_uuid" "ASSETS not reformatted"
run "${helper[@]}" --root-source "${dev}p5" --check
assert_eq "$RC" 0 "check after the fix"

# Refusals: a disk that does not hold root, and root that is not partition 5.
run "${helper[@]}" --root-source "${dev}p5" --disk /dev/null --check
assert_eq "$RC" 1 "other disk refused"
assert_contains "$OUT" "does not hold the root filesystem"
run "${helper[@]}" --root-source "${dev}p4" --check
assert_eq "$RC" 1 "root on another partition refused"
assert_contains "$OUT" "is not partition 5"

# A partition holding another filesystem is reported and never reformatted.
mkfs.ext4 -q -F "${dev}p4"
other_uuid="$(blkid -p -s UUID -o value "${dev}p4")"
run "${helper[@]}" --root-source "${dev}p5" --format-empty
assert_eq "$RC" 1 "foreign filesystem reported"
assert_contains "$OUT" "holds ext4, expected exfat"
assert_eq "$(blkid -p -s UUID -o value "${dev}p4")" "$other_uuid" "foreign filesystem left alone"

pass "drive layout helper"
