#!/usr/bin/env bash
# Task 3.2 / 3A.10: the software read-only policy helper (airlock-setro) and its udev rule.
# Part 1 runs anywhere: a fake sysfs tree and a stub blockdev.
# Part 2 needs root and loop devices: real loop devices get the kernel read-only flag and a
# dd write to the "evidence" loop fails while the "boot" loop stays writable.
# shellcheck source=tests/functional/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

ROLE="$REPO_ROOT/ansible/roles/harden_storage/files"
HELPER="$ROLE/airlock-setro"
RULE="$ROLE/00-forensic-ro.rules"
assert_file "$HELPER"
assert_file "$RULE"
# The rule is numbered 00 so its RUN entry is queued before any package rule's (69-bcache.rules'
# bcache-register, for example). No late 99- copy may be left beside it.
assert_no_file "$ROLE/99-forensic-ro.rules" "no 99- copy of the read-only rule"

export AIRLOCK_PYLIB="$PYLIB"
export AIRLOCK_LOG_LIB="$REPO_ROOT/ansible/roles/session_tools/files/lib/airlock-log.sh"
export AIRLOCK_RUN_DIR="$TEST_TMP/run"
LOG="$AIRLOCK_SESSION_DIR/current.log"

# ------------------------------------------------------------------ the udev rule
rule_line="$(grep -v '^[[:space:]]*#' "$RULE" | grep -v '^[[:space:]]*$')"
assert_contains "$rule_line" 'SUBSYSTEM=="block"' "rule matches block devices"
assert_contains "$rule_line" 'KERNEL=="sd*|nvme*|mmcblk*|vd*"' "rule matches every disk family"
assert_contains "$rule_line" 'ACTION=="add|change"' "rule runs on add and change"
assert_contains "$rule_line" 'RUN+="/usr/local/sbin/airlock-setro %k"' "rule calls the helper with the kernel name"
forget_line="$(grep '^ACTION=="remove"' "$RULE")"
assert_contains "$forget_line" 'ENV{DEVTYPE}=="disk"' "remove rule matches whole disks"
assert_contains "$forget_line" 'RUN+="/usr/local/sbin/airlock-setro --forget %k"' "remove rule deletes the unlock marker"
if grep -qi 'write.blocker' "$RULE" && ! grep -qi 'not a write blocker' "$RULE"; then
  fail "the rule file calls the policy a write blocker"
fi
if command -v udevadm >/dev/null 2>&1 && udevadm verify --help >/dev/null 2>&1; then
  run udevadm verify --resolve-names=never "$RULE"
  assert_eq "$RC" 0 "udevadm verify: $OUT"
fi

# ------------------------------------------------------------------ part 1: fake sysfs
FS="$TEST_TMP/sys"
export AIRLOCK_SYSFS="$FS"
export AIRLOCK_DEV_DIR="$TEST_TMP/dev"
mkdir -p "$FS/class/block" "$FS/dev/block" "$AIRLOCK_DEV_DIR"

# mkdev PARENT_PATH NAME MAJ:MIN [partition]
mkdev() {
  local parent="$1" name="$2" majmin="$3" part="${4:-}" dir
  dir="$FS/devices/$parent/$name"
  mkdir -p "$dir/slaves" "$dir/holders"
  echo 0 >"$dir/ro"
  echo "$majmin" >"$dir/dev"
  [[ -n "$part" ]] && echo "$part" >"$dir/partition"
  ln -s "../../devices/$parent/$name" "$FS/class/block/$name"
  ln -s "../../devices/$parent/$name" "$FS/dev/block/$majmin"
}
mkdev pci0/host0/block sda 8:0
mkdev pci0/host0/block/sda sda1 8:1 1
mkdev pci0/host0/block/sda sda5 8:5 5
mkdev pci0/host1/block sdb 8:16
mkdev pci0/host1/block/sdb sdb1 8:17 1
mkdev pci0/host2/block sdc 8:32
mkdev pci0/host2/block/sdc sdc1 8:33 1
mkdev pci0/nvme/nvme0/block nvme0n1 259:0
mkdev pci0/nvme/nvme0/block/nvme0n1 nvme0n1p1 259:1 1
mkdev pci0/mmc/block mmcblk0 179:0
mkdev pci0/virtio/block vdb 254:16
mkdev virtual/block loop0 7:0
mkdev virtual/block dm-0 252:0
ln -s ../../../../pci0/host0/block/sda/sda5 "$FS/devices/virtual/block/dm-0/slaves/sda5"

# Stub blockdev: records calls and sets the fake ro flag; fails for any device named in FAIL_SETRO.
BLOCKDEV_LOG="$TEST_TMP/blockdev.calls"
stub blockdev "
printf '%s\n' \"\$*\" >>'$BLOCKDEV_LOG'
dev=\"\${2##*/}\"
if [[ \" \${FAIL_SETRO:-} \" == *\" \$dev \"* ]]; then echo 'BLKROSET: Permission denied' >&2; exit 1; fi
[[ \"\$1\" == --setro ]] && echo 1 >'$FS/class/block/'\"\$dev\"/ro
exit 0"
export AIRLOCK_BLOCKDEV="$STUB_DIR/blockdev"

ro_of() { cat "$FS/class/block/$1/ro"; }
reset_ro() {
  local p
  for p in "$FS"/class/block/*; do echo 0 >"$p/ro"; done
  : >"$BLOCKDEV_LOG"
}
last_log() { tail -n 1 "$LOG"; }
log_field() { # log_field JSON KEY
  python3 -c 'import json,sys; print(json.loads(sys.argv[1]).get(sys.argv[2], ""))' "$1" "$2"
}

# 1. With / on sda5, a partition on another disk becomes read-only.
export AIRLOCK_SETRO_ROOT_DEV=sda5
reset_ro
run "$HELPER" sdb1
assert_eq "$RC" 0 "setro sdb1 exit: $OUT"
assert_eq "$(ro_of sdb1)" 1 "sdb1 read-only"
assert_eq "$(cat "$BLOCKDEV_LOG")" "--setro $AIRLOCK_DEV_DIR/sdb1" "blockdev called once on sdb1"
line="$(last_log)"
assert_eq "$(log_field "$line" event)" ro_policy "log event"
assert_eq "$(log_field "$line" tool)" airlock-setro "log tool"
assert_eq "$(log_field "$line" decision)" readonly "log decision"
assert_eq "$(log_field "$line" disk)" sdb "log disk"
assert_eq "$(log_field "$line" ro)" 1 "log ro flag"
assert_eq "$(log_field "$line" boot_disk)" sda "log boot disk"

# 2. Every device on the boot disk is left writable (whole disk and each partition).
for dev in sda sda1 sda5; do
  reset_ro
  run "$HELPER" "$dev"
  assert_eq "$RC" 0 "setro $dev exit: $OUT"
  assert_eq "$(ro_of "$dev")" 0 "$dev stays writable"
  assert_eq "$(cat "$BLOCKDEV_LOG")" "" "blockdev not called for $dev"
  assert_eq "$(log_field "$(last_log)" decision)" exempt_boot_disk "$dev decision"
done

# 3. NVMe, MMC, and virtio disks are covered too.
reset_ro
for dev in nvme0n1 nvme0n1p1 mmcblk0 vdb; do
  run "$HELPER" "$dev"
  assert_eq "$RC" 0 "setro $dev exit: $OUT"
  assert_eq "$(ro_of "$dev")" 1 "$dev read-only"
done

# 4. --check reports writable devices and fails; --all fixes them; loop devices are not in scope.
reset_ro
run "$HELPER" --check
assert_eq "$RC" 1 "--check fails while devices are writable"
assert_contains "$OUT" "rw sdb1 disk=sdb" "--check lists sdb1 as writable"
assert_contains "$OUT" "exempt sda5 disk=sda" "--check lists the boot disk as exempt"
assert_not_contains "$OUT" "loop0" "--check ignores loop devices"
run "$HELPER" --all
assert_eq "$RC" 0 "--all exit: $OUT"
for dev in sdb sdb1 sdc sdc1 nvme0n1 nvme0n1p1 mmcblk0 vdb; do
  assert_eq "$(ro_of "$dev")" 1 "--all set $dev read-only"
done
for dev in sda sda1 sda5 loop0 dm-0; do
  assert_eq "$(ro_of "$dev")" 0 "--all left $dev alone"
done
run "$HELPER" --check
assert_eq "$RC" 0 "--check passes after --all: $OUT"
assert_contains "$OUT" "boot_disk=sda devices=" "--check summary"

# 5. Root on device-mapper (LVM, LUKS): the disks under it are found through slaves/.
export AIRLOCK_SETRO_ROOT_DEV=dm-0
reset_ro
run "$HELPER" sda1
assert_eq "$RC" 0 "dm root: $OUT"
assert_eq "$(ro_of sda1)" 0 "dm root: sda1 on the boot disk stays writable"
run "$HELPER" sdb
assert_eq "$(ro_of sdb)" 1 "dm root: sdb read-only"

# 6. Root found from findmnt MAJ:MIN with no override (the real code path).
unset AIRLOCK_SETRO_ROOT_DEV
stub findmnt 'case "$*" in *MAJ:MIN*) echo " 8:5";; *) echo /dev/sda5;; esac'
reset_ro
run "$HELPER" sda1
assert_eq "$(ro_of sda1)" 0 "findmnt root: sda1 stays writable"
run "$HELPER" sdc1
assert_eq "$(ro_of sdc1)" 1 "findmnt root: sdc1 read-only"

# 7. Root disk cannot be worked out: fail closed, every device read-only, logged.
stub findmnt 'exit 1'
reset_ro
run "$HELPER" sda1
assert_eq "$RC" 0 "fail closed: $OUT"
assert_eq "$(ro_of sda1)" 1 "fail closed: sda1 read-only"
python3 -c 'import json,sys; sys.exit(0 if any(json.loads(l).get("event") == "ro_policy_boot_disk_unknown" for l in open(sys.argv[1])) else 1)' "$LOG" \
  || fail "fail closed was not logged"

# 8. / not on a block device (overlay root): no exemptions.
export AIRLOCK_SETRO_ROOT_DEV=none
reset_ro
run "$HELPER" sda5
assert_eq "$(ro_of sda5)" 1 "no boot disk: sda5 read-only"
assert_eq "$(log_field "$(last_log)" boot_disk)" none "no boot disk logged"

# 9. A disk unlocked by evidence-unlock-output (marker in /run/airlock/rw-allow) is left alone
# while the marker's identity matches the drive now called sdc.
export AIRLOCK_SETRO_ROOT_DEV=sda5
mkdir -p "$AIRLOCK_RUN_DIR/rw-allow" "$FS/class/block/sdc/device"
echo 21 >"$FS/class/block/sdc/diskseq"
echo 'naa.5000c500a1b2c3d4' >"$FS/class/block/sdc/device/wwid"
echo 'OUTPUT-SERIAL-1' >"$FS/class/block/sdc/device/serial"
echo 1953525168 >"$FS/class/block/sdc/size"
# write_marker DISK: the marker evidence-unlock-output writes (its own identity code).
write_marker() {
  python3 - "$PYLIB" "$1" "$AIRLOCK_RUN_DIR/rw-allow/$1" <<'PY_MARKER'
import sys

sys.path.insert(0, sys.argv[1])
from airlock_common import jsonio
from airlock_session import unlock

fields, identity = unlock.drive_identity(sys.argv[2])
assert identity, "fake disk has no identity"
jsonio.dump_json(sys.argv[3], {"identity_sha256": identity, "drive_identity": fields})
PY_MARKER
}
write_marker sdc
reset_ro
run "$HELPER" sdc1
assert_eq "$RC" 0 "unlocked: $OUT"
assert_eq "$(ro_of sdc1)" 0 "unlocked disk stays writable"
assert_eq "$(log_field "$(last_log)" decision)" unlocked "unlocked decision logged"
run "$HELPER" --check
assert_contains "$OUT" "unlocked sdc1 disk=sdc" "--check reports unlocked"
# A marker named after a partition never counts (evidence-unlock-output only unlocks disks).
mv "$AIRLOCK_RUN_DIR/rw-allow/sdc" "$AIRLOCK_RUN_DIR/rw-allow/sdc1"
reset_ro
run "$HELPER" sdc1
assert_eq "$(ro_of sdc1)" 1 "partition-named marker ignored"
rm -f "$AIRLOCK_RUN_DIR/rw-allow/sdc1"

# 9b. sdc is unplugged without --lock (no remove event seen) and another drive is plugged in
# and named sdc. Different serial, new diskseq: the leftover marker is ignored and deleted and
# the new drive is read-only.
write_marker sdc
reset_ro
echo 22 >"$FS/class/block/sdc/diskseq"
echo 'naa.5000c500ffffffff' >"$FS/class/block/sdc/device/wwid"
echo 'EVIDENCE-SERIAL-2' >"$FS/class/block/sdc/device/serial"
run "$HELPER" sdc
assert_eq "$RC" 0 "replacement sdc: $OUT"
assert_eq "$(ro_of sdc)" 1 "replacement drive under the old name is read-only"
assert_no_file "$AIRLOCK_RUN_DIR/rw-allow/sdc" "stale marker deleted"
python3 -c 'import json,sys; sys.exit(0 if any(json.loads(l).get("event") == "ro_policy_marker_removed" and json.loads(l).get("reason") == "identity_mismatch" for l in open(sys.argv[1])) else 1)' "$LOG" \
  || fail "stale marker removal was not logged"
run "$HELPER" sdc1
assert_eq "$(ro_of sdc1)" 1 "replacement partition read-only"
run "$HELPER" --check
assert_contains "$OUT" "ro sdc1 disk=sdc" "--check: replacement partition read-only"
assert_not_contains "$OUT" "unlocked sdc" "--check: replacement not reported as unlocked"

# 9c. The same drive plugged in again gets a new diskseq: read-only too.
write_marker sdc
reset_ro
echo 23 >"$FS/class/block/sdc/diskseq"
run "$HELPER" sdc1
assert_eq "$(ro_of sdc1)" 1 "re-plugged drive (new diskseq) read-only"

# 9d. A marker with no identity, an unreadable one, or a symlink is not honoured.
for bad in '{}' '{"identity_sha256": "short"}'; do
  printf '%s\n' "$bad" >"$AIRLOCK_RUN_DIR/rw-allow/sdc"
  reset_ro
  run "$HELPER" sdc
  assert_eq "$(ro_of sdc)" 1 "marker '$bad' ignored"
  assert_no_file "$AIRLOCK_RUN_DIR/rw-allow/sdc" "marker '$bad' deleted"
done
write_marker sdc
mv "$AIRLOCK_RUN_DIR/rw-allow/sdc" "$TEST_TMP/real-marker"
ln -s "$TEST_TMP/real-marker" "$AIRLOCK_RUN_DIR/rw-allow/sdc"
reset_ro
run "$HELPER" sdc
assert_eq "$(ro_of sdc)" 1 "symlinked marker ignored"

# 9e. A disk with no diskseq, wwid, or serial never matches a marker.
write_marker sdc
mv "$FS/class/block/sdc/diskseq" "$TEST_TMP/sdc.diskseq"
mv "$FS/class/block/sdc/device" "$TEST_TMP/sdc.device"
reset_ro
run "$HELPER" sdc
assert_eq "$(ro_of sdc)" 1 "disk without identity read-only despite a marker"
mv "$TEST_TMP/sdc.diskseq" "$FS/class/block/sdc/diskseq"
mv "$TEST_TMP/sdc.device" "$FS/class/block/sdc/device"

# 9f. --forget (the udev remove rule) deletes the marker of a disk that went away.
write_marker sdc
run "$HELPER" --forget sdc
assert_eq "$RC" 0 "--forget: $OUT"
assert_no_file "$AIRLOCK_RUN_DIR/rw-allow/sdc" "--forget deleted the marker"
run "$HELPER" --forget sdc
assert_eq "$RC" 0 "--forget with no marker is fine"
run "$HELPER" --forget ../x
assert_eq "$RC" 2 "--forget refuses a path"

# 10. blockdev failure: non-zero exit, one line saying what failed, logged.
reset_ro
FAIL_SETRO="sdb1" run "$HELPER" sdb1
assert_eq "$RC" 1 "setro failure exit"
assert_contains "$OUT" "could not set $AIRLOCK_DEV_DIR/sdb1 read-only" "failure message"
assert_eq "$(log_field "$(last_log)" decision)" setro_failed "failure logged"

# 11. Bad input.
run "$HELPER" ../sda
assert_eq "$RC" 2 "path-like name refused"
run "$HELPER" sdz9
assert_eq "$RC" 1 "missing device refused"
assert_contains "$OUT" "no block device named 'sdz9'" "missing device message"
run "$HELPER"
assert_eq "$RC" 2 "no argument refused"
run "$HELPER" --bogus
assert_eq "$RC" 2 "unknown option refused"

# 12. Logging falls back to the journal or stderr when the session log is not available.
reset_ro
AIRLOCK_LOG_LIB="$TEST_TMP/missing.sh" AIRLOCK_PYLIB="$TEST_TMP/nopylib" AIRLOCK_OPT_DIR="$TEST_TMP/noopt" \
  run "$HELPER" sdb
assert_eq "$RC" 0 "no session log still applies the policy: $OUT"
assert_eq "$(ro_of sdb)" 1 "no session log: sdb read-only"

echo "part 1 (fake sysfs): ok"

# ------------------------------------------------------------------ part 2: real loop devices
LOOP_BOOT=""
LOOP_EVID=""
REAL_BLOCKDEV="$(PATH="${PATH#"$STUB_DIR:"}" command -v blockdev || true)"
# shellcheck disable=SC2317 # called from the EXIT trap through on_exit
cleanup_loops() {
  if [[ -n "$LOOP_EVID" ]]; then "$REAL_BLOCKDEV" --setrw "$LOOP_EVID" 2>/dev/null || true; fi
  if [[ -n "$LOOP_BOOT" ]]; then losetup -d "$LOOP_BOOT" 2>/dev/null || true; fi
  if [[ -n "$LOOP_EVID" ]]; then losetup -d "$LOOP_EVID" 2>/dev/null || true; fi
}

part2() {
  if [[ "$(id -u)" -ne 0 ]]; then echo "part 2 skipped: needs root"; return 0; fi
  if ! losetup -f >/dev/null 2>&1; then echo "part 2 skipped: no free loop device"; return 0; fi
  local boot_img="$TEST_TMP/boot.img" evid_img="$TEST_TMP/evidence.img" bootdev evidev
  local bname ename before after sys_path
  truncate -s 16M "$boot_img" "$evid_img"
  head -c 65536 /dev/urandom >"$TEST_TMP/pattern"
  dd if="$TEST_TMP/pattern" of="$evid_img" conv=notrunc status=none
  on_exit cleanup_loops
  bootdev="$(losetup -f --show "$boot_img")"
  LOOP_BOOT="$bootdev"
  evidev="$(losetup -f --show "$evid_img")"
  LOOP_EVID="$evidev"
  # The stub blockdev from part 1 is first on PATH; part 2 uses the real one.
  sys_path="${PATH#"$STUB_DIR:"}"
  # A loop device keeps a read-only flag from an earlier run after detach; start both writable.
  PATH="$sys_path" blockdev --setrw "$bootdev"
  PATH="$sys_path" blockdev --setrw "$evidev"
  [[ -n "$REAL_BLOCKDEV" ]] || fail "real: blockdev not found"
  bname="${bootdev##*/}"
  ename="${evidev##*/}"

  # Real sysfs, real blockdev, real device nodes; only the root device is pinned so the test
  # never touches any disk but its own two loop devices.
  env -u AIRLOCK_SYSFS -u AIRLOCK_DEV_DIR -u AIRLOCK_BLOCKDEV \
    AIRLOCK_SETRO_ROOT_DEV="$bname" PATH="$sys_path" "$HELPER" "$bname" \
    || fail "real: helper failed on the boot loop"
  before="$(sha256sum <"$evidev" | cut -d' ' -f1)"
  env -u AIRLOCK_SYSFS -u AIRLOCK_DEV_DIR -u AIRLOCK_BLOCKDEV \
    AIRLOCK_SETRO_ROOT_DEV="$bname" PATH="$sys_path" "$HELPER" "$ename" \
    || fail "real: helper failed on the evidence loop"

  assert_eq "$("$REAL_BLOCKDEV" --getro "$evidev")" 1 "real: evidence loop read-only"
  assert_eq "$("$REAL_BLOCKDEV" --getro "$bootdev")" 0 "real: boot loop stays writable"
  if dd if=/dev/zero of="$evidev" bs=4096 count=1 oflag=direct conv=notrunc status=none 2>/dev/null; then
    fail "real: dd wrote to the read-only evidence loop"
  fi
  after="$(sha256sum <"$evidev" | cut -d' ' -f1)"
  assert_eq "$after" "$before" "real: evidence hash unchanged"
  dd if=/dev/zero of="$bootdev" bs=4096 count=1 oflag=direct conv=notrunc status=none \
    || fail "real: the boot loop should stay writable"
  echo "part 2 (real loop devices): ok"
}
part2

pass "airlock-setro and 00-forensic-ro.rules"
