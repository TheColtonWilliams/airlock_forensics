#!/usr/bin/env bash
# Task 4.10 (evidence-unlock-output), surviving risk 1 (logging, not enforcement).
# Part 1 runs as root with a fake lsblk tree, fake sysfs, and a stub blockdev: refuses the
# boot disk, partitions, unknown names, and any run without the typed confirmation; unlocks
# with --confirm, writes the rw-allow marker airlock-setro honours, logs model/serial/size;
# --lock undoes it. The harden_storage role's airlock-setro is then run on the same fake sysfs
# (as a udev "change" event would) to show it leaves the unlocked drive writable and locks it
# again after --lock. Part 2 uses a real loop device and the real blockdev.
# shellcheck source=tests/functional/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

require_root
require_cmd python3
export AIRLOCK_PYLIB="$PYLIB"
export AIRLOCK_RUN_DIR="$TEST_TMP/run"
CMD="$BIN_DIR/evidence-unlock-output"
LOG="$AIRLOCK_SESSION_DIR/current.log"

# ---------------------------------------------------------------- part 1: fakes
FS="$TEST_TMP/sys"
SETRO="$REPO_ROOT/ansible/roles/harden_storage/files/airlock-setro"
# Laid out like the kernel's: partitions sit inside their disk's folder and carry a
# "partition" file; class/block holds symlinks (airlock-setro finds the parent disk this way).
mkdir -p "$FS/class/block"
for disk in sda sdb; do
  mkdir -p "$FS/devices/virtual/block/$disk"
  ln -s "../../devices/virtual/block/$disk" "$FS/class/block/$disk"
done
for part in sda/sda1 sdb/sdb1 sdb/sdb2; do
  mkdir -p "$FS/devices/virtual/block/$part"
  echo 1 >"$FS/devices/virtual/block/$part/partition"
  ln -s "../../devices/virtual/block/$part" "$FS/class/block/${part#*/}"
done
for name in sda sda1 sdb sdb1 sdb2; do
  echo 1 >"$FS/class/block/$name/ro"
done
# Identity files, as the kernel has them: diskseq (new on every attach), serial or wwid, size.
echo 7 >"$FS/class/block/sda/diskseq"
echo 9 >"$FS/class/block/sdb/diskseq"
mkdir -p "$FS/class/block/sdb/device"
printf 'OUT123   \n' >"$FS/class/block/sdb/device/serial"
echo 976773168 >"$FS/class/block/sdb/size"
echo 0 >"$FS/class/block/sda/ro"
echo 0 >"$FS/class/block/sda1/ro"
cat >"$TEST_TMP/lsblk.json" <<'JSON'
{"blockdevices": [
  {"name": "sda", "path": "/dev/sda", "type": "disk", "size": 64000000000, "ro": false,
   "rm": true, "tran": "usb", "model": "AIRLOCK STICK", "serial": "BOOT1",
   "children": [{"name": "sda1", "path": "/dev/sda1", "type": "part", "size": 1000,
                 "ro": false, "rm": true, "mountpoints": ["/"]}]},
  {"name": "sdb", "path": "/dev/sdb", "type": "disk", "size": 500107862016, "ro": true,
   "rm": false, "tran": "usb", "model": "Output Disk", "serial": "OUT123",
   "children": [{"name": "sdb1", "path": "/dev/sdb1", "type": "part", "size": 2000, "ro": true,
                 "rm": false, "mountpoints": [null]},
                {"name": "sdb2", "path": "/dev/sdb2", "type": "part", "size": 3000, "ro": true,
                 "rm": false, "mountpoints": [null]}]}
]}
JSON
CALLS="$TEST_TMP/blockdev.calls"
: >"$CALLS"
stub blockdev "
printf '%s\n' \"\$*\" >>'$CALLS'
dev=\"\${2##*/}\"
case \"\$1\" in
  --setrw) echo 0 >'$FS/class/block/'\"\$dev\"/ro ;;
  --setro) echo 1 >'$FS/class/block/'\"\$dev\"/ro ;;
esac"

# shellcheck disable=SC2317 # called through run
fake() { AIRLOCK_SYSFS="$FS" AIRLOCK_LSBLK_JSON="$TEST_TMP/lsblk.json" "$@"; }

# The boot disk is refused, even with a matching confirmation.
run fake "$CMD" /dev/sda --confirm sda
assert_eq "$RC" 1 "boot disk refused"
assert_contains "$OUT" "AIRLOCK drive itself" "boot disk message"
grep -q '"reason":"boot_disk"' "$LOG" || fail "boot disk refusal logged"

# A partition is refused.
run fake "$CMD" /dev/sdb1 --confirm sdb1
assert_eq "$RC" 1 "partition refused"
assert_contains "$OUT" "partition" "partition message"
assert_contains "$OUT" "/dev/sdb" "partition message names the drive"

# An unknown name is refused.
run fake "$CMD" /dev/sdz --confirm sdz
assert_eq "$RC" 1 "unknown drive refused"
assert_contains "$OUT" "no drive called" "unknown drive message"

# No confirmation (no terminal, no --confirm), with and without --yes.
run fake "$CMD" /dev/sdb </dev/null
assert_eq "$RC" 1 "no confirmation refused"
assert_contains "$OUT" "--confirm sdb" "no-confirmation message says what to pass"
assert_contains "$OUT" "WRITABLE" "warning shown"
run fake "$CMD" --yes /dev/sdb </dev/null
assert_eq "$RC" 1 "--yes does not skip the confirmation"
grep -q '"reason":"no_confirmation"' "$LOG" || fail "no-confirmation refusal logged"

# Wrong name typed back.
run fake "$CMD" /dev/sdb --confirm sdc
assert_eq "$RC" 1 "mismatched confirmation refused"
assert_contains "$OUT" "Nothing was changed" "mismatch message"
grep -q '"reason":"confirmation_mismatch"' "$LOG" || fail "mismatch logged"

[[ ! -s "$CALLS" ]] || fail "blockdev ran during a refusal: $(cat "$CALLS")"
for name in sdb sdb1 sdb2; do assert_eq "$(cat "$FS/class/block/$name/ro")" 1 "$name still read-only"; done
assert_no_file "$AIRLOCK_RUN_DIR/rw-allow/sdb" "no marker after refusals"

# Unlock with the confirmation.
run fake "$CMD" /dev/sdb --confirm sdb
assert_eq "$RC" 0 "unlock with --confirm: $OUT"
assert_contains "$OUT" "now writable" "unlock message"
for name in sdb sdb1 sdb2; do
  assert_eq "$(cat "$FS/class/block/$name/ro")" 0 "$name writable"
  grep -qx -- "--setrw /dev/$name" "$CALLS" || fail "blockdev --setrw /dev/$name not run"
done
assert_file "$AIRLOCK_RUN_DIR/rw-allow/sdb" "rw-allow marker for airlock-setro"
last="$(grep '"event":"output_unlocked"' "$LOG" | tail -n 1)"
assert_contains "$last" '"model":"Output Disk"' "model logged"
assert_contains "$last" '"serial":"OUT123"' "serial logged"
assert_contains "$last" '"size_bytes":500107862016' "size logged"
assert_contains "$last" '"confirmed_via":"flag"' "confirmation route logged"
assert_contains "$last" 'not enforcement' "log says logging is not enforcement"

# A later udev "change" event re-runs the software read-only policy on the drive and its
# partitions: with the marker in place, airlock-setro leaves them writable.
# shellcheck disable=SC2317 # called through run
setro() {
  AIRLOCK_SYSFS="$FS" AIRLOCK_RUN_DIR="$AIRLOCK_RUN_DIR" AIRLOCK_SETRO_ROOT_DEV=sda1 \
    AIRLOCK_DEV_DIR=/dev AIRLOCK_LOG_LIB="$REPO_ROOT/ansible/roles/session_tools/files/lib/airlock-log.sh" \
    "$SETRO" "$@"
}
: >"$CALLS"
for name in sdb sdb1 sdb2; do
  run setro "$name"
  assert_eq "$RC" 0 "airlock-setro $name after unlock: $OUT"
done
[[ ! -s "$CALLS" ]] || fail "airlock-setro re-locked the unlocked drive: $(cat "$CALLS")"
for name in sdb sdb1 sdb2; do assert_eq "$(cat "$FS/class/block/$name/ro")" 0 "$name stays writable"; done
grep -q '"decision":"unlocked"' "$LOG" ||
  fail "airlock-setro logged the unlocked decision: $(tail -n 3 "$LOG")"
run setro --check
assert_eq "$RC" 0 "airlock-setro --check accepts the unlocked drive: $OUT"
assert_contains "$OUT" "unlocked sdb1 disk=sdb" "check lists sdb1 as unlocked"
grep -Eq '^  "identity_sha256": "[0-9a-f]{64}",$' "$AIRLOCK_RUN_DIR/rw-allow/sdb" ||
  fail "marker records the drive identity: $(cat "$AIRLOCK_RUN_DIR/rw-allow/sdb")"
# Python (evidence-unlock-output) and bash (airlock-setro) hash the same identity.
py_id="$(AIRLOCK_SYSFS="$FS" python3 -c 'import sys; sys.path.insert(0, sys.argv[1]); from airlock_session import unlock; print(unlock.drive_identity("sdb")[1])' "$PYLIB")"
assert_contains "$(cat "$AIRLOCK_RUN_DIR/rw-allow/sdb")" "$py_id" "marker holds the Python identity"
AIRLOCK_SYSFS="$FS" python3 -c 'import sys; sys.path.insert(0, sys.argv[1]); from airlock_session import unlock; sys.exit(0 if unlock.marker_valid("sdb") else 1)' "$PYLIB" ||
  fail "marker_valid accepts the marker for the drive that wrote it"
cp -- "$AIRLOCK_RUN_DIR/rw-allow/sdb" "$TEST_TMP/marker.sdb"

# The unlocked drive is unplugged without --lock and a different drive is plugged in; the
# kernel gives it the same name. The kernel starts it writable, with a new diskseq and its own
# serial. The leftover marker must not make it writable: airlock-setro sets it read-only and
# deletes the marker (finding: a marker keyed only by kernel name).
for name in sdb sdb1 sdb2; do echo 0 >"$FS/class/block/$name/ro"; done
echo 10 >"$FS/class/block/sdb/diskseq"
echo 'EVID999' >"$FS/class/block/sdb/device/serial"
: >"$CALLS"
for name in sdb sdb1 sdb2; do
  run setro "$name"
  assert_eq "$RC" 0 "airlock-setro $name on the replacement drive: $OUT"
  assert_eq "$(cat "$FS/class/block/$name/ro")" 1 "replacement $name read-only despite the old marker"
  grep -qx -- "--setro /dev/$name" "$CALLS" || fail "blockdev --setro /dev/$name not run"
done
assert_no_file "$AIRLOCK_RUN_DIR/rw-allow/sdb" "stale marker deleted"
grep -q '"event":"ro_policy_marker_removed"' "$LOG" || fail "stale marker removal logged"
grep '"event":"ro_policy_marker_removed"' "$LOG" | tail -n 1 | grep -q '"reason":"identity_mismatch"' ||
  fail "stale marker removal gives the reason"

# Same serial, plugged in again (new diskseq): still read-only. --check does not count a
# stale marker as an unlock either, and leaves the file alone.
echo 'OUT123' >"$FS/class/block/sdb/device/serial"
echo 11 >"$FS/class/block/sdb/diskseq"
cp -- "$TEST_TMP/marker.sdb" "$AIRLOCK_RUN_DIR/rw-allow/sdb"
echo 0 >"$FS/class/block/sdb1/ro"
run setro --check
assert_eq "$RC" 1 "--check fails: the re-plugged drive is writable and its marker is stale"
assert_contains "$OUT" "rw sdb1 disk=sdb" "--check lists sdb1 as writable, not unlocked"
assert_file "$AIRLOCK_RUN_DIR/rw-allow/sdb" "--check changes nothing"
AIRLOCK_SYSFS="$FS" python3 -c 'import sys; sys.path.insert(0, sys.argv[1]); from airlock_session import unlock; sys.exit(1 if unlock.marker_valid("sdb") else 0)' "$PYLIB" ||
  fail "marker_valid rejects a marker written for an earlier attach"
run setro sdb1
assert_eq "$(cat "$FS/class/block/sdb1/ro")" 1 "re-plugged drive read-only"
assert_no_file "$AIRLOCK_RUN_DIR/rw-allow/sdb" "stale marker deleted on the udev event"

# A marker with no identity (older format, or hand-made) is not honoured.
echo '{"device": "/dev/sdb"}' >"$AIRLOCK_RUN_DIR/rw-allow/sdb"
echo 0 >"$FS/class/block/sdb/ro"
run setro sdb
assert_eq "$(cat "$FS/class/block/sdb/ro")" 1 "marker without identity ignored"
assert_no_file "$AIRLOCK_RUN_DIR/rw-allow/sdb" "marker without identity deleted"

# The udev remove rule runs --forget: the marker goes with the drive.
echo '{}' >"$AIRLOCK_RUN_DIR/rw-allow/sdb"
run setro --forget sdb
assert_eq "$RC" 0 "--forget: $OUT"
assert_no_file "$AIRLOCK_RUN_DIR/rw-allow/sdb" "--forget deletes the marker"
grep '"event":"ro_policy_marker_removed"' "$LOG" | tail -n 1 | grep -q '"reason":"removed"' ||
  fail "--forget logged"
run setro --forget ../sdb
assert_eq "$RC" 2 "--forget refuses a path"

# The drive is unlocked again for the rest of the test (new attach, so a new unlock).
for name in sdb sdb1 sdb2; do echo 1 >"$FS/class/block/$name/ro"; done
run fake "$CMD" /dev/sdb --confirm sdb
assert_eq "$RC" 0 "unlock after re-plugging: $OUT"

# A drive that reports no diskseq, wwid, or serial cannot be told apart from the next one.
mv "$FS/class/block/sdb/diskseq" "$TEST_TMP/diskseq.sdb"
mv "$FS/class/block/sdb/device/serial" "$TEST_TMP/serial.sdb"
rm -f "$AIRLOCK_RUN_DIR/rw-allow/sdb"
: >"$CALLS"
run fake "$CMD" /dev/sdb --confirm sdb
assert_eq "$RC" 1 "no drive identity: refused"
assert_contains "$OUT" "no disk sequence number, WWN, or serial" "no-identity message"
assert_no_file "$AIRLOCK_RUN_DIR/rw-allow/sdb" "no marker without an identity"
[[ ! -s "$CALLS" ]] || fail "blockdev ran for a drive with no identity: $(cat "$CALLS")"
grep -q '"reason":"no_drive_identity"' "$LOG" || fail "no-identity refusal logged"
mv "$TEST_TMP/diskseq.sdb" "$FS/class/block/sdb/diskseq"
mv "$TEST_TMP/serial.sdb" "$FS/class/block/sdb/device/serial"

# /dev/sdb typed in full also counts as the name.
: >"$CALLS"
run fake "$CMD" sdb --confirm /dev/sdb
assert_eq "$RC" 0 "kernel name plus full path confirmation: $OUT"

# --lock undoes it.
: >"$CALLS"
run fake "$CMD" /dev/sdb --lock
assert_eq "$RC" 0 "lock: $OUT"
for name in sdb sdb1 sdb2; do assert_eq "$(cat "$FS/class/block/$name/ro")" 1 "$name read-only again"; done
assert_no_file "$AIRLOCK_RUN_DIR/rw-allow/sdb" "marker removed by --lock"
grep -q '"event":"output_locked"' "$LOG" || fail "lock logged"

# Without the marker the next udev event applies the policy again.
for name in sdb sdb1 sdb2; do echo 0 >"$FS/class/block/$name/ro"; done
: >"$CALLS"
run setro sdb1
assert_eq "$RC" 0 "airlock-setro sdb1 after --lock: $OUT"
grep -qx -- "--setro /dev/sdb1" "$CALLS" || fail "airlock-setro did not lock sdb1 after --lock"
assert_eq "$(cat "$FS/class/block/sdb1/ro")" 1 "sdb1 read-only after --lock and a udev event"
for name in sdb sdb2; do echo 1 >"$FS/class/block/$name/ro"; done

# Not root: refused before anything happens.
if command -v setpriv >/dev/null 2>&1; then
  chmod 0777 "$AIRLOCK_SESSION_DIR"
  chmod -R a+rX "$TEST_TMP"
  run setpriv --reuid=65534 --regid=65534 --clear-groups env AIRLOCK_SYSFS="$FS" \
    AIRLOCK_LSBLK_JSON="$TEST_TMP/lsblk.json" "$CMD" /dev/sdb --confirm sdb
  if [[ "$OUT" == *"Permission denied"* && "$OUT" != *"needs root"* ]]; then
    echo "note: non-root check skipped (test tree not readable by nobody)"
  else
    assert_eq "$RC" 1 "non-root refused: $OUT"
    assert_contains "$OUT" "needs root" "non-root message"
  fi
fi

# ---------------------------------------------------------------- part 2: real loop device
if losetup -f >/dev/null 2>&1 && command -v blockdev >/dev/null 2>&1; then
  rm -f -- "$STUB_DIR/blockdev"
  truncate -s 8M "$TEST_TMP/out.img"
  loop="$(losetup --find --show -- "$TEST_TMP/out.img")"
  detach() { losetup -d "$loop" 2>/dev/null || true; }
  on_exit detach
  name="${loop##*/}"
  blockdev --setro "$loop"
  assert_eq "$(blockdev --getro "$loop")" 1 "loop starts read-only (policy)"
  run "$CMD" "$loop" </dev/null
  assert_eq "$RC" 1 "real device: refused without confirmation"
  assert_eq "$(blockdev --getro "$loop")" 1 "real device still read-only"
  run "$CMD" "$loop" --confirm "$name"
  if [[ ! -e "/sys/class/block/$name/diskseq" ]]; then
    # Kernels before 5.15 have no diskseq; a loop device has no serial either.
    assert_eq "$RC" 1 "real device without diskseq refused: $OUT"
    detach
    pass "evidence-unlock-output refuses without confirmation, unlocks one drive, logs it, relocks"
  fi
  assert_eq "$RC" 0 "real device unlocked: $OUT"
  assert_eq "$(blockdev --getro "$loop")" 0 "real device writable"
  grep -Eq '"identity_sha256": "[0-9a-f]{64}"' "$AIRLOCK_RUN_DIR/rw-allow/$name" ||
    fail "real device marker records the identity"
  run "$CMD" "$loop" --lock
  assert_eq "$RC" 0 "real device locked: $OUT"
  assert_eq "$(blockdev --getro "$loop")" 1 "real device read-only again"
  detach
else
  echo "note: part 2 skipped (no free loop device)"
fi

pass "evidence-unlock-output refuses without confirmation, unlocks one drive, logs it, relocks"
