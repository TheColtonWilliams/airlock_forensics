#!/usr/bin/env bash
# Task 4.10 (evidence-unlock-output), surviving risk 1 (logging, not enforcement).
# Part 1 runs as root with a fake lsblk tree, fake sysfs, and a stub blockdev: refuses the
# boot disk, partitions, unknown names, and any run without the typed confirmation; unlocks
# with --confirm, writes the rw-allow marker airlock-setro honours, logs model/serial/size;
# --lock undoes it. Part 2 uses a real loop device and the real blockdev.
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
for name in sda sda1 sdb sdb1 sdb2; do
  mkdir -p "$FS/class/block/$name"
  echo 1 >"$FS/class/block/$name/ro"
done
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
  assert_eq "$RC" 0 "real device unlocked: $OUT"
  assert_eq "$(blockdev --getro "$loop")" 0 "real device writable"
  run "$CMD" "$loop" --lock
  assert_eq "$RC" 0 "real device locked: $OUT"
  assert_eq "$(blockdev --getro "$loop")" 1 "real device read-only again"
  detach
else
  echo "note: part 2 skipped (no free loop device)"
fi

pass "evidence-unlock-output refuses without confirmation, unlocks one drive, logs it, relocks"
