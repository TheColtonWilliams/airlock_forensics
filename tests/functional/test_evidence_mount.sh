#!/usr/bin/env bash
# Tasks 3A.3 and 4.10: evidence-mount mounts image files only, through a kernel read-only loop
# device, with ro,noexec,nosuid,nodev plus noload (ext4) / norecovery (XFS); NTFS through
# ntfs-3g read-only. It warns that mounting exposes kernel parsers, hashes before and after,
# and fails loudly if the image changed. Needs root and loop devices (real mounts).
# shellcheck source=tests/functional/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

require_loop
require_cmd python3 mkfs.ext4 sgdisk sfdisk blkid losetup findmnt
export AIRLOCK_PYLIB="$PYLIB"
CMD="$BIN_DIR/evidence-mount"
LOG="$AIRLOCK_SESSION_DIR/current.log"
MNT="$TEST_TMP/mnt"
mkdir -p "$MNT"

# shellcheck disable=SC2317 # run by on_exit
cleanup_mounts() {
  local mp img
  for mp in "$MNT"/*; do
    if findmnt -n -- "$mp" >/dev/null 2>&1; then umount -l -- "$mp" || true; fi
  done
  for img in "$TEST_TMP"/*.img; do
    [[ -e "$img" ]] || continue
    losetup -j "$img" -O NAME -n 2>/dev/null | while read -r dev; do losetup -d "$dev" || true; done
  done
}
on_exit cleanup_mounts

loops_for() { losetup -j "$1" -O NAME -n 2>/dev/null | grep -c . || true; }
opts_of() { findmnt -n -o OPTIONS -- "$1"; }
fstype_of() { findmnt -n -o FSTYPE -- "$1"; }

# ---------------------------------------------------------------- fixtures (generated text)
mkdir -p "$TEST_TMP/content"
printf 'AIRLOCK test file\n' >"$TEST_TMP/content/hello.txt"
EXT="$TEST_TMP/ext4.img"
truncate -s 16M "$EXT"
mkfs.ext4 -q -F -d "$TEST_TMP/content" -L EVID "$EXT"

# ---------------------------------------------------------------- ext4: whole-image filesystem
before="$(sha256_of "$EXT")"
run "$CMD" "$EXT" "$MNT/ext"
assert_eq "$RC" 0 "mount ext4 image: $OUT"
assert_contains "$OUT" "may be hostile" "kernel parser warning shown"
assert_contains "$OUT" "The Sleuth Kit" "warning points to the safe path"
assert_eq "$(fstype_of "$MNT/ext")" ext4 "ext4 mounted"
o="$(opts_of "$MNT/ext")"
for want in ro nosuid nodev noexec norecovery; do
  [[ ",$o," == *",$want,"* ]] || fail "ext4 option $want missing: $o"
done
assert_eq "$(cat "$MNT/ext/hello.txt")" "AIRLOCK test file" "file readable"
dev="$(findmnt -n -o SOURCE -- "$MNT/ext")"
assert_eq "$(blockdev --getro "$dev")" 1 "loop device is read-only"
if touch "$MNT/ext/new" 2>/dev/null; then fail "a write to the mount succeeded"; fi
grep -q '"event":"evidence_mounted"' "$LOG" || fail "evidence_mounted logged"
assert_contains "$(grep '"event":"evidence_mounted"' "$LOG")" "\"sha256\":\"$before\"" "hash before logged"

run "$CMD" --list
assert_contains "$OUT" "$MNT/ext" "--list shows the mount"

# The same image cannot be mounted twice; a non-empty folder is refused.
run "$CMD" "$EXT" "$MNT/ext2"
assert_eq "$RC" 1 "second mount of the same image refused"
assert_contains "$OUT" "already mounted" "already-mounted message"

run "$CMD" --unmount "$MNT/ext"
assert_eq "$RC" 0 "unmount: $OUT"
assert_contains "$OUT" "SHA-256 unchanged" "unmount re-checks the hash"
findmnt -n -- "$MNT/ext" >/dev/null 2>&1 && fail "still mounted after --unmount"
assert_eq "$(loops_for "$EXT")" 0 "loop device detached"
assert_eq "$(sha256_of "$EXT")" "$before" "ext4 image unchanged"
assert_contains "$(grep '"event":"evidence_unmounted"' "$LOG")" '"unchanged":true' "unmount logged"
assert_no_file "$MNT/ext" "the folder it made is removed"

mkdir -p "$MNT/full"
touch "$MNT/full/x"
run "$CMD" "$EXT" "$MNT/full"
assert_eq "$RC" 1 "non-empty mount folder refused"
assert_contains "$OUT" "not empty" "non-empty message"
assert_eq "$(loops_for "$EXT")" 0 "no loop device left after a refusal"

# ---------------------------------------------------------------- partitioned image (GPT)
DISK="$TEST_TMP/disk.img"
truncate -s 64M "$DISK"
sgdisk -n1:2048:+20M -t1:8300 -n2:0:+20M -t2:0700 "$DISK" >/dev/null
P1="$TEST_TMP/p1.part"
P2="$TEST_TMP/p2.part"
truncate -s 20M "$P1" "$P2"
mkfs.ext4 -q -F -d "$TEST_TMP/content" "$P1"
mkdir -p "$TEST_TMP/content2"
printf 'second partition\n' >"$TEST_TMP/content2/two.txt"
mkfs.ext4 -q -F -d "$TEST_TMP/content2" -L EVIDP2 "$P2"
start2="$(sfdisk -J "$DISK" | python3 -c 'import json,sys; print(json.load(sys.stdin)["partitiontable"]["partitions"][1]["start"])')"
dd if="$P1" of="$DISK" bs=512 seek=2048 conv=notrunc status=none
dd if="$P2" of="$DISK" bs=512 seek="$start2" conv=notrunc status=none
before="$(sha256_of "$DISK")"

run "$CMD" "$DISK" "$MNT/disk"
assert_eq "$RC" 1 "two partitions need --partition"
assert_contains "$OUT" "--partition N" "message asks for --partition"
assert_contains "$OUT" "2 partitions" "message lists the partitions"
assert_eq "$(loops_for "$DISK")" 0 "no loop device left"

run "$CMD" --partition 9 "$DISK" "$MNT/disk"
assert_eq "$RC" 1 "missing partition refused"

run "$CMD" --partition 2 "$DISK" "$MNT/disk"
assert_eq "$RC" 0 "mount partition 2: $OUT"
assert_eq "$(cat "$MNT/disk/two.txt")" "second partition" "partition 2 mounted"
o="$(opts_of "$MNT/disk")"
[[ ",$o," == *",ro,"* && ",$o," == *",noexec,"* ]] || fail "partition 2 options: $o"
run "$CMD" --unmount "$DISK"
assert_eq "$RC" 0 "unmount by image name: $OUT"

run "$CMD" --partition 1 "$DISK" "$MNT/disk1"
assert_eq "$RC" 0 "mount partition 1: $OUT"
assert_eq "$(cat "$MNT/disk1/hello.txt")" "AIRLOCK test file" "partition 1 file readable"
run "$CMD" --unmount "$MNT/disk1"
assert_eq "$RC" 0 "unmount partition 1: $OUT"
assert_eq "$(sha256_of "$DISK")" "$before" "partitioned image unchanged"

# ---------------------------------------------------------------- NTFS through ntfs-3g
if command -v mkfs.ntfs >/dev/null 2>&1 && command -v ntfs-3g >/dev/null 2>&1; then
  NT="$TEST_TMP/ntfs.img"
  truncate -s 16M "$NT"
  mkfs.ntfs -q -F -f "$NT" >/dev/null 2>&1
  before="$(sha256_of "$NT")"
  run "$CMD" "$NT" "$MNT/ntfs"
  assert_eq "$RC" 0 "mount NTFS image: $OUT"
  assert_eq "$(fstype_of "$MNT/ntfs")" fuseblk "NTFS mounted through ntfs-3g"
  o="$(opts_of "$MNT/ntfs")"
  [[ ",$o," == *",ro,"* && ",$o," == *",noexec,"* && ",$o," == *",nodev,"* ]] || fail "ntfs options: $o"
  run "$CMD" --unmount "$MNT/ntfs"
  assert_eq "$RC" 0 "unmount NTFS: $OUT"
  assert_eq "$(sha256_of "$NT")" "$before" "NTFS image unchanged"
else
  echo "note: NTFS part skipped (needs mkfs.ntfs and ntfs-3g)"
fi

# ---------------------------------------------------------------- XFS with norecovery
if command -v mkfs.xfs >/dev/null 2>&1; then
  XF="$TEST_TMP/xfs.img"
  truncate -s 320M "$XF"
  if mkfs.xfs -q -f "$XF" >/dev/null 2>&1; then
    run "$CMD" "$XF" "$MNT/xfs"
    if [[ "$RC" -eq 0 ]]; then
      o="$(opts_of "$MNT/xfs")"
      [[ ",$o," == *",norecovery,"* && ",$o," == *",ro,"* ]] || fail "xfs options: $o"
      run "$CMD" --unmount "$MNT/xfs"
      assert_eq "$RC" 0 "unmount XFS: $OUT"
    elif [[ "$OUT" == *"unknown filesystem type"* || "$OUT" == *"wrong fs type"* ]]; then
      echo "note: XFS part skipped (kernel has no XFS driver)"
    else
      fail "mount XFS image: $OUT"
    fi
  fi
fi

# ---------------------------------------------------------------- refusals
loop="$(losetup --read-only --find --show -- "$EXT")"
run "$CMD" "$loop" "$MNT/dev"
losetup -d "$loop"
assert_eq "$RC" 1 "a block device is refused"
assert_contains "$OUT" "image files only" "block device message"
assert_no_file "$MNT/dev" "no folder made for a refused device"

run "$CMD" /dev/null "$MNT/null"
assert_eq "$RC" 1 "a character device is refused"

E01="$TEST_TMP/case.E01"
printf 'EVF\x09\x0d\x0a\xff\x00rest-of-header' >"$E01"
run "$CMD" "$E01" "$MNT/e01"
assert_eq "$RC" 1 "E01 refused"
assert_contains "$OUT" "ewfmount" "E01 message names ewfmount"

BLANK="$TEST_TMP/blank.img"
truncate -s 4M "$BLANK"
run "$CMD" "$BLANK" "$MNT/blank"
assert_eq "$RC" 1 "an image with no filesystem is refused"
assert_contains "$OUT" "no filesystem" "no-filesystem message"

# ---------------------------------------------------------------- a changed image fails loudly
before="$(sha256_of "$EXT")"
run "$CMD" "$EXT" "$MNT/changed"
assert_eq "$RC" 0 "mount for the change test: $OUT"
# Change the backing file behind the read-only loop (as another program could).
printf 'X' | dd of="$EXT" bs=1 seek=$((15 * 1024 * 1024)) conv=notrunc status=none
run "$CMD" --unmount "$MNT/changed"
assert_eq "$RC" 1 "a changed image fails the unmount check"
assert_contains "$OUT" "THE IMAGE CHANGED" "loud banner"
grep -q '"event":"image_changed"' "$LOG" || fail "image_changed logged"
findmnt -n -- "$MNT/changed" >/dev/null 2>&1 && fail "still mounted after the failed check"
assert_eq "$(loops_for "$EXT")" 0 "loop detached after the failed check"

pass "evidence-mount: images only, read-only loop, safe options, hashes checked, refusals"
