#!/usr/bin/env bash
# Functional test for scripts/flash.sh (tasks 2.1 to 2.5, 4G.3).
#
# lsblk, findmnt and blockdev are stubbed through PATH and the targets are regular files
# (AIRLOCK_FLASH_TEST=1), so no real drive is touched. Every refusal must exit 3, print one
# line saying why, and leave the target byte-identical. The good paths must write the image
# (raw and zstd), leave the bytes after it alone, and verify the read-back; a corrupted
# read-back must fail.
# shellcheck source=tests/functional/lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

require_cmd python3 zstd sha256sum dd od stat

FLASH="$REPO_ROOT/scripts/flash.sh"
FX="$TEST_TMP/fx"
DEV="$TEST_TMP/dev"
IMG="$TEST_TMP/img"
mkdir -p "$FX" "$DEV" "$IMG"
export FX
export AIRLOCK_FLASH_TEST=1
MIB=$((1024 * 1024))

# ---------------------------------------------------------------------------- stubs
# shellcheck disable=SC2016 # stub bodies expand when the stub runs
stub lsblk '
args=" $* "
if [[ "$args" == *" -s "* ]]; then cat "$FX/root.json"; exit 0; fi
if [[ "$args" == *" -d "* ]]; then cat "$FX/disks.json"; exit 0; fi
dev="${*: -1}"
n="$(basename "$dev")"
if [[ -f "$FX/tree-$n.json" ]]; then
  cat "$FX/tree-$n.json"
else
  printf "{\"blockdevices\":[{\"name\":\"%s\",\"type\":\"disk\",\"mountpoints\":[null]}]}\n" "$n"
fi'
# shellcheck disable=SC2016 # stub bodies expand when the stub runs
stub findmnt '
case " $* " in
  *" SOURCE --target / "*) echo /dev/sda2 ;;
  *" MAJ:MIN --target / "*) echo 8:2 ;;
  *" -rn -o SOURCE "*) cat "$FX/mounts.txt" ;;
  *) exit 1 ;;
esac'
# shellcheck disable=SC2016 # stub bodies expand when the stub runs
stub blockdev '
case "$1" in
  --flushbufs) exit 0 ;;
  *) echo "blockdev stub: unexpected $*" >&2; exit 1 ;;
esac'

# Drives. sdr is a removable USB drive that holds the running system (booted from USB).
disk() { # name rm hotplug tran size model serial
  printf '{"name":"%s","model":"%s","size":%s,"rm":%s,"hotplug":%s,"tran":"%s","serial":"%s","type":"disk"}' \
    "$1" "$6" "$5" "$2" "$3" "$4" "$7"
}
{
  printf '{"blockdevices":['
  disk sda false false sata 500107862016 "Internal SSD" INT0001
  printf ','
  disk sdb false false sata 2000398934016 "Internal HDD" INT0002
  printf ','
  printf '{"name":"mmcblk0","model":null,"size":64021856256,"rm":false,"hotplug":true,"tran":null,"serial":null,"type":"disk"}'
  printf ','
  disk sdr true true usb 64021856256 "Live USB" LIVE01
  printf ','
  disk sdx true true usb $((8 * MIB)) "Test Stick" STICK01
  printf ','
  disk sdu false true usb $((8 * MIB)) "USB SSD" SSD01
  printf ','
  disk sdm true true usb $((8 * MIB)) "Mounted Stick" MNT01
  printf ','
  disk sdf true true usb $((8 * MIB)) "Kernel Mounted" KMNT01
  printf ','
  disk sdh true true usb $((8 * MIB)) "LVM Stick" LVM01
  printf ','
  disk sdt true true usb $((2 * MIB)) "Tiny Stick" TINY01
  printf ','
  disk sdw true true usb $((8 * MIB)) "Weird\tModel" WEIRD01
  printf ','
  printf '{"name":"sdn","model":null,"size":%s,"rm":"1","hotplug":"0","tran":null,"serial":null,"type":"disk"}' $((8 * MIB))
  printf ']}\n'
} >"$FX/disks.json"
cat >"$FX/root.json" <<'EOF'
{"blockdevices":[{"name":"sdr2","type":"part","children":[{"name":"sdr","type":"disk"}]}]}
EOF
cat >"$FX/tree-sdm.json" <<'EOF'
{"blockdevices":[{"name":"sdm","type":"disk","mountpoints":[null],"children":[
 {"name":"sdm1","type":"part","mountpoints":["/media/analyst/STICK"]}]}]}
EOF
cat >"$FX/tree-sdh.json" <<'EOF'
{"blockdevices":[{"name":"sdh","type":"disk","mountpoints":[null],"children":[
 {"name":"sdh1","type":"part","mountpoints":[null],"children":[
  {"name":"vg-data","type":"lvm","mountpoints":[null]}]}]}]}
EOF
printf '/dev/sda2\n/dev/sdf1\n/dev/sdx10x\n' >"$FX/mounts.txt"

# Targets: regular files full of random bytes.
for n in sda sdb mmcblk0 sdr sdx sdu sdm sdf sdh sdw sdn; do
  head -c $((8 * MIB)) /dev/urandom >"$DEV/$n"
done
head -c $((2 * MIB)) /dev/urandom >"$DEV/sdt"

# Image: 4 MiB raw, its zstd archive, SHA256SUMS with both.
head -c $((4 * MIB)) /dev/urandom >"$IMG/airlock-test.raw"
zstd -q -T0 -3 --long=27 "$IMG/airlock-test.raw" -o "$IMG/airlock-test.raw.zst"
(cd "$IMG" && sha256sum airlock-test.raw airlock-test.raw.zst >SHA256SUMS)
RAW_SHA="$(sha256_of "$IMG/airlock-test.raw")"

# expect_refusal LABEL EXPECTED-TEXT TARGET-FILE ARGS...: exit 3, one refusal line, target unchanged.
expect_refusal() {
  local label="$1" want="$2" tgt="$3" before size_before lines
  shift 3
  before="$(sha256_of "$tgt")"
  size_before="$(stat -c %s "$tgt")"
  run "$FLASH" "$@"
  [[ "$RC" -eq 3 ]] || fail "$label: expected refusal (exit 3), got exit $RC: $OUT"
  assert_contains "$OUT" "$want" "$label"
  lines="$(grep -c 'refused:' <<<"$OUT" || true)"
  assert_eq "$lines" "1" "$label: refusal lines"
  assert_eq "$(sha256_of "$tgt")" "$before" "$label: target content changed"
  assert_eq "$(stat -c %s "$tgt")" "$size_before" "$label: target size changed"
  echo "ok: refused $label"
}

# ---------------------------------------------------------------------------- --list
run "$FLASH" --list
assert_eq "$RC" "0" "--list exit"
assert_contains "$OUT" "/dev/sdx" "--list shows the USB stick"
assert_contains "$OUT" "/dev/sdu" "--list shows a USB SSD that reports RM=0"
assert_not_contains "$OUT" "/dev/sda " "--list hides the internal SSD"
assert_not_contains "$OUT" "/dev/sdb " "--list hides the internal HDD"
assert_not_contains "$OUT" "mmcblk0" "--list hides internal eMMC"
assert_contains "$OUT" "holds the running system" "--list notes the system drive"
assert_contains "$OUT" "in use: unmount it first" "--list notes a mounted drive"

run "$FLASH" --list --json
assert_eq "$RC" "0" "--list --json exit"
JSON_OUT="$(grep -v '^flash.sh: test mode' <<<"$OUT")"
python3 - "$JSON_OUT" <<'PY' || fail "--list --json content"
import json
import sys

rows = {r["name"]: r for r in json.loads(sys.argv[1])}
assert set(rows) == {"sdr", "sdx", "sdu", "sdm", "sdf", "sdh", "sdt", "sdw", "sdn"}, sorted(rows)
assert rows["sdn"]["tran"] == "" and rows["sdn"]["serial"] == "" and rows["sdn"]["size"] > 0
assert rows["sdx"]["problem"] == "" and rows["sdx"]["serial"] == "STICK01"
assert rows["sdr"]["problem"] == "holds the running system"
assert rows["sdm"]["problem"].startswith("in use")
assert "\t" not in rows["sdw"]["model"], rows["sdw"]["model"]
PY
echo "ok: --list"

# ---------------------------------------------------------------------------- refusals (4G.3)
common=(--image "$IMG/airlock-test.raw" --headroom-gb 0)
expect_refusal "non-removable disk" "not a removable drive" "$DEV/sdb" \
  "${common[@]}" --target "$DEV/sdb" --yes --confirm sdb
expect_refusal "internal eMMC (hot-plug, not USB)" "not a removable drive (RM=0)." "$DEV/mmcblk0" \
  "${common[@]}" --target "$DEV/mmcblk0" --yes --confirm mmcblk0
expect_refusal "disk holding /" "holds the running system" "$DEV/sdr" \
  "${common[@]}" --target "$DEV/sdr" --yes --confirm sdr
expect_refusal "mounted partition" "sdm1 is mounted at /media/analyst/STICK" "$DEV/sdm" \
  "${common[@]}" --target "$DEV/sdm" --yes --confirm sdm
expect_refusal "mounted per the kernel mount table" "sdf1 is mounted" "$DEV/sdf" \
  "${common[@]}" --target "$DEV/sdf" --yes --confirm sdf
expect_refusal "LVM in use" "vg-data is in use (lvm)" "$DEV/sdh" \
  "${common[@]}" --target "$DEV/sdh" --yes --confirm sdh
expect_refusal "too small" "Use a bigger drive" "$DEV/sdt" \
  "${common[@]}" --target "$DEV/sdt" --yes --confirm sdt
expect_refusal "too small with headroom" "plus 1 GB headroom" "$DEV/sdx" \
  --image "$IMG/airlock-test.raw" --headroom-gb 1 --target "$DEV/sdx" --yes --confirm sdx
expect_refusal "default 8 GB headroom" "plus 8 GB headroom" "$DEV/sdx" \
  --image "$IMG/airlock-test.raw" --target "$DEV/sdx" --yes --confirm sdx
expect_refusal "wrong typed confirmation" "does not match sdx" "$DEV/sdx" \
  "${common[@]}" --target "$DEV/sdx" --yes --confirm sdu
expect_refusal "--yes without --confirm" "--yes also needs --confirm sdx" "$DEV/sdx" \
  "${common[@]}" --target "$DEV/sdx" --yes
expect_refusal "no terminal, no confirmation" "no terminal" "$DEV/sdx" \
  "${common[@]}" --target "$DEV/sdx" </dev/null
cp "$DEV/sdx" "$DEV/sdx1"
expect_refusal "partition as target" "not a whole drive" "$DEV/sdx1" \
  "${common[@]}" --target "$DEV/sdx1" --yes --confirm sdx1
expect_refusal "serial changed" "may have been swapped" "$DEV/sdx" \
  "${common[@]}" --target "$DEV/sdx" --yes --confirm sdx --expect-serial OTHER

# Image problems.
mkdir -p "$TEST_TMP/bad"
cp "$IMG/airlock-test.raw" "$TEST_TMP/bad/airlock-test.raw"
printf 'X' | dd of="$TEST_TMP/bad/airlock-test.raw" bs=1 seek=1000 conv=notrunc status=none
cp "$IMG/SHA256SUMS" "$TEST_TMP/bad/SHA256SUMS"
expect_refusal "image hash mismatch" "does not match its SHA256SUMS line" "$DEV/sdx" \
  --image "$TEST_TMP/bad/airlock-test.raw" --headroom-gb 0 --target "$DEV/sdx" --yes --confirm sdx
mkdir -p "$TEST_TMP/nosums"
cp "$IMG/airlock-test.raw" "$TEST_TMP/nosums/"
expect_refusal "missing SHA256SUMS" "no SHA256SUMS found" "$DEV/sdx" \
  --image "$TEST_TMP/nosums/airlock-test.raw" --headroom-gb 0 --target "$DEV/sdx" --yes --confirm sdx
mkdir -p "$TEST_TMP/noline"
cp "$IMG/airlock-test.raw" "$TEST_TMP/noline/other.raw"
cp "$IMG/SHA256SUMS" "$TEST_TMP/noline/"
expect_refusal "image not listed in SHA256SUMS" "has no SHA-256 line for other.raw" "$DEV/sdx" \
  --image "$TEST_TMP/noline/other.raw" --headroom-gb 0 --target "$DEV/sdx" --yes --confirm sdx
mkdir -p "$TEST_TMP/stream"
zstd -q -c <"$IMG/airlock-test.raw" >"$TEST_TMP/stream/airlock-test.raw.zst"
(cd "$TEST_TMP/stream" && sha256sum airlock-test.raw.zst >SHA256SUMS)
expect_refusal "zstd stream without a size" "cannot tell how big" "$DEV/sdx" \
  --image "$TEST_TMP/stream/airlock-test.raw.zst" --headroom-gb 0 --target "$DEV/sdx" --yes --confirm sdx
expect_refusal "missing image" "not found" "$DEV/sdx" \
  --image "$TEST_TMP/none.raw" --headroom-gb 0 --target "$DEV/sdx" --yes --confirm sdx

# Without test mode a regular file is never a target.
before="$(sha256_of "$DEV/sdx")"
run env -u AIRLOCK_FLASH_TEST "$FLASH" "${common[@]}" --target "$DEV/sdx" --yes --confirm sdx
[[ "$RC" -eq 3 ]] || fail "regular file outside test mode: expected exit 3, got $RC: $OUT"
assert_contains "$OUT" "is not a drive (block device)" "regular file outside test mode"
assert_eq "$(sha256_of "$DEV/sdx")" "$before" "regular file outside test mode: target changed"
echo "ok: refused a regular file outside test mode"

# Usage errors.
run "$FLASH" --target "$DEV/sdx"
assert_eq "$RC" "2" "missing --image is a usage error"

# ---------------------------------------------------------------------------- good paths
# check_written TARGET ORIGINAL-COPY: first 4 MiB = image, rest untouched.
check_written() {
  local tgt="$1" orig="$2"
  assert_eq "$(head -c $((4 * MIB)) "$tgt" | sha256sum | cut -d' ' -f1)" "$RAW_SHA" "$tgt: image range"
  assert_eq "$(tail -c +$((4 * MIB + 1)) "$tgt" | sha256sum | cut -d' ' -f1)" \
    "$(tail -c +$((4 * MIB + 1)) "$orig" | sha256sum | cut -d' ' -f1)" "$tgt: bytes after the image"
  assert_eq "$(stat -c %s "$tgt")" "$((8 * MIB))" "$tgt: size"
}

cp "$DEV/sdx" "$TEST_TMP/sdx.orig"
run "$FLASH" "${common[@]}" --target "$DEV/sdx" --yes --confirm /dev/sdx
[[ "$RC" -eq 0 ]] || fail "raw write: exit $RC: $OUT"
assert_contains "$OUT" "readback_sha256=$RAW_SHA" "raw write: read-back hash"
check_written "$DEV/sdx" "$TEST_TMP/sdx.orig"
echo "ok: raw image written and verified"

cp "$DEV/sdu" "$TEST_TMP/sdu.orig"
run "$FLASH" --image "$IMG/airlock-test.raw.zst" --headroom-gb 0 --target "$DEV/sdu" --confirm sdu \
  --expect-serial SSD01 </dev/null
[[ "$RC" -eq 0 ]] || fail "zstd write to a USB SSD: exit $RC: $OUT"
assert_contains "$OUT" "readback_sha256=$RAW_SHA" "zstd write: read-back hash"
check_written "$DEV/sdu" "$TEST_TMP/sdu.orig"
echo "ok: zstd image written to a USB SSD (RM=0, USB hot-plug) and verified"

# A drive with no model, serial or bus and old-style "1"/"0" flags.
cp "$DEV/sdn" "$TEST_TMP/sdn.orig"
run "$FLASH" "${common[@]}" --target "$DEV/sdn" --yes --confirm sdn
[[ "$RC" -eq 0 ]] || fail "write to a drive without model or serial: exit $RC: $OUT"
assert_contains "$OUT" "Model:     unknown" "empty model shown as unknown"
check_written "$DEV/sdn" "$TEST_TMP/sdn.orig"
echo "ok: drive with empty lsblk fields written"

# A zstd stream without a size in its header is accepted with a .size file from the build.
stat -c %s "$IMG/airlock-test.raw" >"$TEST_TMP/stream/airlock-test.raw.size"
head -c $((8 * MIB)) /dev/urandom >"$DEV/sdx"
cp "$DEV/sdx" "$TEST_TMP/sdx.orig"
run "$FLASH" --image "$TEST_TMP/stream/airlock-test.raw.zst" --headroom-gb 0 --target "$DEV/sdx" --yes --confirm sdx
[[ "$RC" -eq 0 ]] || fail "zstd stream with .size: exit $RC: $OUT"
check_written "$DEV/sdx" "$TEST_TMP/sdx.orig"
echo "ok: zstd stream with a .size file written and verified"

# Interactive confirmation typed on a terminal.
if command -v script >/dev/null 2>&1; then
  head -c $((8 * MIB)) /dev/urandom >"$DEV/sdx"
  cp "$DEV/sdx" "$TEST_TMP/sdx.orig"
  cmd="$(printf '%q ' env "PATH=$PATH" AIRLOCK_FLASH_TEST=1 "FX=$FX" "$FLASH" "${common[@]}" --target "$DEV/sdx")"
  set +e
  OUT="$(printf 'sdu\n' | script -qec "$cmd" /dev/null 2>&1)"
  set -e
  assert_contains "$OUT" "does not match sdx" "typed wrong name"
  assert_eq "$(sha256_of "$DEV/sdx")" "$(sha256_of "$TEST_TMP/sdx.orig")" "typed wrong name: target changed"
  set +e
  OUT="$(printf 'sdx\n' | script -qec "$cmd" /dev/null 2>&1)"
  set -e
  assert_contains "$OUT" "readback_sha256=$RAW_SHA" "typed right name"
  check_written "$DEV/sdx" "$TEST_TMP/sdx.orig"
  echo "ok: interactive typed confirmation"
else
  echo "note: 'script' not installed; interactive confirmation not exercised"
fi

# ---------------------------------------------------------------------------- read-back failure
real_dd="$(PATH="${PATH#"$STUB_DIR:"}" command -v dd)"
stub dd "
for a in \"\$@\"; do
  if [[ \"\$a\" == iflag=count_bytes* ]]; then
    { printf X; \"$real_dd\" \"\$@\" | tail -c +2; }
    exit 0
  fi
done
exec \"$real_dd\" \"\$@\""
run "$FLASH" "${common[@]}" --target "$DEV/sdx" --yes --confirm sdx
assert_eq "$RC" "1" "corrupted read-back must fail"
assert_contains "$OUT" "read-back check failed" "corrupted read-back message"
rm -f "$STUB_DIR/dd"
echo "ok: corrupted read-back detected"

pass "flash.sh refusals, writes and read-back verification"
