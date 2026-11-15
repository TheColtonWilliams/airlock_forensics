#!/usr/bin/env bash
# Task 4.10, 4.11: evidence-hash hashes an image (and, as root, a read-only loop device over
# it) in one pass, matches sha256sum/md5sum/sha1sum, appends to the session log, and leaves
# the target unchanged. It refuses things that are not a drive or an image.
# shellcheck source=tests/functional/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

require_cmd python3 sha256sum md5sum sha1sum
export AIRLOCK_PYLIB="$PYLIB"
CMD="$BIN_DIR/evidence-hash"
LOG="$AIRLOCK_SESSION_DIR/current.log"

IMG="$TEST_TMP/evidence.raw"
python3 -c 'import sys; open(sys.argv[1], "wb").write(bytes(range(256)) * 40002)' "$IMG"
want256="$(sha256_of "$IMG")"
want_md5="$(md5sum -- "$IMG" | cut -d' ' -f1)"
want_sha1="$(sha1sum -- "$IMG" | cut -d' ' -f1)"
mtime_before="$(stat -c '%Y' -- "$IMG")"

# ---------------------------------------------------------------- image, plain output
run "$CMD" "$IMG"
assert_eq "$RC" 0 "evidence-hash image: $OUT"
assert_contains "$OUT" "SHA-256  $want256" "SHA-256 printed"
assert_contains "$OUT" "MD5      $want_md5" "MD5 printed"
assert_not_contains "$OUT" "SHA-1" "SHA-1 only with --sha1"
assert_file "$LOG" "session log created"
last="$(tail -n 1 "$LOG")"
assert_contains "$last" '"event":"evidence_hash"' "evidence_hash logged"
assert_contains "$last" "\"sha256\":\"$want256\"" "SHA-256 in the log"
assert_contains "$last" "\"md5\":\"$want_md5\"" "MD5 in the log"
assert_contains "$last" '"kind":"image"' "target kind logged"
assert_contains "$last" '"tool":"evidence-hash"' "tool name logged"
grep -q '"event":"session_implicit"' "$LOG" || fail "an implicit session is started when none exists"

# ---------------------------------------------------------------- --sha1 --json
run "$CMD" --sha1 --json "$IMG"
assert_eq "$RC" 0 "evidence-hash --sha1 --json: $OUT"
got="$(python3 -c 'import json,sys; d=json.loads(sys.stdin.read()); h=d["hashes"]; print(h["sha256"], h["md5"], h["sha1"], d["bytes_read"], d["expected_bytes"], d["complete"], d["algorithms"])' <<<"$OUT")"
size="$(stat -c '%s' -- "$IMG")"
assert_eq "$got" "$want256 $want_md5 $want_sha1 $size $size True ['sha256', 'sha1', 'md5']" "JSON result"
# bytes_read is what the digests cover, counted while hashing (not the size seen beforehand).
assert_contains "$(tail -n 1 "$LOG")" "\"bytes_read\":$size" "bytes hashed logged"

# The target is unchanged.
assert_eq "$(sha256_of "$IMG")" "$want256" "image unchanged"
assert_eq "$(stat -c '%Y' -- "$IMG")" "$mtime_before" "image mtime unchanged"

# ---------------------------------------------------------------- refusals
run "$CMD" "$TEST_TMP/missing.raw"
assert_eq "$RC" 1 "missing target exits 1"
assert_contains "$OUT" "does not exist" "missing target message"
assert_eq "$(grep -c . <<<"$OUT")" 1 "one line on failure"
run "$CMD" "$TEST_TMP"
assert_eq "$RC" 1 "a folder is refused"
assert_contains "$OUT" "not a drive or an image file" "folder message"
grep -q '"event":"failed"' "$LOG" || fail "failures are logged"

# ---------------------------------------------------------------- device (root + loop)
if [[ "$(id -u)" -eq 0 ]] && losetup -f >/dev/null 2>&1; then
  loop="$(losetup --read-only --find --show -- "$IMG")"
  detach() { losetup -d "$loop" 2>/dev/null || true; }
  on_exit detach
  run "$CMD" --json "$loop"
  assert_eq "$RC" 0 "evidence-hash on a loop device: $OUT"
  assert_contains "$OUT" "\"sha256\": \"$want256\"" "device hash equals the image hash"
  assert_contains "$OUT" '"kind": "device"' "device kind"
  assert_contains "$OUT" '"readonly": true' "read-only flag recorded"
  detach
  assert_eq "$(sha256_of "$IMG")" "$want256" "image unchanged after device hash"
else
  echo "note: device part skipped (needs root and a free loop device)"
fi

pass "evidence-hash: hashes match, logged, target unchanged, bad targets refused"
