#!/usr/bin/env bash
# Copy-first mode (task 4C.24): ddrescue (raw copy + map file) and ewfacquire (E01) each make a
# copy of a read-only loop device, verify it against the drive's before hash, hash the drive
# again, and analyse the copy. The drive and the copy must both be unchanged.
# Also checks that --purge-exports at the end keeps the copy (it is evidence, not an export).
set -euo pipefail
# shellcheck source=tests/functional/test_analyze_helpers.sh
source "$(dirname "${BASH_SOURCE[0]}")/test_analyze_helpers.sh"
analyze_require

img="$TEST_TMP/ntfs.img"
make_ntfs_fixture "$img"
before="$(sha256_of "$img")"
loop_ro "$img"
loop="$LOOP"
write_test_modules "$TEST_TMP/mods"
out="$AIRLOCK_OUTPUT_DIR"
tested=()

for imager in ddrescue ewf; do
  tool=ddrescue
  [[ "$imager" == ewf ]] && tool=ewfacquire
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "note: $tool not installed; $imager not tested"
    continue
  fi
  analyze --target "$loop" --mode image --imager "$imager" --preset quick --output "$out" \
    --case-id "I-$imager" --purge-exports
  [[ "$RC" -eq 0 ]] || fail "$imager run exited $RC: $OUT"
  rd="$(run_dirs "$out" "I-$imager" | tail -n1)"
  assert_eq "$(jq -r .image.verified "$rd/run.json")" "true" "$imager copy verified"
  assert_eq "$(jq -r .image.sha256 "$rd/run.json")" "$before" "$imager copy hash"
  assert_eq "$(jq -r .hashes.after.sha256 "$rd/run.json")" "$before" "$imager drive after hash"
  assert_eq "$(jq -r '.image.files_sha256 == .image.files_sha256_after' "$rd/run.json")" "true" \
    "$imager copy unchanged by the analysis"
  assert_eq "$(jq -r .mode_record.mode "$rd/run.json")" "image" "$imager mode record"
  assert_eq "$(jq -r .integrity.ok "$rd/run.json")" "true" "$imager integrity"
  assert_eq "$(jq -r '.modules[] | select(.name=="inventory") | .status' "$rd/run.json")" "ok" \
    "$imager analysis of the copy"
  copy="$(jq -r .image.image_path "$rd/run.json")"
  assert_file "$copy" "$imager copy kept after purge"
  [[ "$imager" == ddrescue ]] && assert_file "$rd/image/target.map" "map file"
  assert_no_file "$rd/modules/inventory/export"
  run "$FA" --verify "$rd"
  [[ "$RC" -eq 0 ]] || fail "$imager run does not verify: $OUT"
  tested+=("$imager")
done
[[ "${#tested[@]}" -gt 0 ]] || skip "needs ddrescue or ewfacquire"
assert_eq "$(sha256_of "$img")" "$before" "fixture unchanged"

# A too-small output drive is refused before copying.
small="$TEST_TMP/small"
mkdir -p "$small"
mount -t tmpfs -o size=8M tmpfs "$small"
# shellcheck disable=SC2317 # called by the EXIT trap
_umount_small() { umount "$small" 2>/dev/null || true; }
on_exit _umount_small
analyze --target "$loop" --mode image --imager "${tested[0]}" --preset quick --output "$small" \
  --case-id I-small
[[ "$RC" -eq 1 ]] || fail "small output drive: expected exit 1, got $RC: $OUT"
assert_contains "$OUT" "Copy-first mode needs room" "space message"

pass "copy-first with: ${tested[*]}"
