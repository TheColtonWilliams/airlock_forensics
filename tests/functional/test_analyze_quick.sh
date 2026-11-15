#!/usr/bin/env bash
# forensic-analyze end to end (tasks 4C.1, 4C.16, 4C.17, 4C.18, 4C.20, 4C.25, 2B.17, 3A.5, 3A.9):
# a non-interactive Quick run against an NTFS fixture on a read-only loop device must produce
# run.json, findings.jsonl, and outputs.sha256 with a valid signature; leave the fixture hash
# unchanged with zero write requests; replay with --config must give the same module plan; an
# exFAT target must skip the NTFS-only module with a reason; tampering must fail --verify.
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

# 1. Quick run, every value from flags.
analyze --target "$loop" --preset quick --output "$out" --case-id T-1 --exhibit-id EX-1 \
  --reference-time 2026-11-15T00:00:00Z --reference-source "test clock" --write-blocker no
[[ "$RC" -eq 0 ]] || fail "quick run exited $RC: $OUT"
assert_contains "$OUT" "Read-directly mode" "direct-mode warning shown"
rd="$(run_dirs "$out" T-1 | tail -n1)"
[[ -n "$rd" ]] || fail "no run folder"
assert_file "$rd/run.json"
assert_file "$rd/findings.jsonl"
assert_file "$rd/outputs.sha256"
assert_file "$rd/outputs.sha256.sig"
[[ "$(basename "$rd")" =~ ^R-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{6}$ ]] || fail "bad run id $(basename "$rd")"
assert_eq "$(jq -r .status "$rd/run.json")" "complete" "status"
assert_eq "$(jq -r .hashes.before.sha256 "$rd/run.json")" "$before" "before hash recorded"
assert_eq "$(jq -r .hashes.after.sha256 "$rd/run.json")" "$before" "after hash recorded"
assert_eq "$(jq -r .write_requests_total "$rd/run.json")" "0" "write requests"
assert_eq "$(jq -r .write_requests.target.method "$rd/run.json")" "block_stat" "tracer method"
assert_eq "$(jq -r .integrity.ok "$rd/run.json")" "true" "integrity"
assert_eq "$(jq -r .case.examiner "$rd/run.json")" "Test Examiner" "examiner"
assert_eq "$(jq -r .case.exhibit_id "$rd/run.json")" "EX-1" "exhibit"
assert_eq "$(jq -r .authority_ack.acknowledged "$rd/run.json")" "true" "authority ack"
assert_eq "$(jq -r .write_blocker.in_use "$rd/run.json")" "no" "blocker answer"
assert_eq "$(jq -r .clock.reference_source "$rd/run.json")" "test clock" "clock source"
[[ "$(jq -r .clock.clock_offset_seconds "$rd/run.json")" != "null" ]] || fail "no clock offset"
assert_eq "$(jq -r .clock.system_time_changed "$rd/run.json")" "false" "system time untouched"
assert_eq "$(jq -r .mode_record.mode "$rd/run.json")" "direct" "mode record"
assert_ne "$(jq -r .sandbox.method "$rd/run.json")" "null" "sandbox method recorded"
assert_eq "$(jq -r '.summary.modules | length > 0' "$rd/run.json")" "true" "summary for report"
assert_eq "$(jq -r '.handle.method' "$rd/run.json")" "ro_loop" "read-only handle"
[[ "$(jq -r '.tools | length' "$rd/run.json")" -gt 0 ]] || fail "no tool records"
assert_eq "$(jq -r '[.tools[] | select(.binary_sha256 == "")] | length' "$rd/run.json")" "0" \
  "every tool has a binary hash"
inv_status="$(jq -r '.modules[] | select(.name == "inventory") | .status' "$rd/run.json")"
assert_eq "$inv_status" "ok" "inventory module"
if [[ -f "$rd/modules/inventory/fls-v0.txt" ]]; then
  assert_contains "$(cat "$rd/findings.jsonl")" "Docs/keep.txt" "live file listed"
  assert_contains "$(head -n1 "$rd/findings.jsonl")" '"finding_id":"F-000001"' "finding ids"
fi
assert_eq "$(sha256_of "$img")" "$before" "fixture unchanged"

# 2. Signature and hashes verify, by hand and with --verify.
(cd "$rd" && sha256sum --quiet -c outputs.sha256) || fail "sha256sum -c failed"
openssl pkeyutl -verify -pubin -inkey "$rd/outputs.sha256.pub.pem" -rawin \
  -in "$rd/outputs.sha256" -sigfile "$rd/outputs.sha256.sig" >/dev/null || fail "signature"
run "$FA" --verify "$rd"
[[ "$RC" -eq 0 ]] || fail "--verify on a clean run: $OUT"
# The private key lives on the root filesystem, never on the output drive.
key="$AIRLOCK_STATE_DIR/signing/$(cat "$out/.airlock/signing/key-id")/key.pem"
assert_file "$key"
assert_no_file "$out/.airlock/signing/key.pem"
assert_eq "$(stat -c %a "$key")" "600" "key mode"

# 3. Replay with --config gives the same module plan.
analyze --config "$rd/run.json" --reference-time 2026-11-15T00:00:00Z
[[ "$RC" -eq 0 ]] || fail "replay exited $RC: $OUT"
rd2="$(run_dirs "$out" T-1 | grep -v "$(basename "$rd")" | tail -n1)"
[[ -n "$rd2" ]] || fail "no replay run folder"
assert_eq "$(jq -c .plan.planned "$rd2/run.json")" "$(jq -c .plan.planned "$rd/run.json")" "plan"
assert_eq "$(jq -c .config "$rd2/run.json")" "$(jq -c .config "$rd/run.json")" "config replayed"
strip='del(.run_id, .finding_id)'
assert_eq "$(jq -c "$strip" "$rd2/findings.jsonl" | sha256sum)" \
  "$(jq -c "$strip" "$rd/findings.jsonl" | sha256sum)" "same findings apart from run id"

# 4. Purge exported copies after the run: findings stay, copies go, outputs re-signed.
if [[ -f "$rd2/modules/inventory/fls-v0.txt" ]]; then
  assert_file "$rd2/modules/inventory/export/keep.txt" "test module exported a file"
  assert_eq "$(cat "$rd2/modules/inventory/export/keep.txt")" "hello" "exported via icat"
  run "$FA" --purge-run "$rd2"
  [[ "$RC" -eq 0 ]] || fail "--purge-run exited $RC: $OUT"
  assert_no_file "$rd2/modules/inventory/export"
  assert_file "$rd2/findings.jsonl"
  assert_eq "$(jq -r .purge.removed_files "$rd2/run.json")" "1" "purge recorded"
  run "$FA" --verify "$rd2"
  [[ "$RC" -eq 0 ]] || fail "purged run does not verify: $OUT"
fi

# 5. Tampering is detected.
printf 'x' >>"$rd/findings.jsonl"
run "$FA" --verify "$rd"
[[ "$RC" -ne 0 ]] || fail "--verify accepted a changed file"
assert_contains "$OUT" "changed: findings.jsonl" "tamper message"

# 6. exFAT target: the NTFS-only module is skipped with the reason.
ex="$TEST_TMP/exfat.img"
make_exfat_fixture "$ex"
loop_ro "$ex"
exloop="$LOOP"
analyze --target "$exloop" --preset quick --output "$out" --case-id T-EX
[[ "$RC" -eq 0 ]] || fail "exFAT run exited $RC: $OUT"
rd3="$(run_dirs "$out" T-EX | tail -n1)"
assert_eq "$(jq -r '.volumes[0].fs_type' "$rd3/run.json")" "exfat" "exFAT detected"
inv="$(jq -c '.modules[] | select(.name == "inventory")' "$rd3/run.json")"
assert_contains "$inv" '"status":"skipped"' "NTFS module skipped on exFAT"
assert_contains "$inv" "needs a ntfs volume" "skip reason"

# 7. A writable device is refused before anything is read.
loop_rw "$ex"
rw="$LOOP"
analyze --target "$rw" --preset quick --output "$out" --case-id T-RW
[[ "$RC" -eq 1 ]] || fail "writable target not refused (rc $RC)"
assert_contains "$OUT" "not read-only" "refusal message"

pass "quick run, signature, replay, exFAT skip, writable refusal"
