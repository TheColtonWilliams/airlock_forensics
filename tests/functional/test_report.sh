#!/usr/bin/env bash
# Tasks 4B.11, 4E.1, 4E.11: forensic-analyze calls evidence-report at the end of a real run
# against an NTFS fixture on a read-only loop device. The report must be written to the run
# folder, listed in outputs.sha256, and covered by the signature; without a model it must
# still render with "No AI draft: local model not available"; with a stub model on 127.0.0.1
# (AIRLOCK_LLAMA_URL) it must hold labelled AI drafts whose sentences all cite findings.
# Re-rendering a finished run by hand re-hashes and re-signs it.
set -euo pipefail
# shellcheck source=tests/functional/test_analyze_helpers.sh
source "$(dirname "${BASH_SOURCE[0]}")/test_analyze_helpers.sh"
analyze_require
[[ -x "$BIN_DIR/evidence-report" ]] || fail "evidence-report is missing at $BIN_DIR"
export PATH="$BIN_DIR:$PATH"
export AIRLOCK_LLAMA_NO_START=1
export AIRLOCK_LLAMA_RUN_DIR="$TEST_TMP/llama-run"
unset AIRLOCK_EXTRA_MODULES

img="$TEST_TMP/ntfs.img"
make_ntfs_fixture "$img"
loop_ro "$img"
loop="$LOOP"
out="$AIRLOCK_OUTPUT_DIR"

# check_signed RD: outputs.sha256 lists the report and both the list and signature verify.
check_signed() {
  local rd="$1"
  grep -q ' report.html$' "$rd/outputs.sha256" || fail "report.html not in outputs.sha256"
  grep -q ' report.md$' "$rd/outputs.sha256" || fail "report.md not in outputs.sha256"
  (cd "$rd" && sha256sum --quiet -c outputs.sha256) || fail "outputs.sha256 does not verify"
  openssl pkeyutl -verify -pubin -inkey "$rd/outputs.sha256.pub.pem" -rawin \
    -in "$rd/outputs.sha256" -sigfile "$rd/outputs.sha256.sig" >/dev/null ||
    fail "signature does not verify"
}

# 1. No model: the runner calls evidence-report before hashing and signing.
export AIRLOCK_LLAMA_URL="http://127.0.0.1:9"
analyze --target "$loop" --preset quick --output "$out" --case-id T-REP --exhibit-id EX-1 \
  --reference-time 2026-11-15T00:00:00Z --reference-source "test clock" --write-blocker no
[[ "$RC" -eq 0 ]] || fail "quick run exited $RC: $OUT"
rd="$(run_dirs "$out" T-REP | tail -n1)"
assert_eq "$(jq -r .report.status "$rd/run.json")" "ok" "runner recorded the report"
assert_file "$rd/report.html"
assert_file "$rd/report.md"
check_signed "$rd"
md="$(cat "$rd/report.md")"
assert_contains "$md" "No AI draft: local model not available" "no-model text"
assert_contains "$md" "$(jq -r .run_id "$rd/run.json")" "run id in report"
assert_contains "$md" "$(jq -r .hashes.before.sha256 "$rd/run.json")" "evidence hash in report"
assert_contains "$md" "Not all evidence may be found." "NIST IR 8354 limitation 1"
assert_contains "$md" "Recovered deleted files may include extraneous material." "limitation 2"
assert_contains "$md" "Artifact meaning changes between OS versions." "limitation 3"
assert_contains "$md" "kept no forensic copy" "direct-mode statement"
assert_contains "$md" "| Observed write requests to the target | 0 |" "write count"
assert_not_contains "$md" "AI-generated draft. Not evidence." "no AI paragraph without a model"

# 2. Re-render by hand: the folder is re-hashed and re-signed.
run "$BIN_DIR/evidence-report" "$rd" --no-model
[[ "$RC" -eq 0 ]] || fail "re-render exited $RC: $OUT"
assert_contains "$OUT" "rewritten to include the new report" "re-sign message"
check_signed "$rd"

# 3. With a stub model reachable on 127.0.0.1.
head -c 4096 /dev/urandom >"$TEST_TMP/stub-Q4_K_M.gguf"
python3 "$REPO_ROOT/tests/fixtures/injection/stub_report_llm.py" --port-file "$TEST_TMP/port" \
  --log "$TEST_TMP/stub.jsonl" --model-file "$TEST_TMP/stub-Q4_K_M.gguf" --mode behave &
stub_pid=$!
# shellcheck disable=SC2317 # called from the EXIT trap through on_exit
stop_stub() { kill "$stub_pid" 2>/dev/null || true; }
on_exit stop_stub
for _ in $(seq 1 50); do [[ -s "$TEST_TMP/port" ]] && break; sleep 0.1; done
[[ -s "$TEST_TMP/port" ]] || fail "stub server did not start"
port="$(cat "$TEST_TMP/port")"
export AIRLOCK_LLAMA_URL="http://127.0.0.1:$port"
analyze --target "$loop" --preset quick --output "$out" --case-id T-REP2 --exhibit-id EX-1 \
  --reference-time 2026-11-15T00:00:00Z --reference-source "test clock" --write-blocker no
[[ "$RC" -eq 0 ]] || fail "quick run with model exited $RC: $OUT"
rd="$(run_dirs "$out" T-REP2 | tail -n1)"
check_signed "$rd"
md="$(cat "$rd/report.md")"
assert_contains "$md" "AI-generated draft. Not evidence." "AI paragraph"
assert_contains "$md" "Reviewed by:" "review line"
assert_contains "$md" "$(sha256_of "$TEST_TMP/stub-Q4_K_M.gguf")" "model hash"
prov="$rd/logs/report-provenance.json"
[[ "$(jq '[.sections[].sentences[]] | length' "$prov")" -gt 0 ]] || fail "no drafted sentence kept"
bad="$(jq -r '.sections[].sentences[].text | select(test("\\[F-[0-9]{6,}(, F-[0-9]{6,})*\\]\\.?$") | not)' "$prov")"
[[ -z "$bad" ]] || fail "a kept sentence does not end with finding IDs: $bad"
# Every cited ID exists in findings.jsonl.
while IFS= read -r fid; do
  grep -q "\"finding_id\":\"$fid\"" "$rd/findings.jsonl" || fail "cited $fid does not exist"
done < <(jq -r '.sections[].sentences[].ids[]' "$prov" | sort -u)

pass "report written, hashed, and signed with the run; AI drafts labelled and cited"
