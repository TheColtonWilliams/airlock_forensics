#!/usr/bin/env bash
# Task 4G.11: a model that refuses, or answers with nothing, must give a model_declined row for
# every cleared file. No file may be dropped from describe.csv.
set -euo pipefail
# shellcheck source=tests/functional/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
# shellcheck source=tests/fixtures/ai/lib-ai.sh
source "$REPO_ROOT/tests/fixtures/ai/lib-ai.sh"
require_cmd python3 jq
export AIRLOCK_SANDBOX=none

files=("$AI_FIX"/neutral/landscape.png "$AI_FIX"/neutral/shapes-circle.png)
run "$BIN_DIR/evidence-screen" "${files[@]}" -o "$TEST_TMP/screen.csv" \
  --backend "stub:$AI_FIX/stub-scores.json"
assert_eq "$RC" "0" "screen: $OUT"

for mode in decline empty; do
  start_llama_stub "$mode"
  out="$TEST_TMP/describe-$mode.csv"
  run "$BIN_DIR/evidence-describe" "${files[@]}" -o "$out" --screen-csv "$TEST_TMP/screen.csv"
  assert_eq "$RC" "0" "$mode: exit code: $OUT"
  assert_contains "$OUT" "2 declined by the model" "$mode: counted"
  rows="$(python3 -c 'import csv,sys; print(len(list(csv.DictReader(open(sys.argv[1], encoding="utf-8-sig")))))' "$out")"
  assert_eq "$rows" "2" "$mode: every file has a row"
  for f in landscape.png shapes-circle.png; do
    assert_eq "$(csv_col "$out" "$f" status)" "model_declined" "$mode: $f status"
    assert_eq "$(csv_col "$out" "$f" description)" "" "$mode: no description"
    assert_eq "$(csv_col "$out" "$f" model_sha256)" "$(sha256_of "$LLAMA_MODEL")" "$mode: hash"
    [[ -n "$(csv_col "$out" "$f" prompt_sha256)" ]] || fail "$mode: no prompt hash"
  done
  assert_eq "$(wc -l <"$LLAMA_LOG")" "2" "$mode: both files were asked"
  stop_llama_stub
done
pass "refusals and empty replies are recorded as model_declined, never dropped"
