#!/usr/bin/env bash
# Task 4G.10: the screening true-positive path, with a stub classifier (no sensitive fixtures
# exist in the repository). evidence-screen must flag what the stub scores high, flag a video
# with the timestamp of its flagged frame, never clear a file it could not score, and
# evidence-describe must send only cleared files to the model and count the rest.
# Module-level "never exported" is covered by tests/unit/test_module_images.py and
# tests/unit/test_module_video.py.
set -euo pipefail
# shellcheck source=tests/functional/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
# shellcheck source=tests/fixtures/ai/lib-ai.sh
source "$REPO_ROOT/tests/fixtures/ai/lib-ai.sh"
require_cmd ffmpeg python3

work="$TEST_TMP/in"
mkdir -p "$work"
cp "$AI_FIX"/neutral/*.png "$work/"
make_neutral_video "$work/cut.mp4"
export AIRLOCK_SANDBOX=none
stub="stub:$AI_FIX/stub-scores.json"

run "$BIN_DIR/evidence-screen" "$work" -o "$TEST_TMP/screen.csv" --backend "$stub"
assert_eq "$RC" "4" "exit code when one file could not be screened"
assert_contains "$OUT" "2 flagged" "flagged count"
assert_contains "$OUT" "1 not screened" "error count"
assert_contains "$OUT" "forensic-escalate" "stop-control hint"
assert_eq "$(csv_col "$TEST_TMP/screen.csv" shapes-squares.png verdict)" "flagged" "image flag"
assert_eq "$(csv_col "$TEST_TMP/screen.csv" shapes-squares.png category)" "sexual" "category"
assert_eq "$(csv_col "$TEST_TMP/screen.csv" text-render.png verdict)" "error" "never cleared"
assert_eq "$(csv_col "$TEST_TMP/screen.csv" cut.mp4 verdict)" "flagged" "video flagged"
assert_contains "$(csv_col "$TEST_TMP/screen.csv" cut.mp4 reasons)" "at 4." "frame timestamp"
assert_eq "$(csv_col "$TEST_TMP/screen.csv" landscape.png verdict)" "cleared" "neutral cleared"
[[ -z "$(find "$TEST_TMP" -name 's_0*.png' -o -name 'i_0*.png')" ]] || fail "frames were kept"

start_llama_stub describe
run "$BIN_DIR/evidence-describe" "$work"/*.png "$work/cut.mp4" -o "$TEST_TMP/describe.csv" \
  --screen-csv "$TEST_TMP/screen.csv"
assert_eq "$RC" "0" "describe exit code: $OUT"
assert_contains "$OUT" "3 not sent (not cleared)" "flagged and unscreened counted"
sent="$(jq -r '.images[]' "$LLAMA_LOG" | sort)"
expected="$(for f in landscape shapes-circle shapes-triangle; do
  sha256_of "$work/$f.png"
done | sort)"
assert_eq "$sent" "$expected" "only cleared files reached the model"
assert_not_contains "$sent" "$(sha256_of "$work/shapes-squares.png")" "flagged image not sent"
assert_eq "$(csv_col "$TEST_TMP/describe.csv" shapes-squares.png status)" "not_cleared" "row kept"
assert_eq "$(csv_col "$TEST_TMP/describe.csv" cut.mp4 status)" "not_cleared" "video row kept"
assert_eq "$(csv_col "$TEST_TMP/describe.csv" landscape.png status)" "described" "described"
pass "stub classifier path: flags held back, counted, and never sent"
