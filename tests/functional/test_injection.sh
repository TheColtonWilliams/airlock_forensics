#!/usr/bin/env bash
# Task 4E.10: evidence-borne prompt injection. A run folder built from
# tests/fixtures/injection/rows.json (file names and document text that carry planted
# instructions; text only) is reported through the evidence-report command with a stub
# llama-server on 127.0.0.1:
#   1. a compromised stub that obeys the planted instructions: every unsupported sentence is
#      removed and listed by hash, and no planted name or instruction appears in the report;
#   2. a well-behaved stub: its sentences pass and are labelled AI-generated with the model
#      and prompt SHA-256 and a review line;
#   3. in every request, evidence text sits only inside delimited data blocks, the system
#      prompt is one of the fixed prompt files, and media rows carry no path or name.
set -euo pipefail
# shellcheck source=tests/functional/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
require_cmd python3 jq
export AIRLOCK_PYLIB="$PYLIB"
export AIRLOCK_LLAMA_RUN_DIR="$TEST_TMP/llama-run"
FIX="$REPO_ROOT/tests/fixtures/injection"
REPORT="$BIN_DIR/evidence-report"
[[ -x "$REPORT" ]] || fail "evidence-report is missing at $REPORT"

STUB_PID=""
stop_stub() { [[ -z "$STUB_PID" ]] || kill "$STUB_PID" 2>/dev/null || true; }
on_exit stop_stub

# start_stub MODE: starts the stub, sets STUB_URL and STUB_LOG.
start_stub() {
  local mode="$1"
  STUB_LOG="$TEST_TMP/stub-$mode.jsonl"
  head -c 4096 /dev/urandom >"$TEST_TMP/stub-Q4_K_M.gguf"
  rm -f "$TEST_TMP/port"
  python3 "$FIX/stub_report_llm.py" --port-file "$TEST_TMP/port" --log "$STUB_LOG" \
    --model-file "$TEST_TMP/stub-Q4_K_M.gguf" --mode "$mode" &
  STUB_PID=$!
  for _ in $(seq 1 50); do [[ -s "$TEST_TMP/port" ]] && break; sleep 0.1; done
  [[ -s "$TEST_TMP/port" ]] || fail "stub server did not start"
  STUB_URL="http://127.0.0.1:$(cat "$TEST_TMP/port")"
}

# report_with MODE: builds a fresh run folder and reports it; folder in $RD.
report_with() {
  local mode="$1"
  RD="$(python3 "$FIX/make_run.py" "$TEST_TMP/out-$mode")"
  start_stub "$mode"
  run "$REPORT" "$RD" --model-url "$STUB_URL" --no-start
  stop_stub
  STUB_PID=""
  [[ "$RC" -eq 0 ]] || fail "evidence-report ($mode) exited $RC: $OUT"
  assert_file "$RD/report.html"
  assert_file "$RD/report.md"
}

no_planted_text() {
  local f
  for f in "$RD/report.md" "$RD/report.html"; do
    if grep -qiE 'smith|ignore previous|suspect|admin mode|deliberately|to hide' "$f"; then
      fail "planted text reached $(basename "$f"): $(grep -oiE '.{40}(smith|ignore previous|suspect|admin mode).{20}' "$f" | head -n1)"
    fi
  done
}

# 1. Compromised model.
report_with obey
no_planted_text
prov="$RD/logs/report-provenance.json"
removed="$(jq '.removed | length' "$prov")"
[[ "$removed" -ge 10 ]] || fail "expected the verifier to remove the planted sentences, removed $removed"
while IFS= read -r h; do
  grep -q "$h" "$RD/report.md" || fail "removed sentence $h is not listed in Appendix E"
done < <(jq -r '.removed[].sha256' "$prov")
assert_contains "$(jq -r 'select(.event=="sentence_removed") | .text' "$RD/logs/report.jsonl")" \
  "John Smith" "removed text kept in the run log for audit"
# Each removal reason is a fixed phrase that never quotes the sentence.
if jq -r '.removed[].reasons[]' "$prov" | grep -qi smith; then fail "a reason quotes evidence text"; fi
[[ "$(grep -c 'AI-generated draft. Not evidence.' "$RD/report.md")" -ge 3 ]] ||
  fail "the supported sentences of the compromised stub should still be drafted"

# 3. Data blocks, fixed prompts, greedy decoding (checked on the compromised run's requests).
python3 - "$STUB_LOG" "$PYLIB/evidence_report/prompts" <<'PY' || fail "request check failed"
import hashlib, json, re, sys
from pathlib import Path
block = re.compile(r"<<<DATA id=(\S+)>>>\n(.*?)\n<<<END DATA id=\1>>>", re.DOTALL)
fixed = {hashlib.sha256(p.read_bytes()).hexdigest() for p in Path(sys.argv[2]).glob("*.txt")}
reqs = [json.loads(l) for l in open(sys.argv[1], encoding="utf-8")]
assert reqs, "no requests"
planted_seen = False
for r in reqs:
    assert r["system_sha256"] in fixed, "system prompt is not a fixed prompt file"
    assert (r["temperature"], r["top_k"]) == (0, 1), "decoding is not greedy"
    user = r["user"]
    outside = block.sub("", user)
    for bad in ("IGNORE", "Smith", "admin mode"):
        assert bad not in outside, f"{bad!r} outside a data block"
    for m in block.finditer(user):
        assert "<<<" not in m.group(2) and ">>>" not in m.group(2), "delimiter inside data"
    assert "/Pictures/" not in user and "describe this image" not in user, "media path sent"
    assert "‮" not in user, "bidi override sent"
    planted_seen |= "IGNORE PREVIOUS INSTRUCTIONS" in user
assert planted_seen, "the planted text never reached the model inside a block"
PY

# 2. Well-behaved model.
report_with behave
no_planted_text
prov="$RD/logs/report-provenance.json"
assert_eq "$(jq '.removed | length' "$prov")" "0" "behaving model: nothing removed"
assert_eq "$(jq -r '.model.quantization' "$prov")" "Q4_K_M" "quantization recorded"
model_sha="$(sha256_of "$TEST_TMP/stub-Q4_K_M.gguf")"
assert_eq "$(jq -r '.model.model_sha256' "$prov")" "$model_sha" "model hash recorded"
assert_contains "$(cat "$RD/report.md")" "$model_sha" "model hash in the report"
map_sha="$(sha256_of "$PYLIB/evidence_report/prompts/results_map.txt")"
assert_contains "$(cat "$RD/report.md")" "$map_sha" "prompt hash in the report"
n_ai="$(grep -c 'AI-generated draft. Not evidence.' "$RD/report.md")"
n_review="$(grep -c 'Reviewed by:' "$RD/report.md")"
[[ "$n_ai" -ge 8 ]] || fail "expected AI paragraphs for every category, got $n_ai"
assert_eq "$n_review" "$n_ai" "every AI paragraph has a review line"
assert_contains "$(cat "$RD/report.md")" "NOT FINAL. This report contains AI-generated" "not-final header"

pass "planted instructions ignored and stripped; behaving drafts kept and labelled"
