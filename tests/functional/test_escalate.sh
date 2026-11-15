#!/usr/bin/env bash
# Task 4G.12: forensic-escalate halts a running job (and its children), freezes exports, and
# records only the path, the finding ID, and the hash. It must never open the file.
set -euo pipefail
# shellcheck source=tests/functional/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
require_cmd python3 jq
export AIRLOCK_PYLIB="$PYLIB"

run_dir="$AIRLOCK_OUTPUT_DIR/cases/CASE-9/R-20261115T010203Z-0a0b0c"
mkdir -p "$run_dir/modules/images/export/.pending" "$run_dir/modules/video/export" \
  "$run_dir/extract/v0"
printf 'x' >"$run_dir/modules/images/export/v0_68-128-2.jpg"
printf 'y' >"$run_dir/modules/images/export/.pending/v0_70-128-2.png"
printf '{"finding_id":"F-000007","path":"/Users/x/a.png","sha256":"%s"}\n' \
  "$(printf 'c%.0s' $(seq 64))" >"$run_dir/findings.jsonl"
printf '{"run_id":"R-20261115T010203Z-0a0b0c","status":"running"}\n' >"$run_dir/run.json"

# A stand-in for a running forensic-analyze: a process named forensic-analyze with a child
# that keeps exporting (it would write into the export folder if it were not stopped).
cat >"$TEST_TMP/forensic-analyze" <<'PY'
import subprocess, sys, time
child = subprocess.Popen(["bash", "-c", "while :; do sleep 0.2; done"])
open(sys.argv[2], "w").write(str(child.pid))
while True:
    time.sleep(0.1)
PY
python3 "$TEST_TMP/forensic-analyze" "$run_dir" "$TEST_TMP/child.pid" &
analyzer=$!
for _ in $(seq 1 100); do [[ -s "$TEST_TMP/child.pid" ]] && break; sleep 0.05; done
child="$(cat "$TEST_TMP/child.pid")"
printf '%s\n' "$analyzer" >"$run_dir/forensic-analyze.pid"

run "$BIN_DIR/forensic-escalate" --finding F-000007 --yes --grace 2
assert_eq "$RC" "0" "exit code: $OUT"
assert_contains "$OUT" "tips.fbi.gov" "US guidance"
assert_contains "$OUT" "ICAC" "ICAC guidance"
assert_contains "$OUT" "national police" "non-US guidance"
assert_contains "$OUT" "Analysis stopped" "halted"
wait "$analyzer" 2>/dev/null || true
# A killed process may stay a zombie until something reaps it; that still counts as stopped.
alive() { [[ -r "/proc/$1/stat" ]] && [[ "$(awk '{print $3}' "/proc/$1/stat")" != [ZX] ]]; }
sleep 0.5
! alive "$analyzer" || fail "analyzer still running"
! alive "$child" || fail "analyzer child still running"

assert_file "$run_dir/ESCALATED"
assert_eq "$(jq -r 'keys | join(",")' "$run_dir/ESCALATED")" "finding_id,path,sha256,utc" "marker"
assert_eq "$(jq -r .path "$run_dir/escalation.json")" "/Users/x/a.png" "path recorded"
assert_eq "$(jq -r .finding_id "$run_dir/escalation.json")" "F-000007" "finding recorded"
assert_eq "$(jq -r .sha256 "$run_dir/escalation.json" | cut -c1-4)" "cccc" "hash recorded"
assert_eq "$(jq -r .status "$run_dir/run.json")" "escalated" "run status"
writable="$(find "$run_dir"/modules/*/export "$run_dir/extract" -perm /222 -print)"
assert_eq "$writable" "" "exports frozen (no write bits)"
grep -q '"event":"escalated"' "$AIRLOCK_SESSION_DIR/current.log" || fail "not in the session log"

# A second module start after escalation refuses to export anything.
PYTHONPATH="$PYLIB" python3 -c '
import sys
from airlock_ai.escalate import is_escalated
sys.exit(0 if is_escalated(sys.argv[1]) else 1)' "$run_dir" || fail "marker not seen"
pass "forensic-escalate halted the job, froze exports, and recorded only path, ID, and hash"
