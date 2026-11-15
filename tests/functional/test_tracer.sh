#!/usr/bin/env bash
# Write tracer true-positive test (task 4G.6, for 3A.5): a deliberate write and a discard sent
# to a scratch disk must both be counted. Without this, a count of zero proves nothing.
# Also checks the negative: reading a read-only loop device counts zero write requests.
set -euo pipefail
# shellcheck source=tests/functional/test_analyze_helpers.sh
source "$(dirname "${BASH_SOURCE[0]}")/test_analyze_helpers.sh"
require_loop
require_cmd dd blkdiscard python3

scratch="$TEST_TMP/scratch.img"
truncate -s 32M "$scratch"
loop_rw "$scratch"
dev="$LOOP"

trace() {
  # trace DEVICE COMMAND...: run COMMAND between two tracer samples; print the result JSON.
  local d="$1"
  shift
  python3 - "$d" "$@" <<'PY'
import json
import subprocess
import sys

from forensic_analyze.tracer import WriteTracer

tr = WriteTracer(sys.argv[1])
tr.start()
subprocess.run(sys.argv[2:], check=True)
res = tr.stop()
print(json.dumps(res.to_dict(), sort_keys=True))
PY
}

# 1. A deliberate direct write is counted.
res="$(trace "$dev" dd if=/dev/urandom of="$dev" bs=4096 count=8 oflag=direct status=none)"
writes="$(jq -r .delta.write_ios <<<"$res")"
[[ "$writes" -gt 0 ]] || fail "write not counted: $res"
[[ "$(jq -r .write_requests <<<"$res")" -gt 0 ]] || fail "write_requests is 0: $res"
assert_eq "$(jq -r .clean <<<"$res")" "false" "clean flag after a write"

# 2. A discard is counted.
res="$(trace "$dev" blkdiscard -o 0 -l 1048576 "$dev")"
discards="$(jq -r .delta.discard_ios <<<"$res")"
[[ "$discards" -gt 0 ]] || fail "discard not counted: $res"

# 3. Reading a read-only loop device (as the runner does) counts nothing.
loop_ro "$scratch"
ro="$LOOP"
res="$(trace "$ro" python3 -c 'import sys; from airlock_common import hashing; hashing.hash_file(sys.argv[1])' "$ro")"
assert_eq "$(jq -r .write_requests <<<"$res")" "0" "reads only: $res"
assert_eq "$(jq -r .method <<<"$res")" "block_stat" "method"

# 4. A plain image file is not applicable (checked by hash instead).
na="$(python3 -c 'from forensic_analyze.tracer import WriteTracer; t = WriteTracer(None); t.start(); print(t.stop().method)')"
assert_eq "$na" "not_applicable" "file target"

pass "write ($writes) and discard ($discards) counted; reads count 0"
