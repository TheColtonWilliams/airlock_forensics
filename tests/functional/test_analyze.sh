#!/usr/bin/env bash
# Task 4C.21: a non-interactive Standard run of forensic-analyze against an NTFS fixture on a
# kernel read-only loop device must list the known deleted files (in findings.jsonl, from
# The Sleuth Kit, and from Dissect when it is installed), report the known recycle-bin
# entries with original path, deletion time, and owner account SID, write run.json, and leave
# the fixture hash unchanged. A run against an exFAT fixture must skip every NTFS module with
# the reason.
#
# The fixture is built here (tests/unit/test_parsers_ntfs_fixture.py, generated text only)
# because the recycle-bin ground truth comes from that builder. When the shared fixture
# tests/fixtures/ntfs-basic.img.zst and its ground truth JSON exist, the deleted files listed
# there are checked too.
set -euo pipefail
# shellcheck source=tests/functional/test_analyze_helpers.sh
source "$(dirname "${BASH_SOURCE[0]}")/test_analyze_helpers.sh"

[[ -x "$FA" ]] || skip "forensic-analyze is not present yet ($FA)"
analyze_require
require_cmd mkfs.ntfs ntfs-3g python3 jq
[[ -e /dev/fuse ]] || skip "needs /dev/fuse for ntfs-3g"
unset AIRLOCK_EXTRA_MODULES

# build_fixture IMG TRUTH_JSON
build_fixture() {
  python3 -c '
import json, sys
from pathlib import Path
sys.path.insert(0, sys.argv[3])
from test_parsers_ntfs_fixture import build_ntfs_image
truth = build_ntfs_image(Path(sys.argv[1]))
Path(sys.argv[2]).write_text(json.dumps(truth, sort_keys=True))
' "$1" "$2" "$REPO_ROOT/tests/unit"
}

# check_deleted FINDINGS PATH...: each path has an unallocated file_entry row from tsk (and
# from dissect when target-query is installed).
check_deleted() {
  local findings="$1" p parsers
  shift
  for p in "$@"; do
    parsers="$(jq -r --arg p "$p" 'select(.category=="inventory" and .artifact_type=="file_entry"
      and .path==$p and .allocated==false) | .parser' "$findings" | sort -u | tr '\n' ' ')"
    assert_contains "$parsers" "tsk" "deleted $p listed by The Sleuth Kit"
    if command -v target-query >/dev/null 2>&1; then
      assert_contains "$parsers" "dissect" "deleted $p listed by Dissect"
    fi
  done
}

img="$TEST_TMP/ntfs.img"
truth="$TEST_TMP/truth.json"
build_fixture "$img" "$truth" || fail "could not build the NTFS fixture"
before="$(sha256_of "$img")"
loop_ro "$img"
loop="$LOOP"
out="$AIRLOCK_OUTPUT_DIR"

# 1. Standard run, every value from flags.
analyze --target "$loop" --preset standard --output "$out" --case-id T-STD --exhibit-id EX-1 \
  --reference-time 2026-11-15T00:00:00Z --reference-source "test clock" --write-blocker no
[[ "$RC" -eq 0 ]] || fail "standard run exited $RC: $OUT"
rd="$(run_dirs "$out" T-STD | tail -n1)"
[[ -n "$rd" ]] || fail "no run folder"
assert_file "$rd/run.json"
assert_file "$rd/findings.jsonl"
assert_eq "$(jq -r .status "$rd/run.json")" "complete" "run status"
assert_eq "$(jq -r .config.preset "$rd/run.json")" "standard" "preset recorded"
for m in inventory recycle_bin deletion_history users timeline; do
  assert_eq "$(jq -r --arg m "$m" '.modules[] | select(.name==$m) | .status' "$rd/run.json")" \
    "ok" "module $m"
done
f="$rd/findings.jsonl"
mapfile -t deleted < <(jq -r '.deleted[]' "$truth")
check_deleted "$f" "${deleted[@]}"

# 2. The known recycle-bin entries: original path, deletion time, owner account SID.
sid="$(jq -r .sid "$truth")"
while IFS= read -r name; do
  path="$(jq -r --arg n "$name" '.recycle[$n].path' "$truth")"
  when="$(jq -r --arg n "$name" '.recycle[$n].deleted' "$truth")"
  got="$(jq -r --arg p "$path" 'select(.category=="recycle_bin" and .parser=="airlock.recycle"
    and .path==$p) | [.datetime, .owner_sid, .timestamp_desc] | @tsv' "$f")"
  assert_eq "$got" "$when	$sid	Deletion Time" "recycle bin entry $name"
done < <(jq -r '.recycle | keys[]' "$truth")
assert_eq "$(jq -r 'select(.artifact_type=="vss_check") | .message' "$f" | grep -c 'no Volume Shadow')" \
  "1" "VSS none found reported"
assert_eq "$(jq -s '[.[] | select(.category=="xval" and .artifact_type=="xval_summary")] | length > 0' \
  "$f")" "true" "cross-check summaries"
assert_eq "$(sha256_of "$img")" "$before" "fixture unchanged"
assert_eq "$(jq -r .hashes.after.sha256 "$rd/run.json")" "$before" "after hash recorded"
assert_eq "$(jq -r .write_requests_total "$rd/run.json")" "0" "no write requests"

# 3. The shared fixture, when another package has committed it with its ground truth.
shared="$REPO_ROOT/tests/fixtures/ntfs-basic.img.zst"
shared_truth="$(find "$REPO_ROOT/tests/fixtures" -maxdepth 1 -name 'ntfs-basic*.json' 2>/dev/null |
  head -n1)"
if [[ -f "$shared" && -n "$shared_truth" ]] && command -v zstd >/dev/null 2>&1; then
  mapfile -t sdel < <(jq -r '(.deleted // .deleted_files // [])[] | if type=="object" then .path
    else . end' "$shared_truth")
  if [[ "${#sdel[@]}" -gt 0 ]]; then
    simg="$TEST_TMP/shared.img"
    zstd -q -d -f "$shared" -o "$simg"
    sbefore="$(sha256_of "$simg")"
    loop_ro "$simg"
    analyze --target "$LOOP" --preset standard --output "$out" --case-id T-SHARED
    [[ "$RC" -eq 0 ]] || fail "shared fixture run exited $RC: $OUT"
    srd="$(run_dirs "$out" T-SHARED | tail -n1)"
    check_deleted "$srd/findings.jsonl" "${sdel[@]}"
    assert_eq "$(sha256_of "$simg")" "$sbefore" "shared fixture unchanged"
  else
    echo "note: $shared_truth lists no deleted files in a known form; shared check skipped"
  fi
fi

# 4. exFAT: every NTFS module is skipped with the reason.
ex="$TEST_TMP/exfat.img"
make_exfat_fixture "$ex"
loop_ro "$ex"
analyze --target "$LOOP" --preset standard --output "$out" --case-id T-EXF
[[ "$RC" -eq 0 ]] || fail "exFAT run exited $RC: $OUT"
erd="$(run_dirs "$out" T-EXF | tail -n1)"
for m in inventory recycle_bin deletion_history users; do
  rec="$(jq -c --arg m "$m" '.modules[] | select(.name==$m)' "$erd/run.json")"
  assert_contains "$rec" '"status":"skipped"' "$m skipped on exFAT"
  assert_contains "$rec" "needs a ntfs volume" "$m skip reason"
done
assert_eq "$(jq -r '.modules[] | select(.name=="timeline") | .status' "$erd/run.json")" "ok" \
  "timeline still runs on exFAT"

pass "standard run: deleted files, recycle bin, run.json, hash unchanged, exFAT skips"
