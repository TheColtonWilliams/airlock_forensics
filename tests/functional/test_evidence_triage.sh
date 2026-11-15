#!/usr/bin/env bash
# Task 4.10: evidence-triage runs mmls, fsstat per partition, the evidence hash, and Dissect
# target-info against an image, writes each result to the session log, and leaves the image
# unchanged. With no forensic tools on PATH it logs tool_missing and still hashes.
# shellcheck source=tests/functional/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

require_cmd python3 mmls fsstat sgdisk mkfs.ext4
export AIRLOCK_PYLIB="$PYLIB"
CMD="$BIN_DIR/evidence-triage"
LOG="$AIRLOCK_SESSION_DIR/current.log"

event_count() { grep -c "\"event\":\"$1\"" "$LOG" || true; }

# ---------------------------------------------------------------- fixture: GPT, ext4 + NTFS
DISK="$TEST_TMP/disk.img"
truncate -s 48M "$DISK"
sgdisk -n1:2048:+16M -t1:8300 -n2:0:+16M -t2:0700 "$DISK" >/dev/null
mkdir -p "$TEST_TMP/content"
printf 'triage fixture\n' >"$TEST_TMP/content/readme.txt"
truncate -s 16M "$TEST_TMP/p1"
mkfs.ext4 -q -F -d "$TEST_TMP/content" "$TEST_TMP/p1"
dd if="$TEST_TMP/p1" of="$DISK" bs=512 seek=2048 conv=notrunc status=none
have_ntfs=0
if command -v mkfs.ntfs >/dev/null 2>&1; then
  truncate -s 16M "$TEST_TMP/p2"
  mkfs.ntfs -q -F -f "$TEST_TMP/p2" >/dev/null 2>&1
  dd if="$TEST_TMP/p2" of="$DISK" bs=512 seek=$((2048 + 32768)) conv=notrunc status=none
  have_ntfs=1
fi
before="$(sha256_of "$DISK")"

# ---------------------------------------------------------------- full run
run "$CMD" --timeout 300 "$DISK"
assert_eq "$RC" 0 "evidence-triage: $OUT"
assert_contains "$OUT" "Partition table: yes" "summary shows the partition table"
assert_contains "$OUT" "SHA-256  $before" "summary shows the hash"
assert_eq "$(event_count triage_start)" 1 "triage_start logged"
assert_eq "$(event_count triage_mmls)" 1 "mmls logged"
assert_contains "$(grep '"event":"triage_mmls"' "$LOG")" '"has_partition_table":true' "mmls found the GPT"
fsstat_lines="$(grep '"event":"triage_fsstat"' "$LOG")"
assert_eq "$(grep -c . <<<"$fsstat_lines")" 2 "fsstat ran once per partition"
assert_contains "$fsstat_lines" '"fs_type":"Ext4"' "ext4 partition identified"
assert_contains "$fsstat_lines" '"offset_bytes":1048576' "first partition offset"
if [[ "$have_ntfs" == 1 ]]; then
  assert_contains "$fsstat_lines" '"fs_type":"NTFS"' "NTFS partition identified"
fi
assert_contains "$(grep '"event":"evidence_hash"' "$LOG")" "\"sha256\":\"$before\"" "hash logged"
assert_contains "$(grep '"event":"evidence_hash"' "$LOG")" '"tool":"evidence-triage"' "hash logged by triage"
if command -v target-info >/dev/null 2>&1 || command -v target-query >/dev/null 2>&1; then
  assert_eq "$(event_count triage_dissect)" 1 "Dissect logged"
else
  assert_contains "$(grep '"event":"tool_missing"' "$LOG")" '"command":"target-info"' "Dissect missing logged"
fi
assert_eq "$(event_count triage_done)" 1 "triage_done logged"
assert_eq "$(sha256_of "$DISK")" "$before" "image unchanged after triage"

# ---------------------------------------------------------------- --json, whole filesystem image
FSIMG="$TEST_TMP/fs.img"
cp -- "$TEST_TMP/p1" "$FSIMG"
run "$CMD" --json --no-dissect "$FSIMG"
assert_eq "$RC" 0 "evidence-triage --json on a bare filesystem: $OUT"
got="$(python3 -c 'import json,sys; d=json.loads(sys.stdin.read()); print(d["partition_table"], d["volumes"][0]["slot"], d["volumes"][0]["fs_type"], "dissect" in d)' <<<"$OUT")"
assert_eq "$got" "False whole Ext4 False" "bare filesystem: fsstat on the whole image"

# ---------------------------------------------------------------- no forensic tools at all
NOTOOLS="$TEST_TMP/notools"
mkdir -p "$NOTOOLS"
ln -s "$(command -v python3)" "$NOTOOLS/python3"
lines_before="$(wc -l <"$LOG")"
run env PATH="$NOTOOLS" "$CMD" --timeout 60 "$DISK"
assert_eq "$RC" 0 "triage without tools still succeeds: $OUT"
new="$(tail -n +"$((lines_before + 1))" "$LOG")"
for tool in mmls fsstat target-info; do
  assert_contains "$new" "\"command\":\"$tool\"" "tool_missing for $tool"
done
assert_contains "$new" '"event":"tool_missing"' "tool_missing events"
assert_contains "$new" "\"sha256\":\"$before\"" "hash still taken without tools"
assert_eq "$(sha256_of "$DISK")" "$before" "image unchanged"

# ---------------------------------------------------------------- refusal
run "$CMD" "$TEST_TMP/nothing.img"
assert_eq "$RC" 1 "missing target refused"
assert_contains "$OUT" "does not exist" "missing target message"

pass "evidence-triage: mmls, fsstat per partition, hash, Dissect logged; tolerant of missing tools"
