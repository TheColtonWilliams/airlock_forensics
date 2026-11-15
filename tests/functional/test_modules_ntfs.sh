#!/usr/bin/env bash
# NTFS modules inside the real runner and parser sandbox (tasks 4C.5, 4C.7, 4C.13 to 4C.15,
# 4C.27 to 4C.29): a Full-preset run on the generated NTFS fixture (read-only loop device)
# must run every NTFS module through the sandbox with zero write requests, copy system files
# into extract/, carve the deleted picture and the deleted USN records from unallocated
# space, report the shortcut (LNK) file and owner SIDs, build a timeline, keep only valid
# findings, and the end-of-run purge must remove the exported and carved copies.
set -euo pipefail
# shellcheck source=tests/functional/test_analyze_helpers.sh
source "$(dirname "${BASH_SOURCE[0]}")/test_analyze_helpers.sh"

[[ -x "$FA" ]] || skip "forensic-analyze is not present yet ($FA)"
analyze_require
require_cmd mkfs.ntfs ntfs-3g python3 jq blkls icat photorec
[[ -e /dev/fuse ]] || skip "needs /dev/fuse for ntfs-3g"
unset AIRLOCK_EXTRA_MODULES

img="$TEST_TMP/ntfs.img"
truth="$TEST_TMP/truth.json"
python3 -c '
import json, sys
from pathlib import Path
sys.path.insert(0, sys.argv[3])
from test_parsers_ntfs_fixture import build_ntfs_image
Path(sys.argv[2]).write_text(json.dumps(build_ntfs_image(Path(sys.argv[1])), sort_keys=True))
' "$img" "$truth" "$REPO_ROOT/tests/unit" || fail "could not build the NTFS fixture"
before="$(sha256_of "$img")"
loop_ro "$img"
out="$AIRLOCK_OUTPUT_DIR"

# Stand-ins for MFTECmd and RBCmd (EZ Tools cannot be fetched here). They write their CSV
# into a folder the module made, so this checks the sandboxed tool can write there.
keep_entry="$(ifind -n /Docs/keep.txt "$img")"
cat >"$STUB_DIR/MFTECmd" <<PY
#!/usr/bin/env python3
import sys
from pathlib import Path
a = sys.argv[1:]
out = Path(a[a.index("--csv") + 1]) / a[a.index("--csvf") + 1]
out.write_text("EntryNumber,SequenceNumber,InUse,ParentPath,FileName,FileSize,IsDirectory\n"
               "$keep_entry,1,True,.\\Docs,keep.txt,6,False\n")
PY
cat >"$STUB_DIR/RBCmd" <<'PY'
#!/usr/bin/env python3
import sys
from pathlib import Path
a = sys.argv[1:]
src = Path(a[a.index("-d") + 1])
out = Path(a[a.index("--csv") + 1]) / a[a.index("--csvf") + 1]
lines = ["SourceName,FileName,FileSize,DeletedOn"]
for f in sorted(src.rglob("$I*")):
    lines.append(f"{f},X:\\stand-in.txt,1,2020-01-01 00:00:00")
out.write_text("\n".join(lines) + "\n")
PY
chmod +x "$STUB_DIR/MFTECmd" "$STUB_DIR/RBCmd"

analyze --target "$LOOP" --preset full --output "$out" --case-id T-FULL \
  --reference-time 2026-11-15T00:00:00Z --reference-source "test clock" --write-blocker no
[[ "$RC" -eq 0 ]] || fail "full run exited $RC: $OUT"
rd="$(run_dirs "$out" T-FULL | tail -n1)"
f="$rd/findings.jsonl"
for m in inventory recycle_bin deletion_history users timeline carve; do
  assert_eq "$(jq -r --arg m "$m" '.modules[] | select(.name==$m) | .status' "$rd/run.json")" \
    "ok" "module $m"
done
assert_ne "$(jq -r .sandbox.method "$rd/run.json")" "null" "sandbox method recorded"
assert_eq "$(jq -r .write_requests_total "$rd/run.json")" "0" "no write requests"
assert_eq "$(sha256_of "$img")" "$before" "fixture unchanged"
python3 -m forensic_analyze.findings validate "$f" >/dev/null || fail "findings do not validate"

# Every tool of these modules ran through the runner's tool recorder, sandboxed.
unsandboxed="$(jq -r '[.tools[] | select(.module as $m | ["inventory","recycle_bin",
  "deletion_history","users","timeline","carve"] | index($m)) | select(.sandbox.method ==
  "unsandboxed")] | length' "$rd/run.json")"
assert_eq "$unsandboxed" "0" "NTFS module tools sandboxed"

# The stand-in EZ Tools ran in the sandbox and their rows were joined (and disagree).
assert_eq "$(jq -r 'select(.parser=="mftecmd") | .path' "$f")" "/Docs/keep.txt" "MFTECmd rows"
assert_eq "$(jq -s '[.[] | select(.parser=="rbcmd")] | length' "$f")" \
  "$(jq -r '.recycle | length' "$truth")" "RBCmd rows"
assert_eq "$(jq -s '[.[] | select(.category=="recycle_bin" and .xval_status=="disagree")] |
  length > 0' "$f")" "true" "RBCmd disagreement listed"

# System files copied once, with their metadata.
for name in MFT Secure_SDS LogFile Bitmap; do
  assert_file "$rd/extract/v0/$name" "$name copied"
  assert_file "$rd/extract/v0/$name.json" "$name metadata"
done

# Carving: the deleted picture comes back byte for byte; carved USN delete record found.
png="$(jq -r '.png_sha256' "$truth")"
assert_eq "$(jq -r --arg h "$png" 'select(.artifact_type=="carved_file" and .sha256==$h) |
  .parser' "$f" | head -n1)" "photorec" "picture carved"
assert_contains "$(jq -r 'select(.artifact_type=="usn_delete_carved") | .filename' "$f")" \
  "$(jq -r .carved_usn_name "$truth")" "USN delete record carved"
assert_file "$rd/modules/carve/carved.jsonl"
assert_contains "$(cat "$rd/modules/carve/carved.jsonl")" "$png" "carved index lists the picture"

# Users: the shortcut file and at least one owner account SID.
assert_contains "$(jq -r 'select(.artifact_type=="lnk_file") | .text' "$f")" \
  "$(jq -r .lnk.target "$truth")" "LNK target"
assert_eq "$(jq -s '[.[] | select(.artifact_type=="owner_sid_summary")] | length > 0' "$f")" \
  "true" "owner SID summary"
# Timeline from file system times (Plaso not installed) or Plaso.
assert_eq "$(jq -s '[.[] | select(.category=="timeline" and .datetime != null)] | length > 0' \
  "$f")" "true" "timeline rows"
# No row names a person: messages about owners speak of account SIDs.
if jq -r 'select(.owner_sid != null) | .message' "$f" | grep -qiE '\buser [A-Z][a-z]+\b'; then
  fail "a message names a user instead of an account SID"
fi

# The purge removes exported and carved copies and keeps the findings.
run "$FA" --purge-run "$rd"
[[ "$RC" -eq 0 ]] || fail "--purge-run exited $RC: $OUT"
assert_no_file "$rd/modules/carve/carved"
assert_no_file "$rd/modules/carve/export"
assert_no_file "$rd/modules/recycle_bin/export"
assert_file "$f"

pass "full run: sandboxed NTFS modules, carving, users, timeline, purge"
