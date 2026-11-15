#!/usr/bin/env bash
# Task 4.14: every NTFS parser on the image finds the known deleted files of the committed
# fixture (tests/fixtures/ntfs-basic.*, built by tests/fixtures/build-ntfs-fixture.sh):
#   1. The Sleuth Kit: fls -rd lists every deleted name; icat recovers the deleted files'
#      exact bytes (resident and non-resident).
#   2. Dissect: target-query -f mft marks every deleted name as not in use.
#   3. MFTECmd (EZ Tools) on the $MFT copied out with icat, when dotnet and MFTECmd are
#      installed; and on $UsnJrnl:$J when the volume has one (ntfs-3g keeps none).
# Also: fls -rd finds the deleted files of the exFAT fixture (tests/fixtures/exfat-basic.*),
# and both fixtures' hashes match the committed .sha256 files before and after the parsers ran.
# A parser that is not installed is skipped with a message; with AIRLOCK_REQUIRE_ALL_PARSERS=1
# (the QEMU/CI stage) a missing parser fails the test instead.
# shellcheck source=tests/functional/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

require_cmd zstd sha256sum fls icat ifind python3
FIX="$REPO_ROOT/tests/fixtures"
for f in ntfs-basic.img.zst ntfs-basic.truth.json ntfs-basic.sha256 \
  exfat-basic.img.zst exfat-basic.truth.json exfat-basic.sha256; do
  assert_file "$FIX/$f" "committed fixture"
done

ran=()
missing() {
  if [[ "${AIRLOCK_REQUIRE_ALL_PARSERS:-0}" == "1" ]]; then
    fail "$1 is not installed, and AIRLOCK_REQUIRE_ALL_PARSERS=1 asks for every parser"
  fi
  echo "note: $1 is not installed; that part is skipped"
}

# expected_sha FIXTURE FILE: the hash the committed .sha256 file records for FILE.
expected_sha() {
  awk -v f="$2" '$2 == f { print $1 }' "$FIX/$1.sha256"
}

# unpack NAME: check the .zst hash, decompress to $TEST_TMP/NAME.img, check the image hash,
# make the copy read-only.
unpack() {
  local name="$1" img="$TEST_TMP/$1.img"
  assert_eq "$(sha256_of "$FIX/$name.img.zst")" "$(expected_sha "$name" "$name.img.zst")" \
    "$name.img.zst matches $name.sha256"
  zstd -q -d -f -o "$img" -- "$FIX/$name.img.zst"
  chmod 0444 "$img"
  assert_eq "$(sha256_of "$img")" "$(expected_sha "$name" "$name.img")" "$name.img matches $name.sha256"
  assert_eq "$(sha256_of "$img")" "$(python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))["image_sha256"])' "$FIX/$name.truth.json")" \
    "$name.img matches its ground truth"
}

# truth_lines TRUTH_JSON KEY OUT: one line per item of KEY ("deleted_names", or "deleted" as
# entry<TAB>sha256<TAB>path) written to OUT; fails the test if the ground truth cannot be read.
truth_lines() {
  python3 -I - "$1" "$2" >"$3" <<'PY' || fail "cannot read $1"
import json, sys
truth = json.load(open(sys.argv[1], encoding="utf-8"))
for item in truth[sys.argv[2]]:
    if isinstance(item, dict):
        entry = item.get("mft_entry", item.get("dir_entry"))
        print(f"{entry}\t{item['sha256']}\t{item['path']}")
    else:
        print(item)
PY
}

unpack ntfs-basic
unpack exfat-basic
NTFS="$TEST_TMP/ntfs-basic.img"
EXFAT="$TEST_TMP/exfat-basic.img"
TRUTH="$FIX/ntfs-basic.truth.json"
truth_lines "$TRUTH" deleted_names "$TEST_TMP/truth-names.txt"
truth_lines "$TRUTH" deleted "$TEST_TMP/truth-deleted.txt"
truth_lines "$FIX/exfat-basic.truth.json" deleted_names "$TEST_TMP/exfat-truth-names.txt"
mapfile -t DELETED_NAMES <"$TEST_TMP/truth-names.txt"
[[ "${#DELETED_NAMES[@]}" -ge 5 ]] || fail "ground truth lists too few deleted names"

# deleted_basenames FLS_OUTPUT: the last path part of every entry fls marks deleted ('*').
deleted_basenames() {
  python3 -I - "$1" <<'PY'
import sys
with open(sys.argv[1], encoding="utf-8", errors="surrogateescape") as fh:
    for line in fh:
        meta, _, path = line.rstrip("\n").partition("\t")
        if meta.split(" ")[1:2] == ["*"]:
            print(path.rsplit("/", 1)[-1])
PY
}

# check_names LISTING_FILE PARSER: every known deleted name is in LISTING_FILE (one per line).
check_names() {
  local listing="$1" parser="$2" name
  for name in "${DELETED_NAMES[@]}"; do
    grep -Fxq -- "$name" "$listing" || fail "$parser did not find the deleted file '$name'"
  done
}

# ---------------------------------------------------------------------- 1. The Sleuth Kit
fls -r -d -p -- "$NTFS" >"$TEST_TMP/fls-deleted.txt" || fail "fls -rd could not read the NTFS fixture"
deleted_basenames "$TEST_TMP/fls-deleted.txt" >"$TEST_TMP/fls-names.txt"
check_names "$TEST_TMP/fls-names.txt" "fls -rd"
# icat recovers each plainly named deleted file byte for byte (resident and non-resident).
while IFS=$'\t' read -r entry want path; do
  got="$(icat -- "$NTFS" "$entry" | sha256sum | cut -d' ' -f1)"
  assert_eq "$got" "$want" "icat recovers $path (MFT entry $entry)"
  recovered=$((${recovered:-0} + 1))
done <"$TEST_TMP/truth-deleted.txt"
[[ "${recovered:-0}" -ge 3 ]] || fail "expected at least 3 recoverable deleted files, checked ${recovered:-0}"
# The live recycle-bin $I file holds the Windows 10 (version 2) record the truth describes.
i_path="$(python3 -I -c 'import json,sys; r=json.load(open(sys.argv[1]))["recycle_bin"][0]; print(r["i_path"])' "$TRUTH")"
i_entry="$(ifind -n "$i_path" -- "$NTFS")" || fail "ifind did not find $i_path"
icat -- "$NTFS" "$i_entry" >"$TEST_TMP/i-file.bin"
run python3 -I - "$TEST_TMP/i-file.bin" "$TRUTH" <<'PY'
import json, struct, sys
data = open(sys.argv[1], "rb").read()
rec = json.load(open(sys.argv[2], encoding="utf-8"))["recycle_bin"][0]
version, size, when, chars = struct.unpack_from("<qqqi", data)
path = data[28:28 + 2 * chars].decode("utf-16-le").rstrip("\0")
got = {"format_version": version, "original_size": size, "deleted_filetime": when,
       "original_path": path}
want = {k: rec[k] for k in got}
sys.exit(0 if got == want else f"$I record {got} != ground truth {want}")
PY
[[ "$RC" -eq 0 ]] || fail "recycle-bin \$I file: $OUT"
ran+=("fls/icat")

# ---------------------------------------------------------------------- 2. Dissect
TQ="$(command -v target-query || true)"
[[ -n "$TQ" || ! -x /opt/dissect/bin/target-query ]] || TQ=/opt/dissect/bin/target-query
if [[ -n "$TQ" ]]; then
  "$TQ" -q -f mft -j --compact -- "$NTFS" >"$TEST_TMP/dissect-mft.jsonl" 2>"$TEST_TMP/dissect.err" ||
    fail "target-query -f mft failed: $(tail -n 3 "$TEST_TMP/dissect.err")"
  python3 -I - "$TEST_TMP/dissect-mft.jsonl" >"$TEST_TMP/dissect-names.txt" <<'PY'
import json, sys
for line in open(sys.argv[1], encoding="utf-8"):
    rec = json.loads(line)
    if rec.get("_type") == "record" and rec.get("inuse") is False:
        parts = [p for p in str(rec.get("path", "")).replace("/", "\\").split("\\") if p]
        if parts:
            print(parts[-1])
PY
  check_names "$TEST_TMP/dissect-names.txt" "Dissect target-query -f mft"
  ran+=("dissect")
else
  missing "Dissect (target-query)"
fi

# ---------------------------------------------------------------------- 3. MFTECmd
if command -v dotnet >/dev/null 2>&1 && command -v MFTECmd >/dev/null 2>&1; then
  icat -- "$NTFS" 0 >"$TEST_TMP/MFT"
  mkdir -p "$TEST_TMP/mftecmd"
  run MFTECmd -f "$TEST_TMP/MFT" --csv "$TEST_TMP/mftecmd" --csvf mft.csv
  [[ "$RC" -eq 0 ]] || fail "MFTECmd on \$MFT failed: $OUT"
  python3 -I - "$TEST_TMP/mftecmd/mft.csv" >"$TEST_TMP/mftecmd-names.txt" <<'PY'
import csv, sys
with open(sys.argv[1], encoding="utf-8-sig", newline="") as fh:
    for row in csv.DictReader(fh):
        if str(row.get("InUse", "")).lower() == "false":
            print(row.get("FileName", ""))
PY
  check_names "$TEST_TMP/mftecmd-names.txt" "MFTECmd (\$MFT)"
  ran+=("mftecmd")
  # shellcheck disable=SC2016 # $Extend and $UsnJrnl are NTFS names, not shell variables
  if usn="$(ifind -n '/$Extend/$UsnJrnl' -- "$NTFS" 2>/dev/null)" && [[ -n "$usn" ]]; then
    icat -- "$NTFS" "$usn-128-3" >"$TEST_TMP/J" 2>/dev/null || icat -- "$NTFS" "$usn" >"$TEST_TMP/J"
    run MFTECmd -f "$TEST_TMP/J" --csv "$TEST_TMP/mftecmd" --csvf j.csv
    [[ "$RC" -eq 0 ]] || fail "MFTECmd on \$J failed: $OUT"
    for name in "${DELETED_NAMES[@]}"; do
      grep -Fq -- "$name" "$TEST_TMP/mftecmd/j.csv" || fail "MFTECmd (\$J) did not list '$name'"
    done
    ran+=("mftecmd-j")
  else
    echo "note: the fixture has no \$UsnJrnl (ntfs-3g keeps no USN journal); MFTECmd \$J step skipped"
  fi
else
  missing "MFTECmd (EZ Tools on .NET 9)"
fi

# ---------------------------------------------------------------------- exFAT fixture
fls -r -d -p -- "$EXFAT" >"$TEST_TMP/exfat-deleted.txt" || fail "fls -rd could not read the exFAT fixture"
deleted_basenames "$TEST_TMP/exfat-deleted.txt" >"$TEST_TMP/exfat-names.txt"
exfat_count=0
while IFS= read -r name; do
  grep -Fxq -- "$name" "$TEST_TMP/exfat-names.txt" || fail "fls -rd did not find the deleted exFAT file '$name'"
  exfat_count=$((exfat_count + 1))
done <"$TEST_TMP/exfat-truth-names.txt"
[[ "$exfat_count" -ge 3 ]] || fail "exFAT ground truth lists too few deleted names"

# ---------------------------------------------------------------------- unchanged afterwards
assert_eq "$(sha256_of "$NTFS")" "$(expected_sha ntfs-basic ntfs-basic.img)" "NTFS fixture unchanged by the parsers"
assert_eq "$(sha256_of "$EXFAT")" "$(expected_sha exfat-basic exfat-basic.img)" "exFAT fixture unchanged by fls"
assert_eq "$(sha256_of "$FIX/ntfs-basic.img.zst")" "$(expected_sha ntfs-basic ntfs-basic.img.zst)" \
  "committed NTFS fixture unchanged"

pass "deleted files found by: ${ran[*]}; ${recovered} recovered by icat; exFAT fls (${exfat_count}); fixture hashes unchanged"
