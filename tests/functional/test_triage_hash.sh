#!/usr/bin/env bash
# Tasks 4A.4, 4A.6, 4D.8 (milestone 4A exit check): offline hash triage drops a known-good
# file through a synthetic NSRL-schema database and flags a known-bad test file through a
# MalwareBazaar-style .hsb that clamscan loads. The EICAR test string is joined at run time
# (the repository never holds it whole). The input files are not changed and nothing is
# written next to them; with root and loop devices the same run reads a read-only mounted
# filesystem.
# shellcheck source=tests/functional/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

require_cmd python3 clamscan sha256sum
export AIRLOCK_PYLIB="$PYLIB"
CMD="$BIN_DIR/evidence-triage-hash"
FIX="$REPO_ROOT/tests/fixtures/hashsets"
LOG="$AIRLOCK_SESSION_DIR/current.log"
HS="$TEST_TMP/hashsets"
mkdir -p "$HS/clamav" "$HS/yara" "$HS/ssdeep"

python3 "$FIX/hashset_fixtures.py" "$TEST_TMP/fx" >/dev/null
SAMPLES="$TEST_TMP/fx/samples"
eicar_sha="$(sha256_of "$SAMPLES/eicar-test.com")"
known_sha="$(sha256_of "$SAMPLES/known-good.txt")"
assert_eq "$eicar_sha" "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f" \
  "EICAR test string joined correctly"

# ------------------------------------------------- MalwareBazaar export -> .hsb (4A.4)
run python3 -P -m airlock_hashsets.build mbz-hsb --source "$TEST_TMP/fx/mbz/full_sha256.zip" \
  --dest "$HS/clamav"
assert_eq "$RC" 0 "mbz-hsb: $OUT"
assert_contains "$OUT" '"changed": true' "hsb written"
grep -qx "$eicar_sha:\*:MalwareBazaar\.${eicar_sha:0:16}:73" "$HS/clamav/malwarebazaar.hsb" ||
  fail "the .hsb line for the EICAR SHA-256 is missing or malformed"
assert_contains "$(tail -n 1 "$LOG")" '"event":"hashset_applied"' "snapshot logged"
assert_contains "$(tail -n 1 "$LOG")" '"snapshot":"2026-11-14' "snapshot date logged"
run python3 -P -m airlock_hashsets.build mbz-hsb --source "$TEST_TMP/fx/mbz/full_sha256.zip" \
  --dest "$HS/clamav"
assert_contains "$OUT" '"changed": false' "second conversion changes nothing"

# clamscan itself loads the generated .hsb and flags the EICAR file through it.
run clamscan --no-summary -d "$HS/clamav/malwarebazaar.hsb" "$SAMPLES/eicar-test.com"
assert_eq "$RC" 1 "clamscan flags EICAR through the .hsb: $OUT"
assert_contains "$OUT" "MalwareBazaar.${eicar_sha:0:16}.UNOFFICIAL FOUND"

if command -v yarac >/dev/null 2>&1 && command -v yara >/dev/null 2>&1; then
  (cd "$FIX" && tar -czf "$TEST_TMP/pack.tar.gz" airlock-test.yar needs-external.yar broken.yar)
  run python3 -P -m airlock_hashsets.build yara --source "$TEST_TMP/pack.tar.gz" \
    --dest "$HS/yara/test" --name "AIRLOCK test" --version t-1
  assert_eq "$RC" 0 "yara pack: $OUT"
  assert_contains "$OUT" '"rule_files": 2' "broken rule skipped, others compiled"
  have_yara=1
else
  echo "note: yara/yarac missing; YARA part not checked"
  have_yara=0
fi

cat >"$AIRLOCK_ETC_DIR/hashsets.json" <<JSON
{"clamav_dir": "$HS/clamav", "nsrl_dirs": ["$HS/nsrl-unused"], "yara_dir": "$HS/yara",
 "ssdeep_dir": "$HS/ssdeep"}
JSON
# NSRL lives off the image by default: nsrl_path in airlock.conf.json points at it.
printf '{"nsrl_path": "%s"}\n' "$TEST_TMP/fx/nsrl" >"$AIRLOCK_ETC_DIR/airlock.conf.json"

before="$(cd "$SAMPLES" && find . -type f -printf '%p %s %T@\n' | sort; sha256sum -- * | sort)"
OUTDIR="$AIRLOCK_OUTPUT_DIR/triage"

# --------------------------------------------------------------- triage (4A.6, 4D.8)
run "$CMD" "$SAMPLES" -o "$OUTDIR/triage.csv"
assert_eq "$RC" 0 "evidence-triage-hash: $OUT"
assert_contains "$OUT" "known software (NSRL)" "summary line"
assert_contains "$OUT" "FLAGGED  $SAMPLES/eicar-test.com  MalwareBazaar 2026-11-14" "EICAR flagged"
CSV="$OUTDIR/triage.csv"
assert_file "$CSV"
[[ "$(head -c 3 "$CSV" | od -An -tx1 | tr -d ' ')" == "efbbbf" ]] || fail "CSV has no UTF-8 BOM"
csv_get() { # csv_get FILE-NAME COLUMN
  python3 - "$CSV" "$1" "$2" <<'PY'
import csv, sys
with open(sys.argv[1], encoding="utf-8-sig", newline="") as fh:
    for row in csv.DictReader(fh):
        if row["path"].rsplit("/", 1)[-1] == sys.argv[2]:
            print(row[sys.argv[3]])
PY
}
assert_eq "$(csv_get eicar-test.com verdict)" flagged "EICAR verdict"
assert_eq "$(csv_get eicar-test.com sha256)" "$eicar_sha" "EICAR SHA-256 in the CSV"
assert_contains "$(csv_get eicar-test.com hash_hits)" "MalwareBazaar" "EICAR hash set"
assert_eq "$(csv_get known-good.txt verdict)" known_good "NSRL drops the known-good file"
assert_eq "$(csv_get known-good.txt nsrl_match_algorithm)" sha256 "NSRL matched on SHA-256"
assert_eq "$(csv_get known-good.txt sha256)" "$known_sha" "known-good SHA-256"
assert_eq "$(csv_get legacy.txt nsrl_match_algorithm)" sha1 "legacy row matched on SHA-1"
assert_eq "$(csv_get collision.txt verdict)" no_match "an MD5-only collision is not known good"
if ((have_yara)); then
  assert_contains "$(csv_get '=marker,cmd.bin' yara_hits)" "Airlock_Test_Marker" "YARA hit"
fi
last="$(grep '"event":"hash_triage"' "$LOG" | tail -n 1)"
assert_contains "$last" '"known_good":2' "counts in the session log"
assert_contains "$last" "\"csv_sha256\":\"$(sha256_of "$CSV")\"" "CSV hash in the session log"

# A relative list with a formula-like name: the CSV cell is neutralised.
printf '%s\n' "=marker,cmd.bin" "eicar-test.com" >"$TEST_TMP/list.txt"
run bash -c 'cd "$1" && "$2" --list "$3" -o "$4" --quiet' _ "$SAMPLES" "$CMD" \
  "$TEST_TMP/list.txt" "$OUTDIR/list.csv"
assert_eq "$RC" 0 "list input: $OUT"
grep -q "^\"'=marker,cmd.bin\"\|^'=marker,cmd.bin" "$OUTDIR/list.csv" ||
  fail "formula-like file name not neutralised: $(cat "$OUTDIR/list.csv")"

# Refuses to write into the folder it checks; leaves the inputs untouched.
run "$CMD" "$SAMPLES" -o "$SAMPLES/out.csv"
assert_ne "$RC" 0 "output inside the input folder refused"
assert_contains "$OUT" "OUTPUT drive" "says where to write instead"
after="$(cd "$SAMPLES" && find . -type f -printf '%p %s %T@\n' | sort; sha256sum -- * | sort)"
assert_eq "$after" "$before" "input files unchanged and nothing added"

# ---------------------------------------- read-only mounted filesystem (root + loop)
if [[ "$(id -u)" -eq 0 ]] && losetup -f >/dev/null 2>&1 && command -v mkfs.ext4 >/dev/null; then
  IMG="$TEST_TMP/evidence.img"
  truncate -s 16M "$IMG"
  mkfs.ext4 -q -d "$SAMPLES" "$IMG"
  img_before="$(sha256_of "$IMG")"
  LOOP="$(losetup -f --show -r "$IMG")"
  detach() { umount "$TEST_TMP/mnt" 2>/dev/null || true; losetup -d "$LOOP" 2>/dev/null || true; }
  on_exit detach
  mkdir -p "$TEST_TMP/mnt"
  if mount -o ro,noload,noexec,nosuid,nodev "$LOOP" "$TEST_TMP/mnt" 2>/dev/null; then
    run "$CMD" "$TEST_TMP/mnt" -o "$OUTDIR/mounted.csv"
    assert_eq "$RC" 0 "triage of a read-only mount: $OUT"
    assert_contains "$OUT" "eicar-test.com  MalwareBazaar" "EICAR flagged on the mount"
    detach
    assert_eq "$(sha256_of "$IMG")" "$img_before" "evidence image unchanged"
  else
    echo "note: could not mount ext4 here; read-only mount part not checked"
  fi
else
  echo "note: needs root and a loop device; read-only mount part not checked"
fi

pass "hash triage drops known-good (NSRL) and flags known-bad (.hsb via clamscan), offline"
