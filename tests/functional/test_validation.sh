#!/usr/bin/env bash
# Validation suite end to end at small scale (tasks 4F.1, 4F.3, 4F.4, 4G.15):
# build the synthetic NTFS and exFAT sets, run the whole wizard on them through read-only loop
# devices, score every artifact class, check that a wrong ground truth fails, build and sign
# the validation report and verify it, then run the scale test on a small image, record a
# baseline, and check that a regression against it fails.
set -euo pipefail
# shellcheck source=tests/functional/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

require_root
require_loop
require_cmd python3 jq openssl mkfs.ntfs ntfs-3g mkfs.exfat mount.exfat-fuse faketime fls mmls \
  icat blkls photorec
[[ -e /dev/fuse ]] || skip "needs /dev/fuse"
unset AIRLOCK_EXTRA_MODULES
V="$REPO_ROOT/validation"
out="$TEST_TMP/vout"

# 4F.1 + 4F.3: build, run, score.
run "$V/run.sh" --build --out "$out"
[[ "$RC" -eq 0 ]] || fail "run.sh exited $RC: $OUT"
assert_file "$out/synthetic/ntfs-synthetic.truth.json"
assert_file "$out/synthetic/exfat-synthetic.img"
assert_eq "$(jq -r .overall "$out/summary.json")" "ok" "summary"
ntfs="$out/ntfs-synthetic/score.json"
assert_eq "$(jq -r .overall "$ntfs")" "pass" "NTFS set overall"
for cls in live_files deleted_files recycle_bin timestamps timestomp carving usn_carved; do
  assert_eq "$(jq -r --arg c "$cls" '.classes[$c].status' "$ntfs")" "pass" "NTFS class $cls"
done
assert_eq "$(jq -r .run.write_requests_total "$ntfs")" "0" "no write requests"
assert_eq "$(jq -r .run.hash_unchanged "$ntfs")" "true" "image unchanged"
assert_eq "$(jq -r '.classes.timestomp.known_undetected_methods[0].method' "$ntfs")" \
  "ntfs3g_xattr" "known timestomp limit recorded"
ex="$out/exfat-synthetic/score.json"
assert_eq "$(jq -r .classes.live_files.status "$ex")" "unsupported" "exFAT inventory unsupported"
assert_eq "$(jq -r .classes.carving.status "$ex")" "pass" "exFAT carving"

# A ground truth that lists a deleted file the image does not hold must fail.
bad="$TEST_TMP/bad-truth.json"
jq '.files += [{"path": "/Data/never-existed.txt", "state": "deleted", "times": null}]' \
  "$out/synthetic/ntfs-synthetic.truth.json" >"$bad"
run_dir="$(jq -r .run.run_dir "$ntfs")"
mkdir -p "$TEST_TMP/neg/x"
run python3 "$V/scoring.py" score --truth "$bad" --run "$run_dir" --out "$TEST_TMP/neg/x/score.json"
[[ "$RC" -eq 0 ]] || fail "scoring the wrong truth exited $RC: $OUT"
assert_eq "$(jq -r .classes.deleted_files.status "$TEST_TMP/neg/x/score.json")" "fail" \
  "missing deleted file fails the class"
run python3 "$V/scoring.py" summary "$TEST_TMP/neg"
[[ "$RC" -eq 1 ]] || fail "summary of a failed set should exit 1, got $RC"

# 4F.4: report, signed with a throw-away key, verified, tamper detected.
openssl genpkey -algorithm ed25519 -out "$TEST_TMP/release.pem" 2>/dev/null
openssl pkey -in "$TEST_TMP/release.pem" -pubout -out "$TEST_TMP/release.pub.pem"
run python3 "$V/report/build.py" --results "$out" --release test-0 --key "$TEST_TMP/release.pem" \
  --pub "$TEST_TMP/release.pub.pem" --require-signature --require-pass
[[ "$RC" -eq 0 ]] || fail "report build exited $RC: $OUT"
md="$out/report/validation-report.md"
assert_contains "$(cat "$md")" "docs/known-limitations.md" "report links the known limitations"
assert_contains "$(cat "$md")" "| ntfs-synthetic | pass (12/12)" "report table"
run python3 "$V/report/build.py" --verify "$out/report" --pub "$TEST_TMP/release.pub.pem"
[[ "$RC" -eq 0 ]] || fail "report does not verify: $OUT"
printf 'edited\n' >>"$md"
run python3 "$V/report/build.py" --verify "$out/report" --pub "$TEST_TMP/release.pub.pem"
[[ "$RC" -eq 1 ]] || fail "an edited report must not verify"

# 4G.15 at small scale: generate, record a baseline, compare, and catch a regression.
scale=(python3 "$V/scale/scale.py")
run "${scale[@]}" generate --out "$TEST_TMP/scale.img" --files 120
[[ "$RC" -eq 0 ]] || fail "scale generate exited $RC: $OUT"
bl="$TEST_TMP/baseline.json"
run "${scale[@]}" run --image "$TEST_TMP/scale.img" --out "$TEST_TMP/s1" --preset quick \
  --baseline "$bl" --update-baseline
[[ "$RC" -eq 0 ]] || fail "scale run exited $RC: $OUT"
r1="$TEST_TMP/s1/result.json"
assert_eq "$(jq -r .verdict "$r1")" "baseline recorded" "baseline recorded"
assert_eq "$(jq -r .modules.inventory.status "$r1")" "ok" "inventory ran"
[[ "$(jq -r '.modules.inventory.duration_s > 0' "$r1")" == true ]] || fail "no module time"
[[ "$(jq -r '.peak_tree_rss_kib > 0' "$r1")" == true ]] || fail "no memory peak"
run "${scale[@]}" compare --result "$r1" --baseline "$bl"
[[ "$RC" -eq 0 ]] || fail "same result against its own baseline exited $RC: $OUT"
jq '.baselines["quick-120"].total_s = 0.01 | .tolerance.slack_s = 0' "$bl" >"$bl.tight"
run "${scale[@]}" compare --result "$r1" --baseline "$bl.tight"
[[ "$RC" -eq 1 ]] || fail "a slower run than the baseline must fail, got $RC: $OUT"
assert_contains "$OUT" "regression: total run time" "regression named"

pass "validation suite: synthetic sets scored, report signed, scale baseline enforced"
