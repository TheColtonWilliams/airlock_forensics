#!/usr/bin/env bash
# scripts/build-tool-spike.sh compare (task 0.11): two small AIRLOCK-layout images whose
# root filesystems differ in known ways. The report must list exactly those differences,
# per-partition results, and say the images are not identical; the same image twice must
# come out identical. Images are attached read-only and left unchanged.
# shellcheck source=tests/functional/lib.sh
. "$(dirname "$0")/lib.sh"
# shellcheck source=tests/vm/lib/disks.sh
. "$REPO_ROOT/tests/vm/lib/disks.sh"
require_loop
require_cmd sgdisk partx mkfs.ext4 python3 jq

spike="$REPO_ROOT/scripts/build-tool-spike.sh"

make_image() { # OUT TREE
  local out="$1" tree="$2" start
  airlock_mini_layout_disk "$out" 128
  start="$(sgdisk -i 5 "$out" | awk '/^First sector/ {print $3}')"
  truncate -s 40M "$TEST_TMP/root.fs"
  E2FSPROGS_FAKE_TIME=1700000000 mkfs.ext4 -q -F -L AIRLOCK_ROOT -U 11111111-2222-3333-4444-555555555555 \
    -E root_owner=0:0 -d "$tree" "$TEST_TMP/root.fs"
  dd if="$TEST_TMP/root.fs" of="$out" bs=512 seek="$start" conv=notrunc,sparse status=none
  rm -f "$TEST_TMP/root.fs"
}

mkdir -p "$TEST_TMP/tree-a/etc" "$TEST_TMP/tree-a/usr/bin"
printf 'same\n' >"$TEST_TMP/tree-a/etc/same.conf"
printf 'build A\n' >"$TEST_TMP/tree-a/etc/build-info"
printf 'old\n' >"$TEST_TMP/tree-a/usr/bin/only-in-a"
ln -s same.conf "$TEST_TMP/tree-a/etc/link"
cp -a "$TEST_TMP/tree-a" "$TEST_TMP/tree-b"
printf 'build B\n' >"$TEST_TMP/tree-b/etc/build-info"
rm "$TEST_TMP/tree-b/usr/bin/only-in-a"
printf 'new\n' >"$TEST_TMP/tree-b/usr/bin/only-in-b"
chmod 0600 "$TEST_TMP/tree-b/etc/same.conf"

make_image "$TEST_TMP/a.raw" "$TEST_TMP/tree-a"
make_image "$TEST_TMP/b.raw" "$TEST_TMP/tree-b"
sum_a="$(sha256_of "$TEST_TMP/a.raw")"

run "$spike" compare "$TEST_TMP/a.raw" "$TEST_TMP/b.raw" --out "$TEST_TMP/report"
assert_eq "$RC" 0 "compare: $OUT"
r="$TEST_TMP/report/spike-report.json"
assert_file "$r"
assert_file "$TEST_TMP/report/spike-report.md"
assert_eq "$(jq -r .images_identical "$r")" false
assert_eq "$(jq -r '.root_added | join(",")' "$r")" "/usr/bin/only-in-b"
assert_eq "$(jq -r '.root_removed | join(",")' "$r")" "/usr/bin/only-in-a"
assert_eq "$(jq -r '.root_changed | join(",")' "$r")" "/etc/build-info,/etc/same.conf"
assert_eq "$(jq -r '[.partitions[] | select(.identical)] | map(.name) | join(",")' "$r")" "BIOSBOOT,EFI,ASSETS,OUTPUT"
assert_contains "$(cat "$TEST_TMP/report/spike-report.md")" "Byte-identical images: **no**"
assert_eq "$(sha256_of "$TEST_TMP/a.raw")" "$sum_a" "image A unchanged by the comparison"

run "$spike" compare "$TEST_TMP/a.raw" "$TEST_TMP/a.raw" --out "$TEST_TMP/report2"
assert_eq "$RC" 0 "compare with itself"
assert_eq "$(jq -r '.images_identical and .root_identical' "$TEST_TMP/report2/spike-report.json")" true

run "$spike" compare "$TEST_TMP/a.raw" --out "$TEST_TMP/report3"
assert_eq "$RC" 1 "one image is a usage error"
run "$spike" frobnicate
assert_eq "$RC" 1 "unknown mode"
[[ -z "$(losetup -j "$TEST_TMP/a.raw")" ]] || fail "loop device left attached"

pass "build-tool spike compare"
