#!/usr/bin/env bash
# Functional test for make-usb.sh and scripts/prereqs.sh (tasks 2A.1 to 2A.6, 2A.8).
#
# Runs make-usb.sh from a scratch copy of the repository in which the heavy steps are stubs:
# scripts/build.sh, tests/run-qemu-tests.sh, scripts/fetch-assets.sh and
# scripts/gen-manifest.py record their arguments in calls.log; scripts/flash.sh is a wrapper
# that records its arguments and runs the real flash.sh.
#
# Part A (no root needed): usage and host-check refusals, prerequisite handling (the real
#   prereqs.sh with a cut-down PATH and an apt-get stub), drive, profile and key refusals,
#   the --image-only step order, failure reporting and resume from the output folder.
# Part B (root, a loop device, exFAT mount support): 'make-usb.sh --yes --profile ci'
#   against a loop device: real flash.sh (test mode), real ASSETS mount, staged files read
#   back, smoke boot through a qcow2 overlay on the drive, the abuse.ch key reaching the
#   fetcher only through its environment and never any file, a corrupted staged file caught,
#   and --flash-only.
# Exit 0 when both parts pass; 77 when part A passed and part B could not run (the last line
# says why).
# shellcheck source=tests/functional/lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

require_cmd python3 zstd sha256sum awk
python3 -c 'import yaml' 2>/dev/null || skip "needs python3-yaml"

FAKE="$TEST_TMP/repo"
CALLS="$TEST_TMP/calls.log"
FX="$TEST_TMP/fx"
mkdir -p "$FAKE/scripts" "$FAKE/tests/goss" "$FAKE/assets" "$FAKE/ansible/group_vars/all" "$FX"
export CALLS FX
cp "$REPO_ROOT/make-usb.sh" "$FAKE/make-usb.sh"
cp "$REPO_ROOT/scripts/flash.sh" "$FAKE/scripts/flash-real.sh"
cp "$REPO_ROOT/scripts/prereqs.sh" "$FAKE/scripts/prereqs.sh"
cp "$REPO_ROOT/ansible/group_vars/all/main.yml" "$REPO_ROOT/ansible/group_vars/all/pins.yml" \
  "$FAKE/ansible/group_vars/all/"
MAKE="$FAKE/make-usb.sh"
GB=1000000000

# ---------------------------------------------------------------------------- fake repo stubs
fake_script() { # PATH BODY
  printf '#!/usr/bin/env bash\nset -euo pipefail\n%s\n' "$2" >"$1"
  chmod +x "$1"
}

# shellcheck disable=SC2016 # stub bodies expand when the stub runs
fake_script "$FAKE/scripts/flash.sh" '
echo "flash $*" >>"$CALLS"
if [[ -n "${FLASH_LIST_JSON:-}" && " $* " == *" --list "* ]]; then cat "$FLASH_LIST_JSON"; exit 0; fi
exec "$(dirname "$0")/flash-real.sh" "$@"'

# build.sh: "builds" by copying the prepared image into --output.
# shellcheck disable=SC2016
fake_script "$FAKE/scripts/build.sh" '
echo "build $*" >>"$CALLS"
if [[ "${BUILD_FAIL:-0}" == "1" ]]; then echo "packer exploded: disk full in the guest"; exit 1; fi
out=""
while (($#)); do case "$1" in --output) out="$2"; shift 2 ;; --prepare-tools) exit 0 ;; *) shift ;; esac; done
[[ -n "$out" ]] || { echo "no --output" >&2; exit 1; }
rm -rf "$out"; mkdir -p "$out"
cp "$FX/image/"* "$out/"
echo "build ok"'

# run-qemu-tests.sh: checks its --image exists; for the smoke boot, that it is a qcow2 overlay
# whose backing file is the drive.
# shellcheck disable=SC2016
fake_script "$FAKE/tests/run-qemu-tests.sh" '
echo "qemu $*" >>"$CALLS"
img=""
args=("$@")
for ((i = 0; i < ${#args[@]}; i++)); do [[ "${args[i]}" == "--image" ]] && img="${args[i + 1]}"; done
[[ -f "$img" ]] || { echo "qemu stub: no image $img" >&2; exit 1; }
if [[ " $* " == *" --only "* ]]; then
  backing="$(qemu-img info --output=json "$img" | python3 -c "import json,sys; print(json.load(sys.stdin).get(\"backing-filename\",\"\"))")"
  echo "smoke-backing $backing" >>"$CALLS"
fi
[[ "${QEMU_FAIL:-0}" == "1" ]] && { echo "goss: 3 failures"; exit 1; }
echo "qemu ok"'

# fetch-assets.sh: records its flags, checks the key arrived in its environment (by hash, so
# the stub itself never writes the key), and stages two files plus profile.json.
mkdir -p "$FAKE/tests/vm"
# shellcheck disable=SC2016
fake_script "$FAKE/scripts/fetch-assets.sh" '
echo "fetch $*" >>"$CALLS"
if [[ -n "${AIRLOCK_ABUSECH_KEY:-}" ]]; then
  if [[ "$(printf "%s" "$AIRLOCK_ABUSECH_KEY" | sha256sum | cut -d" " -f1)" == "${EXPECT_KEY_SHA:-}" ]]; then
    echo "fetch-key match" >>"$CALLS"
  else
    echo "fetch-key wrong" >>"$CALLS"
  fi
else
  echo "fetch-key none" >>"$CALLS"
fi
assets=""
args=("$@")
for ((i = 0; i < ${#args[@]}; i++)); do [[ "${args[i]}" == "--assets" ]] && assets="${args[i + 1]}"; done
[[ -d "$assets" ]] || { echo "fetch stub: no --assets dir" >&2; exit 1; }
mkdir -p "$assets/files/yara"
printf "rule test { condition: false }\n" >"$assets/files/yara/test.yar"
printf "ci data\n" >"$assets/files/ci.txt"
s1="$(sha256sum "$assets/files/yara/test.yar" | cut -d" " -f1)"
s2="$(sha256sum "$assets/files/ci.txt" | cut -d" " -f1)"
[[ "${FETCH_CORRUPT:-0}" == "1" ]] && printf "changed\n" >>"$assets/files/ci.txt"
cat >"$assets/profile.json" <<EOF
{"schema": 1, "profile": "ci", "files": [
 {"id": "yara_test", "sha256": "$s1", "target": "yara/test.yar", "verify": "sha256", "staged_at": "2026-11-15T00:00:00Z"},
 {"id": "ci_data", "sha256": "$s2", "target": "ci.txt", "verify": "sha256", "staged_at": "2026-11-15T00:00:00Z"}],
 "skipped": [], "case_defaults": {"examiner": "", "agency": "", "case_id_prefix": ""}}
EOF
echo "fetch ok"'

cat >"$FAKE/scripts/gen-manifest.py" <<'PY'
import os
import shutil
import sys

with open(os.environ["CALLS"], "a", encoding="utf-8") as fh:
    fh.write("gen-manifest " + " ".join(sys.argv[1:]) + "\n")
repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
shutil.copy(os.environ["FX"] + "/manifest.json", os.path.join(repo, "assets", "manifest.json"))
PY

cat >"$FX/manifest.json" <<EOF
{"schema": 1, "release": "test",
 "files": [
  {"id": "iso", "url": "https://example.invalid/iso", "size": $((3 * GB)), "sha256": null, "target": null, "profiles": ["build"], "verify": "sha256", "license": "x", "version": "1"},
  {"id": "model_a", "url": "https://example.invalid/a", "size": $((1 * GB)), "sha256": null, "target": "models/a", "profiles": ["default"], "verify": "sha256", "license": "x", "version": "1"},
  {"id": "hashes_b", "url": "https://example.invalid/b", "size": $((GB / 2)), "sha256": null, "target": "hashes/b", "profiles": ["default"], "verify": "sha256", "license": "x", "version": "1"},
  {"id": "yara_test", "url": "https://example.invalid/y", "size": 1000, "sha256": null, "target": "yara/test.yar", "profiles": ["ci", "default"], "verify": "sha256", "license": "x", "version": "1"},
  {"id": "huge", "url": "https://example.invalid/h", "size": $((30 * GB)), "sha256": null, "target": "huge", "profiles": ["big"], "verify": "sha256", "license": "x", "version": "1"}],
 "profiles": {
  "default": {"description": "Recommended", "features": {"malwarebazaar": true}, "files": ["model_a", "hashes_b", "yara_test"]},
  "minimal": {"description": "Smallest", "features": {"malwarebazaar": false}, "files": []},
  "ci": {"description": "CI only", "features": {"malwarebazaar": false}, "files": ["yara_test"]},
  "big": {"description": "Too big", "features": {"malwarebazaar": true}, "files": ["huge"]}}}
EOF
cp "$FX/manifest.json" "$FAKE/assets/manifest.json"

# A small but real AIRLOCK-shaped image: GPT with the five partitions of contract section 3,
# ASSETS formatted exFAT when the tools allow (part B).
mkdir -p "$FX/image"
make_image() {
  local raw="$FX/image/airlock-0.0.0-test.raw"
  rm -f "$raw"
  truncate -s 64M "$raw"
  if command -v sgdisk >/dev/null 2>&1; then
    sgdisk -n1:2048:+1M -t1:ef02 -c1:BIOSBOOT -n2:0:+8M -t2:ef00 -c2:EFI -n3:0:+24M -t3:0700 -c3:ASSETS \
      -n4:0:+8M -t4:0700 -c4:OUTPUT -n5:0:0 -t5:8300 -c5:AIRLOCK_ROOT "$raw" >/dev/null
  fi
  if [[ "${1:-}" == "exfat" ]]; then
    local loop
    loop="$(losetup -f --show "$raw")"
    partx -a "$loop" 2>/dev/null || true
    mkfs.exfat -L ASSETS "${loop}p3" >/dev/null
    partx -d "$loop" 2>/dev/null || true
    losetup -d "$loop"
  fi
  rm -f "$raw.zst"
  zstd -q -3 --long=27 "$raw" -o "$raw.zst"
  (cd "$FX/image" && sha256sum "$(basename "$raw")" "$(basename "$raw").zst" >SHA256SUMS)
}
make_image

# ---------------------------------------------------------------------------- PATH stubs
# shellcheck disable=SC2016 # stub bodies expand when the stub runs
stub id 'if [[ "${1:-}" == "-u" ]]; then echo "${FAKE_UID:-0}"; else exec /usr/bin/id "$@"; fi'
# shellcheck disable=SC2016
stub df 'echo "Filesystem 1B-blocks Used Available Capacity Mounted"; echo "fake 1 1 ${FAKE_AVAIL:-999999999999999} 1% /"'
# shellcheck disable=SC2016
stub curl 'if [[ "${FAKE_NET:-1}" == "1" ]]; then exit 0; else echo "curl: (6) Could not resolve host" >&2; exit 6; fi'
# shellcheck disable=SC2016
stub uname 'case "${1:-}" in -s) echo "${FAKE_UNAME_S:-Linux}" ;; -m) echo "${FAKE_UNAME_M:-x86_64}" ;; *) exec /usr/bin/uname "$@" ;; esac'

# Prerequisites stub for most runs (the real one is tested on its own below).
cp "$FAKE/scripts/prereqs.sh" "$FAKE/scripts/prereqs-real.sh"
# shellcheck disable=SC2016
fake_script "$FAKE/scripts/prereqs.sh" '
echo "prereqs $*" >>"$CALLS"
case " $* " in
  *" --goss-path "*) exit 1 ;;
  *" --check "*) if [[ "${PREREQS_MISSING:-0}" == "1" ]]; then echo "missing: zstd (apt package zstd)"; exit 3; fi; exit 0 ;;
  *) exit 0 ;;
esac'

COMMON_ENV=(env AIRLOCK_KVM_DEV="$TEST_TMP/no-kvm")
mk() { : >"$CALLS"; run "${COMMON_ENV[@]}" "$MAKE" --cache "$TEST_TMP/cache" --log "$TEST_TMP/build.log" "$@"; }
calls() { cat "$CALLS"; }
called() { grep -q "^$1" "$CALLS"; }
expect_fail() { # LABEL TEXT [args...]
  local label="$1" want="$2"
  shift 2
  mk "$@"
  [[ "$RC" -ne 0 ]] || fail "$label: expected failure, got exit 0: $OUT"
  assert_contains "$OUT" "$want" "$label"
  echo "ok: $label"
}

# ============================================================================ part A
# Usage errors.
mk --yes --profile ci
assert_eq "$RC" "2" "--yes without --target is a usage error"
assert_contains "$OUT" "--yes needs --target"
mk --yes --profile ci --target /dev/sdz
assert_eq "$RC" "2" "--yes without --confirm is a usage error"
mk --image-only --target /dev/sdz
assert_eq "$RC" "2" "--image-only with --target is a usage error"
mk --image-only --flash-only x
assert_eq "$RC" "2" "two modes at once is a usage error"
echo "ok: usage errors"

# Host checks (2A.1).
FAKE_UNAME_S=Darwin expect_fail "non-Linux host refused" "needs a Linux x86_64 computer" --image-only --accel tcg --yes
FAKE_UNAME_M=aarch64 expect_fail "non-x86_64 host refused" "needs a Linux x86_64 computer" --image-only --accel tcg --yes
expect_fail "no /dev/kvm refused" "no usable $TEST_TMP/no-kvm (KVM)" --image-only --yes
FAKE_UID=1000 expect_fail "full run without root refused" "needs root" --accel tcg --yes --profile ci --target /dev/sdz --confirm sdz
FAKE_AVAIL=1000 expect_fail "low disk space refused" "not enough free disk space" --image-only --accel tcg --yes
rm -rf "$TEST_TMP/cache"
FAKE_NET=0 expect_fail "no internet refused" "no internet: cannot reach releases.ubuntu.com" --image-only --accel tcg --yes
! called build || fail "a refused host check must not build"

# Prerequisites: missing items offered for install; with --yes they are installed.
PREREQS_MISSING=1 mk --image-only --accel tcg </dev/null
[[ "$RC" -ne 0 ]] || fail "missing prerequisites without --yes and no terminal must stop"
assert_contains "$OUT" "missing: zstd" "missing prerequisites listed"
assert_contains "$OUT" "no terminal to ask"
! grep -q -- "--install" "$CALLS" || fail "must not install without consent"
PREREQS_MISSING=1 mk --image-only --accel tcg --yes
assert_contains "$(calls)" "prereqs --install --yes --for build" "prerequisites installed after --yes"
echo "ok: prerequisites offered and installed"

# --image-only: build then boot tests, nothing else; FAKE_UID 1000 (no root needed).
rm -rf "$FAKE/output"
FAKE_UID=1000 mk --image-only --accel tcg --yes
[[ "$RC" -eq 0 ]] || fail "--image-only: exit $RC: $OUT"
order="$(grep -oE '^(build|qemu|flash|fetch|gen-manifest)' "$CALLS" | paste -sd, -)"
assert_eq "$order" "build,qemu" "--image-only step order"
assert_contains "$(calls)" "build --cache $TEST_TMP/cache --output $FAKE/output/airlock-" "build flags"
assert_contains "$(calls)" "--accel tcg" "accel passed on"
assert_contains "$(calls)" "qemu --image $FAKE/output/airlock-" "boot tests run on the raw image"
assert_contains "$OUT" "Build time:   8 hours or more" "build time estimate shown"
assert_contains "$OUT" "Image size:   about" "image size estimate shown"
assert_contains "$OUT" "Done. Image:" "image-only end message"
assert_file "$TEST_TMP/build.log"
assert_contains "$(cat "$TEST_TMP/build.log")" "build ok" "step output in build.log"
echo "ok: --image-only order, flags and log"

# Resume: the finished, tested image is reused; --rebuild builds again.
mk --image-only --accel tcg --yes
[[ "$RC" -eq 0 ]] || fail "resume: exit $RC: $OUT"
! called build || fail "resume must not rebuild a finished image: $(calls)"
! called qemu || fail "resume must not repeat passed boot tests: $(calls)"
assert_contains "$OUT" "reusing the finished image"
mk --image-only --accel tcg --yes --rebuild
[[ "$RC" -eq 0 ]] || fail "--rebuild: exit $RC: $OUT"
assert_contains "$(calls)" "--force" "--rebuild replaces the output folder"
echo "ok: resume and --rebuild"

# A damaged image in the output folder is rebuilt, not reused.
printf 'X' | dd of="$(ls "$FAKE"/output/*/airlock-*.raw)" bs=1 seek=4096 conv=notrunc status=none
mk --image-only --accel tcg --yes
[[ "$RC" -eq 0 ]] || fail "damaged image: exit $RC: $OUT"
called build || fail "an image that no longer matches SHA256SUMS must be rebuilt"
echo "ok: damaged image rebuilt"

# Failure handling (2A.5): the failing step is named, the log has the detail.
BUILD_FAIL=1 mk --image-only --accel tcg --yes --rebuild
assert_eq "$RC" "1" "failed build exit"
assert_contains "$OUT" 'step "build the image" failed' "failing step named"
assert_contains "$(cat "$TEST_TMP/build.log")" "packer exploded" "failure detail in build.log"
! called qemu || fail "no boot tests after a failed build"
mk --image-only --accel tcg --yes
QEMU_FAIL=1 mk --image-only --accel tcg --yes --rebuild
assert_eq "$RC" "1" "failed boot tests exit"
assert_contains "$OUT" 'step "boot tests in QEMU" failed' "failing test step named"
echo "ok: failures named and logged"

# Drive, profile and key refusals (2A.2, 2A.3), with a fixed drive list.
cat >"$FX/list.json" <<EOF
[{"hotplug": true, "model": "Big Stick", "name": "sdz", "path": "/dev/sdz", "problem": "", "rm": true, "serial": "BIG1", "size": $((128 * GB)), "tran": "usb"},
 {"hotplug": true, "model": "Small Stick", "name": "sdt", "path": "/dev/sdt", "problem": "", "rm": true, "serial": "SM1", "size": $((32 * GB)), "tran": "usb"},
 {"hotplug": true, "model": "Busy Stick", "name": "sdm", "path": "/dev/sdm", "problem": "in use: unmount it first", "rm": true, "serial": "BZ1", "size": $((128 * GB)), "tran": "usb"}]
EOF
export FLASH_LIST_JSON="$FX/list.json"
base=(--accel tcg --yes --no-abuse-key)
expect_fail "too-small drive refused" "/dev/sdt is too small" "${base[@]}" --profile ci --target /dev/sdt --confirm sdt
expect_fail "busy drive refused" "/dev/sdm cannot be used: in use" "${base[@]}" --profile ci --target /dev/sdm --confirm sdm
expect_fail "unknown drive refused" "not a removable drive this tool can write" "${base[@]}" --profile ci --target /dev/sdq --confirm sdq
expect_fail "wrong confirmation refused" "does not match sdz" "${base[@]}" --profile ci --target /dev/sdz --confirm sdt
expect_fail "profile too big for ASSETS refused" "but the ASSETS partition holds" "${base[@]}" --profile big --target /dev/sdz --confirm sdz
expect_fail "unknown profile refused" "no profile named 'nosuch'" "${base[@]}" --profile nosuch --target /dev/sdz --confirm sdz
# shellcheck disable=SC2016 # a literal $(...) inside the key, never expanded
printf 'MARK%s\n' 'Q$(touch x)' >"$TEST_TMP/badkey2"
expect_fail "malformed key refused" "unexpected characters" --accel tcg --yes --profile default --target /dev/sdz --confirm sdz --abuse-key-file "$TEST_TMP/badkey2"
assert_not_contains "$OUT" 'MARKQ' "a refused key is not echoed"
! grep -q 'MARKQ' "$TEST_TMP/build.log" || fail "a refused key reached build.log"
! grep -qE '^(build|flash --image|fetch)' "$CALLS" || fail "refusals must happen before any step: $(calls)"
echo "ok: refusals happen before any step"

# Estimates for a named profile (2A.3), stopped at the final question (no terminal).
rm -rf "$FAKE/output"
mk --accel tcg --profile default --target /dev/sdz --confirm sdz --no-abuse-key </dev/null
assert_contains "$OUT" "Staged files: 3, 1.5 GB to download" "staged download estimate"
assert_contains "$OUT" "Build downloads: 3.0 GB" "build download estimate"
assert_contains "$OUT" "MalwareBazaar hash set will not be staged" "skipped key is reported"
assert_contains "$(cat "$TEST_TMP/build.log")" "MalwareBazaar hash set will not be staged" "skipped key is in the log"
assert_contains "$OUT" "Drive needed: at least" "drive size shown"
assert_contains "$OUT" "no terminal to ask" "stops at the start question without a terminal"
! called build || fail "nothing runs without the final yes"
echo "ok: estimates shown before anything runs"

# A missing manifest is made by scripts/gen-manifest.py (same code as 2B).
rm -f "$FAKE/assets/manifest.json"
mk --accel tcg --profile ci --target /dev/sdz --confirm sdz --no-abuse-key </dev/null
assert_contains "$(calls)" "gen-manifest" "gen-manifest.py runs when the manifest is missing"
assert_file "$FAKE/assets/manifest.json"
echo "ok: manifest made by gen-manifest.py"
unset FLASH_LIST_JSON

# The real prereqs.sh: lists what is missing and installs it with apt-get (2A.1).
MINBIN="$TEST_TMP/minbin"
mkdir -p "$MINBIN"
for c in bash env python3 sed grep head cat cut sha256sum install mkdir mv dirname basename tr; do
  p="$(PATH="${PATH#"$STUB_DIR:"}" command -v "$c")" || continue
  ln -sf "$p" "$MINBIN/$c"
done
printf '#!/bin/sh\necho 0\n' >"$MINBIN/id"
printf '#!/bin/sh\necho "apt-get $*" >>"%s"\n' "$CALLS" >"$MINBIN/apt-get"
printf '#!/bin/sh\necho "goss stub"\n' >"$MINBIN/goss"
chmod +x "$MINBIN/id" "$MINBIN/apt-get" "$MINBIN/goss"
: >"$CALLS"
run env -i "PATH=$MINBIN" "CALLS=$CALLS" AIRLOCK_OVMF_CODE=/nonexistent \
  "$FAKE/scripts/prereqs-real.sh" --check --for build --cache "$TEST_TMP/cache"
assert_eq "$RC" "3" "prereqs --check exit when something is missing"
assert_contains "$OUT" "missing: QEMU, runs the build VM and the boot tests (apt package qemu-system-x86)"
assert_contains "$OUT" "(apt package ovmf)"
assert_contains "$OUT" "(pinned download: scripts/build.sh --prepare-tools)"
assert_not_contains "$OUT" "lsblk" "--for build does not list flash-only tools"
run env -i "PATH=$MINBIN" "CALLS=$CALLS" AIRLOCK_OVMF_CODE=/nonexistent \
  "$FAKE/scripts/prereqs-real.sh" --install --for build --cache "$TEST_TMP/cache" </dev/null
[[ "$RC" -ne 0 ]] || fail "prereqs --install without --yes and no terminal must stop"
! grep -q apt-get "$CALLS" || fail "prereqs installed without consent"
run env -i "PATH=$MINBIN" "CALLS=$CALLS" AIRLOCK_OVMF_CODE=/nonexistent \
  "$FAKE/scripts/prereqs-real.sh" --install --yes --for all --cache "$TEST_TMP/cache"
assert_contains "$(calls)" "apt-get update -q"
install_line="$(grep '^apt-get install' "$CALLS")"
assert_contains "$install_line" "-y -q --no-install-recommends" "apt-get flags"
for pkg in qemu-system-x86 qemu-utils ovmf zstd curl openssl gdisk e2fsprogs util-linux exfatprogs; do
  assert_contains "$install_line " " $pkg " "apt-get installs $pkg"
done
assert_eq "$(grep -o ' util-linux' <<<"$install_line" | wc -l | tr -d ' ')" "1" "each package once"
assert_contains "$(calls)" "build --prepare-tools --cache $TEST_TMP/cache" "Packer fetched through build.sh --prepare-tools"
assert_eq "$RC" "1" "still missing after a no-op install"
assert_contains "$OUT" "still missing after the install"
rm -f "$MINBIN/goss"
run env -i "PATH=$MINBIN" "CALLS=$CALLS" "$FAKE/scripts/prereqs-real.sh" --install --yes --for build --cache "$TEST_TMP/cache"
assert_contains "$OUT" "has no SHA-256 yet, so goss is not downloaded" "an unpinned download is refused"
echo "ok: prereqs.sh lists, asks, installs with apt-get, refuses unpinned downloads"

# docs/quickstart.md covers both paths (2A.7, 2B.3) and the warnings the plan requires.
QS="$(cat "$REPO_ROOT/docs/quickstart.md")"
for want in "git clone" "sudo ./make-usb.sh" "--image-only" "Get-FileHash" "SHA256SUMS" \
  "**Rufus: use DD Image mode." "balenaEtcher" "fetch-assets.ps1" "scripts/flash.sh" "WSL2" \
  "untested" "64 GB" "USB SSD" "BitLocker" "Secure Boot" "hardware write blocker" \
  "software read-only policy"; do
  assert_contains "$QS" "$want" "docs/quickstart.md mentions '$want'"
done
assert_not_contains "$(grep -v 'not a write blocker\|hardware write blocker' <<<"$QS")" "write blocker" \
  "quickstart never calls the software policy a write blocker"
echo "ok: quickstart covers the Linux and Windows paths and the warnings"

# ============================================================================ part B
part_b_missing=""
if [[ "$(/usr/bin/id -u)" -ne 0 ]]; then
  part_b_missing="root"
elif ! losetup -f >/dev/null 2>&1; then
  part_b_missing="a free loop device"
else
  for c in sgdisk mkfs.exfat partx qemu-img losetup blkid; do
    command -v "$c" >/dev/null 2>&1 || part_b_missing="$c"
  done
  if [[ -z "$part_b_missing" ]] && ! grep -qw exfat /proc/filesystems &&
    ! modinfo exfat >/dev/null 2>&1 && ! command -v mount.exfat-fuse >/dev/null 2>&1; then
    part_b_missing="exFAT mount support (kernel exfat or exfat-fuse)"
  fi
fi
if [[ -n "$part_b_missing" ]]; then
  echo "part A passed"
  skip "loop-device part B needs $part_b_missing"
fi

make_image exfat
rm -rf "$FAKE/output"
LOOP_FILE="$TEST_TMP/usb.img"
truncate -s 64G "$LOOP_FILE"
LOOP="$(losetup -f --show "$LOOP_FILE")"
LOOP_NAME="$(basename "$LOOP")"
# shellcheck disable=SC2317,SC2329 # run by the exit trap
detach_loop() {
  local m
  for m in $(lsblk -rn -o MOUNTPOINT "$LOOP" 2>/dev/null); do umount "$m" 2>/dev/null || true; done
  partx -d "$LOOP" 2>/dev/null || true
  losetup -d "$LOOP" 2>/dev/null || true
}
on_exit detach_loop
export LOOP_NAME
export AIRLOCK_FLASH_TEST=1
# lsblk wrapper: the loop device is reported as a removable USB drive; everything else is real.
REAL_LSBLK="$(PATH="${PATH#"$STUB_DIR:"}" command -v lsblk)"
export REAL_LSBLK
# shellcheck disable=SC2016
stub lsblk '
if [[ " $* " == *" -d "* ]]; then
  "$REAL_LSBLK" "$@" | python3 -c "
import json, os, sys
d = json.load(sys.stdin)
for n in d.get(\"blockdevices\") or []:
    if n.get(\"name\") == os.environ[\"LOOP_NAME\"]:
        n[\"rm\"] = True; n[\"tran\"] = \"usb\"; n[\"serial\"] = \"LOOPTEST1\"; n[\"model\"] = \"Loop Stick\"
json.dump(d, sys.stdout)
"
else
  exec "$REAL_LSBLK" "$@"
fi'

KEY="TESTKEY-$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')"
printf '%s\n' "$KEY" >"$TEST_TMP/abuse.key"
chmod 0600 "$TEST_TMP/abuse.key"
EXPECT_KEY_SHA="$(printf '%s' "$KEY" | sha256sum | cut -d' ' -f1)"
export EXPECT_KEY_SHA

# 2A.8: the CI form, against a loop device.
mk --yes --profile ci --target "$LOOP" --confirm "$LOOP_NAME" --accel tcg --abuse-key-file "$TEST_TMP/abuse.key"
[[ "$RC" -eq 0 ]] || fail "full run on a loop device: exit $RC: $OUT"
order="$(grep -oE '^(build|qemu|flash --image|fetch |smoke-backing)' "$CALLS" | paste -sd, -)"
assert_eq "$order" "build,qemu,flash --image,fetch ,qemu,smoke-backing" "full run step order"
assert_contains "$(calls)" "flash --image $FAKE/output/airlock-" "flash gets the built image"
assert_contains "$(calls)" "--target $LOOP --yes --confirm $LOOP_NAME --headroom-gb 8 --expect-serial LOOPTEST1" "flash flags"
assert_contains "$(calls)" "fetch --yes --manifest $FAKE/assets/manifest.json --profile ci --assets " "fetch flags"
assert_contains "$(calls)" "--cache $TEST_TMP/cache" "fetch uses the same cache"
assert_contains "$(calls)" "fetch-key match" "the key reached the fetcher's environment"
assert_contains "$(calls)" "smoke-backing $LOOP" "smoke boot overlay is backed by the drive"
assert_contains "$(calls)" "--only ^smoke\\.yaml\$ --no-extra-disks --firmware uefi,bios --boot-bus usb" "smoke boot flags"
assert_contains "$OUT" "read back 2 staged file(s) from ASSETS" "staged files read back"
assert_contains "$OUT" "reads back correctly" "flash read-back ran"
assert_contains "$OUT" "is ready" "end message"
# The drive holds the image and the staged files.
# (ASSETS changed after the write, so only the GPT area still equals the image; flash.sh
# verified the whole written range before staging.)
raw="$(ls "$FAKE"/output/*/airlock-*.raw)"
assert_eq "$(head -c 1048576 "$LOOP" | sha256sum | cut -d' ' -f1)" "$(head -c 1048576 "$raw" | sha256sum | cut -d' ' -f1)" "GPT on the drive"
[[ -z "$(lsblk -rn -o MOUNTPOINT "$LOOP" | grep -v '^$' || true)" ]] || fail "ASSETS left mounted"
# The key is in no file anywhere: not the log, the cache, the output folder, or the drive.
key_files="$(grep -rlF --exclude=abuse.key --exclude=usb.img -e "$KEY" "$TEST_TMP" 2>/dev/null || true)"
[[ -z "$key_files" ]] || fail "the abuse.ch key was written to a file: $key_files"
if head -c $((64 * 1024 * 1024)) "$LOOP_FILE" | grep -qaF -- "$KEY"; then fail "the abuse.ch key was written to the drive"; fi
assert_not_contains "$OUT" "$KEY" "key not printed"
echo "ok: make-usb.sh --yes --profile ci against a loop device"

# A staged file that does not read back is caught and named.
FETCH_CORRUPT=1 mk --yes --profile ci --target "$LOOP" --confirm "$LOOP_NAME" --accel tcg --no-abuse-key
assert_eq "$RC" "1" "corrupted staging must fail"
assert_contains "$OUT" 'step "read back the staged files" failed' "verify step named"
assert_contains "$OUT" "ci_data: SHA-256 does not match profile.json"
assert_contains "$(calls)" "fetch-key none" "no key given, none passed"
! grep -q 'smoke-backing' "$CALLS" || fail "no smoke boot after a failed verify"
[[ -z "$(lsblk -rn -o MOUNTPOINT "$LOOP" | grep -v '^$' || true)" ]] || fail "ASSETS left mounted after a failure"
echo "ok: corrupted staged file caught"

# --flash-only: no build, no image boot tests; write, stage, verify, smoke.
zst="$(ls "$FAKE"/output/*/airlock-*.raw.zst)"
mk --yes --flash-only "$zst" --profile ci.yml --target "$LOOP" --confirm "$LOOP_NAME" --accel tcg --no-abuse-key
[[ "$RC" -eq 0 ]] || fail "--flash-only: exit $RC: $OUT"
order="$(grep -oE '^(build|qemu|flash --image|fetch |smoke-backing)' "$CALLS" | paste -sd, -)"
assert_eq "$order" "flash --image,fetch ,qemu,smoke-backing" "--flash-only step order"
assert_contains "$(calls)" "--profile ci --assets" "profile given as ci.yml is passed on as ci"
echo "ok: --flash-only"

pass "make-usb.sh and prereqs.sh"
