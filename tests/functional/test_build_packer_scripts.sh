#!/usr/bin/env bash
# packer/scripts/*.sh: the steps Packer runs in the build VM and on the build host.
#   postprocess.sh (1.6): refuses an image without the finalize marker, makes .zst and SHA256SUMS
#   run-ansible.sh (1.4): installs the repo copy and runs ansible-playbook -c local site.yml
#   finalize.sh    (1.5): removes build access, writes the marker, powers off; on failure never powers off
#   bootstrap.sh   (1.4): waits for cloud-init, installs Ansible, makes the upload folder
# Guest commands (ansible-playbook, apt-get, cloud-init, fstrim, systemctl) are stubs here.
# shellcheck source=tests/functional/lib.sh
. "$(dirname "$0")/lib.sh"
require_cmd zstd sha256sum python3

scripts="$REPO_ROOT/packer/scripts"

# ---------------------------------------------------------------- postprocess.sh
out="$TEST_TMP/out"
mkdir -p "$out"
head -c 3000000 /dev/urandom >"$out/airlock-test.raw"
truncate -s 64M "$out/airlock-test.raw" # sparse tail, like the real image
printf 'boot noise\nAIRLOCK-FINALIZE-OK\n' >"$out/serial.log"

run bash "$scripts/postprocess.sh" --output-dir "$out" --image airlock-test.raw --zstd-level 3
assert_eq "$RC" 0 "postprocess exit"
assert_file "$out/airlock-test.raw.zst"
assert_file "$out/SHA256SUMS"
assert_contains "$(cat "$out/SHA256SUMS")" "  airlock-test.raw"
assert_contains "$(cat "$out/SHA256SUMS")" "  airlock-test.raw.zst"
(cd "$out" && sha256sum --quiet -c SHA256SUMS) || fail "SHA256SUMS does not verify"
assert_eq "$(zstd -dc --long=27 "$out/airlock-test.raw.zst" | sha256sum | cut -d' ' -f1)" \
  "$(sha256_of "$out/airlock-test.raw")" "zst round trip"

# Same run through the AIRLOCK_PP_* variables Packer sets.
rm -f "$out/SHA256SUMS" "$out/airlock-test.raw.zst"
AIRLOCK_PP_OUTPUT_DIR="$out" AIRLOCK_PP_IMAGE=airlock-test.raw AIRLOCK_PP_SERIAL_LOG="$out/serial.log" \
  AIRLOCK_PP_ZSTD_LEVEL=1 run bash "$scripts/postprocess.sh"
assert_eq "$RC" 0 "postprocess via environment"
assert_file "$out/SHA256SUMS"

# No marker, a failure marker, or no serial log: refused.
printf 'boot noise only\n' >"$out/serial.log"
run bash "$scripts/postprocess.sh" --output-dir "$out" --image airlock-test.raw
assert_ne "$RC" 0 "missing marker must fail"
assert_contains "$OUT" "did not report success"
printf 'AIRLOCK-FINALIZE-OK\nAIRLOCK-FINALIZE-FAILED (exit 1)\n' >"$out/serial.log"
run bash "$scripts/postprocess.sh" --output-dir "$out" --image airlock-test.raw
assert_ne "$RC" 0 "failure marker must fail"
assert_contains "$OUT" "reported a failure"
run bash "$scripts/postprocess.sh" --output-dir "$out" --image airlock-test.raw --serial-log "$out/nope.log"
assert_ne "$RC" 0 "missing serial log must fail"
run bash "$scripts/postprocess.sh" --output-dir "$out" --image missing.raw --no-marker-check
assert_ne "$RC" 0 "missing image must fail"
run bash "$scripts/postprocess.sh" --output-dir "$out" --image airlock-test.raw --zstd-level 25 --no-marker-check
assert_ne "$RC" 0 "bad level must fail"

# ---------------------------------------------------------------- run-ansible.sh
stage="$TEST_TMP/stage"
mkdir -p "$stage/ansible" "$stage/profiles" "$stage/docs" "$stage/tests/goss"
printf 'file: {}\n' >"$stage/tests/goss/base.yaml"
printf -- '- hosts: airlock\n' >"$stage/ansible/site.yml"
printf '[defaults]\n' >"$stage/ansible/ansible.cfg"
chmod 0777 "$stage/ansible/site.yml"
calls="$TEST_TMP/calls"
stub ansible-playbook "
printf '%s\n' \"\$PWD\" \"\$ANSIBLE_CONFIG\" \"\$*\" >>'$calls'
for a in \"\$@\"; do if [[ \"\$a\" == @* ]]; then cat \"\${a#@}\" >>'$calls'; fi; done
if [[ -f '$TEST_TMP/second' ]]; then echo \"localhost : ok=10 changed=\${CHANGED:-0} failed=0\"; fi
touch '$TEST_TMP/second'"

repo="$TEST_TMP/opt/airlock/repo"
AIRLOCK_REPO_STAGE="$stage" AIRLOCK_REPO_DIR="$repo" AIRLOCK_BUILD_VARS_FILE="$TEST_TMP/vars.json" \
  AIRLOCK_BUILD_COMMIT=abc123 AIRLOCK_BUILD_DATE=2026-11-15T00:00:00Z \
  run bash "$scripts/run-ansible.sh"
assert_eq "$RC" 0 "run-ansible exit"
assert_file "$repo/ansible/site.yml"
assert_file "$repo/tests/goss/base.yaml" "tests/goss in the repo copy (provisioning self-test)"
[[ -d "$repo/docs" ]] || fail "docs/ missing from the repo copy"
assert_eq "$(stat -c %a "$repo/ansible/site.yml")" 755 "repo copy is not group/world writable"
assert_contains "$(cat "$calls")" "$repo/ansible"
assert_contains "$(cat "$calls")" "-c local -i inventory.ini site.yml -e @$TEST_TMP/vars.json"
vars="$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(d["airlock_phase"], d["base_build_commit"], d["base_build_date"])' "$TEST_TMP/vars.json")"
assert_eq "$vars" "image abc123 2026-11-15T00:00:00Z" "extra variables"

# Idempotence check: a second run that still changes something fails.
rm -f "$TEST_TMP/second"
AIRLOCK_REPO_STAGE="$stage" AIRLOCK_REPO_DIR="$repo" AIRLOCK_BUILD_VARS_FILE="$TEST_TMP/vars.json" \
  AIRLOCK_IDEMPOTENCE_CHECK=1 CHANGED=0 run bash "$scripts/run-ansible.sh"
assert_eq "$RC" 0 "idempotent second run passes"
rm -f "$TEST_TMP/second"
AIRLOCK_REPO_STAGE="$stage" AIRLOCK_REPO_DIR="$repo" AIRLOCK_BUILD_VARS_FILE="$TEST_TMP/vars.json" \
  AIRLOCK_IDEMPOTENCE_CHECK=1 CHANGED=2 run bash "$scripts/run-ansible.sh"
assert_ne "$RC" 0 "non-idempotent second run fails"
assert_contains "$OUT" "idempotence check failed"

# A missing upload is refused before anything is installed.
AIRLOCK_REPO_STAGE="$TEST_TMP/nothing" AIRLOCK_REPO_DIR="$TEST_TMP/repo2" run bash "$scripts/run-ansible.sh"
assert_ne "$RC" 0 "missing upload fails"
assert_no_file "$TEST_TMP/repo2"

# ---------------------------------------------------------------- finalize.sh
console="$TEST_TMP/console"
: >"$console"
cp "$scripts/finalize.sh" "$TEST_TMP/finalize.sh"
mkdir -p "$TEST_TMP/stage2"
printf '{}' >"$TEST_TMP/vars2.json"
: >"$calls"
stub fstrim 'echo "/: 1 GiB trimmed"'
stub fake-poweroff "touch '$TEST_TMP/powered-off'"
mkdir -p "$TEST_TMP/inputs2"
printf 'x' >"$TEST_TMP/inputs2/manifest.json"
AIRLOCK_REPO_DIR="$repo" AIRLOCK_BUILD_VARS_FILE="$TEST_TMP/vars2.json" AIRLOCK_REPO_STAGE="$TEST_TMP/stage2" \
  AIRLOCK_INPUTS_STAGE="$TEST_TMP/inputs2" \
  AIRLOCK_FINALIZE_CONSOLE="$console" AIRLOCK_FINALIZE_POWEROFF=fake-poweroff \
  run bash "$TEST_TMP/finalize.sh"
assert_eq "$RC" 0 "finalize exit"
assert_no_file "$TEST_TMP/inputs2" "build inputs upload folder removed"
assert_contains "$(cat "$calls")" "--tags airlock_finalize"
assert_contains "$(cat "$calls")" '{"base_finalize_build": true}'
assert_contains "$(cat "$console")" "AIRLOCK-FINALIZE-OK"
assert_file "$TEST_TMP/powered-off"
assert_no_file "$TEST_TMP/finalize.sh" "finalize deletes itself"
assert_no_file "$TEST_TMP/vars2.json" "build variables removed"
assert_no_file "$TEST_TMP/stage2" "upload folder removed"

# Ansible fails: FAILED marker, no OK marker, no power off.
: >"$console"
rm -f "$TEST_TMP/powered-off"
cp "$scripts/finalize.sh" "$TEST_TMP/finalize.sh"
printf '{}' >"$TEST_TMP/vars2.json"
stub ansible-playbook 'echo "TASK [base : Delete the build user] FAILED"; exit 2'
AIRLOCK_REPO_DIR="$repo" AIRLOCK_BUILD_VARS_FILE="$TEST_TMP/vars2.json" AIRLOCK_REPO_STAGE="$TEST_TMP/stage2" \
  AIRLOCK_FINALIZE_CONSOLE="$console" AIRLOCK_FINALIZE_POWEROFF=fake-poweroff \
  run bash "$TEST_TMP/finalize.sh"
assert_ne "$RC" 0 "finalize must fail when Ansible fails"
assert_contains "$(cat "$console")" "AIRLOCK-FINALIZE-FAILED"
assert_not_contains "$(cat "$console")" "AIRLOCK-FINALIZE-OK"
assert_no_file "$TEST_TMP/powered-off" "never powers off after a failure"

# ---------------------------------------------------------------- bootstrap.sh
: >"$calls"
stub cloud-init 'exit 2' # done with warnings: accepted
stub systemctl "echo systemctl \"\$*\" >>'$calls'"
stub apt-get "echo apt-get \"\$*\" >>'$calls'"
stub ansible-playbook 'echo "ansible-playbook [core 2.16.3]"'
AIRLOCK_BUILD_USER="$(id -un)" AIRLOCK_REPO_STAGE="$TEST_TMP/upload" AIRLOCK_INPUTS_STAGE="$TEST_TMP/inputs" \
  run bash "$scripts/bootstrap.sh"
assert_eq "$RC" 0 "bootstrap exit"
[[ -d "$TEST_TMP/upload/tests" ]] || fail "tests/ upload folder (for tests/goss) not created"
[[ -d "$TEST_TMP/inputs" ]] || fail "build inputs upload folder not created"
assert_contains "$(cat "$calls")" "install -y --no-install-recommends ansible python3-apt"
assert_contains "$(cat "$calls")" "DPkg::Lock::Timeout=900"
[[ -d "$TEST_TMP/upload" ]] || fail "upload folder not created"
stub cloud-init 'exit 1'
AIRLOCK_BUILD_USER="$(id -un)" AIRLOCK_REPO_STAGE="$TEST_TMP/upload" run bash "$scripts/bootstrap.sh"
assert_ne "$RC" 0 "cloud-init failure stops the build"
assert_contains "$OUT" "cloud-init failed"

pass "packer scripts"
