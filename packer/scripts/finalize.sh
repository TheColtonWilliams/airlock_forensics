#!/usr/bin/env bash
# Runs inside the build VM as root, started by Packer's shutdown_command through systemd-run
# so it keeps going after the build user (and its SSH session) is deleted.
# Removes build-time access (task 1.5: build user, SSH server, cloud-init, installer network
# config), prepares first boot (task 1.10), trims free space so the raw image stays sparse,
# writes AIRLOCK-FINALIZE-OK to the serial console, and powers off.
# On any failure it writes AIRLOCK-FINALIZE-FAILED and does NOT power off: Packer then hits
# shutdown_timeout and fails, and packer/scripts/postprocess.sh refuses an image without the
# OK marker. An image that still has build access is never published.
# Test: tests/functional/test_build_packer_scripts.sh
set -Eeuo pipefail

repo_dir="${AIRLOCK_REPO_DIR:-/opt/airlock/repo}"
vars_file="${AIRLOCK_BUILD_VARS_FILE:-/var/tmp/airlock-build-vars.json}"
repo_stage="${AIRLOCK_REPO_STAGE:-/var/tmp/airlock-repo}"
console="${AIRLOCK_FINALIZE_CONSOLE:-/dev/ttyS0}"
poweroff_cmd="${AIRLOCK_FINALIZE_POWEROFF:-systemctl poweroff}"

if ! { : >>"$console"; } 2>/dev/null; then
  console=/dev/null
fi

say() { printf 'airlock-finalize: %s\n' "$*" | tee -a -- "$console"; }
on_error() {
  local rc=$?
  printf 'AIRLOCK-FINALIZE-FAILED (exit %s). Build access may still be present; this image must not be used.\n' "$rc" |
    tee -a -- "$console" >&2
  exit "$rc"
}
trap on_error ERR

[[ -f "$repo_dir/ansible/site.yml" ]] || {
  say "no repo copy at $repo_dir"
  false
}
[[ -f "$vars_file" ]] || {
  say "no build variables at $vars_file"
  false
}

cd -- "$repo_dir/ansible"
export ANSIBLE_CONFIG="$repo_dir/ansible/ansible.cfg"
export ANSIBLE_FORCE_COLOR=0
export PYTHONUNBUFFERED=1

say "removing build access (ansible tag airlock_finalize)"
ansible-playbook -c local -i inventory.ini site.yml --tags airlock_finalize \
  -e "@$vars_file" -e '{"base_finalize_build": true}' 2>&1 | tee -a -- "$console"

rm -rf -- "$repo_stage" "$vars_file"

say "trimming free space so the raw image stays sparse"
fstrim -av 2>&1 | tee -a -- "$console" || say "fstrim reported a problem; the image is still valid but compresses less"
sync

printf 'AIRLOCK-FINALIZE-OK\n' | tee -a -- "$console"
rm -f -- "$0"
# shellcheck disable=SC2086 # the override is a command line on purpose (tests use a stub)
$poweroff_cmd
