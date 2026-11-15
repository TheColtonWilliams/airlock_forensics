#!/usr/bin/env bash
# Runs inside the build VM as root, as Packer's first provisioner (task 1.4).
# Waits for cloud-init, then installs Ansible from the dated apt snapshot that the
# autoinstall configured (task 6.1), and makes the upload folder for the repo copy.
# Test: tests/functional/test_build_packer_scripts.sh
set -euo pipefail

build_user="${AIRLOCK_BUILD_USER:-airlock-build}"
repo_stage="${AIRLOCK_REPO_STAGE:-/var/tmp/airlock-repo}"
apt_lock_timeout="${AIRLOCK_APT_LOCK_TIMEOUT:-900}"

log() { printf 'airlock-bootstrap: %s\n' "$*"; }
die() {
  printf 'airlock-bootstrap: %s\n' "$*" >&2
  exit 1
}

if command -v cloud-init >/dev/null 2>&1; then
  log "waiting for cloud-init to finish"
  rc=0
  cloud-init status --wait >/dev/null || rc=$?
  # 0: done. 2: done with recoverable warnings (deprecated keys and similar).
  if [[ "$rc" -ne 0 && "$rc" -ne 2 ]]; then
    die "cloud-init failed (exit $rc). Read /var/log/cloud-init-output.log in the build VM, then rerun scripts/build.sh."
  fi
fi

# First boot starts apt timers that hold the dpkg lock. Stop them; apt below also waits.
systemctl stop apt-daily.timer apt-daily-upgrade.timer unattended-upgrades.service >/dev/null 2>&1 || true

export DEBIAN_FRONTEND=noninteractive
apt_opts=(-o "DPkg::Lock::Timeout=${apt_lock_timeout}" -o "Acquire::Retries=5")

log "apt sources in use:"
grep -rhE '^(URIs|deb) ' /etc/apt/sources.list /etc/apt/sources.list.d/ 2>/dev/null | sed 's/^/  /' || true

apt-get "${apt_opts[@]}" update ||
  die "apt-get update failed. Check that the build VM reaches the apt snapshot mirror, then rerun scripts/build.sh."
# 'ansible' (not only ansible-core) so roles may use the collections Ubuntu ships with it.
apt-get "${apt_opts[@]}" install -y --no-install-recommends ansible python3-apt ||
  die "installing Ansible failed. Read the apt output above, then rerun scripts/build.sh."

install -d -m 0750 -o "$build_user" -g "$build_user" -- "$repo_stage" ||
  die "could not create $repo_stage for the repo upload."
log "ok: $(ansible-playbook --version | head -n1)"
