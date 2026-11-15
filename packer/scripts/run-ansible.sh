#!/usr/bin/env bash
# Runs inside the build VM as root (task 1.4): installs the uploaded repo copy at
# /opt/airlock/repo (docs/dev/contract.md section 2) and runs
#   ansible-playbook -c local site.yml
# with airlock_phase=image. With AIRLOCK_IDEMPOTENCE_CHECK=1 it runs the playbook again and
# fails if any task still reports a change.
# Test: tests/functional/test_build_packer_scripts.sh
set -euo pipefail

repo_stage="${AIRLOCK_REPO_STAGE:-/var/tmp/airlock-repo}"
repo_dir="${AIRLOCK_REPO_DIR:-/opt/airlock/repo}"
vars_file="${AIRLOCK_BUILD_VARS_FILE:-/var/tmp/airlock-build-vars.json}"
idempotence_check="${AIRLOCK_IDEMPOTENCE_CHECK:-0}"

log() { printf 'airlock-run-ansible: %s\n' "$*"; }
die() {
  printf 'airlock-run-ansible: %s\n' "$*" >&2
  exit 1
}

[[ -f "$repo_stage/ansible/site.yml" ]] ||
  die "no ansible/site.yml under $repo_stage. The Packer file upload did not run; rerun scripts/build.sh."

log "installing the repo copy at $repo_dir"
install -d -m 0755 -- "$(dirname -- "$repo_dir")"
rm -rf -- "$repo_dir.new"
cp -a -- "$repo_stage" "$repo_dir.new"
chown -R 0:0 -- "$repo_dir.new"
chmod -R u+rwX,go+rX,go-w -- "$repo_dir.new"
rm -rf -- "$repo_dir"
mv -- "$repo_dir.new" "$repo_dir"

# Extra variables as a JSON file, so no value passes through a shell word split.
python3 - "$vars_file" <<'PY'
import json
import os
import sys

data = {
    "airlock_phase": "image",
    "base_build_commit": os.environ.get("AIRLOCK_BUILD_COMMIT", "unknown"),
    "base_build_date": os.environ.get("AIRLOCK_BUILD_DATE", "unknown"),
}
with open(sys.argv[1], "w", encoding="utf-8") as fh:
    json.dump(data, fh, sort_keys=True)
    fh.write("\n")
PY
chmod 0600 -- "$vars_file"

cd -- "$repo_dir/ansible"
export ANSIBLE_CONFIG="$repo_dir/ansible/ansible.cfg"
export ANSIBLE_FORCE_COLOR=0
export PYTHONUNBUFFERED=1
playbook=(ansible-playbook -c local -i inventory.ini site.yml -e "@$vars_file")

log "running: ${playbook[*]}"
"${playbook[@]}" || die "ansible-playbook failed. The first failed task is named above; fix it and rerun scripts/build.sh."

if [[ "$idempotence_check" == "1" ]]; then
  log "idempotence check: running site.yml again"
  second_log="$(mktemp)"
  "${playbook[@]}" | tee -- "$second_log" ||
    die "second ansible-playbook run failed. Read the output above."
  if grep -Eq 'changed=[1-9]' -- "$second_log"; then
    rm -f -- "$second_log"
    die "idempotence check failed: the second run still changed something (see the PLAY RECAP above)."
  fi
  rm -f -- "$second_log"
  log "idempotence check passed"
fi
log "ok"
