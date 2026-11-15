#!/usr/bin/env bash
# Tasks 4.10, 4.11, 4F.6: run the session_tools role for real with every path pointed into a
# temporary folder (no users, no apt), check what it installed, then run it again and require
# zero changes (idempotence).
# shellcheck source=tests/functional/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

require_cmd ansible-playbook python3
require_root # files are installed owned by root, as on the image

# A snapshot of the repo parts the role reads (ansible/, tests/goss/, docs/), so concurrent
# edits or byte-compiles in the working tree cannot make the second run look non-idempotent.
SRC="$TEST_TMP/src"
mkdir -p "$SRC/tests"
cp -a -- "$REPO_ROOT/ansible" "$SRC/ansible"
cp -a -- "$REPO_ROOT/tests/goss" "$SRC/tests/goss"
cp -a -- "$REPO_ROOT/docs" "$SRC/docs"
find "$SRC" -name __pycache__ -type d -prune -exec rm -rf -- {} +

ROOT="$TEST_TMP/root"
mkdir -p "$ROOT/home/analyst" "$ROOT/usr/share/applications" "$ROOT/usr/local/bin"
VARS="$TEST_TMP/vars.json"
python3 - "$VARS" "$ROOT" "$SRC" <<'PY'
import json
import sys

out, root, repo = sys.argv[1], sys.argv[2], sys.argv[3]
data = {
    "airlock_user": "root",
    "airlock_parse_user": "airlock-parse",
    "airlock_opt_dir": f"{root}/opt/airlock",
    "airlock_repo_dir": f"{root}/opt/airlock/repo",
    "airlock_etc_dir": f"{root}/etc/airlock",
    "airlock_state_dir": f"{root}/var/lib/airlock",
    "airlock_session_dir": f"{root}/var/log/forensic-session",
    "airlock_output_mount": "/srv/airlock/output",
    "image_max_age_days": 90,
    "session_tools_bin_dir": f"{root}/usr/local/bin",
    "session_tools_applications_dir": f"{root}/usr/share/applications",
    "session_tools_analyst_home": f"{root}/home/analyst",
    "session_tools_mount_base": f"{root}/mnt/airlock",
    "session_tools_repo_src": repo,
    "session_tools_manage_users": False,
    "session_tools_install_packages": False,
    "session_tools_include_provision_unit": False,
}
with open(out, "w", encoding="utf-8") as fh:
    json.dump(data, fh, sort_keys=True)
PY

cat >"$TEST_TMP/play.yml" <<'YML'
- name: Apply session_tools into a temporary root
  hosts: localhost
  connection: local
  gather_facts: false
  become: false
  roles:
    - role: session_tools
YML

# shellcheck disable=SC2317 # called through run
play() {
  ANSIBLE_ROLES_PATH="$SRC/ansible/roles" ANSIBLE_NOCOLOR=1 ANSIBLE_RETRY_FILES_ENABLED=0 \
    ANSIBLE_LOCALHOST_WARNING=0 ANSIBLE_INVENTORY_UNPARSED_WARNING=0 \
    ansible-playbook -i localhost, "$TEST_TMP/play.yml" -e "@$VARS"
}

run play
assert_eq "$RC" 0 "first role run: $OUT"
assert_contains "$OUT" "Compile Python packages" "pylib compile handler ran"

mode_of() { stat -c '%a' -- "$1"; }

# Commands: every file in files/bin, 0755.
for f in "$SRC"/ansible/roles/session_tools/files/bin/*; do
  name="$(basename -- "$f")"
  assert_file "$ROOT/usr/local/bin/$name" "command $name installed"
  assert_eq "$(mode_of "$ROOT/usr/local/bin/$name")" 755 "mode of $name"
done
for name in forensic-session-start evidence-unlock-output evidence-mount evidence-hash evidence-triage; do
  assert_file "$ROOT/usr/local/bin/$name" "session command $name"
done
# No network toggle is shipped (task 4.10).
if find "$ROOT/usr/local/bin" -maxdepth 1 -iregex '.*net\(work\)?[-_]?\(on\|up\|enable\).*' | grep -q .; then
  fail "a network toggle command was installed"
fi

# Python packages, compiled.
assert_file "$ROOT/opt/airlock/lib/python/airlock_session/start.py"
assert_file "$ROOT/opt/airlock/lib/python/airlock_common/sessionlog.py"
compgen -G "$ROOT/opt/airlock/lib/python/airlock_session/__pycache__/start.*.pyc" >/dev/null ||
  fail "airlock_session was not byte-compiled"
assert_file "$ROOT/opt/airlock/lib/airlock-log.sh"
assert_eq "$(mode_of "$ROOT/opt/airlock/lib/airlock-log.sh")" 644 "log library mode"

# The installed copy works: evidence-hash on a file, through the installed paths.
printf 'airlock\n' >"$TEST_TMP/x.bin"
run env AIRLOCK_PYLIB="$ROOT/opt/airlock/lib/python" "$ROOT/usr/local/bin/evidence-hash" --json "$TEST_TMP/x.bin"
assert_eq "$RC" 0 "installed evidence-hash runs: $OUT"
assert_contains "$OUT" "$(sha256_of "$TEST_TMP/x.bin")" "installed evidence-hash prints the SHA-256"

# Folders and modes.
assert_eq "$(mode_of "$ROOT/etc/airlock")" 755 "/etc/airlock mode"
assert_eq "$(mode_of "$ROOT/var/lib/airlock")" 750 "/var/lib/airlock mode"
assert_eq "$(mode_of "$ROOT/var/log/forensic-session")" 2750 "session log folder mode"
assert_eq "$(stat -c '%U:%G' -- "$ROOT/var/log/forensic-session")" "root:adm" "session log folder owner"

# Config.
CONF="$ROOT/etc/airlock/airlock.conf.json"
assert_file "$CONF"
got="$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(d["image_max_age_days"], d["nsrl_path"], d["cases_dir"], d["schema"])' "$CONF")"
assert_eq "$got" "90 /srv/airlock/output/nsrl /srv/airlock/output/cases 1" "airlock.conf.json values"
for f in "$SRC"/ansible/roles/session_tools/files/etc/*; do
  [[ -e "$f" ]] || continue
  assert_file "$ROOT/etc/airlock/$(basename -- "$f")" "config file $(basename -- "$f")"
done

# Repo copy for offline provisioning.
assert_file "$ROOT/opt/airlock/repo/ansible/site.yml" "repo copy: site.yml"
assert_file "$ROOT/opt/airlock/repo/ansible/group_vars/all/pins.yml" "repo copy: pins"
assert_file "$ROOT/opt/airlock/repo/ansible/group_vars/all/profiles.yml" "repo copy: profiles"
assert_file "$ROOT/opt/airlock/repo/tests/goss/session_tools.yaml" "repo copy: goss files"
# evidence-report cites docs/known-limitations.md by path and SHA-256 (repo_copy.yml).
assert_file "$ROOT/opt/airlock/repo/docs/known-limitations.md" "repo copy: known limitations"
assert_eq "$(sha256_of "$ROOT/opt/airlock/repo/docs/known-limitations.md")" \
  "$(sha256_of "$SRC/docs/known-limitations.md")" "repo copy: known limitations unchanged"

# Launchers.
assert_file "$ROOT/usr/share/applications/airlock-session-start.desktop"
assert_file "$ROOT/usr/share/applications/airlock-forensic-analyze.desktop"
AUTO="$ROOT/home/analyst/.config/autostart/airlock-session-start.desktop"
assert_file "$AUTO" "autostart entry"
assert_contains "$(cat "$AUTO")" "forensic-session-start --pause-at-end" "autostart runs session start"

# Idempotence: the second run changes nothing.
run play
assert_eq "$RC" 0 "second role run: $OUT"
recap="$(grep -E '^localhost +:' <<<"$OUT" || true)"
assert_contains "$recap" "changed=0" "second run must change nothing: $(grep -E -B3 '^changed:' <<<"$OUT" || true)"

pass "session_tools role installs commands, packages, folders, config, launchers; idempotent"
