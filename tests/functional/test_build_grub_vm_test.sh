#!/usr/bin/env bash
# /etc/grub.d/06_airlock_vm_test (task 1.11, harness support for airlock.noprovision).
# Runs the snippet as update-grub would and checks: it prints only grub script, accepts only the
# exact OEM string "airlock.noprovision", exports airlock_test_args, and is valid grub script
# together with a linux line built from the rendered 90-airlock.cfg (when grub-script-check is
# installed). Also checks tests/vm/lib/qemu.sh passes that OEM string only when asked.
# The grub smbios command itself only runs in a booted guest (tests/run-qemu-tests.sh).
# The strings below are grub script and must stay literal.
# shellcheck disable=SC2016
# shellcheck source=tests/functional/lib.sh
. "$(dirname "$0")/lib.sh"
require_cmd python3
python3 -c 'import jinja2, yaml' 2>/dev/null || skip "needs python3-jinja2 and python3-yaml"

role="$REPO_ROOT/ansible/roles/base"
script="$role/files/06_airlock_vm_test"

run sh "$script"
assert_eq "$RC" 0 "hook exit: $OUT"
hook="$OUT"
assert_contains "$hook" 'smbios --type 11 --get-string 4 --set airlock_oem_string'
assert_contains "$hook" '[ "${airlock_oem_string}" = "airlock.noprovision" ]'
assert_contains "$hook" 'set airlock_test_args="airlock.noprovision"'
assert_contains "$hook" 'export airlock_test_args'
assert_not_contains "$hook" 'set airlock_test_args="${airlock_oem_string}"' "firmware text is never copied"
# The only value it can ever set is the literal word.
sets="$(printf '%s\n' "$hook" | grep -o 'set airlock_test_args="[^"]*"' | sort -u | tr '\n' ' ')"
assert_eq "$sets" 'set airlock_test_args="" set airlock_test_args="airlock.noprovision" ' "values set"

# 90-airlock.cfg appends the grub variable (not its value) to the default entries only.
python3 - "$role" "$REPO_ROOT/ansible/group_vars/all/main.yml" "$TEST_TMP/90-airlock.cfg" <<'PY'
import sys
from pathlib import Path

import jinja2
import yaml

role, main, out = Path(sys.argv[1]), sys.argv[2], sys.argv[3]
values = {**yaml.safe_load(open(main)), **yaml.safe_load(open(role / "defaults" / "main.yml"))}
env = jinja2.Environment(loader=jinja2.FileSystemLoader(str(role / "templates")),
                         undefined=jinja2.StrictUndefined, keep_trailing_newline=True)
Path(out).write_text(env.get_template("90-airlock.cfg.j2").render(**values))
PY
# shellcheck source=/dev/null
. "$TEST_TMP/90-airlock.cfg"
assert_eq "$GRUB_CMDLINE_LINUX_DEFAULT" 'quiet splash $airlock_test_args' "default args keep the grub variable"
assert_not_contains "$GRUB_CMDLINE_LINUX" "airlock" "the hardening line has no test word"

# A linux line the way 10_linux writes it, after the hook, must be valid grub script.
{
  printf '%s\n' "$hook"
  printf "menuentry 'Ubuntu' {\n\tlinux\t/boot/vmlinuz root=UUID=0b1c2d3e ro %s %s\n\tinitrd\t/boot/initrd.img\n}\n" \
    "$GRUB_CMDLINE_LINUX" "$GRUB_CMDLINE_LINUX_DEFAULT"
} >"$TEST_TMP/grub.cfg"
if command -v grub-script-check >/dev/null 2>&1; then
  grub-script-check "$TEST_TMP/grub.cfg" || fail "the hook is not valid grub script"
fi

# The harness side: the OEM string is passed only for a no-provision boot.
# shellcheck source=tests/vm/lib/qemu.sh
. "$REPO_ROOT/tests/vm/lib/qemu.sh"
Q_FIRMWARE=bios Q_ACCEL=tcg Q_OVERLAY=/x.qcow2 Q_VARS=/x.fd Q_BOOT_BUS=virtio Q_MEMORY=1024 Q_CPUS=1
Q_QGA_SOCKET=/x.sock Q_SERIAL_LOG=/x.log Q_NIC=0 Q_DISKS=()
Q_NOPROVISION=1
airlock_qemu_argv
assert_contains " ${QEMU_ARGV[*]} " " -smbios type=11,value=airlock.noprovision " "noprovision boot"
Q_NOPROVISION=0
airlock_qemu_argv
assert_not_contains " ${QEMU_ARGV[*]} " "smbios" "provisioning boot"

pass "VM test hook (airlock.noprovision)"
