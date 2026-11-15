#!/usr/bin/env bash
# /etc/grub.d/41_airlock_usb_compat (task 1.12): the "USB compatibility mode (UAS off)"
# boot entry. Run as update-grub would, with the kernel command line from the rendered
# 90-airlock.cfg, against a stub grub-mkconfig_lib. Checks the entry boots the current
# kernel by root UUID with every AIRLOCK kernel parameter plus modprobe.blacklist=uas, adds
# a usb-storage quirk only when one is configured and well formed, names no vendor by
# default, and is valid grub script.
# shellcheck source=tests/functional/lib.sh
. "$(dirname "$0")/lib.sh"
require_cmd python3
python3 -c 'import jinja2, yaml' 2>/dev/null || skip "needs python3-jinja2 and python3-yaml"

script="$REPO_ROOT/ansible/roles/base/files/41_airlock_usb_compat"
role="$REPO_ROOT/ansible/roles/base"

# Render 90-airlock.cfg from group_vars and role defaults, then read it like grub-mkconfig.
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
export GRUB_CMDLINE_LINUX GRUB_CMDLINE_LINUX_DEFAULT

mkdir -p "$TEST_TMP/grub" "$TEST_TMP/root/boot"
cat >"$TEST_TMP/grub/grub-mkconfig_lib" <<'LIB'
prepare_grub_to_access_device() { echo "insmod part_gpt"; echo "insmod ext2"; echo "search --no-floppy --fs-uuid --set=root 0b1c2d3e"; }
make_system_path_relative_to_its_root() { echo "$1"; }
LIB
: >"$TEST_TMP/root/boot/vmlinuz"
: >"$TEST_TMP/root/boot/initrd.img"
export pkgdatadir="$TEST_TMP/grub" AIRLOCK_GRUB_SYSROOT="$TEST_TMP/root"
export GRUB_DEVICE_UUID=0b1c2d3e GRUB_DEVICE_BOOT=/dev/sda5
quirks="$TEST_TMP/usb-storage-quirks"
export AIRLOCK_USB_QUIRKS_FILE="$quirks"

printf '# empty: UAS off for every device\n\n' >"$quirks"
run bash "$script"
assert_eq "$RC" 0 "entry: $OUT"
assert_contains "$OUT" "menuentry 'Ubuntu, AIRLOCK USB compatibility mode (UAS off)'"
assert_contains "$OUT" "'airlock-usb-compat'"
linux_line="$(printf '%s\n' "$OUT" | grep -P '^\tlinux\t')"
assert_contains "$linux_line" "/boot/vmlinuz root=UUID=0b1c2d3e ro "
for p in $GRUB_CMDLINE_LINUX; do
  [[ " ${linux_line#*$'\t'} " == *" $p "* ]] || fail "kernel parameter $p missing from the entry"
done
assert_contains "$linux_line" " modprobe.blacklist=uas"
assert_not_contains "$OUT" "usb-storage.quirks" "no vendor quirk by default"
assert_contains "$OUT" "initrd	/boot/initrd.img"
assert_contains "$OUT" "search --no-floppy --fs-uuid --set=root"

if command -v grub-script-check >/dev/null 2>&1; then
  { echo 'menuentry_id_option="--id"'; echo 'function load_video { true; }'; printf '%s\n' "$OUT"; } >"$TEST_TMP/check.cfg"
  grub-script-check "$TEST_TMP/check.cfg" || fail "the entry is not valid grub script"
fi

# One site's quirk for one bridge.
printf '# from lsusb\n0000:0001:u\n' >"$quirks"
run bash "$script"
assert_eq "$RC" 0 "entry with quirk"
assert_contains "$OUT" " modprobe.blacklist=uas usb-storage.quirks=0000:0001:u"

# A malformed quirk is ignored with a warning; the entry still has UAS off.
printf 'ABCD:xyz:u\n' >"$quirks"
run bash "$script"
assert_eq "$RC" 0 "malformed quirk"
assert_contains "$OUT" "ignoring 'ABCD:xyz:u'"
assert_not_contains "$OUT" "usb-storage.quirks="
assert_contains "$OUT" "modprobe.blacklist=uas"

# No kernel symlink or no root UUID: no entry, and update-grub carries on.
rm -f "$TEST_TMP/root/boot/vmlinuz"
run bash "$script"
assert_eq "$RC" 0 "missing kernel"
assert_not_contains "$OUT" "menuentry"
: >"$TEST_TMP/root/boot/vmlinuz"
GRUB_DEVICE_UUID="" run bash "$script"
assert_eq "$RC" 0 "missing UUID"
assert_not_contains "$OUT" "menuentry"

# Root by UUID only, never by device name.
assert_not_contains "$linux_line" "root=/dev/"

pass "USB compatibility boot entry"
