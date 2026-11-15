#!/usr/bin/env bash
# airlock-install-bootloader (task 1.9) on a loop disk with the AIRLOCK layout, then a real
# boot of that disk in QEMU (command line from tests/vm/lib/qemu.sh):
#   * legacy BIOS: i386-pc grub in the BIOS boot partition, booted under SeaBIOS;
#   * UEFI: signed shim + grub at EFI/BOOT/BOOTX64.EFI (no NVRAM entry, no fbx64.efi),
#     booted under OVMF and under OVMF with Secure Boot and Microsoft keys.
# grub reads a test grub.cfg that prints its platform and lockdown state on the serial port.
# The UEFI half of the installer needs a kernel that can mount FAT. Without it, the same
# signed files the installer would place (shim as EFI/BOOT/BOOTX64.EFI, signed grub, and
# the EFI/ubuntu/grub.cfg stub) are copied in with mtools, so the Secure Boot chain from
# the dated snapshot is still booted under OVMF (task 1.13); only the installer's UEFI
# step is then left to CI.
# shellcheck source=tests/functional/lib.sh
. "$(dirname "$0")/lib.sh"
# shellcheck source=tests/vm/lib/disks.sh
. "$REPO_ROOT/tests/vm/lib/disks.sh"
# shellcheck source=tests/vm/lib/qemu.sh
. "$REPO_ROOT/tests/vm/lib/qemu.sh"
require_loop
require_cmd grub-install sgdisk partx mkfs.ext4 mkfs.vfat qemu-system-x86_64 qemu-img
[[ -d /usr/lib/grub/i386-pc ]] || skip "needs grub-pc-bin (/usr/lib/grub/i386-pc)"

installer="$REPO_ROOT/ansible/roles/base/files/airlock-install-bootloader"
img="$TEST_TMP/disk.raw"
mnt="$TEST_TMP/mnt"
airlock_mini_layout_disk "$img" 160
dev="$(airlock_loop_attach "$img")" || fail "could not attach $img"
# shellcheck disable=SC2317 # run by on_exit
release() {
  umount "$mnt/boot/efi" 2>/dev/null || true
  umount "$mnt" 2>/dev/null || true
  airlock_loop_detach "$dev"
}
on_exit release
mkfs.vfat -n EFI "${dev}p2" >/dev/null
mkfs.ext4 -q -F -L AIRLOCK_ROOT "${dev}p5"
mkdir -p "$mnt"
mount "${dev}p5" "$mnt"
mkdir -p "$mnt/boot/efi" "$mnt/boot/grub"
cat >"$mnt/boot/grub/grub.cfg" <<'CFG'
set timeout=0
insmod serial
serial --unit=0 --speed=115200
terminal_input console serial
terminal_output console serial
echo "AIRLOCK-GRUB-OK platform=${grub_platform} lockdown=${lockdown}"
sleep 600
CFG

targets=bios
efi_note=""
if mount -t vfat "${dev}p2" "$mnt/boot/efi" 2>/dev/null; then
  if [[ -e /usr/lib/shim/shimx64.efi.signed && -d /usr/lib/grub/x86_64-efi-signed ]]; then
    targets=efi,bios
  else
    efi_note="UEFI half skipped: shim-signed and grub-efi-amd64-signed are not installed"
  fi
else
  efi_note="UEFI half skipped: this kernel cannot mount FAT"
fi

run "$installer" --disk "$dev" --boot-dir "$mnt/boot" --efi-dir "$mnt/boot/efi" --targets "$targets"
assert_eq "$RC" 0 "install: $OUT"
assert_contains "$OUT" "airlock-bootloader: changed"
run "$installer" --disk "$dev" --boot-dir "$mnt/boot" --efi-dir "$mnt/boot/efi" --targets "$targets"
assert_eq "$RC" 0 "second install"
assert_contains "$OUT" "airlock-bootloader: unchanged"

# Refuses a disk that does not hold the boot folder.
other="$TEST_TMP/other.raw"
airlock_mini_layout_disk "$other" 96
odev="$(losetup -f --show "$other")"
run "$installer" --disk "$odev" --boot-dir "$mnt/boot" --efi-dir "$mnt/boot/efi" --targets bios
losetup -d "$odev"
assert_eq "$RC" 1 "wrong disk refused"
assert_contains "$OUT" "refusing to write a boot loader"
run "$installer" --disk "$dev" --boot-dir "$mnt/boot" --targets floppy
assert_eq "$RC" 1 "bad target refused"

assert_file "$mnt/boot/grub/i386-pc/core.img"
if [[ "$targets" == efi,bios ]]; then
  assert_file "$mnt/boot/efi/EFI/BOOT/BOOTX64.EFI"
  assert_file "$mnt/boot/efi/EFI/BOOT/grubx64.efi"
  assert_file "$mnt/boot/efi/EFI/ubuntu/grub.cfg"
  assert_no_file "$mnt/boot/efi/EFI/BOOT/fbx64.efi" "shim fallback would write the host's NVRAM"
  cmp -s "$mnt/boot/efi/EFI/BOOT/BOOTX64.EFI" /usr/lib/shim/shimx64.efi.signed ||
    fail "BOOTX64.EFI is not the signed shim"
  umount "$mnt/boot/efi"
fi
umount "$mnt"
sync

# Boot it. Each run gets an overlay, so the disk image stays as built.
boot_and_expect() { # FIRMWARE EXPECTED-TEXT
  local fw="$1" want="$2" pid i
  Q_FIRMWARE="$fw" Q_ACCEL="$(airlock_qemu_accel)" Q_BOOT_BUS=virtio Q_MEMORY=512 Q_CPUS=1 Q_NIC=0
  Q_OVERLAY="$TEST_TMP/overlay-$fw.qcow2" Q_VARS="$TEST_TMP/vars-$fw.fd"
  Q_QGA_SOCKET="$TEST_TMP/qga-$fw.sock" Q_SERIAL_LOG="$TEST_TMP/serial-$fw.log" Q_DISKS=()
  qemu-img create -q -f qcow2 -F raw -b "$img" "$Q_OVERLAY"
  if [[ "$fw" == uefi* ]]; then
    [[ -f "$(airlock_ovmf_code "$fw")" ]] || { echo "note: $fw firmware not installed"; return 0; }
    cp "$(airlock_ovmf_vars_template "$fw")" "$Q_VARS"
  fi
  airlock_qemu_argv
  "${QEMU_ARGV[@]}" >"$TEST_TMP/qemu-$fw.log" 2>&1 &
  pid=$!
  for ((i = 0; i < 180; i++)); do
    grep -aq 'AIRLOCK-GRUB-OK' "$Q_SERIAL_LOG" 2>/dev/null && break
    kill -0 "$pid" 2>/dev/null || break
    sleep 1
  done
  kill "$pid" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true
  local got
  got="$(tr -d '\r' <"$Q_SERIAL_LOG" | grep -aoE 'AIRLOCK-GRUB-OK platform=[a-z]* lockdown=[a-z]?' | head -n1)"
  [[ -n "$got" ]] || fail "$fw: grub did not start from the disk (see $Q_SERIAL_LOG, $TEST_TMP/qemu-$fw.log)"
  assert_contains "$got" "$want" "$fw boot"
  echo "booted ($fw): $got"
}

# No FAT support here: place the signed chain with mtools (no mount needed).
if [[ "$targets" == bios ]] && command -v mcopy >/dev/null 2>&1 &&
  [[ -e /usr/lib/shim/shimx64.efi.signed && -e /usr/lib/grub/x86_64-efi-signed/grubx64.efi.signed ]]; then
  esp_off=$(($(sgdisk -i 2 "$img" | awk '/^First sector/ {print $3}') * 512))
  root_uuid="$(blkid -p -s UUID -o value "${dev}p5")"
  printf "search.fs_uuid %s root\nset prefix=(\$root)'/boot/grub'\nconfigfile \$prefix/grub.cfg\n" "$root_uuid" >"$TEST_TMP/stub.cfg"
  m=(-i "$img@@$esp_off")
  mmd "${m[@]}" ::/EFI ::/EFI/BOOT ::/EFI/ubuntu
  mcopy "${m[@]}" /usr/lib/shim/shimx64.efi.signed ::/EFI/BOOT/BOOTX64.EFI
  mcopy "${m[@]}" /usr/lib/grub/x86_64-efi-signed/grubx64.efi.signed ::/EFI/BOOT/grubx64.efi
  mcopy "${m[@]}" "$TEST_TMP/stub.cfg" ::/EFI/ubuntu/grub.cfg
  targets=efi-files,bios
  efi_note="installer UEFI step skipped (no FAT in this kernel); signed shim and grub placed with mtools and booted"
fi

boot_and_expect bios "platform=pc"
if [[ "$targets" == efi* ]]; then
  boot_and_expect uefi "platform=efi"
  boot_and_expect uefi-sb "platform=efi lockdown=y"
fi
[[ -z "$efi_note" ]] || echo "note: $efi_note"

pass "portable boot loader"
