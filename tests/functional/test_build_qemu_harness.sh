#!/usr/bin/env bash
# tests/run-qemu-tests.sh (tasks 1.11, 3.9) without a built image: the QEMU command lines
# for each firmware, boot bus and NIC choice; the test disks it builds (ext4, GPT swap, and
# LVM + mdraid + swap signatures for 3A.10); the payload copied into the guest; argument
# refusals; and a real QEMU launch of an unbootable image, which must fail cleanly with the
# guest-agent timeout, leave the image and the test disks unchanged, and keep the logs.
# shellcheck source=tests/functional/lib.sh
. "$(dirname "$0")/lib.sh"
# shellcheck source=tests/vm/lib/disks.sh
. "$REPO_ROOT/tests/vm/lib/disks.sh"
require_cmd qemu-img sgdisk mkfs.ext4 mkswap blkid python3 tar

harness="$REPO_ROOT/tests/run-qemu-tests.sh"
image="$TEST_TMP/airlock.raw"
truncate -s 256M "$image"

argv_for() { printf '%s\n' "$1" | grep "^qemu\[$2\]:"; }

# ---------------------------------------------------------------- command lines
run "$harness" --image "$image" --dry-run --firmware uefi,uefi-sb,bios --work "$TEST_TMP/w1" --accel tcg
assert_eq "$RC" 0 "dry run: $OUT"
uefi="$(argv_for "$OUT" uefi)"
sb="$(argv_for "$OUT" uefi-sb)"
bios="$(argv_for "$OUT" bios)"
assert_contains "$uefi" "OVMF_CODE_4M.fd"
assert_contains "$uefi" 'if=pflash\,format=raw\,unit=0\,readonly=on'
assert_contains "$sb" "OVMF_CODE_4M.secboot.fd"
assert_contains "$sb" 'q35\,smm=on'
assert_contains "$sb" 'property=secure\,value=on'
assert_not_contains "$bios" "pflash" "SeaBIOS boot uses no OVMF"
for line in "$uefi" "$sb" "$bios"; do
  assert_contains "$line" "-nic none" "no network device by default"
  assert_contains "$line" 'name=org.qemu.guest_agent.0'
  assert_contains "$line" 'format=qcow2\,file='"$TEST_TMP"'/w1/overlay-'
  assert_not_contains "$line" "file=$image" "the image itself is never attached"
  assert_contains "$line" 'serial=airlock-ext4'
  assert_contains "$line" 'serial=airlock-swap'
  assert_contains "$line" "-accel tcg"
  assert_contains "$line" "-display none"
done
assert_contains "$OUT" "overlay_size=$((256 * 1024 * 1024 + 4 * 1024 * 1024 * 1024))"
assert_contains "$OUT" "goss files: "

run "$harness" --image "$image" --dry-run --firmware bios --nic --boot-bus usb --no-extra-disks --grow-gib 1
assert_eq "$RC" 0 "dry run, usb + nic"
bios="$(argv_for "$OUT" bios)"
assert_contains "$bios" 'user\,model=virtio-net-pci\,restrict=on' "restricted NIC for the air-gap test"
assert_contains "$bios" 'usb-storage\,bus=xhci.0\,drive=bootdisk'
assert_not_contains "$bios" "airlock-ext4" "no test disks"

run "$harness" --image "$image" --dry-run --firmware bios --ntfs-fixture "$image" --only 'storage|airgap'
assert_eq "$RC" 0 "dry run, ntfs + only"
assert_contains "$(argv_for "$OUT" bios)" 'serial=airlock-ntfs'
assert_not_contains "$(printf '%s\n' "$OUT" | grep '^goss files')" "base.yaml" "--only filters goss files"

# ---------------------------------------------------------------- refusals
run "$harness" --dry-run
assert_eq "$RC" 2 "no image"
run "$harness" --image "$image.zst" --dry-run
assert_eq "$RC" 2 "compressed image refused"
assert_contains "$OUT" "zstd -d"
run "$harness" --image "$TEST_TMP/missing.raw" --dry-run
assert_eq "$RC" 1 "missing image"
run "$harness" --image "$image" --dry-run --firmware coreboot
assert_eq "$RC" 2 "bad firmware"
run "$harness" --image "$image" --dry-run --boot-bus scsi
assert_eq "$RC" 2 "bad boot bus"
run "$harness" --image "$image" --dry-run --memory lots
assert_eq "$RC" 2 "bad memory"

# ---------------------------------------------------------------- test disks
airlock_build_ext4_disk "$TEST_TMP/ext4.raw"
assert_contains "$(sgdisk -p "$TEST_TMP/ext4.raw")" "8300  AIRLOCK_TEST_EXT4"
assert_eq "$(blkid -p -O 1048576 -s TYPE -o value "$TEST_TMP/ext4.raw")" ext4
if command -v debugfs >/dev/null 2>&1; then
  assert_contains "$(debugfs -R 'cat /hello.txt' "$TEST_TMP/ext4.raw?offset=1048576" 2>/dev/null)" "AIRLOCK test disk"
fi
airlock_build_swap_disk "$TEST_TMP/swap.raw"
assert_contains "$(sgdisk -p "$TEST_TMP/swap.raw")" "8200  AIRLOCK_TEST_SWAP"
assert_eq "$(blkid -p -O 1048576 -s TYPE -o value "$TEST_TMP/swap.raw")" swap

if airlock_can_build_sig_disk; then
  airlock_build_sig_disk "$TEST_TMP/sig.raw" || fail "sig disk"
  table="$(sgdisk -p "$TEST_TMP/sig.raw")"
  assert_contains "$table" "8E00  AIRLOCK_TEST_LVM"
  assert_contains "$table" "FD00  AIRLOCK_TEST_MD0"
  assert_contains "$table" "8200  AIRLOCK_TEST_SWAP"
  sdev="$(airlock_loop_attach "$TEST_TMP/sig.raw")"
  types="$(for p in 1 2 3 4; do blkid -p -s TYPE -o value "${sdev}p$p"; done | paste -sd,)"
  md_ok=1
  if command -v mdadm >/dev/null 2>&1; then
    mdadm --examine "${sdev}p2" 2>/dev/null | grep -q 'Checksum : .* correct' || md_ok=0
  fi
  airlock_loop_detach "$sdev"
  assert_eq "$types" "LVM2_member,linux_raid_member,linux_raid_member,swap" "signatures"
  ((md_ok)) || fail "mdadm does not accept the mdraid members"
  sig_note="sig disk built"
else
  sig_note="sig disk not built here (needs root, loop devices, lvm2)"
fi

# ---------------------------------------------------------------- payload
mkdir -p "$TEST_TMP/goss" "$TEST_TMP/vm/lib"
printf '#!/bin/sh\necho fake goss\n' >"$TEST_TMP/fake-goss"
chmod +x "$TEST_TMP/fake-goss"
printf 'file: {}\n' >"$TEST_TMP/goss/a.yaml"
printf '#!/usr/bin/env bash\nexit 0\n' >"$TEST_TMP/vm/test_x.sh"
printf '# helper\n' >"$TEST_TMP/vm/lib/h.sh"
airlock_build_payload "$TEST_TMP/payload.tgz" "$TEST_TMP/fake-goss" "$TEST_TMP/goss" "$TEST_TMP/vm"
listing="$(tar -tzvf "$TEST_TMP/payload.tgz")"
assert_contains "$listing" "./goss-bin"
assert_contains "$listing" "./goss/a.yaml"
assert_contains "$listing" "./vm/test_x.sh"
assert_contains "$listing" "./vm/lib/h.sh"
assert_contains "$(tar -tzvf "$TEST_TMP/payload.tgz" ./goss-bin)" "rwxr-xr-x 0/0"

# ---------------------------------------------------------------- real launch, no OS
if command -v qemu-system-x86_64 >/dev/null 2>&1; then
  before="$(sha256_of "$image")"
  run "$harness" --image "$image" --firmware bios --accel tcg --boot-timeout 8 --memory 256 --cpus 1 \
    --goss "$TEST_TMP/fake-goss" --work "$TEST_TMP/w2" --keep-work --results "$TEST_TMP/results"
  assert_eq "$RC" 1 "an unbootable image fails"
  assert_contains "$OUT" "FAIL [bios] boot: the guest agent never answered"
  assert_contains "$OUT" "PASS test disks unchanged"
  assert_eq "$(sha256_of "$image")" "$before" "the image under test is unchanged"
  assert_file "$TEST_TMP/results/bios/qemu-command.txt"
  assert_file "$TEST_TMP/results/bios/serial.log"
  assert_file "$TEST_TMP/w2/overlay-bios.qcow2"
  pgrep -f "airlock-test-bios" >/dev/null && fail "QEMU was left running"
fi

pass "QEMU harness ($sig_note)"
