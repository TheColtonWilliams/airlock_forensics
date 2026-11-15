#!/usr/bin/env bash
# Test-disk builders for tests/run-qemu-tests.sh. Source this file; it defines functions only.
#
# Disks attached to the test VM (virtio, serial in brackets, /dev/disk/by-id/virtio-<serial>
# inside the guest):
#   ext4 disk  [airlock-ext4]  GPT, one Linux partition with ext4 and a text file (3.1, 3.2)
#   swap disk  [airlock-swap]  GPT, one partition of type Linux swap with a swap signature (3.3, 3.4)
#   sig disk   [airlock-sig]   GPT: LVM PV + VG, two mdraid v1.2 members, swap (3A.10)
# The first two need no root: filesystems are made in a separate file and copied into place.
# The sig disk needs root, loop devices and lvm2; mdraid members come from mdadm when the
# host has the md driver, else from tests/vm/lib/mdsb.py (same on-disk format).
#
# Test: tests/functional/test_build_qemu_harness.sh

_airlock_disks_lib_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

airlock_disk_err() { printf 'disks: %s\n' "$*" >&2; }

# airlock_put_fs DISK FS_IMAGE START_MIB: copy a filesystem image into a disk image.
airlock_put_fs() {
  dd if="$2" of="$1" bs=1M seek="$3" conv=notrunc,sparse status=none
}

# airlock_build_ext4_disk OUT [SIZE_MIB]
airlock_build_ext4_disk() {
  local out="$1" size="${2:-64}" tmp
  tmp="$(mktemp -d)"
  rm -f -- "$out"
  truncate -s "${size}M" -- "$out"
  sgdisk -o -n 1:1M:0 -t 1:8300 -c 1:AIRLOCK_TEST_EXT4 -- "$out" >/dev/null ||
    { airlock_disk_err "sgdisk failed on $out"; rm -rf -- "$tmp"; return 1; }
  mkdir -p -- "$tmp/root"
  printf 'AIRLOCK test disk. Any change to this file or disk is a test failure.\n' >"$tmp/root/hello.txt"
  # Partition 1 runs from 1 MiB to the backup GPT; 2 MiB smaller than the disk is safe.
  truncate -s "$((size - 2))M" -- "$tmp/fs.img"
  mkfs.ext4 -q -F -L AIRLOCK_TEST -d "$tmp/root" -- "$tmp/fs.img" ||
    { airlock_disk_err "mkfs.ext4 failed"; rm -rf -- "$tmp"; return 1; }
  airlock_put_fs "$out" "$tmp/fs.img" 1
  rm -rf -- "$tmp"
}

# airlock_build_swap_disk OUT [SIZE_MIB]
airlock_build_swap_disk() {
  local out="$1" size="${2:-64}" tmp
  tmp="$(mktemp -d)"
  rm -f -- "$out"
  truncate -s "${size}M" -- "$out"
  sgdisk -o -n 1:1M:0 -t 1:8200 -c 1:AIRLOCK_TEST_SWAP -- "$out" >/dev/null ||
    { airlock_disk_err "sgdisk failed on $out"; rm -rf -- "$tmp"; return 1; }
  truncate -s "$((size - 2))M" -- "$tmp/swap.img"
  mkswap -L AIRLOCKTESTSWAP -- "$tmp/swap.img" >/dev/null 2>&1 ||
    { airlock_disk_err "mkswap failed"; rm -rf -- "$tmp"; return 1; }
  airlock_put_fs "$out" "$tmp/swap.img" 1
  rm -rf -- "$tmp"
}

# airlock_loop_attach FILE: print the loop device; partition nodes exist on return.
airlock_loop_attach() {
  local file="$1" dev i n
  dev="$(losetup -f --show -P -- "$file")" || return 1
  partx -a -- "$dev" >/dev/null 2>&1 || true
  n="$(sgdisk -p -- "$file" 2>/dev/null | awk '/^ +[0-9]+ / {c++} END {print c+0}')"
  for ((i = 1; i <= n; i++)); do
    local t=0
    until [[ -b "${dev}p$i" ]]; do
      ((t++ < 50)) || { airlock_disk_err "partition ${dev}p$i did not appear"; airlock_loop_detach "$dev"; return 1; }
      sleep 0.1
    done
  done
  printf '%s\n' "$dev"
}

airlock_loop_detach() {
  partx -d -- "$1" >/dev/null 2>&1 || true
  losetup -d "$1"
}

# airlock_can_build_sig_disk: 0 when root, loop devices, lvm2 and mdraid tooling are there.
airlock_can_build_sig_disk() {
  [[ "$(id -u)" -eq 0 ]] || return 1
  local c
  for c in losetup partx pvcreate vgcreate mkswap sgdisk python3; do
    command -v "$c" >/dev/null 2>&1 || return 1
  done
  losetup -f >/dev/null 2>&1
}

# airlock_build_sig_disk OUT: LVM, mdraid and swap signatures on one GPT disk (3A.10).
airlock_build_sig_disk() {
  local out="$1" dev rc=0 lvm=(--devicesfile "")
  airlock_can_build_sig_disk || { airlock_disk_err "the sig disk needs root, loop devices, lvm2 and python3"; return 1; }
  rm -f -- "$out"
  truncate -s 256M -- "$out"
  sgdisk -o \
    -n 1:1M:+64M -t 1:8E00 -c 1:AIRLOCK_TEST_LVM \
    -n 2:0:+32M -t 2:FD00 -c 2:AIRLOCK_TEST_MD0 \
    -n 3:0:+32M -t 3:FD00 -c 3:AIRLOCK_TEST_MD1 \
    -n 4:0:+32M -t 4:8200 -c 4:AIRLOCK_TEST_SWAP -- "$out" >/dev/null ||
    { airlock_disk_err "sgdisk failed on $out"; return 1; }
  dev="$(airlock_loop_attach "$out")" || return 1
  {
    # LVM: physical volume and volume group, never auto-activated on this host.
    pvcreate "${lvm[@]}" -q -ff -y -- "${dev}p1" >/dev/null &&
      vgcreate "${lvm[@]}" -q --setautoactivation n airlocktest_vg "${dev}p1" >/dev/null &&
      { lvcreate "${lvm[@]}" -q -an -Zn -L 16M -n airlocktest_lv airlocktest_vg >/dev/null 2>&1 ||
        airlock_disk_err "no logical volume (host lacks device-mapper); the PV and VG signatures are still there"; } &&
      vgchange "${lvm[@]}" -q -an airlocktest_vg >/dev/null 2>&1
  } || rc=1
  if ((rc == 0)); then
    # mdraid: two RAID1 members. mdadm needs the md driver; fall back to writing superblocks.
    if command -v mdadm >/dev/null 2>&1 &&
      mdadm --create /dev/md/airlocktest --run --quiet --level=1 --raid-devices=2 --metadata=1.2 \
        --homehost=airlock-test "${dev}p2" "${dev}p3" >/dev/null 2>&1; then
      mdadm --stop /dev/md/airlocktest >/dev/null 2>&1 || true
    else
      python3 "$_airlock_disks_lib_dir/mdsb.py" --name airlock-test:airlocktest "${dev}p2" "${dev}p3" >/dev/null || rc=1
    fi
  fi
  if ((rc == 0)); then
    mkswap -L AIRLOCKSIGSWAP -- "${dev}p4" >/dev/null 2>&1 || rc=1
  fi
  sync
  # Forget the VG on this host so nothing here holds the loop device.
  vgchange "${lvm[@]}" -q -an airlocktest_vg >/dev/null 2>&1 || true
  airlock_loop_detach "$dev"
  ((rc == 0)) || airlock_disk_err "could not write the LVM, mdraid and swap signatures to $out"
  return "$rc"
}

# airlock_build_payload OUT_TGZ GOSS_BIN GOSS_DIR VM_DIR: the files copied into the guest.
# Layout inside: goss (binary), goss/*.yaml, vm/*.sh
airlock_build_payload() {
  local out="$1" goss_bin="$2" goss_dir="$3" vm_dir="$4" stage f
  stage="$(mktemp -d)"
  mkdir -p -- "$stage/goss" "$stage/vm"
  install -m 0755 -- "$goss_bin" "$stage/goss-bin"
  for f in "$goss_dir"/*.yaml; do
    [[ -e "$f" ]] && install -m 0644 -- "$f" "$stage/goss/"
  done
  for f in "$vm_dir"/*.sh; do
    [[ -e "$f" ]] && install -m 0755 -- "$f" "$stage/vm/"
  done
  if [[ -d "$vm_dir/lib" ]]; then
    mkdir -p -- "$stage/vm/lib"
    for f in "$vm_dir"/lib/*.sh; do
      [[ -e "$f" ]] && install -m 0644 -- "$f" "$stage/vm/lib/"
    done
  fi
  tar -C "$stage" --owner=0 --group=0 --numeric-owner -czf "$out" . || { rm -rf -- "$stage"; return 1; }
  rm -rf -- "$stage"
}

airlock_sha256() { sha256sum -- "$1" | cut -d' ' -f1; }

# airlock_mini_layout_disk OUT SIZE_MIB [plain]: a small disk with the five AIRLOCK
# partitions in contract order (BIOSBOOT 1M, EFI 64M, ASSETS 8M, OUTPUT 8M, root rest).
# With "plain", names are empty and ASSETS/OUTPUT are typed Linux, as the installer leaves
# them, so tests/functional can check that the base role helper fixes them.
airlock_mini_layout_disk() {
  local out="$1" size="$2" plain="${3:-}" t3=0700 t4=0700 n=()
  rm -f -- "$out"
  truncate -s "${size}M" -- "$out"
  if [[ "$plain" == "plain" ]]; then
    t3=8300
    t4=8300
  else
    n=(-c 1:BIOSBOOT -c 2:EFI -c 3:ASSETS -c 4:OUTPUT -c 5:AIRLOCK_ROOT)
  fi
  sgdisk -o -n 1:2048:+1M -t 1:EF02 -n 2:0:+64M -t 2:EF00 -n 3:0:+8M -t "3:$t3" \
    -n 4:0:+8M -t "4:$t4" -n 5:0:0 -t 5:8300 "${n[@]}" -- "$out" >/dev/null ||
    { airlock_disk_err "sgdisk failed on $out"; return 1; }
}
