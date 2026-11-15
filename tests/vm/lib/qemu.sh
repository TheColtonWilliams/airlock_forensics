#!/usr/bin/env bash
# QEMU command-line builder for tests/run-qemu-tests.sh. Source this file; functions only.
#
# airlock_qemu_argv fills the global array QEMU_ARGV from these globals:
#   Q_FIRMWARE   uefi | uefi-sb | bios
#   Q_ACCEL      kvm | tcg
#   Q_OVERLAY    qcow2 overlay of the image under test (the image itself is never written)
#   Q_VARS       writable copy of the OVMF variable store (uefi, uefi-sb)
#   Q_BOOT_BUS   virtio | usb | sata
#   Q_MEMORY     MiB        Q_CPUS  count
#   Q_QGA_SOCKET guest agent Unix socket      Q_SERIAL_LOG  serial console log file
#   Q_NIC        0 (no network device at all) | 1 (user-mode NIC, restricted, for the air-gap test)
#   Q_DISKS      array of "serial=path" extra raw disks (virtio, /dev/disk/by-id/virtio-<serial>)
#   Q_NOPROVISION 1: pass the SMBIOS OEM string "airlock.noprovision"; the image's grub hook
#                (/etc/grub.d/06_airlock_vm_test) then puts airlock.noprovision on the kernel
#                command line and airlock-provision.service is skipped. 0 or unset (default, so
#                a direct caller such as the CI provisioning boot still provisions): none.
#                tests/run-qemu-tests.sh sets 1 unless --provision.
# Firmware files can be moved with AIRLOCK_OVMF_CODE, AIRLOCK_OVMF_VARS,
# AIRLOCK_OVMF_SB_CODE, AIRLOCK_OVMF_SB_VARS.
#
# Test: tests/functional/test_build_qemu_harness.sh (--dry-run argv checks)

# shellcheck disable=SC2034 # QEMU_ARGV is read by the sourcing script
QEMU_ARGV=()

airlock_ovmf_code() {
  case "$1" in
    uefi) printf '%s\n' "${AIRLOCK_OVMF_CODE:-/usr/share/OVMF/OVMF_CODE_4M.fd}" ;;
    uefi-sb) printf '%s\n' "${AIRLOCK_OVMF_SB_CODE:-/usr/share/OVMF/OVMF_CODE_4M.secboot.fd}" ;;
    *) return 1 ;;
  esac
}

airlock_ovmf_vars_template() {
  case "$1" in
    uefi) printf '%s\n' "${AIRLOCK_OVMF_VARS:-/usr/share/OVMF/OVMF_VARS_4M.fd}" ;;
    # Microsoft keys enrolled, so the signed shim must verify.
    uefi-sb) printf '%s\n' "${AIRLOCK_OVMF_SB_VARS:-/usr/share/OVMF/OVMF_VARS_4M.ms.fd}" ;;
    *) return 1 ;;
  esac
}

# airlock_qemu_accel: kvm when /dev/kvm is usable, else tcg.
airlock_qemu_accel() {
  if [[ -r /dev/kvm && -w /dev/kvm ]]; then echo kvm; else echo tcg; fi
}

airlock_qemu_argv() {
  local machine="q35" d serial path i=0
  QEMU_ARGV=(qemu-system-x86_64 -name "airlock-test-${Q_FIRMWARE}" -nodefaults -no-user-config)
  case "$Q_FIRMWARE" in
    uefi-sb) machine="q35,smm=on" ;;
    uefi | bios) ;;
    *) printf 'qemu.sh: unknown firmware %s\n' "$Q_FIRMWARE" >&2; return 1 ;;
  esac
  case "$Q_ACCEL" in
    kvm) QEMU_ARGV+=(-machine "$machine" -accel kvm -cpu host) ;;
    tcg) QEMU_ARGV+=(-machine "$machine" -accel "tcg,thread=multi" -cpu max) ;;
    *) printf 'qemu.sh: unknown accelerator %s\n' "$Q_ACCEL" >&2; return 1 ;;
  esac
  QEMU_ARGV+=(-m "$Q_MEMORY" -smp "$Q_CPUS")
  # Exactly one OEM string, so grub's "smbios --type 11 --get-string 4" (the count byte, 1)
  # reads it. The image accepts no other value.
  if [[ "${Q_NOPROVISION:-0}" == "1" ]]; then
    QEMU_ARGV+=(-smbios "type=11,value=airlock.noprovision")
  fi
  if [[ "$Q_FIRMWARE" == uefi* ]]; then
    [[ "$Q_FIRMWARE" == "uefi-sb" ]] && QEMU_ARGV+=(-global "driver=cfi.pflash01,property=secure,value=on")
    QEMU_ARGV+=(
      -drive "if=pflash,format=raw,unit=0,readonly=on,file=$(airlock_ovmf_code "$Q_FIRMWARE")"
      -drive "if=pflash,format=raw,unit=1,file=$Q_VARS"
    )
  fi
  # Display: a standard VGA card so GDM starts; nothing is shown on the host.
  QEMU_ARGV+=(-vga std -display none)
  QEMU_ARGV+=(-serial "file:$Q_SERIAL_LOG" -monitor none -no-reboot)
  # Boot disk: the overlay, on the chosen bus.
  QEMU_ARGV+=(-drive "if=none,id=bootdisk,format=qcow2,file=$Q_OVERLAY,cache=unsafe,discard=unmap")
  case "$Q_BOOT_BUS" in
    virtio) QEMU_ARGV+=(-device "virtio-blk-pci,drive=bootdisk,bootindex=0,serial=airlock-boot") ;;
    usb) QEMU_ARGV+=(-device "qemu-xhci,id=xhci" -device "usb-storage,bus=xhci.0,drive=bootdisk,bootindex=0,serial=airlock-boot") ;;
    sata) QEMU_ARGV+=(-device "ide-hd,bus=ide.0,drive=bootdisk,bootindex=0,serial=airlock-boot") ;;
    *) printf 'qemu.sh: unknown boot bus %s\n' "$Q_BOOT_BUS" >&2; return 1 ;;
  esac
  # Extra disks are raw files so any write by the guest changes their hash.
  for d in "${Q_DISKS[@]+"${Q_DISKS[@]}"}"; do
    serial="${d%%=*}"
    path="${d#*=}"
    QEMU_ARGV+=(-drive "if=none,id=extra$i,format=raw,file=$path,cache=none"
      -device "virtio-blk-pci,drive=extra$i,serial=$serial")
    i=$((i + 1))
  done
  # Guest agent on a virtio serial port: the only channel into the guest.
  QEMU_ARGV+=(
    -chardev "socket,id=qga0,path=$Q_QGA_SOCKET,server=on,wait=off"
    -device virtio-serial-pci
    -device "virtserialport,chardev=qga0,name=org.qemu.guest_agent.0"
  )
  if [[ "$Q_NIC" == "1" ]]; then
    # restrict=on: even a broken image cannot reach the host network or the internet.
    QEMU_ARGV+=(-nic "user,model=virtio-net-pci,restrict=on")
  else
    QEMU_ARGV+=(-nic none)
  fi
}
