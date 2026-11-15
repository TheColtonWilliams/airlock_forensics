#!/usr/bin/env bash
# Boot an AIRLOCK image headless in QEMU and run the in-guest tests (tasks 1.11, 3.9).
#
# The image is never written: each boot uses a fresh qcow2 overlay (grown by --grow-gib so
# the first-boot unit has room to grow the root filesystem). Extra raw test disks are
# attached: an ext4 disk, a disk with a GPT swap partition, and (root, lvm2) a disk with
# LVM, mdraid and swap signatures (3A.10). Their SHA-256 is taken before and after; any
# change is a failure. The guest has no network device unless --nic is given (air-gap
# test), and then only a restricted user-mode NIC.
#
# Inside the guest, through the QEMU guest agent (no network):
#   1. the booted firmware is checked (UEFI or legacy BIOS, as asked),
#   2. the system must reach "running" (no failed units),
#   3. every tests/goss/*.yaml runs with goss (copied in from the host),
#   4. every tests/vm/*.sh runs as root: exit 0 pass, 77 skip, anything else fail.
#
# Usage: tests/run-qemu-tests.sh --image FILE [options]
#   --image FILE        raw or qcow2 AIRLOCK image (decompress .zst first: zstd -d)
#   --firmware LIST     comma list of uefi, uefi-sb, bios (default: uefi,bios)
#   --boot-bus BUS      virtio (default), usb, or sata
#   --nic               attach a restricted user-mode network card (air-gap test)
#   --no-extra-disks    attach no test disks
#   --provision         let offline provisioning run at boot. Default: the guest boots with
#                       airlock.noprovision on the kernel command line (SMBIOS OEM string read
#                       by the image's grub hook), so an unprovisioned image is tested as built
#                       and airlock-provision.service never reboots it under the tests
#   --require-sig-disk  fail if the LVM/mdraid/swap disk cannot be built (CI)
#   --ntfs-fixture FILE also attach a copy of this NTFS image (serial airlock-ntfs)
#   --grow-gib N        overlay is N GiB larger than the image (default 4)
#   --memory MIB        guest memory (default 4096)   --cpus N  (default 2)
#   --accel MODE        auto (default), kvm, or tcg
#   --boot-timeout SEC  wait for the guest agent (default 900 with KVM, 5400 without)
#   --test-timeout SEC  per goss file or vm test (default 900 with KVM, 3600 without)
#   --only REGEX        run only goss files and vm tests whose name matches
#   --goss FILE         goss binary for the guest (default: goss on PATH)
#   --allow-degraded    do not fail when systemd reports failed units
#   --work DIR          work folder (default: a new temporary folder)
#   --keep-work         keep the work folder (serial logs, overlays, results)
#   --results DIR       copy logs and results there (for CI artifacts)
#   --dry-run           print the test plan and QEMU command lines; boot nothing
#   -h, --help          this help
# Inside the guest the tests get AIRLOCK_TEST_DIR, AIRLOCK_TEST_FIRMWARE, AIRLOCK_TEST_NIC,
# AIRLOCK_TEST_DISK_{EXT4,SWAP,SIG,NTFS} (/dev/disk/by-id paths, or empty), and
# AIRLOCK_SIGDISK_SHA256 (the host's hash of the sig disk before boot).
# goss gets --vars-inline {"disks": {...}, "firmware", "nic", "provision": false}; the same
# files run inside forensic-provision's self-test with "provision": true and no test disks, so
# checks that need the test disks or a running desktop are skipped there.
# Exit status: 0 all passed; 1 any failure (summary at the end); 2 bad usage.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
lib="$repo_root/tests/vm/lib"
# shellcheck source=tests/vm/lib/disks.sh
. "$lib/disks.sh"
# shellcheck source=tests/vm/lib/qemu.sh
. "$lib/qemu.sh"

image=""
firmwares="uefi,bios"
boot_bus="virtio"
nic=0
noprovision=1
extra_disks=1
require_sig=0
ntfs_fixture=""
grow_gib=4
memory=4096
cpus=2
accel="auto"
boot_timeout=""
test_timeout=""
only=""
goss_bin=""
allow_degraded=0
work=""
keep_work=0
results_dir=""
dry_run=0
guest_dir="/run/airlock-tests"

usage() { sed -n '2,48p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; }
die() {
  printf 'run-qemu-tests: %s\n' "$*" >&2
  exit 1
}
bad_usage() {
  printf 'run-qemu-tests: %s Run with --help.\n' "$*" >&2
  exit 2
}
log() { printf 'run-qemu-tests: %s\n' "$*"; }

while (($#)); do
  case "$1" in
    --image) image="${2:-}"; shift 2 ;;
    --firmware) firmwares="${2:-}"; shift 2 ;;
    --boot-bus) boot_bus="${2:-}"; shift 2 ;;
    --nic) nic=1; shift ;;
    --no-extra-disks) extra_disks=0; shift ;;
    --provision) noprovision=0; shift ;;
    --require-sig-disk) require_sig=1; shift ;;
    --ntfs-fixture) ntfs_fixture="${2:-}"; shift 2 ;;
    --grow-gib) grow_gib="${2:-}"; shift 2 ;;
    --memory) memory="${2:-}"; shift 2 ;;
    --cpus) cpus="${2:-}"; shift 2 ;;
    --accel) accel="${2:-}"; shift 2 ;;
    --boot-timeout) boot_timeout="${2:-}"; shift 2 ;;
    --test-timeout) test_timeout="${2:-}"; shift 2 ;;
    --only) only="${2:-}"; shift 2 ;;
    --goss) goss_bin="${2:-}"; shift 2 ;;
    --allow-degraded) allow_degraded=1; shift ;;
    --work) work="${2:-}"; shift 2 ;;
    --keep-work) keep_work=1; shift ;;
    --results) results_dir="${2:-}"; shift 2 ;;
    --dry-run) dry_run=1; shift ;;
    -h | --help) usage; exit 0 ;;
    *) bad_usage "unknown option '$1'." ;;
  esac
done

# ------------------------------------------------------------------------------ checks
[[ -n "$image" ]] || bad_usage "--image is required."
case "$image" in *.zst | *.xz | *.gz) bad_usage "decompress $image first (for example: zstd -d --sparse $image)." ;; esac
[[ -f "$image" ]] || die "image $image not found. Build it with scripts/build.sh."
image="$(cd "$(dirname -- "$image")" && pwd)/$(basename -- "$image")"
IFS=',' read -r -a fw_list <<<"$firmwares"
((${#fw_list[@]} > 0)) || bad_usage "--firmware is empty."
for fw in "${fw_list[@]}"; do
  case "$fw" in uefi | uefi-sb | bios) ;; *) bad_usage "--firmware '$fw' is not uefi, uefi-sb, or bios." ;; esac
done
case "$boot_bus" in virtio | usb | sata) ;; *) bad_usage "--boot-bus must be virtio, usb, or sata." ;; esac
for n in "$grow_gib" "$memory" "$cpus"; do
  [[ "$n" =~ ^[0-9]+$ ]] || bad_usage "'$n' is not a whole number."
done
case "$accel" in auto) accel="$(airlock_qemu_accel)" ;; kvm | tcg) ;; *) bad_usage "--accel must be auto, kvm, or tcg." ;; esac
if [[ "$accel" == "kvm" ]]; then
  boot_timeout="${boot_timeout:-900}"
  test_timeout="${test_timeout:-900}"
else
  boot_timeout="${boot_timeout:-5400}"
  test_timeout="${test_timeout:-3600}"
fi
[[ -z "$ntfs_fixture" || -f "$ntfs_fixture" ]] || die "NTFS fixture $ntfs_fixture not found."

missing=()
for c in qemu-img python3 sgdisk mkfs.ext4 mkswap sha256sum tar; do
  command -v "$c" >/dev/null 2>&1 || missing+=("$c")
done
((dry_run)) || command -v qemu-system-x86_64 >/dev/null 2>&1 || missing+=(qemu-system-x86_64)
((${#missing[@]} == 0)) || die "missing tools: ${missing[*]}. Install them (apt install qemu-system-x86 qemu-utils gdisk e2fsprogs) and rerun."
if [[ -z "$goss_bin" ]]; then
  goss_bin="$(command -v goss || true)"
fi
if ((!dry_run)); then
  [[ -n "$goss_bin" && -x "$goss_bin" ]] ||
    die "goss not found. Install the pinned goss (pins.goss_linux_amd64) or pass --goss FILE."
fi
for fw in "${fw_list[@]}"; do
  if [[ "$fw" == uefi* ]]; then
    for f in "$(airlock_ovmf_code "$fw")" "$(airlock_ovmf_vars_template "$fw")"; do
      [[ -f "$f" ]] || ((dry_run)) || die "firmware file $f not found. Install ovmf (apt install ovmf)."
    done
  fi
done

if [[ -z "$work" ]]; then
  work="$(mktemp -d "${TMPDIR:-/tmp}/airlock-qemu.XXXXXX")"
else
  mkdir -p -- "$work"
  work="$(cd "$work" && pwd)"
fi
qemu_pid=""
# shellcheck disable=SC2317 # called by the EXIT trap
cleanup() {
  if [[ -n "$qemu_pid" ]] && kill -0 "$qemu_pid" 2>/dev/null; then
    kill "$qemu_pid" 2>/dev/null || true
  fi
  if ((keep_work)); then
    log "work folder kept: $work"
  else
    rm -rf -- "$work"
  fi
}
trap cleanup EXIT

image_format="$(qemu-img info --output=json -- "$image" | python3 -c 'import json,sys; print(json.load(sys.stdin)["format"])')"
case "$image_format" in raw | qcow2) ;; *) die "image format '$image_format' is not raw or qcow2." ;; esac
image_bytes="$(qemu-img info --output=json -- "$image" | python3 -c 'import json,sys; print(json.load(sys.stdin)["virtual-size"])')"
overlay_bytes=$((image_bytes + grow_gib * 1024 * 1024 * 1024))

# ------------------------------------------------------------------------------ disks
declare -A disk_path=()
declare -A disk_by_id=([ext4]="" [swap]="" [sig]="" [ntfs]="")
if ((extra_disks)); then
  disk_path[ext4]="$work/disk-ext4.raw"
  disk_path[swap]="$work/disk-swap.raw"
  if airlock_can_build_sig_disk; then
    disk_path[sig]="$work/disk-sig.raw"
  elif ((require_sig)); then
    die "the LVM/mdraid/swap test disk needs root, loop devices, lvm2 and python3 (--require-sig-disk)."
  else
    log "skipping the LVM/mdraid/swap test disk: needs root, loop devices, lvm2 and python3"
  fi
fi
[[ -n "$ntfs_fixture" ]] && disk_path[ntfs]="$work/disk-ntfs.raw"

build_disks() {
  [[ -n "${disk_path[ext4]:-}" ]] && airlock_build_ext4_disk "${disk_path[ext4]}"
  [[ -n "${disk_path[swap]:-}" ]] && airlock_build_swap_disk "${disk_path[swap]}"
  if [[ -n "${disk_path[sig]:-}" ]]; then
    airlock_build_sig_disk "${disk_path[sig]}" || {
      ((require_sig)) && die "could not build the LVM/mdraid/swap test disk."
      log "the LVM/mdraid/swap test disk could not be built; continuing without it"
      unset 'disk_path[sig]'
    }
  fi
  if [[ -n "${disk_path[ntfs]:-}" ]]; then
    cp --sparse=always -- "$ntfs_fixture" "${disk_path[ntfs]}"
  fi
  return 0
}

Q_DISKS=()
set_disk_list() {
  local key
  Q_DISKS=()
  for key in ext4 swap sig ntfs; do
    if [[ -n "${disk_path[$key]:-}" ]]; then
      Q_DISKS+=("airlock-$key=${disk_path[$key]}")
      disk_by_id[$key]="/dev/disk/by-id/virtio-airlock-$key"
    fi
  done
}

hash_disks() { # prints "key hash" lines
  local key
  for key in ext4 swap sig ntfs; do
    [[ -n "${disk_path[$key]:-}" ]] && printf '%s %s\n' "$key" "$(airlock_sha256 "${disk_path[$key]}")"
  done
  return 0
}

# ------------------------------------------------------------------------------ plan
matches_only() { [[ -z "$only" || "$1" =~ $only ]]; }
goss_files=()
for f in "$repo_root"/tests/goss/*.yaml; do
  [[ -e "$f" ]] || continue
  name="$(basename -- "$f")"
  [[ "$name" == "vars.yaml" ]] && continue
  matches_only "$name" && goss_files+=("$name")
done
vm_tests=()
for f in "$repo_root"/tests/vm/*.sh; do
  [[ -e "$f" ]] || continue
  name="$(basename -- "$f")"
  matches_only "$name" && vm_tests+=("$name")
done

Q_ACCEL="$accel"
Q_BOOT_BUS="$boot_bus"
Q_MEMORY="$memory"
Q_CPUS="$cpus"
Q_NIC="$nic"
Q_NOPROVISION="$noprovision"

if ((dry_run)); then
  set_disk_list
  log "dry run: nothing is booted"
  printf 'image=%s format=%s size=%s overlay_size=%s accel=%s boot_timeout=%s test_timeout=%s\n' \
    "$image" "$image_format" "$image_bytes" "$overlay_bytes" "$accel" "$boot_timeout" "$test_timeout"
  printf 'noprovision=%s\n' "$noprovision"
  printf 'goss files: %s\n' "${goss_files[*]:-(none)}"
  printf 'vm tests: %s\n' "${vm_tests[*]:-(none)}"
  for key in ext4 swap sig ntfs; do
    printf 'disk %s: %s\n' "$key" "${disk_path[$key]:-(not attached)}"
  done
  for fw in "${fw_list[@]}"; do
    Q_FIRMWARE="$fw"
    Q_OVERLAY="$work/overlay-$fw.qcow2"
    Q_VARS="$work/OVMF_VARS-$fw.fd"
    Q_QGA_SOCKET="$work/qga-$fw.sock"
    Q_SERIAL_LOG="$work/serial-$fw.log"
    airlock_qemu_argv
    printf 'qemu[%s]:' "$fw"
    printf ' %q' "${QEMU_ARGV[@]}"
    printf '\n'
  done
  exit 0
fi

log "building test disks in $work"
build_disks
set_disk_list
hash_disks >"$work/disks.before"
payload="$work/payload.tgz"
airlock_build_payload "$payload" "$goss_bin" "$repo_root/tests/goss" "$repo_root/tests/vm"

# ------------------------------------------------------------------------------ run
results="$work/results"
mkdir -p -- "$results"
failures=()
passes=0
skips=0

record() { # STATUS NAME
  case "$1" in
    pass) passes=$((passes + 1)); log "PASS $2" ;;
    skip) skips=$((skips + 1)); log "SKIP $2" ;;
    *) failures+=("$2"); log "FAIL $2" ;;
  esac
}

qga() { python3 "$lib/qga.py" --socket "$Q_QGA_SOCKET" "$@"; }

# guest_exec NAME TIMEOUT PROGRAM [ARGS...]: run in the guest, log to results; sets rc.
guest_exec() {
  local name="$1" t="$2"
  shift 2
  rc=0
  qga exec --timeout "$t" "${guest_env[@]}" -- "$@" >"$results/$fw/$name.log" 2>&1 || rc=$?
}

goss_vars_json() {
  python3 - "$fw" "$nic" "${disk_by_id[ext4]}" "${disk_by_id[swap]}" "${disk_by_id[sig]}" "${disk_by_id[ntfs]}" <<'PY'
import json
import sys

fw, nic, ext4, swap, sig, ntfs = sys.argv[1:7]
print(json.dumps({"disks": {"ext4": ext4, "ntfs": ntfs, "sig": sig, "swap": swap},
                  "firmware": fw, "nic": nic == "1", "provision": False}, sort_keys=True))
PY
}

for fw in "${fw_list[@]}"; do
  mkdir -p -- "$results/$fw"
  Q_FIRMWARE="$fw"
  Q_OVERLAY="$work/overlay-$fw.qcow2"
  Q_VARS="$work/OVMF_VARS-$fw.fd"
  Q_QGA_SOCKET="$work/qga-$fw.sock"
  Q_SERIAL_LOG="$results/$fw/serial.log"
  rm -f -- "$Q_OVERLAY" "$Q_QGA_SOCKET"
  qemu-img create -q -f qcow2 -F "$image_format" -b "$image" -- "$Q_OVERLAY" "$overlay_bytes"
  if [[ "$fw" == uefi* ]]; then
    cp -- "$(airlock_ovmf_vars_template "$fw")" "$Q_VARS"
  fi
  airlock_qemu_argv
  printf '%q ' "${QEMU_ARGV[@]}" >"$results/$fw/qemu-command.txt"
  log "[$fw] booting ($accel, boot bus $boot_bus, timeout ${boot_timeout}s)"
  "${QEMU_ARGV[@]}" >"$results/$fw/qemu.log" 2>&1 &
  qemu_pid=$!

  guest_env=(--env "AIRLOCK_TEST_DIR=$guest_dir" --env "AIRLOCK_TEST_FIRMWARE=$fw" --env "AIRLOCK_TEST_NIC=$nic"
    --env "AIRLOCK_TEST_DISK_EXT4=${disk_by_id[ext4]}" --env "AIRLOCK_TEST_DISK_SWAP=${disk_by_id[swap]}"
    --env "AIRLOCK_TEST_DISK_SIG=${disk_by_id[sig]}" --env "AIRLOCK_TEST_DISK_NTFS=${disk_by_id[ntfs]}"
    --env "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
  # The storage test compares the sig disk's hash inside the guest with the host's.
  sig_hash="$(awk '$1 == "sig" {print $2}' "$work/disks.before")"
  [[ -n "$sig_hash" ]] && guest_env+=(--env "AIRLOCK_SIGDISK_SHA256=$sig_hash")

  if ! qga wait --timeout "$boot_timeout" >"$results/$fw/agent-wait.log" 2>&1; then
    record fail "[$fw] boot: the guest agent never answered (see $results/$fw/serial.log)"
    kill "$qemu_pid" 2>/dev/null || true
    wait "$qemu_pid" 2>/dev/null || true
    qemu_pid=""
    continue
  fi
  record pass "[$fw] boot: guest agent answered"

  # Firmware actually used.
  guest_exec firmware 60 /bin/sh -c 'test -d /sys/firmware/efi && echo uefi || echo bios'
  got="$(tr -d '[:space:]' <"$results/$fw/firmware.log")"
  if [[ "$got" == "${fw%-sb}" ]]; then
    record pass "[$fw] booted through ${fw%-sb} firmware"
  else
    record fail "[$fw] expected ${fw%-sb} firmware, guest reports '$got'"
  fi
  if [[ "$fw" == "uefi-sb" ]]; then
    guest_exec secureboot 60 /bin/sh -c 'od -An -t u1 -j4 -N1 /sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c'
    if [[ "$(tr -d '[:space:]' <"$results/$fw/secureboot.log")" == "1" ]]; then
      record pass "[$fw] Secure Boot is on"
    else
      record fail "[$fw] Secure Boot is not on (see $results/$fw/secureboot.log)"
    fi
  fi

  # An unprovisioned image is tested as built: airlock.noprovision must have reached the kernel.
  if ((noprovision)); then
    guest_exec cmdline 60 /bin/cat /proc/cmdline
    if grep -Eq '(^| )airlock\.noprovision( |$)' "$results/$fw/cmdline.log"; then
      record pass "[$fw] airlock.noprovision on the kernel command line (provisioning skipped)"
    else
      record fail "[$fw] airlock.noprovision missing from the kernel command line; the grub hook did not see the SMBIOS OEM string (see $results/$fw/cmdline.log)"
    fi
  fi

  # Whole system up, no failed units.
  guest_exec system-running "$test_timeout" /bin/sh -c 'systemctl is-system-running --wait; systemctl --failed --no-legend --plain'
  state="$(head -n1 "$results/$fw/system-running.log" | tr -d '[:space:]')"
  if [[ "$state" == "running" ]]; then
    record pass "[$fw] system state running"
  elif ((allow_degraded)); then
    record skip "[$fw] system state '$state' (allowed by --allow-degraded)"
  else
    record fail "[$fw] system state '$state'; failed units are listed in $results/$fw/system-running.log"
  fi

  # Payload: goss and the tests.
  if ! qga put "$payload" /run/airlock-tests.tgz >"$results/$fw/payload.log" 2>&1; then
    record fail "[$fw] could not copy the test payload into the guest"
  else
    guest_exec unpack 300 /bin/sh -c "rm -rf $guest_dir && mkdir -p $guest_dir && tar -xzf /run/airlock-tests.tgz -C $guest_dir && rm -f /run/airlock-tests.tgz"
    if ((rc != 0)); then
      record fail "[$fw] could not unpack the test payload (see $results/$fw/unpack.log)"
    else
      vars_inline="$(goss_vars_json)"
      for g in "${goss_files[@]+"${goss_files[@]}"}"; do
        goss_args=("$guest_dir/goss-bin" -g "$guest_dir/goss/$g")
        [[ -f "$repo_root/tests/goss/vars.yaml" ]] && goss_args+=(--vars "$guest_dir/goss/vars.yaml")
        goss_args+=(--vars-inline "$vars_inline" validate --format tap --no-color --retry-timeout 300s --sleep 10s)
        guest_exec "goss-${g%.yaml}" "$test_timeout" "${goss_args[@]}"
        if ((rc == 0)); then record pass "[$fw] goss $g"; else record fail "[$fw] goss $g (see $results/$fw/goss-${g%.yaml}.log)"; fi
      done
      for t in "${vm_tests[@]+"${vm_tests[@]}"}"; do
        guest_exec "vm-${t%.sh}" "$test_timeout" /bin/bash "$guest_dir/vm/$t"
        case "$rc" in
          0) record pass "[$fw] vm $t" ;;
          77) record skip "[$fw] vm $t: $(tail -n1 "$results/$fw/vm-${t%.sh}.log")" ;;
          *) record fail "[$fw] vm $t (exit $rc, see $results/$fw/vm-${t%.sh}.log)" ;;
        esac
      done
    fi
  fi

  log "[$fw] shutting down"
  qga shutdown >/dev/null 2>&1 || true
  for _ in $(seq 1 120); do
    kill -0 "$qemu_pid" 2>/dev/null || break
    sleep 1
  done
  if kill -0 "$qemu_pid" 2>/dev/null; then
    log "[$fw] guest did not power off; stopping QEMU"
    kill "$qemu_pid" 2>/dev/null || true
  fi
  wait "$qemu_pid" 2>/dev/null || true
  qemu_pid=""
done

# ------------------------------------------------------------------------------ evidence disks untouched
hash_disks >"$work/disks.after"
if diff -u "$work/disks.before" "$work/disks.after" >"$results/disk-hashes.diff"; then
  [[ -s "$work/disks.before" ]] && record pass "test disks unchanged ($(awk '{print $1}' "$work/disks.before" | paste -sd, -))"
else
  record fail "a test disk changed during the run (see $results/disk-hashes.diff)"
fi

if [[ -n "$results_dir" ]]; then
  mkdir -p -- "$results_dir"
  cp -r -- "$results/." "$results_dir/"
  cp -- "$work/disks.before" "$work/disks.after" "$results_dir/" 2>/dev/null || true
fi

log "summary: $passes passed, ${#failures[@]} failed, $skips skipped"
if ((${#failures[@]})); then
  printf 'run-qemu-tests: failed: %s\n' "${failures[@]}" >&2
  exit 1
fi
exit 0
