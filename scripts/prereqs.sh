#!/usr/bin/env bash
# Check, and on request install, what make-usb.sh needs on the Linux build host (task 2A.1).
#
# Usage: scripts/prereqs.sh [--check | --install] [options]
#   --check             list what is missing (default). Exit 0 if nothing is, 3 if something is.
#   --install           install what is missing: Ubuntu/Debian packages with apt-get, goss from
#                       its pin in pins.yml, Packer and its QEMU plugin through
#                       scripts/build.sh --prepare-tools (pinned version and SHA-256)
#   --for WHAT          build, flash, or all (default all). build = build the image and boot
#                       test it; flash = write, stage and smoke-boot a drive.
#   --yes               install without asking
#   --cache DIR         download cache (default: cache/ in the repository)
#   --goss-path         print the goss binary to use (on PATH or in the cache) and stop
#   -h, --help          this help
#
# Ansible is not listed: it runs inside the build VM, not on the host (decision log 2026-11-15).
# Downloads are checked against pins.yml; a pin without a SHA-256 is never downloaded.
# Exit status: 0 nothing missing; 3 something missing (--check); 1 an install step failed;
# 2 bad usage.
# Test: tests/functional/test_make_usb.sh
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
prog="prereqs.sh"
pins_file="$repo_root/ansible/group_vars/all/pins.yml"
cache_dir="$repo_root/cache"
mode="check"
want="all"
yes=0
PACKER_VERSION="1.11.2"
GOSS_PIN="goss_linux_amd64"

usage() { sed -n '2,/^set -euo pipefail$/p' "${BASH_SOURCE[0]}" | sed '$d' | sed 's/^# \{0,1\}//'; }
die() {
  printf '%s: %s\n' "$prog" "$*" >&2
  exit 1
}
bad_usage() {
  printf '%s: %s Run scripts/prereqs.sh --help.\n' "$prog" "$*" >&2
  exit 2
}
log() { printf '%s: %s\n' "$prog" "$*"; }
have() { command -v "$1" >/dev/null 2>&1; }

while (($#)); do
  case "$1" in
    --check) mode="check"; shift ;;
    --install) mode="install"; shift ;;
    --goss-path) mode="goss-path"; shift ;;
    --for) want="${2:-}"; shift 2 || bad_usage "--for needs build, flash, or all." ;;
    --yes) yes=1; shift ;;
    --cache) cache_dir="${2:-}"; shift 2 || bad_usage "--cache needs a folder." ;;
    -h | --help) usage; exit 0 ;;
    *) bad_usage "unknown option '$1'." ;;
  esac
done
case "$want" in build | flash | all) ;; *) bad_usage "--for must be build, flash, or all." ;; esac

# pin_field ID FIELD: one field of a pin from pins.yml ("" when missing or null).
pin_field() {
  have python3 || return 0
  python3 - "$pins_file" "$1" "$2" <<'PY' 2>/dev/null || true
import sys

import yaml

with open(sys.argv[1], encoding="utf-8") as fh:
    pins = (yaml.safe_load(fh) or {}).get("pins") or {}
value = (pins.get(sys.argv[2]) or {}).get(sys.argv[3])
if value is not None:
    text = str(value)
    if "\n" not in text:
        print(text)
PY
}

goss_version() { pin_field "$GOSS_PIN" version; }

# goss_path: goss on PATH, else the copy prereqs.sh installed into the cache.
goss_path() {
  local ver cached
  if have goss; then
    command -v goss
    return 0
  fi
  ver="$(goss_version)"
  cached="$cache_dir/tools/goss-${ver:-unknown}/goss"
  if [[ -n "$ver" && -x "$cached" ]]; then
    printf '%s\n' "$cached"
    return 0
  fi
  return 1
}

packer_ok() {
  if have packer && [[ "$(packer version 2>/dev/null | head -n1)" == "Packer v$PACKER_VERSION" ]]; then
    return 0
  fi
  [[ -x "$cache_dir/tools/packer-$PACKER_VERSION/packer" ]]
}

exfat_mount_ok() {
  grep -qw exfat /proc/filesystems 2>/dev/null && return 0
  have modinfo && modinfo exfat >/dev/null 2>&1 && return 0
  have mount.exfat-fuse
}

ovmf_ok() { [[ -f "${AIRLOCK_OVMF_CODE:-/usr/share/OVMF/OVMF_CODE_4M.fd}" ]]; }

python_yaml_ok() { have python3 && python3 -c 'import yaml' >/dev/null 2>&1; }

# Requirements: "check|apt package|needed for|what it is for". check is cmd:NAME or fn:FUNCTION.
REQS=(
  "cmd:qemu-system-x86_64|qemu-system-x86|build,flash|QEMU, runs the build VM and the boot tests"
  "cmd:qemu-img|qemu-utils|build,flash|qemu-img, makes the test disk overlays"
  "fn:ovmf_ok|ovmf|build,flash|UEFI firmware for QEMU"
  "cmd:zstd|zstd|build,flash|zstd, compresses and unpacks the image"
  "cmd:curl|curl|build,flash|curl, downloads pinned files"
  "cmd:python3|python3|build,flash|Python 3"
  "fn:python_yaml_ok|python3-yaml|build,flash|Python YAML support, reads pins.yml"
  "cmd:openssl|openssl|build|openssl, makes the one-time build key"
  "cmd:sha256sum|coreutils|build,flash|sha256sum"
  "cmd:sgdisk|gdisk|build|sgdisk, builds the boot-test disks"
  "cmd:mkfs.ext4|e2fsprogs|build|mkfs.ext4, builds the boot-test disks"
  "cmd:mkswap|util-linux|build|mkswap, builds the boot-test disks"
  "cmd:tar|tar|build,flash|tar, packs the in-guest tests"
  "cmd:lsblk|util-linux|flash|lsblk, finds the USB drive"
  "cmd:findmnt|util-linux|flash|findmnt, finds mounted drives"
  "cmd:blockdev|util-linux|flash|blockdev, reads the drive size"
  "cmd:partx|util-linux|flash|partx, rereads the partition table after writing"
  "cmd:fsck.exfat|exfatprogs|flash|exFAT tools, for the ASSETS partition"
  "fn:exfat_mount_ok|exfat-fuse|flash|exFAT mount support, to stage files onto ASSETS"
  "fn:goss_present|PIN:goss|build,flash|goss, runs the tests inside the booted image"
  "fn:packer_ok|PACKER|build|Packer $PACKER_VERSION and its QEMU plugin"
)

goss_present() { goss_path >/dev/null; }

if [[ "$mode" == "goss-path" ]]; then
  goss_path || exit 1
  exit 0
fi

missing=()     # human lines
apt_pkgs=()    # apt packages to install
need_goss=0
need_packer=0

scan() {
  local entry check pkg for_list what ok
  missing=()
  apt_pkgs=()
  need_goss=0
  need_packer=0
  for entry in "${REQS[@]}"; do
    IFS='|' read -r check pkg for_list what <<<"$entry"
    if [[ "$want" != "all" && ",$for_list," != *",$want,"* ]]; then
      continue
    fi
    ok=0
    case "$check" in
      cmd:*) have "${check#cmd:}" && ok=1 ;;
      fn:*) "${check#fn:}" && ok=1 ;;
    esac
    ((ok)) && continue
    case "$pkg" in
      PIN:goss)
        need_goss=1
        missing+=("$what (pinned download: pins.$GOSS_PIN)")
        ;;
      PACKER)
        need_packer=1
        missing+=("$what (pinned download: scripts/build.sh --prepare-tools)")
        ;;
      *)
        missing+=("$what (apt package $pkg)")
        [[ " ${apt_pkgs[*]-} " == *" $pkg "* ]] || apt_pkgs+=("$pkg")
        ;;
    esac
  done
}

print_missing() {
  local m
  for m in "${missing[@]}"; do printf 'missing: %s\n' "$m"; done
}

scan
if ((${#missing[@]} == 0)); then
  log "all prerequisites for '$want' are present"
  exit 0
fi
print_missing
if [[ "$mode" == "check" ]]; then
  log "${#missing[@]} missing. Install them with: sudo scripts/prereqs.sh --install --for $want"
  exit 3
fi

# ---------------------------------------------------------------------------- install
if ((!yes)); then
  [[ -t 0 ]] || die "nothing installed: no terminal to ask. Rerun with --yes to install the list above."
  read -r -p "Install the missing items now? [y/N] " answer || answer=""
  [[ "$answer" =~ ^[Yy]([Ee][Ss])?$ ]] || die "nothing installed. Install the list above yourself, then rerun."
fi

if ((${#apt_pkgs[@]})); then
  have apt-get ||
    die "apt-get not found. Install these with your package manager: ${apt_pkgs[*]}; then rerun."
  [[ "$(id -u)" == "0" ]] || die "installing packages needs root. Rerun with sudo."
  log "installing with apt-get: ${apt_pkgs[*]}"
  DEBIAN_FRONTEND=noninteractive apt-get update -q ||
    die "apt-get update failed. Check the network and the apt sources, then rerun."
  DEBIAN_FRONTEND=noninteractive apt-get install -y -q --no-install-recommends "${apt_pkgs[@]}" ||
    die "apt-get install failed for: ${apt_pkgs[*]}. Read the message above, fix it, and rerun."
fi

if ((need_goss)); then
  ver="$(goss_version)"
  url="$(pin_field "$GOSS_PIN" url)"
  sha="$(pin_field "$GOSS_PIN" sha256)"
  [[ -n "$ver" && "$url" == https://* ]] || die "pins.$GOSS_PIN is missing from $pins_file."
  [[ "$sha" =~ ^[0-9a-f]{64}$ ]] ||
    die "pins.$GOSS_PIN has no SHA-256 yet, so goss is not downloaded. Install goss $ver yourself (on PATH), or fill the pin, then rerun."
  have curl || die "curl is missing. Install it (apt install curl) and rerun."
  dest="$cache_dir/sha256/$sha"
  mkdir -p -- "$cache_dir/sha256"
  if ! [[ -f "$dest" && "$(sha256sum -- "$dest" | cut -d' ' -f1)" == "$sha" ]]; then
    log "downloading goss $ver"
    curl -fsSL --retry 3 -o "$dest.part" -- "$url" || die "download failed: $url. Check the network and rerun."
    [[ "$(sha256sum -- "$dest.part" | cut -d' ' -f1)" == "$sha" ]] ||
      die "goss download does not match pins.$GOSS_PIN.sha256; it was not used. Check the pin and the download."
    mv -f -- "$dest.part" "$dest"
  fi
  mkdir -p -- "$cache_dir/tools/goss-$ver"
  install -m 0755 -- "$dest" "$cache_dir/tools/goss-$ver/goss"
  log "goss $ver is in $cache_dir/tools/goss-$ver/goss"
fi

if ((need_packer)); then
  log "fetching the pinned Packer and QEMU plugin with scripts/build.sh --prepare-tools"
  "$repo_root/scripts/build.sh" --prepare-tools --cache "$cache_dir" ||
    die "could not fetch the pinned Packer. Read the message above, fix it, and rerun."
fi

scan
if ((${#missing[@]})); then
  print_missing
  die "${#missing[@]} still missing after the install. Install them yourself, then rerun."
fi
log "all prerequisites for '$want' are present"
