#!/usr/bin/env bash
# Build the AIRLOCK raw image with Packer (task 1.7).
#
# Reads the ISO pin from ansible/group_vars/all/pins.yml and the drive layout, apt snapshot,
# and version from ansible/group_vars/all/main.yml, so those files stay the single source.
# Uses exactly the pinned Packer and QEMU plugin versions: if they are missing it downloads
# them from releases.hashicorp.com into the cache and checks their SHA-256 against pins.yml.
# A fresh SSH key is made for each build and deleted afterwards; it is never stored.
#
# Usage: scripts/build.sh [options]
#   --output DIR        output folder (default: output/airlock-<version>)
#   --cache DIR         download cache (default: cache/)
#   --accel MODE        auto (default), kvm, or tcg. auto refuses to build without /dev/kvm.
#   --force             replace an existing output folder
#   --zstd-level N      compression level for the published archive (default 15)
#   --idempotence-check run site.yml twice in the guest and fail on any change
#   --var KEY=VALUE     extra Packer variable (repeatable)
#   --dry-run           check inputs, print the Packer variables and command, build nothing
#   --prepare-tools     only fetch and check the pinned Packer and QEMU plugin, then stop
#   --pins FILE         pins file (default: ansible/group_vars/all/pins.yml)
#   --vars FILE         main variables file (default: ansible/group_vars/all/main.yml)
#   -h, --help          this help
#
# Exit status: 0 on success; 1 with one line saying what failed and what to do next.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

PACKER_VERSION="1.11.2"
QEMU_PLUGIN_VERSION="1.1.8"
PACKER_PIN="packer_linux_amd64"
QEMU_PLUGIN_PIN="packer_plugin_qemu_linux_amd64"

pins_file="$repo_root/ansible/group_vars/all/pins.yml"
vars_file="$repo_root/ansible/group_vars/all/main.yml"
output_dir=""
cache_dir="$repo_root/cache"
accel="auto"
force=0
dry_run=0
prepare_only=0
zstd_level=15
idempotence=0
extra_vars=()

die() {
  printf 'build.sh: %s\n' "$*" >&2
  exit 1
}
log() { printf 'build.sh: %s\n' "$*"; }
have() { command -v "$1" >/dev/null 2>&1; }

usage() { sed -n '2,25p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; }

while (($#)); do
  case "$1" in
    --output) output_dir="${2:?--output needs a folder}"; shift 2 ;;
    --cache) cache_dir="${2:?--cache needs a folder}"; shift 2 ;;
    --accel) accel="${2:?--accel needs auto, kvm, or tcg}"; shift 2 ;;
    --force) force=1; shift ;;
    --zstd-level) zstd_level="${2:?--zstd-level needs a number}"; shift 2 ;;
    --idempotence-check) idempotence=1; shift ;;
    --var) extra_vars+=("${2:?--var needs KEY=VALUE}"); shift 2 ;;
    --dry-run) dry_run=1; shift ;;
    --prepare-tools) prepare_only=1; shift ;;
    --pins) pins_file="${2:?--pins needs a file}"; shift 2 ;;
    --vars) vars_file="${2:?--vars needs a file}"; shift 2 ;;
    -h | --help) usage; exit 0 ;;
    *) die "unknown option '$1'. Run scripts/build.sh --help." ;;
  esac
done

case "$accel" in auto | kvm | tcg) ;; *) die "--accel must be auto, kvm, or tcg, not '$accel'." ;; esac
if ! [[ "$zstd_level" =~ ^[0-9]+$ ]] || ((zstd_level < 1 || zstd_level > 19)); then
  die "--zstd-level must be 1 to 19, not '$zstd_level'."
fi
for kv in "${extra_vars[@]+"${extra_vars[@]}"}"; do
  [[ "$kv" =~ ^[a-z_][a-z0-9_]*=.*$ ]] || die "--var '$kv' is not KEY=VALUE."
done

# ---------------------------------------------------------------------------- host checks
[[ "$(uname -s)" == "Linux" && "$(uname -m)" == "x86_64" ]] ||
  die "the build host must be Linux x86_64 (this is $(uname -s) $(uname -m))."
have python3 || die "python3 is missing. Install it (apt install python3 python3-yaml) and rerun."
python3 -c 'import yaml' 2>/dev/null || die "Python YAML support is missing. Install it (apt install python3-yaml) and rerun."
have openssl || die "openssl is missing. Install it (apt install openssl) and rerun."
[[ -f "$pins_file" ]] || die "pins file $pins_file not found."
[[ -f "$vars_file" ]] || die "variables file $vars_file not found."

if ((prepare_only)); then
  have curl || die "curl is missing. Install it (apt install curl) and rerun."
elif ((!dry_run)); then
  missing=()
  for c in qemu-system-x86_64 qemu-img zstd sha256sum curl; do have "$c" || missing+=("$c"); done
  ((${#missing[@]} == 0)) ||
    die "missing tools: ${missing[*]}. Install them (apt install qemu-system-x86 qemu-utils zstd coreutils curl) and rerun."
fi

if ((prepare_only)); then
  : # no VM is started
elif [[ "$accel" == "auto" ]]; then
  if [[ -r /dev/kvm && -w /dev/kvm ]]; then
    accel=kvm
  elif ((dry_run)); then
    accel=tcg
    log "no usable /dev/kvm; a real build would need --accel tcg (dry run continues)"
  else
    die "no usable /dev/kvm. Enable virtualisation (KVM) on this host, or rerun with --accel tcg to emulate (many hours)."
  fi
elif [[ "$accel" == "kvm" ]] && ! [[ -r /dev/kvm && -w /dev/kvm ]] && ((!dry_run)); then
  die "--accel kvm was asked for but /dev/kvm is not usable. Add your user to the kvm group, or use --accel tcg."
fi

# ---------------------------------------------------------------------------- inputs
# One KEY=VALUE per line from the pins and variables files. Values are checked here.
read_inputs() {
  python3 - "$pins_file" "$vars_file" "$PACKER_PIN" "$QEMU_PLUGIN_PIN" <<'PY'
import re
import sys

import yaml

pins_path, vars_path, packer_pin, plugin_pin = sys.argv[1:5]
with open(pins_path, encoding="utf-8") as fh:
    pins = (yaml.safe_load(fh) or {}).get("pins") or {}
with open(vars_path, encoding="utf-8") as fh:
    main = yaml.safe_load(fh) or {}


def fail(msg: str) -> None:
    print(f"ERROR={msg}")
    sys.exit(0)


iso = pins.get("ubuntu_server_iso")
if not iso:
    fail("pins.ubuntu_server_iso is missing from the pins file")
sha = iso.get("sha256")
if not isinstance(sha, str) or not re.fullmatch(r"[0-9a-f]{64}", sha):
    fail("pins.ubuntu_server_iso.sha256 is not pinned (null or not 64 hex characters); fill it first")
url = iso.get("url") or ""
if not url.startswith("https://"):
    fail("pins.ubuntu_server_iso.url must be an https URL")

out = {"ISO_URL": url, "ISO_SHA256": sha}
for key, pin in (("PACKER", packer_pin), ("QEMU_PLUGIN", plugin_pin)):
    entry = pins.get(pin) or {}
    out[f"{key}_URL"] = entry.get("url") or ""
    out[f"{key}_SHA256"] = entry.get("sha256") or ""
    out[f"{key}_PIN_VERSION"] = str(entry.get("version") or "")

snap = str(main.get("apt_snapshot", ""))
if not re.fullmatch(r"[0-9]{8}T[0-9]{6}Z", snap):
    fail("apt_snapshot in main.yml must look like 20261101T000000Z")
out["APT_SNAPSHOT"] = snap
out["USE_APT_SNAPSHOT"] = "true" if main.get("use_apt_snapshot", True) else "false"
for key in ("esp_size_mib", "assets_partition_gib", "output_partition_gib", "root_image_gib"):
    val = main.get(key)
    if not isinstance(val, int) or isinstance(val, bool) or val <= 0:
        fail(f"{key} in main.yml must be a positive whole number")
    out[key.upper()] = str(val)
ver = str(main.get("airlock_version", ""))
if not re.fullmatch(r"[0-9A-Za-z][0-9A-Za-z.+-]*", ver):
    fail("airlock_version in main.yml must be letters, digits, dots, plus or minus")
out["AIRLOCK_VERSION"] = ver
out["AIRLOCK_USER"] = str(main.get("airlock_user", "analyst"))
for k, v in out.items():
    if "\n" in v:
        fail(f"{k} contains a line break")
    print(f"{k}={v}")
PY
}

declare -A in=()
while IFS='=' read -r key value; do
  [[ -n "$key" ]] || continue
  in["$key"]="$value"
done < <(read_inputs)
[[ -z "${in[ERROR]:-}" ]] || die "${in[ERROR]}."
[[ -n "${in[ISO_SHA256]:-}" ]] || die "could not read $pins_file and $vars_file."

[[ "${in[PACKER_PIN_VERSION]}" == "$PACKER_VERSION" ]] ||
  die "pins.$PACKER_PIN.version is '${in[PACKER_PIN_VERSION]}' but build.sh pins Packer $PACKER_VERSION. Make them match."
[[ "${in[QEMU_PLUGIN_PIN_VERSION]}" == "$QEMU_PLUGIN_VERSION" ]] ||
  die "pins.$QEMU_PLUGIN_PIN.version is '${in[QEMU_PLUGIN_PIN_VERSION]}' but build.sh pins the QEMU plugin $QEMU_PLUGIN_VERSION. Make them match."

version="${in[AIRLOCK_VERSION]}"
[[ -n "$output_dir" ]] || output_dir="$repo_root/output/airlock-$version"
output_dir="$(realpath -m -- "$output_dir")"
cache_dir="$(realpath -m -- "$cache_dir")"
if ((prepare_only)); then
  mkdir -p -- "$cache_dir" || die "could not create $cache_dir."
elif ((!dry_run)); then
  mkdir -p -- "$(dirname -- "$output_dir")" "$cache_dir" ||
    die "could not create $(dirname -- "$output_dir") or $cache_dir."
fi

if [[ -e "$output_dir" ]] && ((!force)) && ((!dry_run)) && ((!prepare_only)); then
  die "output folder $output_dir already exists. Move it away or rerun with --force."
fi

# Build metadata: SOURCE_DATE_EPOCH makes the date reproducible.
if [[ -n "${SOURCE_DATE_EPOCH:-}" ]]; then
  [[ "$SOURCE_DATE_EPOCH" =~ ^[0-9]+$ ]] || die "SOURCE_DATE_EPOCH must be whole seconds."
  build_date="$(date -u -d "@$SOURCE_DATE_EPOCH" +%Y-%m-%dT%H:%M:%SZ)"
else
  build_date="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
fi
git_commit="unknown"
if have git && git -C "$repo_root" rev-parse --git-dir >/dev/null 2>&1; then
  git_commit="$(git -C "$repo_root" rev-parse HEAD 2>/dev/null || echo unknown)"
  if [[ -n "$(git -C "$repo_root" status --porcelain 2>/dev/null)" ]]; then
    git_commit="$git_commit-dirty"
  fi
fi

# ---------------------------------------------------------------------------- pinned tools
tools_dir="$cache_dir/tools"
plugin_dir="$cache_dir/packer-plugins"

# fetch_pinned URL SHA256 DEST: download once, keep by hash, refuse a mismatch.
fetch_pinned() {
  local url="$1" sha="$2" dest="$3"
  [[ "$sha" =~ ^[0-9a-f]{64}$ ]] || die "no SHA-256 pinned for $url. Fill it in pins.yml first."
  if [[ -f "$dest" ]] && [[ "$(sha256sum -- "$dest" | cut -d' ' -f1)" == "$sha" ]]; then
    return 0
  fi
  mkdir -p -- "$(dirname -- "$dest")"
  log "downloading $url"
  curl -fsSL --retry 3 -o "$dest.part" -- "$url" || die "download failed: $url. Check the network and rerun."
  [[ "$(sha256sum -- "$dest.part" | cut -d' ' -f1)" == "$sha" ]] ||
    die "SHA-256 mismatch for $url. The file was not used; check pins.yml and the download source."
  mv -f -- "$dest.part" "$dest"
}

unzip_member() { # ZIP MEMBER-REGEX DEST
  python3 - "$1" "$2" "$3" <<'PY'
import re
import shutil
import sys
import zipfile

zpath, pattern, dest = sys.argv[1:4]
with zipfile.ZipFile(zpath) as zf:
    names = [n for n in zf.namelist() if re.fullmatch(pattern, n)]
    if len(names) != 1:
        sys.exit(f"expected one member matching {pattern} in {zpath}, found {names}")
    with zf.open(names[0]) as src, open(dest, "wb") as dst:
        shutil.copyfileobj(src, dst)
print(names[0])
PY
}

ensure_packer() {
  if have packer && [[ "$(packer version 2>/dev/null | head -n1)" == "Packer v$PACKER_VERSION" ]]; then
    packer_bin="$(command -v packer)"
    return 0
  fi
  local zip="$cache_dir/sha256/${in[PACKER_SHA256]}.zip"
  fetch_pinned "${in[PACKER_URL]}" "${in[PACKER_SHA256]}" "$zip"
  mkdir -p -- "$tools_dir/packer-$PACKER_VERSION"
  unzip_member "$zip" 'packer' "$tools_dir/packer-$PACKER_VERSION/packer" >/dev/null ||
    die "could not unpack Packer from $zip. Delete the cache folder and rerun."
  chmod 0755 -- "$tools_dir/packer-$PACKER_VERSION/packer"
  packer_bin="$tools_dir/packer-$PACKER_VERSION/packer"
}

ensure_qemu_plugin() {
  export PACKER_PLUGIN_PATH="$plugin_dir"
  if "$packer_bin" plugins installed 2>/dev/null | grep -q "packer-plugin-qemu_v${QEMU_PLUGIN_VERSION}_"; then
    return 0
  fi
  local zip="$cache_dir/sha256/${in[QEMU_PLUGIN_SHA256]}.zip" member bin
  fetch_pinned "${in[QEMU_PLUGIN_URL]}" "${in[QEMU_PLUGIN_SHA256]}" "$zip"
  mkdir -p -- "$tools_dir/qemu-plugin-$QEMU_PLUGIN_VERSION"
  member="$(unzip_member "$zip" "packer-plugin-qemu_v${QEMU_PLUGIN_VERSION}_x[0-9.]+_linux_amd64" \
    "$tools_dir/qemu-plugin-$QEMU_PLUGIN_VERSION/plugin")" ||
    die "could not unpack the QEMU plugin from $zip. Delete the cache folder and rerun."
  bin="$tools_dir/qemu-plugin-$QEMU_PLUGIN_VERSION/$member"
  mv -f -- "$tools_dir/qemu-plugin-$QEMU_PLUGIN_VERSION/plugin" "$bin"
  chmod 0755 -- "$bin"
  "$packer_bin" plugins install --path "$bin" github.com/hashicorp/qemu >/dev/null ||
    die "packer could not install the QEMU plugin from $bin."
}

if ((prepare_only)); then
  ensure_packer
  ensure_qemu_plugin
  log "ok: $packer_bin ($("$packer_bin" version | head -n1)), plugins in $PACKER_PLUGIN_PATH"
  "$packer_bin" plugins installed
  exit 0
fi

# ---------------------------------------------------------------------------- per-build key
work="$(mktemp -d "${TMPDIR:-/tmp}/airlock-build.XXXXXX")"
cleanup() { rm -rf -- "$work"; }
trap cleanup EXIT

# Ed25519 via openssl (always present); Packer reads the PKCS#8 key, the guest gets the
# OpenSSH public form.
openssl genpkey -algorithm ed25519 -out "$work/build_key" 2>/dev/null ||
  die "openssl could not make a build key."
chmod 0600 -- "$work/build_key"
pubkey="$(openssl pkey -in "$work/build_key" -pubout -outform DER | python3 -c '
import base64, struct, sys
raw = sys.stdin.buffer.read()[-32:]
def s(b): return struct.pack(">I", len(b)) + b
print("ssh-ed25519 " + base64.b64encode(s(b"ssh-ed25519") + s(raw)).decode() + " airlock-build-ephemeral")
')" || die "could not derive the build public key."

boot_wait="10s"
# The ISO's grub menu waits 30 s; under emulation OVMF needs about 15 to 30 s to reach it.
[[ "$accel" == "tcg" ]] && boot_wait="45s"

# ---------------------------------------------------------------------------- variables
var_file="$work/airlock.pkrvars.json"
# Values travel as environment variables, never pasted into program text.
AL_ACCEL="$accel" AL_USER="${in[AIRLOCK_USER]}" AL_VERSION="$version" \
  AL_SNAPSHOT="${in[APT_SNAPSHOT]}" AL_USE_SNAPSHOT="${in[USE_APT_SNAPSHOT]}" \
  AL_ASSETS="${in[ASSETS_PARTITION_GIB]}" AL_OUTPUT="${in[OUTPUT_PARTITION_GIB]}" \
  AL_ROOT="${in[ROOT_IMAGE_GIB]}" AL_ESP="${in[ESP_SIZE_MIB]}" AL_BOOT_WAIT="$boot_wait" \
  AL_DATE="$build_date" AL_KEY="$work/build_key" AL_PUBKEY="$pubkey" AL_COMMIT="$git_commit" \
  AL_IDEMPOTENCE="$idempotence" AL_ISO_SHA="${in[ISO_SHA256]}" AL_ISO_URL="${in[ISO_URL]}" \
  AL_OUT="$output_dir" AL_ZSTD="$zstd_level" \
  python3 - "$var_file" "${extra_vars[@]+"${extra_vars[@]}"}" <<'PY'
import json
import os
import sys

e = os.environ
out = {
    "accelerator": e["AL_ACCEL"],
    "airlock_user": e["AL_USER"],
    "airlock_version": e["AL_VERSION"],
    "apt_snapshot": e["AL_SNAPSHOT"],
    "assets_partition_gib": int(e["AL_ASSETS"]),
    "boot_wait": e["AL_BOOT_WAIT"],
    "build_date": e["AL_DATE"],
    "build_ssh_private_key_file": e["AL_KEY"],
    "build_ssh_public_key": e["AL_PUBKEY"],
    "esp_size_mib": int(e["AL_ESP"]),
    "git_commit": e["AL_COMMIT"],
    "idempotence_check": e["AL_IDEMPOTENCE"] == "1",
    "iso_sha256": e["AL_ISO_SHA"],
    "iso_url": e["AL_ISO_URL"],
    "output_dir": e["AL_OUT"],
    "output_partition_gib": int(e["AL_OUTPUT"]),
    "root_image_gib": int(e["AL_ROOT"]),
    "use_apt_snapshot": e["AL_USE_SNAPSHOT"] == "true",
    "zstd_level": int(e["AL_ZSTD"]),
}
for kv in sys.argv[2:]:
    key, _, value = kv.partition("=")
    out[key] = value
with open(sys.argv[1], "w", encoding="utf-8") as fh:
    json.dump(out, fh, indent=2, sort_keys=True)
    fh.write("\n")
PY

packer_args=(build -var-file="$var_file")
((force)) && packer_args+=(-force)
packer_args+=("$repo_root/packer")

if ((dry_run)); then
  log "dry run: no image is built"
  printf 'packer_version=%s\nqemu_plugin_version=%s\naccelerator=%s\noutput=%s\n' \
    "$PACKER_VERSION" "$QEMU_PLUGIN_VERSION" "$accel" "$output_dir"
  printf 'command: packer'
  printf ' %q' "${packer_args[@]}"
  printf '\n'
  # The key path is per run and the public key is not useful to show.
  python3 -c '
import json, sys
data = json.load(open(sys.argv[1], encoding="utf-8"))
data["build_ssh_private_key_file"] = "<temporary>"
data["build_ssh_public_key"] = "<temporary>"
print(json.dumps(data, indent=2, sort_keys=True))
' "$var_file"
  exit 0
fi

ensure_packer
ensure_qemu_plugin
export CHECKPOINT_DISABLE=1
export PACKER_CACHE_DIR="$cache_dir/packer"
mkdir -p -- "$PACKER_CACHE_DIR"
export PACKER_LOG=1
export PACKER_LOG_PATH="$output_dir.packer.log"

log "validating the Packer template"
"$packer_bin" validate -var-file="$var_file" "$repo_root/packer" >/dev/null ||
  die "packer validate failed. Run '$packer_bin validate -var-file=... packer/' to see why."

log "building AIRLOCK $version ($accel). Packer log: $PACKER_LOG_PATH"
[[ "$accel" == "tcg" ]] && log "emulation is slow: expect several hours"
"$packer_bin" "${packer_args[@]}" ||
  die "packer build failed. Read the end of $PACKER_LOG_PATH and $output_dir/serial.log, fix the cause, and rerun with --force."

log "done: $output_dir"
(cd "$output_dir" && cat SHA256SUMS)
