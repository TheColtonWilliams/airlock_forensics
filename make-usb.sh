#!/usr/bin/env bash
# One command from a git checkout to a tested AIRLOCK drive (Milestone 2A).
#
#   sudo ./make-usb.sh
#
# Checks the build host, asks for the drive, the profile and an optional abuse.ch key, shows
# the download, image and time estimates, then runs, in order:
#   1. build        scripts/build.sh (the same base image the release publishes)
#   2. test         tests/run-qemu-tests.sh on the built image
#   3. flash        scripts/flash.sh (refuses wrong drives, verifies the written range)
#   4. stage        scripts/fetch-assets.sh onto the drive's ASSETS partition, using
#                   assets/manifest.json from scripts/gen-manifest.py (same code as Milestone 2B)
#   5. verify       reads every staged file back and checks its SHA-256 against profile.json
#   6. smoke boot   boots the drive itself in QEMU through a throw-away overlay (the drive is
#                   opened read-only) and runs tests/goss/smoke.yaml
# All questions come first; after that it runs unattended. On first boot the drive sets itself
# up from ASSETS with no network (forensic-provision).
#
# Options:
#   --profile NAME|FILE   default, minimal, full, ci, or a profile file (default: ask; default)
#   --target DEV          drive to erase, for example /dev/sdb (default: ask)
#   --confirm NAME        the drive's name typed back (for example sdb); needed with --yes
#   --abuse-key-file FILE read the optional abuse.ch key from FILE (it is never written
#                         anywhere and never logged). Default: ask, Enter skips.
#   --no-abuse-key        do not ask for the key (no MalwareBazaar hash set)
#   --image-only          build and test the image only; no drive is needed
#   --flash-only IMAGE    skip the build; write IMAGE (.raw or .raw.zst with SHA256SUMS beside it)
#   --yes                 ask nothing; needs --target and --confirm unless --image-only
#   --cache DIR           download cache, files kept by SHA-256 (default: cache/)
#   --output DIR          image folder (default: output/airlock-<version>)
#   --log FILE            full log (default: build.log)
#   --accel MODE          auto (default, needs /dev/kvm), kvm, or tcg (emulation, many hours)
#   --headroom-gb N       spare space the drive needs beyond the image (default 8)
#   --rebuild             build again even if a finished image is in the output folder
#   -h, --help            this help
#
# A rerun resumes: a finished image that still matches its SHA256SUMS is reused, a passed
# boot test is not repeated, and downloads come from the cache.
# Exit status: 0 done; 1 a check or step failed (one line names it); 2 bad usage.
# Test: tests/functional/test_make_usb.sh
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
prog="make-usb"

flash_sh="$repo_root/scripts/flash.sh"
build_sh="$repo_root/scripts/build.sh"
prereqs_sh="$repo_root/scripts/prereqs.sh"
fetch_sh="$repo_root/scripts/fetch-assets.sh"
gen_manifest="$repo_root/scripts/gen-manifest.py"
qemu_tests="$repo_root/tests/run-qemu-tests.sh"
manifest="$repo_root/assets/manifest.json"
main_vars="$repo_root/ansible/group_vars/all/main.yml"
pins_file="$repo_root/ansible/group_vars/all/pins.yml"
kvm_dev="${AIRLOCK_KVM_DEV:-/dev/kvm}"

profile_arg=""
target=""
confirm=""
key_file=""
no_key=0
mode="full"
flash_image=""
yes=0
cache_dir="$repo_root/cache"
output_dir=""
log_file="$repo_root/build.log"
accel="auto"
headroom_gb=8
rebuild=0

usage() { sed -n '2,/^set -euo pipefail$/p' "${BASH_SOURCE[0]}" | sed '$d' | sed 's/^# \{0,1\}//'; }
die() {
  printf '%s: %s\n' "$prog" "$*" >&2
  exit 1
}
bad_usage() {
  printf '%s: %s Run ./make-usb.sh --help.\n' "$prog" "$*" >&2
  exit 2
}
have() { command -v "$1" >/dev/null 2>&1; }
gb() { awk -v b="$1" 'BEGIN { printf "%.1f GB", b / 1000000000 }'; }
# say: to the screen and the log.
say() {
  printf '%s\n' "$*"
  [[ -n "${log_ready:-}" ]] && printf '%s\n' "$*" >>"$log_file"
  return 0
}

while (($#)); do
  case "$1" in
    --profile) profile_arg="${2:-}"; shift 2 || bad_usage "--profile needs a name or a file." ;;
    --target) target="${2:-}"; shift 2 || bad_usage "--target needs a device." ;;
    --confirm) confirm="${2:-}"; shift 2 || bad_usage "--confirm needs the drive name." ;;
    --abuse-key-file) key_file="${2:-}"; shift 2 || bad_usage "--abuse-key-file needs a file." ;;
    --no-abuse-key) no_key=1; shift ;;
    --image-only) [[ "$mode" == "full" ]] || bad_usage "use only one of --image-only and --flash-only."; mode="image"; shift ;;
    --flash-only)
      [[ "$mode" == "full" ]] || bad_usage "use only one of --image-only and --flash-only."
      mode="flash"
      flash_image="${2:-}"
      shift 2 || bad_usage "--flash-only needs an image file."
      ;;
    --yes) yes=1; shift ;;
    --cache) cache_dir="${2:-}"; shift 2 || bad_usage "--cache needs a folder." ;;
    --output) output_dir="${2:-}"; shift 2 || bad_usage "--output needs a folder." ;;
    --log) log_file="${2:-}"; shift 2 || bad_usage "--log needs a file." ;;
    --accel) accel="${2:-}"; shift 2 || bad_usage "--accel needs auto, kvm, or tcg." ;;
    --headroom-gb) headroom_gb="${2:-}"; shift 2 || bad_usage "--headroom-gb needs a number." ;;
    --rebuild) rebuild=1; shift ;;
    -h | --help) usage; exit 0 ;;
    *) bad_usage "unknown option '$1'." ;;
  esac
done

case "$accel" in auto | kvm | tcg) ;; *) bad_usage "--accel must be auto, kvm, or tcg." ;; esac
[[ "$headroom_gb" =~ ^[0-9]+$ ]] || bad_usage "--headroom-gb must be a whole number."
if [[ "$mode" == "image" ]]; then
  [[ -z "$target" && -z "$confirm" ]] || bad_usage "--image-only writes no drive; drop --target and --confirm."
  [[ -z "$profile_arg" && -z "$key_file" ]] || bad_usage "--image-only stages nothing; drop --profile and --abuse-key-file."
fi
if ((yes)) && [[ "$mode" != "image" ]]; then
  [[ -n "$target" ]] || bad_usage "--yes needs --target (the drive to erase)."
  [[ -n "$confirm" ]] || bad_usage "--yes needs --confirm NAME, the drive's name typed back (for example sdb)."
fi
[[ -z "$key_file" ]] || ((!no_key)) || bad_usage "use only one of --abuse-key-file and --no-abuse-key."

mkdir -p -- "$cache_dir"
cache_dir="$(cd -- "$cache_dir" && pwd)"

# ---------------------------------------------------------------------------- Python helper
# Reads main.yml, pins.yml and the manifest. Prints KEY<TAB>VALUE lines; never evaluated.
read -r -d '' PY_PLAN <<'PY' || true
import json
import os
import re
import sys
from urllib.parse import urlparse

import yaml

what, main_path, pins_path, manifest_path, profile_arg = sys.argv[1:6]
GIB = 1024**3
MIB = 1024**2


def out(key, value):
    text = str(value).replace("\t", " ").replace("\n", " ")
    print(f"{key}\t{text}")


with open(main_path, encoding="utf-8") as fh:
    main = yaml.safe_load(fh) or {}

if what == "basics":
    out("VERSION", main.get("airlock_version", "unknown"))
    esp = int(main.get("esp_size_mib", 512))
    parts = sum(int(main.get(k, 0)) for k in ("assets_partition_gib", "output_partition_gib", "root_image_gib"))
    # 1 MiB alignment + 1 MiB BIOS boot + ESP + data partitions + 1 MiB backup GPT.
    out("IMAGE_BYTES", (3 + esp) * MIB + parts * GIB)
    out("ASSETS_BYTES", int(main.get("assets_partition_gib", 0)) * GIB)
    with open(pins_path, encoding="utf-8") as fh:
        pins = (yaml.safe_load(fh) or {}).get("pins") or {}
    iso = pins.get("ubuntu_server_iso") or {}
    out("NET_HOST", urlparse(iso.get("url") or "https://releases.ubuntu.com/").hostname or "releases.ubuntu.com")
    sys.exit(0)

manifest = {}
if manifest_path and os.path.isfile(manifest_path):
    with open(manifest_path, encoding="utf-8") as fh:
        manifest = json.load(fh)
files = {f.get("id"): f for f in manifest.get("files") or []}
profiles = manifest.get("profiles") or {}


def sized(ids):
    total = unknown = 0
    for i in ids:
        size = (files.get(i) or {}).get("size")
        if isinstance(size, int) and not isinstance(size, bool) and size >= 0:
            total += size
        else:
            unknown += 1
    return total, unknown


if what == "profiles":
    for name in sorted(profiles):
        out(name, (profiles[name] or {}).get("description", ""))
    sys.exit(0)

if what == "plan":
    build_ids = [i for i, f in files.items() if "build" in (f.get("profiles") or [])]
    total, unknown = sized(build_ids)
    out("BUILD_BYTES", total)
    out("BUILD_UNKNOWN", unknown)
    name = ""
    ids = None
    features = None
    if profile_arg and os.path.isfile(profile_arg):
        with open(profile_arg, encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
        if isinstance(data, dict) and isinstance(data.get("profiles"), dict) and len(data["profiles"]) == 1:
            name, data = next(iter(data["profiles"].items()))
        if isinstance(data, dict):
            name = str(data.get("name") or name or os.path.splitext(os.path.basename(profile_arg))[0])
            if isinstance(data.get("files"), list):
                ids = [str(i) for i in data["files"]]
            if isinstance(data.get("features"), dict):
                features = data["features"]
            if ids is None and name in profiles:
                ids = list((profiles[name] or {}).get("files") or [])
        out("PROFILE_KIND", "file")
    else:
        stem = re.sub(r"\.ya?ml$", "", profile_arg)
        if stem not in profiles:
            out("PROFILE_ERROR", f"no profile named '{profile_arg}' in the manifest")
            sys.exit(0)
        name = stem
        ids = list((profiles[stem] or {}).get("files") or [])
        features = (profiles[stem] or {}).get("features")
        out("PROFILE_KIND", "name")
    out("PROFILE_NAME", name)
    if ids is None:
        out("STAGE_BYTES", "")
        out("STAGE_FILES", "")
        out("STAGE_UNKNOWN", "")
    else:
        total, unknown = sized(ids)
        out("STAGE_BYTES", total)
        out("STAGE_FILES", len(ids))
        out("STAGE_UNKNOWN", unknown)
    if isinstance(features, dict) and "malwarebazaar" in features:
        out("MALWAREBAZAAR", "1" if features.get("malwarebazaar") else "0")
    else:
        out("MALWAREBAZAAR", "unknown")
    sys.exit(0)

sys.exit(f"unknown request {what}")
PY

# plan_query WHAT [PROFILE]: fills the associative array P from the helper's output.
declare -A P=()
plan_query() {
  local key value
  P=()
  while IFS=$'\t' read -r key value; do
    [[ -n "$key" ]] && P["$key"]="$value"
  done < <(python3 -c "$PY_PLAN" "$1" "$main_vars" "$pins_file" "$manifest" "${2:-}") ||
    die "could not read $main_vars, $pins_file or $manifest. Check they exist and are valid."
  return 0
}

# ---------------------------------------------------------------------------- prompts
tty_ok() { [[ -t 0 ]]; }
need_tty() { tty_ok || die "no terminal to ask $1. Pass $2 (or --yes with the needed flags)."; }

ask_yes_no() { # QUESTION -> 0 yes, 1 no
  local answer=""
  ((yes)) && return 0
  need_tty "'$1'" "--yes"
  read -r -p "$1 [y/N] " answer || answer=""
  [[ "$answer" =~ ^[Yy]([Ee][Ss])?$ ]]
}

# ---------------------------------------------------------------------------- host checks
host_checks() {
  local avail need
  [[ "$(uname -s)" == "Linux" && "$(uname -m)" == "x86_64" ]] ||
    die "this needs a Linux x86_64 computer (this is $(uname -s) $(uname -m)). On Windows, follow the Windows steps in docs/quickstart.md."
  if [[ "$mode" != "image" && "$(id -u)" != "0" ]]; then
    die "writing a drive needs root. Run it again with sudo: sudo ./make-usb.sh"
  fi
  if [[ "$accel" != "tcg" ]] && ! [[ -r "$kvm_dev" && -w "$kvm_dev" ]]; then
    die "no usable $kvm_dev (KVM). Turn on virtualisation (VT-x or AMD-V) in the firmware settings, or rerun with --accel tcg (emulation, many hours)."
  fi
  need="$1"
  avail="$(df -P -B1 -- "$cache_dir" 2>/dev/null | awk 'NR == 2 { print $4 }')"
  [[ "$avail" =~ ^[0-9]+$ ]] || die "could not read the free disk space under $cache_dir."
  if ((avail < need)); then
    die "not enough free disk space: $(gb "$avail") free under $cache_dir, about $(gb "$need") needed. Free some space or pass --cache and --output on a bigger disk."
  fi
}

check_internet() {
  if ! curl -sS -o /dev/null -I --max-time 20 "https://${P_BASICS_NET_HOST}/" 2>/dev/null; then
    if [[ -n "$(find "$cache_dir" -mindepth 1 -maxdepth 2 -print -quit 2>/dev/null)" ]]; then
      say "warning: cannot reach ${P_BASICS_NET_HOST}; continuing with the cache. Downloads that are not cached will fail."
    else
      die "no internet: cannot reach ${P_BASICS_NET_HOST}. Connect this computer to the internet and rerun."
    fi
  fi
}

check_prereqs() {
  local for_what rc=0
  case "$mode" in image) for_what=build ;; flash) for_what=flash ;; *) for_what=all ;; esac
  "$prereqs_sh" --check --for "$for_what" --cache "$cache_dir" || rc=$?
  ((rc == 0)) && return 0
  ((rc == 3)) || die "scripts/prereqs.sh failed (exit $rc). Read the message above."
  ask_yes_no "Install the missing items listed above now?" ||
    die "missing prerequisites. Install them (sudo scripts/prereqs.sh --install) and rerun."
  "$prereqs_sh" --install --yes --for "$for_what" --cache "$cache_dir" ||
    die "installing the prerequisites failed. Read the message above, fix it, and rerun."
}

# ---------------------------------------------------------------------------- start
have python3 || die "python3 is missing. Install it (apt install python3 python3-yaml) and rerun."
python3 -c 'import yaml' 2>/dev/null || die "Python YAML support is missing. Install it (apt install python3-yaml) and rerun."
[[ -f "$main_vars" && -f "$pins_file" ]] || die "$main_vars or $pins_file is missing. Run this from a full git checkout."

plan_query basics
[[ "${P[IMAGE_BYTES]:-}" =~ ^[0-9]+$ ]] || die "could not read the drive layout from $main_vars."
P_BASICS_NET_HOST="${P[NET_HOST]}"
version="${P[VERSION]}"
image_estimate="${P[IMAGE_BYTES]}"
assets_bytes="${P[ASSETS_BYTES]}"
[[ -n "$output_dir" ]] || output_dir="$repo_root/output/airlock-$version"
mkdir -p -- "$(dirname -- "$output_dir")"
output_dir="$(cd -- "$(dirname -- "$output_dir")" && pwd)/$(basename -- "$output_dir")"

if [[ "$mode" == "flash" ]]; then
  [[ -f "$flash_image" ]] || die "image $flash_image not found. Give the path to the .raw.zst (or .raw) file."
  flash_image="$(cd -- "$(dirname -- "$flash_image")" && pwd)/$(basename -- "$flash_image")"
fi

# Log: full output of every step. The abuse.ch key is never written here.
mkdir -p -- "$(dirname -- "$log_file")"
touch -- "$log_file" || die "cannot write the log file $log_file. Pass --log FILE."
chmod 0600 -- "$log_file" 2>/dev/null || true
log_ready=1
{
  printf '\n===== %s make-usb.sh started (mode %s, accel %s)\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$mode" "$accel"
} >>"$log_file"

say "AIRLOCK make-usb $version: checking this computer"
image_ready() {
  [[ -f "$output_dir/SHA256SUMS" ]] || return 1
  local zst
  zst="$(find_zst)" || return 1
  [[ -f "${zst%.zst}" ]] || return 1
  (cd -- "$output_dir" && sha256sum --quiet -c SHA256SUMS >/dev/null 2>&1)
}
find_zst() {
  local found=()
  shopt -s nullglob
  found=("$output_dir"/airlock-*.raw.zst)
  shopt -u nullglob
  ((${#found[@]} == 1)) || return 1
  printf '%s\n' "${found[0]}"
}

reuse_image=0
if [[ "$mode" != "flash" ]] && ((!rebuild)) && image_ready; then
  reuse_image=1
fi

# Space: the raw image, the ISO, the compressed copy and the tools, plus staged downloads.
space_need=$((2 * 1024 * 1024 * 1024))
if [[ "$mode" != "flash" ]] && ((!reuse_image)); then
  space_need=$((space_need + image_estimate + 8 * 1024 * 1024 * 1024))
fi

# ---------------------------------------------------------------------------- manifest
if [[ "$mode" != "image" && ! -f "$manifest" ]]; then
  [[ -f "$gen_manifest" ]] || die "assets/manifest.json and scripts/gen-manifest.py are both missing. Update the git checkout."
  say "making assets/manifest.json with scripts/gen-manifest.py"
  python3 "$gen_manifest" >>"$log_file" 2>&1 ||
    die "scripts/gen-manifest.py failed. See $log_file, fix the cause, and rerun."
  [[ -f "$manifest" ]] || die "scripts/gen-manifest.py did not write assets/manifest.json. See $log_file."
fi

# ---------------------------------------------------------------------------- profile
profile_name=""
stage_bytes=""
if [[ "$mode" != "image" ]]; then
  if [[ -z "$profile_arg" ]]; then
    if ((yes)); then
      profile_arg="default"
    else
      need_tty "for the profile" "--profile NAME"
      plan_query profiles
      printf '\nProfiles (what gets staged on the drive for offline use):\n'
      for p in default minimal full; do
        [[ -n "${P[$p]+x}" ]] && printf '  %-8s %s\n' "$p" "${P[$p]}"
      done
      read -r -p "Profile [default], or a profile file: " profile_arg || profile_arg=""
      profile_arg="${profile_arg:-default}"
    fi
  fi
  plan_query plan "$profile_arg"
  [[ -z "${P[PROFILE_ERROR]:-}" ]] || die "${P[PROFILE_ERROR]}. Use default, minimal, full, ci, or a profile file."
  profile_name="${P[PROFILE_NAME]}"
  # The fetcher gets the profile's name, or the profile file's full path.
  if [[ "${P[PROFILE_KIND]}" == "file" ]]; then
    fetch_profile="$(cd -- "$(dirname -- "$profile_arg")" && pwd)/$(basename -- "$profile_arg")"
  else
    fetch_profile="$profile_name"
  fi
  stage_bytes="${P[STAGE_BYTES]}"
  stage_unknown="${P[STAGE_UNKNOWN]}"
  stage_files="${P[STAGE_FILES]}"
  build_bytes="${P[BUILD_BYTES]}"
  build_unknown="${P[BUILD_UNKNOWN]}"
  wants_mb="${P[MALWAREBAZAAR]}"
  [[ -n "$stage_bytes" ]] && space_need=$((space_need + stage_bytes))
else
  plan_query plan default 2>/dev/null || true
  build_bytes="${P[BUILD_BYTES]:-0}"
  build_unknown="${P[BUILD_UNKNOWN]:-0}"
fi

host_checks "$space_need"
check_prereqs
check_internet

# ---------------------------------------------------------------------------- target
t_name=""
t_serial=""
t_size=0
t_model=""
if [[ "$mode" != "image" ]]; then
  drives_json="$("$flash_sh" --list --json)" || die "scripts/flash.sh --list failed. Read the message above."
  # drive_rows: name, path, size, model, serial, problem (TSV, "-" for empty)
  drive_rows() {
    python3 -c '
import json, sys
for r in json.loads(sys.argv[1]):
    vals = [r["name"], r["path"], str(r["size"]), r["model"], r["serial"], r["problem"]]
    print("\t".join(v.replace("\t", " ") or "-" for v in vals))
' "$drives_json"
  }
  if [[ -z "$target" ]]; then
    need_tty "which drive to use" "--target /dev/sdX"
    mapfile -t rows < <(drive_rows)
    ((${#rows[@]})) || die "no removable drive found. Plug in the USB drive (64 GB or more) and rerun."
    printf '\nRemovable drives:\n'
    i=0
    for r in "${rows[@]}"; do
      i=$((i + 1))
      IFS=$'\t' read -r _ r_path r_size r_model r_serial r_problem <<<"$r"
      [[ "$r_problem" == "-" ]] && r_problem=""
      printf '  %d) %-12s %-10s %-28s serial %s %s\n' "$i" "$r_path" "$(gb "$r_size")" "$r_model" "$r_serial" \
        "${r_problem:+ [$r_problem]}"
    done
    read -r -p "Drive number: " pick || pick=""
    if ! [[ "$pick" =~ ^[0-9]+$ ]] || ((pick < 1 || pick > ${#rows[@]})); then
      die "no drive chosen. Rerun and pick a number from the list."
    fi
    target="$(cut -f2 <<<"${rows[pick - 1]}")"
  fi
  [[ -L "$target" ]] && target="$(readlink -f -- "$target")"
  row="$(drive_rows | awk -F '\t' -v t="$target" '$2 == t' | head -n1)"
  [[ -n "$row" ]] ||
    die "$target is not a removable drive this tool can write. Plug in the USB drive and run scripts/flash.sh --list to see its name."
  IFS=$'\t' read -r t_name _ t_size t_model t_serial t_problem <<<"$row"
  [[ "$t_model" == "-" ]] && t_model=""
  [[ "$t_serial" == "-" ]] && t_serial=""
  [[ "$t_problem" == "-" ]] || die "$target cannot be used: $t_problem."
  need_bytes=$((image_estimate + headroom_gb * 1000000000))
  if ((t_size < need_bytes)); then
    die "$target is too small: $(gb "$t_size"). The image needs about $(gb "$image_estimate") plus $headroom_gb GB headroom. Use a 64 GB or larger drive (a USB SSD is best)."
  fi
  if [[ -z "$confirm" ]]; then
    need_tty "for the drive confirmation" "--confirm ${t_name}"
    printf '\nThis will ERASE %s: %s, serial %s, %s.\n' "$target" "${t_model:-unknown model}" "${t_serial:-unknown}" "$(gb "$t_size")"
    read -r -p "Type the drive name ($t_name) to confirm: " confirm || confirm=""
  fi
  confirm="${confirm#/dev/}"
  [[ "$confirm" == "$t_name" ]] || die "the confirmation does not match $t_name. Nothing was changed; rerun and type the name shown."
fi

# ---------------------------------------------------------------------------- abuse.ch key
abuse_key=""
if [[ "$mode" != "image" ]]; then
  if [[ -n "$key_file" ]]; then
    [[ -f "$key_file" && -r "$key_file" ]] || die "cannot read the key file $key_file."
    IFS= read -r abuse_key <"$key_file" || true
    abuse_key="${abuse_key//[[:space:]]/}"
    [[ -n "$abuse_key" ]] || die "the key file $key_file is empty. Put the key on its first line, or use --no-abuse-key."
  elif ((!no_key && !yes)) && [[ "$wants_mb" != "0" ]]; then
    need_tty "for the abuse.ch key" "--abuse-key-file FILE or --no-abuse-key"
    printf '\nOptional: an abuse.ch key lets the drive carry the MalwareBazaar known-bad hash set.\n'
    printf 'It is used for this download only and is never saved. Press Enter to skip.\n'
    read -r -s -p "abuse.ch key: " abuse_key || abuse_key=""
    printf '\n'
    abuse_key="${abuse_key//[[:space:]]/}"
  fi
  if [[ -n "$abuse_key" ]] && ! [[ "$abuse_key" =~ ^[A-Za-z0-9._~+/=-]{8,256}$ ]]; then
    abuse_key=""
    die "the abuse.ch key has unexpected characters or length. Check it and rerun (it was not saved)."
  fi
fi

# ---------------------------------------------------------------------------- estimates
if [[ "$accel" == "tcg" ]]; then build_time="8 hours or more (emulation, no KVM)"; else build_time="about 1 to 2 hours with KVM"; fi
say ""
say "Plan:"
case "$mode" in
  image) say "  Build and test the image only. No drive is written." ;;
  flash) say "  Write $(basename -- "$flash_image") to $target, stage the '$profile_name' profile, verify, smoke boot." ;;
  *) say "  Build, test, write to $target (${t_model:-unknown model}, serial ${t_serial:-unknown}), stage the '$profile_name' profile, verify, smoke boot." ;;
esac
if [[ "$mode" != "flash" ]]; then
  if ((reuse_image)); then
    say "  Image:        reusing the finished image in $output_dir"
  else
    unknown_note=""
    [[ "$build_unknown" =~ ^[0-9]+$ ]] && ((build_unknown > 0)) && unknown_note=" plus $build_unknown file(s) of unknown size"
    say "  Build downloads: $(gb "$build_bytes")$unknown_note plus Ubuntu packages (several GB)"
    say "  Build time:   $build_time"
  fi
  say "  Image size:   about $(gb "$image_estimate") when written (compressed copy is much smaller)"
fi
if [[ "$mode" != "image" ]]; then
  if [[ -n "$stage_bytes" ]]; then
    unknown_note=""
    ((stage_unknown > 0)) && unknown_note=" (plus $stage_unknown file(s) of unknown size)"
    say "  Staged files: $stage_files, $(gb "$stage_bytes") to download$unknown_note"
    if ((stage_bytes > assets_bytes)); then
      die "the '$profile_name' profile needs $(gb "$stage_bytes") but the ASSETS partition holds $(gb "$assets_bytes"). Pick a smaller profile (default or minimal)."
    fi
  else
    say "  Staged files: size unknown for this profile file; the fetcher checks free space before it starts"
  fi
  say "  Drive needed: at least $(gb $((image_estimate + headroom_gb * 1000000000))); $target has $(gb "$t_size")"
  if [[ -n "$abuse_key" ]]; then
    say "  abuse.ch key: given (used for the download only, not recorded)"
  elif [[ "$wants_mb" != "0" ]]; then
    say "  abuse.ch key: none, so the MalwareBazaar hash set will not be staged"
  fi
fi
say "  Log:          $log_file"
say ""
ask_yes_no "Start now?" || die "stopped before doing anything. Nothing was changed."

# ---------------------------------------------------------------------------- steps
work="$(mktemp -d "${TMPDIR:-/tmp}/airlock-make-usb.XXXXXX")"
assets_mnt="$work/assets"
current_step=""
# shellcheck disable=SC2317,SC2329 # called by traps
cleanup() {
  abuse_key=""
  if [[ -d "$assets_mnt" ]] && findmnt -rn --mountpoint "$assets_mnt" >/dev/null 2>&1; then
    umount -- "$assets_mnt" 2>/dev/null || true
  fi
  rm -rf -- "$work"
}
# shellcheck disable=SC2317,SC2329 # called by traps
on_signal() {
  [[ -n "$current_step" ]] && printf '%s: stopped during step "%s". Rerun to continue; finished steps are reused.\n' "$prog" "$current_step" >&2
  exit 1
}
trap cleanup EXIT
trap on_signal INT TERM HUP

step_no=0
case "$mode" in image) step_total=2 ;; flash) step_total=4 ;; *) step_total=6 ;; esac

run_step() { # NAME FUNCTION
  local name="$1" rc
  shift
  current_step="$name"
  step_no=$((step_no + 1))
  printf '\n==> [%d/%d] %s\n' "$step_no" "$step_total" "$name"
  printf '\n===== %s step %d/%d: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$step_no" "$step_total" "$name" >>"$log_file"
  set +e
  ("$@") 2>&1 | tee -a -- "$log_file"
  rc="${PIPESTATUS[0]}"
  set -e
  if ((rc != 0)); then
    printf '\n%s: step "%s" failed (exit %s). The full log is %s.\n' "$prog" "$name" "$rc" "$log_file" >&2
    printf '%s: fix the cause and run make-usb.sh again; finished steps and downloads are reused.\n' "$prog" >&2
    printf '===== step "%s" failed (exit %s)\n' "$name" "$rc" >>"$log_file"
    exit 1
  fi
  printf '===== step "%s" ok\n' "$name" >>"$log_file"
}

goss_args=()
if goss_bin="$("$prereqs_sh" --goss-path --cache "$cache_dir" 2>/dev/null)"; then
  goss_args=(--goss "$goss_bin")
fi

step_build() {
  if ((reuse_image)); then
    echo "reusing the finished image in $output_dir (it matches its SHA256SUMS); use --rebuild to build again"
    return 0
  fi
  local args=(--cache "$cache_dir" --output "$output_dir" --accel "$accel")
  [[ -e "$output_dir" ]] && args+=(--force)
  "$build_sh" "${args[@]}"
}

raw_sha() { # the raw image's SHA-256 from SHA256SUMS
  local zst raw
  zst="$(find_zst)" || return 1
  raw="$(basename -- "${zst%.zst}")"
  awk -v n="$raw" '$2 == n || $2 == "*" n { print $1 }' "$output_dir/SHA256SUMS" | head -n1
}

step_test() {
  local zst marker="$output_dir/make-usb-tested.sha256" sha
  zst="$(find_zst)" || { echo "no airlock-*.raw.zst in $output_dir after the build" >&2; return 1; }
  sha="$(raw_sha)"
  if [[ -n "$sha" && -f "$marker" && "$(cat -- "$marker")" == "$sha" ]]; then
    echo "boot tests already passed for this image ($sha); not repeated"
    return 0
  fi
  "$qemu_tests" --image "${zst%.zst}" --accel "$accel" --results "$output_dir/qemu-results" \
    "${goss_args[@]+"${goss_args[@]}"}" || return 1
  [[ -n "$sha" ]] && printf '%s\n' "$sha" >"$marker"
  return 0
}

step_flash() {
  local args=(--image "$1" --target "$target" --yes --confirm "$t_name" --headroom-gb "$headroom_gb")
  [[ -n "$t_serial" ]] && args+=(--expect-serial "$t_serial")
  "$flash_sh" "${args[@]}"
}

# assets_partition: /dev path of the ASSETS partition on the target (GPT name or label).
assets_partition() {
  local json name label
  json="$(lsblk -J -o NAME,LABEL,PARTLABEL,TYPE -- "$target")" || return 1
  while IFS=$'\t' read -r name label; do
    if [[ "$label" == "ASSETS" ]]; then
      printf '/dev/%s\n' "$name"
      return 0
    fi
    if [[ "$label" == "-" ]] && have blkid; then
      if [[ "$(blkid -p -o value -s PARTLABEL -- "/dev/$name" 2>/dev/null)" == "ASSETS" ||
        "$(blkid -p -o value -s LABEL -- "/dev/$name" 2>/dev/null)" == "ASSETS" ]]; then
        printf '/dev/%s\n' "$name"
        return 0
      fi
    fi
  done < <(python3 -c '
import json, sys
def walk(nodes):
    for n in nodes or []:
        if n.get("type") == "part":
            lab = "ASSETS" if "ASSETS" in (n.get("partlabel"), n.get("label")) else "-"
            print(n["name"] + "\t" + lab)
        walk(n.get("children"))
walk(json.load(sys.stdin).get("blockdevices"))
' <<<"$json")
  return 1
}

step_stage() {
  local part i
  echo "rereading the partition table of $target"
  blockdev --rereadpt "$target" 2>/dev/null || true
  partx -a "$target" 2>/dev/null || true
  partx -u "$target" 2>/dev/null || true
  if have udevadm; then udevadm settle --timeout=30 2>/dev/null || true; fi
  part=""
  for i in 1 2 3 4 5 6 7 8 9 10; do
    part="$(assets_partition || true)"
    [[ -n "$part" && -b "$part" ]] && break
    part=""
    sleep 1
  done
  [[ -n "$part" ]] || { echo "no ASSETS partition found on $target after writing; the image may be damaged" >&2; return 1; }
  mkdir -p -- "$assets_mnt"
  echo "mounting $part (ASSETS) at $assets_mnt"
  if ! mount -t exfat -o nosuid,nodev,noexec -- "$part" "$assets_mnt" 2>"$work/mount.err"; then
    # FUSE fallback where the kernel has no exFAT driver. Its daemon must not hold the log pipe.
    if ! { have mount.exfat-fuse &&
      mount.exfat-fuse -o nosuid,nodev,noexec "$part" "$assets_mnt" </dev/null >/dev/null 2>>"$work/mount.err"; }; then
      cat -- "$work/mount.err" >&2
      echo "could not mount $part (exFAT). Install exFAT support (sudo scripts/prereqs.sh --install) and rerun." >&2
      return 1
    fi
  fi
  local args=(--yes --manifest "$manifest" --profile "$fetch_profile" --assets "$assets_mnt" --cache "$cache_dir")
  if [[ -n "$abuse_key" ]]; then
    # The key travels in this one process's environment only: never in argv, a file or the log.
    AIRLOCK_ABUSECH_KEY="$abuse_key" "$fetch_sh" "${args[@]}"
  else
    echo "no abuse.ch key: the MalwareBazaar hash set will not be staged"
    "$fetch_sh" "${args[@]}"
  fi
}

step_verify() {
  local listed
  [[ -f "$assets_mnt/profile.json" ]] || { echo "the fetcher wrote no profile.json on ASSETS" >&2; return 1; }
  # The key, when given, reaches Python through the environment only, to prove it is not on ASSETS.
  listed="$(AIRLOCK_KEY_CHECK="$abuse_key" python3 - "$assets_mnt" <<'PY'
import hashlib
import json
import os
import sys
from pathlib import Path, PurePosixPath

root = Path(sys.argv[1])
data = json.loads((root / "profile.json").read_text(encoding="utf-8"))
bad = 0
count = 0
for entry in data.get("files") or []:
    target = PurePosixPath(str(entry.get("target") or ""))
    if not target.parts or target.is_absolute() or ".." in target.parts:
        print(f"bad target path for {entry.get('id')}", file=sys.stderr)
        bad += 1
        continue
    path = root / "files" / Path(*target.parts)
    digest = hashlib.sha256()
    try:
        with open(path, "rb") as fh:
            for block in iter(lambda: fh.read(4 * 1024 * 1024), b""):
                digest.update(block)
    except OSError as exc:
        print(f"{entry.get('id')}: cannot read {path}: {exc.strerror}", file=sys.stderr)
        bad += 1
        continue
    if digest.hexdigest() != str(entry.get("sha256") or "").lower():
        print(f"{entry.get('id')}: SHA-256 does not match profile.json", file=sys.stderr)
        bad += 1
        continue
    count += 1
key = os.environ.pop("AIRLOCK_KEY_CHECK", "").encode()
if key:
    for path in sorted(root.rglob("*")):
        if path.is_file() and path.stat().st_size < 2 * 1024 * 1024 and key in path.read_bytes():
            print("the abuse.ch key was found on ASSETS, which must never happen. "
                  "Do not use this drive; report it as a bug.", file=sys.stderr)
            bad += 1
            break
print(count)
sys.exit(1 if bad else 0)
PY
)" || { echo "staged files on ASSETS do not read back correctly; rerun to stage them again" >&2; return 1; }
  echo "read back $listed staged file(s) from ASSETS: all match profile.json"
  sync
  umount -- "$assets_mnt" || { echo "could not unmount ASSETS ($assets_mnt)" >&2; return 1; }
  echo "ASSETS unmounted"
}

step_smoke() {
  local overlay="$work/smoke-overlay.qcow2" before after p
  # Partitions a desktop may have auto-mounted after the write are unmounted first.
  while IFS= read -r p; do
    [[ -n "$p" ]] && umount -- "$p" 2>/dev/null && echo "unmounted $p (auto-mounted by the desktop)"
  done < <(lsblk -rn -o MOUNTPOINT -- "$target" 2>/dev/null | grep -v '^$' || true)
  before="$(dd if="$target" bs=1M count=1 status=none | sha256sum | cut -d' ' -f1)"
  qemu-img create -q -f qcow2 -F raw -b "$target" -- "$overlay" ||
    { echo "could not make a QEMU overlay on $target" >&2; return 1; }
  "$qemu_tests" --image "$overlay" --only '^smoke\.yaml$' --no-extra-disks --firmware uefi,bios \
    --boot-bus usb --accel "$accel" --results "$work/smoke-results" "${goss_args[@]+"${goss_args[@]}"}" || return 1
  after="$(dd if="$target" bs=1M count=1 status=none | sha256sum | cut -d' ' -f1)"
  [[ "$before" == "$after" ]] || { echo "the drive's first MiB changed during the smoke boot" >&2; return 1; }
  echo "the drive boots and passes the smoke test; it was not changed by the test boot"
}

if [[ "$mode" != "flash" ]]; then
  run_step "build the image" step_build
  run_step "boot tests in QEMU" step_test
fi
if [[ "$mode" == "image" ]]; then
  zst="$(find_zst)" || die "the build finished but no airlock-*.raw.zst is in $output_dir."
  say ""
  say "Done. Image: $zst"
  say "Write it with: sudo scripts/flash.sh --image $zst --target /dev/sdX"
  say "or on Windows with Rufus in DD mode or balenaEtcher (see docs/quickstart.md)."
  exit 0
fi

if [[ "$mode" == "flash" ]]; then
  image_to_write="$flash_image"
else
  image_to_write="$(find_zst)" || die "no airlock-*.raw.zst in $output_dir after the build."
fi
run_step "write the drive" step_flash "$image_to_write"
run_step "stage the '$profile_name' profile onto ASSETS" step_stage
run_step "read back the staged files" step_verify
abuse_key=""
run_step "smoke boot the drive in QEMU" step_smoke
current_step=""

say ""
say "Done. $target is ready: it boots, and the '$profile_name' files are staged."
say "On first boot it sets itself up from ASSETS with no network. Then follow docs/quickstart.md."
say "Attach evidence drives through a hardware write blocker. The software read-only policy is a second layer only."
