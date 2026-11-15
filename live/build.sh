#!/usr/bin/env bash
# Build the AIRLOCK live ISO (task 7.2): an amnesic variant that boots from read-only media and
# keeps nothing between boots. It uses live-build (Ubuntu's package, `lb`) and reuses the same
# Ansible roles as the installed image: a chroot hook (live/hooks/0500-airlock-site.hook.chroot)
# runs ansible/site.yml inside the live system with airlock_target=live, so hardening is applied
# and re-applied last exactly as on the installed drive (decision log 2026-11-15, task 7.1).
#
# Usage: sudo live/build.sh [options]
#   --out DIR        output folder (default: output/airlock-live-<version>)
#   --snapshot STAMP apt snapshot to build from, YYYYMMDDTHHMMSSZ (default: apt_snapshot in
#                    ansible/group_vars/all/main.yml; the archive itself when use_apt_snapshot
#                    is false)
#   --config-only    write the live-build configuration (lb config, hook, repo copy) and stop;
#                    needs no root and downloads nothing
#   --force          replace an existing output folder
#   -h, --help       this help
#
# Needs: Ubuntu 24.04 or newer build host, root, the live-build package (apt install
# live-build), python3 with python3-yaml, and network access to the Ubuntu archive or
# snapshot.ubuntu.com. Writes DIR/airlock-live-<version>.iso and DIR/SHA256SUMS.
# Exit status: 0 built (or configured); 1 a step failed (one line says which and what to do);
# 2 bad usage.
# Test: tests/unit/test_repo_meta.py (--config-only). The full build runs on a build host only.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
prog="live/build.sh"
main_vars="$repo_root/ansible/group_vars/all/main.yml"
hook_src="$repo_root/live/hooks/0500-airlock-site.hook.chroot"

out_dir=""
snapshot=""
config_only=0
force=0

usage() { sed -n '2,/^# Test:/p' "${BASH_SOURCE[0]}" | sed '$d' | sed 's/^# \{0,1\}//'; }
die() {
  printf '%s: %s\n' "$prog" "$*" >&2
  exit 1
}
bad_usage() {
  printf '%s: %s Run with --help.\n' "$prog" "$*" >&2
  exit 2
}
log() { printf '%s: %s\n' "$prog" "$*"; }
have() { command -v "$1" >/dev/null 2>&1; }

while (($#)); do
  case "$1" in
    --out)
      [[ $# -ge 2 && -n "$2" ]] || bad_usage "--out needs a folder."
      out_dir="$2"
      shift 2
      ;;
    --snapshot)
      [[ $# -ge 2 && "$2" =~ ^[0-9]{8}T[0-9]{6}Z$ ]] || bad_usage "--snapshot needs YYYYMMDDTHHMMSSZ."
      snapshot="$2"
      shift 2
      ;;
    --config-only) config_only=1; shift ;;
    --force) force=1; shift ;;
    -h | --help) usage; exit 0 ;;
    *) bad_usage "unknown option '$1'." ;;
  esac
done

[[ "$(uname -s)" == "Linux" ]] || die "the live ISO builds on Linux only. Use an Ubuntu 24.04 host."
have python3 || die "python3 is missing. Install it (apt install python3 python3-yaml) and rerun."
python3 -c 'import yaml' 2>/dev/null || die "Python YAML support is missing. Install it (apt install python3-yaml) and rerun."
have lb || die "live-build is missing. Install it (sudo apt install live-build) and rerun."
if ((!config_only)) && [[ "$(id -u)" -ne 0 ]]; then
  die "building the ISO needs root. Rerun with sudo, or use --config-only to only write the configuration."
fi
[[ -f "$hook_src" ]] || die "the chroot hook $hook_src is missing. Check out the whole repository."

# Settings from main.yml, one per line, read by Python so no value is parsed by the shell.
mapfile -t settings < <(python3 - "$main_vars" <<'PY'
import sys

import yaml

with open(sys.argv[1], encoding="utf-8") as fh:
    v = yaml.safe_load(fh) or {}
print(v.get("airlock_version", "0.0.0-dev"))
print(v.get("ubuntu_release", "noble"))
print(v.get("apt_snapshot", ""))
print("true" if v.get("use_apt_snapshot", True) else "false")
print(" ".join(str(x) for x in (v.get("airlock_kernel_cmdline") or [])))
PY
)
((${#settings[@]} == 5)) || die "could not read $main_vars. Check that it is valid YAML."
version="${settings[0]}"
release="${settings[1]}"
use_snapshot="${settings[3]}"
cmdline="${settings[4]}"
[[ -n "$snapshot" ]] || snapshot="${settings[2]}"
[[ "$version" =~ ^[0-9A-Za-z.+~-]+$ ]] || die "airlock_version '$version' in main.yml has characters a file name cannot have."
[[ "$release" =~ ^[a-z]+$ ]] || die "ubuntu_release '$release' in main.yml is not a release code name."

if [[ "$use_snapshot" == "true" ]]; then
  [[ "$snapshot" =~ ^[0-9]{8}T[0-9]{6}Z$ ]] || die "apt_snapshot '$snapshot' is not YYYYMMDDTHHMMSSZ. Fix main.yml or pass --snapshot."
  mirror="https://snapshot.ubuntu.com/ubuntu/$snapshot"
else
  mirror="http://archive.ubuntu.com/ubuntu"
fi

[[ -n "$out_dir" ]] || out_dir="$repo_root/output/airlock-live-$version"
out_dir="$(realpath -m -- "$out_dir")"
if [[ -e "$out_dir" ]]; then
  ((force)) || die "output folder $out_dir already exists. Move it away or rerun with --force."
  rm -rf -- "$out_dir"
fi
work="$out_dir/lb"
mkdir -p -- "$work" || die "could not create $work."
cd -- "$work"

lb_config=(
  lb config
  --mode ubuntu
  --distribution "$release"
  --architectures amd64
  --linux-flavours generic
  --initramfs casper
  --binary-images iso-hybrid
  --archive-areas "main restricted universe multiverse"
  --parent-archive-areas "main restricted universe multiverse"
  --mirror-bootstrap "$mirror"
  --mirror-chroot "$mirror"
  --mirror-chroot-security "$mirror"
  --mirror-binary "$mirror"
  --mirror-binary-security "$mirror"
  --parent-mirror-bootstrap "$mirror"
  --parent-mirror-chroot "$mirror"
  --parent-mirror-chroot-security "$mirror"
  --parent-mirror-binary "$mirror"
  --parent-mirror-binary-security "$mirror"
  --apt-recommends false
  --apt-source-archives false
  --bootappend-live "boot=casper $cmdline"
  --iso-volume "AIRLOCK_LIVE_${version//[^0-9A-Za-z]/_}"
  --iso-application "AIRLOCK live"
  --memtest none
  --source false
  --debian-installer false
  --firmware-chroot false
  --firmware-binary false
  --checksums sha256
  --debconf-frontend noninteractive
)
log "running: ${lb_config[*]}"
"${lb_config[@]}" >"$out_dir/lb-config.log" 2>&1 ||
  die "lb config failed; see $out_dir/lb-config.log."

# The repository's roles and profiles, as on the installed image (/opt/airlock/repo).
inc="$work/config/includes.chroot/opt/airlock"
mkdir -p -- "$inc/repo"
cp -a -- "$repo_root/ansible" "$inc/repo/ansible"
[[ -d "$repo_root/profiles" ]] && cp -a -- "$repo_root/profiles" "$inc/repo/profiles"

# Extra variables as JSON, so no value passes through a shell word split.
commit="$(git -C "$repo_root" rev-parse HEAD 2>/dev/null || echo unknown)"
python3 - "$inc/live-build-vars.json" "$commit" <<'PY'
import datetime
import json
import os
import sys

epoch = os.environ.get("SOURCE_DATE_EPOCH")
when = (
    datetime.datetime.fromtimestamp(int(epoch), datetime.UTC)
    if epoch
    else datetime.datetime.now(datetime.UTC)
)
data = {
    "airlock_phase": "image",
    "airlock_target": "live",
    "base_build_commit": sys.argv[2],
    "base_build_date": when.strftime("%Y-%m-%dT%H:%M:%SZ"),
}
with open(sys.argv[1], "w", encoding="utf-8") as fh:
    json.dump(data, fh, sort_keys=True)
    fh.write("\n")
PY
chmod 0600 -- "$inc/live-build-vars.json"

# Ansible runs in the chroot, so it must be installed there first.
mkdir -p -- "$work/config/package-lists" "$work/config/hooks"
printf '%s\n' ansible-core python3 python3-apt python3-yaml sudo ca-certificates \
  >"$work/config/package-lists/airlock.list.chroot"
install -m 0755 -- "$hook_src" "$work/config/hooks/0500-airlock-site.hook.chroot"

if ((config_only)); then
  log "configuration written to $work (mirror $mirror). Build it with: sudo live/build.sh --force --out $out_dir"
  exit 0
fi

log "building the live ISO in $work (this downloads the base system and takes a long time)"
lb build >"$out_dir/lb-build.log" 2>&1 ||
  die "lb build failed; the end of $out_dir/lb-build.log names the step. Fix it and rerun with --force."

iso="$(find "$work" -maxdepth 1 -name '*.iso' -type f | head -n1)"
[[ -n "$iso" ]] || die "lb build finished but left no .iso in $work; see $out_dir/lb-build.log."
final="$out_dir/airlock-live-$version.iso"
mv -f -- "$iso" "$final"
(cd -- "$out_dir" && sha256sum -- "$(basename -- "$final")" >SHA256SUMS)
log "done: $final"
log "write it with scripts/flash.sh or any imaging tool; check it against $out_dir/SHA256SUMS first."
