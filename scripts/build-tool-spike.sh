#!/usr/bin/env bash
# Build-tool spike (task 0.11): how reproducible is the Packer + Ansible build?
#
#   scripts/build-tool-spike.sh build [--out DIR] [--epoch SECONDS] [-- BUILD.SH ARGS...]
#       Builds the image twice with scripts/build.sh (same commit, same SOURCE_DATE_EPOCH,
#       same apt snapshot) into DIR/a and DIR/b, then runs 'compare' on the two raw images.
#       Needs a Linux x86_64 host with KVM; each build takes about an hour.
#   scripts/build-tool-spike.sh compare IMAGE_A IMAGE_B [--out DIR]
#       Compares two raw AIRLOCK images: whole-image and per-partition SHA-256, then a
#       file-by-file manifest of the root filesystem (type, mode, owner, size, SHA-256,
#       link target) mounted read-only. Writes DIR/spike-report.json and spike-report.md.
#       Needs root and loop devices (mounting ext4 read-only with noload).
#
# The mkosi half of the spike is manual for now; docs/build.md lists the steps. Record the
# result of both halves in docs/decision-log.md.
# Exit status: 0 report written (identical or not); 1 failure (one line says what to do next).
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

die() {
  printf 'build-tool-spike: %s\n' "$*" >&2
  exit 1
}
log() { printf 'build-tool-spike: %s\n' "$*"; }
usage() { sed -n '2,19p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; }

mode="${1:-}"
[[ -n "$mode" ]] || { usage; exit 1; }
shift

out="$repo_root/output/spike"
epoch="${SOURCE_DATE_EPOCH:-}"
build_args=()
images=()
while (($#)); do
  case "$1" in
    --out) out="${2:?--out needs a folder}"; shift 2 ;;
    --epoch) epoch="${2:?--epoch needs seconds}"; shift 2 ;;
    --) shift; build_args=("$@"); break ;;
    -h | --help) usage; exit 0 ;;
    -*) die "unknown option '$1'. Run with --help." ;;
    *) images+=("$1"); shift ;;
  esac
done
case "$mode" in
  build | compare) ;;
  -h | --help) usage; exit 0 ;;
  *) die "unknown mode '$mode'. Use build or compare." ;;
esac
mkdir -p -- "$out"
out="$(cd "$out" && pwd)"

# ------------------------------------------------------------------ compare
attached=()
mounts=()
# shellcheck disable=SC2317 # called by the EXIT trap
cleanup() {
  local m d
  for m in "${mounts[@]+"${mounts[@]}"}"; do
    umount -- "$m" 2>/dev/null || true
    rmdir -- "$m" 2>/dev/null || true
  done
  for d in "${attached[@]+"${attached[@]}"}"; do
    partx -d -- "$d" >/dev/null 2>&1 || true
    losetup -d "$d" 2>/dev/null || true
  done
}
trap cleanup EXIT

attach_ro() { # IMAGE: sets $dev to a read-only loop device with partition nodes
  local n i t
  dev="$(losetup -r -f --show -P -- "$1")" || die "could not attach $1 read-only."
  attached+=("$dev")
  partx -a -- "$dev" >/dev/null 2>&1 || true
  n="$(sgdisk -p -- "$1" 2>/dev/null | awk '/^ +[0-9]+ / {c++} END {print c+0}')"
  for ((i = 1; i <= n; i++)); do
    for ((t = 0; t < 50; t++)); do [[ -b "${dev}p$i" ]] && break; sleep 0.1; done
  done
}

manifest() { # ROOT_DIR OUT_FILE: one JSON line per path, sorted
  python3 - "$1" "$2" <<'PY'
import hashlib
import json
import os
import stat
import sys

root, out = sys.argv[1], sys.argv[2]
rows = []
for dirpath, dirnames, filenames in os.walk(root):
    dirnames.sort()
    for name in sorted(dirnames + filenames):
        full = os.path.join(dirpath, name)
        rel = "/" + os.path.relpath(full, root)
        st = os.lstat(full)
        row = {"path": rel, "mode": oct(stat.S_IMODE(st.st_mode)), "uid": st.st_uid, "gid": st.st_gid}
        if stat.S_ISLNK(st.st_mode):
            row.update(type="link", target=os.readlink(full))
        elif stat.S_ISDIR(st.st_mode):
            row.update(type="dir")
        elif stat.S_ISREG(st.st_mode):
            h = hashlib.sha256()
            with open(full, "rb") as fh:
                for block in iter(lambda: fh.read(1 << 20), b""):
                    h.update(block)
            row.update(type="file", size=st.st_size, sha256=h.hexdigest())
        else:
            row.update(type="other")
        rows.append(row)
with open(out, "w", encoding="utf-8") as fh:
    for row in sorted(rows, key=lambda r: r["path"]):
        fh.write(json.dumps(row, sort_keys=True) + "\n")
PY
}

compare() {
  local a="$1" b="$2" da db i mnt_a mnt_b dev=""
  [[ "$(id -u)" -eq 0 ]] || die "compare needs root (it mounts the root filesystems read-only)."
  for f in "$a" "$b"; do [[ -f "$f" ]] || die "image $f not found."; done
  log "hashing the images"
  sha256sum -- "$a" "$b" | awk '{print $1}' >"$out/image.sha256"
  attach_ro "$a"
  da="$dev"
  attach_ro "$b"
  db="$dev"
  : >"$out/partitions.tsv"
  for i in 1 2 3 4 5; do
    [[ -b "${da}p$i" && -b "${db}p$i" ]] || die "partition $i is missing on one image; these are not AIRLOCK images."
    printf '%s\t%s\t%s\n' "$i" "$(sha256sum <"${da}p$i" | cut -d' ' -f1)" "$(sha256sum <"${db}p$i" | cut -d' ' -f1)" >>"$out/partitions.tsv"
  done
  mnt_a="$(mktemp -d)"
  mnt_b="$(mktemp -d)"
  mount -o ro,noload -t ext4 -- "${da}p5" "$mnt_a" || die "could not mount the root of $a read-only."
  mounts+=("$mnt_a")
  mount -o ro,noload -t ext4 -- "${db}p5" "$mnt_b" || die "could not mount the root of $b read-only."
  mounts+=("$mnt_b")
  log "listing every file (this reads the whole root filesystem twice)"
  manifest "$mnt_a" "$out/manifest-a.jsonl"
  manifest "$mnt_b" "$out/manifest-b.jsonl"
  python3 - "$out" "$a" "$b" <<'PY'
import json
import sys
from pathlib import Path

out, img_a, img_b = Path(sys.argv[1]), sys.argv[2], sys.argv[3]
ha, hb = (out / "image.sha256").read_text().split()
parts = []
names = {1: "BIOSBOOT", 2: "EFI", 3: "ASSETS", 4: "OUTPUT", 5: "AIRLOCK_ROOT"}
for line in (out / "partitions.tsv").read_text().splitlines():
    n, pa, pb = line.split("\t")
    parts.append({"number": int(n), "name": names[int(n)], "identical": pa == pb, "sha256_a": pa, "sha256_b": pb})


def load(p: Path) -> dict[str, dict]:
    return {r["path"]: r for r in map(json.loads, p.read_text().splitlines())}


ma, mb = load(out / "manifest-a.jsonl"), load(out / "manifest-b.jsonl")
added = sorted(set(mb) - set(ma))
removed = sorted(set(ma) - set(mb))
changed = sorted(p for p in set(ma) & set(mb) if ma[p] != mb[p])
report = {
    "schema": 1,
    "image_a": {"path": img_a, "sha256": ha},
    "image_b": {"path": img_b, "sha256": hb},
    "images_identical": ha == hb,
    "partitions": parts,
    "root_files": {"a": len(ma), "b": len(mb)},
    "root_added": added,
    "root_removed": removed,
    "root_changed": changed,
    "root_identical": not (added or removed or changed),
}
(out / "spike-report.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
lines = [
    "# Build-tool spike: Packer + Ansible (task 0.11)",
    "",
    f"* Image A: `{img_a}` sha256 `{ha}`",
    f"* Image B: `{img_b}` sha256 `{hb}`",
    f"* Byte-identical images: **{'yes' if ha == hb else 'no'}**",
    f"* Root filesystem: {len(ma)} paths in A, {len(mb)} in B; "
    f"{len(added)} added, {len(removed)} removed, {len(changed)} changed",
    "",
    "| # | Partition | Identical |",
    "|---|---|---|",
]
lines += [f"| {p['number']} | {p['name']} | {'yes' if p['identical'] else 'no'} |" for p in parts]
for title, items in (("Added in B", added), ("Removed in B", removed), ("Changed", changed)):
    if items:
        lines += ["", f"## {title} ({len(items)})", ""]
        lines += [f"* `{p}`" for p in items[:200]]
        if len(items) > 200:
            lines.append(f"* ... and {len(items) - 200} more (see spike-report.json)")
(out / "spike-report.md").write_text("\n".join(lines) + "\n")
print(f"images identical: {ha == hb}; root paths added {len(added)}, removed {len(removed)}, changed {len(changed)}")
PY
  log "report: $out/spike-report.md and $out/spike-report.json"
}

case "$mode" in
  compare)
    ((${#images[@]} == 2)) || die "compare needs two images: compare IMAGE_A IMAGE_B."
    compare "${images[0]}" "${images[1]}"
    ;;
  build)
    [[ -n "$epoch" ]] || epoch="$(git -C "$repo_root" log -1 --format=%ct 2>/dev/null || date +%s)"
    [[ "$epoch" =~ ^[0-9]+$ ]] || die "--epoch must be whole seconds."
    for run_name in a b; do
      log "build $run_name of 2 (SOURCE_DATE_EPOCH=$epoch)"
      SOURCE_DATE_EPOCH="$epoch" "$repo_root/scripts/build.sh" --output "$out/$run_name" --force \
        "${build_args[@]+"${build_args[@]}"}" || die "build $run_name failed; see its log above."
    done
    version="$(python3 -c 'import sys,yaml; print(yaml.safe_load(open(sys.argv[1]))["airlock_version"])' \
      "$repo_root/ansible/group_vars/all/main.yml")"
    compare "$out/a/airlock-$version.raw" "$out/b/airlock-$version.raw"
    ;;
esac
