#!/usr/bin/env bash
# run.sh: run the whole forensic-analyze wizard, non-interactively, over every validation set
# and score each artifact class against ground truth (task 4F.3). Host side or CI; needs root
# (read-only loop devices) and the analysis tools (The Sleuth Kit, PhotoRec, ...).
#
# Usage:
#   validation/run.sh [--build] [--synthetic DIR] [--reference DIR] [--out DIR]
#                     [--preset full|standard|quick] [--only SET] [--analyze CMD]
#                     [--system-paths]
#
#   --build          build the synthetic sets first (validation/synthetic/build.sh)
#   --synthetic DIR  folder with <set>.img and <set>.truth.json (default: OUT/synthetic)
#   --reference DIR  folder fetch.sh downloaded into (default: OUT/reference); a reference set
#                    is scored when validation/reference/truth/<set>.json exists, otherwise it
#                    is run and recorded as not scored
#   --out DIR        results (default: validation/out): OUT/<set>/score.json, OUT/summary.json
#   --preset NAME    default full (carving is part of full only)
#   --only SET       run one set
#   --analyze CMD    the forensic-analyze command (default: the repo's copy, or the installed
#                    one when the repo copy is missing)
#   --system-paths   use the real /var/log, /etc/airlock ... paths (inside a booted image);
#                    by default every on-image path is redirected under OUT/<set>/env
#
# Exit status: 0 every scored class passed or was not applicable, 1 a class failed or a run
# could not start, 2 usage error, 77 a prerequisite is missing.
# Test: tests/functional/test_validation.sh
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
die() {
  printf 'validation/run.sh: %s\n' "$1" >&2
  exit "${2:-1}"
}

build=0
synthetic=""
reference=""
out="$repo/validation/out"
preset=full
only=""
analyze=""
system_paths=0
while (($#)); do
  case "$1" in
    --build)
      build=1
      shift
      ;;
    --system-paths)
      system_paths=1
      shift
      ;;
    --synthetic | --reference | --out | --preset | --only | --analyze)
      [[ $# -ge 2 && -n "$2" ]] || die "$1 needs a value" 2
      case "$1" in
        --synthetic) synthetic="$2" ;;
        --reference) reference="$2" ;;
        --out) out="$2" ;;
        --preset) preset="$2" ;;
        --only) only="$2" ;;
        --analyze) analyze="$2" ;;
      esac
      shift 2
      ;;
    -h | --help)
      sed -n '2,/^# Test:/p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *) die "unknown option '$1'. Run validation/run.sh --help." 2 ;;
  esac
done
case "$preset" in quick | standard | full) ;; *) die "--preset must be quick, standard or full" 2 ;; esac
[[ "$(id -u)" -eq 0 ]] || die "needs root (read-only loop devices). Run it with sudo." 77
for c in python3 losetup sha256sum; do
  command -v "$c" >/dev/null 2>&1 || die "'$c' is missing. Install it and run again." 77
done

mkdir -p "$out"
out="$(cd "$out" && pwd)"
synthetic="${synthetic:-$out/synthetic}"
reference="${reference:-$out/reference}"
scoring=(python3 "$repo/validation/scoring.py")
pylib="$repo/ansible/roles/session_tools/files/pylib"
if [[ -z "$analyze" ]]; then
  if [[ -x "$repo/ansible/roles/session_tools/files/bin/forensic-analyze" ]]; then
    analyze="$repo/ansible/roles/session_tools/files/bin/forensic-analyze"
    export AIRLOCK_PYLIB="${AIRLOCK_PYLIB:-$pylib}"
  elif command -v forensic-analyze >/dev/null 2>&1; then
    analyze="$(command -v forensic-analyze)"
  else
    die "forensic-analyze not found. Pass --analyze CMD." 77
  fi
fi

if ((build)); then
  "$repo/validation/synthetic/build.sh" --out "$synthetic" || die "building the synthetic sets failed"
fi

loops=()
cleanup() {
  local l
  for l in "${loops[@]+"${loops[@]}"}"; do losetup -d "$l" 2>/dev/null || true; done
}
trap cleanup EXIT

# run_set NAME IMAGE TRUTH(or empty)
run_set() {
  local name="$1" image="$2" truth="$3" dir target rc run_dir case_id
  dir="$out/$name"
  rm -rf -- "$dir"
  mkdir -p "$dir/runs"
  case_id="VAL-$name"
  if ((!system_paths)); then
    export AIRLOCK_OPT_DIR="$dir/env/opt" AIRLOCK_ETC_DIR="$dir/env/etc"
    export AIRLOCK_STATE_DIR="$dir/env/state" AIRLOCK_SESSION_DIR="$dir/env/session"
    export AIRLOCK_ASSETS_DIR="$dir/env/assets" AIRLOCK_OUTPUT_DIR="$dir/runs"
    mkdir -p "$AIRLOCK_OPT_DIR" "$AIRLOCK_ETC_DIR" "$AIRLOCK_STATE_DIR" "$AIRLOCK_SESSION_DIR" \
      "$AIRLOCK_ASSETS_DIR"
  fi
  case "$image" in
    *.E01 | *.e01) target="$image" ;;
    *)
      target="$(losetup -r -f --show "$image")" || die "could not attach $image read-only"
      loops+=("$target")
      [[ "$(cat "/sys/block/$(basename "$target")/ro")" == 1 ]] ||
        die "$target is not read-only; refusing to analyse it"
      ;;
  esac
  echo "validation: $name: forensic-analyze --preset $preset on $target"
  set +e
  "$analyze" --authority-ack --yes --examiner "AIRLOCK validation" --case-id "$case_id" \
    --exhibit-id "$name" --notes "validation set $name" --target "$target" \
    --preset "$preset" --output "$dir/runs" --write-blocker no \
    --reference-time "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --reference-source "validation host clock (not a trusted reference)" \
    >"$dir/analyze.log" 2>&1
  rc=$?
  set -e
  run_dir="$(find "$dir/runs/cases/$case_id" -mindepth 1 -maxdepth 1 -type d -name 'R-*' 2>/dev/null |
    sort | tail -n1 || true)"
  if [[ -z "$run_dir" || ! -f "$run_dir/run.json" ]]; then
    python3 - "$dir/not-scored.json" "$name" "forensic-analyze exited $rc before a run started; see $dir/analyze.log" <<'PY'
import json, sys
open(sys.argv[1], "w").write(json.dumps({"set": sys.argv[2], "reason": sys.argv[3]}, sort_keys=True) + "\n")
PY
    echo "validation: $name: no run (exit $rc); see $dir/analyze.log" >&2
    return 0
  fi
  if [[ -z "$truth" ]]; then
    python3 - "$dir/not-scored.json" "$name" "$run_dir" <<'PY'
import json, sys
doc = {"set": sys.argv[2], "run_dir": sys.argv[3],
       "reason": "no ground truth in the scoring format yet (validation/reference/truth/)"}
open(sys.argv[1], "w").write(json.dumps(doc, sort_keys=True) + "\n")
PY
    echo "validation: $name: run complete, not scored (no ground truth file)"
    return 0
  fi
  "${scoring[@]}" score --truth "$truth" --run "$run_dir" --out "$dir/score.json" --exit-code "$rc" ||
    die "scoring $name failed"
}

found=0
shopt -s nullglob
for truth in "$synthetic"/*.truth.json; do
  name="$(basename "$truth" .truth.json)"
  [[ -z "$only" || "$only" == "$name" ]] || continue
  image="$synthetic/$name.img"
  [[ -f "$image" ]] || die "$image is missing (truth without image). Rebuild with --build."
  run_set "$name" "$image" "$truth"
  found=$((found + 1))
done
if [[ -f "$reference/fetched.json" ]]; then
  while IFS=$'\t' read -r name image; do
    [[ -z "$only" || "$only" == "$name" ]] || continue
    truth="$repo/validation/reference/truth/$name.json"
    [[ -f "$truth" ]] || truth=""
    run_set "$name" "$image" "$truth"
    found=$((found + 1))
  done < <(python3 - "$reference/fetched.json" <<'PY'
import json, sys
for s in json.load(open(sys.argv[1]))["sets"]:
    if s.get("image"):
        print(f"{s['id']}\t{s['image']}")
PY
  )
fi
((found > 0)) || die "no validation sets found in $synthetic or $reference. Run with --build." 1
"${scoring[@]}" summary "$out"
