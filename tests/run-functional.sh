#!/usr/bin/env bash
# Run every tests/functional/test_*.sh. Exit codes per test: 0 pass, 1 fail, 77 skip.
# Usage: tests/run-functional.sh [name-filter]
set -euo pipefail
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"
filter="${1:-}"
pass=0 fail=0 skip=0
failed_names=()
for t in tests/functional/test_*.sh; do
  [[ -e "$t" ]] || continue
  name="$(basename "$t" .sh)"
  if [[ -n "$filter" && "$name" != *"$filter"* ]]; then continue; fi
  set +e
  out="$(bash "$t" 2>&1)"
  rc=$?
  set -e
  case "$rc" in
    0) pass=$((pass + 1)); echo "PASS $name" ;;
    77) skip=$((skip + 1)); echo "SKIP $name: $(printf '%s\n' "$out" | tail -n1)" ;;
    *) fail=$((fail + 1)); failed_names+=("$name"); echo "FAIL $name"; printf '%s\n' "$out" | tail -n 40 | sed 's/^/    /' ;;
  esac
done
echo "functional: $pass passed, $fail failed, $skip skipped"
if ((fail > 0)); then
  echo "functional: failing tests: ${failed_names[*]}" >&2
  exit 1
fi
