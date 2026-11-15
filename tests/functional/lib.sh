#!/usr/bin/env bash
# Shared helpers for tests/functional/test_*.sh. Source this file.
# Exit codes: 0 pass, 1 fail, 77 skip.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
export REPO_ROOT
PYLIB="$REPO_ROOT/ansible/roles/session_tools/files/pylib"
export PYLIB
BIN_DIR="$REPO_ROOT/ansible/roles/session_tools/files/bin"
export BIN_DIR
export PYTHONPATH="$PYLIB${PYTHONPATH:+:$PYTHONPATH}"

TEST_TMP="$(mktemp -d "${TMPDIR:-/tmp}/airlock-test.XXXXXX")"
export TEST_TMP
_cleanup_fns=()
on_exit() { _cleanup_fns+=("$1"); }
_run_cleanup() {
  local fn
  for fn in "${_cleanup_fns[@]+"${_cleanup_fns[@]}"}"; do "$fn" || true; done
  rm -rf -- "$TEST_TMP"
}
trap _run_cleanup EXIT

# Sandbox every on-image path into the temp dir.
export AIRLOCK_OPT_DIR="$TEST_TMP/opt"
export AIRLOCK_ETC_DIR="$TEST_TMP/etc"
export AIRLOCK_STATE_DIR="$TEST_TMP/state"
export AIRLOCK_SESSION_DIR="$TEST_TMP/session"
export AIRLOCK_ASSETS_DIR="$TEST_TMP/assets"
export AIRLOCK_OUTPUT_DIR="$TEST_TMP/output"
mkdir -p "$AIRLOCK_OPT_DIR" "$AIRLOCK_ETC_DIR" "$AIRLOCK_STATE_DIR" "$AIRLOCK_SESSION_DIR" \
  "$AIRLOCK_ASSETS_DIR" "$AIRLOCK_OUTPUT_DIR"

skip() { echo "skip: $*"; exit 77; }
fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "pass: ${*:-ok}"; exit 0; }

require_root() { [[ "$(id -u)" -eq 0 ]] || skip "needs root"; }
require_cmd() { local c; for c in "$@"; do command -v "$c" >/dev/null 2>&1 || skip "needs '$c'"; done; }
require_loop() { require_root; losetup -f >/dev/null 2>&1 || skip "needs a free loop device"; }

assert_eq() { [[ "$1" == "$2" ]] || fail "${3:-assert_eq}: expected '$2', got '$1'"; }
assert_ne() { [[ "$1" != "$2" ]] || fail "${3:-assert_ne}: did not expect '$2'"; }
assert_contains() { [[ "$1" == *"$2"* ]] || fail "${3:-assert_contains}: '$2' not found in output: $1"; }
assert_not_contains() { [[ "$1" != *"$2"* ]] || fail "${3:-assert_not_contains}: '$2' unexpectedly found"; }
assert_file() { [[ -f "$1" ]] || fail "${2:-assert_file}: missing file $1"; }
assert_no_file() { [[ ! -e "$1" ]] || fail "${2:-assert_no_file}: unexpected file $1"; }

# Run a command, capture combined output in $OUT and exit code in $RC; never aborts.
# shellcheck disable=SC2034 # OUT and RC are read by the sourcing test
run() {
  set +e
  OUT="$("$@" 2>&1)"
  RC=$?
  set -e
}

# Put stub executables first on PATH. Usage: stub NAME 'script body'
STUB_DIR="$TEST_TMP/stubs"
mkdir -p "$STUB_DIR"
export PATH="$STUB_DIR:$PATH"
stub() {
  local name="$1" body="$2"
  printf '#!/usr/bin/env bash\nset -euo pipefail\n%s\n' "$body" >"$STUB_DIR/$name"
  chmod +x "$STUB_DIR/$name"
}

sha256_of() { sha256sum -- "$1" | cut -d' ' -f1; }
