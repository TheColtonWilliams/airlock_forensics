#!/usr/bin/env bash
# Sandbox tests (task 4G.7, for 3A.9): a parser stand-in that tries to write outside its output
# folder, write to the evidence handle, open a network socket, exceed its memory limit, and
# exceed its time limit must be stopped each time. Runs every sandbox method that works here
# (bwrap; unshare fallback) and checks that it ran as the unprivileged parse user.
set -euo pipefail
# shellcheck source=tests/functional/test_analyze_helpers.sh
source "$(dirname "${BASH_SOURCE[0]}")/test_analyze_helpers.sh"
require_root
require_loop
require_cmd python3 unshare

work="$TEST_TMP/sbx"
mkdir -p "$work/out"
chmod 755 "$TEST_TMP" "$work"
cat >"$work/standin.py" <<'PY'
"""Parser stand-in: each action prints ALLOWED or STOPPED <errno>."""

import os
import socket
import sys
import time

action = sys.argv[1]
try:
    if action == "write_inside":
        with open("inside.txt", "w") as fh:
            fh.write("ok")
    elif action == "write_outside":
        with open(sys.argv[2], "w") as fh:
            fh.write("escaped")
    elif action == "write_evidence":
        fd = os.open(sys.argv[2], os.O_WRONLY)
        os.write(fd, b"x" * 512)
    elif action == "read_evidence":
        fd = os.open(sys.argv[2], os.O_RDONLY)
        os.read(fd, 512)
    elif action == "socket":
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect(("127.0.0.1", 9))
    elif action == "memory":
        blob = bytearray(2 * 1024 * 1024 * 1024)
    elif action == "time":
        time.sleep(60)
    elif action == "whoami":
        print(f"uid={os.getuid()}")
except OSError as exc:
    print(f"STOPPED {exc.errno}")
    sys.exit(0)
except MemoryError:
    print("STOPPED memory")
    sys.exit(0)
print("ALLOWED")
PY
chmod 644 "$work/standin.py"
truncate -s 4M "$work/evidence.img"
loop_ro "$work/evidence.img"
ev="$LOOP"

parse_uid="$(python3 -c 'from forensic_analyze.sandbox import sandbox_user; print(sandbox_user().uid)')"
[[ "$parse_uid" -ne 0 ]] || fail "parse user is root"
methods=(unshare)
if command -v bwrap >/dev/null 2>&1; then methods=(bwrap unshare); fi
tested=()
for method in "${methods[@]}"; do
  set +e
  out="$(python3 - "$method" "$work" "$ev" <<'PY'
import sys
from pathlib import Path

from forensic_analyze import sandbox as sb

method, work, ev = sys.argv[1], Path(sys.argv[2]), sys.argv[3]
box = sb.Sandbox(method=method, ro_paths=[str(work / "standin.py")], devices=[ev])
if method == "bwrap" and not sb._bwrap_works("bwrap"):
    print("SKIP bwrap does not work here")
    sys.exit(0)
box.grant_device(ev)
outdir = work / f"out-{method}"
py = sys.executable
script = str(work / "standin.py")
cases = [
    ("whoami", []),
    ("write_inside", []),
    ("write_outside", [str(work / f"escaped-{method}.txt")]),
    ("write_outside", ["/etc/airlock-escape-test"]),
    ("write_evidence", [ev]),
    ("read_evidence", [ev]),
    ("socket", []),
    ("memory", []),
]
for action, extra in cases:
    cp, rec = box.run([py, script, action, *extra], workdir=outdir, memory_bytes=512 * 1024**2)
    lines = cp.stdout.strip().splitlines() or [f"EXIT {cp.returncode}"]
    print(f"{action} {lines[-1]} {' '.join(lines[:-1])} user={rec.user}")
try:
    box.run([py, script, "time"], workdir=outdir, timeout=3)
    print("time ALLOWED")
except sb.LimitExceeded:
    print("time STOPPED limit")
print("describe", box.describe()["method"], box.describe()["seccomp"])
PY
)"
  rc=$?
  set -e
  [[ "$rc" -eq 0 ]] || fail "$method: harness failed: $out"
  if [[ "$out" == SKIP* ]]; then
    echo "$out"
    continue
  fi
  while IFS= read -r line; do printf '  [%s] %s\n' "$method" "$line"; done <<<"$out"
  assert_contains "$out" "whoami ALLOWED" "$method whoami"
  assert_contains "$out" "uid=$parse_uid " "$method runs as the parse user"
  assert_contains "$out" "write_inside ALLOWED" "$method write inside output folder"
  assert_not_contains "$out" "write_outside ALLOWED" "$method write outside stopped"
  assert_not_contains "$out" "write_evidence ALLOWED" "$method evidence write stopped"
  assert_contains "$out" "read_evidence ALLOWED" "$method evidence readable"
  assert_contains "$out" "socket STOPPED" "$method socket stopped"
  assert_contains "$out" "memory STOPPED memory" "$method memory limit"
  assert_contains "$out" "time STOPPED limit" "$method time limit"
  assert_no_file "$work/escaped-$method.txt"
  assert_no_file "/etc/airlock-escape-test"
  tested+=("$method")
done
[[ "${#tested[@]}" -gt 0 ]] || skip "no sandbox method works here"
pass "stopped each time with: ${tested[*]}"
