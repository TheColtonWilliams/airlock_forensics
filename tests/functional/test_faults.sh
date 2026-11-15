#!/usr/bin/env bash
# Fault tests for the wizard (task 4G.8):
#   1. a run killed mid-way and resumed: finished modules are not run again (done markers);
#   2. an output drive that fills up: the run stops with a clear message and resumes later;
#   3. a target with read errors: the evidence file sits on an ext4 filesystem that is shut down
#      (EXT4_IOC_SHUTDOWN) so every read returns EIO. Device-mapper is not available in the
#      authoring container, so dm-error/dm-flakey cannot be used; partial (sector-level) errors
#      are covered by tests/unit/test_analyze_hashing.py with a reader that raises EIO;
#   4. BitLocker without a key stops with a clear message; with a wrong key it stops too.
#      A real BitLocker fixture cannot be made on Linux, so "with the right key" is verified in
#      the QEMU/CI stage (see docs/build-plan.md under Milestone 4G).
#
# The faults are runner faults, so the runs use two test-only stand-in modules with their own
# names (fault_list, fault_counter), registered through AIRLOCK_EXTRA_MODULES and chosen with
# --preset custom. They need hooks a real module must never have (sleep on demand, fill the
# output drive, shut down the drive holding the evidence). They do not shadow any real module:
# the real ones (inventory, recycle_bin, ...) stay installed and always win on a name clash.
set -euo pipefail
# shellcheck source=tests/functional/test_analyze_helpers.sh
source "$(dirname "${BASH_SOURCE[0]}")/test_analyze_helpers.sh"
analyze_require
require_cmd mkfs.ext4

# write_fault_modules DIR: the two stand-ins, then export AIRLOCK_EXTRA_MODULES.
#   fault_list     fls listing of every NTFS volume (sandboxed), one row per entry
#                  AIRLOCK_TEST_FILL=N writes N MiB into its work folder (output-full test);
#                  AIRLOCK_TEST_SHUTDOWN=DIR shuts down the ext4 filesystem mounted at DIR
#                  before it reads (the evidence file lives there, so reads fail with EIO).
#   fault_counter  counts its own runs in $AIRLOCK_TEST_COUNTER_DIR/fault_counter.count;
#                  sleeps AIRLOCK_TEST_SLEEP seconds when set (kill and resume test).
write_fault_modules() {
  local dir="$1"
  mkdir -p "$dir"
  cat >"$dir/fault_list.py" <<'PY'
"""Test-only stand-in module: fls listing with fault hooks (tests/functional/test_faults.sh)."""

from __future__ import annotations

import fcntl
import os
import struct

from forensic_analyze.api import Module, ModuleContext, ModuleResult


class FaultList(Module):
    name = "fault_list"
    title = "Test file list (fls)"
    fs_types = frozenset({"ntfs"})
    order = 1010

    def run(self, ctx: ModuleContext) -> ModuleResult:
        shutdown = os.environ.get("AIRLOCK_TEST_SHUTDOWN")
        if shutdown:  # simulate the drive failing mid-run: shut down the fs holding it
            fd = os.open(shutdown, os.O_RDONLY)
            fcntl.ioctl(fd, 0x8004587D, struct.pack("I", 2))  # EXT4_IOC_SHUTDOWN, NOLOGFLUSH
            os.close(fd)
            # Drop cached blocks so the next read really goes to the failed "drive".
            with open("/proc/sys/vm/drop_caches", "w") as fh:
                fh.write("3")
        rows = []
        for vol in ctx.target.volumes_of("ntfs"):
            out = ctx.workdir / f"fls-v{vol.index}.txt"
            sector = vol.offset_bytes // 512
            cp = ctx.tool(
                ["fls", "-r", "-p", "-o", str(sector), str(ctx.target.path)], stdout_path=out
            )
            if cp.returncode != 0:
                return ModuleResult("failed", f"fls exit {cp.returncode}")
            for line in out.read_text(encoding="utf-8", errors="replace").splitlines():
                head, _, path = line.partition("\t")
                parts = head.split()
                if len(parts) < 2:
                    continue
                deleted = "*" in parts
                rows.append(
                    {
                        "category": "inventory",
                        "artifact_type": "file_entry",
                        "message": "deleted file entry" if deleted else "file entry",
                        "derivation": "observed",
                        "source_tool": "fls",
                        "tool_version": ctx.tool_version("fls"),
                        "parser": "tsk",
                        "path": path,
                        "inode_ref": f"v{vol.index}:{parts[-1].rstrip(':')}",
                        "allocated": not deleted,
                    }
                )
        rows.sort(key=lambda r: (r["inode_ref"], r["path"]))
        for r in rows:
            ctx.emit(r)
        fill = int(os.environ.get("AIRLOCK_TEST_FILL") or 0)
        if fill:
            with open(ctx.workdir / "fill.bin", "wb") as fh:
                for _ in range(fill):
                    fh.write(b"\0" * 1024 * 1024)
                    fh.flush()
                    os.fsync(fh.fileno())
        return ModuleResult("ok", counts={"entries": len(rows)})


MODULE = FaultList()
PY
  cat >"$dir/fault_counter.py" <<'PY'
"""Test-only stand-in module: counts its own runs; optional sleep (kill and resume test)."""

from __future__ import annotations

import os
import time
from pathlib import Path

from forensic_analyze.api import Module, ModuleContext, ModuleResult


class FaultCounter(Module):
    name = "fault_counter"
    title = "Test counter"
    fs_types = None
    order = 1020

    def run(self, ctx: ModuleContext) -> ModuleResult:
        counter = Path(os.environ["AIRLOCK_TEST_COUNTER_DIR"]) / "fault_counter.count"
        n = int(counter.read_text()) + 1 if counter.exists() else 1
        counter.write_text(str(n))
        time.sleep(float(os.environ.get("AIRLOCK_TEST_SLEEP") or 0))
        return ModuleResult("ok", counts={"runs": n})


MODULE = FaultCounter()
PY
  export AIRLOCK_EXTRA_MODULES="$dir/fault_list.py:$dir/fault_counter.py"
  export AIRLOCK_TEST_COUNTER_DIR="$dir"
}

img="$TEST_TMP/ntfs.img"
make_ntfs_fixture "$img"
loop_ro "$img"
loop="$LOOP"
write_fault_modules "$TEST_TMP/mods"
# The stand-ins are registered next to the real modules, which are not shadowed.
names="$(python3 -c 'from forensic_analyze.modules import all_modules, load_errors
print(",".join(m.name for m in all_modules())); assert not load_errors(), load_errors()')" ||
  fail "module registry: $names"
assert_contains ",$names," ",inventory," "real inventory module still registered"
assert_contains ",$names," ",fault_list,fault_counter," "stand-in modules registered after the real ones"
out="$AIRLOCK_OUTPUT_DIR"
faults=(--preset custom --modules "fault_list,fault_counter")
common=("${faults[@]}" --output "$out")

# 1. Kill and resume -----------------------------------------------------------------------
counter="$TEST_TMP/mods/fault_counter.count"
AIRLOCK_TEST_SLEEP=60 "$FA" --authority-ack --examiner T --yes --target "$loop" "${common[@]}" \
  --case-id K-1 >"$TEST_TMP/kill.log" 2>&1 &
pid=$!
for _ in $(seq 1 100); do
  [[ -f "$counter" ]] && break
  sleep 0.2
done
[[ -f "$counter" ]] || fail "second module never started: $(cat "$TEST_TMP/kill.log")"
kill -9 "$pid"
wait "$pid" 2>/dev/null || true
rd="$(run_dirs "$out" K-1 | tail -n1)"
assert_file "$rd/modules/fault_list/.done" "first module finished before the kill"
assert_no_file "$rd/modules/fault_counter/.done"
assert_eq "$(jq -r .status "$rd/run.json")" "running" "killed run left as running"
stale="$(jq -r .handle.loop_device "$rd/run.json")"
run "$FA" --resume "$rd" --yes
[[ "$RC" -eq 0 ]] || fail "resume exited $RC: $OUT"
assert_eq "$(jq -r .status "$rd/run.json")" "complete" "resumed run complete"
assert_eq "$(cat "$counter")" "2" "interrupted module ran again"
grep -q '"event":"module_skipped_done","module":"fault_list"' "$rd/logs/run.jsonl" ||
  fail "finished module was not skipped on resume"
assert_eq "$(jq -r '.resumes | length' "$rd/run.json")" "1" "resume recorded"
assert_eq "$(jq -r .hashes.after.sha256 "$rd/run.json")" "$(sha256_of "$img")" "after hash"
if [[ -n "$stale" && "$stale" != "null" ]]; then
  [[ ! -e "/sys/block/$(basename "$stale")/loop/backing_file" ]] ||
    [[ "$(cat "/sys/block/$(basename "$stale")/loop/backing_file")" != "$loop" ]] ||
    fail "stale loop device $stale from the killed run was left attached"
fi
run "$FA" --verify "$rd"
[[ "$RC" -eq 0 ]] || fail "resumed run does not verify: $OUT"

# 2. Output drive fills up ------------------------------------------------------------------
small="$TEST_TMP/small-out"
mkdir -p "$small"
mount -t tmpfs -o size=6M tmpfs "$small"
# shellcheck disable=SC2317 # called by the EXIT trap
_umount_small() { umount "$small" 2>/dev/null || true; }
on_exit _umount_small
rm -f "$counter"
AIRLOCK_TEST_FILL=32 analyze --target "$loop" "${faults[@]}" --output "$small" --case-id F-1
[[ "$RC" -eq 1 ]] || fail "full output drive: expected exit 1, got $RC: $OUT"
assert_contains "$OUT" "output drive is full" "full-drive message"
assert_contains "$OUT" "--resume" "says how to continue"
rd="$(run_dirs "$small" F-1 | tail -n1)"
assert_no_file "$rd/modules/fault_list/.done"
mount -o remount,size=64M "$small"
run "$FA" --resume "$rd" --yes
[[ "$RC" -eq 0 ]] || fail "resume after freeing space exited $RC: $OUT"
assert_eq "$(jq -r .status "$rd/run.json")" "complete" "complete after space was freed"
assert_file "$rd/modules/fault_list/.done"

# 3. Read errors ----------------------------------------------------------------------------
host="$TEST_TMP/host.img"
truncate -s 96M "$host"
mkfs.ext4 -q "$host"
hm="$TEST_TMP/hostmnt"
mkdir -p "$hm"
mount -o loop "$host" "$hm"
# shellcheck disable=SC2317 # called by the EXIT trap
_umount_host() { umount "$hm" 2>/dev/null || true; }
on_exit _umount_host
cp "$img" "$hm/evidence.img"
bad="$(losetup -r -f --show --direct-io=on "$hm/evidence.img")"
_analyze_loops=("$bad" "${_analyze_loops[@]}")
AIRLOCK_TEST_SHUTDOWN="$hm" analyze --target "$bad" "${faults[@]}" --output "$out" --case-id E-1
[[ "$RC" -eq 3 ]] || fail "drive failing mid-run: expected exit 3, got $RC: $OUT"
rd="$(run_dirs "$out" E-1 | tail -n1)"
assert_eq "$(jq -r .status "$rd/run.json")" "complete" "run completed despite read errors"
assert_eq "$(jq -r '.modules[] | select(.name=="fault_list") | .status' "$rd/run.json")" "failed" \
  "module reading the failed drive failed"
assert_contains "$OUT" "Module fault_list failed" "failure shown at once"
assert_eq "$(jq -r '.modules[] | select(.name=="fault_counter") | .status' "$rd/run.json")" "ok" \
  "run continued after the failure"
assert_eq "$(jq -r .hashes.after.complete "$rd/run.json")" "false" "after hash marked incomplete"
assert_eq "$(jq -r .integrity.ok "$rd/run.json")" "false" "integrity flagged"
# A drive that cannot be read at all stops before any module runs.
analyze --target "$bad" "${faults[@]}" --output "$out" --case-id E-2
[[ "$RC" -eq 1 ]] || fail "unreadable drive: expected exit 1, got $RC: $OUT"
assert_contains "$OUT" "could not be read at all" "unreadable message"

# 4. BitLocker ------------------------------------------------------------------------------
bl="$TEST_TMP/bitlocker.img"
truncate -s 8M "$bl"
printf '\xeb\x58\x90-FVE-FS-' | dd of="$bl" conv=notrunc status=none
loop_ro "$bl"
blloop="$LOOP"
analyze --target "$blloop" "${faults[@]}" --output "$out" --case-id B-1
[[ "$RC" -eq 1 ]] || fail "BitLocker without key: expected exit 1, got $RC: $OUT"
assert_contains "$OUT" "BitLocker" "BitLocker named"
assert_contains "$OUT" "--bitlocker-key-file" "says which flag to use"
rd="$(run_dirs "$out" B-1 | tail -n1)"
assert_eq "$(jq -r .bitlocker.found "$rd/run.json")" "true" "BitLocker recorded"
assert_eq "$(jq -r .status "$rd/run.json")" "stopped" "run stopped"
keyf="$TEST_TMP/recovery.txt"
printf '111111-222222-333333-444444-555555-666666-777777-888888\n' >"$keyf"
analyze --target "$blloop" "${faults[@]}" --output "$out" --case-id B-2 --bitlocker-key-file "$keyf"
[[ "$RC" -eq 1 ]] || fail "BitLocker with a wrong key: expected exit 1, got $RC: $OUT"
assert_contains "$OUT" "BitLocker" "wrong key named"
rd="$(run_dirs "$out" B-2 | tail -n1)"
if grep -q "111111-222222" "$rd/run.json" "$rd/logs/run.jsonl" "$AIRLOCK_SESSION_DIR"/*.log; then
  fail "recovery key leaked into a record"
fi

# With the right key: needs a BitLocker fixture made on Windows (manage-bde), which cannot be
# built on Linux. Runs when tests/fixtures/bitlocker-ntfs.img.zst and its key file exist.
blfx="$REPO_ROOT/tests/fixtures/bitlocker-ntfs.img.zst"
blkey="$REPO_ROOT/tests/fixtures/bitlocker-ntfs.recovery.txt"
if [[ -f "$blfx" && -f "$blkey" ]] && command -v zstd >/dev/null 2>&1 && command -v fve-dd >/dev/null 2>&1; then
  zstd -q -d -f "$blfx" -o "$TEST_TMP/bl-real.img"
  loop_ro "$TEST_TMP/bl-real.img"
  analyze --target "$LOOP" --preset quick --output "$out" --case-id B-3 --bitlocker-key-file "$blkey"
  [[ "$RC" -eq 0 ]] || fail "BitLocker with the right key exited $RC: $OUT"
  rd="$(run_dirs "$out" B-3 | tail -n1)"
  assert_eq "$(jq -r .bitlocker.unlocked "$rd/run.json")" "true" "unlocked"
  assert_contains "$(jq -c '[.volumes[].fs_type]' "$rd/run.json")" "ntfs" "decrypted volume seen"
  echo "BitLocker with the right key: passed"
else
  echo "note: no BitLocker fixture here; the right-key case runs in the QEMU/CI stage"
fi

pass "kill and resume, output full, read errors, BitLocker without and with a wrong key"
