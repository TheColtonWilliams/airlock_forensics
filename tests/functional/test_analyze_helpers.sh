#!/usr/bin/env bash
# Helpers shared by the forensic-analyze functional tests (test_analyze_*.sh, test_faults.sh).
# Sourced: defines functions only. Run directly: checks that the helpers themselves work
# (fixture builder, read-only loop device, test module registry).
#
# Test-only hook: AIRLOCK_EXTRA_MODULES points the module registry at small test modules
# written by write_test_modules. They are used only when the real module of the same name is
# not installed. Never set on the image.

# shellcheck source=tests/functional/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

FA="$BIN_DIR/forensic-analyze"
export AIRLOCK_PYLIB="$PYLIB"
_analyze_loops=()

_analyze_detach_loops() {
  local l
  for l in "${_analyze_loops[@]+"${_analyze_loops[@]}"}"; do losetup -d "$l" 2>/dev/null || true; done
}
on_exit _analyze_detach_loops

analyze_require() {
  require_root
  require_loop
  require_cmd fls mmls fsstat img_cat openssl jq sha256sum
}

# make_ntfs_fixture OUT: the shared NTFS fixture when it exists, else a small one built here.
# The local one holds Docs/keep.txt (live) and Docs/gone.txt (deleted).
make_ntfs_fixture() {
  local out="$1" shared="$REPO_ROOT/tests/fixtures/ntfs-basic.img.zst" mnt
  if [[ -f "$shared" ]] && command -v zstd >/dev/null 2>&1; then
    zstd -q -d -f "$shared" -o "$out"
    return 0
  fi
  require_cmd mkfs.ntfs ntfs-3g
  truncate -s 40M "$out"
  mkfs.ntfs -Q -F -L FIXTURE "$out" >/dev/null 2>&1
  mnt="$(mktemp -d "$TEST_TMP/mnt.XXXXXX")"
  ntfs-3g "$out" "$mnt"
  mkdir -p "$mnt/Docs"
  printf 'hello\n' >"$mnt/Docs/keep.txt"
  printf 'plan for tuesday\n' >"$mnt/Docs/gone.txt"
  sync
  rm -f "$mnt/Docs/gone.txt"
  umount "$mnt"
  rmdir "$mnt"
}

# make_exfat_fixture OUT
make_exfat_fixture() {
  local out="$1" loop
  require_cmd mkfs.exfat
  truncate -s 16M "$out"
  loop="$(losetup -f --show "$out")"
  mkfs.exfat -L EXF "$loop" >/dev/null
  losetup -d "$loop"
}

# loop_ro IMAGE: attach a kernel read-only loop device; its path is left in $LOOP.
# (Not used in $(...): the detach list must live in this shell.)
LOOP=""
loop_ro() {
  LOOP="$(losetup -r -f --show "$1")"
  _analyze_loops+=("$LOOP")
}

# loop_rw IMAGE: a writable loop device (for refusal tests); path in $LOOP.
loop_rw() {
  LOOP="$(losetup -f --show "$1")"
  _analyze_loops+=("$LOOP")
}

# write_test_modules DIR: test-only modules, then export AIRLOCK_EXTRA_MODULES.
#   inventory    fls listing of every NTFS volume (sandboxed), one row per entry
#   recycle_bin  writes a counter file; sleeps AIRLOCK_TEST_SLEEP seconds when set
# AIRLOCK_TEST_FILL=N makes inventory write N MiB into its work folder (output-full test).
# AIRLOCK_TEST_SHUTDOWN=DIR makes inventory shut down the ext4 filesystem mounted at DIR before
# it reads (the evidence file lives there, so every later read fails with EIO).
write_test_modules() {
  local dir="$1"
  mkdir -p "$dir"
  cat >"$dir/test_inventory.py" <<'PY'
"""Test-only module: fls listing (functional tests)."""

from __future__ import annotations

import fcntl
import os
import struct

from forensic_analyze.api import Module, ModuleContext, ModuleResult


class FlsList(Module):
    name = "inventory"
    title = "Test file list (fls)"
    fs_types = frozenset({"ntfs"})
    order = 10

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
        # Export one live file the way real modules do (into export/), for the purge test.
        for r in rows:
            if r["path"].endswith("keep.txt") and r["allocated"]:
                vol_index, _, addr = r["inode_ref"][1:].partition(":")
                vol = ctx.target.volumes[int(vol_index)]
                (ctx.workdir / "export").mkdir(exist_ok=True)
                ctx.tool(
                    ["icat", "-o", str(vol.offset_bytes // 512), str(ctx.target.path), addr],
                    stdout_path=ctx.workdir / "export" / "keep.txt",
                )
        fill = int(os.environ.get("AIRLOCK_TEST_FILL") or 0)
        if fill:
            with open(ctx.workdir / "fill.bin", "wb") as fh:
                for _ in range(fill):
                    fh.write(b"\0" * 1024 * 1024)
                    fh.flush()
                    os.fsync(fh.fileno())
        return ModuleResult("ok", counts={"entries": len(rows)})


MODULE = FlsList()
PY
  cat >"$dir/test_recycle_bin.py" <<'PY'
"""Test-only module: counts its own runs; optional sleep (kill and resume test)."""

from __future__ import annotations

import os
import time
from pathlib import Path

from forensic_analyze.api import Module, ModuleContext, ModuleResult


class Counter(Module):
    name = "recycle_bin"
    title = "Test counter"
    fs_types = None
    order = 20

    def run(self, ctx: ModuleContext) -> ModuleResult:
        counter = Path(os.environ["AIRLOCK_TEST_COUNTER_DIR"]) / "recycle_bin.count"
        n = int(counter.read_text()) + 1 if counter.exists() else 1
        counter.write_text(str(n))
        time.sleep(float(os.environ.get("AIRLOCK_TEST_SLEEP") or 0))
        return ModuleResult("ok", counts={"runs": n})


MODULE = Counter()
PY
  export AIRLOCK_EXTRA_MODULES="$dir/test_inventory.py:$dir/test_recycle_bin.py"
  export AIRLOCK_TEST_COUNTER_DIR="$dir"
}

# run_dirs OUTPUT CASE: every run folder of a case, oldest first.
run_dirs() {
  find "$1/cases/$2" -mindepth 1 -maxdepth 1 -type d -name 'R-*' | sort
}

# analyze ARGS...: run forensic-analyze with the common non-interactive flags.
analyze() {
  run "$FA" --authority-ack --examiner "Test Examiner" --yes "$@"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  analyze_require
  img="$TEST_TMP/ntfs.img"
  make_ntfs_fixture "$img"
  loop_ro "$img"
  loop="$LOOP"
  assert_eq "$(cat "/sys/block/$(basename "$loop")/ro")" "1" "loop is read-only"
  write_test_modules "$TEST_TMP/mods"
  names="$(python3 -c 'from forensic_analyze.modules import all_modules; print(",".join(m.name for m in all_modules()))')"
  assert_contains "$names" "inventory" "registry sees the test module"
  pass "helpers work"
fi
