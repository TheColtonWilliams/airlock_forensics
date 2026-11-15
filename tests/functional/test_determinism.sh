#!/usr/bin/env bash
# 4D.9 determinism test: the same input gives a byte-identical findings.jsonl (apart from AI
# fields) and identical exports.
#
# Full replay: when forensic-analyze (runner + CLI) and the NTFS fixture are present, run the
# Quick preset, replay its run.json into a second output folder, and compare.
# Always: a stand-in inventory module reads `fls -m` output from an NTFS image (the shared
# fixture, or one made here) and emits rows through FindingsWriter in two separate processes
# with different hash seeds; merge and every export must then match byte for byte, and the
# image must be unchanged.
# shellcheck source=tests/functional/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

require_cmd python3

FIXTURE_ZST="$REPO_ROOT/tests/fixtures/ntfs-basic.img.zst"
IMG="$TEST_TMP/ntfs.img"

# ---------------------------------------------------------------------------- the image
populate() {
  local u="$1/Users/u"
  mkdir "$1/Users" && mkdir "$u" || return 1
  printf 'plain text\n' >"$u/report.txt" || return 1
  printf 'formula name\n' >"$u/=cmd.txt" || return 1
  printf 'plus name\n' >"$u/+1.txt" || return 1
  printf 'newline name\n' >"$u/line"$'\n'"break.txt" || return 1
  printf 'bidi name\n' >"$u/invoice"$'\u202e'"txt.exe" || return 1
  printf 'to delete\n' >"$u/gone.txt" || return 1
  sync
  rm -f -- "$u/gone.txt"
}

make_image() {
  if [[ -f "$FIXTURE_ZST" ]] && command -v zstd >/dev/null 2>&1; then
    zstd -q -d -o "$IMG" -- "$FIXTURE_ZST"
    echo "using shared fixture $FIXTURE_ZST"
    return 0
  fi
  command -v mkfs.ntfs >/dev/null 2>&1 || return 1
  truncate -s 16M "$IMG"
  mkfs.ntfs -q -F -f -L DETERMINISM "$IMG" >/dev/null 2>&1 || return 1
  # Add files (hostile names included) when this host can mount NTFS through FUSE.
  if [[ "$(id -u)" -eq 0 ]] && command -v ntfs-3g >/dev/null 2>&1 && [[ -e /dev/fuse ]]; then
    local mnt="$TEST_TMP/mnt"
    mkdir -p "$mnt"
    if ntfs-3g "$IMG" "$mnt" 2>/dev/null; then
      if populate "$mnt"; then
        umount "$mnt"
        echo "made NTFS image with files"
        return 0
      fi
      umount "$mnt" || true
      echo "note: could not add files to the NTFS image"
    fi
  fi
  echo "made empty NTFS image (no FUSE mount here)"
}

HAVE_IMAGE=0
if make_image && command -v fls >/dev/null 2>&1; then
  HAVE_IMAGE=1
fi

# ---------------------------------------------------------------------------- full replay
if [[ "$HAVE_IMAGE" -eq 1 && -x "$BIN_DIR/forensic-analyze" \
  && -f "$PYLIB/forensic_analyze/runner.py" ]]; then
  export AIRLOCK_PYLIB="$PYLIB"
  img_before="$(sha256_of "$IMG")"
  out1="$TEST_TMP/replay1" out2="$TEST_TMP/replay2"
  mkdir -p "$out1" "$out2"
  run "$BIN_DIR/forensic-analyze" --authority-ack --target "$IMG" --preset quick \
    --examiner "Test Examiner" --case-id DET-1 --output "$out1" --yes
  [[ "$RC" -eq 0 ]] || fail "first forensic-analyze run failed: $OUT"
  run_json="$(find "$out1" -name run.json -print -quit)"
  [[ -n "$run_json" ]] || fail "first run wrote no run.json"
  run "$BIN_DIR/forensic-analyze" --authority-ack --config "$run_json" --output "$out2" --yes
  [[ "$RC" -eq 0 ]] || fail "replay of run.json failed: $OUT"
  f1="$(find "$out1" -name findings.jsonl -print -quit)"
  f2="$(find "$out2" -name findings.jsonl -print -quit)"
  [[ -n "$f1" && -n "$f2" ]] || fail "a run wrote no findings.jsonl"
  run python3 -m forensic_analyze.findings compare "$f1" "$f2"
  [[ "$RC" -eq 0 ]] || fail "replay is not reproducible outside AI fields: $OUT"
  assert_eq "$(sha256_of "$IMG")" "$img_before" "image changed during the runs"
  echo "full replay: findings match outside AI fields"
else
  echo "note: forensic-analyze runner or image not available; full replay not run"
fi

# ---------------------------------------------------------------------------- stand-in module
EMIT="$TEST_TMP/emit_standin.py"
cat >"$EMIT" <<'PY'
"""Stand-in inventory module: fls bodyfile lines -> findings rows (raw bytes kept)."""
import datetime as dt
import sys
from pathlib import Path

from forensic_analyze import findings

run_dir, body = Path(sys.argv[1]), sys.argv[2]
kw = {
    "run_id": "R-20261115T120000Z-abc123",
    "evidence_id": "DETERMINISM-01",
    "evidence_sha256": sys.argv[3],
}
DESC = {7: "Last Access Time", 8: "Content Modification Time",
        9: "Metadata Modification Time", 10: "Creation Time"}
lines = Path(body).read_bytes().split(b"\n") if body != "-" else []
rows = []
for n, line in enumerate(lines, 1):
    cols = line.split(b"|")
    if len(cols) != 11:
        continue
    name = cols[1]
    deleted = name.endswith(b" (deleted)")
    if deleted:
        name = name[: -len(b" (deleted)")]
    for idx, desc in DESC.items():
        secs = int(cols[idx] or 0)
        if secs <= 0:
            continue
        when = dt.datetime.fromtimestamp(secs, dt.UTC)
        rows.append((name, idx, {
            "category": "inventory", "artifact_type": "file_entry",
            "message": "File system entry", "derivation": "observed",
            "source_tool": "sleuthkit", "tool_version": "test", "parser": "fls",
            "path": name, "inode_ref": "v0:" + cols[2].decode("ascii", "replace"),
            "size_bytes": int(cols[6] or 0), "allocated": not deleted,
            "datetime": when, "timestamp_desc": desc, "tz_basis": "utc",
            "source_record": f"modules/inventory/fls.body#L{n}",
        }))
# Hostile synthetic rows so the test has them even on an empty image.
for i, raw in enumerate([b"=cmd|x.txt", b"+1.txt", b"bad\xff\xfe.txt", "a\u202eb".encode(),
                         b"line\nbreak"]):
    rows.append((b"/synthetic/" + raw, 0, {
        "category": "inventory", "artifact_type": "file_entry", "message": "Synthetic entry",
        "derivation": "observed", "source_tool": "test", "tool_version": "1", "parser": "synthetic",
        "path": b"/synthetic/" + raw, "size_bytes": i,
    }))
rows.sort(key=lambda r: (r[0], r[1]))  # modules sort before emitting
with findings.FindingsWriter(findings.part_path(run_dir, "inventory"), module="inventory", **kw) as w:
    for _, _, row in rows:
        w.emit(row)
with findings.FindingsWriter(findings.part_path(run_dir, "images"), module="images", **kw) as w:
    w.emit({"category": "images", "artifact_type": "ai_description",
            "message": "A red circle", "derivation": "ai_generated", "text": sys.argv[4],
            "model_id": "stub", "model_sha256": "a" * 64, "prompt_sha256": "b" * 64,
            "source_tool": "stub", "tool_version": "1", "parser": "describe"})
print(w.count)
PY

body="-"
img_sha="$(printf 'no image' | sha256sum | cut -d' ' -f1)"
if [[ "$HAVE_IMAGE" -eq 1 ]]; then
  img_sha="$(sha256_of "$IMG")"
  body="$TEST_TMP/fls.body"
  fls -r -m / -- "$IMG" >"$body" || fail "fls could not read the NTFS image"
  [[ -s "$body" ]] || fail "fls listed nothing on the NTFS image"
else
  echo "note: no NTFS image or fls; using synthetic rows only"
fi

for n in 1 2; do
  d="$TEST_TMP/run$n"
  mkdir -p "$d"
  run env PYTHONHASHSEED="$n" python3 "$EMIT" "$d" "$body" "$img_sha" "AI text from run $n"
  [[ "$RC" -eq 0 ]] || fail "stand-in module failed: $OUT"
  run env PYTHONHASHSEED="$n" python3 -m forensic_analyze.findings merge "$d" inventory images
  [[ "$RC" -eq 0 ]] || fail "merge failed: $OUT"
  for exp in export_csv export_sqlite export_bodyfile; do
    run env PYTHONHASHSEED="$n" python3 -m "forensic_analyze.$exp" "$d"
    [[ "$RC" -eq 0 ]] || fail "$exp failed: $OUT"
  done
done

r1="$TEST_TMP/run1" r2="$TEST_TMP/run2"
rows="$(wc -l <"$r1/findings.jsonl")"
[[ "$rows" -ge 6 ]] || fail "expected rows in findings.jsonl, got $rows"

# AI text differs between the runs on purpose: bytes differ, the non-AI comparison must pass
# and the drift must be reported.
run python3 -m forensic_analyze.findings compare "$r1/findings.jsonl" "$r2/findings.jsonl"
[[ "$RC" -eq 0 ]] || fail "findings differ outside AI fields: $OUT"
assert_contains "$OUT" '"ai_drift_count": 1' "AI drift not reported"
assert_contains "$OUT" '"non_ai_identical": true'

# With equal AI text the files must be byte-identical.
d3="$TEST_TMP/run3"
mkdir -p "$d3"
env PYTHONHASHSEED=3 python3 "$EMIT" "$d3" "$body" "$img_sha" "AI text from run 1" >/dev/null
python3 -m forensic_analyze.findings merge "$d3" inventory images >/dev/null
for exp in export_csv export_sqlite export_bodyfile; do
  python3 -m "forensic_analyze.$exp" "$d3" >/dev/null
done
cmp -s "$r1/findings.jsonl" "$d3/findings.jsonl" || fail "findings.jsonl is not byte-identical"
cmp -s "$r1/findings.csv" "$d3/findings.csv" || fail "findings.csv is not byte-identical"
cmp -s "$r1/findings.bodyfile" "$d3/findings.bodyfile" || fail "findings.bodyfile differs"
run python3 - "$r1/case.sqlite" "$d3/case.sqlite" <<'PY'
import sqlite3, sys
def rows(p):
    con = sqlite3.connect(p)
    out = con.execute("SELECT rowid, * FROM findings ORDER BY rowid").fetchall()
    out += con.execute("SELECT * FROM export_info ORDER BY key").fetchall()
    con.close()
    return out
sys.exit(0 if rows(sys.argv[1]) == rows(sys.argv[2]) else 1)
PY
[[ "$RC" -eq 0 ]] || fail "case.sqlite rows differ between identical runs"

if [[ "$HAVE_IMAGE" -eq 1 ]]; then
  assert_eq "$(sha256_of "$IMG")" "$img_sha" "image changed while it was read"
fi
pass "findings.jsonl and exports are deterministic ($rows rows)"
