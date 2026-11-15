#!/usr/bin/env bash
# Host-side fetchers against a local HTTPS test server (tasks 2B.10, 2B.11, 4A.4, 4A.7, 4B.15;
# the Linux half of 4G.2): scripts/fetch-assets.sh and, when pwsh is installed,
# scripts/fetch-assets.ps1 stage the same files with the same hashes. Covers: SHA-256 checked
# before and after the copy, resume of a cut download with an HTTP Range request, the abuse.ch
# key sent only with the MalwareBazaar download and never written, unpinned files refused, a
# changed file refused, --refresh, the NVIDIA packages only with nvidia_proprietary, profile
# changes, the free-space check, and (as root with loop devices) a real exFAT ASSETS partition.
# Also: the ClamAV set as pinned in the repo (tag clamav, verify vendor_signature, target
# hashsets/clamav/*.cvd), a wheel tagged by gen-manifest from the tools_ai role (classifiers),
# and make-usb.sh's exact call ("--yes --manifest M --profile P --assets DIR --cache DIR", the
# abuse.ch key only in AIRLOCK_ABUSECH_KEY, no terminal) against both fetchers.
set -euo pipefail
# shellcheck source=tests/functional/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

require_cmd python3 openssl sha256sum
python3 -c 'import yaml' 2>/dev/null || skip "needs python3-yaml"

FETCH="$REPO_ROOT/scripts/fetch-assets.sh"
KEY="abusech-test-key-$RANDOM$RANDOM"
SRV="$TEST_TMP/srv"
REQLOG="$TEST_TMP/requests.log"
mkdir -p "$SRV/models" "$SRV/yara" "$SRV/clamav" "$SRV/mb" "$SRV/nvidia" "$SRV/bad" "$SRV/wheels"

# ------------------------------------------------------------------ test server
cat >"$TEST_TMP/server.py" <<'PY'
"""HTTPS file server for the fetcher tests: Range, If-Range, ETag, HEAD, a request log, and a
connection cut once per path listed in ROOT/.drops.json ({"/path": bytes_before_cut})."""
import http.server
import json
import os
import ssl
import sys
import threading

root, cert, key, portfile, logfile = sys.argv[1:6]
lock = threading.Lock()


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def serve(self, body):
        with lock, open(logfile, "a", encoding="utf-8") as fh:
            fh.write(json.dumps({"method": self.command, "path": self.path,
                                 "key": self.headers.get("Auth-Key"),
                                 "range": self.headers.get("Range")}) + "\n")
        path = os.path.join(root, self.path.lstrip("/"))
        if not os.path.isfile(path):
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        with open(path, "rb") as fh:
            data = fh.read()
        etag = '"%x-%x"' % (len(data), os.stat(path).st_mtime_ns)
        start, status = 0, 200
        rng = self.headers.get("Range")
        if rng and rng.startswith("bytes=") and self.headers.get("If-Range") in (None, etag):
            start = int(rng[6:].split("-")[0])
            if start >= len(data):
                self.send_response(416)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            status = 206
        part = data[start:]
        self.send_response(status)
        self.send_header("Content-Length", str(len(part)))
        self.send_header("ETag", etag)
        if status == 206:
            self.send_header("Content-Range", f"bytes {start}-{len(data) - 1}/{len(data)}")
        self.end_headers()
        if not body:
            return
        cut = None
        drops = os.path.join(root, ".drops.json")
        with lock:
            if status == 200 and os.path.exists(drops):
                with open(drops, encoding="utf-8") as fh:
                    table = json.load(fh)
                cut = table.pop(self.path, None)
                with open(drops, "w", encoding="utf-8") as fh:
                    json.dump(table, fh)
        if cut is not None:
            self.wfile.write(part[:cut])
            self.wfile.flush()
            self.close_connection = True
            return
        self.wfile.write(part)

    def do_GET(self):
        self.serve(True)

    def do_HEAD(self):
        self.serve(False)


srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(cert, key)
srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
with open(portfile + ".tmp", "w", encoding="utf-8") as fh:
    fh.write(str(srv.server_address[1]))
os.replace(portfile + ".tmp", portfile)
srv.serve_forever()
PY

openssl req -x509 -newkey ed25519 -nodes -keyout "$TEST_TMP/tls.key" -out "$TEST_TMP/tls.crt" \
  -days 2 -subj /CN=127.0.0.1 -addext subjectAltName=IP:127.0.0.1 >/dev/null 2>&1 ||
  skip "openssl cannot make a test TLS certificate"
python3 "$TEST_TMP/server.py" "$SRV" "$TEST_TMP/tls.crt" "$TEST_TMP/tls.key" "$TEST_TMP/port" "$REQLOG" &
server_pid=$!
stop_server() { kill "$server_pid" 2>/dev/null || true; }
on_exit stop_server
for _ in $(seq 1 50); do [[ -s "$TEST_TMP/port" ]] && break; sleep 0.1; done
[[ -s "$TEST_TMP/port" ]] || fail "the test HTTPS server did not start"
PORT="$(cat "$TEST_TMP/port")"
BASE="https://127.0.0.1:$PORT"
export SSL_CERT_FILE="$TEST_TMP/tls.crt"
export NO_PROXY="127.0.0.1,localhost${NO_PROXY:+,$NO_PROXY}" no_proxy="127.0.0.1,localhost${no_proxy:+,$no_proxy}"

# ------------------------------------------------------------------ content and manifest
head -c 2000000 /dev/urandom >"$SRV/models/tier0.gguf"
# shellcheck disable=SC2016 # YARA syntax, not a shell expansion
printf 'rule demo { strings: $a = "airlock" condition: $a }\n' >"$SRV/yara/rules.yar"
printf 'ClamAV-VDB:daily v1\n' >"$SRV/clamav/daily.cvd"
printf 'sha256_hash\n%064d\n' 0 >"$SRV/mb/full.txt"
printf 'nvidia test package\n' >"$SRV/nvidia/modules.deb"
printf 'the real file\n' >"$SRV/bad/file.bin"
printf 'not a real wheel, test bytes\n' >"$SRV/wheels/demo-1.0-py3-none-any.whl"

size_of() { stat -c %s -- "$1"; }
cat >"$TEST_TMP/pins.yml" <<EOF
pins:
  model_tier0:
    {url: "$BASE/models/tier0.gguf", version: "1", sha256: "$(sha256_of "$SRV/models/tier0.gguf")", size: $(size_of "$SRV/models/tier0.gguf"), stage: assets, target: models/tier0.gguf, profiles: [ai_tier0], verify: sha256, license: Apache-2.0, notes: ""}
  yara_rules:
    {url: "$BASE/yara/rules.yar", version: "abc", sha256: "$(sha256_of "$SRV/yara/rules.yar")", size: $(size_of "$SRV/yara/rules.yar"), stage: assets, target: yara/rules.yar, profiles: [yara], verify: sha256, license: DRL-1.1, notes: ""}
  clamav_daily:
    {url: "$BASE/clamav/daily.cvd", version: daily, sha256: null, size: null, stage: assets, target: hashsets/clamav/daily.cvd, profiles: [clamav], verify: vendor_signature, license: GPL-2.0, notes: daily}
  wheel_demo:
    {url: "$BASE/wheels/demo-1.0-py3-none-any.whl", version: "1.0", sha256: "$(sha256_of "$SRV/wheels/demo-1.0-py3-none-any.whl")", size: null, stage: assets, target: wheels/demo-1.0-py3-none-any.whl, profiles: [gpu], verify: sha256, license: MIT, notes: ""}
  malwarebazaar_full:
    {url: "$BASE/mb/full.txt", version: daily, sha256: null, size: null, stage: assets, target: hashsets/mb.txt, profiles: [malwarebazaar], verify: trusted_at_staging, license: CC0, notes: daily}
  nvidia_pkg:
    {url: "$BASE/nvidia/modules.deb", version: "1", sha256: "$(sha256_of "$SRV/nvidia/modules.deb")", size: null, stage: assets, target: nvidia/modules.deb, profiles: [nvidia_proprietary], verify: sha256, license: NVIDIA, notes: ""}
  unpinned_tool:
    {url: "$BASE/none.bin", version: "1", sha256: null, size: null, stage: assets, target: tools/none.bin, profiles: [default], verify: sha256, license: MIT, notes: host unreachable}
  bad_hash:
    {url: "$BASE/bad/file.bin", version: "1", sha256: "$(printf 'something else' | sha256sum | cut -d' ' -f1)", size: null, stage: assets, target: bad/file.bin, profiles: [ci], verify: sha256, license: MIT, notes: ""}
  huge_file:
    {url: "$BASE/huge.bin", version: "1", sha256: "$(printf x | sha256sum | cut -d' ' -f1)", size: 999999999999999, stage: assets, target: huge/huge.bin, profiles: [ci], verify: sha256, license: MIT, notes: ""}
EOF
cat >"$TEST_TMP/profiles.yml" <<'EOF'
profiles:
  default: {description: d, features: {ai_tiers: [tier0], clamav: true, yara: true, malwarebazaar: true, nvidia_proprietary: false, classifiers: true}}
  minimal: {description: m, features: {ai_tiers: [], yara: true}}
  gpu: {description: g, features: {ai_tiers: [tier0], yara: true, nvidia_proprietary: true}}
  ci: {description: c, features: {ai_tiers: []}}
EOF
printf 'ai_tiers: {}\n' >"$TEST_TMP/ai.yml"
# gen-manifest tags the tools_ai role's wheels with their feature (here: classifiers).
printf 'tools_ai_triage_wheel_pins: [wheel_demo]\n' >"$TEST_TMP/ai-role.yml"
REL="$TEST_TMP/release"
mkdir -p "$REL"
run python3 "$REPO_ROOT/scripts/gen-manifest.py" --pins "$TEST_TMP/pins.yml" --profiles "$TEST_TMP/profiles.yml" \
  --ai-models "$TEST_TMP/ai.yml" --ai-role "$TEST_TMP/ai-role.yml" --release v0.1.0-test --out "$REL/manifest.json"
assert_eq "$RC" 0 "gen-manifest: $OUT"
openssl genpkey -algorithm ed25519 -out "$TEST_TMP/sign.key" 2>/dev/null
run bash "$REPO_ROOT/scripts/sign-manifest.sh" --key "$TEST_TMP/sign.key" --manifest "$REL/manifest.json"
assert_eq "$RC" 0 "sign-manifest: $OUT"
MANIFEST="$REL/manifest.json"

gets() { grep -c '"method": "GET"' "$REQLOG" 2>/dev/null || true; }
staged_ids() { python3 -c 'import json,sys; print(" ".join(f["id"] for f in json.load(open(sys.argv[1]))["files"]))' "$1/profile.json"; }
staged_rows() { python3 -c 'import json,sys; print("\n".join(" ".join((f["id"], f["sha256"], f["target"], f["verify"])) for f in json.load(open(sys.argv[1]))["files"]))' "$1/profile.json"; }
skip_reason() { python3 -c 'import json,sys; print({s["id"]: s["reason"] for s in json.load(open(sys.argv[1]))["skipped"]}.get(sys.argv[2], ""))' "$1/profile.json" "$2"; }
no_key_in() { if grep -rqF -- "$KEY" "$@"; then fail "the abuse.ch key was written under $*"; fi; }

# ------------------------------------------------------------------ A: stage, resume, key
A="$TEST_TMP/assets-a"
mkdir -p "$A"
printf '{"/models/tier0.gguf": 700000}\n' >"$SRV/.drops.json"
run env AIRLOCK_ABUSECH_KEY="$KEY" bash "$FETCH" --yes --manifest "$MANIFEST" --profile default \
  --target-volume "$A" --cache "$TEST_TMP/cache-a" --examiner "Test Examiner"
assert_eq "$RC" 0 "bash fetcher stages the default profile: $OUT"
assert_contains "$OUT" "free; this profile needs" "free space reported before starting"
assert_eq "$(staged_ids "$A")" "clamav_daily malwarebazaar_full model_tier0 wheel_demo yara_rules" "staged set"
assert_contains "$(staged_rows "$A")" "clamav_daily $(sha256_of "$SRV/clamav/daily.cvd") hashsets/clamav/daily.cvd vendor_signature" \
  "ClamAV set staged with its observed hash, the repo's target and vendor_signature"
assert_file "$A/files/wheels/demo-1.0-py3-none-any.whl"
assert_eq "$(sha256_of "$A/files/models/tier0.gguf")" "$(sha256_of "$SRV/models/tier0.gguf")" "model copied intact"
assert_contains "$(skip_reason "$A" unpinned_tool)" "not pinned yet" "unpinned file refused"
assert_no_file "$A/files/tools/none.bin"
assert_no_file "$A/files/nvidia/modules.deb"
assert_file "$A/manifest.json"
assert_file "$A/manifest.json.sig"
cmp -s "$MANIFEST" "$A/manifest.json" || fail "manifest.json not copied verbatim"
grep -q '"range": "bytes=700000-"' "$REQLOG" || fail "the cut download was not resumed with a Range request"
python3 - "$REQLOG" <<'PY' || fail "the abuse.ch key went to a request other than the MalwareBazaar one"
import json, sys
for line in open(sys.argv[1], encoding="utf-8"):
    r = json.loads(line)
    if r["key"] and r["path"] != "/mb/full.txt":
        sys.exit(1)
    if r["path"] == "/mb/full.txt" and r["method"] == "GET" and not r["key"]:
        sys.exit(1)
PY
no_key_in "$A" "$TEST_TMP/cache-a"
assert_contains "$(cat "$A/profile.json")" '"examiner": "Test Examiner"' "case defaults"
echo "ok: bash fetcher stages, resumes, and keeps the key off the drive"

# ------------------------------------------------------------------ B: rerun is a no-op
before="$(gets)"
run bash "$FETCH" --yes --manifest "$MANIFEST" --profile default --target-volume "$A" --cache "$TEST_TMP/cache-a"
assert_eq "$RC" 0 "rerun: $OUT"
assert_eq "$(gets)" "$before" "rerun downloads nothing"
assert_contains "$OUT" "5 already on ASSETS and checked" "rerun checks what is there"
assert_contains "$OUT" "no abuse.ch key given; keeping the copy" "no key: the staged list is kept"
echo "ok: rerun keeps verified files"

# ------------------------------------------------------------------ PowerShell: same result
if command -v pwsh >/dev/null 2>&1; then
  P="$TEST_TMP/assets-ps"
  mkdir -p "$P"
  printf '{"/models/tier0.gguf": 500000}\n' >"$SRV/.drops.json"
  start_line="$(wc -l <"$REQLOG")"
  run env AIRLOCK_ABUSECH_KEY="$KEY" pwsh -NoProfile -NonInteractive -File "$REPO_ROOT/scripts/fetch-assets.ps1" \
    -Yes -Manifest "$MANIFEST" -Profile default -TargetVolume "$P" -Cache "$TEST_TMP/cache-ps"
  assert_eq "$RC" 0 "PowerShell fetcher stages the default profile: $OUT"
  assert_eq "$(staged_rows "$P")" "$(staged_rows "$A")" "both fetchers stage the same files and hashes"
  assert_contains "$(skip_reason "$P" unpinned_tool)" "not pinned yet" "PowerShell refuses unpinned files"
  assert_contains "$(head -c 400 "$P/profile.json")" '"case_defaults"' "PowerShell profile.json"
  python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); assert d["schema"] == 1 and d["fetcher"].startswith("fetch-assets.ps1 ") and d["features"]["ai_tiers"] == ["tier0"]' "$P/profile.json" ||
    fail "PowerShell profile.json shape"
  tail -n +"$((start_line + 1))" "$REQLOG" | grep -q '"range": "bytes=500000-"' || fail "PowerShell did not resume the cut download"
  no_key_in "$P" "$TEST_TMP/cache-ps"
  run pwsh -NoProfile -NonInteractive -File "$REPO_ROOT/scripts/fetch-assets.ps1" -Yes -Manifest "$MANIFEST" \
    -Profile default -TargetVolume "$TEST_TMP" -Cache "$TEST_TMP/cache-ps"
  assert_eq "$RC" 2 "PowerShell refuses a folder that is not ASSETS"
  echo "ok: PowerShell fetcher matches the bash fetcher"
else
  echo "note: pwsh not installed; PowerShell half not run"
fi

# ------------------------------------------------------------------ M: make-usb.sh's call
# Exactly the arguments make-usb.sh step_stage passes, the key only in the environment, stdin
# not a terminal: nothing is asked, and both fetchers stage what the bash run above staged.
M="$TEST_TMP/assets-m"
mkdir -p "$M"
run env AIRLOCK_ABUSECH_KEY="$KEY" bash "$FETCH" --yes --manifest "$MANIFEST" --profile default \
  --assets "$M" --cache "$TEST_TMP/cache-m" </dev/null
assert_eq "$RC" 0 "bash fetcher with make-usb.sh's arguments: $OUT"
assert_not_contains "$OUT" "Auth-Key for the MalwareBazaar" "no key prompt with --yes"
assert_eq "$(staged_ids "$M")" "$(staged_ids "$A")" "make-usb call stages the same set"
no_key_in "$M" "$TEST_TMP/cache-m"
if command -v pwsh >/dev/null 2>&1; then
  MP="$TEST_TMP/assets-mps"
  mkdir -p "$MP"
  run env AIRLOCK_ABUSECH_KEY="$KEY" pwsh -NoProfile -NonInteractive -File "$REPO_ROOT/scripts/fetch-assets.ps1" \
    --yes --manifest "$MANIFEST" --profile default --assets "$MP" --cache "$TEST_TMP/cache-mps" </dev/null
  assert_eq "$RC" 0 "PowerShell fetcher with make-usb.sh's (GNU-style) arguments: $OUT"
  assert_eq "$(staged_rows "$MP")" "$(staged_rows "$M")" "PowerShell stages the same files from the same call"
  no_key_in "$MP" "$TEST_TMP/cache-mps"
  run pwsh -NoProfile -NonInteractive -File "$REPO_ROOT/scripts/fetch-assets.ps1" --yes --manifest "$MANIFEST" \
    --profile default --target-volume "$MP" --cache "$TEST_TMP/cache-mps" --dry-run --case-prefix X </dev/null
  assert_eq "$RC" 0 "PowerShell takes --target-volume, --dry-run and --case-prefix too: $OUT"
fi
echo "ok: make-usb.sh's fetcher call works with both fetchers and asks nothing"

# ------------------------------------------------------------------ C: --refresh
printf 'ClamAV-VDB:daily v2 (newer)\n' >"$SRV/clamav/daily.cvd"
before="$(gets)"
run bash "$FETCH" --yes --refresh --manifest "$MANIFEST" --profile default --target-volume "$A" --cache "$TEST_TMP/cache-a"
assert_eq "$RC" 0 "refresh: $OUT"
assert_eq "$(sha256_of "$A/files/hashsets/clamav/daily.cvd")" "$(sha256_of "$SRV/clamav/daily.cvd")" "daily set restaged"
assert_contains "$(staged_rows "$A")" "clamav_daily $(sha256_of "$SRV/clamav/daily.cvd")" "new daily hash recorded"
after="$(gets)"
assert_eq "$((after - before))" 1 "refresh downloads only the daily set (MalwareBazaar kept without a key)"
echo "ok: --refresh restages the daily-changing set"

# ------------------------------------------------------------------ D: NVIDIA only when asked (4B.15)
run bash "$FETCH" --yes --manifest "$MANIFEST" --profile gpu --target-volume "$A" --cache "$TEST_TMP/cache-a"
assert_eq "$RC" 0 "gpu profile: $OUT"
assert_file "$A/files/nvidia/modules.deb"
assert_no_file "$A/files/hashsets/clamav/daily.cvd"
assert_contains "$OUT" "removed files/hashsets/clamav/daily.cvd (not in this profile)" "profile change prunes old files"
echo "ok: nvidia_proprietary stages the driver packages; profile change prunes"

# ------------------------------------------------------------------ E: changed file refused
printf '{"name": "broken", "files": ["bad_hash"]}\n' >"$TEST_TMP/broken.json"
E="$TEST_TMP/assets-e"
mkdir -p "$E"
run bash "$FETCH" --yes --manifest "$MANIFEST" --profile "$TEST_TMP/broken.json" --target-volume "$E" --cache "$TEST_TMP/cache-e"
assert_eq "$RC" 1 "a file that does not match its pin fails the run"
assert_contains "$OUT" "does not match its pinned SHA-256" "says why"
assert_no_file "$E/files/bad/file.bin"
assert_contains "$(skip_reason "$E" bad_hash)" "does not match its pinned SHA-256" "recorded in profile.json"
echo "ok: a download that does not match its pin is refused"

# ------------------------------------------------------------------ F: not enough space
printf '{"name": "huge", "files": ["huge_file"]}\n' >"$TEST_TMP/huge.json"
F="$TEST_TMP/assets-f"
mkdir -p "$F"
run bash "$FETCH" --yes --manifest "$MANIFEST" --profile "$TEST_TMP/huge.json" --target-volume "$F" --cache "$TEST_TMP/cache-f"
assert_eq "$RC" 2 "refuses when ASSETS is too small"
assert_contains "$OUT" "not enough space on ASSETS" "says why"
assert_no_file "$F/profile.json"
echo "ok: free-space refusal"

# ------------------------------------------------------------------ G: wrong folder refused
mkdir -p "$TEST_TMP/not-assets/stuff"
run bash "$FETCH" --yes --manifest "$MANIFEST" --profile minimal --target-volume "$TEST_TMP/not-assets" --cache "$TEST_TMP/cache-g"
assert_eq "$RC" 1 "a non-empty folder without ASSETS markers is refused"
assert_contains "$OUT" "is not the ASSETS partition" "says why"
assert_no_file "$TEST_TMP/not-assets/profile.json"
echo "ok: refuses a folder that is not ASSETS"

# ------------------------------------------------------------------ H: real exFAT partition
if [[ "$(id -u)" == 0 ]] && command -v mkfs.exfat >/dev/null 2>&1 && command -v blkid >/dev/null 2>&1 &&
  losetup -f >/dev/null 2>&1; then
  loops=()
  detach() { local l; for l in "${loops[@]+"${loops[@]}"}"; do losetup -d "$l" 2>/dev/null || true; done; }
  on_exit detach
  loop=""
  mkloop() { # IMAGE LABEL; sets $loop (no subshell, so the cleanup list keeps it)
    truncate -s 48M "$1"
    mkfs.exfat -L "$2" "$1" >/dev/null
    loop="$(losetup -f --show -- "$1")"
    loops+=("$loop")
    # Some hosts attach new loop devices read-only; the test image must be writable.
    blockdev --setrw "$loop" 2>/dev/null || true
  }
  mkloop "$TEST_TMP/assets.img" ASSETS
  good="$loop"
  mkloop "$TEST_TMP/other.img" OTHER
  other="$loop"
  run bash "$FETCH" --yes --manifest "$MANIFEST" --profile minimal --target-volume "$other" --cache "$TEST_TMP/cache-h"
  assert_eq "$RC" 1 "a partition not labelled ASSETS is refused"
  assert_contains "$OUT" "is not labelled ASSETS" "says why"
  run bash "$FETCH" --yes --manifest "$MANIFEST" --profile minimal --target-volume "$good" --cache "$TEST_TMP/cache-h"
  if [[ "$RC" == 0 ]]; then
    assert_contains "$OUT" "mounted $good" "the fetcher mounts the partition itself"
    findmnt -n --source "$good" >/dev/null 2>&1 && fail "the fetcher left $good mounted"
    mkdir -p "$TEST_TMP/check"
    if mount -t exfat -o ro "$good" "$TEST_TMP/check" 2>/dev/null || mount.exfat-fuse -o ro "$good" "$TEST_TMP/check" >/dev/null 2>&1; then
      assert_file "$TEST_TMP/check/profile.json"
      assert_eq "$(sha256_of "$TEST_TMP/check/files/yara/rules.yar")" "$(sha256_of "$SRV/yara/rules.yar")" "staged onto exFAT"
      umount "$TEST_TMP/check"
    fi
    echo "ok: stages onto a real exFAT partition labelled ASSETS and unmounts it"
  else
    assert_contains "$OUT" "could not mount" "only a missing exFAT driver may stop the loop-device part: $OUT"
    echo "note: no exFAT mount support here; block-device staging not exercised"
  fi
else
  echo "note: not root or no loop/exFAT tools; block-device part not run"
fi

echo "PASS test_fetch_assets"
