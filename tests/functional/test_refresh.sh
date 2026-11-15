#!/usr/bin/env bash
# Refresh test (task 4G.16; checks 4A.7, 2B.7, 2B.15): a drive staged and provisioned from
# release v0.1.0 is restaged on the host with `fetch-assets.sh --refresh` from a newer signed
# release whose default profile changed (a newer ClamAV daily set, newer YARA rules, and a new
# speech model for the added whisper feature). Offline, forensic-import verifies and applies
# it and logs each file's SHA-256; the boot unit's `forensic-provision --if-changed` then has
# nothing left to do, and applies the next restage by itself. Ansible, goss and systemctl are
# stubs; the test HTTPS server stands in for the vendors; the signing key is thrown away.
set -euo pipefail
# shellcheck source=tests/functional/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

require_cmd python3 openssl sha256sum
python3 -c 'import yaml' 2>/dev/null || skip "needs python3-yaml"

SRV="$TEST_TMP/srv"
REQLOG="$TEST_TMP/requests.log"
mkdir -p "$SRV/models" "$SRV/yara" "$SRV/clamav"

# ------------------------------------------------------------------ test server (as in test_fetch_assets.sh)
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
BASE="https://127.0.0.1:$(cat "$TEST_TMP/port")"
export SSL_CERT_FILE="$TEST_TMP/tls.crt"
export NO_PROXY="127.0.0.1,localhost${NO_PROXY:+,$NO_PROXY}" no_proxy="127.0.0.1,localhost${no_proxy:+,$no_proxy}"

# ------------------------------------------------------------------ the drive's offline world
export AIRLOCK_PYLIB="$PYLIB"
export AIRLOCK_REPO_DIR="$TEST_TMP/repo"
export AIRLOCK_ALLOW_NONROOT=1
CALLS="$TEST_TMP/calls.log"
export AIRLOCK_TEST_CALLS="$CALLS"
mkdir -p "$TEST_TMP/sys/class/net/lo" "$TEST_TMP/proc/net"
printf '0x1003\n' >"$TEST_TMP/sys/class/net/lo/flags"
printf 'Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n' >"$TEST_TMP/proc/net/route"
: >"$TEST_TMP/proc/net/ipv6_route"
export AIRLOCK_SYSFS_DIR="$TEST_TMP/sys" AIRLOCK_PROC_DIR="$TEST_TMP/proc"
lsblk_fixture() { # 1 = an evidence disk is attached too
  local extra=""
  [[ "$1" == 1 ]] && extra=', {"name": "sdb", "path": "/dev/sdb", "type": "disk", "size": 250000000000, "tran": "sata", "mountpoints": [null]}'
  printf '{"blockdevices": [{"name": "sda", "path": "/dev/sda", "type": "disk", "size": 64000000000, "tran": "usb", "mountpoints": [null], "children": [{"name": "sda5", "path": "/dev/sda5", "type": "part", "size": 30000000000, "mountpoints": ["/"]}]}%s]}\n' \
    "$extra" >"$TEST_TMP/lsblk.json"
}
lsblk_fixture 0
export AIRLOCK_LSBLK_JSON="$TEST_TMP/lsblk.json"
mkdir -p "$AIRLOCK_REPO_DIR/ansible" "$AIRLOCK_REPO_DIR/tests/goss"
for f in site.yml inventory.ini ansible.cfg; do printf '# test\n' >"$AIRLOCK_REPO_DIR/ansible/$f"; done
printf 'file: {}\n' >"$AIRLOCK_REPO_DIR/tests/goss/base.yaml"
# shellcheck disable=SC2016 # stub bodies expand when the stubs run
stub ansible-playbook 'printf "ansible-playbook %s\n" "$*" >>"$AIRLOCK_TEST_CALLS"
for a in "$@"; do case "$a" in @*) cp -- "${a#@}" "$AIRLOCK_TEST_CALLS.vars.json" ;; esac; done'
# shellcheck disable=SC2016
stub goss 'printf "goss %s\n" "$*" >>"$AIRLOCK_TEST_CALLS"; echo "{\"summary\": {\"failed-count\": 0, \"test-count\": 1}}"'
# shellcheck disable=SC2016
stub systemctl 'printf "systemctl %s\n" "$*" >>"$AIRLOCK_TEST_CALLS"'
ansible_runs() { grep -c '^ansible-playbook' "$CALLS" 2>/dev/null || true; }

# ------------------------------------------------------------------ release v0.1.0
head -c 200000 /dev/urandom >"$SRV/models/tier0.gguf"
printf 'rule v1 { condition: false }\n' >"$SRV/yara/rules.yar"
printf 'ClamAV-VDB:daily 1\n' >"$SRV/clamav/daily.cvd"
write_release() { # VERSION OUTDIR WITH_WHISPER
  local whisper_pin="" whisper_feature="false"
  if [[ "$3" == 1 ]]; then
    whisper_pin="  whisper_model: {url: \"$BASE/models/whisper.bin\", version: \"small\", sha256: \"$(sha256_of "$SRV/models/whisper.bin")\", size: $(stat -c %s -- "$SRV/models/whisper.bin"), stage: assets, target: models/whisper.bin, profiles: [whisper], verify: sha256, license: MIT, notes: \"\"}"
    whisper_feature="true"
  fi
  cat >"$TEST_TMP/pins-$1.yml" <<PINS
pins:
  model_tier0: {url: "$BASE/models/tier0.gguf", version: "1", sha256: "$(sha256_of "$SRV/models/tier0.gguf")", size: $(stat -c %s -- "$SRV/models/tier0.gguf"), stage: assets, target: models/tier0.gguf, profiles: [ai_tier0], verify: sha256, license: Apache-2.0, notes: ""}
  yara_rules: {url: "$BASE/yara/rules.yar", version: "$1", sha256: "$(sha256_of "$SRV/yara/rules.yar")", size: $(stat -c %s -- "$SRV/yara/rules.yar"), stage: assets, target: yara/rules.yar, profiles: [yara], verify: sha256, license: DRL-1.1, notes: ""}
  clamav_daily: {url: "$BASE/clamav/daily.cvd", version: daily, sha256: null, size: null, stage: assets, target: clamav/daily.cvd, profiles: [clamav], verify: vendor_signature, license: GPL-2.0, notes: daily}
$whisper_pin
PINS
  cat >"$TEST_TMP/profiles-$1.yml" <<PROF
profiles:
  default: {description: d, features: {ai_tiers: [tier0], yara: true, clamav: true, whisper: $whisper_feature}}
PROF
  printf 'ai_tiers: {}\n' >"$TEST_TMP/ai.yml"
  mkdir -p "$2"
  python3 "$REPO_ROOT/scripts/gen-manifest.py" --pins "$TEST_TMP/pins-$1.yml" --profiles "$TEST_TMP/profiles-$1.yml" \
    --ai-models "$TEST_TMP/ai.yml" --release "$1" --out "$2/manifest.json" >/dev/null
  bash "$REPO_ROOT/scripts/sign-manifest.sh" --key "$TEST_TMP/sign.key" --manifest "$2/manifest.json" >/dev/null
}
openssl genpkey -algorithm ed25519 -out "$TEST_TMP/sign.key" 2>/dev/null
openssl pkey -in "$TEST_TMP/sign.key" -pubout -out "$AIRLOCK_ETC_DIR/manifest-signing.pub.pem" 2>/dev/null
write_release v0.1.0 "$TEST_TMP/rel1" 0
cp -- "$TEST_TMP/rel1/manifest.json" "$TEST_TMP/rel1/manifest.json.sig" "$AIRLOCK_STATE_DIR/"   # baked

FETCH=(bash "$REPO_ROOT/scripts/fetch-assets.sh" --yes --profile default --target-volume "$AIRLOCK_ASSETS_DIR" --cache "$TEST_TMP/cache")
run "${FETCH[@]}" --manifest "$TEST_TMP/rel1/manifest.json"
assert_eq "$RC" 0 "first staging: $OUT"
run "$BIN_DIR/forensic-provision" --no-reboot
assert_eq "$RC" 0 "first provisioning: $OUT"
old_daily="$(sha256_of "$SRV/clamav/daily.cvd")"
old_rules="$(sha256_of "$SRV/yara/rules.yar")"
echo "ok: drive staged from v0.1.0 and provisioned"

# ------------------------------------------------------------------ host: newer release, changed profile, --refresh
printf 'ClamAV-VDB:daily 2 (newer)\n' >"$SRV/clamav/daily.cvd"
printf 'rule v2 { condition: true }\n' >"$SRV/yara/rules.yar"
head -c 50000 /dev/urandom >"$SRV/models/whisper.bin"
write_release v0.1.1 "$TEST_TMP/rel2" 1
run "${FETCH[@]}" --refresh --manifest "$TEST_TMP/rel2/manifest.json"
assert_eq "$RC" 0 "restaging with --refresh: $OUT"
new_daily="$(sha256_of "$SRV/clamav/daily.cvd")"
new_rules="$(sha256_of "$SRV/yara/rules.yar")"
whisper="$(sha256_of "$SRV/models/whisper.bin")"
assert_ne "$new_daily" "$old_daily" "the daily set really changed"

# ------------------------------------------------------------------ drive: session start sees unapplied files
run python3 -m airlock_common.assets verify
assert_eq "$RC" 1 "before import the restaged files are not in use"
assert_contains "$OUT" "run 'sudo forensic-import'" "session start says what to do"

# ------------------------------------------------------------------ forensic-import refuses with evidence attached
lsblk_fixture 1
runs="$(ansible_runs)"
run "$BIN_DIR/forensic-import"
assert_eq "$RC" 1 "forensic-import refuses while an evidence disk is attached"
assert_contains "$OUT" "/dev/sdb" "names the disk"
assert_eq "$(ansible_runs)" "$runs" "nothing applied while refused"
lsblk_fixture 0

# ------------------------------------------------------------------ forensic-import applies offline
run "$BIN_DIR/forensic-import" --dry-run
assert_eq "$RC" 0 "dry run: $OUT"
assert_contains "$OUT" "clamav_daily: changed $new_daily" "dry run lists the new daily hash"
assert_contains "$OUT" "whisper_model: new $whisper" "dry run lists the new model"
assert_eq "$(ansible_runs)" "$runs" "dry run applies nothing"
run "$BIN_DIR/forensic-import"
assert_eq "$RC" 0 "forensic-import: $OUT"
assert_eq "$(ansible_runs)" "$((runs + 1))" "the Ansible roles ran once, offline"
python3 - "$AIRLOCK_SESSION_DIR/current.log" "$old_daily" "$new_daily" "$old_rules" "$new_rules" "$whisper" <<'PY' ||
import json, sys
log, old_daily, new_daily, old_rules, new_rules, whisper = sys.argv[1:7]
ev = [json.loads(l) for l in open(log, encoding="utf-8") if l.strip()]
applied = {e["id"]: e for e in ev if e["event"] == "asset_applied" and e["tool"] == "forensic-import"}
assert applied["clamav_daily"]["status"] == "changed", applied["clamav_daily"]
assert applied["clamav_daily"]["previous_sha256"] == old_daily
assert applied["clamav_daily"]["sha256"] == new_daily
assert applied["yara_rules"]["previous_sha256"] == old_rules
assert applied["yara_rules"]["sha256"] == new_rules
assert applied["whisper_model"]["status"] == "new" and applied["whisper_model"]["sha256"] == whisper
assert applied["model_tier0"]["status"] == "unchanged"
verified = [e for e in ev if e["event"] == "assets_verified" and e["tool"] == "forensic-import"][-1]
assert verified["ok"] and verified["manifest_release"] == "v0.1.1", verified
assert verified["files"]["clamav_daily"] == new_daily
PY
  fail "forensic-import did not log each file's SHA-256 (see the assertion above)"
python3 - "$AIRLOCK_STATE_DIR/applied-assets.json" "$CALLS.vars.json" "$AIRLOCK_STATE_DIR/manifest.json" <<'PY' ||
import json, sys
applied = json.load(open(sys.argv[1], encoding="utf-8"))
assert applied["mode"] == "import"
assert applied["manifest_release"] == "v0.1.1" and applied["manifest_source"] == "assets"
assert applied["features"]["whisper"] is True
v = json.load(open(sys.argv[2], encoding="utf-8"))
assert v["airlock_features"]["whisper"] is True
assert v["airlock_assets"]["whisper_model"]["path"].endswith("files/models/whisper.bin")
baked = json.load(open(sys.argv[3], encoding="utf-8"))
assert baked["release"] == "v0.1.1", "the newer signed manifest is kept as the trusted one"
PY
  fail "applied state after import (see the assertion above)"
run python3 -m airlock_common.assets verify --log-tool forensic-session-start
assert_eq "$RC" 0 "session start is clean after the import: $OUT"
run "$BIN_DIR/forensic-provision" --if-changed --no-reboot
assert_eq "$RC" 0 "boot unit: $OUT"
assert_contains "$OUT" "nothing changed on ASSETS" "the boot unit has nothing left to do"
echo "ok: forensic-import applied the newer signature set and changed profile offline and logged the hashes"

# ------------------------------------------------------------------ next restage, applied by the boot unit
printf 'ClamAV-VDB:daily 3\n' >"$SRV/clamav/daily.cvd"
run "${FETCH[@]}" --refresh --manifest "$TEST_TMP/rel2/manifest.json"
assert_eq "$RC" 0 "second refresh: $OUT"
runs="$(ansible_runs)"
run "$BIN_DIR/forensic-provision" --if-changed --no-reboot
assert_eq "$RC" 0 "boot unit applies a changed ASSETS set: $OUT"
assert_contains "$OUT" "the ASSETS set changed" "says why it runs"
assert_eq "$(ansible_runs)" "$((runs + 1))" "applied once"
grep -q "\"sha256\": \"$(sha256_of "$SRV/clamav/daily.cvd")\"" "$AIRLOCK_STATE_DIR/applied-assets.json" ||
  fail "the boot unit did not record the new daily hash"
grep -q 'systemctl reboot' "$CALLS" && fail "an update must not reboot"
echo "ok: the boot unit applies the next restage offline"

echo "PASS test_refresh"
