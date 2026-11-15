#!/usr/bin/env bash
# Asset tamper tests (task 4G.4; checks 2B.12, 2B.14, 2B.15). A drive staged by the real
# fetcher is tampered with in four ways: a swapped file, a truncated file, an edited manifest,
# and a bad signature (plus a changed daily signature file and a ClamAV database whose vendor
# signature fails). Each must be detected both at
# provisioning (forensic-provision) and at session start (the airlock_common.assets check that
# forensic-session-start runs), with the asset named and the feature that needs it turned off.
# Ansible, goss, systemctl and sigtool are stubs; the signing key is made here and thrown away.
set -euo pipefail
# shellcheck source=tests/functional/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

require_cmd python3 openssl sha256sum
python3 -c 'import yaml' 2>/dev/null || skip "needs python3-yaml"

export AIRLOCK_PYLIB="$PYLIB"
export AIRLOCK_REPO_DIR="$TEST_TMP/repo"
export AIRLOCK_ALLOW_NONROOT=1
PROVISION="$BIN_DIR/forensic-provision"
CALLS="$TEST_TMP/calls.log"
export AIRLOCK_TEST_CALLS="$CALLS"

# ------------------------------------------------------------------ fake host: offline, one disk
mkdir -p "$TEST_TMP/sys/class/net/lo" "$TEST_TMP/sys/class/net/eth0" "$TEST_TMP/proc/net"
printf '0x1003\n' >"$TEST_TMP/sys/class/net/lo/flags"
printf '0x1002\n' >"$TEST_TMP/sys/class/net/eth0/flags"
printf 'down\n' >"$TEST_TMP/sys/class/net/eth0/operstate"
printf 'Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n' >"$TEST_TMP/proc/net/route"
: >"$TEST_TMP/proc/net/ipv6_route"
export AIRLOCK_SYSFS_DIR="$TEST_TMP/sys" AIRLOCK_PROC_DIR="$TEST_TMP/proc"
cat >"$TEST_TMP/lsblk.json" <<'EOF'
{"blockdevices": [{"name": "sda", "path": "/dev/sda", "type": "disk", "size": 64000000000,
  "ro": false, "rm": true, "tran": "usb", "mountpoints": [null],
  "children": [{"name": "sda5", "path": "/dev/sda5", "type": "part", "size": 30000000000,
                "mountpoints": ["/"]}]}]}
EOF
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
# The fake daily.cvd below is not signed by ClamAV; the stand-in sigtool accepts it (lib.sh).
stub_sigtool

# ------------------------------------------------------------------ release: content, manifest
SRC="$TEST_TMP/src"
mkdir -p "$SRC"
head -c 300000 /dev/urandom >"$SRC/model.gguf"
# shellcheck disable=SC2016 # YARA syntax, not a shell expansion
printf 'rule demo { strings: $a = "airlock" condition: $a }\n' >"$SRC/rules.yar"
printf 'ClamAV-VDB:daily test\n' >"$SRC/daily.cvd"
pin() { # ID FILE TARGET TAG
  printf '  %s: {url: "https://example.invalid/%s", version: "1", sha256: "%s", size: %s, stage: assets, target: %s, profiles: [%s], verify: sha256, license: test, notes: ""}\n' \
    "$1" "$1" "$(sha256_of "$2")" "$(stat -c %s -- "$2")" "$3" "$4"
}
{
  echo "pins:"
  pin model_tier0 "$SRC/model.gguf" models/tier0.gguf ai_tier0
  pin yara_rules "$SRC/rules.yar" yara/rules.yar yara
  printf '  clamav_daily: {url: "https://example.invalid/daily.cvd", version: daily, sha256: null, size: null, stage: assets, target: clamav/daily.cvd, profiles: [clamav], verify: vendor_signature, license: GPL-2.0, notes: daily}\n'
} >"$TEST_TMP/pins.yml"
cat >"$TEST_TMP/profiles.yml" <<'EOF'
profiles:
  default: {description: d, features: {ai_tiers: [tier0], yara: true, clamav: true}}
EOF
printf 'ai_tiers: {}\n' >"$TEST_TMP/ai.yml"
REL="$TEST_TMP/release"
mkdir -p "$REL"
gen() { # RELEASE OUT
  python3 "$REPO_ROOT/scripts/gen-manifest.py" --pins "$TEST_TMP/pins.yml" --profiles "$TEST_TMP/profiles.yml" \
    --ai-models "$TEST_TMP/ai.yml" --release "$1" --out "$2" >/dev/null
}
gen v0.1.0 "$REL/manifest.json"
openssl genpkey -algorithm ed25519 -out "$TEST_TMP/sign.key" 2>/dev/null
openssl pkey -in "$TEST_TMP/sign.key" -pubout -out "$AIRLOCK_ETC_DIR/manifest-signing.pub.pem" 2>/dev/null
bash "$REPO_ROOT/scripts/sign-manifest.sh" --key "$TEST_TMP/sign.key" --manifest "$REL/manifest.json" >/dev/null
cp -- "$REL/manifest.json" "$REL/manifest.json.sig" "$AIRLOCK_STATE_DIR/"   # baked into the image

# Stage with the real fetcher from a pre-filled download cache (no network needed).
CACHE="$TEST_TMP/cache"
mkdir -p "$CACHE/blobs" "$CACHE/moving" "$CACHE/partial"
for f in model.gguf rules.yar daily.cvd; do cp -- "$SRC/$f" "$CACHE/blobs/$(sha256_of "$SRC/$f")"; done
printf '{"sha256": "%s", "url": "https://example.invalid/daily.cvd", "size": 1, "fetched_at": "t"}\n' \
  "$(sha256_of "$SRC/daily.cvd")" >"$CACHE/moving/clamav_daily.json"
PRISTINE="$TEST_TMP/pristine"
mkdir -p "$PRISTINE"
run bash "$REPO_ROOT/scripts/fetch-assets.sh" --yes --manifest "$REL/manifest.json" --profile default \
  --target-volume "$PRISTINE" --cache "$CACHE"
assert_eq "$RC" 0 "staging the pristine drive: $OUT"

reset_drive() {
  rm -rf -- "$AIRLOCK_ASSETS_DIR" "$AIRLOCK_STATE_DIR/provision" "$AIRLOCK_STATE_DIR/applied-assets.json" \
    "$AIRLOCK_STATE_DIR/provision-manifest.json" "$AIRLOCK_SESSION_DIR" "$CALLS" "$CALLS.vars.json"
  mkdir -p "$AIRLOCK_SESSION_DIR"
  cp -a -- "$PRISTINE" "$AIRLOCK_ASSETS_DIR"
}
session_check() { python3 -m airlock_common.assets verify --log-tool forensic-session-start; }
last_session_event() {
  python3 - "$AIRLOCK_SESSION_DIR/current.log" <<'PY'
import json, sys
events = [json.loads(l) for l in open(sys.argv[1], encoding="utf-8") if l.strip()]
last = [e for e in events if e["event"] == "assets_verified"][-1]
print(json.dumps({"ok": last["ok"], "problems": last["problems"], "disabled": last["disabled_features"]}))
PY
}
disabled_in_vars() { python3 -c 'import json,sys; print(" ".join(json.load(open(sys.argv[1]))["airlock_disabled_features"]))' "$CALLS.vars.json"; }

# ------------------------------------------------------------------ baseline
reset_drive
run "$PROVISION" --no-reboot
assert_eq "$RC" 0 "clean drive provisions: $OUT"
assert_contains "$OUT" "all 3 staged file(s) check out" "clean drive verified"
run session_check
assert_eq "$RC" 0 "clean drive passes the session-start check: $OUT"
echo "ok: clean drive passes at provisioning and session start"

# expect_detected NAME ASSET REASON FEATURE: session start after provisioning, then provisioning.
expect_detected() {
  local name="$1" asset="$2" reason="$3" feature="$4" ev
  run session_check
  assert_eq "$RC" 1 "$name: session start must fail"
  assert_contains "$OUT" "$asset: " "$name: session start names the asset"
  assert_contains "$OUT" "$reason" "$name: session start says why"
  assert_contains "$OUT" "turned off: $feature" "$name: session start names the feature"
  ev="$(last_session_event)"
  assert_contains "$ev" '"ok": false' "$name: session log records the failure"
  assert_contains "$ev" "\"$asset\"" "$name: session log names the asset"
  run "$PROVISION" --no-reboot
  assert_eq "$RC" 0 "$name: provisioning continues without the feature: $OUT"
  assert_contains "$OUT" "$asset: " "$name: provisioning names the asset"
  assert_contains "$OUT" "$reason" "$name: provisioning says why"
  assert_contains "$OUT" "Turned off because of them: $feature" "$name: provisioning report"
  assert_contains " $(disabled_in_vars) " " $feature " "$name: feature off in the Ansible variables"
  python3 - "$AIRLOCK_STATE_DIR/applied-assets.json" "$asset" "$feature" <<'PY' || fail "$name: applied-assets.json"
import json, sys
data = json.load(open(sys.argv[1], encoding="utf-8"))
assert sys.argv[3] in data["disabled_features"], data["disabled_features"]
assert sys.argv[2] in [p[0] for p in data["problems"]], data["problems"]
assert sys.argv[2] not in data["files"]
PY
  assert_contains "$(cat "$AIRLOCK_OUTPUT_DIR/airlock-provision-report.txt")" "$asset" "$name: report on OUTPUT"
  echo "ok: $name detected at session start and at provisioning; $feature turned off"
}

# ------------------------------------------------------------------ 1. swapped file
reset_drive
"$PROVISION" --no-reboot >/dev/null
head -c "$(stat -c %s -- "$SRC/model.gguf")" /dev/urandom >"$AIRLOCK_ASSETS_DIR/files/models/tier0.gguf"
expect_detected "swapped file" model_tier0 "SHA-256 does not match the trusted manifest" ai_tier0

# ------------------------------------------------------------------ 2. truncated file
reset_drive
"$PROVISION" --no-reboot >/dev/null
truncate -s 5 "$AIRLOCK_ASSETS_DIR/files/yara/rules.yar"
expect_detected "truncated file" yara_rules "truncated or replaced" yara

# ------------------------------------------------------------------ 3. edited manifest
# The attacker swaps the model and edits the ASSETS manifest to bless it; the signature fails,
# so the baked manifest is used and still catches the swap.
reset_drive
"$PROVISION" --no-reboot >/dev/null
head -c 1000 /dev/urandom >"$AIRLOCK_ASSETS_DIR/files/models/tier0.gguf"
python3 - "$AIRLOCK_ASSETS_DIR/manifest.json" "$(sha256_of "$AIRLOCK_ASSETS_DIR/files/models/tier0.gguf")" <<'PY'
import json, sys
m = json.load(open(sys.argv[1], encoding="utf-8"))
m["release"] = "v0.9.0"
for f in m["files"]:
    if f["id"] == "model_tier0":
        f["sha256"], f["size"] = sys.argv[2], 1000
open(sys.argv[1], "w", encoding="utf-8").write(json.dumps(m, sort_keys=True, indent=2) + "\n")
PY
expect_detected "edited manifest" model_tier0 "size 1000 differs" ai_tier0
run session_check
assert_contains "$OUT" "manifest.json: ASSETS manifest signature does not verify" "edited manifest named"

# ------------------------------------------------------------------ 4. bad signature
# A newer manifest for a different model, with a signature from someone else's key.
reset_drive
"$PROVISION" --no-reboot >/dev/null
head -c 4000 /dev/urandom >"$SRC/other-model.gguf"
python3 - "$TEST_TMP/pins.yml" "$SRC/other-model.gguf" <<'PY'
import hashlib, os, sys, yaml
doc = yaml.safe_load(open(sys.argv[1], encoding="utf-8"))
data = open(sys.argv[2], "rb").read()
doc["pins"]["model_tier0"].update(sha256=hashlib.sha256(data).hexdigest(), size=len(data), version="2")
open(sys.argv[1] + ".v2", "w", encoding="utf-8").write(yaml.safe_dump(doc))
PY
python3 "$REPO_ROOT/scripts/gen-manifest.py" --pins "$TEST_TMP/pins.yml.v2" --profiles "$TEST_TMP/profiles.yml" \
  --ai-models "$TEST_TMP/ai.yml" --release v0.2.0 --out "$AIRLOCK_ASSETS_DIR/manifest.json" >/dev/null
openssl genpkey -algorithm ed25519 -out "$TEST_TMP/attacker.key" 2>/dev/null
bash "$REPO_ROOT/scripts/sign-manifest.sh" --key "$TEST_TMP/attacker.key" --manifest "$AIRLOCK_ASSETS_DIR/manifest.json" >/dev/null
cp -- "$SRC/other-model.gguf" "$AIRLOCK_ASSETS_DIR/files/models/tier0.gguf"
python3 - "$AIRLOCK_ASSETS_DIR/profile.json" "$(sha256_of "$SRC/other-model.gguf")" <<'PY'
import json, sys
p = json.load(open(sys.argv[1], encoding="utf-8"))
for f in p["files"]:
    if f["id"] == "model_tier0":
        f["sha256"] = sys.argv[2]
open(sys.argv[1], "w", encoding="utf-8").write(json.dumps(p))
PY
expect_detected "bad signature" model_tier0 "different SHA-256 than the trusted manifest" ai_tier0
run session_check
assert_contains "$OUT" "manifest.json: ASSETS manifest signature does not verify" "bad signature named"
grep -q '"manifest_source": "baked"' "$AIRLOCK_STATE_DIR/applied-assets.json" || fail "bad signature: baked manifest must stay in use"

# ------------------------------------------------------------------ 5. changed daily signature file
reset_drive
"$PROVISION" --no-reboot >/dev/null
printf 'X' >>"$AIRLOCK_ASSETS_DIR/files/clamav/daily.cvd"
run session_check
assert_eq "$RC" 1 "changed daily file caught at session start"
assert_contains "$OUT" "clamav_daily: size" "daily file named"
assert_contains "$OUT" "turned off: clamav" "clamav turned off"
echo "ok: a changed daily signature file is caught against the hash recorded at provisioning"

# ------------------------------------------------------------------ 6. vendor signature fails
# A ClamAV database whose own signature does not verify (sigtool says so) is refused even
# though its hash matches what was staged and applied.
reset_drive
"$PROVISION" --no-reboot >/dev/null
assert_contains "$(cat "$TEST_TMP/sigtool.calls")" "daily.cvd" "sigtool checked the ClamAV database"
export AIRLOCK_TEST_SIGTOOL_FAIL=1
expect_detected "failed vendor signature" clamav_daily "vendor signature check failed (sigtool)" clamav
unset AIRLOCK_TEST_SIGTOOL_FAIL

echo "PASS test_assets"
