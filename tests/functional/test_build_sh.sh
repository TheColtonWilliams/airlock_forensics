#!/usr/bin/env bash
# scripts/build.sh (task 1.7): reads the pins and variables, refuses unpinned or malformed
# inputs, passes the right Packer variables, and fetches the pinned Packer and QEMU plugin
# only when their SHA-256 matches pins.yml. No VM is started (dry run and --prepare-tools).
# shellcheck source=tests/functional/lib.sh
. "$(dirname "$0")/lib.sh"
require_cmd python3 openssl sha256sum
python3 -c 'import yaml' 2>/dev/null || skip "needs python3-yaml"

build="$REPO_ROOT/scripts/build.sh"
pins="$REPO_ROOT/ansible/group_vars/all/pins.yml"
main="$REPO_ROOT/ansible/group_vars/all/main.yml"
pin() { python3 -c 'import sys,yaml; print(yaml.safe_load(open(sys.argv[1]))["pins"][sys.argv[2]][sys.argv[3]])' "$pins" "$1" "$2"; }
var() { python3 -c 'import sys,yaml; print(yaml.safe_load(open(sys.argv[1]))[sys.argv[2]])' "$main" "$1"; }
json_of() { printf '%s\n' "$1" | sed -n '/^{/,/^}/p'; }
jget() { python3 -c 'import json,sys; print(json.loads(sys.stdin.read())[sys.argv[1]])' "$1"; }

# ---------------------------------------------------------------- dry run
SOURCE_DATE_EPOCH=1700000000 run "$build" --dry-run --output "$TEST_TMP/out" --var boot_wait=5s
assert_eq "$RC" 0 "dry run: $OUT"
vars="$(json_of "$OUT")"
assert_eq "$(jget iso_sha256 <<<"$vars")" "$(pin ubuntu_server_iso sha256)" "ISO hash from pins.yml"
assert_eq "$(jget iso_url <<<"$vars")" "$(pin ubuntu_server_iso url)" "ISO URL from pins.yml"
assert_eq "$(jget apt_snapshot <<<"$vars")" "$(var apt_snapshot)" "apt snapshot from main.yml"
assert_eq "$(jget assets_partition_gib <<<"$vars")" "$(var assets_partition_gib)" "ASSETS size"
assert_eq "$(jget output_partition_gib <<<"$vars")" "$(var output_partition_gib)" "OUTPUT size"
assert_eq "$(jget root_image_gib <<<"$vars")" "$(var root_image_gib)" "root size"
assert_eq "$(jget esp_size_mib <<<"$vars")" "$(var esp_size_mib)" "ESP size"
assert_eq "$(jget airlock_version <<<"$vars")" "$(var airlock_version)" "version"
assert_eq "$(jget build_date <<<"$vars")" "2023-11-14T22:13:20Z" "SOURCE_DATE_EPOCH honoured"
assert_eq "$(jget output_dir <<<"$vars")" "$TEST_TMP/out" "output folder"
assert_eq "$(jget boot_wait <<<"$vars")" "5s" "--var override"
assert_eq "$(jget build_ssh_private_key_file <<<"$vars")" "<temporary>" "key path not shown"
assert_contains "$OUT" "packer_version=1.11.2"
assert_contains "$OUT" "qemu_plugin_version=1.1.8"
assert_contains "$OUT" "command: packer build -var-file="
assert_not_contains "$OUT" "PRIVATE KEY"

# ---------------------------------------------------------------- refusals
bad_pins="$TEST_TMP/pins-null.yml"
python3 - "$pins" "$bad_pins" <<'PY'
import sys, yaml
d = yaml.safe_load(open(sys.argv[1]))
d["pins"]["ubuntu_server_iso"]["sha256"] = None
yaml.safe_dump(d, open(sys.argv[2], "w"))
PY
run "$build" --dry-run --pins "$bad_pins"
assert_eq "$RC" 1 "null ISO hash refused"
assert_contains "$OUT" "not pinned"

bad_main="$TEST_TMP/main-bad.yml"
python3 - "$main" "$bad_main" <<'PY'
import sys, yaml
d = yaml.safe_load(open(sys.argv[1]))
d["apt_snapshot"] = "latest"
yaml.safe_dump(d, open(sys.argv[2], "w"))
PY
run "$build" --dry-run --vars "$bad_main"
assert_eq "$RC" 1 "bad snapshot refused"
assert_contains "$OUT" "apt_snapshot"

bad_ver="$TEST_TMP/pins-ver.yml"
python3 - "$pins" "$bad_ver" <<'PY'
import sys, yaml
d = yaml.safe_load(open(sys.argv[1]))
d["pins"]["packer_linux_amd64"]["version"] = "1.0.0"
yaml.safe_dump(d, open(sys.argv[2], "w"))
PY
run "$build" --dry-run --pins "$bad_ver"
assert_eq "$RC" 1 "Packer version mismatch refused"
assert_contains "$OUT" "Make them match"

run "$build" --dry-run --zstd-level 40
assert_eq "$RC" 1 "bad zstd level"
run "$build" --bogus
assert_eq "$RC" 1 "unknown option"
assert_contains "$OUT" "unknown option"
run "$build" --dry-run --var 'Bad Key=1'
assert_eq "$RC" 1 "bad --var"

# ---------------------------------------------------------------- pinned tool download
# Fake release zips: a 'packer' that records plugin installs, and a plugin binary.
dl="$TEST_TMP/dl"
mkdir -p "$dl"
log="$TEST_TMP/packer-calls"
python3 - "$dl" "$log" <<'PY'
import sys, zipfile, os
dl, log = sys.argv[1:3]
fake_packer = f"""#!/usr/bin/env bash
case "$1" in
  version) echo "Packer v1.11.2" ;;
  plugins) echo "$*" >>'{log}'; [[ "$2" == installed ]] && cat '{log}.installed' 2>/dev/null; [[ "$2" == install ]] && echo "$4" >'{log}.installed' ;;
esac
exit 0
"""
with zipfile.ZipFile(os.path.join(dl, "packer.zip"), "w") as z:
    z.writestr("packer", fake_packer)
with zipfile.ZipFile(os.path.join(dl, "plugin.zip"), "w") as z:
    z.writestr("LICENSE.txt", "MPL-2.0")
    z.writestr("packer-plugin-qemu_v1.1.8_x5.0_linux_amd64", "#!/bin/sh\nexit 0\n")
PY
fake_pins="$TEST_TMP/pins-fake.yml"
python3 - "$pins" "$fake_pins" "$(sha256_of "$dl/packer.zip")" "$(sha256_of "$dl/plugin.zip")" <<'PY'
import sys, yaml
d = yaml.safe_load(open(sys.argv[1]))
d["pins"]["packer_linux_amd64"]["url"] = "https://releases.example.invalid/packer.zip"
d["pins"]["packer_linux_amd64"]["sha256"] = sys.argv[3]
d["pins"]["packer_plugin_qemu_linux_amd64"]["url"] = "https://releases.example.invalid/plugin.zip"
d["pins"]["packer_plugin_qemu_linux_amd64"]["sha256"] = sys.argv[4]
yaml.safe_dump(d, open(sys.argv[2], "w"))
PY
stub packer 'echo "Packer v0.0.1"' # wrong version on PATH: build.sh must fetch the pinned one
stub curl "
out=''; url=''
while ((\$#)); do case \"\$1\" in -o) out=\"\$2\"; shift 2 ;; --) url=\"\$2\"; shift 2 ;; *) shift ;; esac; done
cp '$dl'/\"\$(basename \"\$url\")\" \"\$out\""

run "$build" --prepare-tools --pins "$fake_pins" --cache "$TEST_TMP/cache"
assert_eq "$RC" 0 "prepare tools: $OUT"
assert_file "$TEST_TMP/cache/tools/packer-1.11.2/packer"
assert_file "$TEST_TMP/cache/tools/qemu-plugin-1.1.8/packer-plugin-qemu_v1.1.8_x5.0_linux_amd64"
assert_contains "$(cat "$log")" "plugins install --path $TEST_TMP/cache/tools/qemu-plugin-1.1.8/packer-plugin-qemu_v1.1.8_x5.0_linux_amd64 github.com/hashicorp/qemu"

# Second run: cached zip and installed plugin are reused, nothing is downloaded again.
stub curl 'echo "unexpected download" >&2; exit 9'
: >"$log"
run "$build" --prepare-tools --pins "$fake_pins" --cache "$TEST_TMP/cache"
assert_eq "$RC" 0 "prepare tools from cache: $OUT"
assert_not_contains "$(cat "$log")" "plugins install --path"

# A download whose hash differs from the pin is refused and not kept.
python3 - "$fake_pins" <<'PY'
import sys, yaml
d = yaml.safe_load(open(sys.argv[1]))
d["pins"]["packer_linux_amd64"]["sha256"] = "0" * 64
yaml.safe_dump(d, open(sys.argv[1], "w"))
PY
stub curl "
out=''; url=''
while ((\$#)); do case \"\$1\" in -o) out=\"\$2\"; shift 2 ;; --) url=\"\$2\"; shift 2 ;; *) shift ;; esac; done
cp '$dl'/\"\$(basename \"\$url\")\" \"\$out\""
run "$build" --prepare-tools --pins "$fake_pins" --cache "$TEST_TMP/cache2"
assert_eq "$RC" 1 "hash mismatch refused"
assert_contains "$OUT" "SHA-256 mismatch"
[[ -z "$(find "$TEST_TMP/cache2" -type f -name '*.zip' 2>/dev/null)" ]] || fail "mismatched download was kept"

pass "build.sh"
