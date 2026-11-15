#!/usr/bin/env bash
# Task 4B.12: the neutral fixture set (generated shapes, a text render, a procedural landscape)
# must all screen as neutral with the real classifiers, describe must return non-empty text,
# and the probe must pick tier0 on a machine with no GPU (the recorded QEMU/llvmpipe output).
#
# The real classifiers need the /opt/triage venv with NudeNet and a staged SigLIP export
# (stage=assets). Set AIRLOCK_TRIAGE_PYTHON to another venv to run here; when no SigLIP export
# is staged and that venv has `onnx`, a stand-in SigLIP is built (plumbing only; noted below).
# Describe uses the real llama-server on 127.0.0.1:8088 when it answers, else the stub.
set -euo pipefail
# shellcheck source=tests/functional/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
# shellcheck source=tests/fixtures/ai/lib-ai.sh
source "$REPO_ROOT/tests/fixtures/ai/lib-ai.sh"
require_cmd python3

# 1. The committed fixtures are exactly what the generator makes (no hand-edited media).
python3 "$AI_FIX/make-neutral-fixtures.py" "$TEST_TMP/regen"
for f in "$AI_FIX"/neutral/*; do
  assert_eq "$(sha256_of "$TEST_TMP/regen/$(basename "$f")")" "$(sha256_of "$f")" "regen $f"
done

# 2. No GPU (recorded llvmpipe report, as in QEMU): tier0 on the CPU.
mkdir -p "$AIRLOCK_ASSETS_DIR/files/models/t0"
printf 'm' >"$AIRLOCK_ASSETS_DIR/files/models/t0/m.gguf"
printf 'p' >"$AIRLOCK_ASSETS_DIR/files/models/t0/p.gguf"
python3 - "$AIRLOCK_ETC_DIR/ai-tiers.json" <<'PY'
import json, sys
sys.path.insert(0, __import__("os").environ["PYLIB"])
from airlock_ai.config import DEFAULT_AI_CONFIG
cfg = json.loads(json.dumps(DEFAULT_AI_CONFIG))
cfg["tiers"]["tier0"]["models"] = [{"role": "model", "target": "models/t0/m.gguf"},
                                   {"role": "mmproj", "target": "models/t0/p.gguf"}]
json.dump(cfg, open(sys.argv[1], "w"))
PY
run "$BIN_DIR/ai-probe" --vulkaninfo "$REPO_ROOT/tests/fixtures/vulkaninfo/recorded-llvmpipe-no-gpu.txt" --json
assert_eq "$RC" "0" "probe: $OUT"
assert_eq "$(jq -r .tier <<<"$OUT")" "tier0" "no-GPU tier"
assert_eq "$(jq -r .backend <<<"$OUT")" "cpu" "no-GPU backend"

# 3. Real classifiers over the neutral set.
triage_py="${AIRLOCK_TRIAGE_PYTHON:-/opt/triage/bin/python}"
[[ -x "$triage_py" ]] || skip "needs the classifier venv (/opt/triage or AIRLOCK_TRIAGE_PYTHON)"
export AIRLOCK_TRIAGE_PYTHON="$triage_py"
sig="$AIRLOCK_ASSETS_DIR/files/models/siglip-base-patch16-224"
if [[ -n "${AIRLOCK_TEST_SIGLIP_DIR:-}" ]]; then
  mkdir -p "$sig" && cp "$AIRLOCK_TEST_SIGLIP_DIR"/* "$sig/"
elif "$triage_py" -c 'import onnx' 2>/dev/null; then
  echo "note: no SigLIP export staged; using a stand-in SigLIP (plumbing only)"
  "$triage_py" "$AI_FIX/make-fake-siglip.py" "$sig" 8
else
  skip "needs a staged SigLIP export (AIRLOCK_TEST_SIGLIP_DIR) or onnx in the venv"
fi
chmod -R a+rX "$TEST_TMP"
if [[ "$(id -u)" -eq 0 && "$triage_py" != /opt/* ]]; then
  # A venv outside /opt may not be readable by the sandbox user; run the launcher only.
  echo "note: venv outside /opt: sandbox method none for this run"
  export AIRLOCK_SANDBOX=none
fi
imgs=("$AI_FIX"/neutral/*.png)
run "$BIN_DIR/evidence-screen" "${imgs[@]}" -o "$TEST_TMP/screen.csv"
assert_eq "$RC" "0" "screen: $OUT"
assert_contains "$OUT" "Screened ${#imgs[@]} files: ${#imgs[@]} not flagged" "all neutral"

# 4. Describe returns non-empty text for every cleared fixture.
if ! python3 -c 'import urllib.request,sys; urllib.request.urlopen("http://127.0.0.1:8088/health", timeout=2)' 2>/dev/null; then
  start_llama_stub describe
fi
run "$BIN_DIR/evidence-describe" "${imgs[@]}" -o "$TEST_TMP/describe.csv" \
  --screen-csv "$TEST_TMP/screen.csv"
assert_eq "$RC" "0" "describe: $OUT"
assert_contains "$OUT" "${#imgs[@]} described" "every file described"
for f in "${imgs[@]}"; do
  [[ -n "$(csv_col "$TEST_TMP/describe.csv" "$(basename "$f")" description)" ]] ||
    fail "empty description for $f"
done
pass "neutral fixtures: screened neutral, described, tier0 without a GPU"
