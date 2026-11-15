#!/usr/bin/env bash
# Helpers for the AI functional tests (tests/functional/test_screen_stub.sh, test_declined.sh,
# test_ai_*.sh). Source after tests/functional/lib.sh.
AI_FIX="$REPO_ROOT/tests/fixtures/ai"
export AI_FIX
export AIRLOCK_PYLIB="$PYLIB"

# start_llama_stub MODE: the stub model server on 127.0.0.1; sets LLAMA_URL, LLAMA_LOG,
# LLAMA_MODEL and points the AI helpers at it (no systemd start).
start_llama_stub() {
  local mode="$1" port_file="$TEST_TMP/llama.port"
  LLAMA_LOG="$TEST_TMP/llama-requests-$mode.jsonl"
  LLAMA_MODEL="$TEST_TMP/stub-model.gguf"
  printf 'GGUF stub model\n' >"$LLAMA_MODEL"
  rm -f -- "$port_file"
  python3 "$AI_FIX/stub_llama_server.py" --port-file "$port_file" --log "$LLAMA_LOG" \
    --model-file "$LLAMA_MODEL" --mode "$mode" &
  LLAMA_PID=$!
  on_exit stop_llama_stub
  local i
  for i in $(seq 1 100); do
    [[ -s "$port_file" ]] && break
    sleep 0.05
  done
  [[ -s "$port_file" ]] || fail "stub model server did not start (tried $i times)"
  LLAMA_URL="http://127.0.0.1:$(cat "$port_file")"
  export LLAMA_URL LLAMA_LOG LLAMA_MODEL
  export AIRLOCK_LLAMA_URL="$LLAMA_URL" AIRLOCK_LLAMA_NO_START=1
  export AIRLOCK_LLAMA_RUN_DIR="$TEST_TMP/no-llama-run"
}

stop_llama_stub() {
  if [[ -n "${LLAMA_PID:-}" ]]; then
    kill "$LLAMA_PID" 2>/dev/null || true
  fi
}

# A neutral video with a scene change at 4 s (landscape, then a circle) and a sine tone.
make_neutral_video() {
  local out="$1"
  ffmpeg -nostdin -loglevel error -y \
    -loop 1 -t 4 -i "$AI_FIX/neutral/landscape.png" \
    -loop 1 -t 4 -i "$AI_FIX/neutral/shapes-circle.png" \
    -f lavfi -t 8 -i sine=frequency=300:sample_rate=16000 \
    -filter_complex '[0:v][1:v]concat=n=2:v=1:a=0,format=yuv420p[v]' \
    -map '[v]' -map 2:a -r 10 -c:v libx264 -c:a aac -shortest "$out"
}

csv_col() { # csv_col FILE NAME-COLUMN-MATCH COLUMN: value of COLUMN in rows whose path matches
  python3 - "$@" <<'PY'
import csv, sys
path, match, col = sys.argv[1:4]
with open(path, encoding="utf-8-sig", newline="") as fh:
    for row in csv.DictReader(fh):
        if match in row["path"]:
            print(row[col])
PY
}
