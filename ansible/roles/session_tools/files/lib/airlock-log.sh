#!/usr/bin/env bash
# Source this file from bash helpers. Provides: airlock_log TOOL EVENT [key=value ...]
# Installed to /opt/airlock/lib/airlock-log.sh. The Python logger does the JSON escaping.

airlock_pylib="${AIRLOCK_PYLIB:-${AIRLOCK_OPT_DIR:-/opt/airlock}/lib/python}"

airlock_log() {
  PYTHONPATH="$airlock_pylib${PYTHONPATH:+:$PYTHONPATH}" python3 -m airlock_common.sessionlog "$@"
}
