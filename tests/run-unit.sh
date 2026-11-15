#!/usr/bin/env bash
# Run the Python unit tests. No root, no VM.
set -euo pipefail
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"
exec python3 -m pytest -q tests/unit "$@"
