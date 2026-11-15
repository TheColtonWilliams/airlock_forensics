#!/usr/bin/env bash
# fetch.sh: download the public reference sets in sets.json and verify each by SHA-256
# (task 4F.2). Host computer only: the AIRLOCK drive never downloads, and this refuses to run
# there.
#
# Usage: validation/reference/fetch.sh [--only ID]... [--out DIR] [--record] [--check]
#
#   --only ID   fetch one set (repeatable); default: every pinned set
#   --out DIR   default: validation/out/reference (images, downloads, fetched.json)
#   --record    also fetch sets with no hash yet and write the hash seen into sets.json
#               (trust on first use: compare it with the publisher's page before committing)
#   --check     only check that sets.json is well formed
#
# Then: validation/run.sh --reference DIR
# Exit status: 0 fetched (or nothing pinned to fetch), 1 a download or hash check failed,
# 2 usage error, 77 python3 missing.
# Test: tests/unit/test_validation_reference.py
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
case "${1:-}" in
  -h | --help)
    sed -n '2,/^# Test:/p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
    exit 0
    ;;
esac
command -v python3 >/dev/null 2>&1 || {
  echo "fetch.sh: python3 is missing. Install it (sudo apt-get install python3)." >&2
  exit 77
}
exec python3 "$here/fetch.py" --sets "$here/sets.json" "$@"
