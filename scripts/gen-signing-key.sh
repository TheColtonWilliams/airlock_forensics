#!/usr/bin/env bash
# gen-signing-key.sh: make the Ed25519 key pair that signs assets/manifest.json (task 2B.15).
#
# Usage: scripts/gen-signing-key.sh --out-dir DIR [--force]
#
# Writes DIR/manifest-signing.key.pem (private, mode 0600) and DIR/manifest-signing.pub.pem.
# The private key belongs in the release workflow's secrets (MANIFEST_SIGNING_KEY), never in
# this repository: the script refuses a folder inside the git checkout. The public key is baked
# into the image at /etc/airlock/manifest-signing.pub.pem.
#
# Exit status: 0 written, 1 refused or failed, 2 usage error.
# Test: tests/unit/test_manifest_signing.py
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
die() {
  printf 'gen-signing-key: %s\n' "$1" >&2
  exit "${2:-1}"
}

out_dir=""
force=0
while (($#)); do
  case "$1" in
    --out-dir)
      [[ $# -ge 2 && -n "$2" ]] || die "--out-dir needs a folder" 2
      out_dir="$2"
      shift 2
      ;;
    --force)
      force=1
      shift
      ;;
    -h | --help)
      sed -n '2,/^# Exit status/p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *) die "unknown option '$1'. Run scripts/gen-signing-key.sh --help." 2 ;;
  esac
done
[[ -n "$out_dir" ]] || die "pass --out-dir DIR (a folder outside this repository)." 2
command -v openssl >/dev/null 2>&1 || die "openssl is missing. Install it (sudo apt-get install openssl)."

out_abs="$(realpath -m -- "$out_dir")"
repo_abs="$(realpath -m -- "$repo_root")"
if [[ "$out_abs" == "$repo_abs" || "$out_abs" == "$repo_abs"/* ]]; then
  die "$out_dir is inside the repository. Private keys never go in the repository; choose another folder."
fi
mkdir -p -- "$out_abs"

key="$out_abs/manifest-signing.key.pem"
pub="$out_abs/manifest-signing.pub.pem"
if [[ -e "$key" && "$force" != 1 ]]; then
  die "$key already exists. Keep it, or pass --force to replace it (old signatures stop verifying)."
fi

umask 077
tmp="$(mktemp "$out_abs/.manifest-signing.key.XXXXXX")"
trap 'rm -f -- "$tmp"' EXIT
openssl genpkey -algorithm ed25519 -out "$tmp" 2>/dev/null || die "openssl could not make an Ed25519 key."
chmod 0600 -- "$tmp"
mv -f -- "$tmp" "$key"
openssl pkey -in "$key" -pubout -out "$pub" 2>/dev/null || die "openssl could not write the public key."
chmod 0644 -- "$pub"
printf 'gen-signing-key: wrote %s (private, keep secret) and %s (public)\n' "$key" "$pub"
printf 'gen-signing-key: next, store the private key as the MANIFEST_SIGNING_KEY secret and bake the public key into the image.\n'
