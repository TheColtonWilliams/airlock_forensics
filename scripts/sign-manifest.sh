#!/usr/bin/env bash
# sign-manifest.sh: sign or verify assets/manifest.json with Ed25519 (task 2B.15).
# The signature is a raw Ed25519 signature (openssl pkeyutl -sign -rawin), checked on the drive
# against the public key baked in at /etc/airlock/manifest-signing.pub.pem.
#
# Usage:
#   scripts/sign-manifest.sh (--key FILE | --key-env VAR) [--manifest FILE] [--out FILE]
#                            [--pub FILE]
#   scripts/sign-manifest.sh --verify --pub FILE [--manifest FILE] [--sig FILE]
#
#   --key FILE      private key PEM (from scripts/gen-signing-key.sh)
#   --key-env VAR   read the private key PEM from environment variable VAR (CI secret); it is
#                   handed to openssl through a pipe and never written to disk
#   --manifest F    default: assets/manifest.json
#   --out / --sig   default: the manifest path plus .sig
#   --pub FILE      when signing: also check the key matches this public key
#
# Exit status: 0 signed or verified, 1 failed, 2 usage error.
# Test: tests/unit/test_manifest_signing.py
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
die() {
  printf 'sign-manifest: %s\n' "$1" >&2
  exit "${2:-1}"
}

mode=sign
key_file=""
key_env=""
manifest="$repo_root/assets/manifest.json"
sig=""
pub=""
while (($#)); do
  case "$1" in
    --verify)
      mode=verify
      shift
      ;;
    --key | --key-env | --manifest | --out | --sig | --pub)
      [[ $# -ge 2 && -n "$2" ]] || die "$1 needs a value" 2
      case "$1" in
        --key) key_file="$2" ;;
        --key-env) key_env="$2" ;;
        --manifest) manifest="$2" ;;
        --out | --sig) sig="$2" ;;
        --pub) pub="$2" ;;
      esac
      shift 2
      ;;
    -h | --help)
      sed -n '2,/^# Exit status/p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *) die "unknown option '$1'. Run scripts/sign-manifest.sh --help." 2 ;;
  esac
done
command -v openssl >/dev/null 2>&1 || die "openssl is missing. Install it (sudo apt-get install openssl)."
[[ -f "$manifest" ]] || die "$manifest does not exist. Run scripts/gen-manifest.py first."
sig="${sig:-$manifest.sig}"

verify() { # PUB
  openssl pkeyutl -verify -pubin -inkey "$1" -rawin -in "$manifest" -sigfile "$sig" >/dev/null 2>&1
}

if [[ "$mode" == verify ]]; then
  [[ -n "$pub" ]] || die "--verify needs --pub FILE (the public key)." 2
  [[ -f "$sig" ]] || die "$sig does not exist. Sign the manifest first."
  if verify "$pub"; then
    printf 'sign-manifest: %s verifies against %s\n' "$manifest" "$pub"
    exit 0
  fi
  die "the signature $sig does NOT verify for $manifest with $pub. Do not publish or use this manifest."
fi

if [[ -n "$key_env" ]]; then
  [[ "$key_env" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || die "--key-env needs a variable name" 2
  [[ -n "${!key_env:-}" ]] || die "environment variable $key_env is empty. Set the signing key secret."
  key_src() { printf '%s\n' "${!key_env}"; }
elif [[ -n "$key_file" ]]; then
  [[ -f "$key_file" ]] || die "$key_file does not exist."
  key_src() { cat -- "$key_file"; }
else
  die "pass --key FILE or --key-env VAR." 2
fi

tmp_sig="$(mktemp "$(dirname -- "$sig")/.manifest.sig.XXXXXX")"
tmp_pub="$(mktemp)"
trap 'rm -f -- "$tmp_sig" "$tmp_pub"' EXIT
openssl pkeyutl -sign -rawin -inkey <(key_src) -in "$manifest" -out "$tmp_sig" 2>/dev/null ||
  die "openssl could not sign $manifest. Check the key is an Ed25519 private key."
openssl pkey -in <(key_src) -pubout -out "$tmp_pub" 2>/dev/null ||
  die "openssl could not derive the public key from the signing key."
if [[ -n "$pub" ]] && ! cmp -s -- "$tmp_pub" "$pub"; then
  die "the signing key does not match the public key $pub. Use the key whose public half is baked into the image."
fi
sig_ok() { openssl pkeyutl -verify -pubin -inkey "$tmp_pub" -rawin -in "$manifest" -sigfile "$tmp_sig" >/dev/null 2>&1; }
sig_ok || die "the new signature does not verify; nothing written."
chmod 0644 -- "$tmp_sig"
mv -f -- "$tmp_sig" "$sig"
printf 'sign-manifest: wrote %s (sha256 of the manifest %s)\n' "$sig" "$(sha256sum -- "$manifest" | cut -d' ' -f1)"
