# Release process

How an AIRLOCK release is made, how often, and how a user checks one. Tasks 6.3, 2B.1, 2B.2,
2B.19. The workflow is [.github/workflows/release.yml](../.github/workflows/release.yml).

## Cadence (task 2B.19)

* **Monthly.** The base image is rebuilt on the 1st of each month (`build.yml` runs on a
  schedule) and a release is tagged from it when the month's checks are green. An air-gapped
  drive gets no security updates, so a regular rebuild is the only way parsers get fixes.
* **Out of band.** A security fix in a parser that reads evidence (The Sleuth Kit, libewf,
  Dissect, exiftool, ffmpeg, libyara, ClamAV, and the like) triggers a rebuild and a release
  within a week of the fixed package reaching the Ubuntu archive or its pin. Move
  `apt_snapshot` in `ansible/group_vars/all/main.yml` (and the tool's pin) forward first.
* **Every release reruns the validation suite** (Milestone 4F). The release workflow runs
  `validation/run.sh` and signs the validation report; a failed class blocks the release until it
  is fixed or recorded in [known-limitations.md](known-limitations.md).

## One-time setup (repository owner)

1. Make the manifest signing key on a trusted computer, outside the checkout:
   `scripts/gen-signing-key.sh --out-dir ~/airlock-keys`. Keep the private key offline as well.
2. In the repository settings, add the secret **`MANIFEST_SIGNING_KEY`** (the whole private key
   PEM) and the variable **`MANIFEST_SIGNING_PUBKEY`** (the whole public key PEM). The public key
   is built into every image at `/etc/airlock/manifest-signing.pub.pem`; changing it means older
   drives no longer accept new manifests.
3. Optional: set the variable **`AIRLOCK_BUILD_RUNS_ON`** to a self-hosted runner with KVM, for
   example `["self-hosted","linux","x64","kvm"]`, if the hosted runners are too slow (they fall
   back to emulation without KVM).
4. Until the licence review (task 6.6) is signed off, leave **`AIRLOCK_LICENCE_REVIEW_DONE`**
   unset: releases are then created as drafts that only maintainers can see. Set it to `true`
   once [licenses.md](licenses.md) has been reviewed, so releases are published.

## Making a release

1. Make sure `main` is green (lint, windows and build workflows) and every pin has a SHA-256:
   `python3 scripts/check-pins.py --strict`.
2. Set `airlock_version` in `ansible/group_vars/all/main.yml` to the new version (for example
   `0.1.0`), commit it through a pull request, and merge.
3. Tag the merge commit and push the tag: `git tag -s v0.1.0 -m "AIRLOCK v0.1.0"` then
   `git push origin v0.1.0`. The tag must be `v` plus `airlock_version`, or the workflow stops.
4. The release workflow then:
   1. checks the tag and runs `scripts/check-pins.py --strict`;
   2. writes `assets/manifest.json` for this tag and signs it with `scripts/sign-manifest.sh`
      (raw Ed25519; the key reaches openssl through a pipe and is never written to disk);
   3. builds the base image with `scripts/build.sh` (2B.1: Ubuntu 24.04 desktop, hardening
      applied, the roles at this tag, `forensic-provision`, every redistributable tool installed;
      no EZ Tools, model weights, NSRL, ClamAV or MalwareBazaar data, which users stage);
   4. boots it under UEFI, UEFI with Secure Boot, and BIOS with `tests/run-qemu-tests.sh`;
   5. writes an SPDX SBOM of the image's root filesystem with syft, and the licence record;
   6. splits the compressed image into 1900 MiB parts when it is larger than that (2B.2);
   7. reruns the validation suite and signs the validation report;
   8. writes `SHA256SUMS` over every file and signs it with cosign (keyless, tied to this
      workflow), then creates the GitHub Release.

Pins, actions, and tools the workflows download are pinned by SHA-256 (in `pins.yml`) or by
commit SHA (actions). Moving any of them is a pull request like any other change.

## What a release contains

| File | What it is |
|---|---|
| `airlock-<version>.raw.zst` or `airlock-<version>.raw.zst.part00`, `.part01`, ... | the compressed base image, whole or in parts |
| `SHA256SUMS` | SHA-256 of every file, plus the whole `.raw.zst` and the `.raw` inside it |
| `SHA256SUMS.sig`, `SHA256SUMS.pem`, `SHA256SUMS.sigstore.json` | cosign signature, certificate, and bundle for `SHA256SUMS` |
| `manifest.json`, `manifest.json.sig`, `manifest-signing.pub.pem` | the asset manifest the fetchers use, its Ed25519 signature, and the public key |
| `fetch-assets.ps1`, `fetch-assets.sh`, `fetch_assets.py` | the host-side fetchers |
| `airlock-<tag>.spdx.json` | SBOM of the image's root filesystem (syft, SPDX JSON) |
| `airlock-<tag>-licenses.md` | licence record: every pin and every package licence |
| `validation-report.md`, `.json`, `.sha256`, `.sha256.sig` | the signed validation report |

GitHub limits each release file to 2 GiB (verify the current limit before each release; it was
the documented limit when this was written). The workflow keeps every file under it by
splitting the image into 1900 MiB parts.

## Checking a release (users)

### 1. Put the image back together (only if it came in parts)

Linux or macOS, in the download folder:

```
cat airlock-<version>.raw.zst.part* > airlock-<version>.raw.zst
```

Windows PowerShell, in the download folder:

```powershell
$name  = 'airlock-<version>.raw.zst'
$parts = Get-ChildItem -Filter "$name.part*" | Sort-Object Name
$out   = [System.IO.File]::Create((Join-Path $PWD $name))
foreach ($p in $parts) { $in = [System.IO.File]::OpenRead($p.FullName); $in.CopyTo($out); $in.Close() }
$out.Close()
```

The parts sort in the right order by name (`part00`, `part01`, ...). Delete the parts afterwards.

### 2. Check the SHA-256

* Linux: `sha256sum -c --ignore-missing SHA256SUMS` must print `OK` for every file you have.
* Windows: `Get-FileHash .\airlock-<version>.raw.zst -Algorithm SHA256`, then compare the hash
  with the `airlock-<version>.raw.zst` line in `SHA256SUMS`. If they differ, download again; do
  not write the image.

### 3. Check that SHA256SUMS came from this project (optional, recommended)

With [cosign](https://docs.sigstore.dev/) installed:

```
cosign verify-blob SHA256SUMS --bundle SHA256SUMS.sigstore.json \
  --certificate-identity "https://github.com/<owner>/airlock/.github/workflows/release.yml@refs/tags/<tag>" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

Replace `<owner>` and `<tag>` with the repository owner and the release tag. `Verified OK` means
`SHA256SUMS` was signed by this repository's release workflow for that tag.

### 4. Check the asset manifest (the drive does this itself)

```
openssl pkeyutl -verify -pubin -inkey manifest-signing.pub.pem -rawin \
  -in manifest.json -sigfile manifest.json.sig
```

The drive checks the same signature against the key built into it, so a manifest copied onto
`ASSETS` by anyone else is refused.

## Version tags

A milestone's version is tagged only when its exit check in [build-plan.md](build-plan.md)
(section 2.9) holds, which includes its QEMU and CI checks. Tags so far: none.

| Tag | Gate |
|---|---|
| v0.1 (task 3.11) | Milestones 0 to 3A green in CI, including the QEMU boot and offline provisioning jobs |
| v0.2 (task 4.16) | Milestones 4 to 4G green, the validation report attached |
| v0.3 (task 5.9) | Milestone 5 controls pass in the emulator; lint, build and test run on every change |
| v0.4 (task 6.7) | a tagged release publishes a signed image, checksums, SBOM and licence record |
| v1.0 (task 7.5) | hardware matrix and outside review recorded, docs complete |
