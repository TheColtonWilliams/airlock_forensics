# Assets: pins, manifest, staging, and offline provisioning

The AIRLOCK drive never goes online. Everything it needs that is not in the base image (models,
hash sets, signature databases, EZ Tools, optional drivers) is downloaded on the host computer
and copied onto the drive's `ASSETS` partition. The drive checks every file against a signed
list before it uses it. Formats: `docs/dev/contract.md` sections 5 and 6.

```
pins.yml + profiles.yml + ai_models.yml
   │ scripts/gen-manifest.py            (2B.10)
   ▼
assets/manifest.json ──scripts/sign-manifest.sh──▶ manifest.json.sig   (2B.15, release workflow)
   │ scripts/fetch-assets.sh / fetch-assets.ps1   (2B.11; host computer, online)
   ▼
ASSETS/ manifest.json(.sig)  profile.json  files/<target>
   │ forensic-provision (first boot, 2B.4-2B.6, 2B.12)  │ forensic-import (refresh, 4A.7)
   ▼                                                    ▼
/var/lib/airlock/applied-assets.json, provision-manifest.json; session start re-checks (2B.14)
```

## Pins and profile tags

Every download has one entry in `ansible/group_vars/all/pins.yml` with all ten fields
(`url`, `version`, `sha256`, `size`, `stage`, `target`, `profiles`, `verify`, `license`,
`notes`). `scripts/check-pins.py` checks each field (https URL, stage and verify values, a safe
relative `target` for `stage: assets`, 64-hex or null hash, a note when the hash is null) and
lists the pins not pinned yet. `scripts/lint.sh` runs it; the release workflow runs it with
`--strict`, which fails while any `sha256: null` + `verify: sha256` entry remains.

The `profiles` list of a pin holds tags. A staging profile pulls in a pin when one tag matches:

| Tag | Pulled in by |
|---|---|
| a profile name (`default`, `full`, `ci`, ...) | that profile |
| `all` | every profile |
| `ai_tier0` .. `ai_tier4` | profiles whose `ai_tiers` list the tier (models listed under a tier in `ai_models.yml` get the tag automatically) |
| `clamav`, `malwarebazaar`, `nsrl`, `yara`, `eztools`, `classifiers`, `whisper`, `autopsy`, `sift`, `nvidia_proprietary` | profiles with that feature `true` |
| `build`, `image` | no profile: build host or Packer build only |

So the NVIDIA proprietary packages (task 4B.15) are staged only when a profile sets
`nvidia_proprietary: true`, which no shipped profile does. The same feature tags name what the
drive turns off when a file is missing or damaged.

`verify` says how a file is trusted: `sha256` (pinned hash; refused while null),
`vendor_signature` (changes daily and carries its vendor's signature, such as ClamAV `.cvd`;
`sigtool` checks it on the drive when installed) or `trusted_at_staging` (changes daily, no
vendor signature, such as the MalwareBazaar export). For the last two the fetcher records the
hash it saw in `profile.json`; the drive checks that hash at provisioning and then checks the
file against the hash it recorded when it applied it.

## Manifest and signature

* `python3 scripts/gen-manifest.py` writes `assets/manifest.json` (gitignored): every pin, plus
  each profile's resolved file list. Sorted keys, files sorted by id, deterministic for a given
  release string (`--release`, default `git describe`). `--check` fails when the file is out
  of date. Host dependency: PyYAML (`python3-yaml`).
* `scripts/gen-signing-key.sh --out-dir DIR` makes the Ed25519 key pair once. It refuses a
  folder inside the repository. The private key goes into the release workflow's
  `MANIFEST_SIGNING_KEY` secret; the public key is baked in at
  `/etc/airlock/manifest-signing.pub.pem`.
* `scripts/sign-manifest.sh --key-env MANIFEST_SIGNING_KEY --pub PUB` signs (raw Ed25519,
  `openssl pkeyutl -sign -rawin`) and checks the new signature before writing it;
  `--verify --pub PUB` checks one.

## Fetchers (host computer)

Linux: `scripts/fetch-assets.sh`. Windows: `scripts\fetch-assets.ps1` (PowerShell 5.1 or 7).
They behave the same and write the same `profile.json`.

| bash | PowerShell | Meaning |
|---|---|---|
| `--profile NAME\|FILE` | `-Profile` | profile from the manifest, or a profile file (JSON; the bash fetcher also reads YAML) with `features` and optionally `files`; asked when missing, default `default` |
| `--manifest FILE` | `-Manifest` | release `manifest.json` (its `.sig` is copied too) |
| `--target-volume DEV\|DIR` (`--assets DIR`) | `-TargetVolume E:` | the ASSETS partition. Default: the one partition labelled `ASSETS` (Linux mounts it itself when run with sudo; Windows uses `Get-Volume`) |
| `--cache DIR` | `-Cache` | download cache (default `~/.cache/airlock/assets`, `%LOCALAPPDATA%\airlock\assets-cache`) |
| `--refresh` | `-Refresh` | download the daily-changing sets again; pinned files that changed in a newer manifest are restaged either way |
| `--abuse-key-file F` | `-AbuseKeyFile` | abuse.ch Auth-Key file; also `AIRLOCK_ABUSECH_KEY` or a hidden prompt |
| `--yes` | `-Yes` | ask nothing |
| `--examiner`, `--agency`, `--case-prefix` | same | `case_defaults` in `profile.json` |
| `--dry-run` | `-DryRun` | plan and space check only |

What they do, in order: read the manifest and profile; refuse unpinned files (listed under
`skipped` with the reason); check what is already on ASSETS by SHA-256 and keep it; report the
free space on ASSETS and in the cache and refuse when either is too small; remove files of an
earlier profile that this profile no longer needs; download into the cache (resuming a cut
download with an HTTP `Range` request from `<cache>/partial/<id>.part`; daily files resume only
with an `If-Range` validator); check the SHA-256; copy onto ASSETS through a temporary file and
read it back to check the SHA-256 again; copy `manifest.json` and `manifest.json.sig`; write
`profile.json` last, atomically. They write nothing outside ASSETS and the cache. A directory
target must be labelled `ASSETS`, already hold `profile.json`, or be empty.

Cache layout: `blobs/<sha256>` (checked files), `partial/<id>.part` (+ `.part.json`: URL, ETag),
`moving/<id>.json` (the last copy of a daily file). Rerunning the same command resumes.

The abuse.ch key: read from the environment variable (removed from the process environment at
once), a key file, or a hidden prompt; sent only as the `Auth-Key` header of files tagged
`malwarebazaar`, never across a redirect (urllib unredirected header; manual redirects in
PowerShell), never logged or written. Without a key the MalwareBazaar file is skipped (an
earlier staged copy is kept). `make-usb.sh` passes it the same way (decision log).

Exit status: 0 staged, 1 a file failed or the target was refused (rerun to resume), 2 usage
error or not enough space.

## On the drive

### Trust and checks: `airlock_common.assets`

* `load_manifest()`: the manifest baked at `/var/lib/airlock/manifest.json`, or a manifest on
  ASSETS when its signature verifies against the baked public key and it is not an older
  release. A newer signed manifest that provisioning or import applied replaces the baked one
  (the old one is kept as `manifest.json.previous`).
* `verify_staged(deep=True)`: every file named in `profile.json` (and every file the manifest's
  profile of that name lists) is checked against the trusted manifest: present, target as in
  the manifest, size, and (deep) SHA-256. Pinned files use the manifest's hash, so editing
  `profile.json` cannot hide a swap. Daily files use the hash recorded in
  `applied-assets.json`; a restaged daily file is reported until `forensic-import` applies it.
  Problems are `(asset id, reason)` pairs; `disabled_features` lists the features they serve.
  `for_apply=True` (provisioning and import) checks daily files against `profile.json`.
* `asset_path(id)`: the ASSETS path of an applied file (cheap size check), or `None`.
* `log_report(report, tool)`: event `assets_verified` in the session log with every file's
  SHA-256. `forensic-session-start` runs `verify_staged()` and `log_report()` at every boot
  (task 2B.14); bash can use `python3 -m airlock_common.assets verify --log-tool TOOL`.

### `forensic-provision`

Runs unattended from `airlock-provision.service` (`forensic-provision --if-changed`, ordered
before the display manager; skip it with `airlock.noprovision` on the kernel command line).
It refuses to start while a non-loopback interface is up, a default route exists (IPv4 or
IPv6), any disk other than the boot drive is attached, or it is not root. Steps, each
checkpointed in `/var/lib/airlock/provision/steps/<step>.json` so a power cut resumes at the
first unfinished step:

1. `verify`: `verify_staged(deep=True, for_apply=True)`; writes the Ansible variables
   (`provision/vars.json`, mode 0600).
2. `ansible`: `ansible-playbook -c local -i /opt/airlock/repo/ansible/inventory.ini
   /opt/airlock/repo/ansible/site.yml -e airlock_phase=provision -e @vars.json` (log in
   `provision/ansible-<run>.log`). The inventory file is used instead of `-i localhost,`
   because `site.yml` targets the `airlock` group.
3. `record`: `applied-assets.json` (files with hash, size, target; features in effect;
   problems); `asset_applied` / `asset_removed` session-log events with old and new SHA-256.
4. `goss`: every `/opt/airlock/repo/tests/goss/*.yaml` with `--vars-inline
   {"provision": true, "firmware": ..., "nic": ..., "disks": {}}`.
5. `manifest`: `/var/lib/airlock/provision-manifest.json` (status, tool versions, asset and
   model hashes, hardware capacities, kernel, date, test results), the same in the session log,
   and a plain report in `provision/report.txt` and on OUTPUT as
   `airlock-provision-report.txt`. Then it reboots (`--no-reboot` for tests).

Missing or damaged files never stop provisioning: they are named, the features that need them
are turned off for the roles and in the report, and the fix is to rerun the fetcher on the host
computer. With `--if-changed` it does nothing unless the drive was never provisioned, a run was
cut short, `profile.json` changed since it was applied, or a newer signed manifest is on
ASSETS; a changed set is applied without a reboot (task 2B.7).

Provisioning variables passed to the roles (`runner.build_vars`, as `-e @vars.json`):

| Variable | Meaning |
|---|---|
| `airlock_phase` | `provision` |
| `airlock_profile` | profile name from `profile.json` when it is a plain name (letters, digits, `_.-`, at most 64 characters), otherwise empty |
| `airlock_features`, `airlock_profile_features` | the profile's features after the schema check below, with every disabled one turned off (two names, one value; the tool roles read the second) |
| `airlock_disabled_features` | e.g. `[ai_tier1, clamav]` |
| `airlock_assets` | `{id: {path, sha256, size, target, verify, version}}`, verified files only |
| `install_autopsy` | true only when `airlock_features.autopsy` is true |

`profile.json` is not signed and ASSETS can be written from any computer, while Ansible
templates every string it is given. So the features are rebuilt from a fixed schema before
they are passed: each feature (`autopsy`, `classifiers`, `clamav`, `eztools`, `malwarebazaar`,
`nsrl`, `nvidia_proprietary`, `sift`, `whisper`, `yara`) must be JSON `true` or `false`, and any
other value turns it off and is reported; `ai_tiers` keeps only known tier names (`tier0` to
`tier4`); keys outside the schema are dropped. A `profile.json` holding template markup
(`{{`, `{%` or `{#`, in any key or value) refuses provisioning, and `build_vars` refuses
again if any string it would pass holds one. Free text is not passed: forensic-analyze reads
`case_defaults` from `profile.json` as data, and the asset problems are in the step results
and the provisioning report. No role reads `profile.json` itself
(`tests/unit/test_offline_phase.py`), and a feature turns on only for a real `true`.

### `forensic-import`

`sudo forensic-import` applies files restaged with `fetch-assets --refresh`: the same refusal
checks (no evidence disk, no network), then verify, Ansible, record, with every file's old and
new SHA-256 in the session log. `--dry-run` lists new, changed, and dropped files and changes
nothing. It does nothing when the verified set is already applied (`--force` reapplies).
Operating system and tool updates come by reflashing a newer base image.

## Tests

* `tests/unit/test_manifest.py`, `test_manifest_signing.py`: check-pins, gen-manifest,
  signing scripts.
* `tests/unit/test_assets.py`, `test_assets_fetch.py`: the drive-side checks and the fetcher
  core.
* `tests/unit/test_provision.py`, `test_provision_unit.py`: refusal checks, steps, resume,
  change detection, import, the boot unit.
* `tests/functional/test_fetch_assets.sh`: both fetchers against a local HTTPS server
  (resume, key handling, refusal, refresh, NVIDIA tag, exFAT loop device).
* `tests/functional/test_assets.sh` (4G.4): tamper cases at provisioning and session start.
* `tests/functional/test_refresh.sh` (4G.16): newer signed set and changed profile applied
  offline by `forensic-import` and the boot unit.

Test-only overrides: `AIRLOCK_SYSFS_DIR` and `AIRLOCK_PROC_DIR` (network and hardware reads),
`AIRLOCK_LSBLK_JSON` (disks), `AIRLOCK_ALLOW_NONROOT=1`, `AIRLOCK_FETCH_TIMEOUT` (seconds).
