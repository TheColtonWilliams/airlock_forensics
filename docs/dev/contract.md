# AIRLOCK developer contract

AIRLOCK: **A**ir-gapped, **I**solated, **R**ead-only, **L**ocked-down, **O**ffline **C**ase **K**it.

This file fixes the names, paths, formats, and interfaces that every part of the
repository shares. `docs/build-plan.md` says *what* to build; this file says
*how the parts fit*. If you need to change something here, change it here first
and record why in `docs/decision-log.md`.

## 1. Repository layout

```
airlock/
  make-usb.sh                      one-command Linux builder (Milestone 2A)
  packer/                          Packer template + autoinstall (Milestone 1)
  ansible/
    ansible.cfg
    site.yml                       every role, hardening re-applied last
    group_vars/all/main.yml        feature flags and tunables
    group_vars/all/pins.yml        every external download (section 5)
    group_vars/all/ai_models.yml   model tiers (references pins.yml keys)
    group_vars/all/profiles.yml    staging profiles (section 6)
    roles/<role>/                  one control per task file
    roles/session_tools/files/bin/     on-image commands (installed to /usr/local/bin)
    roles/session_tools/files/pylib/   on-image Python packages (installed to /opt/airlock/lib/python)
  scripts/                         host-side tools (build, flash, fetch, manifest, lint)
  tests/
    unit/                          pytest, runs anywhere (no root, no VM)
    functional/                    bash test_*.sh, run on a Linux host; may need root + loop devices
    goss/                          goss files, run inside the booted image
    vm/                            scripts run inside the QEMU guest by tests/run-qemu-tests.sh
    fixtures/                      scripts that build fixtures + small committed fixture images
  validation/                      validation suite (Milestone 4F)
  docs/                            user and developer docs
  .github/workflows/               lint.yml, build.yml, release.yml
```

Deviation from the plan's paths, recorded in the decision log: the plan writes
`forensic-analyze/x.py` and `evidence-report/x.py`. Python cannot import
hyphenated packages, so these live at
`ansible/roles/session_tools/files/pylib/forensic_analyze/x.py` and
`.../pylib/evidence_report/x.py`. Commands such as `forensic-provision` live in
`.../files/bin/`.

## 2. On-image paths

| Purpose | Path | Env override (tests) |
|---|---|---|
| Install prefix | `/opt/airlock` | `AIRLOCK_OPT_DIR` |
| Python packages | `/opt/airlock/lib/python` | (sys.path) |
| Repo copy used by provisioning | `/opt/airlock/repo` (ansible/, profiles) | `AIRLOCK_REPO_DIR` |
| Commands | `/usr/local/bin/<name>` | `PATH` |
| Config | `/etc/airlock/` (`airlock.conf.json`, `screen-thresholds.json`, `manifest-signing.pub.pem`, `build-info.json`) | `AIRLOCK_ETC_DIR` |
| State | `/var/lib/airlock/` (`provision/`, `applied-assets.json`, `manifest.json`) | `AIRLOCK_STATE_DIR` |
| Session logs | `/var/log/forensic-session/` | `AIRLOCK_SESSION_DIR` |
| ASSETS partition mount | `/srv/airlock/assets` (exFAT, `ro,noexec,nosuid,nodev`) | `AIRLOCK_ASSETS_DIR` |
| OUTPUT partition mount | `/srv/airlock/output` (exFAT, `rw,noexec,nosuid,nodev,uid=analyst`) | `AIRLOCK_OUTPUT_DIR` |
| Parser sandbox user | `airlock-parse` (system user, no login, no home) | |
| Operator account | `analyst` (locked password, autologin, passwordless sudo) | |

`airlock_common.paths` is the only place that reads these env vars. Every Python
module gets paths from there. Bash helpers use the same variable names with the
same defaults.

## 3. Drive layout (GPT)

| # | Name / label | Type | Size (default var) | Notes |
|---|---|---|---|---|
| 1 | `BIOSBOOT` | EF02 BIOS boot | 1 MiB | `grub-install --target=i386-pc` |
| 2 | `EFI` | EF00, FAT32 | 512 MiB (`esp_size_mib`) | `EFI/BOOT/BOOTX64.EFI`, shim + grub, `--removable --no-nvram` |
| 3 | `ASSETS` | 0700 (basic data), exFAT | 20 GiB (`assets_partition_gib`) | staged by host fetcher; empty in published image |
| 4 | `OUTPUT` | 0700 (basic data), exFAT | 8 GiB (`output_partition_gib`) | case output, readable on Windows |
| 5 | `AIRLOCK_ROOT` | 8300, ext4 | 14 GiB in the image (`root_image_gib`), grows on first boot | last, so `growpart` can extend it |

The published raw image is about 43 GiB uncompressed (sparse, compresses to a
few GiB), which leaves room for the 8 GB headroom check in `flash.sh` on a 64 GB
drive. fstab references partitions by UUID only. The boot disk is the disk that
holds `/`; every partition on it is exempt from the read-only udev rule.

## 4. Session log

* One file per session: `/var/log/forensic-session/<YYYYMMDDTHHMMSSZ>.log`,
  plus a symlink `current.log` pointing at it.
* `forensic-session-start` creates a new session. Any other helper appends to
  `current.log`; if none exists it creates one and logs `session_implicit`.
* One JSON object per line, sorted keys, UTF-8, `\n` line ends.
  Required keys: `ts` (UTC ISO 8601 with `Z`, microseconds), `event`
  (snake_case), `tool` (command name), `pid`. Other keys are event fields.
* Python: `airlock_common.sessionlog.log_event(tool, event, **fields)`.
  Bash: `airlock_log <tool> <event> [key=value ...]` from
  `/opt/airlock/lib/airlock-log.sh` (source:
  `ansible/roles/session_tools/files/lib/airlock-log.sh`), which calls the
  Python logger so escaping is correct.

## 5. Pins (`ansible/group_vars/all/pins.yml`)

Every file downloaded at build or staging time has one entry under `pins:`:

```yaml
pins:
  ubuntu_server_iso:            # key = stable asset id, snake_case
    url: https://releases.ubuntu.com/24.04/ubuntu-24.04.5-live-server-amd64.iso
    version: "24.04.5"
    sha256: "97f3...f5"          # 64 hex chars, or null = NOT YET PINNED
    size: null                  # bytes if known
    stage: build                # build | image | assets
    target: null                # for stage=assets: path under the ASSETS root
    profiles: [build]           # which profiles need it (section 6)
    verify: sha256              # sha256 | vendor_signature | trusted_at_staging
    license: "Ubuntu (various, redistributable)"
    notes: ""
```

* `stage: build`: fetched by `scripts/build.sh` / Packer on the build host.
* `stage: image`: fetched during the Packer build by an Ansible role and baked
  into the base image (redistributable only).
* `stage: assets`: never fetched by the image. Staged onto ASSETS by
  `scripts/fetch-assets.{sh,ps1}`, installed or used in place offline by
  `forensic-provision`.
* `sha256: null` means the hash could not be computed when the entry was
  written (host unreachable from the authoring environment). Fetchers and
  roles **refuse** null-hash files unless `verify` is `vendor_signature` or
  `trusted_at_staging`. `scripts/check-pins.py` lists them; the release
  workflow fails if any remain.
* Ansible roles fetch with `ansible.builtin.get_url` and
  `checksum: "sha256:{{ pins.<id>.sha256 }}"` and must fail when the hash is null.

## 6. Profiles, manifest, and staged assets

* Profiles live in `ansible/group_vars/all/profiles.yml` under `profiles:`.
  Each profile: `description`, `features` (booleans and lists, see below), and
  is resolved to asset ids by `scripts/gen-manifest.py`.
  Features: `ai_tiers` (list of `tier0`..`tier4`), `nsrl` (bool, default
  false: NSRL lives on the output drive), `autopsy`, `sift`, `malwarebazaar`,
  `clamav`, `yara`, `eztools`, `classifiers`, `whisper`, `nvidia_proprietary`.
  Profiles shipped: `default` (tier0..tier2, NSRL off), `minimal`
  (no AI, no NSRL), `full` (all tiers, NSRL on), `ci` (tiny, test-only assets).
* `scripts/gen-manifest.py` writes `assets/manifest.json`:
  `{"schema": 1, "release": "<git describe>", "files": [{"id", "url",
  "version", "size", "sha256", "target", "profiles", "verify", "license"}],
  "profiles": {"<name>": {"description", "features", "files": [ids]}}}`
  with sorted keys and files sorted by id.
* The release workflow signs it: `manifest.json.sig` is a raw Ed25519
  signature made with `openssl pkeyutl -sign -rawin`. The public key is
  baked into the image at `/etc/airlock/manifest-signing.pub.pem`; the trusted
  manifest is baked at `/var/lib/airlock/manifest.json`. A newer manifest
  found on ASSETS is accepted only if its signature verifies against the baked
  key (`openssl pkeyutl -verify -pubin -rawin`).
* ASSETS partition layout written by the fetchers:
  ```
  ASSETS/
    manifest.json  manifest.json.sig     (copied from the release the user fetched)
    profile.json                         (what the user chose, see below)
    files/<target>                       (target path from pins.yml)
  ```
* `profile.json`: `{"schema": 1, "profile": "default", "features": {...},
  "staged_at": "<UTC>", "fetcher": "fetch-assets.sh <version>",
  "files": [{"id", "sha256", "target", "verify", "staged_at"}],
  "skipped": [{"id", "reason"}],
  "case_defaults": {"examiner": "", "agency": "", "case_id_prefix": ""}}`.
  The abuse.ch key is **never** written to the drive.

## 7. Python rules (on-image code)

* Python 3.12 syntax (Ubuntu 24.04). Standard library only. Type hints.
  `ruff` clean with the repo's `pyproject.toml`.
* `subprocess` with argument lists only; never `shell=True`. Use
  `airlock_common.proc.run(argv, ...)`, which logs the command line.
* JSON written with `airlock_common.jsonio.dump_json` / `dumps_line` (sorted
  keys, UTF-8, `ensure_ascii=False`).
* Hashing via `airlock_common.hashing` (`hash_file(path, algos=("sha256","md5"))`,
  `hash_device(...)` reading in 4 MiB blocks with `O_RDONLY`).
* Device discovery via `airlock_common.devices` (`lsblk -J -b -O` parsing,
  `boot_disk()`, `is_readonly(dev)`).
* Prompts via `airlock_common.ui` (whiptail if present and stdin is a TTY,
  else plain `input()`); every prompt has a CLI flag and `--yes`.
* Evidence-derived text (filenames, document text, transcripts) is data. Never
  pass it through a shell, never format it into a model instruction outside
  the delimited data block of `evidence_report.inputs`.
* Every command exits non-zero on failure and prints one line saying what
  failed, then what to do next.

## 8. forensic-analyze module API

Defined in `pylib/forensic_analyze/api.py`. Summary:

```python
class Module:  # one per file in forensic_analyze/modules/
    name: str  # "inventory"; matches the file name
    title: str  # "File inventory"
    fs_types: frozenset[str] | None  # e.g. frozenset({"ntfs"}); None = any filesystem
    order: int  # fixed run order (lower first)

    def run(self, ctx: ModuleContext) -> ModuleResult: ...
```

`ModuleContext` gives a module: `run_id`, `target` (`Target`: `path` to a
read-only device or image, `kind` `device|image`, `sha256`, `volumes`
list of `Volume(index, offset_bytes, size_bytes, fs_type, label)`),
`workdir` (module scratch dir under the run folder), `options` (preset,
mode, thresholds, flags), `emit(row: dict) -> None` (validated against
`schema.json`; `run_id`, `evidence_id`, `evidence_sha256` filled in),
`tool(argv, *, sandbox=True, timeout=..., stdout_path=None) -> CompletedProcess`
(sandboxed, logged into `run.json` with tool version), `log(event, **fields)`,
and `tool_version(name) -> str`.

`ModuleResult(status: "ok"|"skipped"|"failed", reason: str = "", counts: dict)`.

Modules emit rows **in a deterministic order** (sort before emitting). Rows go
to `<run>/modules/<name>/findings.part.jsonl`. When every module is done the
runner merges the parts in module `order`, assigns `finding_id` `F-000001`
onwards, and writes `findings.jsonl`. A `<run>/modules/<name>/.done` marker
makes a module skip on resume.

## 9. Run folder (on OUTPUT or the chosen output drive)

```
<output>/cases/<case_id>/<run_id>/       run_id = R-<YYYYMMDDTHHMMSSZ>-<6 hex>
  run.json            replayable config + results (sorted keys)
  findings.jsonl      system of record
  findings.csv        flat export (4D.6, 4D.7)
  case.sqlite         views (4D.5)
  report.html report.md
  modules/<name>/     intermediates, raw tool output, findings.part.jsonl
  logs/               per-run JSON-lines log
  outputs.sha256      sha256sum-format list of every file above
  outputs.sha256.sig  signature with the per-OUTPUT signing key
```

## 10. Tests

* `tests/run-unit.sh`: pytest over `tests/unit` with `pylib` and `scripts` on
  `sys.path`.
* `tests/run-functional.sh`: runs every `tests/functional/test_*.sh`. Each
  test sources `tests/functional/lib.sh`, exits 0 pass, 1 fail, 77 skip (with
  one line saying which prerequisite is missing: root, loop devices,
  a tool, a VM).
* Tests that need the booted image live in `tests/vm/` and are run inside the
  guest by `tests/run-qemu-tests.sh` (goss files from `tests/goss/` too).
* No sexual, violent, or otherwise sensitive media anywhere in the repo.
  Image fixtures are generated shapes and text.

## 11. Lint

`scripts/lint.sh` runs everything available: shellcheck (every file with a
bash shebang), yamllint, ansible-lint (production profile), ruff, `packer fmt
-check` + `packer validate -syntax-only`, PSScriptAnalyzer when `pwsh` has it,
`scripts/check-pins.py`. CI runs the same script.

## 12. Wording rules (from the build plan's hard rules)

* The software read-only layer is the "software read-only policy", never a
  "write blocker".
* AI output is labelled "AI-generated", carries model and prompt SHA-256, and
  is triage, never evidence.
* Reports say "account SID", never a person's name.
* No automated age or child detection, anywhere.
