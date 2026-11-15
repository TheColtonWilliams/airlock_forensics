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
| Config | `/etc/airlock/` (`airlock.conf.json`, `screen-thresholds.json`, `hashsets.json`, `manifest-signing.pub.pem`, `build-info.json`) | `AIRLOCK_ETC_DIR` |
| Hash-set config | `/etc/airlock/hashsets.json` (written by the `tools_hashsets` role; read by `airlock_hashsets.config`: `clamav_dir`, `nsrl_dirs`, `yara_dir`, `ssdeep_dir`, limits) | `AIRLOCK_ETC_DIR` |
| State | `/var/lib/airlock/` (`provision/`, `applied-assets.json`, `provision-manifest.json`, `manifest.json`) | `AIRLOCK_STATE_DIR` |
| Runtime state (tmpfs) | `/run/airlock/` (`rw-allow/<disk kernel name>` markers, section 8a) | `AIRLOCK_RUN_DIR` |
| Base-image helpers | `/opt/airlock/libexec/` (`airlock-firstboot`, `airlock-partition-layout`, `airlock-install-bootloader`, `airlock-check-boot-chain`; role `base`) | |
| Session logs | `/var/log/forensic-session/` | `AIRLOCK_SESSION_DIR` |
| ASSETS partition mount | `/srv/airlock/assets` (exFAT, `ro,noexec,nosuid,nodev`) | `AIRLOCK_ASSETS_DIR` |
| OUTPUT partition mount | `/srv/airlock/output` (exFAT, `rw,noexec,nosuid,nodev,uid=analyst`) | `AIRLOCK_OUTPUT_DIR` |
| Parser sandbox user | `airlock-parse` (system user, no login, no home) | |
| Operator account | `analyst` (locked password, autologin, passwordless sudo) | |

`airlock_common.paths` is the only place that reads these env vars. Every Python
module gets paths from there (`opt_dir()`, `repo_dir()`, `etc_dir()`, `state_dir()`,
`session_dir()`, `assets_dir()`, `output_dir()`, `run_dir()`, `rw_allow_dir()` =
`run_dir() / "rw-allow"`). Bash helpers use the same variable names with the
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
  Python logger so escaping is correct. The library runs
  `python3 -m airlock_common.sessionlog` with `${AIRLOCK_PYLIB:-${AIRLOCK_OPT_DIR:-/opt/airlock}/lib/python}`
  on `PYTHONPATH`.
* Bash helpers find the library in this order (as `airlock-setro` does): `AIRLOCK_LOG_LIB`
  (full path of `airlock-log.sh`; tests set it to the repo copy), then
  `${AIRLOCK_PYLIB%/python}/airlock-log.sh` when `AIRLOCK_PYLIB` is set, then
  `${AIRLOCK_OPT_DIR:-/opt/airlock}/lib/airlock-log.sh`. The first readable one wins. On the
  image the second and third are the same file. In the repository layout the second does not
  resolve (`AIRLOCK_PYLIB` is `.../files/pylib`, the library is `.../files/lib/airlock-log.sh`),
  so tests set `AIRLOCK_LOG_LIB`. If none is readable (early boot), the helper writes to the
  system journal (`logger`) instead.

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
`tool(argv, *, sandbox=True, timeout=None, stdout_path=None, memory_bytes=None,
extra_ro=(), redact=(), devices=()) -> CompletedProcess` (text output; logged into
`run.json` with tool version; does not raise on a non-zero exit, raises
`airlock_common.proc.ToolError` only when the tool is missing or breaks its time limit),
`log(event, **fields)`, and `tool_version(name) -> str`.

Sandboxed tools run with no network (not even loopback), the run folder read-only, only
`modules/<name>/` writable (create any sub-folder a tool writes into with
`extract.tool_dir(ctx, path)`), and `target.path` a kernel read-only loop device. `devices`
adds device nodes for one call only (a GPU render node). A module that talks to the local
`llama-server` passes `sandbox=False` for that call.

Module conventions the runner relies on: exported copies go in `modules/<name>/export/`
(or `exports/`, `carved/`), NTFS system files in `<run>/extract/` (the purge option removes
exactly these); a module that used a model calls `ctx.log("model_used", model_id=...,
model_sha256=..., prompt_sha256=..., threshold=...)`, which the runner copies into
`run.json` `models`. Rows with `derivation: ai_generated` must carry `model_sha256` and
`prompt_sha256`. Required strings are never empty (use `"unknown"`); `source_record` is a
path relative to the run folder with an optional `#locator`.

`ModuleResult(status: "ok"|"skipped"|"failed", reason: str = "", counts: dict)`.

Modules emit rows **in a deterministic order** (sort before emitting). Rows go
to `<run>/modules/<name>/findings.part.jsonl`. When every module is done the
runner merges the parts in module `order`, assigns `finding_id` `F-000001`
onwards, and writes `findings.jsonl`. A `<run>/modules/<name>/.done` marker
makes a module skip on resume.

## 8a. Cross-package interfaces (fixed; implement exactly these names)

* **Command wrappers** (`files/bin/<cmd>` written in Python):
  ```python
  #!/usr/bin/python3
  import os, sys

  sys.path.insert(0, os.environ.get("AIRLOCK_PYLIB", "/opt/airlock/lib/python"))
  from forensic_analyze.cli import main

  raise SystemExit(main())
  ```
  Bash commands find `airlock-log.sh` in the order given in section 4 (`AIRLOCK_LOG_LIB`, then
  `${AIRLOCK_PYLIB%/python}/airlock-log.sh`, then `${AIRLOCK_OPT_DIR:-/opt/airlock}/lib/airlock-log.sh`).
  Tests set `AIRLOCK_PYLIB` to the repo's `pylib` and `AIRLOCK_LOG_LIB` to the repo's
  `files/lib/airlock-log.sh`, because `${AIRLOCK_PYLIB%/python}` does not reach it in the
  repository layout.
* **Installation**: the `session_tools` role copies *everything* in `files/bin/` to
  `/usr/local/bin/` (mode 0755), `files/pylib/` to `/opt/airlock/lib/python/` (0644),
  everything in `files/etc/` to `/etc/airlock/` (0644, root-owned; for example
  `screen-thresholds.json`), and `files/lib/airlock-log.sh` to `/opt/airlock/lib/` (0644).
  Other packages only drop files there; they do not edit the role. Desktop launchers in
  `files/desktop/` (`airlock-session-start.desktop`, `airlock-forensic-analyze.desktop`) go to
  `/usr/share/applications/` (0644) from a list in `tasks/desktop_launchers.yml`; a new launcher
  is added to that list. `airlock-session-start.desktop` is also the analyst's login autostart
  entry.
* **Devices**: `airlock_common.devices` (`lsblk()`, `boot_disk()`,
  `attached_disks()`, `is_readonly()`; `AIRLOCK_LSBLK_JSON` fixture override).
* **Read-only policy and output unlock**: `airlock-setro` (harden_storage role, run by the
  udev rule with the kernel name, and `--all` / `--check`) sets every `sd*`, `nvme*`,
  `mmcblk*`, `vd*` device read-only except the disk holding `/`, and leaves alone a device
  whose own kernel name or whose whole disk's kernel name has a file in
  `$AIRLOCK_RUN_DIR/rw-allow/` (default `/run/airlock/rw-allow/`). `evidence-unlock-output`
  creates `rw-allow/<kernel name of the whole disk>` (for example `sdc`) before
  `blockdev --setrw`, removes it again if the drive stays read-only, and `--lock` removes it
  before `blockdev --setro`. The markers are in tmpfs, so a reboot re-locks every drive.
  Python reaches the folder through `airlock_common.paths.rw_allow_dir()`.
* **Evidence mount**: `evidence-mount` attaches one kernel read-only loop device per filesystem
  (`losetup --read-only --find --show`, plus `--offset`/`--sizelimit` for a partition; offsets from `sfdisk -J`,
  filesystem type from `blkid -p`), never `losetup -r -P` (partition scanning depends on udev
  and the kernel; decision log). The loop device exposes only the filesystem being mounted.
* **Assets** (`airlock_common/assets.py`, owned by the assets package):
  `load_manifest() -> dict` (baked, or a newer signed one from ASSETS),
  `load_manifest_info() -> ManifestInfo` (`manifest`, `source` `"baked"|"assets"`, `path`,
  `sha256`, `release`, `notes: list[tuple[str, str]]`; raises `AssetError` when there is no
  trusted manifest),
  `verify_signature(manifest_path, sig_path, pubkey_path) -> bool`,
  `verify_staged(*, deep: bool = True, for_apply: bool = False) -> AssetReport` where
  `AssetReport` has `ok: bool`, `checked: list[str]`, `problems: list[tuple[str, str]]` (asset
  id, reason), `disabled_features: list[str]`, `deep`, `profile`, `features`,
  `manifest_source`, `manifest_release`, `manifest_sha256`, `verified` (asset id to the record
  that was checked), `to_dict()` and `summary()`. `deep=False` checks presence and size only.
  Daily-changing files (`verify: vendor_signature | trusted_at_staging`) are checked against the
  hash recorded at the last apply in `/var/lib/airlock/applied-assets.json`; `for_apply=True`
  (provisioning and import) checks them against the hash in `profile.json` instead.
  `asset_path(asset_id) -> Path | None` returns the on-ASSETS path of an applied file (cheap
  size check against `applied-assets.json`).
  `log_report(report, tool) -> None` writes one `assets_verified` session-log event with every
  checked file's SHA-256. The variables provisioning passes to the roles are listed in
  `docs/assets.md`.
* **Findings** (`forensic_analyze/findings.py`, owned by the findings package):
  `FindingsWriter(part_path, *, run_id, evidence_id, evidence_sha256, module)` with
  `.emit(row: dict) -> None` (validates with `validate_row`, raises `SchemaError`),
  `.count`, `.close()`; `validate_row(row, *, part=False) -> list[str]` (error strings;
  `part=True` checks a part-file row, which has no `finding_id`);
  `merge_parts(run_dir, module_order) -> Path` (writes `findings.jsonl`, assigns
  `finding_id` F-000001.. in module order, returns its path; byte-deterministic).
  `merge(run_dir, module_order) -> MergeResult(path, sha256, count, per_module)` does the
  same and returns the file hash for `run.json`. `finding_id` matches `^F-[0-9]{6,}$`.
  Schema file: `forensic_analyze/schema.json` (JSON Schema draft 2020-12 subset, checked by
  the stdlib validator in `findings.py`).
* **Exports**: `export_sqlite.build(run_dir) -> Path` (`case.sqlite`, table
  `findings` with one column per schema field, views `v_timeline`, `v_deleted`,
  `v_recycle_bin`, `v_media`, `v_hash_hits`, `v_flags`, `v_disagreements`);
  `export_csv.build(run_dir) -> Path`; `export_bodyfile.build(run_dir) -> Path`.
* **Module registry** (`forensic_analyze/modules/__init__.py`, owned by the core package):
  `all_modules() -> list[Module]` imports every `modules/*.py` that defines `MODULE`,
  sorted by `order`. Module names and orders: `inventory` 10, `recycle_bin` 20,
  `deletion_history` 30, `users` 40, `malware` 50, `images` 60, `video` 70,
  `audio` 80, `documents` 90, `timeline` 100, `carve` 110.
* **Presets** (`forensic_analyze/presets.py`): `quick` = inventory, recycle_bin,
  deletion_history, malware; `standard` = quick + users, images, video, audio,
  documents, timeline; `full` = standard + carve; `custom` = a checklist.
* **NTFS extraction helpers** (`forensic_analyze/extract.py`, owned by the NTFS
  modules package): `extract_system_file(ctx, volume, name) -> Path` for `$MFT`,
  `$UsnJrnl:$J`, `$LogFile`, `$Secure:$SDS` (cached under `<run>/extract/v<index>/`);
  `export_file(ctx, volume, inode, dest_dir) -> Path` (icat, read-only).
* **Inventory index**: the `inventory` module writes
  `<run>/modules/inventory/files.jsonl`, one sorted line per file:
  `{"volume_index", "inode", "path", "size_bytes", "allocated", "deleted",
  "mtime", "atime", "ctime", "crtime"}`. Media, malware, and users modules read
  it through `forensic_analyze.inventory_index.iter_files(run_dir, *, extensions=None)`.
* **AI helpers** (`pylib/airlock_ai/`, owned by the AI package): `probe.choose_tier()`,
  `screen.screen_paths(paths, out_csv, thresholds) -> list[ScreenResult]`,
  `describe.describe_paths(paths, out_csv, tier) -> list[DescribeResult]`. The
  CLI commands `ai-probe`, `evidence-screen`, `evidence-describe` wrap them.
* **Hash triage** (`pylib/airlock_hashsets/`, owned by the hash-set package):
  `triage.triage_paths(paths, out_csv) -> list[TriageResult]`, wrapped by
  `evidence-triage-hash`. Applied sets are found through `/etc/airlock/hashsets.json`
  (`airlock_hashsets.config`). In `findings.jsonl` the `malware` module writes hits
  (`artifact_type` `hash_hit`, `clamav_hit`, `yara_hit`) with category `malware`, and
  `nsrl_known_good` (known software, not "safe"), `hashset_status` (one per applied set) and
  `hash_triage_error` (a file that could not be checked) with category `hash`. The
  `v_hash_hits` view holds both categories.
* **Report** (`pylib/evidence_report/`, owned by the report package):
  `render.build(run_dir, *, use_model: bool) -> tuple[Path, Path]` (html, md),
  wrapped by `evidence-report RUN_DIR`. The runner calls it with no other flags before
  signing, so both files are in `outputs.sha256`.
* **Escalation** (`airlock_ai/escalate.py`, `forensic-escalate`): writes
  `<run>/ESCALATED`, then stops the process named in `<run>/forensic-analyze.pid`. The runner
  writes that pid file when it starts and removes it when it ends (it is never hashed),
  checks for `ESCALATED` before every module and before merging, and stops with status
  `escalated` without merging, exporting or signing. An escalated run cannot be resumed.

## 9. Run folder (on OUTPUT or the chosen output drive)

```
<output>/cases/<case_id>/<run_id>/       run_id = R-<YYYYMMDDTHHMMSSZ>-<6 hex>
  run.json            replayable config + results (sorted keys)
  findings.jsonl      system of record
  findings.csv        flat export (4D.6, 4D.7)
  findings.bodyfile   TSK 3.x bodyfile for mactime (4D.10)
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
  Interface inside the guest:
  * Each `tests/vm/*.sh` runs as root and exits 0 pass, 77 skip (last output line says why),
    anything else fail. It gets `AIRLOCK_TEST_DIR` (the copied test folder),
    `AIRLOCK_TEST_FIRMWARE` (`uefi`, `uefi-sb` or `bios`), `AIRLOCK_TEST_NIC` (`1` when a
    restricted network card is attached, else `0`), `AIRLOCK_TEST_DISK_EXT4`,
    `AIRLOCK_TEST_DISK_SWAP`, `AIRLOCK_TEST_DISK_SIG`, `AIRLOCK_TEST_DISK_NTFS`
    (`/dev/disk/by-id/virtio-airlock-<ext4|swap|sig|ntfs>`, or empty when that disk is not
    attached) and `AIRLOCK_SIGDISK_SHA256` (the host's SHA-256 of the LVM/mdraid/swap
    signature disk before boot).
  * goss runs with `--vars-inline` `{"disks": {"ext4", "ntfs", "sig", "swap"}, "firmware",
    "nic", "provision": false}`. `forensic-provision`'s self-test runs the same files with
    `"provision": true` and empty `disks`, so checks that need test disks or a running desktop
    are wrapped in `{{ if not (index .Vars "provision") }}`.
  * Base-image helpers the tests may call are in `/opt/airlock/libexec` (section 2).
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
