# CLAUDE.md

AIRLOCK (Air-gapped, Isolated, Read-only, Locked-down, Offline Case Kit) builds a bootable
forensic USB workstation as code: Ubuntu 24.04, Packer + Ansible, goss tests, a host-side asset
fetcher, a guided analysis wizard (`forensic-analyze`), a findings store, local AI triage and an
LLM-drafted report. Licence: Apache-2.0.

## Read these first

| File | What it is |
|---|---|
| `docs/build-plan.md` | The plan: 215 tasks by milestone, each with a Status cell and note lines. Part 2 has the working rules (2.1), definition of done (2.2), hard rules (2.3), style (2.4), open decisions (2.6) and tasks that need a person (2.7). Part 4 is the original 2026-11-10 decision seed; it is frozen. |
| `docs/dev/contract.md` | **Binding** cross-package contract: repo layout, on-image paths and env overrides, drive layout, session log, `pins.yml` format, manifest and profiles, Python rules, module API, run folder, tests, lint, wording. Code must match it. To change an interface, change the contract first, in the same commit, with a decision-log row saying why. |
| `docs/decision-log.md` | The live decision log (seeded from plan Part 4). Add new rows at the end of the table, in the same commit as any design change or new dependency. |
| `docs/known-limitations.md` | Accepted gaps. A defect counts as accepted only if it is recorded here or in the decision log. |
| `docs/licenses.md` | Licence of every installed, downloaded or called component, and where each may live (a test enforces coverage). |
| `docs/threat-model.md`, `docs/controls.md` | Threats, and the control that answers each one with its test. |

Note: plan 2.2 and task 4B.4 still say `ansible/group_vars/pins.yml` and
`ansible/group_vars/ai_models.yml`. The real files are under `ansible/group_vars/all/`
(decision log; contract section 5). Files directly in `group_vars/` would be ignored.

## Hard rules (build plan 2.3)

1. The built system never uses a network. No task may add a download, update check or listener to the running USB system. Downloads belong to the build (`scripts/build.sh`) or the host fetcher (`scripts/fetch-assets.*`). At `airlock_phase=provision` roles work offline only (`tests/unit/test_offline_phase.py` enforces this).
2. Nothing writes to an evidence device. Analysis code opens targets read-only (kernel read-only loop devices via `losetup --read-only`; E01 files bound read-only) and never mounts them. `evidence-mount` is a separate, manual, read-only convenience (surviving risk 2).
3. No dependence on a hardware vendor or model. Capacities only. Hardware vendors may be named only as test coverage (4B.13) or for an off-by-default add-on (4B.15).
4. No secrets in the repository. Keys and tokens come from prompts, env vars, key files or CI secrets. The abuse.ch key comes only from `AIRLOCK_ABUSECH_KEY`, `--abuse-key-file` (`-AbuseKeyFile`) or a hidden prompt, is sent only as the `Auth-Key` header for the MalwareBazaar download, and is never written to the drive, `profile.json`, logs or the repo.
5. No sexual, violent or otherwise sensitive media in the repository, including fixtures. Generate neutral shapes, text and tones.
6. No automated age or child detection.
7. AIRLOCK's own layer is the **"software read-only policy"**, never a "write blocker" in code, output or docs ("write blocker" means hardware only).
8. AI output is always labelled, carries model and prompt SHA-256, and is never presented as evidence.
9. Text from evidence (file names, document text, transcripts, metadata) is data, never instructions: it never reaches a model prompt outside a data block, a shell, or HTML unescaped.
10. No new third-party dependency without a decision-log row stating its licence (and a row in `docs/licenses.md`).

Repo-text conventions: no personal names or e-mail addresses beyond licence credits, research
citations and the repository URL; do not name the coding assistant or its vendor in repo text
or commit messages.

Where a download may live depends on its licence (plan 2B.18, `docs/licenses.md`): only
redistributable files are baked into the image (`stage: image`). Model weights, ClamAV,
MalwareBazaar, NSRL, YARA packs, EZ Tools and NudeNet stay `stage: assets`, fetched by the user
with `scripts/fetch-assets.*`. No prebuilt image may be published until task 6.6 is decided.

## Working rules (plan 2.1, 2.2)

- Work in milestone order; tasks in order unless a row says otherwise. Do not start a task that
  depends on an open 2.6 decision: mark it `blocked` up front.
- One task per commit where you can. Tasks that edit the same files may share a commit that
  lists every task number (decision log, 2026-11-15). Every commit message starts with task
  numbers, e.g. `3A.5: add write tracer`. No `WIP` commits.
- Update the task's Status cell in `docs/build-plan.md` in the same commit, and keep its note
  line under the milestone table current. Note format:
  `<task ids>: <status>: <what>, verified by <test>`.
  - `done`: a test that fails without the change passed **in your environment**.
  - `doing`: written, and its remaining check runs in the QEMU/CI stage; the note says what is left.
  - `needs-human`: needs a person or physical hardware (real USB drive, laptop, GPU, hardware
    write blocker; plan 2.7); the note says who acts and where the procedure is.
  - `blocked`: waits on a decision or another task; the note says why.
- If a task cannot be done as written, do not improvise a different design: mark it `blocked`
  and continue. Design changes go in the decision log.
- Definition of done (plan 2.2): code at the named path, a test that fails without it and
  passes with it, lint clean, every downloaded file pinned in `pins.yml`, one line of docs,
  Status updated.
- Fail closed. Anything not verified (a hash, a signature, a screening result, a drive
  identity) is treated as failed, never as passed.

## Commands

Run from the repo root.

```bash
scripts/prereqs.sh --check      # host prerequisites (exit 3 if missing); --install, --for build|flash
scripts/lint.sh                 # shellcheck, yamllint, ansible-lint, ruff, packer, pwsh, pins
scripts/lint.sh ruff            # one check: shellcheck|yamllint|ansible-lint|ruff|packer|pwsh|pins
tests/run-unit.sh               # pytest over tests/unit (pylib and scripts on sys.path)
python3 -m pytest -q tests/unit/test_findings.py   # a single unit test file
sudo tests/run-functional.sh    # every tests/functional/test_*.sh (many need root and loop devices)
sudo tests/run-functional.sh analyze_quick         # filter by name; exit 77 = skipped, reason on last line
python3 scripts/check-pins.py --list-unpinned      # pins with sha256: null (--strict exits 1 while any remain)
scripts/build.sh --prepare-tools                   # fetch pinned Packer + plugin + goss into cache/
scripts/build.sh --dev --dry-run                   # check build inputs only
scripts/build.sh --dev          # throwaway signing key; needs /dev/kvm, else add --accel tcg (hours)
sudo tests/run-qemu-tests.sh --image output/airlock-<ver>/airlock-<ver>.raw \
  --firmware uefi,uefi-sb,bios --goss "$(scripts/prereqs.sh --goss-path)"   # default firmware: uefi,bios; --dry-run
sudo ./make-usb.sh              # build (or reuse), flash, stage assets and smoke-test a USB drive
```

`scripts/lint.sh` skips any linter that is not installed and still prints `lint: ok`; check
for a `lint: skipped (tool not installed): ...` line before calling lint clean. Packer is not on
a fresh host's PATH: `scripts/build.sh --prepare-tools` puts the pinned one in `cache/`.

Test and lint tool dependencies are the install steps in `.github/workflows/lint.yml`: the
`lint` job (shellcheck, the pinned `PY_TOOLS`, Packer via `scripts/build.sh --prepare-tools`,
actionlint), the `unit` job, and the `functional` job (its apt list, plus Dissect in a venv at
`/opt/dissect` from `ansible/roles/tools_dissect/files/requirements.txt`). Ansible is not a host
prerequisite for building: it runs inside the build VM.

## Before the first real build

`llama_cpp_source` is the only `stage: image` pin still at `sha256: null`, and the `tools_ai`
role asserts on it inside the build VM, so **every real build (including `--dev`) fails partway
through Ansible until it is pinned**. On a machine that can download it:

```bash
curl -fsSLO https://github.com/ggml-org/llama.cpp/archive/refs/tags/b12030.tar.gz
sha256sum b12030.tar.gz && stat -c %s b12030.tar.gz
```

Put the hash and size in `ansible/group_vars/all/pins.yml`, regenerate the licence table (see
below) and commit. The other 30 null pins are `stage: assets`; the fetchers skip them and the
features that need them stay off.

## Layout

- `packer/`: QEMU builder, autoinstall `user-data`, provisioning scripts (run Ansible `-c local`).
- `ansible/site.yml`: three plays: base + hardening, tool roles + `session_tools`, then the
  hardening roles again last. `ansible/group_vars/all/`: `main.yml` (paths, sizes, kernel
  command line, `airlock_phase`), `pins.yml` (every download), `profiles.yml`, `ai_models.yml`.
- `ansible/roles/`: `base`, `harden_{storage,network,desktop,services}`, `tools_*`,
  `session_tools`. One control per task file, each naming its test.
- `ansible/roles/session_tools/files/bin/`: the analyst-facing commands (`forensic-*`,
  `evidence-*`, `ai-probe`), installed to `/usr/local/bin`. Python commands are thin wrappers
  that put `AIRLOCK_PYLIB` (default `/opt/airlock/lib/python`) on `sys.path`. System helpers
  live in their own roles: `airlock-setro` (harden_storage, `/usr/local/sbin`), firstboot and
  bootloader helpers (base, `/opt/airlock/libexec`); EZ Tools and Autopsy template wrappers.
- `ansible/roles/session_tools/files/pylib/`: on-image Python (3.12, standard library only
  unless the decision log says otherwise): `airlock_common` (paths, JSON, hashing, `proc.run`,
  devices, assets), `forensic_analyze` (wizard, runner, sandbox, tracer, findings, exports,
  signing, `modules/`), `airlock_ai`, `airlock_hashsets`, `airlock_provision`, `airlock_session`,
  `evidence_report`.
- `scripts/`: host-side tools (prereqs, build, flash, fetchers, manifest signing, pin checks, lint).
- `tests/unit` (pytest), `tests/functional` (bash, sourcing `tests/functional/lib.sh`),
  `tests/goss` (in-image checks), `tests/vm` (run inside the booted guest), `tests/windows`.
- `validation/`: reference-set scoring, scale baseline, CFTT method. `live/`: live ISO.

## Things that bite

- Every on-image path has an env override (`AIRLOCK_OPT_DIR`, `AIRLOCK_ETC_DIR`,
  `AIRLOCK_STATE_DIR`, `AIRLOCK_SESSION_DIR`, `AIRLOCK_ASSETS_DIR`, `AIRLOCK_OUTPUT_DIR`,
  `AIRLOCK_RUN_DIR`, ...; contract section 2). Use `airlock_common.paths`, never hard-coded
  paths. Unit tests get them sandboxed by the `airlock_env` fixture (`tests/unit/conftest.py`);
  functional tests set `AIRLOCK_PYLIB` to the repo `pylib` and `AIRLOCK_LOG_LIB` to
  `ansible/roles/session_tools/files/lib/airlock-log.sh` (contract section 8a).
- After any `pins.yml` change, regenerate the table in `docs/licenses.md` with
  `python3 scripts/check-pins.py --licences-table` (paste between the markers); `test_pins.py`
  fails if it drifts. Never invent a hash: only one you computed from the file or read from the
  publisher's machine-readable checksum. Null pins are refused (fail closed): asset pins by the
  fetchers, the ISO by `build.sh`, image-stage pins by their Ansible role in the build VM.
- `profile.json` on ASSETS is unsigned user input: only schema-checked features reach Ansible,
  and no role may read `profile.json` (enforced by `test_offline_phase.py`).
- Subprocesses: argument lists only (`airlock_common.proc.run`), never `shell=True`. JSON is
  written with sorted keys (`airlock_common.jsonio`). Findings rows are emitted in a
  deterministic order; `findings.jsonl` is the system of record.
- Parsers run sandboxed as `airlock-parse`: bwrap, else systemd-run, else unshare (`none` when
  not root, as in unit tests). bwrap and systemd-run give no network, a read-only run folder
  and only `modules/<name>/` writable; the unshare fallback gives only no network plus the
  parse user's permissions. The method used is recorded in `run.json`.
- The read-only udev rule is `00-forensic-ro.rules` (numbered to run before package rules).
  Output-drive unlock markers in `/run/airlock/rw-allow/` are bound to the drive's identity.
- A loop device keeps a read-only flag after detach; functional tests clear it before use.
- This was built without KVM: image builds, boots and everything in `tests/vm` and
  `tests/goss` have only been checked statically. The first real build plus
  `tests/run-qemu-tests.sh` run is what moves most `doing` tasks to `done`.

## Open owner decisions

Resolved (decision log): repository name, Apache-2.0, GNOME minimal desktop, AI tiers 0-2 on
the drive with NSRL off-drive. Packer is used for now, but 2.6.1 stays open until the 0.11
Packer-vs-mkosi spike runs on a KVM host (task 0.11 is `needs-human`).

Still open:
- Task 6.6 (`needs-human`): licence terms for ClamAV signatures, MalwareBazaar (recorded as
  CC0, unconfirmed), NudeNet, NSRL, YARA Forge (18 of its source rule sets state no licence), EZ
  Tools redistribution, and the model licences.
- Dissect (AGPL) is baked into the image with no source offer yet: ship its source with each
  release, or move it to `stage: assets`, before any prebuilt image is published.
- The legal review of risk 31, and the first-release scope (plan 2.8).
