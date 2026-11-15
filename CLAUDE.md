# CLAUDE.md

AIRLOCK (Air-gapped, Isolated, Read-only, Locked-down, Offline Case Kit) builds a bootable
forensic USB workstation as code: Ubuntu 24.04, Packer + Ansible, goss tests, a host-side asset
fetcher, a guided analysis wizard (`forensic-analyze`), a findings store, local AI triage and an
LLM-drafted report. Licence: Apache-2.0.

## Read these first

| File | What it is |
|---|---|
| `docs/build-plan.md` | The plan: 215 tasks by milestone, each with a Status cell and notes. Part 2 has the working rules, definition of done and hard rules. Part 4 starts the decision log. |
| `docs/dev/contract.md` | **Binding** cross-package contract: repo layout, on-image paths and env overrides, drive layout, session log, `pins.yml` format, manifest and profiles, Python rules, the module API, run folder, tests, lint, wording. Code must match it; change it in the same commit when an interface changes. |
| `docs/decision-log.md` | Every design decision with date, reason and licences. Add a row in the same commit as any design change or new dependency. |
| `docs/known-limitations.md` | Accepted gaps. A defect is only "accepted" if it is recorded here or in the decision log. |
| `docs/licenses.md` | Licence of every installed, downloaded or called component (a test enforces coverage). |
| `docs/threat-model.md`, `docs/controls.md` | Threats and the control that answers each one, with its test. |

## Hard rules (build plan 2.3, never break these)

1. The built system never uses a network. No task may add a download, update check or listener to the running USB system. Downloads belong to the build (`scripts/build.sh`) or the host fetcher (`scripts/fetch-assets.*`). At `airlock_phase=provision` roles work offline only (`tests/unit/test_offline_phase.py` enforces this).
2. Nothing writes to an evidence device. Targets are opened read-only (kernel read-only loop devices), never mounted read-write.
3. No dependence on a hardware vendor or model. Capacities only.
4. No secrets in the repository. Keys and tokens come from prompts, env vars or CI secrets. The abuse.ch key only ever comes from `AIRLOCK_ABUSECH_KEY` and is never written anywhere.
5. No sexual, violent or otherwise sensitive media in the repository, including fixtures. Generate neutral shapes, text and tones.
6. No automated age or child detection.
7. AIRLOCK's own layer is the **"software read-only policy"**, never a "write blocker" (that word is only for hardware blockers).
8. AI output is always labelled, carries model and prompt SHA-256, and is never evidence.
9. Text from evidence (file names, document text, transcripts, metadata) is data, never instructions: it never reaches a model prompt outside a data block, a shell, or HTML unescaped.
10. No new third-party dependency without a decision-log row stating its licence (and a row in `docs/licenses.md`).

Also: no AI model names or vendor identifiers and no personal names or emails in repo text
(the pinned model files themselves excepted).

## Working rules

- Work in milestone order; tasks in order unless a row says otherwise. Commit messages start
  with the task number(s), e.g. `3A.5: add write tracer`. So far commits group a work package
  and list every task number (decision log, 2026-11-15).
- Update the task's Status cell in `docs/build-plan.md` in the same commit:
  - `done`: only when a test that fails without the change passed **in your environment**.
  - `doing`: built, but only provable in QEMU/CI or on hardware; add a one-line note under the
    milestone table saying what is left.
  - `needs-human`: a person must act (plan 2.7). `blocked`: waits on a decision or task, with a
    one-line reason.
- Do not improvise a different design when a task cannot be done as written: mark it
  `blocked`, note why, and continue. Design changes go in the decision log.
- Definition of done (plan 2.2): code at the named path, a test that fails without it, lint
  clean, every downloaded file pinned in `pins.yml`, one line of docs, Status updated.
- Fail closed. Anything not verified (a hash, a signature, a screening result, a drive
  identity) is treated as failed, never as passed.

## Commands

Run from the repo root.

```bash
scripts/lint.sh                 # everything: shellcheck, yamllint, ansible-lint, ruff, packer, pwsh, pins
scripts/lint.sh ruff            # one check: shellcheck|yamllint|ansible-lint|ruff|packer|pwsh|pins
tests/run-unit.sh               # pytest over tests/unit (pylib and scripts on sys.path)
python3 -m pytest -q tests/unit/test_findings.py   # a single unit test file
sudo tests/run-functional.sh    # every tests/functional/test_*.sh (many need root and loop devices)
sudo tests/run-functional.sh analyze_quick         # filter by name; exit 77 = skipped, reason on last line
python3 scripts/check-pins.py --strict             # list pins still missing a SHA-256
scripts/build.sh --dev          # build an image with a throwaway signing key (needs KVM, or slow TCG)
sudo tests/run-qemu-tests.sh    # boot the image under UEFI, UEFI + Secure Boot and BIOS; run goss and tests/vm
sudo ./make-usb.sh              # build (or reuse), flash, stage assets and smoke-test a USB drive
```

Test tool dependencies are the apt and pip lists in `.github/workflows/lint.yml` (`unit` and
`functional` jobs), plus `exfat-fuse`/`exfatprogs` and Dissect in `/opt/dissect` for some
functional tests. `ruff format --check` also formats Python code blocks inside Markdown.

## Layout and where things live

- `packer/`: QEMU builder, autoinstall `user-data`, provisioning scripts (run Ansible `-c local`).
- `ansible/site.yml`: three plays: base + hardening, tool roles + `session_tools`, then the
  hardening roles again last. `ansible/group_vars/all/`: `main.yml` (paths, sizes, kernel
  command line, `airlock_phase`), `pins.yml` (every download), `profiles.yml`, `ai_models.yml`.
- `ansible/roles/`: `base`, `harden_{storage,network,desktop,services}`, `tools_*`,
  `session_tools`. Each role has `meta/main.yml`; one control per task file, each naming its test.
- `ansible/roles/session_tools/files/bin/`: every on-image command (`forensic-analyze`,
  `forensic-provision`, `evidence-*`, ...); installed to `/usr/local/bin`. Python commands are
  thin wrappers that put `AIRLOCK_PYLIB` (default `/opt/airlock/lib/python`) on `sys.path`.
- `ansible/roles/session_tools/files/pylib/`: on-image Python (3.12, standard library only
  unless the decision log says otherwise): `airlock_common` (paths, JSON, hashing, `proc.run`,
  devices, assets), `forensic_analyze` (wizard, runner, sandbox, tracer, findings, exports,
  signing, `modules/`), `airlock_ai`, `airlock_hashsets`, `airlock_provision`, `airlock_session`,
  `evidence_report`.
- `scripts/`: host-side tools (build, flash, fetchers, manifest signing, pin checks, lint).
- `tests/unit` (pytest), `tests/functional` (bash, sourcing `tests/functional/lib.sh`),
  `tests/goss` (in-image checks), `tests/vm` (run inside the booted guest), `tests/windows`.
- `validation/`: reference-set scoring, scale baseline, CFTT method. `live/`: live ISO.

## Things that bite

- Every on-image path has an env override (`AIRLOCK_OPT_DIR`, `AIRLOCK_ETC_DIR`,
  `AIRLOCK_STATE_DIR`, `AIRLOCK_SESSION_DIR`, `AIRLOCK_ASSETS_DIR`, `AIRLOCK_OUTPUT_DIR`,
  `AIRLOCK_RUN_DIR`, ...; contract section 2). Tests sandbox them into temp dirs; use
  `airlock_common.paths`, never hard-coded paths.
- After any `pins.yml` change, regenerate the table in `docs/licenses.md` with
  `python3 scripts/check-pins.py --licences-table` (paste between the markers); `test_pins.py`
  fails if it drifts. Never invent a hash: only one you computed from the file or read from the
  publisher's machine-readable checksum. A `sha256: null` pin is refused by the fetchers and
  `build.sh` (fail closed); 31 are still null (AI models, llama.cpp source, signature-base,
  EZ Tools, NSRL, sleuthkit-java).
- `profile.json` on ASSETS is unsigned user input: only schema-checked features reach Ansible,
  and no role may read `profile.json` (enforced by `test_offline_phase.py`).
- Subprocesses: argument lists only (`airlock_common.proc.run`), never `shell=True`. JSON is
  written with sorted keys (`airlock_common.jsonio`). Findings rows are emitted in a
  deterministic order; `findings.jsonl` is the system of record.
- Parsers run sandboxed (bwrap, else systemd-run, else unshare) as `airlock-parse`, with no
  network, the run folder read-only and only `modules/<name>/` writable.
- The read-only udev rule is `00-forensic-ro.rules` (numbered to run before package rules).
  Output-drive unlock markers in `/run/airlock/rw-allow/` are bound to the drive's identity.
- A loop device keeps a read-only flag after detach; functional tests clear it before use.
- This was built without KVM: image builds, boots and everything in `tests/vm` and
  `tests/goss` have only been checked statically. The first real `scripts/build.sh` plus
  `tests/run-qemu-tests.sh` run is what moves most `doing` tasks to `done`.

## Open owner decisions

Resolved so far (decision log): name, Apache-2.0, Packer kept (0.11 spike deferred), GNOME
minimal desktop, AI tiers 0-2 on the drive with NSRL off-drive. Still open: licence terms for
ClamAV signatures, MalwareBazaar, NudeNet, NSRL and YARA Forge (task 6.6); Dissect (AGPL) is
baked into the image with no source offer yet; the legal review of risk 31; first-release scope
(plan 2.8).
