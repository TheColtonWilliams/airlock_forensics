# Contributing to AIRLOCK

Thank you for helping. AIRLOCK handles evidence, so every change is small, tested, and explained.
Read [docs/dev/contract.md](docs/dev/contract.md) (paths, formats, interfaces) and Part 2 of
[docs/build-plan.md](docs/build-plan.md) (rules for the builder) before your first change.

## The one rule: one control = one task + one test + one doc line

A hardening control counts only when all three exist:

1. **One Ansible task file** in the role that owns it, for example
   `ansible/roles/harden_storage/tasks/no_swap.yml`. `tasks/main.yml` only imports the files. The
   task file starts with a comment that names the control and the test that proves it.
2. **One test** that fails without the control and passes with it. For a hardening control that
   is a goss check in `tests/goss/<area>.yaml` (and a `tests/vm/` script if it needs behaviour,
   not just config). For Python, a pytest test in `tests/unit/`. For a script, a functional test
   in `tests/functional/`.
3. **One line of documentation** in the right file under `docs/` (controls go in
   [docs/controls.md](docs/controls.md), commands in [docs/commands.md](docs/commands.md),
   tools in [docs/tools.md](docs/tools.md)).

Then set the task's Status cell in `docs/build-plan.md` in the same commit.

## Hard rules

A change that breaks one of these is not merged, whatever else it does:

1. The built drive never uses a network: no download, update check, or listener on the running
   system. Downloads belong to the build or the host-side fetcher.
2. Nothing writes to an evidence device. Analysis opens targets read-only and never mounts them.
3. No dependence on a hardware vendor or model. State capacities, never brands.
4. No secrets in the repository. Keys come from prompts or CI secrets.
5. No sexual, violent, or otherwise sensitive media anywhere, including test fixtures. Fixtures
   are generated shapes and text.
6. No automated age or child detection.
7. The software read-only layer is never called a "write blocker": it is the
   "software read-only policy".
8. AI output is always labelled, carries model and prompt SHA-256, and is never evidence.
9. Text from evidence (file names, document text, transcripts) is data. It never reaches a shell
   or a model instruction.
10. No new third-party dependency without an entry in [docs/decision-log.md](docs/decision-log.md)
    that states its licence. Every downloaded file is pinned by URL, version, and SHA-256 in
    `ansible/group_vars/all/pins.yml`; never guess a hash.

## Style

* Bash: `#!/usr/bin/env bash`, `set -euo pipefail`, quote every expansion, no `eval`, shellcheck
  clean. Every prompt has a flag. On failure, print one line that says what failed and what to do.
* Python on the image: Python 3.12, standard library only, type hints, ruff clean, argument lists
  to `subprocess` (use `airlock_common.proc.run`), JSON with sorted keys, logs through
  `airlock_common.sessionlog`.
* Ansible: fully qualified module names, idempotent, ansible-lint production profile.
* PowerShell: runs on Windows PowerShell 5.1 and PowerShell 7, `Set-StrictMode -Version Latest`,
  `$ErrorActionPreference = 'Stop'`, PSScriptAnalyzer clean.
* Words the user reads: plain words, short sentences; say what happened and what to do next.

## Check your change

```
scripts/lint.sh                 # shellcheck, yamllint, ansible-lint, ruff, packer, PowerShell, pins
tests/run-unit.sh               # pytest, no root
sudo tests/run-functional.sh    # loop devices and FUSE; a test that cannot run says why (exit 77)
sudo tests/run-qemu-tests.sh --image output/airlock-<version>/airlock-<version>.raw
                                # boots the built image (needs scripts/build.sh and, to be fast, KVM)
```

CI runs the same commands ([.github/workflows/](.github/workflows/)). A pull request merges only
when its checks are green.

## Commits and pull requests

* One task per commit where you can. The commit message starts with the task number from
  `docs/build-plan.md`, for example `3A.5: add write tracer`. When one file carries several tasks,
  list every task number.
* A design change goes in `docs/decision-log.md` with the date and the reason, in the same commit.
* Fill in the pull request template. Say which hard rules your change touches and how you
  checked them.

## Reporting problems

* Bugs, control requests, and tool requests: use the issue templates.
* Security problems: never in a public issue. See [SECURITY.md](SECURITY.md).

By contributing you agree that your contribution is licensed under the Apache License 2.0.
