# AIRLOCK documentation

Start with the [quickstart](quickstart.md). AIRLOCK is not a write blocker and is not
court-validated: read the [threat model](threat-model.md) and the
[known limitations](known-limitations.md) before you rely on it.

## Using AIRLOCK

| Page | What it covers |
|---|---|
| [quickstart.md](quickstart.md) | Make a drive: one command on Linux, or two stages from Windows |
| [flashing.md](flashing.md) | Writing the image to a drive with `scripts/flash.sh`, and what it refuses |
| [assets.md](assets.md) | Pins, the signed manifest, staging `ASSETS` with the fetchers, offline provisioning |
| [workflows/session.md](workflows/session.md) | Session start, clock check, unlocking an output drive, mounting images |
| [workflows/guided-analysis.md](workflows/guided-analysis.md) | `forensic-analyze`: the guided analysis |
| [workflows/windows-external-drive.md](workflows/windows-external-drive.md) | Runbook: deleted files and media metadata on a Windows external drive |
| [workflows/hash-triage.md](workflows/hash-triage.md) | Known software and known malware hash triage |
| [workflows/media-screening.md](workflows/media-screening.md) | Media screening runbook, including the stop control |
| [workflows/report.md](workflows/report.md) | The run report and how AI-drafted text is labelled and checked |
| [schema.md](schema.md) | `findings.jsonl`, the CSV, SQLite, and bodyfile exports |
| [commands.md](commands.md) | Every command on the drive, one line each |

## Trusting AIRLOCK

| Page | What it covers |
|---|---|
| [threat-model.md](threat-model.md) | What it protects against, what it does not, surviving risks |
| [known-limitations.md](known-limitations.md) | What no result can show, in plain words |
| [controls.md](controls.md) | Every hardening control, its mechanism, and its test |
| [write-blockers.md](write-blockers.md) | Hardware write blockers: how to check a test report, how runs record them |
| [validation-guide.md](validation-guide.md) | Prove on your own PC that the drive is read-only and offline |
| [validation.md](validation.md) | The validation suite and the per-release validation report |
| [hardware-checklist.md](hardware-checklist.md) | One-page checklist for each PC in the hardware matrix |
| [hardware-matrix.md](hardware-matrix.md) | Secure Boot, firmware, and results on real hardware |
| [licenses.md](licenses.md) | Licence of every tool and pinned download |
| [tools.md](tools.md) | The forensic tools on the image and where each comes from |

## Building and releasing

| Page | What it covers |
|---|---|
| [build.md](build.md) | Building the image with Packer and Ansible, drive layout, boot |
| [release-process.md](release-process.md) | Release cadence, the release workflow, checking a release |
| [../live/README.md](../live/README.md) | The live ISO variant (amnesic, built with live-build) |

## Developing

| Page | What it covers |
|---|---|
| [../CONTRIBUTING.md](../CONTRIBUTING.md) | One control = one task + one test + one doc line; style; tests |
| [dev/contract.md](dev/contract.md) | Shared paths, formats, and interfaces |
| [dev/repo-setup.md](dev/repo-setup.md) | Creating the GitHub repository and protecting `main` |
| [build-plan.md](build-plan.md) | The task list and its status |
| [decision-log.md](decision-log.md) | Every design decision, rejected alternatives, surviving risks |
| [../SECURITY.md](../SECURITY.md) | Reporting a security problem |
