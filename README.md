# AIRLOCK

**A**ir-gapped, **I**solated, **R**ead-only, **L**ocked-down, **O**ffline **C**ase **K**it.

AIRLOCK builds a bootable USB forensic workstation from stock Ubuntu 24.04 LTS, as code. One
command turns a git checkout into a tested drive. The drive boots locked down: it never goes
online, it does not mount what you plug in, every attached disk is set read-only, nothing indexes
or previews files, and radios are off. Every lockdown control is one small Ansible task with an
automated test, so "this drive is locked down" is something the build proves, not something you
have to assume. Tools, hash sets, and local AI models are staged onto the drive from your normal
computer before first boot; the drive itself never downloads anything.

> **AIRLOCK is not a write blocker. AIRLOCK is not court-validated.**
> Its read-only layer is a *software read-only policy*: a second line of defence that root can
> undo and that some hardware can ignore. Use a hardware write blocker that has a published NIST
> CFTT or DHS test report for real evidence (see [docs/write-blockers.md](docs/write-blockers.md)).
> Validate the drive on your own hardware under your own lab procedure before you rely on it
> ([docs/validation-guide.md](docs/validation-guide.md)). AI output is triage, never evidence.

## Quickstart

Full steps, with the warnings that matter: [docs/quickstart.md](docs/quickstart.md).

* **Linux with KVM, one command:**
  `git clone https://github.com/TheColtonWilliams/airlock_forensics.git airlock`, `cd airlock`,
  `sudo ./make-usb.sh`. It builds, tests, writes the drive, stages the tools and models, and
  boot-tests the finished drive.
* **Windows, or Linux without KVM:** download the published base image from the
  [release page](https://github.com/TheColtonWilliams/airlock_forensics/releases), check its
  SHA-256, write it with Rufus (DD Image mode) or balenaEtcher, run `fetch-assets.ps1` (or
  `fetch-assets.sh`) to stage the tools and models, then boot. The drive sets itself up offline.

You need a 64 GB or larger drive (a USB SSD is much faster than a flash stick) and an x86_64 PC
that can boot from USB. No step depends on a particular brand of PC, GPU, or drive.

## What it locks down

Each row is enforced by an Ansible role and checked by a test that runs in the booted image.
The full list, with the mechanism and the test for every control: [docs/controls.md](docs/controls.md).

| Area | What the drive does | Role | Tests |
|---|---|---|---|
| Attached disks | Nothing auto-mounts; every disk except the AIRLOCK drive is set read-only by the software read-only policy; no swap, hibernate, LVM, RAID or GPT auto-activation on attached disks | `harden_storage` | `tests/goss/storage.yaml`, `tests/vm/test_automount.sh`, `tests/vm/test_storage_untouched.sh` |
| Network | Radios blocked at the kernel module level and by rfkill; every network service masked; drop-all firewall; no switch to turn it back on | `harden_network` | `tests/goss/network.yaml`, `tests/vm/test_airgap.sh` |
| Desktop | No thumbnails, previews, indexers or volume monitors | `harden_desktop` | `tests/goss/desktop.yaml` |
| Services | No telemetry, crash upload, update checks, snaps or discovery daemons | `harden_services` | `tests/goss/services.yaml` |
| Analysis | Targets are read, never mounted; parsers run sandboxed with no network; a write tracer counts write requests to the target (expected: zero); outputs are hashed and signed | `forensic-analyze` | `tests/unit/`, `tests/functional/` |

Hardening runs first and again as the last play of `ansible/site.yml`, so no tool role can undo it.

What the controls do not do: logging that a drive was made writable (`evidence-unlock-output`)
is a record, not enforcement; root can clear the read-only flag; hostile drive firmware can change
its own contents. Read the [threat model](docs/threat-model.md) and
[known limitations](docs/known-limitations.md).

## Threat model

[docs/threat-model.md](docs/threat-model.md): what AIRLOCK protects against (accidental writes,
auto-processing of hostile files, radio and network leakage, background updates, swap and
hibernate writes) and what it does not (malicious drive firmware, kernel bugs in filesystem
drivers, a user who turns the protections off, physical tampering, classifier error).

## Status

**Pre-release. Nothing has been published yet.** What is tested, and where:

| What | Where it runs | Workflow |
|---|---|---|
| Lint (shellcheck, yamllint, ansible-lint, ruff, Packer, pins), unit tests, functional tests on loop devices | every pull request | [lint.yml](.github/workflows/lint.yml) |
| PowerShell analysis and the Windows fetcher against a real exFAT/NTFS volume | every pull request, Windows runner | [windows.yml](.github/workflows/windows.yml) |
| Image build, boot under UEFI, UEFI with Secure Boot and BIOS, every in-image check; the one-command builder on a loop device; offline provisioning with and without a network card | every pull request and monthly; needs KVM to be fast | [build.yml](.github/workflows/build.yml) |
| Signed release: image parts, SHA256SUMS, cosign signature, SBOM, signed asset manifest, validation report, licence record | version tags | [release.yml](.github/workflows/release.yml) |
| Real PCs, Secure Boot firmware, real USB bridges, hardware write blockers, first-use test on Windows | a person, by hand | [docs/hardware-checklist.md](docs/hardware-checklist.md), [docs/hardware-matrix.md](docs/hardware-matrix.md) |

Task-by-task progress is in [docs/build-plan.md](docs/build-plan.md) (Part 3).

## Documentation

Start at [docs/index.md](docs/index.md). Developer contract (paths, formats, interfaces):
[docs/dev/contract.md](docs/dev/contract.md). Every design decision and its reason:
[docs/decision-log.md](docs/decision-log.md).

## Contributing and security

* How to add a control or a tool, and the rules every change follows: [CONTRIBUTING.md](CONTRIBUTING.md).
* To report a security problem, use GitHub private vulnerability reporting: [SECURITY.md](SECURITY.md).

## Licence

The code in this repository is under the [Apache License 2.0](LICENSE). The tools the build
installs and the files the fetcher stages keep their own licences; each one is listed in
[docs/licenses.md](docs/licenses.md). Prebuilt images are published only after the licence review
of every bundled package (task 6.6). This project is not legal advice.
