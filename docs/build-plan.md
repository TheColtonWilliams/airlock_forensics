# Forensic USB Builder: Build Document

Project name: **AIRLOCK** (Air-gapped, Isolated, Read-only, Locked-down, Offline Case Kit). Repository: `airlock`. Interfaces and paths shared by all parts: `docs/dev/contract.md`.

Single source for building the repository from scratch. It merges the former project description and build plan (merged 2026-11-14). Nothing here has been built or tested yet.

How this document is organised:

- Part 1: what is being built and why.
- Part 2: rules for the builder, human or AI agent. Read this before writing anything.
- Part 3: the task list, 215 tasks in milestone order, each naming the files it touches.
- Part 4: decision log, rejected alternatives, and surviving risks.

Status key for task tables: todo / doing / done / blocked / needs-human

# Part 1: What is being built and why

## 1.1 Summary

An open-source, infrastructure-as-code project that builds a bootable USB forensic workstation from a stock Ubuntu LTS base. One command builds the image from a git checkout. The image boots locked down: no auto-mounting, Wi-Fi and Bluetooth off, block devices read-only by default, no indexing, no phone-home. Every control has an automated test, so "this USB is locked down" is something the build proves, not something the user assumes.

## 1.2 Problem

A default desktop Linux install does things that are bad for forensic work:

1. It auto-mounts attached drives.
2. It generates thumbnails and runs file indexers over anything it can see.
3. It turns on Wi-Fi and Bluetooth and checks for updates in the background.
4. It can activate swap partitions found on attached disks.

Each one can alter evidence or expose the analyst's machine to hostile data. Analysts fix this by hand, per machine, from memory. A rebuildable recipe in git is easier to review, test, and repeat.

## 1.3 Goals and non-goals

Goals:

1. Reproducible build from a git checkout, with pinned versions and checksums.
2. Locked-down defaults that are enforced and tested.
3. Air-gapped by design: the USB system never goes online. All downloads happen on the host computer and are staged onto the drive. There is no login: the `analyst` account has a locked password, autologin, and passwordless sudo.
4. Every hardening control is one small Ansible task with a comment and a test.
5. A session-start helper that records the state of the box at the start of each analysis.
6. Complete offline: hash sets, signatures, and AI models are on the drive before first boot. Refreshing them means restaging from the host computer, never the USB system going online.
7. Local AI triage that flags sexual and violent media and describes the rest, so the examiner does not have to view recovered content and does not browse a subject's private files more than the case needs. GPU-agnostic: the model tier is chosen from VRAM at boot, not from the GPU vendor. The project is built for the public: no step depends on a particular brand or model of PC, GPU, drive, or write blocker, and a PC with no usable GPU still works on the CPU tier.
8. One command from clone to bootable drive: `sudo ./make-usb.sh` checks the build host, prompts for the target drive and profile, builds, tests, flashes, and proves the drive boots.
9. Default install path that works from Windows or Linux: write a small published base image with any imaging tool, boot it on a bare-metal PC, and `forensic-provision` downloads and installs the tools and models, tests the result, and locks the system down. Files can be pre-positioned: redistributable tools are already installed in the base image, and a host-side fetcher (PowerShell or bash) stages models, hash sets, and the remaining tools on the drive's `ASSETS` partition so first boot needs no network.
10. The drive runs on the bare-metal PC it is plugged into and uses that machine's CPU, RAM, and GPU. It always advises a hardware write blocker and logs whether one was used.

Non-goals:

1. Not a replacement for a hardware write blocker. Software read-only flags are a second layer.
2. Not a court-validated acquisition platform. Users validate on their own test drive under their own lab procedure.
3. Not a malware-analysis sandbox.
4. No proprietary tools bundled.
5. No Windows or macOS build host in v1. The builder needs Linux x86_64 with KVM. The finished drive boots on any x86_64 PC.

## 1.4 Threat model

Protects against:

1. Accidental writes to evidence from the analyst workstation.
2. The workstation auto-processing hostile files (thumbnails, indexers, previews, cloud AV uploads).
3. Radio and network leakage during evidence handling.
4. Background updates changing tool versions mid-case.
5. Swap or hibernate writing to evidence disks.

Does not protect against:

1. Malicious firmware in the evidence drive or its USB bridge.
2. Kernel bugs triggered by hostile filesystems. Mitigation: image first, then parse in userland with The Sleuth Kit instead of mounting.
3. A user who turns the protections off on purpose.
4. Physical tampering with the USB stick itself.
5. Classifier error. A file the screen clears is "not flagged by this model at this threshold", not "safe". AI output is triage, never evidence.

## 1.5 Base OS: Ubuntu vs SIFT

They are not alternatives. SIFT is a set of Salt states that gets installed on top of Ubuntu. The install command is `sudo cast install teamdfir/sift-saltstack`, using a tool called Cast. The SIFT Salt states repo page lists Ubuntu 22.04 and 24.04 as supported, on amd64 and arm64, with some amd64-only packages skipped on arm64. Older forks and mirrors still list 20.04 and 22.04, so check the live repo on build day. I found no documentation that SIFT disables auto-mount or radios, so assume it does not until a test says otherwise.

| | Plain Ubuntu LTS base | Ubuntu plus SIFT layer |
|---|---|---|
| What it is | Stock distro. You choose tools. | Ubuntu plus a large curated forensic tool set from SIFT's Salt states. |
| Install method | `apt` and pinned downloads | `cast install`, needs network at build time |
| Supported base | Any LTS you test | 22.04 and 24.04 per the repo page I fetched |
| Lockdown | This project | Still this project. SIFT does not appear to add it. |
| Attack surface | Smaller if you stay minimal | Larger, more packages |
| Maintenance | You track tool updates | SIFT maintainers track tools. Can lag. |
| Role in this repo | Default | Optional Ansible role `tools_sift` |

Decision: Ubuntu LTS base, hardening first, tools second. SIFT is an opt-in role. Lockdown runs after the SIFT role so SIFT cannot undo it, and a test fails if it does.

Version choice: SIFT's states and Plaso's packaged release both list Ubuntu 24.04, so 24.04 is the default pick. The SIFT support claim comes from one page fetch on 2026-11-10. Re-check it before pinning.

## 1.6 Architecture

Build pipeline:

1. Fetch the Ubuntu base. Verify checksum and signature.
2. Build a disk image with Packer (QEMU builder) and provision it with Ansible over a local connection.
3. Output a raw image, compressed, with a SHA-256 file and a detached signature.
4. Flash with a documented script that refuses to write to any non-removable disk, prints the target model and size, and requires a typed confirmation.
5. Boot the image in QEMU and run the test suite.

Ansible roles:

| Role | Purpose |
|---|---|
| `base` | Minimal packages, users, locale, UTC clock |
| `harden_network` | Radios off, network off by default |
| `harden_storage` | No auto-mount, read-only block devices, no swap, no hibernate |
| `harden_desktop` | No thumbnails, indexers, previews |
| `harden_services` | Mask telemetry, updates, discovery daemons |
| `tools_acquire` | ewfacquire, dc3dd, ddrescue, Guymager, hashdeep, ssdeep, libvshadow |
| `tools_filesystem` | The Sleuth Kit, libfsntfs, ntfs-3g (info tools only) |
| `tools_dissect` | Dissect (Fox-IT): one Python API over E01, NTFS, USN, registry, BitLocker |
| `tools_eztools` | Eric Zimmerman's tools on the .NET 9 runtime: MFTECmd, RBCmd, LECmd, JLECmd, PECmd, EvtxECmd, RECmd, SBECmd, AmcacheParser, bstrings |
| `tools_timeline` | Plaso (log2timeline, psort) |
| `tools_carve` | PhotoRec, scalpel, foremost, bulk_extractor, usncarve |
| `tools_media` | exiftool, mediainfo, ffmpeg, exiv2, vinetto, Dissect thumbcache parser |
| `tools_registry` | RegRipper, libregf, hivex |
| `tools_hashsets` | ClamAV (scan-only, daemon masked), NSRL RDSv3 known-good set, MalwareBazaar known-bad hashes as a ClamAV `.hsb`, YARA rule packs, ssdeep, TLSH |
| `tools_ai` | llama.cpp with the Vulkan backend (AMD, NVIDIA, Intel from one build), Qwen3-VL GGUF models in VRAM tiers shipped on the image, NudeNet and SigLIP zero-shot classifiers for sexual and violent content screening, faster-whisper for audio |
| `tools_autopsy` | Optional, off by default. Autopsy zip plus Sleuth Kit Java .deb plus Java, pinned and checksummed |
| `tools_sift` | Optional, off by default. Runs Cast, then re-applies hardening. |
| `session_tools` | Helper scripts (section 1.8) |

Tool philosophy: CLI-first, one maintained Linux-native tool per artifact class, two independent parsers for the highest-value artifacts (MFT and USN via both EZ Tools and Dissect) so results can be cross-checked. No GUI case manager is required. Autopsy stays available for people who want one, but it is not the spine of the workflow.

Autopsy note: the latest release I saw on its GitHub releases page was 4.23.1. Pin the version in a variable. Read `Running_Linux_OSX.txt` inside the zip for the exact Java version. The 4.21.0 notes said Java 17.

Sources for the Linux-native claims: SANS published a guide to running EZ Tools natively on Linux with the .NET 9 runtime (https://www.sans.org/blog/running-ez-tools-natively-on-linux-a-step-by-step-guide). Dissect's documentation and PyPI listing are at https://docs.dissect.tools/ and https://pypi.org/user/fox-it/.

## 1.7 Hardening controls

Each row needs a task and a test before it counts as done.

| Control | Mechanism | Test |
|---|---|---|
| Wi-Fi and Bluetooth off | `rfkill block all` in a systemd unit ordered before NetworkManager. `install cfg80211 /bin/false` and `install bluetooth /bin/false` in `/etc/modprobe.d`, since most wireless drivers depend on them. Verify per kernel. | `rfkill list` shows nothing unblocked. `ip -br link` shows no `wlan*`. `lsmod` shows no `bluetooth`. |
| No network at all | NetworkManager, networkd, resolved, and timesyncd masked. nftables drops everything except loopback. No toggle exists. | No interface up except loopback. Drop policy loaded. No default route. |
| No auto-mount | Mask `udisks2.service`. Lock dconf keys `automount=false`, `automount-open=false`, `autorun-never=true`. Disable the gvfs volume monitor. | Attach a virtual disk with a filesystem. `findmnt` shows no new mount. |
| Block devices read-only | udev rule runs `blockdev --setro` on every disk and partition except the device holding `/`. Helper `evidence-unlock-output /dev/sdX` makes one named output drive writable and logs it. | `blockdev --getro` returns 1 on the second virtual disk. A `dd` write to it fails. |
| No swap on attached disks | Mask swap units. Confirm systemd does not auto-activate GPT swap partitions. | Attach a disk with a swap-type partition. `swapon --show` stays empty. |
| No hibernate | Mask hibernate and hybrid-sleep targets. Kernel parameter `noresume`. | `systemctl is-enabled` reports masked. |
| No thumbnails or previews | Nautilus `show-image-thumbnails` set to `never`. Disable thumbnailers. | Browse a directory of images. No thumbnail cache is created. |
| No indexers | Mask `tracker-miner-fs` or `localsearch` (name varies by release). | Units report masked. |
| No telemetry or auto-update | Mask `apport`, `whoopsie`, `ubuntu-report`, `motd-news`. Disable `unattended-upgrades`. Remove `snapd` or hold refreshes. Decide which. | Units report masked or disabled. |
| No discovery daemons | Mask `avahi-daemon`, `cups-browsed`, `ModemManager`, `geoclue`. | Units report masked. |
| Safe mount helper | `evidence-mount` mounts images only with `ro,noexec,nosuid,nodev` plus filesystem-specific flags such as `norecovery` where valid. | Mount an ext4 image. Journal is not replayed. Hash unchanged. |

## 1.8 Helper scripts

1. `forensic-session-start`: writes a log with UTC time, clock offset against a reference if the network is on, kernel version, tool versions, `lsblk` output, `rfkill` state, and read-only flags on every attached disk.
2. `forensic-import`: verifies and applies files restaged on the `ASSETS` partition from the host computer. This replaces any network update.
3. `evidence-unlock-output`: makes one named drive writable for case output.
4. `evidence-mount`: read-only mount helper for image files.
5. `evidence-hash`: hashes a device or image and appends to the session log.
6. `evidence-triage-hash`, `evidence-screen`, `evidence-describe`, `evidence-report`: hash triage, sexual and violent content screening, description of cleared media, and the merged report.
7. Host-side fetcher (`fetch-assets.ps1`, `fetch-assets.sh`): downloads, verifies, and stages every external file; `--refresh` restages signatures, hash sets, and models.
8. `forensic-escalate`: operator-run stop control for suspected illegal material.
9. `forensic-analyze`: the guided entry point. It asks which drive, where output goes, and which broad categories to analyze (file inventory, recycle bin, deletion history, images, video, audio, documents, malware, users, timeline, carving), offers Quick, Standard, and Full presets, runs everything unattended, and ends with one report. Every prompt has a command-line flag, and each run writes a `run.json` that replays it exactly.

## 1.9 Testing

1. Boot the built image headless in QEMU with extra virtual disks (ext4, NTFS, one with a swap-type partition).
2. Run the checks over the serial console or the QEMU guest agent, so the guest network stays off during the test.
3. Use goss or pytest-testinfra, one test file per control.
4. Run on every pull request. Use hardware KVM if the CI runner provides it. Otherwise accept the slower emulated run.
5. A release is blocked if any control test fails.

## 1.10 Supply chain and release

1. Pin apt sources to a dated snapshot or an internal mirror where possible.
2. Pin every downloaded tool by version and SHA-256.
3. Publish the image, its SHA-256, and a detached signature (cosign, minisign, or GPG).
4. Generate an SBOM with a tool such as syft.
5. Stretch goal: reproducible builds.

## 1.11 Proposed repo layout

```
forensic-usb-iac/
  README.md
  SECURITY.md
  CONTRIBUTING.md
  LICENSE
  docs/
    threat-model.md
    validation-guide.md
    decision-log.md
  packer/
  ansible/
    site.yml
    group_vars/
    roles/
      base/ harden_network/ harden_storage/ harden_desktop/ harden_services/
      tools_acquire/ tools_filesystem/ tools_dissect/ tools_eztools/
      tools_timeline/ tools_carve/ tools_media/ tools_registry/
      tools_hashsets/ tools_ai/ tools_autopsy/ tools_sift/ session_tools/
  tests/
    goss/
  scripts/
    flash.sh
    build.sh
  .github/workflows/
```

## 1.12 License and legal

1. Repo code: Apache-2.0 or MIT. Pick one before the first commit.
2. Publish build recipes first. Do not publish prebuilt images until each bundled package's license has been reviewed.
3. Never bundle proprietary tools such as FTK Imager.
4. This is a planning note, not legal advice.

## 1.13 Open questions

1. Ubuntu 24.04 (default pick) or 22.04?
2. GNOME (Ubuntu default) or a lighter desktop with less to lock down?
3. Installed image first, or live ISO first?
4. Autopsy is off by default. Revisit only if a GUI case manager becomes a real need.
5. Remove `snapd` or hold refreshes?
6. arm64 support in v1 or later? SIFT's states support it, but some packages are amd64-only.
7. Which model tiers ship by default? tier0 to tier2 (about 12 GB) fits a 64 GB stick. Shipping tier3 and tier4 pushes the minimum to 128 GB.
8. Does NSRL ship on the image or live on the output drive?

## 1.14 Outputs and reporting

1. `findings.jsonl` is the system of record: one typed row per finding, each with a stable finding ID, the run ID, the evidence hash, the tool and version that produced it, and a derivation flag (observed, inferred, or AI-generated).
2. `findings.csv` is the single flat file generated from it: fixed columns, UTC timestamps, importable into Timesketch, and neutralised against spreadsheet formula injection.
3. `case.sqlite` holds the same rows with ready-made views (timeline, deleted, recycle bin, media, hash hits, flags, disagreements).
4. `report.html` and `report.md`: code fills the factual sections; the local model drafts results, interpretation, and conclusions from structured rows using fixed, hashed prompts. Every sentence cites finding IDs, a code verifier removes any sentence it cannot match to its cited rows, and each AI paragraph is labelled as a draft awaiting the examiner's review.
5. Everything lands on an exFAT `OUTPUT` partition that Windows can read, hashed and signed per run.

## 1.15 Standards basis

1. Analysis modes: read directly, which is the default and counts as documented triage (SWGDE 17-F-002-2.1), or copy first (SWGDE 18-F-001-2.0). Both record SHA-256 and MD5 before and after.
2. The software read-only layer is a policy and a second line of defence, not a write blocker (Suhanov; NIST CFTT). A tracer records write requests to the target; the expected count is zero. Only CFTT-tested hardware blockers are recommended.
3. Every release carries a validation report against synthetic and public ground-truth images (SWGDE 18-Q-001; UK FSR Code of Practice v2).
4. Reports state the NIST IR 8354 limitations and never attribute actions to a person, only to an account SID.
5. LLM use follows the published findings on evidence-borne prompt injection (Kim, Kim and Min, DFRWS APAC 2026; Breitinger et al., arXiv 2610.29747) and on report drafting (Michelet and Breitinger, FSI:DI 2024).

## 1.16 Sources

1. SIFT repo (supported distros, Cast install): https://github.com/teamdfir/sift
2. SIFT Salt states (22.04 and 24.04, amd64 and arm64, MIT): https://github.com/teamdfir/sift-saltstack
3. Cast: https://github.com/ekristen/cast
4. SIFT issue on Cast build failures: https://www.github.com/teamdfir/sift/issues/626
5. Plaso on Ubuntu (24.04 only): https://plaso.readthedocs.io/en/stable/sources/user/Ubuntu-Packaged-Release.html
6. SANS read-only mount walkthrough (manual `ro,loop`): https://sans.org/blog/digital-forensic-sifting-how-to-perform-a-read-only-mount-of-filesystem-evidence
7. Autopsy releases (4.23.1 seen as latest): https://github.com/sleuthkit/autopsy/releases
8. `blockdev --setro` usage: https://oneuptime.com/blog/post/2026-03-04-mount-file-systems-read-only-forensics-recovery-rhel-9/view
9. SWGDE acquisitions 17-F-002-2.1: https://www.swgde.org/documents/published-complete-listing/17-f-002-2-1/
10. SWGDE examinations 18-F-001-2.0: https://www.swgde.org/documents/published-complete-listing/18-f-001-swgde-best-practices-for-computer-forensic-examination/
11. Suhanov, Linux-write-blocker: https://github.com/msuhanov/Linux-write-blocker
12. NIST IR 8354: https://www.nist.gov/publications/digital-investigation-techniques-nist-scientific-foundation-review
13. Timesketch import format: https://timesketch.org/guides/user/import-from-json-csv/
14. Michelet and Breitinger 2024: https://dfrws.org/wp-content/uploads/2024/03/ChatGPT-Llama-can-you-write-my-report-An-experim_2024_Forensic-Science-In.pdf
15. Breitinger et al., arXiv 2610.29747: https://arxiv.org/html/2610.29747v1
16. Red Hat, Secure Boot certificate changes 2026: https://developers.redhat.com/articles/2026/02/04/secure-boot-certificate-changes-2026-guidance-rhel-environments

# Part 2: Rules for the builder

## 2.1 How to work through this document

1. Work in milestone order. Inside a milestone, work in task order unless a row says otherwise.
2. One task per commit. The commit message starts with the task number, for example `3A.5: add write tracer`.
3. After each task, change its Status cell in Part 3 of this document in the same commit.
4. Do not start a task that depends on an open decision in 2.6. Mark it `blocked` and move on.
5. If a task cannot be done as written, do not improvise a different design. Mark it `blocked`, add one line under the task table saying why, and continue with the next unblocked task.
6. A change of design goes in the decision log in Part 4 with the date and the reason, in the same commit as the change.

## 2.2 Definition of done, for every task

A task is done only when all of these hold:

1. The code or config exists at the path the task names.
2. At least one automated test fails without it and passes with it. For a hardening control, that is a goss check. For Python, a pytest test. For a script, a functional test under `tests/functional/`.
3. Lint passes: shellcheck, ansible-lint, yamllint, ruff, PSScriptAnalyzer, as applicable.
4. Every file downloaded at build or staging time is listed in `ansible/group_vars/pins.yml` with URL, version, and SHA-256.
5. One line of documentation exists for it, in the relevant file under `docs/`.
6. The Status cell is updated.

Tasks marked manual, or listed in 2.7, cannot be completed by an automated builder. Prepare everything up to the manual step, then set the status to `needs-human`.

## 2.3 Hard rules

1. The built system never uses a network. No task may add a download, update check, or listener to the running USB system. All downloads belong to the host-side fetcher or the build.
2. Nothing may write to an evidence device. Analysis code opens targets read-only and never mounts them.
3. No dependence on a hardware vendor or model. Capacities only.
4. No secrets in the repository. Keys and tokens come from prompts or CI secrets.
5. No sexual, violent, or otherwise sensitive media in the repository, including as test fixtures.
6. No automated age or child detection. See the decision log.
7. The software read-only layer is never called a write blocker in code, output, or docs.
8. AI output is always labelled, always carries model and prompt hashes, and is never presented as evidence.
9. Text that comes from evidence (filenames, document text, transcripts) is data. It is never placed where a model or shell could read it as an instruction or command.
10. No new third-party dependency without a decision-log entry stating its licence.

## 2.4 Languages and style

| Kind | Rules |
|---|---|
| Bash | `#!/usr/bin/env bash`, `set -euo pipefail`, shellcheck clean, quote every expansion, no `eval`. Every prompt has a flag equivalent. Exit non-zero on failure with one line saying what failed. |
| Python | Version shipped with Ubuntu 24.04. Standard library only inside the image unless the decision log says otherwise. Type hints, ruff clean, pytest tests. No shell strings: pass argument lists to `subprocess`. |
| Ansible | Fully qualified module names, idempotent tasks, one control per task file, a comment on each control naming its test. ansible-lint production profile. |
| PowerShell | Runs on Windows PowerShell 5.1 and PowerShell 7. PSScriptAnalyzer clean. `Set-StrictMode -Version Latest`, `$ErrorActionPreference = 'Stop'`. |
| YAML and JSON | yamllint clean. JSON written with sorted keys. |
| Logs | One JSON object per line, UTC ISO 8601 timestamps, written under the session log folder. |
| User-facing text | Plain words, short sentences, no jargon without a one-line explanation. State what happened and what to do next. |

## 2.5 Known inconsistencies to resolve while building

The plan grew by additions. Resolve these when the affected milestone is reached, and record the outcome in the decision log:

1. Milestone 2A (Linux-only full build) predates the air-gap and staging decisions. Keep it only if it can reuse the same manifest and staging code as Milestone 2B. Otherwise drop it.
2. Milestones 1, 2A, 5, and 6 name Packer. Task 0.11 may replace it with mkosi. If it does, rewrite those rows before starting Milestone 1.
3. The two-parser cross-check (4C.28) and the single-tool modules (4C.5 to 4C.7) describe overlapping work. Build the modules to emit both parsers' results from the start.
4. `evidence-report` appears in 4B.11 and again in Milestone 4E. Milestone 4E is the definition.
5. Task 4.9 (Autopsy) and task 6.5 (SIFT) are optional add-ons. Build them last or not at all.

## 2.6 Open decisions the owner must make

Tasks that depend on these are blocked until answered:

1. Build tool: Packer or mkosi (task 0.11).
2. Repository name and licence: Apache-2.0 or MIT (tasks 0.1, 0.2).
3. Which model tiers ship by default, and whether NSRL is staged on the drive (sets drive size and the `ASSETS` partition size, task 2B.9).
4. Ubuntu desktop: GNOME or something lighter (task 1.8).
5. Licence terms still unconfirmed: ClamAV signatures, MalwareBazaar data, NudeNet, NSRL redistribution (task 6.6).
6. Legal review of the child-content gap (risk 31) before any public release that includes media screening.
7. The scope of the first release. A proposal is in 2.8.

## 2.7 Tasks that need a person

An automated builder cannot do these: 1.13 (firmware tests), 2.6, 3.10, 4B.13, 4B.16, 4G.17, 4G.18, 6.6, 7.3, 7.4. It also cannot verify anything that needs a physical write blocker, a physical GPU, or a real USB drive.

## 2.8 Proposed first release (owner to confirm)

All tasks is too much for a first version. Proposed v0.1, enough to boot the drive and list deleted files safely:

1. Milestones 0, 1, 2, and 2B (base image, fetcher, offline provisioning).
2. Milestones 3 and 3A (storage, network, and write-protection hardening).
3. From Milestone 4: acquisition, filesystem, Dissect, and EZ Tools roles, plus the session helpers.
4. From Milestone 4C: the wizard with the Quick preset only (inventory, recycle bin, deletion history).
5. Milestone 4D (findings store and the CSV export).
6. The matching tests from Milestones 4F and 4G.

Left for v0.2: hash sets (4A), local AI (4B), the remaining wizard modules, the AI-drafted report (4E).

## 2.9 Exit check per milestone

| Milestone | It is finished when |
|---|---|
| 0 | The repo exists with licence, README, contributor rules, and lint running on every change. |
| 1 | CI builds an image that boots to a desktop under UEFI and BIOS in the emulator. |
| 2 | The flash script writes the image to a removable drive, verifies it, and refuses every wrong target. |
| 2A | One command on Linux produces a drive that passes the smoke test, or the milestone is dropped (see 2.5). |
| 2B | A drive written on Windows, staged by the fetcher, provisions itself with no network and passes the full test suite. |
| 3 | Every storage and network control has a passing check in the emulator. |
| 3A | A test disk with LVM, RAID, and swap signatures is untouched after a run, and the tracer counts a deliberate write. |
| 4 | Every tool runs, and the fixture's known deleted files are found by each parser. |
| 4A | Hash triage drops known-good files and flags a known-bad test file, offline. |
| 4B | The right model tier is chosen from recorded hardware profiles, and the stub-classifier tests pass. |
| 4C | A non-interactive Standard run on the fixtures produces the expected findings and leaves the fixture hash unchanged. |
| 4D | A replay of the same run gives a byte-identical findings file, and the CSV passes the safety tests. |
| 4E | The report cites a finding for every sentence and ignores planted instructions in the fixtures. |
| 4F | The validation report is generated and attached to a release. |
| 4G | Every test in the milestone runs in CI, or is marked needs-human. |
| 5 | Desktop and service controls pass, and CI runs lint, build, and test on every change. |
| 6 | A tagged release publishes a signed image, checksums, SBOM, and the licence record. |
| 7 | The hardware matrix and outside review are recorded, and v1.0 is tagged. |

# Part 3: Tasks

## Approach (revised after objections)

Build an installed Ubuntu 24.04 LTS image with Packer (QEMU builder), configure it with Ansible over a local connection, test it in QEMU with goss, flash with a guarded script. Image carries the generic kernel so it boots on real laptops, not just the build VM. The USB system is air-gapped: radios blocked at the kernel level, network services masked, drop-all firewall. Files and updates are staged from the host computer onto the `ASSETS` partition. There is no login prompt.

Objections considered and how they changed the plan:

1. A Packer image inherits the build VM's hardware profile. Fix: force `linux-generic`, keep initramfs `MODULES=most`, and gate every milestone on a bare-metal boot test on two different laptops, not just QEMU.
2. A radio block alone still leaves wired networking and a toggle someone can flip. Decision (revised): full air gap. Network services masked, drop-all firewall, no toggle, and every download happens on the host computer.
3. GitHub-hosted runners may lack KVM. Fix: CI checks `/dev/kvm` and falls back to TCG emulation with a longer timeout. Release builds run on a self-hosted runner if the emulated run exceeds 60 minutes.
4. Unlock helper logging is not enforcement. Accepted as a surviving risk; the README says so.
5. A single script would be faster to write. Rejected: no idempotence, no per-control test.

## Research basis (added 2026-11-10)

A research pass against current standards changed this plan. The findings that drive the changes, with the source for each:

1. SWGDE Best Practices for Computer Forensic Examinations (18-F-001-2.0, Jul 2025): analysis should be done on a copy, not the original, and tools should be updated, tested, and validated before use.
2. SWGDE Best Practices for Computer Forensic Acquisitions (17-F-002-2.1, Aug 2025): triage and targeted collection are acceptable when documented well enough to repeat.
3. SWGDE Digital Evidence Collection (18-F-002-2.0, Nov 2025): hash with more than one algorithm.
4. Maxim Suhanov, Linux-write-blocker: `blockdev --setro` relies on each filesystem driver honouring the flag, `ro,noload` on ext4 can still write, and SG_IO commands bypass it. It is not a write blocker.
5. NIST CFTT / DHS (Mar 2020): a USB "write-protect" adapter let 10 of 31 write commands through under Ubuntu. Only blockers with a CFTT report should be recommended.
6. NIST IR 8354 (2022): three limitations every report should state: not all evidence may be found, recovered deleted files may include extraneous material, and artifact meaning changes between OS versions.
7. Michelet and Breitinger (FSI:DI 48, 2024): LLMs can assist report writing but cannot replace the examiner.
8. Kim, Kim and Min (DFRWS APAC 2026) and Breitinger et al. (arXiv 2610.29747): text inside evidence can steer an LLM. Treating evidence as untrusted data cut attack success from 31.3% to 0.6% in the first study.
9. Red Hat and ESET (2026): the Microsoft UEFI CA 2011 expired 27 June 2026 and old shims were revoked in June 2026. Ship a current dual-signed shim.
10. Phoronix (2026): llama.cpp Vulkan is strong on AMD and Intel with a new kernel and Mesa; on NVIDIA the open driver usually reaches half or less of the proprietary driver's speed.

Not verified by the research and still open: the ISO/IEC 27037 to 27043 text (paywalled), licence terms for ClamAV signature databases, MalwareBazaar data, NudeNet, and NSRL redistribution, and any independent error rates for NudeNet or SigLIP.

## Milestone 0: Repo scaffold (one session)

| # | Task | Touches | Status |
|---|---|---|---|
| 0.1 | Create GitHub repo, public, name chosen | github.com | todo |
| 0.2 | Pick license (Apache-2.0 or MIT) and commit LICENSE | LICENSE | todo |
| 0.3 | README with one-paragraph purpose and the "not a write blocker, not court-validated" statement | README.md | todo |
| 0.4 | SECURITY.md with disclosure contact and supported versions | SECURITY.md | todo |
| 0.5 | CONTRIBUTING.md: one control = one task + one test + one doc line | CONTRIBUTING.md | todo |
| 0.6 | docs/decision-log.md seeded with the decisions in this file | docs/decision-log.md | todo |
| 0.7 | Copy the threat model from section 1.4 into docs/threat-model.md | docs/threat-model.md | todo |
| 0.8 | Branch protection on main: PR required, CI green required | github settings | todo |
| 0.9 | Issue templates: control request, bug, tool request | .github/ISSUE_TEMPLATE/ | todo |
| 0.10 | .editorconfig, .gitattributes (LF), pre-commit with ansible-lint, shellcheck, yamllint | repo root | todo |
| 0.11 | Build-tool spike before Milestone 1: build the base image twice with Packer plus Ansible and twice with mkosi, diff the results, and record which is reproducible enough. The research rates mkosi and live-build above Packer for reproducibility; the rest of this plan assumes Packer until this spike says otherwise | docs/decision-log.md | todo |

## Milestone 1: Build pipeline, unhardened (v0.1 part 1)

| # | Task | Touches | Status |
|---|---|---|---|
| 1.1 | Packer template, QEMU builder, Ubuntu 24.04 live-server ISO as source, checksum pinned | packer/ubuntu-24.04.pkr.hcl | todo |
| 1.2 | Autoinstall (cloud-init) config: single ext4 root, no swap partition, no LVM; user `analyst` with a locked password (no password exists), desktop autologin, passwordless sudo, screen lock off, no SSH server installed; build-time access removed at the end; root filesystem grows to fill the drive on first boot | packer/http/user-data | todo |
| 1.3 | Force `linux-generic`, remove `linux-virtual` if pulled in; set initramfs `MODULES=most` | packer/http/user-data | todo |
| 1.4 | Packer provisioner runs `ansible-playbook -c local site.yml` inside the guest | packer/ubuntu-24.04.pkr.hcl | todo |
| 1.5 | Ansible `site.yml` with `base` role only: packages, UTC clock, locale, remove build-time SSH key last | ansible/site.yml, ansible/roles/base/ | todo |
| 1.6 | Post-processor: raw image, zstd compressed, SHA256SUMS file | packer/ubuntu-24.04.pkr.hcl | todo |
| 1.7 | scripts/build.sh wraps packer init/validate/build with pinned Packer version | scripts/build.sh | todo |
| 1.8 | Install `ubuntu-desktop-minimal` (the server ISO has no desktop; `harden_desktop` and the launchers need one) | ansible/roles/base/ | todo |
| 1.9 | Portable boot: GPT with an EFI system partition and a BIOS boot partition; `grub-install --removable --no-nvram` so the loader sits at `EFI/BOOT/BOOTX64.EFI` and does not depend on the build VM's firmware entries; second `grub-install --target=i386-pc` for legacy BIOS; fstab and grub by UUID only | ansible/roles/base/ | todo |
| 1.10 | First-boot unit: regenerate machine-id and SSH host keys, grow the root filesystem, then disable itself | ansible/roles/base/ | todo |
| 1.11 | Verify: build completes; image boots in QEMU under both OVMF (UEFI) and SeaBIOS to a desktop login | tests/run-qemu-tests.sh | todo |
| 1.12 | Kernel and graphics: HWE kernel and a pinned newer Mesa (the 24.04 GA stack predates the Vulkan gains); initramfs includes `uas`, `usb-storage`, `nvme`, `vmd`, `ahci`, xhci; boot-menu entry with the UAS quirk workaround for flaky USB bridges | ansible/roles/base/ | todo |
| 1.13 | Secure Boot: current Ubuntu dual-signed shim and grub only, SBAT level checked in CI; boot test on firmware with the 2023 CA only and on firmware without the update; quickstart warns that changing Secure Boot settings on a BitLocker PC triggers recovery | ansible/roles/base/, docs/hardware-matrix.md | todo |

## Milestone 2: Flash script (v0.1 part 2)

| # | Task | Touches | Status |
|---|---|---|---|
| 2.1 | scripts/flash.sh: lists removable disks only (`lsblk -d -o NAME,MODEL,SIZE,RM,TRAN`), refuses `RM=0`, refuses targets smaller than the image plus 8 GB headroom | scripts/flash.sh | todo |
| 2.2 | Prints target model, size, serial; requires the user to type the device name back | scripts/flash.sh | todo |
| 2.3 | Refuses if target is the disk holding `/` or any mounted filesystem | scripts/flash.sh | todo |
| 2.4 | Verifies image SHA-256 before writing; writes with `dd bs=4M conv=fsync status=progress` | scripts/flash.sh | todo |
| 2.5 | Reads back and hashes the written range, compares to image hash | scripts/flash.sh | todo |
| 2.6 | Verify: flash to a scratch USB, boot a real laptop, reach login | manual, two laptops | todo |

## Milestone 2A: One-command builder `make-usb.sh` (v0.1 part 2)

Linux-only alternative to Milestone 2B for people who want a complete image built offline before first boot. Purpose: clone, run one script, answer prompts, end with a bootable forensic drive. It chains the build (Milestone 1) and the flash (Milestone 2); it adds no build logic of its own.

| # | Task | Touches | Status |
|---|---|---|---|
| 2A.1 | `make-usb.sh` at the repo root: checks Linux x86_64 host, `/dev/kvm`, free disk space, and internet; lists missing prerequisites (Packer, QEMU, Ansible, zstd) and installs them after a yes/no | make-usb.sh, scripts/prereqs.sh | todo |
| 2A.2 | Prompts: target drive (the 2.1 picker), profile (model tiers, NSRL on the drive or not, Autopsy or not), optional abuse.ch key (skipped key means no MalwareBazaar set, and the build log says so). No username or password prompt | make-usb.sh | todo |
| 2A.3 | Before building: print estimated download size, image size, and build time for the chosen profile; refuse if the target drive is too small | make-usb.sh | todo |
| 2A.4 | Run build, QEMU tests, then flash. Flags: `--image-only`, `--flash-only <image>`, `--yes`, `--profile <file>`. Downloads cached in `./cache` by SHA-256 so a rerun does not fetch them again | make-usb.sh, scripts/build.sh | todo |
| 2A.5 | Failure handling: full log to `build.log`, first failing task named on screen, rerun resumes from the cache | make-usb.sh | todo |
| 2A.6 | After flashing: read-back hash (2.5), then boot the physical drive read-only in QEMU and run a goss smoke test, so the drive is proven bootable before it leaves the build machine | make-usb.sh, tests/ | todo |
| 2A.7 | docs/quickstart.md: `git clone`, `cd`, `sudo ./make-usb.sh`. Section for Windows-only users: build from an Ubuntu live session, or `--image-only` inside WSL2 and flash the image with a Windows imaging tool (WSL2 path untested until someone runs it) | docs/quickstart.md | todo |
| 2A.8 | CI: `make-usb.sh --yes --profile ci.yml` against a loop device as the target | .github/workflows/build.yml | todo |

## Milestone 2B: Two-stage install, the default path for Windows and Linux users (v0.1 part 2)

Stage 1: write a small base image to the USB drive with any imaging tool. Stage 2: boot that drive on a bare-metal PC and let it provision itself. No Packer, QEMU, or KVM on the user's machine, so the steps are the same from Windows and Linux. The base image holds only Ubuntu packages and this repo's code, so it can be published without redistributing third-party tools or models.

| # | Task | Touches | Status |
|---|---|---|---|
| 2B.1 | CI builds the base image from Milestone 1: Ubuntu 24.04 minimal desktop, portable boot (1.9), storage and network hardening already applied, Ansible, the repo's roles at a pinned tag, and `forensic-provision`. Everything that may be redistributed is already installed in place: all Ubuntu-archive tools, the CI-built llama.cpp, YARA rule packs, and Python tools whose licences allow it. Left out: EZ Tools, model weights, NSRL, ClamAV databases, MalwareBazaar | .github/workflows/release.yml | todo |
| 2B.2 | Publish base image, SHA256SUMS, and signature as GitHub Release assets; keep each file under GitHub's per-file size limit or split it (confirm the current limit) | .github/workflows/release.yml | todo |
| 2B.3 | Quickstart, Windows: download, check with `Get-FileHash`, write with Rufus in DD mode or balenaEtcher. Quickstart, Linux: `scripts/flash.sh` (Milestone 2) | docs/quickstart.md | todo |
| 2B.4 | `forensic-provision` runs unattended on first boot with zero prompts and no network: reads `profile.json` written by the fetcher, refuses to run while any disk other than the boot drive is attached | ansible/roles/session_tools/files/forensic-provision | todo |
| 2B.5 | Provisioning runs the same Ansible roles locally, every download checked against `pins.yml`, cached and resumable after a failure or power loss | forensic-provision | todo |
| 2B.6 | Finish: goss tests on the real hardware, hardening re-applied last, network off, manifest written (tool versions, model hashes, hardware, date), reboot | forensic-provision | todo |
| 2B.7 | To add or change parts later: rerun the fetcher on the host computer with a new profile; the next boot detects the changed `ASSETS` set, verifies it, and applies it offline | forensic-provision | todo |
| 2B.8 | CI: boot the base image in QEMU with a virtual NIC, provision with the CI profile, run the full test suite | .github/workflows/build.yml | todo |
| 2B.9 | Pre-positioning, partition layout: EFI, BIOS boot, a fixed-size exFAT partition labelled `ASSETS` (sized for the default profile), then the ext4 root last so it grows to fill the drive. `ASSETS` is empty in the published image, so it compresses to almost nothing | packer/http/user-data | todo |
| 2B.10 | `assets/manifest.json` generated from `pins.yml`: every external file with URL, size, SHA-256, target path, and which profile needs it | scripts/gen-manifest.py | todo |
| 2B.11 | Host-side fetchers `fetch-assets.ps1` (Windows) and `fetch-assets.sh` (Linux): prompt for profile and optional abuse.ch key, download each file in the manifest, verify SHA-256, copy onto the `ASSETS` partition of the flashed drive, write `profile.json`; resumable; reports free space before starting | scripts/fetch-assets.ps1, scripts/fetch-assets.sh | todo |
| 2B.12 | Offline is the only provisioning mode. Missing or corrupt `ASSETS` files are listed by name, the features that need them are disabled and marked in the report, and the fix is to rerun the fetcher on the host computer. The USB system never downloads anything | forensic-provision | todo |
| 2B.13 | Placement: small executables (EZ Tools) are copied into `/opt`. Large data (GGUF models, classifier weights, NSRL, ClamAV and MalwareBazaar databases) stays on `ASSETS`, mounted read-only with `noexec`, and the tools point at it there, so nothing is copied twice | ansible/roles/base/, forensic-provision | todo |
| 2B.14 | Hash check of every `ASSETS` file at each boot's `forensic-session-start`, result in the session log | ansible/roles/session_tools/files/ | todo |
| 2B.15 | Signed manifest: `assets/manifest.json` is signed in the release workflow and the public key is baked into the base image, so pinned files are checked against something the `ASSETS` partition cannot rewrite. Files that change daily (ClamAV, MalwareBazaar) are checked by vendor signature where one exists and otherwise recorded as trusted-at-staging | .github/workflows/release.yml, forensic-provision | todo |
| 2B.16 | CI: build base image, run `fetch-assets.sh` against it as a loop device, boot in QEMU with no NIC, confirm provisioning completes offline and the full test suite passes | .github/workflows/build.yml | todo |
| 2B.17 | Add a separate exFAT `OUTPUT` partition for case output and reports, readable on Windows. `ASSETS` is mounted read-only during runs. Every output file is hashed into `outputs.sha256` | packer/http/user-data, ansible/roles/base/ | todo |
| 2B.18 | Asset placement by licence: EZ Tools (MIT per the research, confirm each repo's LICENSE), Dissect and NudeNet (AGPL, ship licence and source offer) may be baked into the base image; ClamAV signatures, MalwareBazaar, NSRL, YARA packs, and model weights stay user-fetched | docs/licenses.md, assets/manifest.json | todo |
| 2B.19 | Release cadence: rebuild the base image monthly and out of band for parser CVEs; rerun the validation suite (4F) before each release | docs/release-process.md | todo |

## Milestone 3: Storage and network hardening (v0.1 part 3, gates v0.1 release)

| # | Task | Touches | Status |
|---|---|---|---|
| 3.1 | Role `harden_storage`: mask `udisks2.service`, dconf lock `automount=false`, `automount-open=false`, `autorun-never=true` | ansible/roles/harden_storage/ | todo |
| 3.2 | udev rule: `blockdev --setro` on every `sd*`, `nvme*`, `mmcblk*`, `vd*` disk and partition except the root device and its parent | ansible/roles/harden_storage/files/99-forensic-ro.rules | todo |
| 3.3 | Mask `swap.target`, `systemd-hibernate.service`, `systemd-hybrid-sleep.service`; kernel cmdline `noresume` | ansible/roles/harden_storage/ | todo |
| 3.4 | Confirm systemd-gpt-auto-generator does not activate swap or mount partitions on attached disks; add `systemd.gpt_auto=0` to cmdline | ansible/roles/harden_storage/ | todo |
| 3.5 | Role `harden_network` (air-gap profile, the default): systemd unit `forensic-rfkill.service` running `rfkill block all`; NetworkManager, systemd-networkd, systemd-resolved, and systemd-timesyncd masked; no DHCP client runs | ansible/roles/harden_network/ | todo |
| 3.6 | `/etc/modprobe.d/forensic-radios.conf`: `install cfg80211 /bin/false`, `install bluetooth /bin/false`, `install btusb /bin/false`. Wired interfaces stay down: a udev rule leaves every network interface unmanaged | ansible/roles/harden_network/ | todo |
| 3.7 | Second layer: nftables ruleset loaded at boot that drops all traffic in and out on every interface except loopback (the local AI server needs loopback) | ansible/roles/harden_network/ | todo |
| 3.8 | goss tests: automount, blockdev ro on second disk, no swap, rfkill, no wlan interface, no bluetooth module, network services masked, no interface up except loopback, nftables drop policy loaded, no listening socket off loopback | tests/goss/storage.yaml, tests/goss/network.yaml | todo |
| 3.9 | QEMU test harness: boots image with two extra virtual disks (ext4, one with swap-type partition), runs goss over serial console, exits non-zero on failure | tests/run-qemu-tests.sh | todo |
| 3.10 | Verify on bare metal: attach a scratch USB drive, `findmnt` shows nothing, `blockdev --getro` is 1, `dd` write fails | manual | todo |
| 3.11 | Tag v0.1 | git | todo |

## Milestone 3A: Write-protection hardening from the research (v0.1 part 3)

The software read-only layer is defence in depth. Documentation and on-screen text call it "software read-only policy", never a write blocker.

| # | Task | Touches | Status |
|---|---|---|---|
| 3A.1 | Kernel command line: `systemd.gpt_auto=0 rd.systemd.gpt_auto=0 rd.lvm=0 rd.md=0 rd.dm=0 rd.luks=0 nodmraid noresume` | ansible/roles/harden_storage/ | todo |
| 3A.2 | Mask `lvm2-monitor`, `mdmonitor`, `multipathd`, `udisks2`, `smartd`; no automatic fsck; no SMART self-tests or spin-down commands sent to targets | ansible/roles/harden_storage/ | todo |
| 3A.3 | Never mount the target by default: analysis reads the raw device or image through The Sleuth Kit and Dissect. `evidence-mount` remains for images only, with `ro,noload` (ext), `ro,norecovery` (XFS), and a warning | ansible/roles/session_tools/files/ | todo |
| 3A.4 | Restrict `/dev/sg*` and `/dev/bsg/*` to root and ship no tool that sends SG_IO commands to a target | ansible/roles/harden_storage/ | todo |
| 3A.5 | Write tracer: record write and discard requests issued to the target during a run (blktrace or a kprobe) and put the count in `run.json` and the report. Expected value is 0 | forensic-analyze/tracer.py | todo |
| 3A.6 | HPA and DCO detection (`hdparm -N`, `--dco-identify`) logged, never removed. SSD targets get a warning that the drive's own garbage collection can change before and after hashes | forensic-analyze/target.py | todo |
| 3A.7 | Write-blocker record: make, model, firmware, and a link to its CFTT or DHS test report; the docs list only blockers that have one | forensic-analyze/target.py, docs/write-blockers.md | todo |
| 3A.8 | Run the NIST CFTT Federated Testing write-block tests against the built image and publish the result as software read-only policy test results | validation/ | todo |
| 3A.9 | Sandbox every parser: unprivileged user, bubblewrap or `systemd-run` with `PrivateNetwork=yes`, `ProtectSystem=strict`, read-only view of the evidence, one writable output folder, seccomp filter, memory and time limits. Root opens the device once and hands workers a read-only handle | forensic-analyze/sandbox.py | todo |
| 3A.10 | goss and functional tests for 3A.1 to 3A.9, including a disk with LVM, mdraid, and swap signatures that must stay untouched | tests/ | todo |

## Milestone 4: Tool layers and session helpers (v0.2)

Tool selection principle: CLI-first, one tool per artifact class, each with a known maintainer and a Linux-native build. A GUI case manager is optional, not the spine of the workflow. Rationale is in the decision log.

| # | Task | Touches | Status |
|---|---|---|---|
| 4.1 | Role `tools_acquire`: ewf-tools (`ewfacquire`), dc3dd, gddrescue, guymager (GUI imager, Linux-native), hashdeep, ssdeep, afflib-tools, libewf, libvshadow-utils | ansible/roles/tools_acquire/ | todo |
| 4.2 | Role `tools_filesystem`: sleuthkit (`mmls`, `fls`, `istat`, `icat`, `tsk_recover`, `blkls`), libfsntfs-utils, libfsntfs python bindings, ntfs-3g for `ntfsinfo` only | ansible/roles/tools_filesystem/ | todo |
| 4.3 | Role `tools_dissect`: Dissect from PyPI in its own venv under `/opt/dissect`, version pinned; provides `target-query`, `target-shell`, `target-fs`, NTFS, USN, registry, BitLocker, E01 | ansible/roles/tools_dissect/ | todo |
| 4.4 | Role `tools_eztools`: .NET 9 runtime from Microsoft apt repo, then MFTECmd, RBCmd, LECmd, JLECmd, PECmd, EvtxECmd, AmcacheParser, AppCompatCacheParser, RECmd, SBECmd, bstrings from `download.ericzimmermanstools.com/net9`, each pinned by SHA-256 into `/opt/eztools/<Tool>/`, wrapper scripts on PATH | ansible/roles/tools_eztools/ | todo |
| 4.5 | Role `tools_timeline`: Plaso from the GIFT PPA or pinned wheel; Timesketch deferred (needs Docker and a database, wrong fit for a USB stick) | ansible/roles/tools_timeline/ | todo |
| 4.6 | Role `tools_carve`: testdisk (PhotoRec), scalpel, foremost, bulk-extractor, usncarve (USN records from unallocated space) | ansible/roles/tools_carve/ | todo |
| 4.7 | Role `tools_media`: libimage-exiftool-perl (pin to a version above 12.24), mediainfo, ffmpeg, exiv2, vinetto, python3-dissect.thumbcache | ansible/roles/tools_media/ | todo |
| 4.8 | Role `tools_registry`: regripper (Perl), libregf-utils, hivex | ansible/roles/tools_registry/ | todo |
| 4.9 | Role `tools_autopsy`, optional, `install_autopsy=false` by default: Java version read from the Autopsy release notes, Sleuth Kit Java .deb and Autopsy zip pinned by URL and SHA-256, `unix_setup.sh`, desktop launcher | ansible/roles/tools_autopsy/ | todo |
| 4.10 | Role `session_tools`: `forensic-session-start`, `evidence-unlock-output`, `evidence-mount`, `evidence-hash`, `evidence-triage` (runs mmls, fsstat, hash, and a Dissect `target-info` and writes them to the session log). No network toggle exists on the image | ansible/roles/session_tools/files/ | todo |
| 4.11 | All helpers append to `/var/log/forensic-session/<UTC timestamp>.log` | ansible/roles/session_tools/ | todo |
| 4.12 | docs/workflows/windows-external-drive.md: the NTFS deleted-file and media-metadata runbook using 4.1 to 4.8, in order, with the command for each step | docs/workflows/ | todo |
| 4.13 | goss tests: each tool binary present and `--version` runs; `dotnet --list-runtimes` shows 9.x; `target-query --version` runs; helpers present and executable | tests/goss/tools.yaml | todo |
| 4.14 | Functional test: a 64 MB NTFS test image with known created and deleted files, checked into tests/fixtures (built by a script, not hand-made); `fls -rd`, MFTECmd `$MFT` and `$J`, and Dissect `target-query -f mft` must each find the known deleted file names | tests/fixtures/, tests/functional/ | todo |
| 4.15 | Clock handling: with no network there is no time sync. `forensic-session-start` shows the hardware clock in UTC, asks the operator to confirm or correct it against a trusted clock, and logs the answer and any offset | ansible/roles/session_tools/files/ | todo |
| 4.16 | Tag v0.2 | git | todo |

## Milestone 4A: Hash sets and signatures (v0.2)

Two kinds: known-good to discard, known-bad to flag. Pulled during a build-time or update-mode network window, pinned, and logged. ClamAV runs as `clamscan` only; the daemon is masked because on-access scanning quarantines and deletes.

| # | Task | Touches | Status |
|---|---|---|---|
| 4A.1 | Role `tools_hashsets`: clamav, clamav-freshclam (disabled as a service), ssdeep, python3-tlsh, yara, hashdeep | ansible/roles/tools_hashsets/ | todo |
| 4A.2 | NSRL RDSv3 Modern minimal SQLite, release pinned (2026.06.1 at time of writing), SHA-256 from NIST's DBHashes file, stored under `/opt/hashsets/nsrl/`; variable `nsrl_on_image=false` puts it on the output drive instead | ansible/roles/tools_hashsets/ | todo |
| 4A.3 | ClamAV `main.cvd` and `daily.cvd` staged on `ASSETS` by the fetcher and checked with `sigtool` (they carry ClamAV's own signature); `clamav-daemon` and `clamav-freshclam` masked; test asserts both masked | ansible/roles/tools_hashsets/ | todo |
| 4A.4 | MalwareBazaar full SHA-256 export downloaded by the fetcher on the host computer (abuse.ch key used there only, never stored on the drive), converted to a ClamAV `.hsb` on first boot; snapshot date and hash logged | ansible/roles/tools_hashsets/, scripts/fetch-assets.* | todo |
| 4A.5 | YARA rule packs (Neo23x0 signature-base, YARA Forge core) pinned by commit under `/opt/yara/` | ansible/roles/tools_hashsets/ | todo |
| 4A.6 | Helper `evidence-triage-hash`: hashdeep MD5+SHA-1+SHA-256 in one pass, drop NSRL matches via sqlite3, flag ClamAV and `.hsb` hits, YARA and ssdeep on the remainder, CSV out, counts to the session log | ansible/roles/session_tools/files/ | todo |
| 4A.7 | Updates without network: rerun the fetcher on the host computer with `--refresh` to restage ClamAV, MalwareBazaar, YARA, and models. Helper `forensic-import` on the USB system verifies and applies the new set at next boot, logs each artifact's SHA-256, and refuses to run while an evidence disk is attached. OS and tool updates come by reflashing a newer base image; the fetcher keeps a download cache on the host so restaging is quick | ansible/roles/session_tools/files/, scripts/fetch-assets.* | todo |
| 4A.8 | goss tests: hash sets present, clamscan loads the `.hsb`, daemon masked, `forensic-import` refuses with a disk attached | tests/goss/hashsets.yaml | todo |

## Milestone 4B: Local AI triage (v0.2)

Hardware rule: nothing in the build or at runtime depends on a GPU vendor or on any one machine. One image carries the open Vulkan drivers for AMD, Intel, and NVIDIA together, the model tier is picked from measured memory, and a PC with no usable GPU runs the CPU tier. Vendor names below appear only as test coverage (4B.13) or as an optional add-on that is off by default (4B.15). Benchmarks quoted in the research section are background, not requirements.

Purpose: flag sexual and violent content and describe everything else so the examiner never has to view recovered media directly. Output is triage, never evidence. Runtime is GPU-agnostic. Models ship on the image.

| # | Task | Touches | Status |
|---|---|---|---|
| 4B.1 | Role `tools_ai`: llama.cpp built from a pinned release at or after b9562 (native video input via mtmd), `-DGGML_VULKAN=ON`, no CUDA or ROCm; `llama-server` and `llama-mtmd-cli` installed to `/opt/llama/` | ansible/roles/tools_ai/ | todo |
| 4B.2 | Mesa Vulkan drivers (`mesa-vulkan-drivers`, RADV for AMD, NVK or the open NVIDIA kernel module for NVIDIA, ANV for Intel), `vulkan-tools` | ansible/roles/tools_ai/ | todo |
| 4B.3 | Helper `ai-probe`: parses `vulkaninfo --json` for the largest device-local heap. On integrated GPUs that heap is carved from system RAM, so the tier is capped by RAM minus a safety margin. Falls back to the CPU tier if no Vulkan device is found or a model fails to load | ansible/roles/session_tools/files/ | todo |
| 4B.4 | Model tiers in `ansible/group_vars/ai_models.yml`, each GGUF pinned by URL and SHA-256: tier0 (<4 GB or CPU) Qwen3-VL-2B Q4; tier1 (4 to 6 GB) Qwen3-VL-4B Q4; tier2 (6 to 10 GB) Qwen3-VL-8B Q4; tier3 (10 to 20 GB) Qwen3-VL-8B Q8; tier4 (20 GB+) Qwen3-VL-32B Q4. Variable `ai_tiers_on_image` selects which tiers ship (default: tier0 to tier2) | ansible/group_vars/ai_models.yml | todo |
| 4B.5 | Classifier layer in its own venv under `/opt/triage/`: NudeNet (nudity detector with body-part classes) and SigLIP zero-shot via ONNX Runtime on CPU, labels: nudity, sexual activity, violence, weapon, gore, blood, injury, neutral. Models pinned by SHA-256. Licenses recorded in docs/licenses.md | ansible/roles/tools_ai/ | todo |
| 4B.6 | Helper `evidence-screen`: for each image, run NudeNet and SigLIP, write `screen.csv` (path, sha256, nudity score, per-label scores, verdict). Verdict thresholds in a config file, defaults conservative. Flagged files are never sent to the VLM | ansible/roles/session_tools/files/ | todo |
| 4B.7 | Video path: `ffmpeg` samples 1 frame every 2 s plus scene-change frames, each frame through 4B.6; any flagged frame flags the video with timestamps. Audio track through `faster-whisper` small to a transcript. Cleared videos go to `llama-mtmd-cli` native video input for a description | ansible/roles/session_tools/files/ | todo |
| 4B.8 | Helper `evidence-describe`: cleared files only, through `llama-server` on `127.0.0.1`, fixed prompt, temperature 0, fixed seed; output CSV with path, sha256, description, model file hash, prompt hash, tier. A refusal or empty response is logged as `model_declined`, never dropped | ansible/roles/session_tools/files/ | todo |
| 4B.9 | Documents: `pdftotext` and `libreoffice --convert-to txt` first, scanned pages through the VLM OCR path, summary through the same server with the same provenance columns | ansible/roles/session_tools/files/ | todo |
| 4B.10 | `llama-server` systemd unit bound to `127.0.0.1` only, socket-activated, off until `evidence-describe` starts it; goss asserts no listener on any other interface | ansible/roles/tools_ai/ | todo |
| 4B.11 | `evidence-report` renders the final report from the findings store; see Milestone 4E | ansible/roles/session_tools/files/ | todo |
| 4B.12 | Functional tests: a fixture set of neutral synthetic images (generated shapes, text renders, a stock-free landscape) plus EICAR; screen must pass all as neutral, describe must return non-empty text, probe must pick tier0 in QEMU with no GPU. No sexual or violent fixtures are committed to the repo | tests/fixtures/ai/, tests/functional/ | todo |
| 4B.13 | Hardware matrix: tier selection and tokens/s on at least one AMD and one NVIDIA laptop, recorded in docs/hardware-matrix.md | docs/hardware-matrix.md | todo |
| 4B.14 | docs/workflows/media-screening.md: the screen-then-describe runbook, threshold meaning, what a flag does and does not prove, and the stop-and-report rule for suspected child sexual abuse material | docs/workflows/ | todo |
| 4B.15 | Optional NVIDIA proprietary driver through Ubuntu's signed `linux-modules-nvidia` packages, staged by the fetcher and installed offline (no DKMS, no MOK enrolment). Default stays the open driver | ansible/roles/tools_ai/, scripts/fetch-assets.* | todo |
| 4B.16 | Measure the classifiers' false-positive and false-negative rates on a lawful labelled adult and violence benchmark; publish thresholds and results per release. No independent figures exist | validation/classifiers/ | todo |
| 4B.17 | Media stays hidden by default everywhere in the tools: no thumbnails, scores and counts only. Flagged sexual content is never exported or copied | forensic-analyze/, evidence-report | todo |
| 4B.18 | `forensic-escalate`: operator-run stop control. Halts the run, freezes exports, records only path, finding ID, and hash, and shows the stop-and-contact-law-enforcement guidance | ansible/roles/session_tools/files/ | todo |

## Milestone 4C: Guided analysis wizard `forensic-analyze` (v0.2)

Purpose: one command that asks which drive and what to look at in broad terms, then runs the whole analysis unattended and ends with one report. It orchestrates the helpers from Milestones 4, 4A, and 4B. It adds no new analysis logic of its own.

| # | Task | Touches | Status |
|---|---|---|---|
| 4C.1 | `forensic-analyze` in Python (stdlib only), whiptail menus with a plain-prompt fallback; installed on PATH with a desktop launcher | ansible/roles/session_tools/files/forensic-analyze/ | todo |
| 4C.2 | Step 1, target picker: lists attached disks and image files (E01, raw) with model, serial, size, filesystem; never lists the boot stick; refuses a target whose read-only flag is not set; user types the device name back to confirm | forensic-analyze/target.py | todo |
| 4C.3 | Step 2, output picker: the drive's `OUTPUT` partition by default, or an output drive unlocked through `evidence-unlock-output`; free-space check against an estimate for the chosen modules and mode | forensic-analyze/output.py | todo |
| 4C.4 | Step 3, preset: Quick (inventory, recycle bin, hash triage), Standard (Quick plus images, video, audio, documents, timeline), Full (Standard plus carving unallocated space), or Custom checklist | forensic-analyze/presets.py | todo |
| 4C.5 | Module `inventory`: every file, live and deleted, with path, size, MACB times, deleted flag (fls, MFTECmd on `$MFT`) | forensic-analyze/modules/inventory.py | todo |
| 4C.6 | Module `recycle_bin`: `$I` and `$R` pairs with original path, deletion time, owner SID (RBCmd) | forensic-analyze/modules/recycle_bin.py | todo |
| 4C.7 | Module `deletion_history`: USN journal and `$LogFile` delete records, plus usncarve when the Full preset is chosen | forensic-analyze/modules/deletion_history.py | todo |
| 4C.8 | Module `images`: export, exiftool metadata, thumbcache and Thumbs.db, then `evidence-screen` and `evidence-describe` | forensic-analyze/modules/images.py | todo |
| 4C.9 | Module `video`: export, mediainfo and ffprobe metadata, frame screening, description of cleared videos | forensic-analyze/modules/video.py | todo |
| 4C.10 | Module `audio`: export, metadata, faster-whisper transcript, text summary | forensic-analyze/modules/audio.py | todo |
| 4C.11 | Module `documents`: export, metadata, text extraction, summary | forensic-analyze/modules/documents.py | todo |
| 4C.12 | Module `malware`: `evidence-triage-hash` (NSRL drop, ClamAV, MalwareBazaar, YARA, ssdeep) | forensic-analyze/modules/malware.py | todo |
| 4C.13 | Module `users`: owner SIDs, LNK files, Jump Lists, anything that ties files to an account (LECmd, JLECmd, MFTECmd on `$SDS`) | forensic-analyze/modules/users.py | todo |
| 4C.14 | Module `timeline`: Plaso over the target, CSV out | forensic-analyze/modules/timeline.py | todo |
| 4C.15 | Module `carve`: PhotoRec and bulk_extractor over unallocated space; carved media feeds back into the images, video, and audio modules | forensic-analyze/modules/carve.py | todo |
| 4C.16 | Filesystem awareness: `fsstat` decides which modules can run. On exFAT or FAT the NTFS-only modules are skipped and the report says why. BitLocker asks for the recovery key and uses Dissect to unlock, or stops | forensic-analyze/fsdetect.py | todo |
| 4C.17 | Run control: SHA-256 and MD5 of the target before and after (and of the image when one is made), write-request count from the tracer, `run.json` with target identifiers, hashes, modules, exact command lines, tool versions and hashes, model hashes, thresholds, errors and deviations; one done-marker per module so an interrupted run resumes; first module failure is shown immediately and the run continues | forensic-analyze/runner.py | todo |
| 4C.18 | Every prompt has a flag: `forensic-analyze --target /dev/sdb --preset standard --output /cases/x --yes` and `--config run.json` to replay a run exactly | forensic-analyze/cli.py | todo |
| 4C.19 | End-of-run option: purge exported file copies and keep only CSVs, transcripts, descriptions, and the report, so nothing from the drive is retained beyond findings | forensic-analyze/cleanup.py | todo |
| 4C.20 | Final step calls `evidence-report`; the report opens with counts per module, failures and skipped modules first | forensic-analyze/runner.py | todo |
| 4C.21 | Tests: non-interactive Standard run against the NTFS fixture in QEMU must find the known deleted files and the known recycle-bin entry, produce `run.json`, and leave the fixture hash unchanged; a run against an exFAT fixture must skip the NTFS modules with a reason | tests/functional/test_analyze.sh | todo |
| 4C.22 | Write-blocker advisory: before the target picker, `forensic-analyze` and `forensic-session-start` tell the operator to connect the drive through a hardware write blocker, ask whether one is in use, and log the answer in `run.json`. The software read-only flag is described on screen as a second layer, not a substitute | forensic-analyze/target.py | todo |
| 4C.23 | docs/workflows/guided-analysis.md: what each preset runs, rough time per preset, what each report section means | docs/workflows/ | todo |
| 4C.24 | Mode choice at the start, two options: Read directly (default; reads the device through the blocker, no copy kept, a one-line warning each run that nothing can be re-examined later, and the report states the limits) or Copy first (makes a verified image with `ewfacquire`, or `ddrescue` with a map file for weak drives, then analyses the image; needs an output drive as large as the target). `--mode direct` and `--mode image` on the command line | forensic-analyze/mode.py | todo |
| 4C.25 | Examiner and case fields at the start: examiner name, case ID, exhibit ID, authority reference, free-text notes. Defaults can be preset in `profile.json` so nothing has to be typed. Every run's outputs are signed with a key held on `OUTPUT` | forensic-analyze/case.py | todo |
| 4C.26 | Clock record: reference time and its source entered by the examiner, `clock_offset_seconds` stored, system time never silently corrected, monotonic durations logged beside wall-clock times | forensic-analyze/case.py | todo |
| 4C.27 | NTFS interpretation rows marked as inferred, never observed: `$SI` created before `$FN` created, zero sub-second fractions, `$SI` changes with no USN record. Reports say "account SID", never a person's name | forensic-analyze/modules/ | todo |
| 4C.28 | Cross-validation: core artifacts parsed twice (The Sleuth Kit or Dissect against MFTECmd; RBCmd against Dissect), joined on MFT entry and sequence, with agree, disagree, or single-source recorded per row. Disagreements are listed, never resolved silently | forensic-analyze/xval.py | todo |
| 4C.29 | Volume Shadow Copy check on every NTFS target, with "none found" reported explicitly | forensic-analyze/modules/inventory.py | todo |

## Milestone 4D: Findings data model (v0.2)

One canonical store, three generated views. Every module writes findings; nothing else is the system of record.

| # | Task | Touches | Status |
|---|---|---|---|
| 4D.1 | `findings.jsonl`: append-only, one typed object per finding, deterministic order, sorted keys; its SHA-256 goes in `run.json` | forensic-analyze/findings.py | todo |
| 4D.2 | Schema, required fields: `finding_id` (stable, e.g. F-000123), `run_id`, `evidence_id`, `evidence_sha256`, `category`, `artifact_type`, `message`, `derivation` (observed, inferred, ai_generated), `source_tool`, `tool_version`, `parser` | docs/schema.md, forensic-analyze/schema.json | todo |
| 4D.3 | Schema, optional fields: `datetime` (ISO 8601 UTC), `timestamp_desc`, `tz_basis` (utc, local_unknown_offset, local_with_offset), `path`, `filename`, `path_b64`, `inode_ref`, `size_bytes`, `allocated`, `sha256`, `md5`, `owner_sid`, `hashset_name`, `hashset_version`, `match_algorithm`, `score`, `label`, `threshold`, `text`, `confidence`, `xval_status`, `source_record`, `model_id`, `model_sha256`, `prompt_sha256`, `sensitive_flag` | docs/schema.md, forensic-analyze/schema.json | todo |
| 4D.4 | Every module in 4C writes through one `emit()` function that validates against the schema; raw tool outputs (EZ Tools CSVs, Dissect records) are kept as intermediates and pointed to by `source_record` | forensic-analyze/modules/ | todo |
| 4D.5 | `case.sqlite` built from the JSONL, with views: timeline, deleted, recycle bin, media, hash hits, classifier flags, disagreements | forensic-analyze/export_sqlite.py | todo |
| 4D.6 | `findings.csv`: the single flat file, one row per finding with the fixed column set, importable into Timesketch (`datetime`, `timestamp_desc`, `message`) | forensic-analyze/export_csv.py | todo |
| 4D.7 | CSV safety: UTF-8 with BOM, RFC 4180 quoting, embedded newlines escaped, a leading quote added to any cell starting with `=`, `+`, `-`, `@`, tab, or CR; hostile filenames (control characters, bidi overrides) kept raw in `path_b64` and shown escaped | forensic-analyze/export_csv.py | todo |
| 4D.8 | NSRL matching on SHA-256 first, with the algorithm that produced each hit recorded; fuzzy-hash matches marked inferred | forensic-analyze/modules/malware.py | todo |
| 4D.9 | Determinism test: replaying `run.json` against the same image gives byte-identical `findings.jsonl` apart from AI fields; AI fields are compared separately and any drift is reported | tests/functional/ | todo |
| 4D.10 | Optional exports: bodyfile, and CASE/UCO 1.4 JSON-LD later | forensic-analyze/export_*.py | todo |

## Milestone 4E: LLM-drafted report with fixed prompts (v0.2)

The local model drafts the narrative sections from the findings store. Code fills the factual sections. A person signs it. The draft is labelled as AI-generated and is never evidence.

| # | Task | Touches | Status |
|---|---|---|---|
| 4E.1 | Report skeleton filled by code, no model: title and report type, case and exhibit IDs, examiner, request and authority, items received with identifiers and hashes, methodology (image hash, blocker model, observed write count, mode and reason, tools and versions, validation reference), appendices (run summary, hash verification, disagreement table, glossary) | evidence-report/templates/ | todo |
| 4E.2 | Model-drafted sections: results by category, interpretation and limitations, conclusions. The three NIST IR 8354 limitations are inserted verbatim by code | evidence-report/ | todo |
| 4E.3 | Prompts are fixed files in the repo, versioned, with each prompt's SHA-256 recorded per run; greedy decoding, fixed seed; llama.cpp commit, backend, model hash, and quantization recorded | evidence-report/prompts/ | todo |
| 4E.4 | Inputs are structured rows from SQLite views only. Every evidence-derived string is wrapped in a delimited data block with an instruction that it is data, control and bidi characters are stripped, long strings truncated | evidence-report/inputs.py | todo |
| 4E.5 | Map-reduce for small context windows: summarise per category and time window, each partial citing finding IDs; the merge step may only combine cited statements | evidence-report/mapreduce.py | todo |
| 4E.6 | Every sentence must end with finding IDs. A code verifier (not a model) checks that each ID exists and that every number, date, and path in the sentence appears in the cited rows. Failing sentences are removed and listed. Date arithmetic is done in code and passed in | evidence-report/verify.py | todo |
| 4E.7 | Prompt rules: no attribution to a person, no intent, no claims beyond the rows; phrasing such as "account SID" and "the USN journal records a delete at" | evidence-report/prompts/ | todo |
| 4E.8 | Sensitive categories are summarised from counts, scores, and IDs only, never from image content | evidence-report/ | todo |
| 4E.9 | Each AI paragraph is labelled "AI-generated draft", with a line for the examiner's name and date of review; the report is not final until that is filled | evidence-report/templates/ | todo |
| 4E.10 | Injection test set: fixtures whose filenames and document text carry planted instructions; the report must not follow them, and the verifier must catch any unsupported sentence | tests/functional/test_injection.sh | todo |
| 4E.11 | Output: `report.html` and `report.md` on `OUTPUT`, hashed and signed with the rest | evidence-report/ | todo |

## Milestone 4F: Validation suite and published results (v0.2, gates every release)

SWGDE and the UK Forensic Science Regulator both expect methods to be validated as deployed. The project ships the evidence so users can adopt it in their own validation.

| # | Task | Touches | Status |
|---|---|---|---|
| 4F.1 | Script-built NTFS and exFAT images with a ground-truth manifest: files created, modified, deleted, recycled, and timestomped at known times | validation/synthetic/ | todo |
| 4F.2 | Public reference sets with published ground truth: NIST CFReDS deleted-file and carving images, selected Digital Corpora sets, fetched by hash | validation/reference/ | todo |
| 4F.3 | `validation/run.sh` runs the full wizard non-interactively over every set and scores each artifact class against ground truth | validation/ | todo |
| 4F.4 | Per-release validation report: pass or fail per artifact class, parser versions, cross-parser disagreements, classifier error rates (4B.16), write-policy test results (3A.8); signed and attached to the release | validation/report/ | todo |
| 4F.5 | `docs/known-limitations.md`, linked from every generated report | docs/ | todo |
| 4F.6 | Session start shows the image build date and warns past 90 days; the report records image age | ansible/roles/session_tools/files/ | todo |

## Milestone 4G: Test gaps found in review (v0.2)

Added 2026-11-14 after a review of test coverage. The earlier milestones test that things are installed and configured. These test behaviour, failure, and tampering.

| # | Task | Touches | Status |
|---|---|---|---|
| 4G.1 | Unit tests (pytest) for all Python: schema validation in `emit()`, each export, the report verifier, the sandbox wrapper, target and mode pickers. Add ruff to the lint job | tests/unit/, .github/workflows/lint.yml | todo |
| 4G.2 | PowerShell: PSScriptAnalyzer in lint, and a Windows CI runner that runs `fetch-assets.ps1` against a virtual disk and checks the staged files and hashes | tests/windows/, .github/workflows/ | todo |
| 4G.3 | Flash script refusal tests: non-removable disk, the disk holding `/`, a mounted disk, a too-small disk, a wrong typed confirmation. Each must refuse and write nothing | tests/functional/test_flash.sh | todo |
| 4G.4 | Asset tamper tests: a swapped file, a truncated file, an edited manifest, and a bad signature must each be detected at provisioning and at session start, with the feature disabled and named | tests/functional/test_assets.sh | todo |
| 4G.5 | Air-gap behaviour test: boot with a virtual network card attached to a live network and attempt DNS, HTTP, and ping from root. All must fail. Config checks alone (3.8) do not prove this | tests/functional/test_airgap.sh | todo |
| 4G.6 | Write tracer true-positive test: issue a deliberate write and a discard to a scratch disk and confirm the tracer counts them. Without this, a count of zero proves nothing | tests/functional/test_tracer.sh | todo |
| 4G.7 | Sandbox tests: a parser stand-in that tries to write outside its output folder, open a socket, and exceed its memory and time limits must be stopped each time | tests/functional/test_sandbox.sh | todo |
| 4G.8 | Fault tests for the wizard: a virtual disk with injected read errors, a run killed and resumed, an output drive that fills up, and a BitLocker-encrypted fixture with and without the key | tests/functional/test_faults.sh | todo |
| 4G.9 | Tier selection tests: recorded `vulkaninfo` outputs for discrete, integrated, multi-GPU, and no-GPU machines fed to `ai-probe`; the chosen tier must match a table | tests/unit/test_probe.py | todo |
| 4G.10 | Screening true-positive path: no sexual or violent fixtures are committed, so CI cannot prove a real flag. Test the plumbing with a stub classifier that returns fixed scores (flagged files never reach the model, never get exported, show in counts), and rely on 4B.16 for real detection rates | tests/functional/test_screen_stub.sh | todo |
| 4G.11 | Model refusal and empty-output test: a stub model that declines must produce a `model_declined` row, never a dropped file | tests/functional/test_declined.sh | todo |
| 4G.12 | Stop control test: `forensic-escalate` halts a running job, freezes exports, and records only path, ID, and hash | tests/functional/test_escalate.sh | todo |
| 4G.13 | CSV safety tests: fixture filenames starting with `=`, `+`, `-`, `@`, containing newlines, bidi overrides, and invalid UTF-16; the CSV must parse cleanly and carry no live formula | tests/unit/test_csv.py | todo |
| 4G.14 | Report verifier tests: hand-written sentences with a wrong date, a wrong path, a missing citation, and a non-existent finding ID must each be rejected | tests/unit/test_verify.py | todo |
| 4G.15 | Scale test: a fixture with several hundred thousand files; record run time and peak memory per module and fail on regression | validation/scale/ | todo |
| 4G.16 | Refresh test: restage a newer signature set and a changed profile, boot, and confirm `forensic-import` applies it offline and logs the hashes | tests/functional/test_refresh.sh | todo |
| 4G.17 | Manual hardware checklist, one page, run on every machine in the matrix: boots UEFI and BIOS, Secure Boot on, internal disk read-only, scratch drive not mounted and not writable, tier chosen, Quick run completes, report opens on Windows from `OUTPUT` | docs/hardware-checklist.md | todo |
| 4G.18 | First-use test: someone who has not seen the project follows the quickstart on Windows with no help; every point where they stall becomes an issue | docs/quickstart.md | todo |

## Milestone 5: Desktop and service hardening, CI (v0.3)

| # | Task | Touches | Status |
|---|---|---|---|
| 5.1 | Role `harden_desktop`: Nautilus `show-image-thumbnails=never`, remove thumbnailer packages, disable gvfs volume monitor | ansible/roles/harden_desktop/ | todo |
| 5.2 | Mask indexer (`localsearch` on 24.04; confirm name) | ansible/roles/harden_desktop/ | todo |
| 5.3 | Role `harden_services`: mask apport, whoopsie, ubuntu-report, motd-news, unattended-upgrades, avahi-daemon, cups-browsed, ModemManager, geoclue | ansible/roles/harden_services/ | todo |
| 5.4 | Decide snapd: remove it (default) or hold refreshes. Record in decision log | ansible/group_vars/all.yml | todo |
| 5.5 | goss tests for every unit in 5.1 to 5.4 | tests/goss/desktop.yaml, services.yaml | todo |
| 5.6 | GitHub Actions: lint job (ansible-lint, shellcheck, yamllint, packer validate) on every PR | .github/workflows/lint.yml | todo |
| 5.7 | GitHub Actions: build-and-test job, checks `/dev/kvm`, runs tests/run-qemu-tests.sh, uploads image as artifact | .github/workflows/build.yml | todo |
| 5.8 | Re-apply hardening as the last play in site.yml so no tool role can undo it; test asserts order | ansible/site.yml | todo |
| 5.9 | Tag v0.3 | git | todo |

## Milestone 6: Supply chain and signed releases (v0.4)

| # | Task | Touches | Status |
|---|---|---|---|
| 6.1 | Pin apt to a dated snapshot.ubuntu.com mirror during build | packer/http/user-data | todo |
| 6.2 | Every downloaded artifact listed in `ansible/group_vars/pins.yml` with URL, version, SHA-256 | ansible/group_vars/pins.yml | todo |
| 6.3 | Release workflow on tag: build, test, syft SBOM, cosign keyless signature, GitHub Release with image, SHA256SUMS, .sig, SBOM | .github/workflows/release.yml | todo |
| 6.4 | docs/validation-guide.md: how a user proves the stick is read-only on their own hardware with a scratch drive | docs/validation-guide.md | todo |
| 6.5 | Optional role `tools_sift` behind `install_sift=false`, runs Cast, then hardening re-applies; test proves rfkill and automount still hold afterward | ansible/roles/tools_sift/ | todo |
| 6.6 | License review of every bundled package before any prebuilt image is published; EZ Tools redistribution terms, Dissect AGPL, model licences (Qwen3-VL Apache 2.0, NudeNet, SigLIP), and YARA rule pack licences recorded in docs/licenses.md | docs/licenses.md | todo |
| 6.7 | Tag v0.4 | git | todo |

## Milestone 7: Live ISO variant and 1.0 (v0.5, v1.0)

| # | Task | Touches | Status |
|---|---|---|---|
| 7.1 | Evaluate live-build vs Cubic-free ISO remaster for an amnesic variant; record decision | docs/decision-log.md | todo |
| 7.2 | Live ISO build target reusing the same Ansible roles | packer/ or live/ | todo |
| 7.3 | Secure Boot test matrix: three laptops, document results | docs/hardware-matrix.md | todo |
| 7.4 | Outside review: ask two DFIR practitioners to break the read-only guarantees and file issues | github issues | todo |
| 7.5 | README final, docs complete, tag v1.0 | README.md | todo |

# Part 4: Decisions, alternatives, risks

## Decision log

| Date | Decision | Reason |
|---|---|---|
| 2026-11-10 | Ubuntu 24.04 LTS base | Plaso packaged release and SIFT states both list it. LTS support window to 2029. |
| 2026-11-10 | Plain Ubuntu, SIFT optional and off by default | User wants their own build. SIFT adds packages and a network dependency without adding hardening. |
| 2026-11-10 | Packer + Ansible, not mkosi or a shell script | Contributor familiarity, one role per control, testinfra/goss integration. mkosi revisited after v1.0 for reproducibility. |
| 2026-11-10 | Installed image first, live ISO later | Persistence for case logs and tool updates. Live ISO is v0.5. |
| 2026-11-10 | Radios blocked at module level | A soft rfkill can be undone by a desktop click. A module block cannot. Later extended to a full air gap (see below). |
| 2026-11-10 | goss for tests, not testinfra | Single binary, no Python dependency inside the image, YAML readable by non-developers. |
| 2026-11-10 | Hardening is the last play in site.yml | Any tool role (SIFT in particular) can re-enable services. Order plus a test makes that visible. |
| 2026-11-10 | CLI-first tool layer; Autopsy optional and off by default | Autopsy on Linux is a Java app with a hand-pinned Sleuth Kit .deb that breaks on version drift. The Sleuth Kit, Dissect, EZ Tools (.NET 9, Linux-native), Plaso, and exiftool cover the Windows NTFS and media use case without it and are scriptable, testable, and pinnable. |
| 2026-11-10 | Dissect and EZ Tools both installed, not one | They overlap on MFT and USN. EZ Tools are the de facto standard output format that other examiners recognise. Dissect gives one Python API across E01, NTFS, BitLocker, and registry for scripting. Two independent parsers on the same artifact is also a cross-check. |
| 2026-11-10 | Timesketch deferred | Needs Docker and a database. Wrong fit for a bootable stick. Plaso output can be loaded into Timesketch on another machine. |
| 2026-11-10 | Functional test on a synthetic NTFS image | Tool presence tests prove installation, not function. A fixture with known deleted files proves each parser works on this build. |
| 2026-11-10 | llama.cpp with Vulkan, no CUDA or ROCm on the image | One build runs on AMD, NVIDIA, and Intel. Vendor stacks are large, licence-encumbered, and tie the image to one GPU. Vulkan is slower than CUDA on NVIDIA; accepted. |
| 2026-11-10 | Model tier chosen at boot from VRAM, not from GPU vendor | User requirement. `vulkaninfo` reports device-local heap size the same way on every vendor. |
| 2026-11-10 | Dedicated classifiers screen content; the VLM only describes cleared files | Chat-tuned VLMs refuse or soften on sexual and violent content, which is the content that must be flagged. NudeNet and SigLIP zero-shot do not refuse, run on CPU, and give numeric scores with thresholds the examiner controls. |
| 2026-11-10 | Models ship on the image, pinned by hash | User requirement: the stick must be complete offline. Cost is image size (tier0 to tier2 adds roughly 12 GB) and a 64 GB minimum USB. |
| 2026-11-10 | AI output is triage, never evidence | Every AI row carries model hash, prompt hash, tier, and file hash so it can be reproduced, but the finding is always the file and its metadata. |
| 2026-11-10 | ClamAV as `clamscan` only, daemon masked | On-access scanning quarantines and deletes. Nothing on this image may alter a file it did not create. |
| 2026-11-10 | Default install is two-stage: flash a small base image, then self-provision on first boot | Works the same from Windows and Linux with a stock imaging tool. No third-party binaries or models are redistributed, which removes the licence gate on publishing. Provisioning runs on the real hardware, so driver problems show up at once. Cost: two drives staged on different days can differ; the manifest records exactly what each got. |
| 2026-11-10 | Pre-position files in two layers: redistributable tools baked into the base image, everything else staged by a host-side fetcher onto an exFAT `ASSETS` partition | User requirement: the drive should boot with files already in place. Windows cannot write ext4, so a partition both systems can write is the hand-off point. First boot then needs no network. |
| 2026-11-10 | Large data is used in place from `ASSETS`, read-only, not copied to root | Avoids needing double the space and a long copy on first boot. Read-only plus a per-boot hash check keeps a Windows-writable partition from being a tamper path. |
| 2026-11-10 | Air gap is the default and only shipped profile: the USB system has no working network path | User requirement: little to no internet contact, ever. All downloads happen on the host computer through the fetcher. Network services are masked and a drop-all firewall backs that up. |
| 2026-11-10 | No username or password: locked-password `analyst` account, autologin, passwordless sudo, no SSH server | User requirement. A locked password is safer than a published default one, because there is nothing to guess. With no network, there is no remote login surface. |
| 2026-11-10 | Updates arrive by restaging `ASSETS` or reflashing, never by the USB system going online | Keeps the air gap. Cost: the operating system and parsers age between reflashes. |
| 2026-11-10 | Findings live in one JSONL stream; SQLite and a single flat CSV are generated from it | Research: one flat CSV as the system of record loses types and mishandles hostile filenames and newlines. The CSV the user asked for still exists, as an export with a fixed column set. |
| 2026-11-10 | The LLM drafts only the narrative sections, from structured rows, with fixed hashed prompts, mandatory finding-ID citations, and a code verifier | Michelet and Breitinger 2024; Kim, Kim and Min 2026; Breitinger et al. 2026. Evidence text is attacker-controlled, so it is never given to the model as instructions. |
| 2026-11-10 | Software read-only is called a policy, not a write blocker, and is backed by a write tracer | Suhanov; NIST CFTT. A recorded count of zero write requests is evidence the host did not modify the target. |
| 2026-11-10 | Hardware-neutral by rule: no vendor-specific build step or required component | The audience is the public, on whatever x86_64 PC they have. Vendor-specific items are limited to test coverage and optional add-ons. Minimum hardware is published as capacities (RAM, drive size), never as brands or models. |
| 2026-11-10 | Both modes offered; Read directly is the default | User decision. SWGDE 18-F-001-2.0 prefers analysing a copy, and SWGDE 17-F-002-2.1 accepts documented triage. The wizard warns on each direct run and the report records the mode. |
| 2026-11-10 | Separate `OUTPUT` partition; `ASSETS` read-only during runs | Keeps the signed asset set unchanged and makes reports readable on Windows. |
| 2026-11-10 | Examiner name and case fields recorded per run, outputs signed | The no-login design gives logs no accountable operator. ACPO principle 3 and SWGDE documentation duties need one. Presets avoid typing. |
| 2026-11-10 | Parsers run sandboxed and unprivileged | An air-gapped system ages; sandboxing limits what a parser bug in exiftool or ffmpeg can reach. |
| 2026-11-10 | No automated detection of minors | The research suggested an automatic child-related flag. Not adopted: an age classifier that is wrong in either direction does harm, and the legal position needs counsel. The stop control is operator-run (4B.18). |
| 2026-11-10 | One entry point, `make-usb.sh`, from clone to bootable drive | User requirement. Build and flash stay separate scripts underneath so CI can run them apart. |
| 2026-11-10 | Bootloader installed to the removable-media path, UEFI and BIOS | A Packer-built image registers its boot entry in the build VM's firmware, which does not travel with the drive. The fallback path boots on any machine. |
| 2026-11-10 | Build host is Linux x86_64 with KVM only | Packer with QEMU and raw USB writes are not practical natively on Windows or macOS. Windows users get a documented workaround, and prebuilt images later (gated on 6.6). |
| 2026-11-10 | One guided entry point, `forensic-analyze`, on top of the single-purpose helpers | User requirement: point at a drive, pick broad categories, get a total analysis. The wizard only orchestrates, so each helper stays testable and usable alone. |
| 2026-11-10 | Every wizard prompt has a flag, and each run writes a replayable `run.json` | An interactive-only tool cannot be tested in CI and cannot be reproduced. The same code path serves the menus and the test suite. |
| 2026-11-10 | Wizard reads the device directly through the blocker; imaging stays optional | User does not want to store an image. The before-and-after device hash is the integrity check. |
| 2026-11-10 | Hash sets and AI models refreshed by restaging from the host, applied by `forensic-import` | Superseded the earlier `forensic-update` network window when the air gap became the default. |

## Rejected alternatives

1. One shell script: no idempotence, no per-control tests.
2. mkosi: better reproducibility, fewer contributors know it, revisit after v1.0.
3. NixOS: strongest reproducibility, small forensic package set, steep learning curve.
4. Fork SIFT's Salt states: ties the project to SIFT's pace and does not add hardening.
5. Container: shares host kernel, controls nothing at boot.
6. Ubuntu Core / snap-based image: snap confinement fights the udev and blockdev controls.
7. Ollama as the AI runtime: convenient, but it auto-downloads, auto-updates, and binds a network service by default. llama.cpp gives one static binary with no network behaviour.
8. CUDA and ROCm builds per vendor: two images, two driver stacks, and the image stops being hardware-agnostic.
9. Using the VLM to classify sexual or violent content: refuses or softens, and gives no numeric score to threshold.
10. Shipping models as a separate download: breaks the "complete offline stick" requirement.

11. One flat CSV as the system of record: sparse columns, lost types, and unsafe with hostile filenames. Kept as an export only.
12. Letting the model read raw document text or filenames as part of its instructions: open to evidence-borne prompt injection.
13. An automatic child-content classifier: see the decision log.

## Surviving risks

1. Root can clear the read-only flags. Logging is not enforcement.
2. Mounting a hostile filesystem exposes kernel parsers. `evidence-mount` is a convenience, imaging plus userland parsing is the safe path.
3. Out-of-tree or USB radio drivers may bypass the module block. Hardware matrix testing in 7.3 is the only check.
4. Secure Boot on some laptops may refuse the image. Unknown until 7.3.
5. GitHub-hosted CI without KVM may be too slow for the full build. Self-hosted runner fallback.
6. Autopsy's Java and Sleuth Kit .deb pairing changes per release. The pin file must be updated by hand on each Autopsy bump. Mitigated by making Autopsy optional.
7. EZ Tools: the research reports MIT licences on Eric Zimmerman's repositories, which corrects this plan's earlier claim that they are not open source. Confirm each repo's LICENSE in 6.6 before baking them into the base image. They are still downloaded as prebuilt binaries, so pin by SHA-256.
8. Dissect is AGPL-3.0. Fine to install and run; check the implications before bundling it into a published image.
9. No legal validation. README says so.
10. Classifier accuracy is not uniform. Nudity detection is mature; violence and gore detection by zero-shot labels is weaker and will produce false positives on medical, sports, and news imagery and false negatives on stylised or low-resolution content. Thresholds are a trade-off the examiner must set, and the runbook says a cleared file is "not flagged by this model at this threshold", not "safe".
11. The screening pipeline can surface suspected child sexual abuse material. The runbook rule is: stop processing, do not open or copy the file, preserve the drive as-is, and contact law enforcement (in the US, the FBI or the local ICAC task force). The pipeline does not and must not attempt age estimation.
12. Vulkan on NVIDIA depends on which driver Ubuntu ships with the generic kernel. NVK coverage and performance vary by GPU generation. Hardware matrix testing (4B.13) is the only check.
13. Model weights and classifier weights are large binaries from third-party hosts. If a host removes a file, the pinned build fails closed. Mirror the pinned files to the project's own release assets once licences are confirmed (6.6).
14. The wizard makes a full analysis one keypress away, which makes it easy to run without thinking about authority to examine the drive. The first screen states that the operator must have the owner's permission or legal authority, and logs the acknowledgement.
15. A direct-from-device Full run reads the whole drive several times. On a failing drive that can finish it off. The wizard checks SMART where the bridge exposes it and warns before a Full run.
16. Image size: OS plus tools plus tier0 to tier2 models plus ClamAV is in the 20 to 25 GB range before NSRL. NSRL Modern minimal adds several GB more. Minimum USB is 64 GB; 128 GB if NSRL ships on the image.

17. The one-command promise holds only on a Linux build host with KVM. It needs tens of GB of downloads, roughly 80 GB of free disk (estimate), and likely more than an hour for a full profile. A Windows-only user cannot run it natively.
18. "Boots anywhere" is tested on QEMU plus the laptops in the hardware matrix, nothing more. Secure Boot policy, firmware USB-boot settings, and very new GPUs can each stop a given machine.
19. A USB flash stick is slow for a 20 GB+ OS with multi-GB models. A USB SSD is the practical target; the quickstart says so.

20. Staging depends on every pinned download host being reachable from the host computer on the day the fetcher runs. A missing file fails closed with the name of the artifact.
21. Rufus in its default ISO mode will not write the image correctly. The quickstart must say DD mode in bold.

22. `ASSETS` is writable from any computer the drive is plugged into. Anyone with the drive can swap a model or hash set. The per-boot hash check detects it; it does not prevent it.
23. `ASSETS` has a fixed size because exFAT cannot be grown in place with the stock tools. A profile bigger than the partition (all model tiers plus NSRL) needs the larger published image variant or the network path.
24. Whether Windows assigns a drive letter to the `ASSETS` partition on every USB drive type is untested. The fetcher falls back to naming the volume by label and tells the user if it cannot find it.

25. No password means anyone holding the drive has the full system and any case output left on it. The drive is not encrypted. Purge case data after each job or keep output on a separate drive.
26. An air-gapped system gets no security patches. Parsers such as exiftool and ffmpeg read hostile files, and their bugs get fixed upstream over time. Reflash from a current base image on a schedule; the session log shows the image's build date and warns once it is older than 90 days.
27. No time sync. Session logs are only as accurate as the PC's hardware clock plus the operator's check.

28. Direct triage leaves nothing to re-examine if the drive fails or is returned, and a second tool can never be run later. The report states this whenever that mode is used.
29. LLM report drafts can still be wrong after the verifier passes: the verifier checks that values appear in cited rows, not that the sentence's meaning is right. Human review is the control.
30. GPU inference may not be bit-for-bit repeatable across hardware even with greedy decoding. AI fields are excluded from the determinism guarantee.
31. No one views flagged media, so nothing in the pipeline would recognise child sexual abuse material unless the operator sees an indication elsewhere (filenames, descriptions of cleared files). Counsel should review this gap before the tool is used on drives where that is a possibility.
32. No independent error rates exist for the classifiers. Until 4B.16 is done, flag counts are unvalidated.

## First session, in order

1. 0.1 to 0.10 (scaffold).
2. 1.1 to 1.11 (unhardened image that boots under UEFI and BIOS).
3. Stop. Flash it (2.x) and boot one real laptop before writing any hardening, so hardware problems surface before control problems.
