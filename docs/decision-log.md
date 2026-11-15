# Decision log

Every design decision, with its date and reason. Seeded from the build plan (Part 4) on 2026-11-15.
New entries go at the end of the table, in the same commit as the change they describe.

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
| 2026-11-15 | Project name AIRLOCK (Air-gapped, Isolated, Read-only, Locked-down, Offline Case Kit) | Owner asked for a short acronym name that says what the drive does. Resolves 2.6.2 (name). |
| 2026-11-15 | Licence Apache-2.0 | Owner decision (2.6.2). Explicit patent grant; fine alongside separately installed AGPL tools (Dissect, NudeNet). |
| 2026-11-15 | Default profile ships AI tiers 0 to 2; NSRL lives off-drive (`nsrl_on_image=false`) | Owner decision (2.6.3). Sets `assets_partition_gib` to 20 and keeps the 64 GB minimum drive. |
| 2026-11-15 | Packer stays the build tool for now; the 0.11 Packer-vs-mkosi spike is left for a host with KVM | The authoring environment has no KVM, so two full builds per tool are not practical there. The decision log entry of 2026-11-10 (Packer + Ansible) stands until the spike runs. Resolves inconsistency 2.5.2 by keeping the Packer rows. |
| 2026-11-15 | Desktop: GNOME via `ubuntu-desktop-minimal` | Task 1.8 already names it; the lockdown controls (dconf, Nautilus, localsearch) are written for GNOME. Resolves 2.6.4. |
| 2026-11-15 | Python packages live under `ansible/roles/session_tools/files/pylib/` (`forensic_analyze`, `evidence_report`, `airlock_common`); commands under `.../files/bin/` | Python cannot import hyphenated package names such as `forensic-analyze/`. The plan's `forensic-analyze/x.py` paths map to `pylib/forensic_analyze/x.py`. |
| 2026-11-15 | Shared Ansible variables live in `ansible/group_vars/all/` (`main.yml`, `pins.yml`, `ai_models.yml`, `profiles.yml`) | A file at `group_vars/pins.yml` would only apply to an inventory group named `pins`. `group_vars/all/` applies to every host. |
| 2026-11-15 | Manifest signature uses an OpenSSL Ed25519 raw signature (`openssl pkeyutl -rawin`) | OpenSSL is already on every Ubuntu image, so verification needs no new dependency and stays standard-library Python plus a stock CLI. cosign still signs the release image (6.3). |
| 2026-11-15 | Pins whose host was unreachable from the authoring environment carry `sha256: null` and are refused until filled | GitHub release assets, HuggingFace, and the EZ Tools host were blocked there. Failing closed is safer than an invented hash. `scripts/check-pins.py` lists them and the release workflow fails on any. |
| 2026-11-15 | Tasks that touch the same file are committed together, with every task number in the commit message | Rule 2.1.2 asks for one task per commit. Several tasks (for example 2.1 to 2.5) edit one script, so one commit per file group is the closest practical form. |

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
