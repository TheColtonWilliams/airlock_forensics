# Threat model

What AIRLOCK protects against, what it does not, and which known risks remain. Copied from
section 1.4 of [build-plan.md](build-plan.md) (task 0.7); the numbered risks are the
"Surviving risks" list in [decision-log.md](decision-log.md). Read
[known-limitations.md](known-limitations.md) with it.

**AIRLOCK is not a write blocker and is not court-validated.** Its read-only layer is a software
read-only policy, a second line of defence behind a hardware write blocker.

## Who and what

* **The analyst** uses an AIRLOCK drive on a bare-metal PC to look at a drive or image that may
  hold hostile content. The analyst is trusted, but can make mistakes.
* **The evidence** (the target drive or image) is untrusted. Its file names, file contents,
  filesystem structures, and firmware may be built to attack the tools that read them.
* **The AIRLOCK drive** carries the operating system, the tools, and the case output. The `ASSETS`
  partition can be written by any computer it is plugged into.
* **The host computer** that builds the image or stages `ASSETS` is online. Downloads happen
  there and are checked against pinned SHA-256 hashes and a signed manifest.

## Protects against

Each item starts with the plan's text, then says how AIRLOCK does it.

1. **Accidental writes to evidence from the analyst workstation.** Nothing auto-mounts; every
   attached disk is set read-only; analysis reads the raw device or image and never mounts it; a
   write tracer counts write requests to the target during a run (expected: zero). Controls:
   [controls.md](controls.md), Storage and Run-time controls.
2. **The workstation auto-processing hostile files (thumbnails, indexers, previews, cloud AV
   uploads).** Thumbnailers removed, indexers and volume monitors masked, no network for any
   upload, parsers sandboxed with no network and one writable folder.
3. **Radio and network leakage during evidence handling.** Radio modules cannot load, rfkill
   blocks every radio, every network service is masked, a drop-all firewall backs that up, and
   there is no switch to turn the network on.
4. **Background updates changing tool versions mid-case.** Update services, snaps, and telemetry
   are off. Tools change only when you restage `ASSETS` or rewrite the drive, and the provisioning
   manifest records every version and hash.
5. **Swap or hibernate writing to evidence disks.** Swap units and hibernate targets are masked,
   `noresume` is on the kernel command line, and swap partitions on attached disks are never
   activated.

## Does not protect against

1. **Malicious firmware in the evidence drive or its USB bridge.** The drive can change its own
   contents whatever the host does. Use a hardware write blocker with a published test report
   ([write-blockers.md](write-blockers.md)).
2. **Kernel bugs triggered by hostile filesystems. Mitigation: image first, then parse in
   userland with The Sleuth Kit instead of mounting.** The wizard parses in user space with The
   Sleuth Kit and Dissect and never mounts the target. `evidence-mount` is a convenience for image
   files only, and it warns (risk 2).
3. **A user who turns the protections off on purpose.** Root can clear the read-only flag
   (risk 1). `evidence-unlock-output` logs when a drive is made writable; logging is not
   enforcement.
4. **Physical tampering with the USB stick itself.** The drive has no password and is not
   encrypted (risk 25). `ASSETS` can be rewritten by any computer (risk 22); the per-boot hash
   check against the signed manifest detects a change, it does not prevent it.
5. **Classifier error. A file the screen clears is "not flagged by this model at this
   threshold", not "safe". AI output is triage, never evidence.** See risks 10, 29, 30 and 32.

## Surviving risks that touch this model

| Risk | In short | Where it is handled |
|---|---|---|
| 1 | Root can clear the read-only flags | [validation-guide.md](validation-guide.md), write tracer in every run |
| 2 | Mounting a hostile filesystem exposes kernel parsers | analysis never mounts; `evidence-mount` warns |
| 3 | Out-of-tree or USB radio drivers may bypass the module block | rfkill, masked services and firewall as further layers; [hardware-matrix.md](hardware-matrix.md) |
| 4, 18 | Secure Boot or firmware may refuse the drive on some PCs | [hardware-matrix.md](hardware-matrix.md), [hardware-checklist.md](hardware-checklist.md) |
| 9 | No legal validation | this page and the README say so; [validation-guide.md](validation-guide.md) |
| 11, 31 | Screening can surface suspected child sexual abuse material; nothing detects it automatically | operator-run stop control `forensic-escalate`; no age or child detection by design |
| 13, 20 | A pinned download host can remove a file | the build and the fetcher fail closed and name the file |
| 22 | `ASSETS` is writable from any computer | per-boot hash check against the signed manifest |
| 25 | No password, no disk encryption | purge case data after each job or keep output on a separate drive |
| 26 | An air-gapped system gets no security patches | monthly rebuild ([release-process.md](release-process.md)); the session warns after 90 days |
| 27 | No time sync | the operator confirms the clock at session start; the offset is logged |
| 28 | Direct triage leaves nothing to re-examine | the report says so; the copy-first mode is offered |

## Trust boundaries

* **Build host to image:** every download is pinned by URL, version, and SHA-256
  (`ansible/group_vars/all/pins.yml`); apt uses a dated snapshot.
* **Host computer to `ASSETS`:** the fetcher checks each file's SHA-256 before and after copying;
  the drive checks them again at every boot against a manifest whose Ed25519 signature is checked
  with a public key built into the image.
* **Evidence to tools:** evidence is read through a read-only handle by sandboxed, unprivileged
  parsers with no network. Text from evidence is data: it never reaches a shell, and it reaches the
  local model only inside a delimited data block, never as an instruction.
* **Release to user:** `SHA256SUMS` is signed with cosign (keyless, tied to the release workflow);
  see [release-process.md](release-process.md) for how to check it.
