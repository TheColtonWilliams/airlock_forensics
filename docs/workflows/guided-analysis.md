# Guided analysis with `forensic-analyze`

`forensic-analyze` is the one command that analyses a drive or an image. It asks a few questions,
runs every chosen module unattended, and ends with one report. Every question has a command-line
flag, so a run can be scripted, tested, and replayed exactly.

Run it as root: `sudo forensic-analyze`. It reads drives directly and never mounts them.

## Before you start

1. **Authority.** The first screen asks you to confirm that you have the owner's permission or the
   legal authority to examine the drive. Your answer is logged. Flag: `--authority-ack`.
2. **Hardware write blocker.** Connect the evidence drive through a hardware write blocker if you
   have one. AIRLOCK also sets a *software read-only policy* on every attached drive. That policy
   is a second layer, not a substitute for a write blocker. You are asked whether one is in use;
   the answer goes in `run.json`. Flags: `--write-blocker yes|no|unknown`, `--blocker-make`,
   `--blocker-model`, `--blocker-firmware`, `--blocker-report-url` (a link to its NIST CFTT or DHS
   test report).
3. **Case fields.** Examiner name, case ID, exhibit ID, authority reference (warrant, order, or
   consent number), and notes. Defaults come from `case_defaults` in the ASSETS `profile.json`, so
   nothing has to be typed. Flags: `--examiner`, `--case-id`, `--exhibit-id`, `--authority-ref`,
   `--notes`, `--agency`.
4. **Clock check.** Read the time from a trusted clock (a phone or a radio clock) and enter it in
   UTC, for example `2026-11-15T14:03:00Z`. AIRLOCK stores the difference as
   `clock_offset_seconds`. It never changes the system time. Flags: `--reference-time`,
   `--reference-source`.

## The steps

| Step | Question | Flag | Default |
|---|---|---|---|
| 1 | Which drive or image? Lists attached drives (never the AIRLOCK drive itself) and image files (E01, raw, dd, img) with model, serial, size, and filesystem. A drive whose read-only flag is not set, or that is mounted, is refused. You type the drive name back to confirm. | `--target PATH` (`--images-dir DIR` adds images to the list; `--yes` replaces the typed confirmation) | none |
| 2 | Read directly, or copy first? | `--mode direct\|image`, `--imager ewf\|ddrescue` | `direct`, `ewf` |
| 3 | Where do results go? | `--output DIR` | the drive's `OUTPUT` partition |
| 4 | What to look at? | `--preset quick\|standard\|full\|custom`, `--modules a,b,c` | `quick` |

Other flags: `--bitlocker-key-file FILE`, `--purge-exports`, `--config run.json` (replay),
`--resume RUN_DIR`, `--dry-run` (show the plan only), `--list-targets`, `--list-modules`,
`--verify RUN_DIR`, `--purge-run RUN_DIR`.

A complete non-interactive run:

```
sudo forensic-analyze --authority-ack --target /dev/sdb --preset standard \
    --examiner "A. Examiner" --case-id C-2026-001 --exhibit-id EX-1 \
    --reference-time 2026-11-15T14:03:00Z --reference-source phone --write-blocker yes --yes
```

## Modes

* **Read directly** (default). Reads the drive through the write blocker and keeps no copy. Each
  run prints a one-line warning: if the drive fails or is returned, nothing can be re-examined and
  no other tool can be run later. The report states these limits. This is documented triage
  (SWGDE 17-F-002-2.1).
* **Copy first** (`--mode image`). Makes an E01 with `ewfacquire`, or a raw copy with `ddrescue`
  and a map file for weak drives (`--imager ddrescue`). The copy is checked against the drive's
  hash, the drive is hashed again, and then the copy is analysed (SWGDE 18-F-001-2.0). The output
  drive must have room for the whole drive.

## Presets

| Preset | Modules | Rough time, 500 GB drive | Rough output |
|---|---|---|---|
| Quick | inventory, recycle bin, deletion history, malware and hash triage | about 5 hours | about 4 GB |
| Standard | Quick plus users, images, video, audio, documents, timeline | about 1 day | about 110 GB |
| Full | Standard plus carving of unallocated space | about 2 days | about 200 GB |
| Custom | the modules you tick | depends | depends |

Times assume a USB 3 SSD at about 150 MB/s and include two full read passes for the before and
after hashes. Copy-first mode adds a copy and a verify pass, and needs output space for the whole
drive. Media, document, and timeline modules scale with the number of files, not the drive size,
so treat these as planning numbers only. `--dry-run` shows the estimate for the actual target.

Modules that are not installed on this build are listed as "not available". Modules that need NTFS
(for example the recycle bin and deletion history) are skipped on exFAT, FAT, or ext volumes, and
the report says why.

Before a **Full** run that reads a drive directly, AIRLOCK asks the drive for its SMART health (a
read-only query). If the drive reports failing health or bad-sector counters, you are warned that
a Full run reads the drive several times and can finish it off, and asked whether to go ahead.
`--mode image --imager ddrescue` is the safer choice for a weak drive.

## What happens during a run

1. Checks: the drive is read-only and not mounted. HPA and DCO are queried with `hdparm`
   (read-only queries; nothing is set or removed) on ATA drives. SSDs and flash drives get a
   warning that their own garbage collection can change the hashes.
2. The **write tracer** samples the kernel's write and discard counters for the drive.
3. SHA-256 and MD5 of the drive, in one read pass. Unreadable sectors are hashed as zeros (the
   same bytes a `ddrescue` copy holds), listed in `run.json`, and the run continues.
4. Copy-first mode makes and verifies the copy.
5. Root opens the drive once as a kernel read-only loop device. Every parser runs in a
   **sandbox**: as the unprivileged `airlock-parse` user, with no network, a read-only view of the
   system and the evidence, one writable output folder, a seccomp filter, and memory and time
   limits. The method used (bubblewrap, `systemd-run`, or the `unshare` fallback) is in `run.json`.
6. Filesystems are detected with `mmls` and `fsstat`. A BitLocker volume needs the recovery key
   (`--bitlocker-key-file`, a file holding the 48-digit recovery password or a `.BEK` startup key).
   Dissect's `fve-dd` writes a decrypted working copy into `decrypted/` in the run folder; it is
   read-only and analysed instead. Without the key the run stops and says so. The key is never
   written to any log.
7. Modules run in a fixed order. If a module fails, the failure is shown at once and the run
   continues.
8. The tracer is sampled again and the drive is hashed again. The expected write-request count is
   0, and the before and after hashes must match.
9. Findings are merged into `findings.jsonl`, exported to `findings.csv` and `case.sqlite`, and
   `evidence-report` writes `report.html` and `report.md`.
10. With `--purge-exports`, every exported file copy is deleted (see below).
11. `outputs.sha256` lists every file in the run folder and is signed with the output drive's key,
    which is kept on the AIRLOCK drive's root filesystem, not on the output drive.

## Interrupted runs

Each finished module leaves a `.done` marker. If the run is killed, the power fails, or the output
drive fills up, continue with:

```
sudo forensic-analyze --resume /srv/airlock/output/cases/C-2026-001/R-20261115T140300Z-1a2b3c
```

Finished modules are not run again. A module that was cut off starts again from the beginning.

## Replaying a run

`forensic-analyze --config RUN_DIR/run.json --authority-ack --yes` runs the same target, mode,
preset, modules, and case fields again. Flags given on the command line override the saved values.
The authority confirmation and the clock check are per run and are not replayed.

## The run folder

```
<output>/cases/<case_id>/<run_id>/        run_id = R-<YYYYMMDDTHHMMSSZ>-<6 hex>
  run.json            the replayable configuration and every result (sorted keys)
  findings.jsonl      the system of record, one finding per line
  findings.csv        flat export, importable into Timesketch
  case.sqlite         the same rows with ready-made views
  report.html report.md
  modules/<name>/     intermediates, raw tool output, findings.part.jsonl, .done
  logs/run.jsonl      the run's own log
  image/              the copy, in copy-first mode only
  outputs.sha256      SHA-256 of every file above
  outputs.sha256.sig  Ed25519 signature of outputs.sha256
  outputs.sha256.pub.pem  the public key that checks it
  outputs.sha256.prev-<n>[.sig|.pub.pem]  earlier signed lists, kept when the run is re-signed
```

`run.json` holds: the configuration, the exact command line, the target's identifiers (model,
serial, size, read-only flag, HPA/DCO and SMART results), SHA-256 and MD5 before and after (and of
the copy), the mode and its limits, the write-request count, the sandbox method, every tool's exact
command line with its version and binary SHA-256, model hashes and screening thresholds, each
module's status, reason, and counts, errors and deviations, the examiner and case fields, the clock
record, the write-blocker record, and the authority acknowledgement.

## Checking a run folder

On AIRLOCK: `forensic-analyze --verify RUN_DIR`. On any Linux machine, from inside the folder:

```
sha256sum -c outputs.sha256
openssl pkeyutl -verify -pubin -inkey outputs.sha256.pub.pem -rawin \
    -in outputs.sha256 -sigfile outputs.sha256.sig
```

The private signing key is not on the output drive. It is made the first time an output drive is
used on this AIRLOCK drive and kept on the root filesystem at
`/var/lib/airlock/signing/<key id>/key.pem` (root only, mode 0600). The output drive holds only
`.airlock/signing/key-id` (which key signs for it) and a copy of the public key. When the key is
made, its public-key SHA-256 is written to the session log (`signing_key_created`), and every
signing records it again (`outputs_signed`, `outputs_resigned`). `--verify` prints the run's
public-key SHA-256 and says whether this AIRLOCK drive holds that key.

What a valid signature shows: the files match the list, and the list was signed by the key whose
public half is in the run folder. It does not show that nobody changed the output drive: anyone
holding it can change files and sign a new list with a key of their own, and the commands above
still pass. `run.json` records the public-key SHA-256, but `run.json` is on the same drive and can
be changed with the rest. To tie a run to AIRLOCK, compare the fingerprint with a record kept off
the output drive: the session log on the AIRLOCK drive that made the run, or the fingerprint you
wrote in your case notes at the time. See `docs/known-limitations.md`.

Re-signing a run (`evidence-report RUN_DIR` by hand, or `--purge-run`) checks the run first and
refuses if anything other than the files that command replaces has changed, so a file edited on
another PC (for example `findings.csv` saved from a spreadsheet) is never given a fresh signature.
`--force` re-signs anyway; the override and the problems it covered are recorded in
`logs/run.jsonl` and the session log. Each re-sign keeps the previous list, signature and public
key as `outputs.sha256.prev-<n>`, `.sig` and `.pub.pem`; they are listed in the new
`outputs.sha256`, so the newer signature covers them. Check an earlier list against its own key
with the `openssl` command above, using the `prev-<n>` names.

## Purging exported copies

`--purge-exports` (at the end of a run) or `forensic-analyze --purge-run RUN_DIR` (later) deletes
every copy of a file taken from the drive and keeps findings, CSVs, transcripts, descriptions, logs,
and the report. Purged: `modules/<name>/export/`, `modules/<name>/exports/`,
`modules/<name>/carved/`, `extract/` (system files such as `$MFT`), and `decrypted/`. The copy made
in copy-first mode (`image/`) is evidence and is kept. `--purge-run` checks the run first and
refuses if anything outside the purged folders has changed (`--force` overrides it and is logged);
`outputs.sha256` is then rewritten and signed again, and the previous one is kept as
`outputs.sha256.prev-<n>`.

## The report

The report opens with counts per module, with failed and skipped modules listed first so nothing
missing is overlooked. Then:

* **Run and evidence**: case fields, examiner, authority reference, target identifiers, the mode
  and its limits, hashes before and after, the write-request count, the write-blocker record, and
  the clock record.
* **Results** by category: file inventory, recycle bin, deletion history, users and accounts
  (account SIDs only, never a person), malware and hash hits, media, documents, and the timeline.
  Each statement cites finding IDs from `findings.jsonl`.
* **AI-drafted sections**, each labelled "AI-generated" with the model and prompt SHA-256. They are
  a draft for the examiner to review, never evidence.
* **Limitations**: the NIST IR 8354 limitations, the read-directly limits when that mode was used,
  and any deviations and errors from `run.json`.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Run complete. |
| 1 | Stopped. The message says what failed and what to do next. |
| 2 | A flag or an answer is missing or wrong. |
| 3 | Run complete with integrity warnings: a hash changed, write requests were counted, the copy could not be verified, or the drive had read errors. Read `run.json` before relying on the results. |
| 130 | Stopped by the operator (Ctrl+C). Continue with `--resume`. |

## For developers

The module API is in `docs/dev/contract.md` sections 8 and 8a. `ctx.tool(...)` runs a tool
sandboxed and records it; it returns a `CompletedProcess` and raises
`airlock_common.proc.ToolError` only when the tool is missing or breaks its time limit. Modules put
exported file copies under `modules/<name>/export/` so the purge finds them, and log
`ctx.log("model_used", model_id=..., model_sha256=..., prompt_sha256=..., threshold=...)` so the
model record reaches `run.json`.

Test-only: `AIRLOCK_EXTRA_MODULES` is a `:`-separated list of extra module files. The functional
tests use it to register small test modules when the real module of that name is not installed. It
is never set on the image. `AIRLOCK_SANDBOX` forces a sandbox method in tests.
