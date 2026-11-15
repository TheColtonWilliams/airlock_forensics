# Known limitations

Read this before you rely on anything AIRLOCK reports. Every validation report and every case
report (`evidence-report`) links here. It lists what the tool cannot show, in plain words. Each
item says where it comes from: NIST IR 8354, a surviving risk in `docs/decision-log.md` (risk number), or
what the validation suite (`docs/validation.md`) measured.

## The three limitations every report states (NIST IR 8354)

1. **Not all evidence may be found.** A tool finds what its parsers understand. Overwritten,
   encrypted, damaged, or unfamiliar data can be missed. "Not found" never means "not there".
2. **Recovered deleted files may include material that did not belong to them.** A deleted
   file's clusters can be reused. What comes back can mix the old file with later data, and a
   carved file can be a fragment or two files joined.
3. **What an artifact means can change between operating system versions.** A recycle bin
   record, a USN record, or a timestamp rule means what it meant on the Windows version that
   wrote it. Check the meaning for the version on the drive.

## What the analysis covers

* **NTFS only for most modules.** File inventory, recycle bin, deletion history, users, and
  timestomp patterns read NTFS volumes only. On exFAT and FAT volumes only the timeline and
  carving run; inventory and deleted-file listing are reported as unsupported. Measured on the
  synthetic exFAT set.
* **Small deleted files cannot be carved.** NTFS keeps files smaller than about 700 bytes
  inside their MFT record. Once deleted, they are not in unallocated space, so carving cannot
  bring them back. Measured: the first synthetic run missed three small deleted pictures until
  they were made larger.
* **Carved files have no name, folder, or times.** Only content and offset are known.
* **Times shown to the second.** File system times in the timeline and the inventory index come
  from The Sleuth Kit at whole-second precision. The raw records keep 100-nanosecond precision.
* **Timestomp rows are inferences, not observations.** They point to patterns that changed times
  often leave, and each pattern has innocent causes (copying, extracting archives). A change made
  to both the `$STANDARD_INFORMATION` and `$FILE_NAME` times leaves none of these patterns and is
  not reported. Measured: a change made through `ntfs-3g` is not detected.
* **One parser is often all there is.** The second parsers (EZ Tools, Dissect) are not always
  available: EZ Tools are staged only with the `eztools` feature, and Dissect reads the recycle
  bin only on a recognised Windows system. Rows marked `single_source` were not cross-checked.
* **Large drives are slow.** The Dissect MFT listing in the inventory module takes about 60
  milliseconds per file on the authoring machine, so a drive with several hundred thousand files
  needs hours for that step. Measured by the scale test (`validation/scale/`, task 4G.15).
* **The AI parts are triage.** Classifier flags have no independent error rates yet (risk 32,
  task 4B.16), so flag counts are unvalidated. Violence detection is weaker than nudity
  detection and gives false positives on medical, sports, and news pictures (risk 10). A file
  that is not flagged was "not flagged by this model at this threshold", not "safe".
* **Media screening samples video and skips pictures inside documents.** A video is screened
  from start to end, but only at sampled frames: one every 2 seconds, further apart for videos
  longer than 30 minutes (about 8 seconds at two hours), so a short scene between two frames can
  be missed. Videos whose frames do not reach the end, clips under about 1 second (no frame is
  sampled), images with more than 64 frames or pages, and audio or document files whose content
  type cannot be confirmed (a document must have a document MIME type of its extension's
  family) are not cleared and not kept. An audio file whose cover art cannot be extracted and
  screened is not kept either, sound included. Pictures embedded in documents (PDF pages with
  text, Office files, e-mail attachments, HTML) are not screened, and those documents are kept
  (docs/workflows/media-screening.md).
* **No one views flagged media, and AIRLOCK never estimates age.** Nothing in the pipeline would
  recognise child sexual abuse material unless the operator sees a sign elsewhere (risks 11
  and 31). If you suspect it: stop, do not open or copy the file, preserve the drive, and contact
  law enforcement.
* **AI-drafted report text can be wrong after the verifier passes.** The verifier checks that the
  cited values appear in the cited rows, not that the sentence means the right thing (risk 29).
  The examiner reviews every draft. AI fields can also differ between machines (risk 30).

## What the drive and the session can and cannot prove

* **The software read-only policy is not a write blocker.** Root can clear the read-only flags,
  and logging is not enforcement (risk 1). The write tracer counts write requests to the target;
  a count of zero is evidence, not a guarantee. Use a hardware write blocker with a NIST CFTT
  report on real evidence. The policy's own test results are in `validation/cftt/`.
* **An output-drive unlock is tied to one attach of one drive, as far as sysfs can tell.** The
  marker matches the disk's `diskseq`, WWN, serial and size. On kernels with `diskseq` (5.15 and
  later, including the image's) any re-plug or media change ends the unlock; a card reader that
  reports a media change re-locks the card. A drive with no `diskseq`, WWN or serial is refused.
* **The live ISO stops booting rather than scan other disks.** If the AIRLOCK medium is not
  found within 60 seconds, or an attached disk cannot be set read-only in the initramfs, the
  boot stops at the initramfs shell. When the read-only step failed, leaving that shell retries
  it; it does not skip it.
* **Mounting a hostile file system exposes kernel code.** `evidence-mount` is a convenience;
  analysis without mounting is the safe path (risk 2).
* **Read-directly mode leaves nothing to re-examine.** If the drive fails or is returned, no copy
  exists and no other tool can be run later (risk 28). A Full run on a failing drive reads it
  several times and can finish it off (risk 15).
* **Times in logs are only as good as the PC clock.** There is no time sync (risk 27). The
  session records the operator's clock check; use it.
* **The parsers age.** The drive gets no security patches. Parser bugs fixed upstream stay until
  you reflash; the session warns once the image is older than 90 days (risk 26).
* **Staged files can be swapped.** Anyone holding the drive can change a hash set or a model on
  ASSETS. The check at each boot detects it and turns the feature off; it does not prevent it
  (risk 22).
* **No legal validation.** AIRLOCK has not been validated by any court, lab accreditation body,
  or regulator (risk 9). The validation suite shows what it found on known images; adopt it in
  your own validation before relying on it.
* **Actions are attributed to account SIDs, never people.** A SID shows which account owned or
  changed something, not who used the keyboard.
* **The run signature checks consistency, not who held the output drive.** The private key is on
  the AIRLOCK drive's root filesystem (root only), but the public key travels with the run.
  Anyone holding the output drive can change files, write a new `outputs.sha256` and sign it with
  a key of their own, and the commands in the run folder then pass. Only comparing the public-key
  SHA-256 with a record kept off the output drive (the `signing_key_created` and `outputs_signed`
  entries in the session log of the AIRLOCK drive that made the run, or your case notes) shows
  the key is AIRLOCK's. Root on the AIRLOCK drive, or anyone who can read its unencrypted root
  filesystem, can sign with the real key. Runs signed before the key moved used a key stored on
  the output drive, and their signatures prove nothing against a drive holder. Re-signing
  (`evidence-report`, `--purge-run`) refuses changed runs unless `--force` is given; a forced
  re-sign is logged and the earlier lists are kept as `outputs.sha256.prev-<n>`, but someone who
  can edit the drive can also delete those.

## What the validation suite does not cover yet

* The public reference sets (NIST CFReDS, Digital Corpora) are listed but not pinned: their
  hosts were not reachable when the list was written (task 4F.2). Until they are fetched and
  their ground truth converted, results come from the synthetic images only.
* The synthetic NTFS image has no live USN journal (`ntfs-3g` does not write one), so the live
  journal parser is checked by unit tests only; carved USN records are checked.
* EZ Tools and the AI models could not be obtained in the authoring environment; their rows
  were validated with stand-ins only.
* Autopsy's search server (Solr 8) is bound to 127.0.0.1 only by the
  `SOLR_OPTS="$SOLR_OPTS -Djetty.host=127.0.0.1"` line the role adds to the zip's
  `autopsy-solr.in.sh`; Autopsy's `autopsy-solr` script never reads `SOLR_JETTY_HOST`, so the
  launcher's export of it does not bind anything. goss checks that the line is in the file;
  this is checked against a stand-in zip only, and no VM test yet opens a case and checks that
  nothing listens off loopback (the goss listener check runs with no case open).
