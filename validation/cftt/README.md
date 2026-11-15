# Software read-only policy test results (task 3A.8)

AIRLOCK's software read-only layer (`airlock-setro`, the udev rule, the masked storage
services, and the write tracer in `forensic-analyze`) is a **software read-only policy**. It is
a second line of defence. It is not a write blocker, and nothing here makes it one. This folder
holds the method for testing it with the NIST Computer Forensics Tool Testing (CFTT) Federated
Testing write-block test cases, and the place to publish the results per release.

This step needs a person and real hardware (build plan 2.7): a PC, a test drive, and the CFTT
suite. An automated build cannot do it. Until a results file exists for a release, the
validation report (`validation/report/build.py`) says "Not run - see 3A.8".

## What you need

* The AIRLOCK release under test, written to its own USB drive (`scripts/flash.sh` or the
  quickstart). Record the image SHA-256 from the release page.
* A **test drive** that holds nothing you need (SATA or NVMe in a USB enclosure, and a plain
  USB stick if you can: test every interface you will use for evidence). It will be read and,
  if a test fails, written to.
* A second computer to hash the test drive before and after (never the AIRLOCK session).
* The NIST CFTT Federated Testing suite, downloaded from NIST on the second computer:
  <https://www.nist.gov/itl/ssd/software-quality-group/computer-forensics-tool-testing-program-cftt/federated-testing>.
  Use the suite's own manual for its write-block test cases. Record the suite version and the
  exact test case IDs you ran; do not paraphrase them.

## Steps

1. **Before.** On the second computer, hash the whole test drive (SHA-256 and MD5):
   `sudo sha256sum /dev/sdX` and `sudo md5sum /dev/sdX`. Write both down.
2. **Boot AIRLOCK** on the test PC with the test drive **not** attached. Run
   `forensic-session-start` and note the session log name.
3. **Attach the test drive.** Then check the policy took effect:
   * `sudo airlock-setro --check` must list the drive as read-only;
   * `lsblk -o NAME,RO,SIZE,MODEL` must show `RO 1` for the drive and every partition;
   * `findmnt` must show nothing mounted from it.
   Save the output (photo or `... > /srv/airlock/output/cftt-<case>.txt`).
4. **Run the CFTT write-block test cases** from the suite's manual against the attached drive,
   with AIRLOCK as the tool under test. For each case record the case ID, what the case sends
   (for example write, format, or trim commands), the expected result ("blocked" for every
   command that would change the drive), and what happened. If the suite version you have
   cannot run its cases from inside another operating system, write that down, mark those
   cases `not_run`, and run the AIRLOCK checks in step 5 instead. Never report a case you did
   not run as passed.
5. **AIRLOCK's own checks** (always run these too):
   * `forensic-analyze --authority-ack --target /dev/sdX --preset quick --yes ...` must finish
     with `write_requests_total` 0 in `run.json` (the tracer saw no write or discard request);
   * `sudo dd if=/dev/zero of=/dev/sdX bs=512 count=1 oflag=direct` must fail with
     "Operation not permitted" or "Read-only file system";
   * `sudo blkdiscard -o 0 -l 1048576 /dev/sdX` must fail.
   Record each as a case (IDs `AIRLOCK-TRACER`, `AIRLOCK-DD`, `AIRLOCK-DISCARD`).
6. **After.** Shut AIRLOCK down, move the test drive to the second computer, and hash it again
   the same way. Both hashes must equal the step 1 values.
7. **Write the results** two ways:
   * fill in `results-template.md` (title: software read-only policy test results) and save it
     as `results-<release>.md`;
   * write `results-<release>.json` in the format below (copy `results-template.json`). The
     validation report reads it; `python3 validation/report/build.py --cftt FILE` checks it.
8. Commit both files. A failed case is a release blocker: open an issue with the case ID and
   the saved output, and say so in the release notes.

## Results JSON format

```json
{
  "schema": 1,
  "title": "software read-only policy test results",
  "release": "v0.2.0",
  "image_sha256": "<sha256 of the release image>",
  "suite": "NIST CFTT Federated Testing <version>",
  "tested_by": "<name or role of the tester>",
  "date": "2026-12-01",
  "pc": "<capacities only: CPU cores, RAM, USB ports used>",
  "test_drive": "<interface and capacity, e.g. SATA SSD 256 GB in a USB 3 enclosure>",
  "hash_before": "<sha256>",
  "hash_after": "<sha256>",
  "cases": [
    {"id": "<case ID from the suite>", "description": "<what it sends>",
     "expected": "blocked", "result": "pass", "notes": ""}
  ]
}
```

`result` is `pass`, `fail`, or `not_run`. List PCs by capacities, not by vendor or model
(hard rule 3); the hardware matrix (`docs/hardware-matrix.md`) is the place for models.

## Results

| Release | Suite version | Cases passed / failed / not run | Drive hash unchanged | Date | Tested by |
|---|---|---|---|---|---|
| (none yet) | | | | | |
