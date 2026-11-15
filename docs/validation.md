# Validation suite

Milestone 4F. SWGDE and the UK Forensic Science Regulator expect a method to be validated as
deployed. AIRLOCK ships the means and the results so you can adopt them in your own
validation. Read `docs/known-limitations.md` with every result. For checks on your own PC
(boot, read-only policy on real hardware), see `docs/validation-guide.md`.

Everything here runs on a Linux host or in CI, as root, never on the AIRLOCK drive.

## One command

```bash
sudo validation/run.sh --build                      # build the synthetic sets, run, score
python3 validation/report/build.py --release v0.2.0 --key-env RELEASE_SIGNING_KEY \
    --pub assets/manifest-signing.pub.pem --require-signature
```

## Parts

* `validation/synthetic/build.sh [--out DIR]` (task 4F.1): builds `ntfs-synthetic.img` and
  `exfat-synthetic.img` with `<set>.truth.json` ground truth: files created, modified, deleted,
  recycled (Windows-format `$I`/`$R` pairs, versions 1 and 2), carvable deleted pictures, carved
  USN records, and three kinds of timestomp, all at known times. The FUSE drivers run under
  libfaketime so each step gets a planned time, and the times are read back into the truth.
  Needs `ntfs-3g`, `exfatprogs`, `exfat-fuse`, `faketime`. Generated text and shapes only.
* `validation/reference/sets.json` and `fetch.sh` (task 4F.2): NIST CFReDS deleted-file and
  carving images and Digital Corpora sets, each with URL, SHA-256, licence, and where the
  published ground truth is. `fetch.sh` downloads on the host and refuses a file whose hash does
  not match; `--record` records the hash of a set that has none yet (check it against the
  publisher before committing). Data lands in `validation/out/reference/`, never in the repo.
* `validation/run.sh` (task 4F.3): runs `forensic-analyze --preset full --yes ...` on each set
  through a read-only loop device and scores it with `validation/scoring.py` into
  `validation/out/<set>/score.json`, plus `validation/out/summary.json`. Exit 1 if a class fails.
* `validation/report/build.py` (task 4F.4): `validation-report.md` and `.json` per release:
  pass or fail per artifact class, parser versions, cross-parser disagreements, classifier error
  rates (4B.16), software read-only policy test results (3A.8), and the scale run (4G.15);
  `validation-report.sha256` signed with the release Ed25519 key through
  `scripts/sign-manifest.sh` (`--key-env` reads a CI secret; the key is never committed).
  `--verify DIR --pub KEY` checks a published report.
* `validation/scale/scale.py` (task 4G.15): `generate --files N` builds an NTFS image with N
  files; `run` records run time and peak memory per module (process-tree samples from `/proc`
  matched to `run.json` module times, plus `getrusage`) and fails when a run is slower or bigger
  than `validation/scale/baseline.json` beyond its tolerance. Use `--out validation/out/scale` so the
  report picks the result up.
* `validation/cftt/` (task 3A.8): how to run the NIST CFTT Federated Testing write-block cases
  against the built image, and the results template (software read-only policy test results).
  Needs a person.
* `validation/classifiers/` (task 4B.16): classifier error rates. Needs a person.

## Artifact classes and how they are scored

| Class | Module | Found when | False positive |
|---|---|---|---|
| `live_files` | inventory | a `file_entry` row with the path, allocated | |
| `deleted_files` | inventory | a `file_entry` row with the path, not allocated | a live file listed as deleted |
| `recycle_bin` | recycle_bin | a `recycle_bin_entry` with the original path, deletion time within tolerance, and size | a record not in the truth |
| `timestamps` | timeline (else the inventory index) | creation and modification time within tolerance | |
| `timestomp` | inventory | each expected `ntfs_si_*` inferred row on each detectable stomp | an inferred row on an untouched file |
| `carving` | carve | a `carved_file` row with the SHA-256 of a deleted file | |
| `usn_carved` | deletion_history | a carved USN delete row with the name and time | a delete row for a name not deleted |

A class is `pass`, `fail`, `unsupported` (the module does not read that file system), or
`not_run`. Thresholds are in the truth file (`recall_min` 1.0 and `false_positives_max` 0 for
the synthetic sets; a reference truth may set lower recall for carving).

## Ground truth format (for reference sets)

Write `validation/reference/truth/<set id>.json` by hand from the publisher's ground truth:

```json
{"schema": 1, "set": "<id>", "kind": "reference", "fs_type": "ntfs",
 "image_sha256": "<sha256 of the unpacked image>", "tolerance_s": 2,
 "thresholds": {"recall_min": 1.0, "false_positives_max": 0, "carving": {"recall_min": 0.8}},
 "classes": ["deleted_files", "carving"],
 "files": [{"path": "/dir/name.txt", "state": "deleted", "times": null}],
 "carve": [{"sha256": "<hash>", "size": 1234, "type": "jpg", "from": "<publisher's id>"}],
 "recycle_bin": [], "timestomp": [], "usn_records": []}
```

## Results recorded on 2026-11-15 (authoring container)

Synthetic sets built by `validation/synthetic/build.sh`, analysed with the repository's
`forensic-analyze --preset full` (Sleuth Kit 4.12.1, Dissect target 3.25.1, PhotoRec 7.1; no EZ
Tools, no Plaso, no classifiers, no malware module):

| Set | Live | Deleted | Recycle bin | Timestamps | Timestomp | Carving | Carved USN | Overall |
|---|---|---|---|---|---|---|---|---|
| ntfs-synthetic | pass 12/12 | pass 7/7 | pass 3/3 | pass 12/12 | pass 5/5 | pass 3/3 | pass 2/2 | pass |
| exfat-synthetic | unsupported | unsupported | - | pass 6/6 | - | pass 1/1 | - | incomplete |

Target hash unchanged and zero write requests on both. The `ntfs3g_xattr` timestomp was not
detected, as expected (`docs/known-limitations.md`). The first run failed carving: the three
deleted pictures were under 700 bytes, so NTFS kept them in the MFT and nothing was left to
carve; the generator now writes larger pictures, and the limit is listed.

Scale test at small size (`validation/scale/scale.py`, 2,000 files, standard preset): the
inventory module took 118 s, 116 s of it in the Dissect MFT listing (about 57 ms per file,
linear from 500 to 2,000 files). The full-size run (several hundred thousand files) is for CI
or a release host: expect several hours for that step.
