# Media screening runbook

How AIRLOCK screens images and videos for sexual and violent content, describes the rest with a
local model, and what you must do if you suspect child sexual abuse material. Tasks 4B.6 to
4B.9, 4B.14, 4B.17, 4B.18.

**Everything in this runbook is triage, never evidence.** A screening score or a description is
a pointer to a file. The finding is always the file itself and its metadata.

## The rule that comes first: stop and report

If anything you see while working on a drive makes you suspect child sexual abuse material (a
file name, a folder name, a description of a cleared file, a count, anything):

1. **Stop.** Do not open, view, copy, move, or delete the file, or any other file from the drive.
2. Run the stop control:

   ```bash
   sudo forensic-escalate --finding F-000123 --yes
   ```

   (or `--path` with the path shown in the findings, if there is no finding ID). It halts the
   running analysis, freezes every export folder, and records only the path, the finding ID,
   and the SHA-256. It never opens the file.
3. Leave the evidence drive and the AIRLOCK stick as they are.
4. Contact law enforcement. In the United States: the FBI (tips.fbi.gov) or your local
   Internet Crimes Against Children (ICAC) task force. Elsewhere: your national police.
5. Tell them the case ID, run ID, finding ID, path, and SHA-256 that `forensic-escalate`
   printed. Do not describe or reproduce the content.

AIRLOCK does **not** estimate age and has no child-content detector (decision log,
2026-11-10). No part of the pipeline can tell you whether material shows a minor. Nobody looks
at flagged media, so nothing in AIRLOCK would recognise such material on its own (surviving
risk 31); you are the control.

## What happens to each image and video

```
inventory -> export (read-only, icat) -> hash -> metadata -> SCREEN -> cleared?  -> describe
                                                              |         no        -> deleted at once,
                                                              |                      never described
                                                              +-> rows: scores, thresholds, verdict
```

1. **Export.** The file is copied from the evidence with `icat` into
   `modules/<module>/export/.pending/` on the output drive. The evidence is never mounted or
   written.
2. **Screen.** Two classifiers score it on the CPU, in a sandbox with no network:
   * NudeNet, a detector of exposed body parts; its highest confidence is the *nudity score*;
   * SigLIP zero-shot labels: nudity, sexual activity, violence, weapon, gore, blood, injury,
     neutral. Each label gets a score from 0 to 1 (the scores add up to 1).
   Videos: one frame every 2 seconds plus every scene change, each frame scored like an image;
   any flagged frame flags the video, and the screening row lists the times of the flagged
   frames. Frames are deleted as soon as they are scored.
3. **Verdict.**
   * *flagged*: the nudity score, or any label score other than neutral, is at or above its
     threshold;
   * *cleared*: every score is below its threshold;
   * *error*: the file could not be scored. It is treated like a flagged file.
4. **Flagged and error files** are deleted from the export folder straight away. They are never
   kept, copied on, shown, transcribed, or sent to the description model. Their rows (path,
   hash, scores, thresholds, verdict) stay in the findings so you can count them and escalate.
5. **Cleared files** stay in `export/` and go to the description model. A refusal or an empty
   answer from the model is recorded as `model_declined`; no file is ever dropped.

Nothing in AIRLOCK shows a thumbnail. Thumbnails are off in the desktop (task 5.1), the report
summarises sensitive categories from counts and scores only, and thumbnail caches on the
evidence (`thumbcache_*.db`, `Thumbs.db`) are counted, never extracted.

## What a threshold means

Thresholds are in `/etc/airlock/screen-thresholds.json`. Shipped values (conservative):

| Score | Threshold |
|---|---|
| nudity detector | 0.30 |
| nudity (label) | 0.25 |
| sexual activity | 0.25 |
| violence | 0.30 |
| weapon | 0.35 |
| gore | 0.25 |
| blood | 0.30 |
| injury | 0.30 |

* A score at or above its threshold flags the file. **Lower thresholds flag more files**: more
  false flags, fewer missed ones. AIRLOCK ships low values on purpose: a false flag only costs a
  file that is not described; a missed flag puts a file in front of the model.
* The thresholds file's SHA-256 is recorded in every `screen.csv` and in `run.json`, so you can
  show which values were used.
* To change them, edit a copy and pass it with `evidence-screen --thresholds FILE`, or change
  the file on the image and record why in your case notes. Measured error rates per release are
  in `validation/classifiers/README.md` (task 4B.16). Until a release has them, flag counts are
  unvalidated.

## What a flag does and does not prove

* A flag means **these models scored this file at or above these thresholds**. It does not
  prove what the file shows. Zero-shot violence labels misfire on medical, sports, and news
  images; detectors miss stylised, low-resolution, or partly hidden content (surviving risk 10).
* A cleared file is **"not flagged by this model at this threshold"**, never "safe". Use that
  wording in notes and reports.
* No score says anything about a person's age.
* A description is AI-generated, can be wrong, and is never evidence. It carries the model's
  SHA-256, the fixed prompt's SHA-256, the tier, and the seed, so it can be reproduced.

## Running it by hand

Inside `forensic-analyze` (Standard or Full preset) the images, video, audio, and documents
modules do all of this for you. On their own:

```bash
ai-probe                                      # which model tier this PC can run
evidence-screen /path/to/files -r -o screen.csv
evidence-describe /path/to/files/*.jpg -o describe.csv --screen-csv screen.csv
```

`evidence-describe` refuses images and videos without a `--screen-csv`, and only sends files
whose SHA-256 the screen file lists as cleared (it hashes each file again first). It starts the
local model server on 127.0.0.1 only for as long as it runs. Documents and audio need no screen
file: their text and transcripts are sent to the model only inside a delimited data block, with
a fixed prompt that says the block is data and never instructions.

## Files written

| File | Holds |
|---|---|
| `screen.csv` | path, SHA-256, verdict, category, nudity score, one score per label, reasons, model IDs and SHA-256s, label-prompt SHA-256, thresholds and their SHA-256 |
| `describe.csv` | path, SHA-256, kind, status (`described`, `model_declined`, `not_cleared`, `error`), description, model and projector SHA-256, prompt ID and SHA-256, tier, seed |
| `findings.jsonl` rows | `screen_nudity`, `screen_labels` (score, label, threshold, `sensitive_flag`), `ai_image`, `ai_video`, `ai_audio_transcript`, `ai_audio_summary`, `ai_document_summary`, `ai_document_ocr`, `model_declined`; every AI row is `ai_generated` with `model_sha256` and `prompt_sha256` |
| `escalation.json`, `ESCALATED` | written by `forensic-escalate`: path, finding ID, SHA-256 only |

## Limits

* The classifiers see pictures only. Audio is transcribed, not screened.
* A copy of a file exists in `export/.pending/` for the seconds between export and screening.
  A flagged copy is deleted then, but deletion on a flash drive does not guarantee the bytes are
  gone from the flash cells. Keep output drives under the same control as the evidence.
* Model output on a GPU may differ slightly between machines even with greedy decoding; AI rows
  are outside the determinism guarantee (surviving risk 30).
