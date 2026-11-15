# Classifier error rates (task 4B.16)

The screening step (`evidence-screen`) uses two classifiers: NudeNet (a nudity detector) and
SigLIP zero-shot labels (nudity, sexual activity, violence, weapon, gore, blood, injury,
neutral). No independent error rates exist for them as AIRLOCK uses them. Until this page holds
measured results for a release, **flag counts are unvalidated** (surviving risk 32).

This folder holds only the method and a scoring script. **No media is ever committed here**, and
no file names, thumbnails, or descriptions of benchmark items either.

## Who can do this

A person with lawful access to a labelled benchmark of adult sexual content and violent content,
under their organisation's rules for handling such material. This step needs a person
(build plan 2.7). Never use material that may show minors: AIRLOCK does not estimate age, and
the benchmark must be adult-only and lawful where it is held.

## Steps

1. Boot an AIRLOCK drive of the release being measured, with the default thresholds
   (`/etc/airlock/screen-thresholds.json` unchanged). Record its build date and the
   `ai-probe` tier.
2. Put the benchmark on a separate drive and run, without opening any item:

   ```bash
   evidence-screen /path/to/benchmark -r -o screen.csv
   ```

3. Write `labels.csv` with exactly two columns, `sha256` and `truth`, one row per item.
   `truth` is `sexual`, `violent`, `sexual+violent`, or `neutral`. Take the hashes from your
   benchmark's own records, not from `screen.csv`.
4. Score it:

   ```bash
   python3 validation/classifiers/score.py --screen screen.csv --labels labels.csv \
       --out results-<release>.json
   ```

5. Add a row to the table below with the release, the benchmark's name and size per class,
   the false-positive and false-negative rates at the shipped thresholds, and the model hashes
   from `results-<release>.json`. Attach the JSON (it holds counts and rates only) to the
   release's validation report (4F.4).
6. If a threshold should change, use the `sweep` section of the JSON (rates for every score
   from 0.05 to 0.95) and record the new value and the reason in `docs/decision-log.md`.

## What the numbers mean

* False-positive rate: share of items without the category that were flagged for it. A false
  positive costs a file that is not described by the model; the examiner can still review it.
* False-negative rate: share of items with the category that were not flagged. A false
  negative puts a file in front of the description model and, later, possibly the examiner.
* Items the classifiers could not score are listed separately; AIRLOCK never clears them.

## Results

| Release | Benchmark (items per class) | Sexual FPR | Sexual FNR | Violent FPR | Violent FNR | Models (SHA-256 prefix) | Date | Measured by |
|---|---|---|---|---|---|---|---|---|
| (none yet) | | | | | | | | |
