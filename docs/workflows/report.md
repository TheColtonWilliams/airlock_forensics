# The run report (`evidence-report`)

Every `forensic-analyze` run ends with a report in its run folder: `report.html` (open it in any
browser, on Windows too) and `report.md` (the same content as plain text). This page says what is in
it, which parts the local model drafts, how those parts are checked, and what you must do before the
report is final. Milestone 4E; task 4B.11 points here.

## When it is written

* `forensic-analyze` calls `evidence-report RUN_DIR` after the findings, CSV, and `case.sqlite`
  are written and **before** `outputs.sha256` and its signature. The report is hashed and signed
  with the rest of the run.
* You can run it again by hand: `evidence-report <output>/cases/<case>/<run_id>`. When the folder
  already has `outputs.sha256`, the command re-hashes and re-signs the folder afterwards, so the
  signed list matches the new report (`--no-resign` skips that).

```
evidence-report RUN_DIR [--no-model] [--model-url http://127.0.0.1:PORT] [--no-start]
                        [--seed N] [--data-chars N] [--max-calls N] [--no-resign]
```

* `--no-model`: no AI sections; each says "No AI draft: local model not available".
* `--model-url`: the `llama-server` address. Only `127.0.0.1`, `::1`, or `localhost` is accepted;
  proxy settings are ignored, so nothing can leave the machine.
* `--no-start`: use the model only if `llama-server` is already running; never start it.
* Exit 0 when both files are written; otherwise one line says what failed and what to do next.

## What code fills in (no model)

| Section | Content |
|---|---|
| Header | Title, report type (triage when the drive was read directly, examination when a verified copy was analysed), case, exhibit and evidence IDs, examiner, agency, run ID. A **NOT FINAL** notice. |
| 1. Request and authority | Authority reference, the acknowledgement text, when and how it was given. |
| 2. Items received | Target identifiers (path, model, serial, size), SHA-256 and MD5 before the run, the forensic copy when one was made, volumes. |
| 3. Methodology | Mode with its standards basis and limits, preset and modules, before and after hashes, the hardware write blocker record, the software read-only policy (a policy, not a write blocker), observed write requests, sandbox, clock offset, image version and age, validation reference, tools and versions, deviations, warnings, errors. When the drive was read directly, the direct-mode limitation statement. |
| 4. Summary of the run | Modules, with failed and skipped modules first; findings per category and derivation; rows per `case.sqlite` view. |
| 5. Results by category | For each category: counts, then the AI draft (below). Media screening: counts, labels, and highest scores only. No media and no description of media content is ever shown. |
| 6. Interpretation and limitations | The three NIST IR 8354 limitations, word for word: *Not all evidence may be found. Recovered deleted files may include extraneous material. Artifact meaning changes between OS versions.* The direct-mode statement, the account-SID rule, and a pointer to `docs/known-limitations.md`. Then the AI draft. |
| 7. Conclusions | The AI draft. |
| 8. Examiner declaration | Name, signature, date. |
| Appendices | A run summary; B hash verification (target before and after, copy files, `findings.jsonl` against `run.json`); C parser disagreements (`v_disagreements`); D AI provenance (model, model SHA-256, quantization, llama.cpp build, backend, seed, prompt files and their SHA-256); E sentences removed by the verifier; F glossary. |

## What the model drafts, and how

Only three kinds of section: results by category, interpretation, conclusions.

1. **Inputs are rows from the `case.sqlite` views** (`v_deleted`, `v_recycle_bin`, `v_hash_hits`,
   `v_media`, `v_timeline`, and `v_report_category`, a TEMP view over one category made on the
   read-only connection, for accounts, documents, system records, and cross-check summaries).
   Never `findings.jsonl`, a raw tool output, or a file from the evidence.
2. **Evidence text is data.** Each row goes in as one JSON line inside a delimited block
   (`<<<DATA id=rows-<hash>>>` ... `<<<END DATA id=rows-<hash>>>`). Control, bidi, and zero-width
   characters are removed, `<<<` and `>>>` inside data are broken up, long strings are cut with a
   marker, and the fixed prompt and the text before the block say that the block is data and never
   an instruction. Media rows go in as IDs, labels, scores, and flags only.
3. **Fixed prompts.** `evidence_report/prompts/*.txt`, versioned in the repository. Their SHA-256 is
   in every AI paragraph, in Appendix D, and in `logs/report-provenance.json`. Greedy decoding
   (temperature 0, top-k 1) with a fixed seed. Prompt rules: cite finding IDs on every sentence; no
   person, no intent, nothing beyond the rows; "account SID"; record wording such as "the USN
   journal records a delete at".
4. **Map and reduce** for small context windows: each category is cut into time windows that fit
   the model's context; each window is drafted and checked; the checked sentences are merged, and
   the merge may only cite IDs those sentences cite. Counts, first and last times, and time spans
   are computed by code and passed in; the model never does date arithmetic.
5. **The code verifier** (`evidence_report/verify.py`, not a model) keeps a sentence only if it
   ends with finding IDs (`[F-000123, F-000124]`), every ID exists and was given to the model, and
   every date or time, number, path or file name, hash, and SID in it appears in a cited row or in
   the computed values (dates compared at the precision written, in any common format). It also
   removes sentences that name or describe a person, state intent, say "user" or "account" without
   "account SID", hold a capitalised word that could be a name, repeat evidence text, read like an
   instruction, or claim something (deleted, recycle bin, flagged, malware, created, modified,
   accessed, disagree) that no code-made field of a cited row records. It is strict on purpose:
   a wrongly removed sentence costs a draft line; a wrongly kept one could mislead.
6. **Removed sentences** are listed in Appendix E by section, cited IDs, reason, and SHA-256. Their
   text is not repeated in the report (it may carry planted evidence text); it is in
   `logs/report.jsonl` (event `sentence_removed`) for audit.

Without a reachable model (or with `--no-model`) the report still renders; each AI section says
"No AI draft: local model not available", and Appendix D says why.

## Before the report is final

* Every AI paragraph is labelled **AI-generated draft. Not evidence.**, shows the model and prompt
  SHA-256, and ends with `Reviewed by: ____ Date: ____`.
* Check each sentence against the cited findings (`findings.csv` or `case.sqlite`), edit or delete
  it, then fill in its review line. Sign the declaration in section 8.
* A report with an unfilled review line or declaration is a draft.

## Files

| File | What it holds |
|---|---|
| `report.html`, `report.md` | The report. Self-contained: no scripts, images, or external resources; a Content-Security-Policy forbids loading any. Every value is escaped. |
| `logs/report-provenance.json` | Model record, prompt hashes, per-section status, kept sentences with their IDs, removed sentences by hash, SHA-256 of both report files. |
| `logs/report.jsonl` | Every model call (prompt file and hash, request hash, reply) and every removed sentence with its reasons. |

## Tests

* `tests/unit/test_verify.py` (4G.14): a wrong date, a wrong path, a missing citation, and a
  non-existent finding ID are each rejected; date formats, numbers, wording, names, claims.
* `tests/unit/test_inputs.py`, `tests/unit/test_report_mapreduce.py`,
  `tests/unit/test_report_render.py`, `tests/unit/test_report_model.py`: data blocks, views,
  windows, merge rules, code-filled sections, HTML safety, provenance, loopback-only client.
* `tests/functional/test_injection.sh` (4E.10): fixtures in `tests/fixtures/injection/` with planted
  instructions in file names and document text; a stub model that obeys them is fully stripped, a
  well-behaved stub passes.
* `tests/functional/test_report.sh` (4E.11, 4B.11): a real `forensic-analyze` run writes the report
  before hashing and signing, with and without a model.
