# Findings schema and exports

Every `forensic-analyze` run keeps one system of record, `findings.jsonl`. The SQLite
database, the CSV file, and the bodyfile are generated from it and from nothing else. This page
says what each field means, how the files are built, and which safety rules apply.

Source files (under `ansible/roles/session_tools/files/pylib/forensic_analyze/`):

| File | What it does |
|---|---|
| `schema.json` | The row schema (JSON Schema draft 2020-12, the keyword subset below). |
| `findings.py` | `FindingsWriter.emit()`, `validate_row()`, `merge_parts()`, `safe_path()`, `compare_findings()`. |
| `csvsafe.py` | Display escaping and spreadsheet-formula neutralising, shared by every package that writes CSV. |
| `export_sqlite.py` | `case.sqlite` (4D.5). |
| `export_csv.py` | `findings.csv` (4D.6, 4D.7). |
| `export_bodyfile.py` | `findings.bodyfile` (4D.10). |

## `findings.jsonl`

* One JSON object per line, UTF-8, keys sorted, compact separators (`,` and `:`), each line
  ending in `\n` (no CR). Strings are written as UTF-8, not `\u` escapes.
* Modules write rows through one function, `emit()` (`FindingsWriter.emit`, reached as
  `ModuleContext.emit`). Each row is checked against `schema.json` before it is written; a row
  that fails raises `SchemaError` and is not written. Rows go to
  `<run>/modules/<name>/findings.part.jsonl`, in the order the module emits them. Modules sort
  their rows before emitting.
* `emit()` fills `run_id`, `evidence_id`, and `evidence_sha256`. A module must not set
  `finding_id`; a different `run_id`, `evidence_id`, or `evidence_sha256` is refused.
* When every module has finished, `merge_parts(run_dir, module_order)` reads the part files in
  module run order, keeps each module's emit order, re-checks every row, assigns `finding_id`
  `F-000001`, `F-000002`, ... and writes `findings.jsonl` (temporary file, then rename).
  `findings.merge()` also returns the file's SHA-256 for `run.json`. The same parts always give
  the same bytes.
* The file is append-only in the sense that rows are never edited after merge. A re-merge
  after a resumed run rewrites the whole file, with identical bytes for identical parts.
* Raw tool output (EZ Tools CSVs, `fls` bodyfiles, Dissect records) stays under
  `<run>/modules/<name>/` as intermediates; `source_record` points at the line or record.

## Fields

Required fields come first. Absent means unknown; `null` is never written.

| Field | Type | Required | Meaning |
|---|---|---|---|
| `finding_id` | string `^F-[0-9]{6,}$` | yes | Stable ID assigned at merge, F-000001 onwards in module order. Six digits, more after 999999. |
| `run_id` | string `^R-<YYYYMMDDTHHMMSSZ>-<6 hex>$` | yes | The run that produced the row. |
| `evidence_id` | string, not empty | yes | Exhibit or target identifier for the run. |
| `evidence_sha256` | string, 64 lower-case hex | yes | SHA-256 of the target device or image, taken before the run. |
| `category` | enum | yes | `inventory`, `recycle_bin`, `deletion`, `users`, `malware`, `hash`, `images`, `video`, `audio`, `documents`, `timeline`, `carve`, `system`, `xval`. |
| `artifact_type` | string, not empty | yes | What kind of record produced the row, snake_case by convention (`file_entry`, `usn_delete`, `recycle_bin_entry`, `hash_hit`). |
| `message` | string, not empty | yes | One plain line describing the finding. Says "account SID", never a person. |
| `derivation` | enum | yes | `observed` (read directly from a record), `inferred` (an interpretation made by code, for example `$SI` created before `$FN` created), `ai_generated` (made by a model; triage, never evidence). |
| `source_tool` | string, not empty | yes | Tool that produced the record (`sleuthkit`, `MFTECmd`, `dissect`). |
| `tool_version` | string, not empty | yes | That tool's version as it reports it. |
| `parser` | string, not empty | yes | Parser or code path inside the tool (`fls`, `mftecmd`, `dissect.ntfs.usnjrnl`). |
| `datetime` | string, ISO 8601 with `Z`, up to 9 fraction digits | no | Event time. Checked as a real calendar time. |
| `timestamp_desc` | string, not empty | no | What `datetime` means (Timesketch column). Use `Content Modification Time`, `Last Access Time`, `Metadata Modification Time`, `Creation Time`, `Deletion Time`; add a variant in brackets, for example `Creation Time ($FILE_NAME)`. |
| `tz_basis` | enum | no | `utc` (recorded in UTC), `local_with_offset` (local time converted with a known offset), `local_unknown_offset` (local time, offset unknown: the `Z` is not reliable). |
| `path` | string, display-safe | no | Full path as shown. Control, bidi, invisible, and lone-surrogate characters and invalid UTF-8 bytes are escaped (see Hostile file names). |
| `filename` | string, display-safe | no | Last path component, escaped the same way. |
| `path_b64` | string, standard base64 | no | Raw bytes of the path. Present whenever escaping changed the path, or the path holds a backslash. |
| `inode_ref` | string, not empty | no | Metadata address. Recommended form `v<volume index>:<entry>-<sequence>`, for example `v0:64-1`. |
| `size_bytes` | integer >= 0 | no | Size in bytes. |
| `allocated` | boolean | no | `true` if the metadata entry is allocated; `false` if deleted or unallocated. |
| `sha256` | string, 64 lower-case hex | no | SHA-256 of the file content. |
| `md5` | string, 32 lower-case hex | no | MD5 of the file content. |
| `owner_sid` | string `^S-1-[0-9]+(-[0-9]+)*$` | no | Owner account SID. Never a person's name. |
| `hashset_name` | string, not empty | no | Hash set that matched (NSRL, a malware set, a case set). |
| `hashset_version` | string, not empty | no | Version or date of that hash set. |
| `match_algorithm` | string, not empty | no | What produced the match: `sha256`, `md5`, `sha1`, `ssdeep`, `yara`, `clamav`. Fuzzy matches are `inferred`. |
| `score` | number (finite) | no | Score from a classifier or matcher. |
| `label` | string, not empty | no | Class label, signature, or rule name. |
| `threshold` | number (finite) | no | Threshold the score was compared with. |
| `text` | string | no | Longer text: an extract, transcript excerpt, or description. Evidence text is data. |
| `confidence` | number 0 to 1 | no | Confidence the producing tool gives. |
| `xval_status` | enum | no | Two-parser cross-check: `agree`, `disagree`, `single_source`. |
| `source_record` | string | no | Raw record location: a path relative to the run folder, then `#` and a locator, for example `modules/inventory/MFTECmd.csv#L12`. No leading `/`, no `..`. |
| `model_id` | string, not empty | no | Model name and quantisation. |
| `model_sha256` | string, 64 lower-case hex | no | SHA-256 of the model file. |
| `prompt_sha256` | string, 64 lower-case hex | no | SHA-256 of the fixed prompt file. |
| `sensitive_flag` | boolean | no | `true` if a classifier score passed the examiner's threshold. |

Rules beyond single fields:

* No other field is allowed (`additionalProperties: false`).
* A row with `derivation` = `ai_generated` must carry `model_sha256` and `prompt_sha256`.
* Numbers must be finite (no NaN or infinity). Booleans are not numbers. Text must be valid
  UTF-8: `emit()` escapes lone surrogates in text fields (`\ud800`, or `\xNN` for bytes that
  came through `os.fsdecode`).

### Validator

`findings.py` holds a standard-library validator for exactly the keywords `schema.json` uses:
`type`, `enum`, `const`, `pattern`, `minLength`, `maxLength`, `minimum`, `maximum`, `format`
(`date-time`, and `x-display-safe`: no character `csvsafe.needs_escape` would escape),
`required`, `properties`, `additionalProperties`, `allOf`, `if`/`then`/`else`. Loading a schema
that uses any other keyword fails, so the schema cannot silently outgrow the validator.
`validate_row(row)` returns a list of error strings; `validate_row(row, part=True)` checks a
part-file row (no `finding_id` yet). Error messages show evidence text escaped and cut to 80
characters.

## Hostile file names

`findings.safe_path(raw)` takes `bytes` or `str` and returns `(display, b64)`:

* Bytes that are not valid UTF-8 are shown as `\xNN`.
* Control characters (C0, DEL, C1), Unicode format characters (bidi embeddings, overrides and
  isolates such as U+202E, zero-width characters, the BOM), line and paragraph separators, and
  lone surrogates (invalid UTF-16 from NTFS) are shown as `\uXXXX` (or `\UXXXXXXXX`).
  Newline, carriage return, and tab are shown as `\n`, `\r`, `\t`.
* Other characters, backslashes included, are kept.
* `b64` is base64 of the raw bytes. For `str` input, os.fsdecode surrogate escapes become their
  original bytes and other lone surrogates are kept in generalised UTF-8 (3 bytes each), so
  nothing is lost.

`emit()` applies this to `path` and `filename` when a module passes bytes or unsafe text, and
fills `path_b64` unless the module set it.

## `case.sqlite` (4D.5)

* Table `findings`: one column per field, in the order of the table above. Strings are `TEXT`,
  integers `INTEGER`, numbers `REAL`, booleans `INTEGER` 0 or 1. Required fields are
  `NOT NULL`; `finding_id` is `UNIQUE`. `rowid` order is finding order.
* Indexes: `idx_findings_datetime`, `idx_findings_category`.
* Table `export_info` (`key`, `value`): `schema_version`, `findings_sha256`, `row_count`,
  `source`.
* `PRAGMA user_version` = schema version (1); `PRAGMA application_id` = 0x4149524C. No build
  timestamps are stored. Fixed page size, UTF-8, `VACUUM` after load. Byte-identical files are
  not promised; identical rows are.

Views (every view is `SELECT *` from `findings`):

| View | Rows | Order |
|---|---|---|
| `v_timeline` | `datetime IS NOT NULL` | By time: the first 19 characters, then the fraction with trailing zeros removed (so `00:00:00Z` < `00:00:00.05Z` < `00:00:00.5Z`), then finding order. |
| `v_deleted` | `allocated = 0` or `category = 'deletion'` | Finding order. |
| `v_recycle_bin` | `category = 'recycle_bin'` | Finding order. |
| `v_media` | `category IN ('images', 'video', 'audio')` | Finding order. |
| `v_hash_hits` | `category IN ('malware', 'hash')`: hits (`hash_hit`, `clamav_hit`, `yara_hit`) are `malware`; `nsrl_known_good`, `hashset_status` and `hash_triage_error` are `hash` | Finding order. |
| `v_flags` | Media screening rows only: `category IN ('images', 'video', 'audio', 'documents')` and an `artifact_type` starting `screen_` or equal to `carved_media_removed`, with `sensitive_flag = 1` or a classifier result (`label IS NOT NULL AND score IS NOT NULL`). Hash and malware hits (`ssdeep` similarity rows carry a label and a score too) are in `v_hash_hits`, never here. | Finding order. |
| `v_disagreements` | `xval_status = 'disagree'` | Finding order. |

## `findings.csv` (4D.6, 4D.7)

* Encoding: UTF-8 with a byte order mark, so spreadsheets pick the right encoding.
* RFC 4180: comma separated, CRLF after every record (header included), `"` quoting only where
  needed (`csv.QUOTE_MINIMAL`, chosen so numbers stay numbers in a spreadsheet), `""` for a
  quote inside a quoted cell.
* Fixed columns: `datetime`, `timestamp_desc`, `message` (the Timesketch import columns), then
  every other field in the order of the table above. An empty cell means the field is absent.
  Timesketch needs a `datetime` on every row it imports; filter to rows that have one, or
  import `v_timeline` from `case.sqlite`.
* Text cells are display-escaped: newline, carriage return, and tab become the two characters
  `\n`, `\r`, `\t`; other control, bidi, and invisible characters become `\uXXXX`. Every record
  is therefore one physical line. A literal backslash is kept, so `\n` in a cell can also be a
  real backslash-n; `findings.jsonl` and `path_b64` hold the exact value.
* Formula neutralising: a text cell gets a leading `'` when its raw value starts with a tab or
  carriage return, or when its first character after leading whitespace is `=`, `+`, `-`, `@`,
  or a full-width form of one of them. The whitespace check is there because some spreadsheets
  skip leading spaces before reading a formula. Number cells (`size_bytes`, `score`,
  `threshold`, `confidence`) are plain numbers and are not changed; a number such as `-1.5`
  is not a formula.
* `path_b64` is never escaped. It can start with `+`; then it gets the leading `'` like any
  other cell. Decoders that skip non-base64 characters ignore it, and
  `findings.decode_path_b64()` strips it.
* Rows with `derivation` = `ai_generated` have `message` prefixed with `AI-generated: `.

`csvsafe.csv_cell(value)` applies these rules to one cell. Other packages that write CSV use it.

## `findings.bodyfile` (4D.10)

The Sleuth Kit 3.x bodyfile, for `mactime -b findings.bodyfile -d -z UTC`:
`MD5|name|inode|mode_as_string|UID|GID|size|atime|mtime|ctime|crtime`, times in whole seconds
since 1970 UTC, 0 for unknown.

* A finding contributes when it has `datetime`, `path` (or `filename`, or `inode_ref`), and a
  `timestamp_desc` naming a MACB time: text with "metadata", "entry modif", "record modif",
  "mft modif", or "change" is c; "creat" or "birth" is b; "access" is a; "modif", "written",
  or "write" is m. Other descriptions (such as `Deletion Time`) are left out.
* Findings for the same evidence, `inode_ref`, path, and variant become one line. A second,
  different value for a time already filled starts a further line. A variant in brackets at
  the end of `timestamp_desc` gets its own line with ` (variant)` added to the name. Rows with
  `allocated` = `false` get ` (deleted)` added, as `fls -m` does.
* `inode` is `inode_ref` without the `v<n>:` prefix (mactime accepts only digits and dashes);
  other forms become 0. `|` in a name is written `|`. Mode, UID and GID are 0.
* Rows with `tz_basis` = `local_unknown_offset` are left out, because a bodyfile cannot say a
  time is not UTC. Times before 1970 are written as 0.

CASE/UCO 1.4 JSON-LD export: planned for later, not built yet.

## Determinism (4D.9)

Replaying a run's `run.json` against the same image must give a byte-identical
`findings.jsonl`, apart from AI fields. AI fields are `confidence`, `label`, `message`,
`score`, `sensitive_flag`, and `text` on rows with `derivation` = `ai_generated` or a
`model_sha256` (GPU inference is not bit-for-bit repeatable, risk 30).
`python3 -m forensic_analyze.findings compare A B` reports byte identity, non-AI identity
(exit 1 if broken), and every drifted AI field. `findings.csv` and `findings.bodyfile` are
byte-identical for identical `findings.jsonl`; `case.sqlite` holds identical rows.

## Command line

```
python3 -m forensic_analyze.findings validate FILE [--part]
python3 -m forensic_analyze.findings merge RUN_DIR MODULE [MODULE ...]
python3 -m forensic_analyze.findings compare FINDINGS_A FINDINGS_B
python3 -m forensic_analyze.export_sqlite RUN_DIR
python3 -m forensic_analyze.export_csv RUN_DIR
python3 -m forensic_analyze.export_bodyfile RUN_DIR
```
