# Hash triage: known software and known malware

`evidence-triage-hash` and the `malware` module of `forensic-analyze` hash every file and
check it against hash sets and signatures that are already on the drive. Nothing goes online.
Known software is set aside; matches to known malware are flagged.

## What is checked, in order

1. **Hashes.** MD5, SHA-1, and SHA-256 of each file, in one read-only pass.
2. **NSRL (known software).** The NIST NSRL RDSv3 "Modern minimal" database. The SHA-256 is
   looked up first. SHA-1, then MD5, are used only for older NSRL rows that have no SHA-256.
   The CSV and the findings say which hash matched. A file that matches is **known software**,
   not "safe": it is not scanned further.
3. **ClamAV.** `clamscan` (never the daemon) with ClamAV's `main.cvd` and `daily.cvd`, plus the
   **MalwareBazaar** list of known-malware SHA-256 values, converted to a ClamAV `.hsb` file.
   ClamAV cannot scan files of 2 GiB or more; those are still checked against MalwareBazaar.
4. **YARA.** Each rule pack (Neo23x0 signature-base, YARA Forge core), compiled at setup.
5. **ssdeep.** A fuzzy hash of each remaining file. If lists of known ssdeep hashes are installed
   (see below), similar files are reported with a score from 0 to 100. A fuzzy match means
   *similar content*, not the same file, so it is marked `inferred`. Exact matches are `observed`.

Every scanner runs in the parser sandbox (no network, unprivileged user, time and memory limits)
and only sees neutral names (`f0000000`, `f0000001`, ...). A file name from the evidence is
never given to a tool, so a hostile name cannot fake or hide a result.

## Getting the hash sets onto the drive

They come from the host computer, like everything else:

* Pick a profile with the features you need when you run `fetch-assets` (`default` stages
  ClamAV, MalwareBazaar, and YARA; `full` adds NSRL). MalwareBazaar needs your abuse.ch
  Auth-Key; the fetcher uses it for the download only and never writes it to the drive.
* On first boot `forensic-provision` checks each file and sets it up:
  ClamAV databases must pass `sigtool` (ClamAV's own signature) and are copied to
  `/opt/hashsets/clamav/`; the MalwareBazaar export becomes
  `/opt/hashsets/clamav/malwarebazaar.hsb` (its snapshot date and SHA-256 go to the session
  log); YARA packs are compiled into `/opt/yara/<pack>/rules.yarc`.
* To update later, rerun the fetcher with `--refresh` on the host, plug the drive back in, and
  run `sudo forensic-import`.

### Where NSRL lives

The NSRL database is several GB, so by default (`nsrl_on_image: false`) it lives off the image:

* With the `full` profile, provisioning extracts it to the OUTPUT partition (`OUTPUT/nsrl/`).
* Or copy an extracted `RDS_<release>_modern_minimal.db` to any drive yourself and set
  `nsrl_path` in `/etc/airlock/airlock.conf.json` to the file or its folder.

Lookup order: `nsrl_path`, then `/opt/hashsets/nsrl/` (when `nsrl_on_image: true`), then
`OUTPUT/nsrl/`. The database is opened read-only and never written to. Without NSRL, triage still
runs; it just cannot set known software aside, and says so.

### Optional ssdeep lists

Put lists made with `ssdeep -s FILES > name.ssdeep` in `/opt/hashsets/ssdeep/`. A `name.json`
next to a list may give `{"name": "...", "version": "..."}` for the report.

## Running it

```
evidence-triage-hash FOLDER_OR_FILES... -o /srv/airlock/output/triage.csv
evidence-triage-hash --list paths.txt -o /srv/airlock/output/triage.csv
```

* Give folders (searched recursively; links are not followed), files, or a list file with one
  path per line. A typical source is an image mounted read-only with `evidence-mount`.
* The CSV must not go inside the folder being checked; the command refuses and tells you to
  write to the OUTPUT drive.
* Flagged files are printed with what matched, then one summary line. `--quiet` prints only the
  summary. `--no-sandbox` runs the scanners without the sandbox (only for troubleshooting).

Inside `forensic-analyze`, the `malware` module does the same for every live, deleted, and carved
file the inventory lists. It copies each file out read-only into a temporary folder, triages it,
and deletes the copy straight away. The raw CSVs stay in `modules/malware/triage/`.

## Reading the results

CSV columns: `path`, `size_bytes`, `md5`, `sha1`, `sha256`, `verdict`, `nsrl`,
`nsrl_match_algorithm`, `hash_hits`, `clamav_hits`, `yara_hits`, `ssdeep`, `fuzzy_hits`, `notes`.
The file is UTF-8 with a byte order mark; any cell that a spreadsheet could read as a formula
starts with a `'`, and control characters in names are shown escaped.

| `verdict` | Meaning | What to do |
|---|---|---|
| `known_good` | In NSRL: known published software. | Usually skip it. Known software can still be misused. |
| `flagged` | Matched MalwareBazaar, a ClamAV signature, a YARA rule, or an ssdeep list. | Review it. Treat it as hostile: do not open it on this or any other machine. |
| `no_match` | Not in any set. | Not evidence of anything. New or rare malware matches nothing. |
| `error` | Could not be read. | See `notes`; re-image the source if needed. |

Findings from the module: `hash_hit` (MalwareBazaar, or an ssdeep list with a `score`),
`clamav_hit`, `yara_hit` (category `malware`); `nsrl_known_good`, `hashset_status` (which sets
and versions were used), and `hash_triage_error` (files that could not be checked) (category
`hash`). Each row names the set (`hashset_name`), its version or snapshot date
(`hashset_version`), and the algorithm that matched (`match_algorithm`).

## Limits

* Hash sets only find what someone has already seen. A clean result is not proof of anything.
* MalwareBazaar and ClamAV change daily; the result is only as new as the snapshot on the drive
  (shown in every row and in the session log).
* YARA rules that depend on the file name or path (`filename`, `filepath`, `extension`, ...) do
  not fire: those values are never passed, by design.
* The `malware` module skips files over 2 GiB (listed as `hash_triage_error`). Export such a file
  and run `evidence-triage-hash` on the copy.
* The session log records each run: counts, the CSV and its SHA-256, the hash sets and versions
  used, and the tool versions.
