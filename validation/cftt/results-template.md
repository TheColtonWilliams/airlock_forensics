# Software read-only policy test results

Copy this file to `results-<release>.md`, fill in every field, and commit it with
`results-<release>.json` (format in `README.md`). The software read-only policy is a second line
of defence; it is not a write blocker.

| Field | Value |
|---|---|
| AIRLOCK release | |
| Image SHA-256 | |
| Test suite and version | NIST CFTT Federated Testing |
| Tested by | |
| Date (UTC) | |
| PC (capacities only) | |
| Test drive (interface, capacity) | |
| Test drive SHA-256 before (second computer) | |
| Test drive SHA-256 after (second computer) | |
| Hashes equal | yes / no |

## Policy checks after attaching the drive

| Check | Expected | Seen |
|---|---|---|
| `airlock-setro --check` | drive listed read-only | |
| `lsblk -o NAME,RO` | `RO 1` on the drive and every partition | |
| `findmnt` | nothing mounted from the drive | |

## Test cases

| Case ID | What it sends | Expected | Result (pass / fail / not_run) | Notes |
|---|---|---|---|---|
| | | blocked | | |
| AIRLOCK-TRACER | quick `forensic-analyze` run | `write_requests_total` 0 | | |
| AIRLOCK-DD | one 512-byte direct write with `dd` | refused | | |
| AIRLOCK-DISCARD | `blkdiscard` of the first MiB | refused | | |

## Conclusion

State in one or two plain sentences whether every case passed, and list any case that failed
or was not run, with the reason.
