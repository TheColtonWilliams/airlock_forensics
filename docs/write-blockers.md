# Hardware write blockers

AIRLOCK always advises a hardware write blocker between the PC and the evidence drive, and
records whether you used one (task 3A.7). AIRLOCK's own read-only layer is a **software read-only
policy**, a second line of defence. It is not a write blocker: root can clear it, raw SCSI
commands can bypass it, and some filesystem drivers can still write (Suhanov; NIST CFTT). See
[threat-model.md](threat-model.md).

## Which blockers this page lists

**None, on purpose.** The rule (build plan 3A.7) is to list only blockers that have a published
NIST CFTT or DHS test report, and only when the report can be named exactly: make, model,
firmware or hardware version, and the report itself. The authors could not confirm those details
for any blocker from the authoring environment, so no blocker is listed. A wrong entry here would
be worse than none: a blocker passes or fails a test at one firmware version, and a later
firmware can behave differently. The research behind this project found a USB "write-protect"
adapter that let 10 of 31 write commands through under Ubuntu (NIST CFTT / DHS, March 2020), so
the report matters more than the brand.

AIRLOCK names no vendor as a requirement (hard rule 3). Any blocker with a report that covers your
exact model and firmware is fine.

## How to check a blocker yourself

1. Note the blocker's make, model, and firmware version. The firmware version is usually on a
   label, in the blocker's own status display, or in its vendor tool.
2. Find the test report. The NIST Computer Forensics Tool Testing (CFTT) programme publishes its
   results, and the U.S. Department of Homeland Security (DHS) Science and Technology Directorate
   publishes the CFTT reports it sponsored. Start at the CFTT pages on nist.gov
   (`https://www.nist.gov/itl/ssd/software-quality-group/computer-forensics-tool-testing-program-cftt`)
   and look for the "hardware write block" test results, or search the DHS S&T CFTT report list
   for the model name.
3. Check that the report covers **your** model and **your** firmware version, and the interface
   you will use (USB, SATA, SAS, NVMe). Read the "anomalies" or "results" section: a report can
   describe commands that were not blocked.
4. If you find no report for your exact model and firmware, treat the blocker as untested. You
   can still use it, but record "no test report found" and rely on the before and after hashes.

## Recording it in a run

`forensic-analyze` asks whether a hardware write blocker is in use and records the answer in
`run.json` and the report. Non-interactive form:

```
forensic-analyze ... --write-blocker yes --blocker-make "<make>" --blocker-model "<model>" \
  --blocker-firmware "<version>" --blocker-report-url "<link to the CFTT or DHS report>"
```

`--write-blocker` takes `yes`, `no`, or `unknown`. With `yes` and no report link, the run records
"no test report link recorded for this blocker". The session start helper asks the same question
(`forensic-session-start --write-blocker yes|no|unknown --blocker-model TEXT`).

## Adding a blocker to this page

Open a pull request that adds a row below only with all of: make, model, firmware or hardware
version tested, interface, the report's title and publisher (NIST CFTT or DHS), and a link to the
report. A reviewer checks the report before merging.

| Make | Model | Firmware tested | Interface | Report (title, publisher, link) | Added |
|---|---|---|---|---|---|
