# Security policy

AIRLOCK is used to handle evidence. A flaw that lets it write to an evidence drive, reach a
network, run code from a file it examines, or hide a finding is a security problem. Please report
it privately so it can be fixed before it is public.

## How to report

Use **GitHub private vulnerability reporting**: open the repository's **Security** tab
(<https://github.com/TheColtonWilliams/airlock_forensics/security>) and choose
**Report a vulnerability**. Only the maintainers see the report. There is no personal email
address for reports.

Please include:

* the AIRLOCK release (or commit) and how you made the drive (one command or two stages);
* the steps to reproduce, and what you expected instead;
* the output of `sudo airlock-setro --check` and the session log lines that matter, if any.

Never attach evidence data, case output, or real personal data. If a test file is needed, make a
synthetic one. Do not attach any sexual, violent, or otherwise sensitive media.

## What happens next

* You get an answer within 7 days that says whether the report is accepted.
* An accepted problem is fixed in the supported release line, and a GitHub Security Advisory is
  published with the fix. You are credited unless you ask not to be.
* Please do not make the problem public until the advisory is out or 90 days have passed,
  whichever comes first.

## Supported versions

AIRLOCK is pre-release. Only the newest release gets fixes. The drive never updates itself (it
is air-gapped), so a fix reaches you only when you write the new release to the drive.

| Version | Supported |
|---|---|
| Newest release on the Releases page | yes |
| Any older release | no: rewrite the drive with the newest release |
| Unreleased `main` | best effort; fixes land here first |

The base image is rebuilt monthly and out of band for parser security fixes
([docs/release-process.md](docs/release-process.md)). An AIRLOCK drive warns at session start
once its image is more than 90 days old.

## In scope and out of scope

In scope: anything in this repository, the images and manifests it publishes, and the fetchers.

Out of scope, because the project already says it does not protect against them
([docs/threat-model.md](docs/threat-model.md)): malicious firmware in a drive or USB bridge,
physical tampering with the AIRLOCK drive, and a user with root turning the protections off on
purpose. Problems in third-party tools (The Sleuth Kit, Dissect, exiftool, and others) should go
to their maintainers; tell us too, so we can pin a fixed version.
