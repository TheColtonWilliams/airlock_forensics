# Hardware checklist

One page, run by a person on every PC in the hardware matrix, for every release (task 4G.17).
About 30 minutes per PC. The automated tests run in an emulator; this checklist is the only
proof on real hardware. Copy the results table at the end into
[hardware-matrix.md](hardware-matrix.md) and into your own validation record.

You need: the AIRLOCK drive written from the release, staged with the `default` or `minimal`
profile; a **scratch** USB drive with nothing you need on it (one partition, a small text file);
a second computer to hash the scratch drive (optional, best); and, for step 7, a Windows PC.
Never use real evidence for this checklist. Do not record a PC brand or model as a requirement:
record what you tested, not what anyone must buy.

| # | Check | How | Pass when |
|---|---|---|---|
| 1 | Boots under UEFI | One-time boot menu, pick the USB drive, UEFI entry | desktop appears, no login prompt |
| 2 | Boots under legacy BIOS or CSM (if the PC offers it) | same, legacy entry | desktop appears |
| 3 | Secure Boot on | firmware setup shows Secure Boot enabled; in AIRLOCK run `mokutil --sb-state` | `SecureBoot enabled` and the desktop appears. Read the BitLocker warning in hardware-matrix.md before changing Secure Boot |
| 4 | Internal disk read-only | `sudo airlock-setro --check` | every internal disk listed `ro`, ends with `writable=0` |
| 5 | Scratch drive not mounted and not writable | plug it in, wait 10 s; `findmnt -rn -o SOURCE,TARGET`; `sudo blockdev --getro /dev/sdX`; the `dd` write-back in [validation-guide.md](validation-guide.md) step 5 | no window opens, no mount line, `1`, and the write fails with "Operation not permitted"; scratch hash unchanged afterwards |
| 6 | AI tier chosen | `ai-probe --json` | a tier is chosen from the memory the PC has (tier0 on the CPU when there is no usable GPU); note which |
| 7 | Quick run completes | `forensic-analyze --preset quick` on the scratch drive (answer the prompts, output to `OUTPUT`) | the run ends with status `ok`, the write tracer count is `0`, and the before and after hashes match |
| 8 | Report opens on Windows | shut down, plug the AIRLOCK drive into a Windows PC, open `OUTPUT\cases\...\report.html` | the report opens in a browser; `findings.csv` opens in a spreadsheet with no formula warnings |
| 9 | Radios and network off | `rfkill list`; `ip -br link`; `ping -c 1 -W 2 9.9.9.9` with a cable plugged in | all radios soft-blocked or none listed; nothing `UP` but `lo`; ping fails |

If a check fails: stop using that release on that PC, and open a bug with the check number, the
command output, `sudo airlock-setro --check`, and the boot mode. Never attach evidence data.

## Results

| Date | Release | PC (type, firmware, CPU, RAM, GPU memory) | 1 UEFI | 2 BIOS | 3 Secure Boot | 4 internal ro | 5 scratch | 6 tier | 7 Quick run | 8 Windows | 9 radios/network | Tester |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| | | | | | | | | | | | | |

Task status: 4G.17 is `needs-human` until a person has run this on the PCs in the matrix.

## First-use test on Windows (task 4G.18)

Needs a person who has never seen AIRLOCK (task status: needs-human). It tests the documents, not
the tester.

1. Give them a Windows PC with internet access, an empty 64 GB or larger USB drive, a second PC to
   boot, and one link: the project's [quickstart.md](quickstart.md). Nothing else.
2. Ask them to make a drive with the two-stage Windows path and boot it, thinking aloud.
3. Do not help. Write down every point where they stop, guess, go back, or ask: the step, what they
   expected, and what they did.
4. Stop after 90 minutes, or when the drive has booted to the AIRLOCK desktop and
   `forensic-session-start` has finished.
5. Open one issue per stall with the bug form ("Documentation"), quoting the quickstart step.

| Date | Release | Tester (first time) | Finished? | Time taken | Stalls (issue links) | Observer |
|---|---|---|---|---|---|---|
| | | | | | | |
