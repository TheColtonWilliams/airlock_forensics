# Session helpers

The commands an examiner uses around an analysis: start a session, hash, take a first look,
mount an image for a quick look, and make an output drive writable. Every command appends JSON
lines to the session log. None of them writes to an evidence drive.

Code: `ansible/roles/session_tools/files/pylib/airlock_session/`. Commands are installed in
`/usr/local/bin` by the `session_tools` role. Run them with `sudo` (the analyst has
passwordless sudo): the session log folder is written by root and readable by the analyst
through the `adm` group.

## 1. Start a session: `forensic-session-start`

A terminal opens at login and runs it. You can run it again at any time; each run starts a new
log file `/var/log/forensic-session/<YYYYMMDDTHHMMSSZ>.log`, and `current.log` points at it.

It asks three questions first, so you can walk away while the checks run:

1. **Authority.** You must have the owner's permission or the legal authority to examine the
   drives you will use. If you answer no, it stops. Flag: `--authority-ack`.
2. **Clock.** There is no network, so nothing sets the clock. It shows the system time and the
   PC's hardware clock in UTC. Check them against a trusted clock (a phone on network time, a
   radio clock). If the time is wrong, type the correct UTC time; AIRLOCK logs the difference
   (`offset_seconds` = reference minus system time) and **never changes the clock**. A
   hardware clock that is a whole number of hours off usually means the PC keeps local time
   (Windows does). Flags: `--clock-ok`, or `--reference-time 2026-11-15T09:30:00Z
   --reference-source "phone"`.
3. **Hardware write blocker.** Connect evidence drives through a hardware write blocker, ideally
   one with a NIST CFTT or DHS test report. AIRLOCK's software read-only flag is a second layer,
   not a substitute. Flags: `--write-blocker yes|no|unknown`, `--blocker-model TEXT`.

Then it records, each as one log line: the kernel and its command line, tool versions (missing
tools are logged as absent), `lsblk`, the read-only flag of every disk and partition, radio
(rfkill) state, network interfaces and routes (there should be none besides loopback), the
image build date and age, and the ASSETS check (every staged file hashed against the signed
manifest; `--quick-asset-check` checks sizes only).

Warnings are printed at the end and logged in `session_ready`:

* the image is older than `image_max_age_days` (default 90, in `/etc/airlock/airlock.conf.json`):
  reflash from a current base image, because it has no security fixes since it was built;
* a drive other than the AIRLOCK drive is writable and was not unlocked for output;
* a radio is unblocked, or a network interface is up;
* ASSETS files are missing or changed (rerun the fetcher on the host computer);
* the clock was not checked, or is more than a minute off.

`--yes` takes the default for every question (clock not checked, write blocker unknown) except
authority, which always needs `--authority-ack`.

## 2. Hash: `evidence-hash`

    sudo evidence-hash /dev/sdb
    sudo evidence-hash --sha1 --json /srv/airlock/output/cases/C-1/disk.raw

SHA-256 and MD5 in one read pass (`--sha1` adds SHA-1), read-only, logged as `evidence_hash`.

## 3. First look: `evidence-triage`

    sudo evidence-triage /dev/sdb

Runs `mmls` (partition table), `fsstat` on each partition, the evidence hash, and Dissect
`target-info`, all read-only. Full output goes to the session log; a summary is printed. Tools
that are not installed are logged as `tool_missing` and the rest still runs. For a full
analysis use `forensic-analyze` (see `guided-analysis.md`).

## 4. Quick look inside an image: `evidence-mount`

AIRLOCK never mounts a target by default: analysis reads the raw drive or image with The Sleuth
Kit and Dissect. Mounting lets the kernel parse a filesystem that may be hostile, so
`evidence-mount` is for image files only, for a quick look.

    sudo evidence-mount case.raw                 # one filesystem, or one partition
    sudo evidence-mount --partition 2 disk.raw /mnt/airlock/p2
    sudo evidence-mount --list
    sudo evidence-mount --unmount /mnt/airlock/p2

It refuses drives and partitions, and E01 files (expose those with `ewfmount` first). It hashes
the image, attaches a kernel read-only loop device covering just that filesystem, and mounts
it `ro,noexec,nosuid,nodev` plus `noload` (ext2/3/4), `norecovery` (XFS), or
`rescue=nologreplay` (Btrfs); NTFS goes through `ntfs-3g -o ro`. It hashes again after mounting
and after unmounting and fails loudly if the image changed.

## 5. Output drive: `evidence-unlock-output`

Every attached drive is read-only by the software read-only policy. To write case output to a
second drive (instead of the AIRLOCK `OUTPUT` partition):

    sudo evidence-unlock-output /dev/sdc          # then type sdc to confirm
    sudo evidence-unlock-output /dev/sdc --confirm sdc
    sudo evidence-unlock-output /dev/sdc --lock   # read-only again

It refuses the AIRLOCK drive itself and partitions, and refuses without the typed
confirmation (`--yes` does not skip it). It writes a marker in `/run/airlock/rw-allow/` so the
udev policy leaves the drive writable until reboot or unplug, and logs the drive's model,
serial, and size. **The log records the change; it does not prevent mistakes** (surviving
risk 1). Never unlock an evidence drive.

## Session log format

One JSON object per line, sorted keys, UTF-8: `ts` (UTC, microseconds, `Z`), `event`, `tool`,
`pid`, then event fields. See `docs/dev/contract.md` section 4. Text that comes from evidence
(volume labels, tool output) is stored as data and never passed to a shell.
