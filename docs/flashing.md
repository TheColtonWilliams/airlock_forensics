# Writing the image to a drive

How `scripts/flash.sh` writes an AIRLOCK image (tasks 2.1 to 2.5), and how `make-usb.sh`
chains build, test, write, staging and a boot check (Milestone 2A). For the step-by-step
guide, read [quickstart.md](quickstart.md) first.

## flash.sh in one line

```
sudo scripts/flash.sh --list
sudo scripts/flash.sh --image airlock-<version>.raw.zst --target /dev/sdX
```

It shows the drive's model, serial and size, asks you to type the drive's name back (for
example `sdb`), writes the image, then reads the written range back and checks its SHA-256.

## What it refuses

Every refusal prints one line saying why and what to do, exits with status 3, and writes
nothing. `tests/functional/test_flash.sh` proves each one leaves the target byte-identical.

| Refusal | Why |
|---|---|
| Drive is not removable | Only drives the kernel marks removable (`RM=1`), or hot-plugged USB drives, are written. USB SSDs often report `RM=0` but are hot-plugged on USB, so they are accepted. Internal SATA, NVMe and eMMC drives are refused. |
| Drive holds `/` | Never erase the running system. If it cannot work out which drive holds `/`, it refuses every drive. |
| Any partition mounted, or used by LVM, RAID or encryption | Checked with `lsblk` and the kernel mount table. Unmount (eject) it first. |
| Drive smaller than image + headroom | The image's uncompressed size plus `--headroom-gb` (default 8; GB = 10^9 bytes). The minimum drive is 64 GB. |
| Image does not match `SHA256SUMS` | The image is hashed before writing. Keep `SHA256SUMS` next to the image, or pass `--sums FILE`. |
| Wrong, missing or untyped confirmation | Interactive: type the drive name. Non-interactive: `--confirm NAME` must equal the drive's kernel name; `--yes` alone is refused. |
| Serial changed (`--expect-serial`) | `make-usb.sh` uses this so a drive swapped during a long build is not erased. |
| A partition (`/dev/sdb1`) or a non-disk device | Pick the whole drive. |

## How it writes and checks

1. The image's uncompressed size comes from a `.size` file next to the image (if the build
   wrote one), else the zstd frame header, else the raw file size.
2. `dd bs=4M conv=fsync status=progress oflag=direct`; a `.zst` image is decompressed by
   `zstd -d` into `dd`, and the decompressed stream is hashed on the way.
3. The decompressed stream must match the raw image's line in `SHA256SUMS` (the build lists
   both the `.raw` and the `.raw.zst`).
4. The drive's cache is flushed and exactly the written range is read back with direct I/O. Its
   SHA-256 must equal the raw image's. A mismatch means a faulty or fake-capacity drive.

Exit status: 0 written and verified, 1 failed while writing or verifying, 2 bad usage,
3 refused (nothing written). The last line of a good run is `readback_sha256=<hash>`.

`scripts/flash.sh --list --json` prints the removable drives as JSON (`name`, `path`, `size`,
`model`, `serial`, `tran`, `rm`, `hotplug`, `problem`); `make-usb.sh` uses it for its drive
picker. Model and serial strings come from the device itself, so they are reduced to printable
text before use.

Tests only: `AIRLOCK_FLASH_TEST=1` lets the target be a regular file or a loop device. Every
other check still applies, so the tests stub `lsblk`, `findmnt` and `blockdev` through `PATH`
(or wrap `lsblk` so a loop device reads as removable).

## make-usb.sh

`sudo ./make-usb.sh` asks every question first (drive, profile, optional abuse.ch key), shows
the estimates, then runs unattended:

| Step | Command | Skipped on a rerun when |
|---|---|---|
| build | `scripts/build.sh --cache DIR --output DIR --accel MODE` | the output folder still matches its `SHA256SUMS` |
| boot tests | `tests/run-qemu-tests.sh --image <raw>` | they passed for this image's SHA-256 (`make-usb-tested.sha256`) |
| write | `scripts/flash.sh --image <raw.zst> --target DEV --yes --confirm NAME --expect-serial S` | never |
| stage | `scripts/fetch-assets.sh --yes --manifest assets/manifest.json --profile P --assets MOUNT --cache DIR` | never (the fetcher's cache makes it quick) |
| verify | every file in `ASSETS/profile.json` read back and hashed | never |
| smoke boot | `tests/run-qemu-tests.sh --image <qcow2 overlay on the drive> --only '^smoke\.yaml$' --no-extra-disks --boot-bus usb` | never |

* Same code as the two-stage install (Milestone 2B, plan 2.5.1): the image is the published
  base image, staging uses `assets/manifest.json` from `scripts/gen-manifest.py` (made first
  if missing) and `scripts/fetch-assets.sh`, and the drive provisions itself offline on first
  boot with `forensic-provision`.
* The abuse.ch key is read silently (or from `--abuse-key-file`) and reaches the fetcher only
  through the `AIRLOCK_ABUSECH_KEY` environment variable of that one process. It is never in a
  command line, a file, the log, or the drive; the verify step checks the drive for it.
  Without a key the MalwareBazaar hash set is not staged and the log says so.
* The smoke boot opens the drive as the read-only backing file of a qcow2 overlay, so the boot
  cannot change it; the drive's first MiB is compared before and after.
* Every step's output goes to `build.log` (`--log FILE`). On failure the failing step is named
  on screen; fix the cause and run the same command again.
* `--image-only` builds and tests without a drive (no root needed). `--flash-only IMAGE` skips
  the build and its tests.
* `--yes` asks nothing and needs `--target` and `--confirm`. The CI form (task 2A.8) is
  `sudo ./make-usb.sh --yes --profile ci --target /dev/loopN --confirm loopN` with
  `AIRLOCK_FLASH_TEST=1` and an `lsblk` wrapper that reports the loop device as removable, as
  in `tests/functional/test_make_usb.sh`.
* `scripts/prereqs.sh --check` lists missing host tools; `--install` installs them with apt
  (after a yes/no question), fetches goss from its pin, and gets Packer through
  `scripts/build.sh --prepare-tools` (pinned version and SHA-256). Ansible is not needed on the
  host: it runs inside the build VM.
