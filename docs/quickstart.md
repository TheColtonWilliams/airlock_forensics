# Quickstart

There are two ways to make an AIRLOCK drive. Both end with the same drive.

* **Linux, one command** (a Linux computer with KVM): the script builds the image itself,
  tests it, writes it, stages the tools and models, and proves the drive boots.
* **Windows, or Linux without KVM** (two stages): download the published base image, write it
  with an imaging tool, run the fetcher to stage the tools and models, then boot.

## Before you start

* **Drive:** 64 GB or larger. A USB SSD is much faster than a USB stick and is the
  recommended choice. The `full` profile needs 128 GB or more.
* **Everything on that drive is erased.** Copy off anything you need first.
* **BitLocker and Secure Boot:** if the PC you will boot is protected by BitLocker, changing
  Secure Boot or other firmware settings can start BitLocker recovery on its next normal boot.
  Have its BitLocker recovery key before you change anything. Use the one-time boot menu (the
  key shown on screen at power-on) rather than changing the boot order. AIRLOCK is built to
  boot with Secure Boot on, but a PC that trusts only the newer 2023 Microsoft certificate may
  refuse it; see [hardware-matrix.md](hardware-matrix.md).
* **Write blocker:** connect every evidence drive through a hardware write blocker, ideally one
  with a published NIST CFTT test report. AIRLOCK's software read-only policy is a second layer
  only. It is not a write blocker.
* The drive never goes online. Everything it needs is downloaded on this computer and copied
  onto the drive's `ASSETS` partition.

## Linux: one command

You need: Linux on an x86_64 computer, virtualisation (KVM) turned on, about 80 GB of free disk
space, an internet connection, and a few hours.

```
git clone <AIRLOCK repository URL> airlock
cd airlock
sudo ./make-usb.sh
```

It asks, in this order:

1. To install anything missing (QEMU, zstd, OVMF, exFAT tools, goss, Packer). Say yes.
2. The profile: `default` (recommended), `minimal` (no AI models), or `full` (everything,
   128 GB drive). You can also give a profile file.
3. Which USB drive to use. Only removable drives are listed. Type the drive's name back to
   confirm, for example `sdb`.
4. An optional abuse.ch key for the MalwareBazaar known-bad hash set. Press Enter to skip. The
   key is used for this download only and is never saved.

It then prints the download size, image size and build time, and asks once more. After that
it runs on its own: build, boot tests, write, stage, read-back check, and a test boot of the
drive itself. The full log is `build.log`. If a step fails, the screen names it. Fix the cause
and run the same command again: the finished image and the downloads are reused from `cache/`.

Useful options (all of them: `./make-usb.sh --help`):

| Option | What it does |
|---|---|
| `--image-only` | Build and test the image only. No drive and no root needed. |
| `--flash-only FILE` | Skip the build. Write a published `.raw.zst` (with `SHA256SUMS` beside it), then stage and test. |
| `--profile NAME` | `default`, `minimal`, `full`, or a profile file. |
| `--target /dev/sdX --confirm sdX --yes` | No questions. |
| `--abuse-key-file FILE` | Read the abuse.ch key from a file instead of typing it. |
| `--accel tcg` | No KVM: emulate instead. Expect many hours. |

How the drive is checked, and what `scripts/flash.sh` refuses: [flashing.md](flashing.md).

## Windows (and Linux without KVM): two stages

### 1. Download

From the project's release page, download into one folder:

* `airlock-<version>.raw.zst` (the base image)
* `SHA256SUMS`
* the `scripts` folder (or the whole repository) for the fetcher

### 2. Check the download

In PowerShell, in that folder:

```
Get-FileHash .\airlock-<version>.raw.zst -Algorithm SHA256
```

Compare the hash it prints with the line for `airlock-<version>.raw.zst` in `SHA256SUMS`. If
they differ, the download is damaged. Delete it and download it again. Do not write it.

### 3. Write the image

If your imaging tool cannot open a `.zst` file, decompress it first with the zstd tool for
Windows (`zstd -d airlock-<version>.raw.zst`) and check the `.raw` file's hash against its own
line in `SHA256SUMS` the same way.

**Rufus: use DD Image mode. Rufus's ISO mode does not write this image correctly.**

* Rufus: pick the USB drive under Device, pick the image with SELECT (set the file type to
  All files if the image is not listed), and when Rufus offers a choice, choose
  **DD Image mode**. Press START.
* balenaEtcher: Flash from file, pick the image, Select target, pick the USB drive, Flash.
  Etcher checks the drive after writing.

On Linux without KVM, write it with `sudo scripts/flash.sh --image airlock-<version>.raw.zst
--target /dev/sdX` instead. It refuses internal drives and checks the result.

Windows may offer to format the drive after writing. Say **Cancel**: formatting destroys the
image.

### 4. Stage the tools and models

With the drive still plugged in, run the fetcher on the same computer:

* Windows: `powershell -ExecutionPolicy Bypass -File .\scripts\fetch-assets.ps1`
* Linux: `scripts/fetch-assets.sh`

It asks for the profile and the optional abuse.ch key, downloads every file, checks each
SHA-256, and copies them onto the drive's `ASSETS` partition. If it cannot find the `ASSETS`
partition, it says so and tells you what to do.

### 5. Boot

Plug the drive into the PC you will work on, power on, open the one-time boot menu, and pick
the USB drive. On first boot AIRLOCK sets itself up from `ASSETS` with no network, tests
itself, and restarts. There is no password: it logs in by itself.

## Windows with WSL2 (untested)

You can try `./make-usb.sh --image-only` inside WSL2 if it offers KVM (nested
virtualisation), then write the resulting `.raw.zst` with Rufus (DD Image mode) or
balenaEtcher and stage it as in steps 4 and 5. This path has not been tested yet. Another
choice is to boot an Ubuntu live USB on the PC and run the Linux one-command path from there.

## If something goes wrong

* `flash.sh: refused: ...`: nothing was written. The line says what to do.
* `make-usb: step "..." failed`: read the end of `build.log`, fix the cause, run it again.
* The PC does not list the USB drive in the boot menu: try another USB port, or turn on USB
  boot in the firmware settings (see the BitLocker warning above first).
