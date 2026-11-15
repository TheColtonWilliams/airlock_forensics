# Hardware matrix and Secure Boot

Where the AIRLOCK drive has been booted, and what to know about Secure Boot before you try.
Task 1.13 (and 7.3 later). Results are listed by firmware type and capacity, never as a
recommendation of a brand or model: the drive is meant to boot on any x86_64 PC.

## Before you change anything on a PC with BitLocker

**If the PC runs Windows with BitLocker, changing Secure Boot settings in the firmware makes
Windows ask for the BitLocker recovery key at its next start.** Some PCs do the same after a
change to the boot order or to other firmware settings.

* Do not turn Secure Boot off to start AIRLOCK. The drive is built to boot with it on.
* Use the PC's one-time boot menu (often F12, F11, F9, Esc, or F8 at power-on) to start from
  the USB drive. That does not change any setting.
* If you must change a firmware setting, first find the BitLocker recovery key (in the owner's
  Microsoft account, Active Directory or Entra ID, or a printed copy) and write down every
  setting you change so you can put it back.

## What the drive boots with

* UEFI: Ubuntu's signed shim at `EFI/BOOT/BOOTX64.EFI` (the removable-media path, so no
  firmware boot entry is needed or written), then Ubuntu's signed grub, then the signed Ubuntu
  kernel. Only Ubuntu-signed binaries from the dated apt snapshot are used.
* Legacy BIOS (CSM): grub i386-pc from the BIOS boot partition of the same drive.

### Secure Boot certificates (checked 2026-11-15)

From the packages in the build's apt snapshot (`apt_snapshot: 20261101T000000Z`):

| Binary | Package | SBAT | Signed by |
|---|---|---|---|
| shim (`BOOTX64.EFI`) | shim-signed 1.58+15.8-0ubuntu1 | `shim,4` | Microsoft Corporation UEFI CA 2011 (the `.dualsigned` file adds Canonical's own key) |
| grub (`grubx64.efi`) | grub-efi-amd64-signed 1.202.5+2.12-1ubuntu7.3 | `grub,5` | Canonical (verified by shim) |

* The build fails if shim or grub is below `shim,4` / `grub,5` (`base_min_sbat`), and
  writes what it found to `/etc/airlock/boot-chain.json` in the image.
* The Ubuntu 24.04 archive had **no shim signed under the Microsoft UEFI CA 2023** on that
  date. A PC whose firmware trusts only the 2023 CA (newer PCs, or PCs whose 2011 CA was
  removed from the allowed list) will refuse to start the drive with Secure Boot on. A PC
  that still trusts the 2011 CA starts it normally. Signatures made before the 2011 CA
  expired stay valid; expiry alone does not stop the drive booting.
* When Ubuntu publishes a shim signed under the 2023 CA, move `apt_snapshot` forward and
  rebuild; `boot-chain.json` then shows `ms_uefi_ca_2023: true`.

## Results

Automated (run by `tests/functional/test_build_bootloader.sh` and `tests/run-qemu-tests.sh`):

| Firmware | Secure Boot | Keys | Result | Date | How |
|---|---|---|---|---|---|
| QEMU SeaBIOS (legacy BIOS) | n/a | n/a | grub starts from the AIRLOCK layout | 2026-11-15 | functional test, loop disk |
| QEMU OVMF (UEFI) | off | none | signed shim then grub start from `EFI/BOOT` | 2026-11-15 | functional test, loop disk |
| QEMU OVMF (UEFI) | on | Microsoft 2011 CA (Ubuntu `OVMF_VARS_4M.ms.fd`) | signed shim then grub start, grub reports lockdown | 2026-11-15 | functional test, loop disk |
| QEMU OVMF and SeaBIOS, full image to desktop | both | as above | pending: needs a KVM build host | | `tests/run-qemu-tests.sh --firmware uefi,uefi-sb,bios` |

Needs a person and real hardware (task 1.13 status: needs-human):

| Firmware | Secure Boot | Keys | Result | Date | Tester |
|---|---|---|---|---|---|
| UEFI PC with the 2023 CA only (2011 CA not trusted) | on | 2023 only | expected to refuse (see above); to be confirmed | | |
| UEFI PC without the 2023 CA update | on | 2011 | to be tested | | |
| UEFI PC | off | n/a | to be tested | | |
| Legacy BIOS or CSM PC | n/a | n/a | to be tested | | |

To add a row: boot the drive with the one-time boot menu, note the firmware type, Secure Boot
state (`mokutil --sb-state` in AIRLOCK), and which CA the firmware trusts if known, and whether
the desktop came up. Do not record the PC's brand or model as a requirement.

## Local AI tiers and speed (task 4B.13)

`ai-probe` picks the model tier from measured GPU memory only (decision log 2026-11-10). The
automated tests feed recorded and synthesised `vulkaninfo` reports to it
(`tests/unit/test_probe.py`, 4G.9); only real machines show whether the chosen tier loads and
how fast it runs. Task 4B.13 needs at least one machine with an AMD GPU and one with an NVIDIA
GPU (open drivers, the default). This is the one place vendors are named: as test coverage,
never as a requirement.

On each machine, with a default-profile drive (tiers 0 to 2 staged):

1. `ai-probe --json > probe.json` and note `tier`, `backend`, `device.type`,
   `device.usable_gib`.
2. `vulkaninfo > vulkaninfo.txt`, and add it to `tests/fixtures/vulkaninfo/` as
   `recorded-<type>-<GiB>.txt` (it holds no personal data; check before committing) with a row
   in `tests/unit/test_probe.py`'s table.
3. Describe the neutral fixtures and time it:
   `time evidence-describe tests/fixtures/ai/neutral/*.png -o d.csv --screen-csv s.csv`
   (screen them first with `evidence-screen`), then read tokens per second from
   `journalctl -u llama-server | grep 'eval time'`.
4. Check `/run/airlock-llama/effective.json`: `fallback_reason` must be empty when the GPU tier
   loaded.

| GPU type | Vendor (coverage only) | Device-local memory | RAM | Tier chosen | Backend | Tokens/s (eval) | Fallback | Date | Tester |
|---|---|---|---|---|---|---|---|---|---|
| none (QEMU, llvmpipe) | n/a | n/a | any | tier0 (recorded `vulkaninfo`, unit test) | cpu | to be measured | n/a | 2026-11-15 | automated |
| discrete | AMD (RADV) | | | to be tested | | | | | |
| discrete | NVIDIA (NVK, open driver) | | | to be tested | | | | | |
| integrated | any | | | to be tested | | | | | |

## Secure Boot test matrix: three laptops (task 7.3)

Needs a person and three different laptops (task status: needs-human). The aim is coverage of
firmware kinds, not of brands: pick laptops that differ in firmware age and Secure Boot keys, and
record capacities and firmware facts, never a brand as a requirement.

Pick, if you can:

1. a laptop whose firmware trusts the Microsoft UEFI CA 2011 (most made before 2024);
2. a laptop whose firmware has the 2023 CA and still trusts the 2011 CA;
3. a laptop with the 2023 CA only, or with the 2011 CA revoked by a firmware or DBX update.

On each laptop, with the release image freshly written:

1. Read the BitLocker warning at the top of this page first.
2. In the firmware setup, note the firmware version and date and whether Secure Boot is on.
3. Boot the AIRLOCK drive with Secure Boot **on**. Record whether the desktop appears. If it does,
   run `mokutil --sb-state` and `cat /etc/airlock/boot-chain.json`.
4. If it does not boot, note the exact message, then try with Secure Boot **off** (and turn it
   back on afterwards).
5. Run [hardware-checklist.md](hardware-checklist.md) on the laptop.

| Laptop | Firmware version and date | CA trusted (2011, 2023, both, unknown) | Secure Boot on: result | Secure Boot off: result | Checklist passed | Date | Tester |
|---|---|---|---|---|---|---|---|
| 1 | | | | | | | |
| 2 | | | | | | | |
| 3 | | | | | | | |

Done when all three rows are filled in. A laptop that refuses the drive with Secure Boot on is a
result, not a failure of the test: record it and open an issue with the message shown.

## Outside review (task 7.4)

Needs people (task status: needs-human). Ask two DFIR practitioners who did not build AIRLOCK to
try to break its read-only guarantees, using scratch drives and synthetic data only. Give them:

* the release, [threat-model.md](threat-model.md), [controls.md](controls.md), and
  [validation-guide.md](validation-guide.md);
* the brief: make the drive write to an attached disk, reach a network, run code from evidence,
  or report something the evidence does not support;
* the "Outside review finding" issue form (`.github/ISSUE_TEMPLATE/outside-review.yml`) for each
  finding, and the Security tab for anything exploitable by someone other than the operator.

| Reviewer (as credited) | Release | Areas tried | Issues filed | Date |
|---|---|---|---|---|
| | | | | |
