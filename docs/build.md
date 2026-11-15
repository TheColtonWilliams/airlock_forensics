# Building the AIRLOCK image

How the base image is built, what is in it, and how it is tested before anyone flashes it.
Tasks 1.1 to 1.13, 2B.9, 2B.13 (mount side), 2B.17 (partition and mount), 6.1, and the 0.11
build-tool spike.

## In one line

```
scripts/build.sh --dev      # test build; needs Linux x86_64 with KVM; about an hour
tests/run-qemu-tests.sh --image output/airlock-<version>/airlock-<version>.raw
```

A release build is `scripts/build.sh` without `--dev`. It needs the signed asset manifest in
`assets/` (`manifest.json`, `manifest.json.sig`, `manifest-signing.pub.pem`, written by the
release workflow) and stops if any is missing or the signature does not verify. See
"Build inputs baked into the image" below.

The build writes `output/airlock-<version>/`:

* `airlock-<version>.raw`: the raw drive image, about 43 GiB but sparse (a few GiB on disk).
* `airlock-<version>.raw.zst`: the same image compressed with zstd; this is what is published.
* `SHA256SUMS`: SHA-256 of both. `scripts/flash.sh` compares the written drive with the `.raw` line.
* `serial.log`: the build VM's serial console, with the `AIRLOCK-FINALIZE-OK` line.

## What the build host needs

Linux x86_64 with KVM (`/dev/kvm` readable and writable), `qemu-system-x86`, `qemu-utils`,
`ovmf`, `zstd`, `curl`, `openssl`, `python3` with `python3-yaml`, and about 60 GB free. Packer is
optional: `scripts/build.sh` fetches the pinned Packer 1.11.2 and QEMU plugin 1.1.8 from
releases.hashicorp.com into `cache/` and checks each zip's SHA-256 against `pins.yml`
(`packer_linux_amd64`, `packer_plugin_qemu_linux_amd64`). `packer init` and GitHub are not
used. `scripts/build.sh --prepare-tools` does only that step, for CI caches.

Without KVM the build refuses; `--accel tcg` emulates instead and takes many hours.

## What `scripts/build.sh` does

1. Reads `ansible/group_vars/all/pins.yml` (`ubuntu_server_iso` URL and SHA-256; it refuses a
   null hash) and `ansible/group_vars/all/main.yml` (version, `apt_snapshot`, partition sizes).
2. Makes a fresh Ed25519 key for this build only (in a temporary folder, deleted at the end).
3. Stages the build inputs (trusted manifest, its signature and public key, goss,
   `build-kind.json`) in that temporary folder; see below.
4. Writes the Packer variables and runs `packer validate`, then `packer build` on
   `packer/ubuntu-24.04.pkr.hcl`. `--dry-run` prints the variables and the command instead.
   `SOURCE_DATE_EPOCH` sets the recorded build date.

Inside the build VM (QEMU, UEFI firmware):

1. **Autoinstall** (`packer/http/user-data`, served by Packer): Ubuntu 24.04.5 live-server ISO,
   minimal server, the generic HWE kernel (`linux-generic-hwe-24.04`), no vendor drivers or OEM
   kernels, every package from the dated snapshot `https://snapshot.ubuntu.com/ubuntu/<apt_snapshot>`
   (task 6.1), the drive layout below, no swap, no LVM. Two accounts: `analyst` with a locked
   password and no key, and `airlock-build`, which only has the per-build key.
2. `packer/scripts/bootstrap.sh` waits for cloud-init and installs Ansible from the snapshot.
3. The repo's `ansible/`, `profiles/`, `docs/` and `tests/goss/` are copied to
   `/opt/airlock/repo` (what offline provisioning and its goss self-test read), the build
   inputs to `/var/tmp/airlock-inputs`, and `packer/scripts/run-ansible.sh` runs
   `ansible-playbook -c local site.yml` with `airlock_phase=image` (task 1.4).
   `--idempotence-check` runs it twice and fails on any change.
4. **Finalize** (`packer/scripts/finalize.sh`, started by Packer's shutdown command in its own
   systemd unit): runs `site.yml --tags airlock_finalize`, which purges the SSH server, deletes
   `airlock-build`, its sudo rule and the installer's cloud-init and network files, disables
   cloud-init, empties `/etc/machine-id`, and cleans the apt cache; deletes the upload folders;
   then trims free space,
   writes `AIRLOCK-FINALIZE-OK` to the serial port, and powers off. If anything fails it writes
   `AIRLOCK-FINALIZE-FAILED` and does not power off, so the build times out and fails.
5. **Post-processor** (`packer/scripts/postprocess.sh`, on the host): refuses the image unless the
   serial log has `AIRLOCK-FINALIZE-OK`, compresses it, tests the archive, writes `SHA256SUMS`.

## Build inputs baked into the image

The image never downloads anything for these; `scripts/build.sh` prepares them on the build
host, Packer uploads them, and the base role (`image_inputs.yml`) checks them again before
installing them (decision log 2026-11-15).

| Input | Release build (default) | `--dev` build | Installed at |
|---|---|---|---|
| Asset manifest + signature | `assets/manifest.json`, `assets/manifest.json.sig` (or `--manifest-dir DIR`); refused if missing or if the signature does not verify | made from this checkout by `scripts/gen-manifest.py` (release `<version>-dev`) and signed with a throwaway key | `/var/lib/airlock/manifest.json`, `.sig` |
| Public key | `assets/manifest-signing.pub.pem` | the throwaway key's public half; the private half is deleted right after signing | `/etc/airlock/manifest-signing.pub.pem` |
| goss | `pins.goss_linux_amd64`, SHA-256 checked, cached in `cache/sha256/`; required | the same; skipped with a warning while the pin is null | `/opt/airlock/bin/goss` (provisioning self-test, 2B.6) |
| Build kind | `release` | `dev` | `"build_kind"` in `/etc/airlock/build-info.json` |

A dev image trusts only its own throwaway key, so it provisions from what the fetcher staged
(checked against the dev manifest) but never accepts a release-signed manifest from ASSETS as
newer. Never publish a dev image. `--dry-run` prints the build kind and the staged files;
`--prepare-tools` also fetches goss into the cache.

## Drive layout (contract section 3)

| # | GPT name | Type | Size | Filesystem | Mounted at |
|---|---|---|---|---|---|
| 1 | `BIOSBOOT` | EF02 | 1 MiB | none (grub i386-pc core) | |
| 2 | `EFI` | EF00 | 512 MiB (`esp_size_mib`) | FAT32, label `EFI` | `/boot/efi` |
| 3 | `ASSETS` | 0700 | 20 GiB (`assets_partition_gib`) | exFAT, label `ASSETS` | `/srv/airlock/assets`, `ro,noexec,nosuid,nodev` |
| 4 | `OUTPUT` | 0700 | 8 GiB (`output_partition_gib`) | exFAT, label `OUTPUT` | `/srv/airlock/output`, `rw,noexec,nosuid,nodev,uid=<analyst>` |
| 5 | `AIRLOCK_ROOT` | 8300 | 14 GiB (`root_image_gib`), grows on first boot | ext4, label `AIRLOCK_ROOT` | `/` |

The image is 1 MiB + the partitions + 1 MiB for the backup GPT: 42.5 GiB with the defaults.
Curtin cannot make exFAT or name partitions, so the installer leaves 3 and 4 empty and the
base role's `airlock-partition-layout` sets the names and types and runs `mkfs.exfat` once
(2B.9, 2B.17). It only ever touches the disk that holds `/`, refuses any disk without exactly
these five partitions, and never formats a partition that has a filesystem. fstab names
ASSETS and OUTPUT by UUID with `nofail` and no fsck (2B.13). Large staged data is used in
place from the read-only ASSETS mount; nothing on it can be executed.

## Boot

* **UEFI**: Ubuntu's signed shim and grub at the removable-media path `EFI/BOOT/BOOTX64.EFI`
  (`grub-install --removable --no-nvram`), plus `EFI/ubuntu/` whose `grub.cfg` the signed grub
  reads. No firmware boot entry is written on the build VM or on any PC the drive is plugged
  into; shim's fallback `fbx64.efi`, which would write one, is removed. Package upgrades keep the
  removable copy (`grub2/force_efi_extra_removable`). Task 1.9.
* **Legacy BIOS**: grub i386-pc in the BIOSBOOT partition of the same disk. Both read
  `/boot/grub/grub.cfg`; the kernel finds root by UUID. `os-prober` is off, so `update-grub`
  never opens an attached disk.
* **Kernel command line**: `airlock_kernel_cmdline` from `main.yml`, written to
  `/etc/default/grub.d/90-airlock.cfg` (`GRUB_CMDLINE_LINUX`).
* **Secure Boot**: see `docs/hardware-matrix.md` (task 1.13). The build fails if the installed
  shim or grub is below `base_min_sbat` (shim 4, grub 5); `/etc/airlock/boot-chain.json`
  records the SBAT entries and which Microsoft CA signed the shim.
* **Initramfs**: `MODULES=most` plus `uas`, `usb_storage`, `nvme`, `vmd`, `ahci`, `xhci_pci`
  and friends by name, so the drive boots on hardware other than the build VM (1.3, 1.12).

### USB compatibility mode (UAS workaround, task 1.12)

Some USB-SATA bridges hang or drop out in UAS mode. The boot menu has a second entry,
**"Ubuntu, AIRLOCK USB compatibility mode (UAS off)"**, which boots with
`modprobe.blacklist=uas`: every USB disk then uses the older usb-storage driver. It names no
vendor, so it works for any bridge.

To turn UAS off for one bridge only (and keep it for the AIRLOCK stick itself):

1. Plug the bridge into a running Linux system and run `lsusb`. Note its `ID vvvv:pppp`.
2. One boot: at the boot menu press `e`, add `usb-storage.quirks=vvvv:pppp:u` to the end of
   the `linux` line, and press F10.
3. Every boot on one site: put `vvvv:pppp:u` in `/etc/airlock/usb-storage-quirks` (or set
   `base_uas_quirks` when building a site image) and run `sudo update-grub`. The value is
   added to the compatibility entry only. Never commit a vendor ID to the repository.

## First boot (task 1.10)

`airlock-firstboot.service` runs once on a newly flashed drive: it commits a new machine ID
(the image ships an empty `/etc/machine-id`, so every drive differs), moves the backup GPT to
the real end of the drive, grows `AIRLOCK_ROOT` to fill it (`growpart`, `resize2fs`), writes
`/var/lib/airlock/firstboot.done`, and disables itself. The image has no SSH server, so there
are no SSH host keys to make.

`/etc/airlock/build-info.json` records `schema`, `name`, `version`, `git_commit`,
`build_date` (UTC), `ubuntu_release`, `apt_snapshot`, `apt_snapshot_used`, `kernel_package`.

## Testing the image in QEMU (tasks 1.11, 3.9)

```
tests/run-qemu-tests.sh --image IMAGE.raw [--firmware uefi,uefi-sb,bios] [--nic] [--boot-bus usb]
```

* Boots a qcow2 overlay of the image (the image is never written), grown by 4 GiB so the
  first-boot grow runs, under OVMF (`uefi`), OVMF with Secure Boot and Microsoft keys
  (`uefi-sb`), and SeaBIOS (`bios`). KVM when `/dev/kvm` is usable, otherwise emulation with
  long timeouts.
* Attaches raw test disks (virtio; inside the guest `/dev/disk/by-id/virtio-<serial>`):
  `airlock-ext4` (ext4 with one file), `airlock-swap` (GPT swap partition), `airlock-sig`
  (LVM PV and VG, two mdraid v1.2 members, swap; needs root and lvm2 on the host, 3A.10), and
  optionally `airlock-ntfs` (`--ntfs-fixture FILE`). Each is hashed before and after; any
  change fails the run.
* No network device unless `--nic` (then a QEMU user-mode NIC with `restrict=on`).
* Offline provisioning is kept out of the way: the guest gets the SMBIOS OEM string
  `airlock.noprovision` (`-smbios type=11,...`); the image's grub hook
  `/etc/grub.d/06_airlock_vm_test` turns exactly that word into `airlock.noprovision` on the
  kernel command line, and `airlock-provision.service` (`ConditionKernelCommandLine=!airlock.noprovision`)
  skips. The harness fails the run if the word did not arrive. `--provision` leaves it off.
* Talks to the guest only through the QEMU guest agent on a virtio serial port: copies in the
  host's goss binary, `tests/goss/*.yaml` and `tests/vm/*.sh`, checks the firmware actually
  used and that systemd reaches `running`, then runs every goss file and every VM test as root.
  VM tests get `AIRLOCK_TEST_DIR`, `AIRLOCK_TEST_FIRMWARE`, `AIRLOCK_TEST_NIC` and
  `AIRLOCK_TEST_DISK_{EXT4,SWAP,SIG,NTFS}`; goss files get the same as `--vars-inline`
  (`.Vars.disks.ext4`, `.Vars.firmware`, `.Vars.nic`, `.Vars.provision` false), and `AIRLOCK_SIGDISK_SHA256` carries the host's hash of the sig disk. Exit 77 from a VM test is a skip.
* The same goss files run inside `forensic-provision`'s self-test with `.Vars.provision` true
  and no disks. Checks that need the test disks or a running desktop sit inside
  `# {{ if not (index .Vars "provision") }}` ... `# {{ end }}` (template directives in YAML
  comments, so the files stay plain YAML for the unit tests).
* `--dry-run` prints the plan and the QEMU command lines; `--keep-work` and `--results DIR` keep
  the serial logs and per-test output.

The guest agent package is in the image but only starts when a virtio guest-agent port
exists, which real PCs do not have, and `/etc/qemu/qemu-ga.conf` allows only the commands the
harness uses.

## Build-tool spike (task 0.11)

The plan asks whether Packer + Ansible is reproducible enough, compared with mkosi. This needs
a KVM host and several hours, so it is a person's job (status needs-human).

**Packer half** (scripted):

```
sudo scripts/build-tool-spike.sh build --out output/spike     # two builds, same commit and epoch
sudo scripts/build-tool-spike.sh compare A.raw B.raw --out DIR  # compare any two images
```

`compare` writes `spike-report.md` and `spike-report.json`: whole-image and per-partition
SHA-256, and every root filesystem path that was added, removed, or changed (type, mode,
owner, size, SHA-256, link target).

**mkosi half** (manual, on the same host):

1. Install mkosi 24 or later from the distribution or `pipx install mkosi`, and record its version.
2. Write an `mkosi.conf` for Ubuntu noble: `Distribution=ubuntu`, `Release=noble`,
   `Mirror=https://snapshot.ubuntu.com/ubuntu/<apt_snapshot>`, `Format=disk`, `Bootable=yes`,
   `Bootloader=grub`, `BiosBootloader=grub`, packages `linux-generic-hwe-24.04`,
   `ubuntu-desktop-minimal`, `ansible`, and `SourceDateEpoch=` set to the same epoch.
3. Add a `mkosi.postinst` that runs `ansible-playbook -c local site.yml` from this repo in the
   image tree (`airlock_phase=image`).
4. Build twice into two output folders and compare the two `.raw` files with
   `scripts/build-tool-spike.sh compare` (it needs the five-partition layout; if mkosi's
   layout differs, compare the root partitions with `diffoscope` instead).
5. Record both results, the build times, and the decision in `docs/decision-log.md`.

## Troubleshooting

* The build VM sits at the Ubuntu installer menu: the boot keys were typed too early or too late
  for the ISO's 30-second grub menu. Rerun with `--var boot_wait=20s` (or another value).
* `packer build failed`: read the end of `output/airlock-<version>.packer.log` and
  `output/airlock-<version>/serial.log`. A timeout waiting for SSH usually means the autoinstall
  failed; the serial log shows the installer's error.
* `the finalize step did not report success`: build access may still be in the image. Do not
  publish it; fix the failing finalize task and rebuild.
* `Mesa ... is older than` or `boot chain is below the SBAT minimum`: move `apt_snapshot` in
  `main.yml` to a newer date and rebuild.
