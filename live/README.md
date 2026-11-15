# AIRLOCK live ISO (task 7.2)

An amnesic variant of AIRLOCK: a live system that boots from read-only media and forgets
everything when it shuts down. It is built from the same Ansible roles as the installed drive,
so the same hardening applies and is re-applied last. Status: **implemented, not yet built or
tested**; it needs a build host with network access and root, and then the same QEMU and
hardware checks as the installed image.

Why live-build, and not remastering an Ubuntu ISO: see the decision log entry of 2026-11-15
(task 7.1). In short, live-build builds the system from packages with a recorded
configuration and runs our playbook inside it through a chroot hook; a remaster would start
from someone else's finished image and patch it.

## Build

On an Ubuntu 24.04 host:

```
sudo apt install live-build python3-yaml
sudo live/build.sh                       # writes output/airlock-live-<version>/airlock-live-<version>.iso
live/build.sh --config-only --out /tmp/x # only write the live-build configuration (no root)
```

`live/build.sh`:

1. reads `airlock_version`, `ubuntu_release`, `apt_snapshot` and `airlock_kernel_cmdline` from
   `ansible/group_vars/all/main.yml`;
2. runs `lb config` in Ubuntu mode (casper initramfs, generic kernel, hybrid ISO, no installer,
   no source, no memtest) with every mirror set to the dated snapshot
   `https://snapshot.ubuntu.com/ubuntu/<apt_snapshot>`, and the hardened kernel command line;
3. copies `ansible/` and `profiles/` to `/opt/airlock/repo` in the live system
   (`config/includes.chroot`), writes the Ansible variables (`airlock_phase=image`,
   `airlock_target=live`), and adds `ansible-core` to the package list;
4. installs [hooks/0500-airlock-site.hook.chroot](hooks/0500-airlock-site.hook.chroot), which runs
   `ansible-playbook -c local site.yml` inside the chroot;
5. installs [hooks/0600-airlock-casper.hook.chroot](hooks/0600-airlock-casper.hook.chroot) and the
   files in [initramfs/](initramfs/) (see "Attached disks during boot" below);
6. runs `lb build` and writes the ISO and `SHA256SUMS`.

Logs: `lb-config.log` and `lb-build.log` in the output folder.

## What differs from the installed drive

* Nothing persists: no case output on the boot media, no `OUTPUT` partition. Write case output
  to a separate drive made writable with `evidence-unlock-output`.
* No `ASSETS` partition on the ISO. Large staged data (models, hash sets) comes from a separate
  drive labelled `ASSETS`, checked against the signed manifest as on the installed drive.
* The roles must skip what only fits an installed drive when `airlock_target` is `live`: the
  partition layout, the boot loader install, the first-boot growth unit, and fstab entries by UUID.
  The `base` role honours `airlock_target=live` and skips those tasks. `live/build.sh` does not
  yet stage the signed manifest or goss into `/var/tmp/airlock-inputs`, so a live ISO has no
  baked trusted manifest (build-info `build_kind` is `none`) and every ASSETS feature stays off
  until that is added.

## Attached disks during boot

Ubuntu's live initramfs (casper) would otherwise look for its medium by mounting partitions on
every attached disk, and would run `swapon` on any swap partition it finds. A mount can replay a
filesystem journal and swapping writes to the disk, so both would change evidence before the
software read-only policy exists. The live ISO prevents this in four ways:

* the kernel command line carries `live-media=/dev/disk/by-label/<ISO volume label>`, so casper
  looks only at the AIRLOCK medium, and `nopersistent`, so it never looks for a persistence
  partition; `live/build.sh` refuses a label longer than ISO 9660's 32 characters;
* `0600-airlock-casper.hook.chroot` sets `LIVEMEDIA_TIMEOUT=60` in `/etc/casper.conf` (casper
  reads it only there), so casper never falls back to scanning other disks; if the medium is not
  found it stops the boot instead;
* the same hook diverts `casper-bottom/13swap` out of the initramfs, so nothing runs `swapon`;
* [initramfs/casper-premount-05airlock_readonly](initramfs/casper-premount-05airlock_readonly)
  sets every `sd*`, `nvme*`, `mmcblk*`, and `vd*` disk and partition read-only before casper
  looks for the medium (the medium too: it is mounted read-only anyway), and
  [initramfs/00-airlock-initramfs-ro.rules](initramfs/00-airlock-initramfs-ro.rules) does the
  same for disks that appear later in the initramfs. If a disk cannot be set read-only the boot
  stops.

The hook rebuilds the initramfs and fails the build unless the result holds all of this.
After the switch to the live root, the harden_storage role's udev rule and `airlock-setro` take
over (the live root is an overlay, so no disk is exempt).

## Testing (not done yet)

1. Boot the ISO in QEMU under UEFI and BIOS and run the goss files from `tests/goss/`
   (`tests/run-qemu-tests.sh` boots disk images; it needs a `--cdrom` mode for this).
2. Boot it with test disks attached (an ext4 disk with a dirty journal, a disk with a swap
   partition) and check: `swapon --show` prints nothing, every attached disk reads `1` in
   `/sys/class/block/*/ro`, the test disks' hashes are unchanged after shutdown, and the kernel
   command line holds `live-media=` and `nopersistent`. Also boot with the medium removed after
   the boot loader: casper must stop, not scan the other disks.
3. Run [docs/hardware-checklist.md](../docs/hardware-checklist.md) on real PCs.
