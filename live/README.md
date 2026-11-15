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
5. runs `lb build` and writes the ISO and `SHA256SUMS`.

Logs: `lb-config.log` and `lb-build.log` in the output folder.

## What differs from the installed drive

* Nothing persists: no case output on the boot media, no `OUTPUT` partition. Write case output
  to a separate drive made writable with `evidence-unlock-output`.
* No `ASSETS` partition on the ISO. Large staged data (models, hash sets) comes from a separate
  drive labelled `ASSETS`, checked against the signed manifest as on the installed drive.
* The roles must skip what only fits an installed drive when `airlock_target` is `live`: the
  partition layout, the boot loader install, the first-boot growth unit, and fstab entries by UUID.
  Until the `base` role honours `airlock_target`, the chroot hook stops at the first of those
  tasks. That change belongs to the `base` role (see the 7.2 note in the build plan).

## Testing (not done yet)

1. Boot the ISO in QEMU under UEFI and BIOS and run the goss files from `tests/goss/`
   (`tests/run-qemu-tests.sh` boots disk images; it needs a `--cdrom` mode for this).
2. Run [docs/hardware-checklist.md](../docs/hardware-checklist.md) on real PCs.
