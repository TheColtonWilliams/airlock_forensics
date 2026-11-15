# Hardening controls

Every control the image enforces, how it is enforced, and the test that proves it. A control is one
task file in an Ansible role (`ansible/roles/<role>/tasks/<file>.yml`); `tasks/main.yml` only imports
them. The roles run first in `ansible/site.yml` and again as the last play, so no tool role can undo
them (task 5.8, `tests/unit/test_site_order.py`). `tests/unit/test_harden_coverage.py` fails if a
masked unit, removed package, or removed file has no goss check, or if a control file does not name
an existing test.

goss files run inside the booted image (`tests/run-qemu-tests.sh`); `tests/vm/` scripts run there too.
Units are "masked" when `/etc/systemd/system/<unit>` (or `/etc/systemd/user/<unit>` for user units)
links to `/dev/null`; the goss checks look for exactly that link.

The read-only layer is a **software read-only policy**. It is not a write blocker: root can clear the
flag and raw SCSI commands can bypass it. Use a hardware write blocker as well.

## Storage (`harden_storage`, tests in `tests/goss/storage.yaml`)

| Task | Control | Mechanism | Test |
|---|---|---|---|
| 3.1 | No auto-mount: udisks2 off | `automount_udisks2.yml`: mask `udisks2.service` | goss mask link + not running; `tests/vm/test_automount.sh` |
| 3.1 | No auto-mount: desktop keys | `automount_dconf.yml`: dconf system db `local`, keys `automount=false`, `automount-open=false`, `autorun-never=true`, locked | goss `dconf read`/`list-locks`; `tests/unit/test_harden_desktop.py` compiles and reads them back |
| 3.2 | Software read-only policy | `readonly_udev.yml`: `00-forensic-ro.rules` (numbered to run before any package rule; bcache, multipath and iSCSI activation rules are masked) runs `/usr/local/sbin/airlock-setro %k` on every `sd*`, `nvme*`, `mmcblk*`, `vd*` disk and partition; the helper runs `blockdev --setro` on all but the disk holding `/`, logs each decision, fails closed | `tests/functional/test_udev_ro.sh` (stubs and real loop devices); goss `airlock-setro --check`; `tests/vm/test_automount.sh` (`dd` write refused) |
| 3.3 | No swap | `no_swap.yml`: mask `swap.target`, comment out fstab swap lines, delete `/swap.img` | goss mask link, `swapon --show` empty, fstab; `tests/unit/test_harden_storage.py` |
| 3.3 | No hibernate | `no_hibernate.yml`: mask hibernate, hybrid-sleep, suspend-then-hibernate targets and services; `sleep.conf.d` forbids hibernation | goss mask links and sleep config |
| 3.3, 3.4, 3A.1 | Kernel command line | `kernel_cmdline.yml`: asserts the image's `/etc/default/grub.d/90-airlock.cfg` holds `noresume systemd.gpt_auto=0 rd.systemd.gpt_auto=0 rd.lvm=0 rd.md=0 rd.dm=0 rd.luks=0 nodmraid` (from `airlock_kernel_cmdline`) | goss `/proc/cmdline`; `tests/unit/test_harden_storage.py` runs the task against good and bad files |
| 3.4 | No GPT auto-mount or auto-swap | `gpt_auto_off.yml`: `systemd-gpt-auto-generator` masked (plus `systemd.gpt_auto=0`) | goss link; `tests/vm/test_storage_untouched.sh` |
| 3A.2 | No disk daemons | `storage_daemons_masked.yml`: mask `lvm2-monitor`, `mdmonitor`, md check timers, `multipathd`, `smartmontools` (alias `smartd`), `e2scrub` | goss mask links + not running |
| 3A.1, 3A.2 | No LVM activation | `lvm_autoactivation_off.yml`: `lvm.conf` `auto_activation_volume_list = []`, `event_activation = 0`; initramfs rebuilt | goss grep; `tests/unit/test_harden_storage.py`; `tests/vm/test_storage_untouched.sh` |
| 3A.1, 3A.2 | No RAID assembly | `md_autoassembly_off.yml`: `mdadm.conf` `AUTO -all`; initramfs rebuilt | goss grep; `tests/unit/test_harden_storage.py`; `tests/vm/test_storage_untouched.sh` |
| 3A.2 | No commands sent to disks | `no_disk_commands.yml`: `85-hdparm.rules` overridden by a link to `/dev/null` (no spin-down or APM); smartd masked above | goss link |
| 3A.4 | SCSI generic root-only | `sg_root_only.yml`: `99-airlock-sg-root-only.rules` sets `/dev/sg*` and `/dev/bsg/*` to `0600 root:root` (final `:=`); `sg3-utils`, `sg3-utils-udev`, `sdparm` purged | goss rule, packages absent, node modes |

Nothing mounts or checks an attached disk: fstab names only the AIRLOCK partitions, by UUID
(goss `fstab by UUID`); the GPT auto generator is off; udisks2 and the gvfs volume monitors are off;
LVM and md never activate a foreign volume; e2scrub and smartd are masked. `tests/vm/test_automount.sh`
and `tests/vm/test_storage_untouched.sh` prove it by behaviour after boot and after hot-plug events.

## Network (`harden_network`, tests in `tests/goss/network.yaml`)

| Task | Control | Mechanism | Test |
|---|---|---|---|
| 3.5 | Radios blocked at boot | `rfkill_unit.yml`: `forensic-rfkill.service` runs `rfkill block all` before `network-pre.target` and NetworkManager; `72-forensic-rfkill.rules` soft-blocks each new radio and takes `/dev/rfkill` away from the desktop session; `systemd-rfkill` masked; `rfkill.default_state=0` on the kernel command line | goss unit enabled, `rfkill` shows nothing unblocked; `tests/unit/test_harden_network.py` |
| 3.6 | Radio modules cannot load | `radio_modules.yml`: `/etc/modprobe.d/forensic-radios.conf` with `install MODULE /bin/false` for cfg80211, mac80211, bluetooth, and btusb and `options rfkill default_state=0`; initramfs rebuilt | goss file, `modprobe -n`, `lsmod`, no `wl*` interface; unit test runs `modprobe -n -C` |
| 3.5 | No network services | `network_services_masked.yml`: mask NetworkManager (+wait-online, dispatcher), systemd-networkd (+socket, wait-online), systemd-resolved, systemd-timesyncd, wpa_supplicant | goss mask links + not running, no default route |
| 3.6 | Interfaces unmanaged and down | `netif_unmanaged.yml`: `99-forensic-netif.rules` sets `NM_UNMANAGED=1`, `ID_NET_MANAGED_BY`, and `ip link set dev $name down` for every interface but `lo` | goss nothing up but `lo`; `tests/vm/test_airgap.sh` |
| 3.7 | Drop-all firewall | `nftables.yml`: `/etc/nftables.conf` drops input, output, forward (inet) and ARP; accepts loopback only; `nftables.service` enabled (started on the offline first-boot run, not during the image build) | goss `nft list ruleset`, no listener off loopback; `tests/vm/test_airgap.sh` (DNS, HTTP, ping fail as root, even with the interface raised by hand) |

## Desktop (`harden_desktop`, tests in `tests/goss/desktop.yaml`)

| Task | Control | Mechanism | Test |
|---|---|---|---|
| 5.1 | No thumbnails | `thumbnails_dconf.yml`: Nautilus `show-image-thumbnails='never'`, `org.gnome.desktop.thumbnailers disable-all=true`, locked | goss `dconf read`/`list-locks`; `tests/unit/test_harden_desktop.py` |
| 5.1 | No thumbnailers | `thumbnailers_removed.yml`: purge thumbnailer and previewer packages; `dpkg-divert` every remaining `*.thumbnailer` out of use | goss packages absent, no `*.thumbnailer` left |
| 5.1 | No volume monitors | `volume_monitors_off.yml`: gvfs udisks2, MTP, gphoto2, AFC, GOA monitor user units masked for every user; `.monitor` files diverted | goss user mask links, files gone, no process; `tests/vm/test_automount.sh` |
| 5.1 | LibreOffice never offered on the desktop | `libreoffice_hidden.yml`: LibreOffice stays installed headless for the documents module, but its desktop entries and mailcap entries (full and `-nogui` names, plus any other `libreoffice*` entry found) are moved out of use with `dpkg-divert` to `/usr/lib/airlock/libreoffice-disabled`; `Hidden=true` overrides for every LibreOffice desktop ID in `/usr/local/share/applications`; `/etc/xdg/mimeapps.list` removes every association with them; desktop and mailcap caches rebuilt | goss entries gone, overrides hidden, `gio mime` names no LibreOffice for Office types, `/etc/mailcap` has no `soffice`, `soffice` still present; `tests/unit/test_harden_desktop.py` (runs the tasks on a stand-in tree; the list covers every type LibreOffice claims) |
| 5.2 | No indexer | `indexer_masked.yml`: `tracker-miner-fs-3` and friends (24.04) and `localsearch-3` (later releases) masked for every user, autostart removed, miner keys locked to index nothing | goss user mask links, autostart gone, dconf keys, no process |
| 5.1 | No screen lock | `screen_lock_off.yml` (`20-airlock-screenlock`, the only owner of these keys): `lock-enabled=false`, `disable-lock-screen=true`, `idle-delay=0`, `idle-activation-enabled=false`, `ubuntu-lock-on-suspend=false`, no sleep or idle dimming, all locked (the password is locked, so a lock screen could never be opened) | goss `dconf read`/`list-locks` |

## Services (`harden_services`, tests in `tests/goss/services.yaml`)

| Task | Control | Mechanism | Test |
|---|---|---|---|
| 5.3 | No telemetry | `telemetry_masked.yml`: mask apport, whoopsie, kerneloops, Ubuntu Pro units (`ua-timer`, `esm-cache`, `apt-news`, ...); `ubuntu-report` user units; autostart removed; `/etc/default/apport` `enabled=0` | goss mask links, not running, files |
| 5.3 | No update checks | `updates_off.yml`: mask unattended-upgrades, apt-daily timers, motd-news, fwupd, PackageKit, update-notifier user units; `99airlock-no-periodic` sets every `APT::Periodic` to 0; server-contacting `update-motd.d` scripts removed; `Prompt=never` | goss mask links, files, no update timer active; `tests/unit/test_harden_services.py` feeds the file to `apt-config` |
| 5.3 | No discovery | `discovery_masked.yml`: mask avahi-daemon (+socket), cups-browsed, ModemManager, geoclue, bluetooth | goss mask links + not running; network goss: no listener off loopback |
| 5.3 | No cloud-init | `cloud_init_off.yml`: `/etc/cloud/cloud-init.disabled` and cloud-init units masked | goss file + mask links |
| 5.4 | No snapd | `snapd.yml`: `snapd_policy=remove`: purge snapd, pin it at priority -1 (`/etc/apt/preferences.d/airlock-no-snapd.pref`) | goss package absent, `apt-cache policy` has no candidate; `tests/unit/test_harden_services.py` proves the pin with apt |

## Run-time controls (`forensic-analyze`, code in `pylib/forensic_analyze/`)

| Task | Control | Mechanism | Test |
|---|---|---|---|
| 3A.5 | Write tracer | `tracer.py`: kernel block counters (write, discard, flush requests) for the target sampled before and after each run; count in `run.json` and the report; expected 0 | `tests/functional/test_tracer.sh` (a deliberate write and discard are counted, 4G.6); `tests/unit/test_tracer_unit.py` |
| 3A.6 | HPA/DCO logged, SSD warning | `target.py`: `hdparm -N` and `--dco-identify` (read-only queries, ATA only); `rotational=0` gets a garbage-collection warning | `tests/unit/test_analyze_target.py` pins the exact argument lists |
| 3A.7 | Write-blocker record | `target.py`: in use yes/no/unknown, make, model, firmware, test-report link in `run.json` | `tests/unit/test_analyze_target.py`, `tests/functional/test_analyze_quick.sh` |
| 3A.9 | Parser sandbox | `sandbox.py`: `airlock-parse` user, no network, read-only system and evidence, one writable folder, seccomp, memory and time limits; evidence as a read-only loop device | `tests/functional/test_sandbox.sh` (4G.7); `tests/unit/test_sandbox_unit.py` |
| 4C.17 | Before/after hashes | `runner.py`: SHA-256 and MD5 of the target in one read pass before and after; read errors hashed as zeros and listed | `tests/functional/test_analyze_quick.sh`, `tests/functional/test_faults.sh`, `tests/unit/test_analyze_hashing.py` |
| 4C.25 | Signed outputs | `signing.py`: `outputs.sha256` plus an Ed25519 signature with the per-OUTPUT key | `tests/unit/test_analyze_core.py`, `forensic-analyze --verify` in `tests/functional/test_analyze_quick.sh` |

## Local AI (`tools_ai`, code in `pylib/airlock_ai/`, tests in `tests/goss/ai.yaml`)

| Task | Control | Mechanism | Test |
|---|---|---|---|
| 4B.1 | Vulkan-only llama.cpp | `llama_build.yml`: pinned tarball (`get_url` with SHA-256), `-DGGML_VULKAN=ON`, CUDA/HIP off, portable CPU code, no curl; `/opt/llama/bin` | `tests/unit/test_screen_role.py`; goss no CUDA/ROCm back end, `llama-server --version` |
| 4B.2 | Open Vulkan drivers | `vulkan_drivers.yml`: `mesa-vulkan-drivers`, `vulkan-tools`; no vendor package | goss packages, `vulkaninfo --summary` |
| 4B.3 | Tier from capacity, never vendor | `airlock_ai/probe.py` + `airlock-ai-probe.service` at boot; CPU fallback in `airlock_ai/serve.py` | `tests/unit/test_probe.py` (4G.9 table), `tests/unit/test_describe_serve.py` |
| 4B.6, 4B.17 | Flagged media never kept or described | `airlock_ai/screen.py`, `forensic_analyze/media.py`: flagged and unscored copies deleted at once; describe needs a cleared SHA-256 | `tests/functional/test_screen_stub.sh` (4G.10), `tests/unit/test_module_images.py`, `tests/unit/test_module_video.py` |
| 4B.8 | Refusals recorded | `airlock_ai/describe.py`: empty or refusing replies become `model_declined` rows | `tests/functional/test_declined.sh` (4G.11), `tests/unit/test_describe.py` |
| 4B.9, 2.3.9 | Evidence text is data | `airlock_ai/datablock.py`: cleaned, tagged data block; fixed prompts say it is never an instruction; file names never sent | `tests/unit/test_describe.py`, `tests/unit/test_module_documents.py` |
| 4B.10 | Model server on loopback only, off by default | `llama_server_unit.yml`: `llama-server.socket` on 127.0.0.1:8088 (not enabled), proxy and server units with `IPAddressDeny=any`; client refuses non-loopback URLs and ignores proxies | goss socket/listener checks; `tests/unit/test_describe.py` |
| 4B.18 | Stop control | `airlock_ai/escalate.py`: `ESCALATED` marker, process tree stopped, exports read-only, only path/ID/hash recorded | `tests/functional/test_escalate.sh` (4G.12), `tests/unit/test_escalate.py` |

## Hash sets and signatures (`tools_hashsets`, code in `pylib/airlock_hashsets/`, tests in `tests/goss/hashsets.yaml`)

| Task | Control | Mechanism | Test |
|---|---|---|---|
| 4A.1, 4A.3 | ClamAV never updates itself or runs as a daemon | `clamav_daemons_masked.yml` (runs before the packages): mask `clamav-freshclam.service`, `clamav-freshclam-once.service`, `clamav-freshclam-once.timer`, `clamav-daemon.service`, `clamav-daemon.socket`, `clamav-clamonacc.service` | goss mask links, not running, no `/var/lib/clamav/*.cvd`; `tests/unit/test_hashsets_role.py` |
| 4A.1 | Scan-only tools | `packages.yml`: clamav, yara, ssdeep, python3-tlsh, hashdeep; `clamav-daemon`, `clamdscan` absent | goss packages and `--version` commands |
| 4A.3 | ClamAV databases carry ClamAV's signature | `clamav_databases.yml`: `sigtool --info` must say `Verification OK` before `main.cvd`/`daily.cvd` are copied to `/opt/hashsets/clamav` | `tests/unit/test_hashsets.py`; goss `hash-sets-present-and-load` |
| 4A.4 | MalwareBazaar as a ClamAV hash set, snapshot logged | `malwarebazaar_hsb.yml`: export to `malwarebazaar.hsb` (`sha256:*:name:73`), snapshot date and SHA-256 values to the session log | `tests/unit/test_hashsets.py`, `tests/functional/test_triage_hash.sh` (clamscan flags EICAR through it) |
| 4A.5 | YARA packs pinned and compiled | `yara_packs.yml`: unpack rule files only (no unsafe names), `yarac` with empty externals, broken files skipped and listed | `tests/unit/test_hashsets.py`, `tests/unit/test_hashsets_role.py` |
| 4A.2, 4D.8 | NSRL read-only, SHA-256 first | `nsrl.yml` extracts to `/opt/hashsets/nsrl` or `OUTPUT/nsrl`; `airlock_hashsets/nsrl.py` opens `mode=ro&immutable=1`, weaker hashes only for rows with no SHA-256, algorithm recorded | `tests/unit/test_hashsets.py` (collision row never matches, no file written) |
| 4A.6, 2.3.9 | Evidence names never reach a scanner | `airlock_hashsets/scanners.py`: tools see only aliases `f0000000...` in list files; output mapped back by alias; sandboxed | `tests/unit/test_hashsets.py` (hostile names) |
| 4A.8 | Hash sets present and loadable; import refuses with a disk attached | `python3 -m airlock_hashsets.build check`; `forensic-import --dry-run` | goss `hash-sets-present-and-load`, `forensic-import-refuses-with-disk` |

## Base system (`base`, tests in `tests/goss/base.yaml`)

Build details: `docs/build.md`. Secure Boot: `docs/hardware-matrix.md`.

| Task | Control | Mechanism | Test |
|---|---|---|---|
| 1.2 | No password, autologin, no lock | `analyst_user.yml`, `analyst_sudo.yml`, `gdm_autologin.yml`: locked password (`!`), `NOPASSWD` sudoers file, GDM autologin with XDMCP off; screen lock and suspend off come from `harden_desktop` (row 5.1) | goss `analyst-password-locked`, sudoers, gdm, dconf files, `desktop-session` |
| 1.2, 1.5 | No build access left | `no_ssh_server.yml`, `build_access.yml` (tag `airlock_finalize`): openssh-server purged, build user and its sudo rule deleted, installer cloud-init and netplan files removed, cloud-init disabled; the post-processor refuses an image without `AIRLOCK-FINALIZE-OK` | goss no sshd, no port 22, no `airlock-build`; `tests/functional/test_build_packer_scripts.sh` |
| 1.3, 1.12 | Generic kernel, portable initramfs | `kernel.yml`, `initramfs.yml`: `linux-generic-hwe-24.04`, virtual kernels purged, `MODULES=most` plus uas, usb-storage, nvme, vmd, ahci, xhci by name | goss `kernel-generic`, `initramfs-modules` |
| 1.9 | Portable boot | `bootloader.yml`: signed shim and grub at `EFI/BOOT/BOOTX64.EFI` with `--no-nvram`, no `fbx64.efi`, i386-pc grub in BIOSBOOT; `grub_cmdline.yml`: root by UUID, os-prober off | `tests/functional/test_build_bootloader.sh` (boots SeaBIOS, OVMF, OVMF Secure Boot); goss boot files |
| 1.12 | USB compatibility boot entry | `grub_usb_compat.yml`: `41_airlock_usb_compat` adds an entry with `modprobe.blacklist=uas`, optional per-site quirk | `tests/functional/test_build_grub_usb_compat.sh`; goss `grub.cfg` |
| 1.13 | Secure Boot chain | `boot_chain.yml`: build fails below SBAT `shim,4`/`grub,5`; signers recorded in `/etc/airlock/boot-chain.json` | `tests/unit/test_base_boot_chain.py`; goss `boot-chain.json` |
| 1.10 | First boot | `firstboot.yml`, `image_finalize.yml`: empty machine ID in the image; `airlock-firstboot.service` commits a new one, grows root to the drive, disables itself | `tests/functional/test_build_firstboot.sh`; goss `firstboot.done`, `root-grown` |
| 2B.9, 2B.17 | Drive layout | `partition_layout.yml`: GPT names and types, exFAT ASSETS and OUTPUT, boot disk only, never reformats | `tests/functional/test_build_partition_layout.sh`; goss `drive-layout` |
| 2B.13, 2B.17 | Data partitions mounted safely | `data_mounts.yml`: fstab by UUID, ASSETS `ro,noexec,nosuid,nodev`, OUTPUT `rw,noexec,nosuid,nodev,uid=<analyst>`, `nofail`, no fsck | `tests/unit/test_base_role.py`; goss mounts |
| 6.1 | Dated apt snapshot | `apt_snapshot.yml` and the autoinstall: every package from `snapshot.ubuntu.com/ubuntu/<apt_snapshot>` | `tests/unit/test_packer_user_data.py`, `tests/unit/test_base_role.py`; goss sources file |
| 2B.4, 2B.7 | Offline provisioning at boot, only when ASSETS changed | `session_tools/tasks/provision_unit.yml`: `airlock-provision.service` runs `forensic-provision --if-changed` before the display manager; refuses with a network up or a second disk attached | `tests/unit/test_provision_unit.py`, `tests/unit/test_provision.py`, `tests/functional/test_assets.sh`, `tests/functional/test_refresh.sh` |
| 2B.14, 2B.15, 4G.4 | Staged files checked against the signed manifest | `airlock_common.assets.verify_staged`: ASSETS manifest used only with a valid Ed25519 signature; every file hashed at provisioning, import, and each session start; failing files turn their feature off | `tests/unit/test_assets.py`, `tests/functional/test_assets.sh` |

## Forensic tools (`tools_*` roles, tests in `tests/goss/tools.yaml` and `tests/goss/sift.yaml`)

Tool list and sources: `docs/tools.md`. Role shape, pins and goss coverage:
`tests/unit/test_tools_roles.py`, `tests/unit/test_tools_pins.py`.

| Task | Control | Mechanism | Test |
|---|---|---|---|
| 4.1 | Imaging and hashing tools | `tools_acquire`: `imaging.yml`, `guymager.yml`, `hashing.yml`, `vss.yml` (noble packages) | goss `acquire-*` |
| 4.2 | Parsers that never mount; ntfs-3g for information only | `tools_filesystem`: `sleuthkit.yml`, `libfsntfs.yml`; `ntfs3g_info_only.yml` diverts 14 write-capable ntfs-3g tools to `/usr/lib/airlock/ntfs-3g-disabled` (root only) | goss `filesystem-*`; `tests/functional/test_parsers_ntfs.sh` |
| 4.3 | Dissect pinned by hash | `tools_dissect`: venv `/opt/dissect` built at image time with `pip --require-hashes --no-deps` from `files/requirements.txt`; commands linked into `/usr/local/bin` | goss `dissect-*`; `tests/unit/test_tools_pins.py` |
| 4.4 | .NET 9 and EZ Tools, checked before use | `tools_eztools`: four Microsoft .debs pinned by SHA-256 (no apt source added); at first boot each staged zip is hashed against its pin before it is unpacked; wrappers run `dotnet <Tool>.dll` | goss `eztools-*`; `tests/unit/test_tools_eztools.py` (runs the role) |
| 4.5 | Plaso pinned by hash | `tools_timeline`: venv `/opt/plaso` from `files/requirements.txt` with `--require-hashes` | goss `plaso-version` |
| 4.6 | Carvers | `tools_carve`: PhotoRec, scalpel, foremost (noble); bulk_extractor built from the pinned tarball; usncarve venv | goss `carve-*` |
| 4.7 | Media parsers, exiftool 12.24 or later | `tools_media`: `exiftool.yml` asserts the version; mediainfo, ffmpeg, exiv2, vinetto; Dissect thumbcache commands | goss `media-*`; `tests/unit/test_tools_roles.py` |
| 4.8 | Registry parsers | `tools_registry`: RegRipper (plus `rip.pl`), libregf, hivex | goss `registry-*` |
| 4.9 | Autopsy, optional | Java 17 and the Autopsy libraries baked into every image by `base` (`packages.yml`, image phase); `tools_autopsy` (`install_autopsy=false`) only checks them offline with `dpkg-query` and stops if any is missing; zip and Sleuth Kit Java .deb from ASSETS, hash-checked before install; Solr bound to 127.0.0.1 by `SOLR_OPTS="$SOLR_OPTS -Djetty.host=127.0.0.1"` appended to the zip's `autopsy-solr.in.sh` (provisioning stops if the file is missing) | goss `autopsy-installed` (Java 17, jar, the `-Djetty.host=127.0.0.1` line); `tests/unit/test_tools_autopsy.py`; `tests/unit/test_offline_phase.py` (the packages are on every image) |
| 4.14 | Every parser finds the known deleted files | `tests/fixtures/build-ntfs-fixture.sh` and `build-exfat-fixture.sh` build the committed fixtures and ground truth | `tests/functional/test_parsers_ntfs.sh`; `tests/unit/test_tools_fixtures.py` |
| 6.5 | SIFT cannot undo the lockdown | `tools_sift` (`install_sift=false`): Cast from a pinned .deb, `cast install --mode server` at image build only; the last play of `site.yml` re-applies every hardening role | `tests/goss/sift.yaml` (rfkill, radio modules, automount, udisks2); `tests/unit/test_tools_sift.py` |
