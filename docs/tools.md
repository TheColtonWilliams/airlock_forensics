# Tools

Every third-party tool AIRLOCK calls on the running system: what it is used for and who calls it.

## forensic-analyze (wizard core)

* `bwrap` (bubblewrap, Ubuntu package `bubblewrap`): parser sandbox, first choice (3A.9).
* `systemd-run`, `unshare`, `losetup` (Ubuntu base): sandbox fallbacks and the read-only loop device handed to parsers.
* `mmls`, `fsstat`, `img_cat` (The Sleuth Kit): partition and filesystem detection (4C.16).
* `fve-dd` (Dissect, Python package `dissect.fve`): BitLocker unlock into a read-only working copy (4C.16).
* `ewfacquire`, `ewfverify` (Ubuntu package `ewf-tools`): copy-first mode, E01 (4C.24).
* `ddrescue` (Ubuntu package `gddrescue`): copy-first mode for weak drives, with a map file (4C.24).
* `hdparm`: read-only HPA (`-N`) and DCO (`--dco-identify`) queries on ATA targets (3A.6).
* `smartctl` (Ubuntu package `smartmontools`): read-only health query before a Full direct run (risk 15).
* `blktrace` (optional): per-request detail beside the write tracer's counters (3A.5).
* `openssl`: Ed25519 key, signature, and verification for `outputs.sha256` (4C.25, 2B.17).

## forensic-analyze NTFS modules (`inventory`, `recycle_bin`, `deletion_history`, `users`, `timeline`, `carve`)

Every tool runs through the parser sandbox. Each module emits every installed parser's rows and
the cross-check (`xval`) compares them; a missing optional tool is named in the summary row.

* `fls`, `icat`, `ifind`, `fsstat`, `blkcat`, `blkls`, `mactime` (The Sleuth Kit): file listing (bodyfile), copies of `$MFT`, `$UsnJrnl:$J`, `$LogFile`, `$Secure:$SDS`, `$Bitmap` into `extract/v<N>/` and of single files (`extract.export_file`), unallocated space, file-system timeline (4C.5, 4C.7, 4C.14, 4C.15).
* `target-query` (Dissect, `dissect.target`): second parser for the MFT (`-f mft --compact`), the USN journal (`-f usnjrnl`), and recycle bins on recognised Windows systems (`-f recyclebin`) (4C.28).
* Built in, standard library (`forensic_analyze/parsers/`): `$MFT` records, USN records and USN carving, `$I` files (versions 1 and 2), `$SDS` owner SIDs, LNK files, EZ Tools CSV and Dissect JSON readers.
* `MFTECmd` (`$MFT` and `$SDS`), `RBCmd`, `LECmd`, `JLECmd` (EZ Tools, when staged): further parsers; Jump Lists are parsed only by JLECmd.
* `vshadowinfo` (Ubuntu package `libvshadow-utils`): Volume Shadow Copy check, with a built-in VSS header check beside it (4C.29).
* `photorec` (Ubuntu package `testdisk`) and `bulk_extractor` (when installed): carving unallocated space, Full preset only (4C.15).
* `log2timeline`/`psort` (Plaso, when installed): super-timeline (4C.14); without it the timeline holds file system times only.

## Image build and base system (role `base`, `scripts/build.sh`, `tests/run-qemu-tests.sh`)

* `packer` 1.11.2 and its QEMU plugin 1.1.8 (build host, pinned zips): builds the image (1.1, 1.7).
* `qemu-system-x86_64`, `qemu-img`, OVMF, SeaBIOS (build host): build VM and test VMs (1.11, 3.9).
* `goss` 0.4.9 (build host, copied into test VMs only): runs `tests/goss/*.yaml` in the guest.
* `zstd`, `sha256sum` (build host): compress the image and write `SHA256SUMS` (1.6).
* `qemu-ga` (Ubuntu package `qemu-guest-agent`, in the image): test channel, starts only in a VM (1.11).
* `sgdisk` (`gdisk`), `mkfs.exfat` (`exfatprogs`), `blkid`: drive layout helper (2B.9, 2B.17).
* `grub-install` (`grub-pc-bin`, `grub-efi-amd64-signed`, `shim-signed`): portable boot (1.9).
* `growpart` (`cloud-guest-utils`), `resize2fs`, `systemd-machine-id-setup`: first boot (1.10).
* `openssl pkcs7`: reads shim's signers for the Secure Boot check (1.13).

## Local AI (role `tools_ai`, Milestone 4B)

* `llama-server`, `llama-mtmd-cli` (llama.cpp, built from the pinned tag with Vulkan only, `/opt/llama/bin`): descriptions, OCR of cleared scanned pages, summaries (`evidence-describe`), native video input (4B.1, 4B.7, 4B.8).
* `vulkaninfo` (`vulkan-tools`) and Mesa's Vulkan drivers (`mesa-vulkan-drivers`: RADV, ANV, NVK): tier probe and GPU back end (4B.2, 4B.3).
* `systemd-socket-proxyd`: socket activation of the model server on 127.0.0.1 (4B.10).
* NudeNet and SigLIP through ONNX Runtime in `/opt/triage` (`airlock_ai/triage_runner.py`, sandboxed): screening (4B.5, 4B.6).
* faster-whisper in `/opt/whisper` (`airlock_ai/whisper_runner.py`, sandboxed): audio transcripts (4B.7).
* `ffmpeg` (frames every 2 s plus scene changes, audio tracks), `ffprobe`, `mediainfo`, `exiftool`: video, audio, and image metadata (4B.7, 4C.8-4C.10).
* `pdftotext`, `pdftoppm` (`poppler-utils`), `soffice --headless --convert-to` (LibreOffice): document text and scanned pages (4B.9, 4C.11).
* `llama-server` on 127.0.0.1 (same server, `/v1/chat/completions`, `/completion` fallback, `/props` and `/v1/models` for provenance): draft results, interpretation, and conclusions in `evidence-report` (4E.2, 4E.3); the report runs without it. Standard library only otherwise (`sqlite3`, `urllib`, `html`).

## Hash sets and signatures (role `tools_hashsets`, `evidence-triage-hash`, `malware` module; Milestone 4A)

Every scanner runs in the parser sandbox and sees only alias names (`f0000000`, ...), never names from evidence. See `docs/workflows/hash-triage.md`.

* `clamscan` (noble `clamav`, never `clamd`): `--no-summary --infected --file-list` with `-d` for each ClamAV database and `.hsb` in `/opt/hashsets/clamav`; read only, no `--remove`/`--move`/`--copy` (4A.3, 4A.4, 4A.6, 4C.12).
* `sigtool --info` (noble `clamav`): checks ClamAV's own signature on `main.cvd`/`daily.cvd` at provisioning (4A.3).
* `yara --compiled-rules --scan-list` and `yarac` (noble `yara`): rule packs compiled at provisioning with empty external variables, then scanned (4A.5, 4A.6).
* `ssdeep -s -c -b` (noble `ssdeep`): fuzzy hashes, and `-m LIST` matching against lists in `/opt/hashsets/ssdeep` (4A.6, 4D.8).
* Python `sqlite3` (stdlib): NSRL RDSv3 lookups, read-only and immutable (4A.2, 4D.8). Hashing uses `hashlib`; `hashdeep` and `python3-tlsh` are installed for the examiner (4A.1).

## Assets and provisioning (`forensic-provision`, `forensic-import`, session-start asset check)

* `openssl pkeyutl -verify -pubin -rawin`: checks `manifest.json.sig` against the baked Ed25519 public key (2B.15).
* `ansible-playbook -c local` (Ubuntu package `ansible`): applies the roles offline from `/opt/airlock/repo` (2B.5).
* `goss`: the self-test after provisioning, from `/opt/airlock/repo/tests/goss` (2B.6); recorded as not run when absent.
* `sigtool` (ClamAV, optional): checks the vendor signature of staged `.cvd`/`.cld` files (2B.15).
* `dpkg-query`, `lsblk`, `systemctl reboot`: tool versions for the provisioning manifest, the attached-disk refusal, the final reboot.
* Validation host only (never on the drive, `docs/validation.md`): `mkfs.ntfs` and `ntfs-3g`, `mkfs.exfat` and `mount.exfat-fuse` under libfaketime (`faketime` package) build the synthetic images; `forensic-analyze` with The Sleuth Kit, Dissect and PhotoRec analyses them; `openssl` via `scripts/sign-manifest.sh` signs the validation report.
* Host side only (never on the drive): `python3` with PyYAML for `scripts/gen-manifest.py` and `scripts/check-pins.py`; `fetch-assets.sh` uses `python3`, `lsblk`, `blkid`, `findmnt`, `mount` (or `mount.exfat-fuse`); `fetch-assets.ps1` uses PowerShell's `Invoke-WebRequest`, `Get-FileHash`, `Get-Volume` and .NET `HttpWebRequest`.

## Forensic tool roles (tasks 4.1 to 4.9, 6.5; checks in `tests/goss/tools.yaml`)

One line per tool: command, where it comes from, what it is for. "noble" means the Ubuntu 24.04
archive (from the dated snapshot, task 6.1). Runbook using them in order:
`docs/workflows/windows-external-drive.md`.

* `ewfacquire`, `ewfverify`, `ewfexport`, `ewfinfo` (noble `ewf-tools`, `libewf2`): E01 images, make and check (4.1).
* `dc3dd` (noble `dc3dd`): raw images with hashing and a log (4.1).
* `ddrescue` (noble `gddrescue`): images of weak or failing drives with a map file (4.1).
* `affinfo`, `affcat` (noble `afflib-tools`): AFF images (4.1).
* `guymager` (noble `guymager`): Linux-native GUI imager for E01, AFF and raw (4.1).
* `hashdeep`, `md5deep`, `sha256deep` (noble `hashdeep`): hash sets and audit mode (4.1).
* `ssdeep` (noble `ssdeep`): fuzzy hashes (4.1).
* `vshadowinfo`, `vshadowmount` (noble `libvshadow-utils`): Volume Shadow Copies (4.1).
* `mmls`, `fls`, `istat`, `icat`, `ifind`, `tsk_recover`, `blkls`, `fsstat`, `mactime`, `usnjls` (noble `sleuthkit` 4.12.1): read file systems without mounting them (4.2).
* `fsntfsinfo` and Python `pyfsntfs` (noble `libfsntfs-utils`, `python3-libfsntfs`): NTFS details from libfsntfs (4.2).
* `ntfsinfo`, `ntfsls`, `ntfscat` (noble `ntfs-3g`): NTFS information; ntfs-3g's format, repair, resize, wipe, relabel and write tools (`ntfsfix`, `mkntfs`, `ntfsresize`, ...) are diverted off PATH (4.2).
* `target-query`, `target-shell`, `target-fs`, `target-info`, `target-dump`, `target-reg`, `target-dd`, `target-mount`, `rdump`, `fve-dd`, `parse-lnk` (Dissect 3.22 from PyPI, venv `/opt/dissect`, every package hash-pinned in `tools_dissect/files/requirements.txt`; AGPL-3.0): one Python API over E01, NTFS, USN, registry, BitLocker (4.3).
* `dotnet` (.NET runtime 9.0.4, Microsoft's packages for Ubuntu 22.04 pinned by SHA-256; Microsoft's noble suite has no .NET 9): runs EZ Tools (4.4).
* `MFTECmd`, `RBCmd`, `LECmd`, `JLECmd`, `PECmd`, `EvtxECmd`, `AmcacheParser`, `AppCompatCacheParser`, `RECmd`, `SBECmd`, `bstrings` (EZ Tools .NET 9 zips, staged on ASSETS when the profile has `eztools`, unpacked to `/opt/eztools/<Tool>/` at first boot; wrappers in `/usr/local/bin`): Windows artifact parsers whose CSV output other examiners know (4.4).
* `log2timeline`, `psort`, `pinfo`, `psteal`, `image_export` (Plaso 20261027 from PyPI, venv `/opt/plaso`, hash-pinned in `tools_timeline/files/requirements.txt`; noble's own plaso is from 2020): super-timelines (4.5).
* `photorec`, `testdisk` (noble `testdisk`): file carving (4.6).
* `scalpel`, `foremost` (noble): header and footer carving (4.6).
* `bulk_extractor` 2.1.1 (built from the pinned release tarball into `/opt/bulk_extractor`; noble has no package): feature extraction and carving (4.6).
* `usncarve` (usncarve 1.2.2 from PyPI, venv `/opt/usncarve`): USN journal records carved from unallocated space or any file (4.6).
* `exiftool` (noble `libimage-exiftool-perl` 12.76; the role refuses anything older than 12.24): image and document metadata (4.7).
* `mediainfo`, `ffprobe`, `ffmpeg` (noble): audio and video metadata (4.7).
* `exiv2` (noble): EXIF, IPTC and XMP metadata (4.7).
* `vinetto` (noble): Windows `Thumbs.db` (4.7).
* `thumbcache-extract`, `thumbcache-extract-indexed` (Dissect's `dissect.thumbcache` in `/opt/dissect`; noble has no package): Windows `thumbcache_*.db` (4.7).
* `regripper`, `rip.pl` (noble `regripper` 3.0): registry hive reports (4.8).
* `regfinfo`, `regfexport` (noble `libregf-utils`): registry hive structure (4.8).
* `hivexget`, `hivexml`, `hivexsh` (noble `libhivex-bin`): registry values; open hives without `-w` (4.8).
* `autopsy` (optional, `install_autopsy=false`; Autopsy 4.23.1 zip and Sleuth Kit Java .deb staged on ASSETS, Java 17 from noble): GUI case manager; while a case is open it runs its search server on this computer only (4.9).
* `cast` (optional, `install_sift=false`; Cast 1.0.13 .deb): installs SANS SIFT in server mode at image build only; hardening re-applies after it (6.5).

## CI, release, and repository tools (host side; never on the image)

* `.github/workflows/lint.yml` (5.6, 4G.1): `scripts/lint.sh` plus actionlint, `tests/run-unit.sh`, and `tests/run-functional.sh` as root, on every pull request.
* `.github/workflows/build.yml` (5.7, 2A.8, 2B.8, 2B.16): builds the image, boot-tests it under UEFI, Secure Boot and BIOS (KVM, else TCG), runs `make-usb.sh --yes --profile ci` on a loop device, and provisions the staged image offline with and without a network card, then runs the full suite.
* `.github/workflows/windows.yml` (4G.2): PSScriptAnalyzer on every `.ps1`, and `tests/windows/Test-FetchAssets.ps1` (fetcher under PowerShell 5.1 and 7 against a VHDX with an exFAT or NTFS `ASSETS` volume).
* `.github/workflows/release.yml` (6.3, 2B.1, 2B.2): on a version tag, build, test, signed manifest, syft SBOM, validation report, image parts, `SHA256SUMS` with a cosign keyless signature, GitHub Release. See `docs/release-process.md`.
* `scripts/setup-branch-protection.sh [--dry-run] [--reviews N] [--with-build]` (0.8): protects `main` with `gh api` (pull request and green checks required) and turns on private vulnerability reporting. See `docs/dev/repo-setup.md`.
* `live/build.sh [--config-only]` (7.2): builds the amnesic live ISO with live-build, applying `ansible/site.yml` in a chroot hook. See `live/README.md`.
