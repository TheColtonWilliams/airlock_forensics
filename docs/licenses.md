# Licences

The licence of every third-party component AIRLOCK installs, downloads, or calls.

Ubuntu package licences are read from each package's `/usr/share/doc/<package>/copyright` on
noble (24.04), 2026-11-15; the first licence named is the one for `Files: *` (the bulk of the
package), the rest are the parts the copyright file lists. Ubuntu packages pulled in only as
dependencies of a package listed here carry their own copyright file in the image. "Version
seen" is the noble candidate on that date; the image build installs what the dated snapshot
(`apt_snapshot`) holds. `tests/unit/test_repo_meta.py` fails when a package any role installs
(every `*_packages` list in a role's defaults, and every package an apt task names) has no row
here.

## Called by forensic-analyze (Ubuntu 24.04 packages unless noted)

| Component | Version seen (noble) | Licence |
|---|---|---|
| bubblewrap | 0.9.0 | LGPL-2.0-or-later |
| ewf-tools (libewf) | 20140814 | LGPL-3.0-or-later |
| gddrescue (GNU ddrescue) | 1.27 | GPL-2.0-or-later |
| hdparm | 9.65 | hdparm licence (BSD-style), parts GPL-2.0-or-later or BSD-2-Clause |
| smartmontools | 7.4 | GPL-2.0-or-later |
| blktrace (optional) | 1.2.0 | GPL-2.0-or-later |
| dissect.fve (`fve-dd`, PyPI) | 4.6 | AGPL-3.0-or-later (see surviving risk 8) |
| sleuthkit (`fls`, `icat`, `ifind`, `blkls`, `blkcat`, `mactime`; NTFS modules) | 4.12.1 | CPL-1.0, IBM-PL-1.0, GPL-2.0-or-later (parts) |
| dissect.target (`target-query`, PyPI; NTFS modules' second parser) | 3.25 | AGPL-3.0-or-later (see surviving risk 8); the rest of the Dissect venv closure is listed under "Plaso and Dissect venvs" below |
| libvshadow-utils (`vshadowinfo`; VSS check, 4C.29) | 20190323 | LGPL-3.0-or-later |
| testdisk (`photorec`; carving, 4C.15) | 7.1 | GPL-2.0-or-later |
| EZ Tools MFTECmd, RBCmd, LECmd, JLECmd (staged on ASSETS; optional second parsers) | pinned by the EZ Tools package | MIT (confirm per repository in 6.6, risk 7) |
| bulk_extractor (optional, carving) | pinned by the carving package | MIT (with public-domain parts) |
| Plaso `log2timeline`/`psort` (optional, timeline) | pinned by the timeline package | Apache-2.0 (Plaso itself); its venv closure adds LGPL-3.0-or-later, MPL-2.0, PSF-2.0 and a BitTorrent Open Source Licence part: see "Plaso and Dissect venvs" below |
| exiftool (`libimage-exiftool-perl`; media metadata, 4.7) | 12.76+dfsg-1 | Artistic-1.0-Perl OR GPL-1.0-or-later |

## Base image (role `base`; Ubuntu 24.04 packages from the 20261101 snapshot)

| Component | Version seen | Licence |
|---|---|---|
| shim-signed | 1.58+15.8-0ubuntu1 | BSD-2-Clause (shim) |
| grub-efi-amd64-signed, grub-efi-amd64-bin, grub-pc-bin | 2.12-1ubuntu7.3 | GPL-3.0-or-later |
| linux-generic-hwe-24.04 | 7.0.0-38.38~24.04.4 | GPL-2.0-only |
| Mesa (mesa-vulkan-drivers, libgl1-mesa-dri) | 25.2.8-0ubuntu0.24.04.2 | MIT (mostly) |
| ansible (with ansible-core 2.16.3) | 9.2.0 | GPL-3.0-or-later |
| qemu-guest-agent | 8.2.2 | GPL-2.0-only |
| cloud-guest-utils (growpart) | 0.33 | GPL-3.0 |
| exfatprogs | 1.2.2 | GPL-2.0-or-later |
| gdisk (sgdisk) | 1.0.10 | GPL-2.0-or-later |
| goss (`/opt/airlock/bin/goss`, provisioning self-test; fetched on the build host, pin `goss_linux_amd64`; also copied into test VMs) | 0.4.9 | Apache-2.0 |
| python3-apt | 2.7.7ubuntu5.3 | GPL-2.0-or-later (parts permissive) |
| dconf-cli (also installed by `harden_desktop` and `harden_storage` for their dconf locks) | 0.40.0-4ubuntu0.1 | LGPL-2.0-or-later (parts GPL-3.0) |
| dosfstools | 4.2-1.1build1 | GPL-3.0-or-later (parts public domain) |
| e2fsprogs | 1.47.0-2.4~exp1ubuntu4.1 | GPL-2.0 (parts LGPL-2.0, BSD-3-Clause, MIT, Apache-2.0) |
| locales (GNU C Library data) | 2.39-0ubuntu8 | LGPL-2.1-or-later (parts GPL-2.0, BSD, MIT) |
| openssl | 3.0.13-0ubuntu3 | Apache-2.0 (parts Artistic or GPL-1.0-or-later in the Perl build scripts) |
| tzdata | 2026e-0ubuntu0.24.04.1 | Public domain (parts ICU) |
| util-linux | 2.39.3-9ubuntu6.6 | GPL-2.0-or-later (parts LGPL-2.1-or-later, BSD-3-Clause, BSD-4-Clause, MIT, public domain) |
| libvulkan1 (Vulkan loader; also in `tools_ai`) | 1.3.275.0-1build1 | Apache-2.0 (parts MIT) |
| ubuntu-desktop-minimal (`desktop_package`; GNOME desktop metapackage, each component carries its own copyright file) | 1.539.2 | GPL-2.0-or-later (metapackage) |
| nftables (role `harden_network`, drop-all firewall) | 1.0.9-1ubuntu0.1 | GPL-2.0 (parts GPL-2.0-or-later, CC-BY-SA-4.0 docs) |

## Session helpers (role `session_tools`; Ubuntu 24.04 packages, decision log 2026-11-15)

| Component | Version seen (noble) | Licence |
|---|---|---|
| util-linux-extra (`hwclock`) | 2.39.3-9ubuntu6.6 | GPL-2.0 (util-linux; parts LGPL-2.1-or-later, BSD-3-Clause) |
| rfkill | 2.39.3-9ubuntu6.6 | GPL-2.0 (util-linux; parts LGPL-2.1-or-later, BSD-3-Clause) |
| fdisk (`sfdisk`, read-only listing for `evidence-mount`) | 2.39.3-9ubuntu6.6 | GPL-2.0 (util-linux; parts LGPL-2.1-or-later, BSD-3-Clause) |
| whiptail (prompts) | 0.52.24-2ubuntu2 | LGPL-2.0 |
| iproute2 | 6.1.0-1ubuntu6.4 | GPL-2.0 |
| ntfs-3g (read-only NTFS mounts) | 2022.10.3-1.2ubuntu3.2 | GPL-2.0-or-later (libfuse-lite LGPL-2.0-or-later) |
| gnome-terminal (login launcher) | 3.52.0-1ubuntu2 | GPL-3.0-or-later |

## Forensic tool roles (Milestone 4; Ubuntu 24.04 packages, decision log 2026-11-15)

Every package in the `*_packages` lists of `tools_acquire`, `tools_filesystem`, `tools_carve`,
`tools_media`, `tools_registry` and `tools_eztools`. Packages that also appear in a table above
(ewf-tools, gddrescue, sleuthkit, libvshadow-utils, testdisk, ntfs-3g, ffmpeg, exiftool,
hashdeep, ssdeep) keep their row there.

| Component | Role | Version seen (noble) | Licence |
|---|---|---|---|
| libewf2 (EWF library under ewf-tools) | `tools_acquire`, `tools_carve` | 20140814-1build3 | LGPL-3.0-or-later |
| dc3dd (imaging) | `tools_acquire` | 7.3.1-2 | GPL-3.0-or-later (parts GPL-2.0-or-later, GFDL-1.2-or-later docs, public domain) |
| afflib-tools (AFF images) | `tools_acquire` | 3.7.20-1.1ubuntu5 | Public domain (`Files: *`), with BSD-4-Clause, BSD-3-Clause, ISC, MIT, CPL-1.0 or LGPL-2.1 (bundled LZMA) and GPL-3.0-or-later with Autoconf exception parts |
| guymager (imaging GUI) | `tools_acquire` | 0.8.13-2build2 | GPL-2.0-or-later (md5 code zlib-style) |
| libfsntfs-utils, python3-libfsntfs (`fsntfsinfo`; NTFS cross-check) | `tools_filesystem` | 20200921-2.1build1 | LGPL-3.0-or-later |
| scalpel (header carving) | `tools_carve` | 1.60+git20240110.6960eb2-1build1 | GPL-2.0-or-later |
| foremost (header carving) | `tools_carve` | 1.5.7-11 | Public domain (US Government work), GPL-2.0-or-later parts |
| build-essential, flex, pkg-config, libewf-dev, libexpat1-dev, libssl-dev, zlib1g-dev, libncurses-dev, libsqlite3-dev (bulk_extractor build; left installed) | `tools_carve` | noble | GPL-2.0-or-later (build-essential metapackage; GCC GPL-3.0-or-later), Flex licence (BSD-style; flex), ISC (pkg-config/pkgconf), LGPL-3.0-or-later (libewf-dev), MIT (expat), Apache-2.0 (OpenSSL), Zlib, MIT/X11 (ncurses), public domain (SQLite) |
| libexpat1, zlib1g, libtinfo6, libssl3t64 (bulk_extractor run time) | `tools_carve` | noble | MIT, Zlib, MIT/X11, Apache-2.0 |
| mediainfo | `tools_media` | 24.01.1-1build2 | BSD-2-Clause (parts CC-BY-3.0) |
| exiv2 | `tools_media` | 0.27.6-1ubuntu0.3 | GPL-2.0-or-later (parts BSD-3-Clause, MIT) |
| vinetto (thumbs.db) | `tools_media` | 1:0.8.0-3 | GPL-3.0 (parts GPL-2.0-or-later) |
| regripper (`rip.pl`) | `tools_registry` | 3.0~git20221205.d588019+dfsg-1.1 | MIT |
| libregf-utils (`regfexport`, `regfinfo`) | `tools_registry` | 20201007-2.1build2 | LGPL-3.0-or-later |
| libhivex-bin (`hivexsh`, `hivexregedit`) | `tools_registry` | 1.3.23-1build7 | GPL-2.0-or-later (the tools); LGPL-2.1 (libhivex) |
| unzip (unpacks the EZ Tools and Autopsy zips) | `tools_eztools`, `tools_autopsy` | 6.0-28ubuntu4.1 | Info-ZIP licence (BSD-style) |
| python3-venv (the Dissect, Plaso, usncarve, classifier and speech venvs) | `tools_dissect`, `tools_timeline`, `tools_carve`, `tools_ai` | 3.12.3-0ubuntu2.1 | PSF-2.0 (Python) |

## Autopsy prerequisites (role `base` in every image; checked by `tools_autopsy`, task 4.9)

`base_autopsy_prerequisites` and `tools_autopsy_packages` (the same list). Autopsy itself and
the Sleuth Kit Java .deb are in the pins table below.

| Component | Version seen (noble) | Licence |
|---|---|---|
| openjdk-17-jre (Java 17) | 17.0.21.0.3+1-1~24.04.1 | GPL-2.0 with the Classpath exception (parts BSD-3-Clause, MIT, LGPL-2.1 and others listed in the copyright file of openjdk-17-jre-headless) |
| testdisk (PhotoRec; Autopsy's unix_setup.sh checks for it) | 7.1-5+nmu1build2 | GPL-2.0-or-later |
| libafflib-dev | 3.7.20-1.1ubuntu5 | as afflib-tools above |
| libewf-dev | 20140814-1build3 | LGPL-3.0-or-later |
| libvhdi-dev | 20210425-1build5 | LGPL-3.0-or-later |
| libvmdk-dev | 20200926-2build5 | LGPL-3.0-or-later |
| libsqlite3-dev | 3.45.1-1ubuntu2.9 | Public domain (parts GPL-2.0-or-later) |
| libc3p0-java | 0.9.1.2-10ubuntu2 | LGPL-2.1 |
| libde265-0 | 1.0.15-1ubuntu0.2 | LGPL-3.0-or-later (parts GPL-3.0-or-later, BSD-4-Clause, public domain) |
| libheif1 | 1.17.6-1ubuntu4.9 | LGPL-3.0-or-later (parts GPL-3.0-or-later, BSD-3-Clause, BSD-4-Clause, MIT, BSL-1.0) |
| libpq5 | 16.15-0ubuntu0.24.04.1 | PostgreSQL licence (parts BSD-2-Clause, BSD-3-Clause, Tcl) |
| libgstreamer1.0-0, gstreamer1.0-plugins-base, gstreamer1.0-plugins-good, gstreamer1.0-libav, gstreamer1.0-gtk3 | 1.24.x | LGPL-2.0-or-later / LGPL-2.1-or-later (parts GPL-2.0-or-later, BSD, MIT); gstreamer1.0-libav links ffmpeg (above) |

## Plaso and Dissect venvs (baked into the image; decision log 2026-11-15)

Every package of each pinned closure (`tools_timeline/files/requirements.txt`,
`tools_dissect/files/requirements.txt`), with the licence its PyPI metadata (licence
expression, licence field or classifier) gives for the pinned version, read 2026-11-15. Task 6.6
checks each wheel's own licence file before a prebuilt image is published.

| Venv | Licence | Packages |
|---|---|---|
| `/opt/plaso` | Apache-2.0 | plaso, acstore, artifacts, dfdatetime, dfvfs, dfwinreg, dtfabric, grpcio, opensearch-py, opensearch-protobufs, pytsk3, requests, tzdata, yara-python |
| `/opt/plaso` | LGPL-3.0-or-later | the 35 libyal bindings: libbde-python, libcaes-python, libcreg-python, libesedb-python, libevt-python, libevtx-python, libewf-python, libfcrypto-python, libfsapfs-python, libfsext-python, libfsfat-python, libfshfs-python, libfsntfs-python, libfsxfs-python, libfvde-python, libfwnt-python, libfwsi-python, liblnk-python, libluksde-python, libmodi-python, libmsiecf-python, libolecf-python, libphdi-python, libqcow-python, libregf-python, libscca-python, libsigscan-python, libsmdev-python, libsmraw-python, libvhdi-python, libvmdk-python, libvsapm-python, libvsgpt-python, libvshadow-python, libvslvm-python |
| `/opt/plaso` | BSD (2- or 3-Clause) | events, flor, idna, lz4, protobuf, psutil, pycparser, python-dateutil, pyzmq, xlsxwriter (BSD-2-Clause), zstd |
| `/opt/plaso` | MIT | charset-normalizer, pefile, pyparsing, pytz, pyyaml, redis, urllib3, xattr |
| `/opt/plaso` | MIT-0 | cffi |
| `/opt/plaso` | MPL-2.0 | certifi |
| `/opt/plaso` | PSF-2.0 | defusedxml, typing-extensions |
| `/opt/plaso` | BitTorrent Open Source Licence 1.1 (PyPI classifier "Other/Proprietary License"; verify in 6.6) | bencode-py |
| `/opt/dissect` | AGPL-3.0-or-later | dissect, dissect-apfs, dissect-archive, dissect-btrfs, dissect-cim, dissect-clfs, dissect-cramfs, dissect-etl, dissect-eventlog, dissect-evidence, dissect-executable, dissect-extfs, dissect-fat, dissect-ffs, dissect-fve, dissect-hypervisor, dissect-jffs, dissect-ntfs, dissect-ole, dissect-qnxfs, dissect-regf, dissect-shellitem, dissect-squashfs, dissect-target, dissect-thumbcache, dissect-vmfs, dissect-volume, dissect-xfs, flow-record |
| `/opt/dissect` | Apache-2.0 | dissect-cstruct, dissect-database, dissect-util, asttokens, msgpack |
| `/opt/dissect` | Apache-2.0 OR MIT | structlog |
| `/opt/dissect` | BSD (2- or 3-Clause) | ipython, ipython-pygments-lexers, matplotlib-inline, prompt-toolkit, psutil, pygments (BSD-2-Clause), traitlets |
| `/opt/dissect` | BSD-2-Clause AND Unlicense AND MIT | pycryptodome |
| `/opt/dissect` | ISC | fusepy, pexpect, ptyprocess |
| `/opt/dissect` | MIT | asn1crypto, executing, jedi, parso, pure-eval, ruamel-yaml, stack-data, wcwidth |
| `/opt/dissect` | PSF-2.0 | backports-zstd, defusedxml |
| `/opt/usncarve` | Apache-2.0 | usncarve (pin `usncarve_pypi`) |
| all three (build backend, `files/build-requirements.txt`) | MIT; MIT; Apache-2.0 OR BSD-2-Clause | setuptools 84.2.1, wheel 0.48.0, packaging 26.3 |

## Hash sets and signatures (role `tools_hashsets`, Milestone 4A; decision log 2026-11-15)

Licences read from each package's `/usr/share/doc/<package>/copyright` on noble, 2026-11-15.
The data these tools read (ClamAV databases, MalwareBazaar, NSRL, YARA packs) is in the pins
table below and stays user-fetched.

| Component | Version seen (noble) | Licence |
|---|---|---|
| clamav, clamav-freshclam (masked), libclamav12 (`clamscan`, `sigtool`) | 1.5.4+dfsg-0ubuntu0.24.04.1 | GPL-2.0-only (parts GPL-2.0 with OpenSSL exception, Apache-2.0/MIT, BSD-3-Clause, Zlib, ISC) |
| yara, libyara10 (`yara`, `yarac`) | 4.5.0-1build2 | BSD-3-Clause (packaging parts Apache-2.0) |
| ssdeep | 2.14.1+git20180629.57fcfff-3 | GPL-2.0-or-later (parts public domain, BSL-1.0) |
| python3-tlsh | 3.4.4+20151206-1.4build5 | Apache-2.0 (TLSH; packaging permissive) |
| hashdeep | 4.4-7.1 | Public domain (US Government work) with GPL-2.0-or-later, GPL-3.0-or-later, LGPL-2.1-or-later and BSL-1.0 parts |

## Build host only (never in the image)

| Component | Version | Licence |
|---|---|---|
| Packer | 1.11.2 | BUSL-1.1 |
| packer-plugin-qemu | 1.1.8 | MPL-2.0 |
| exfat-fuse (`make-usb.sh` staging mount when the kernel has no exFAT driver; installed by `scripts/prereqs.sh`) | 1.4.0 (noble) | GPL-2.0-or-later |
| faketime / libfaketime (`validation/synthetic/build.sh`: synthetic images at planned times; validation host only) | 0.9.10 (noble) | GPL-2.0-only |
| ntfs-3g, exfatprogs, exfat-fuse, sleuthkit, testdisk (`validation/`: building and checking synthetic images; validation host only) | noble | GPL-2.0-or-later (ntfs-3g, exfatprogs, exfat-fuse, testdisk); CPL-1.0, IBM-PL-1.0, GPL-2.0-or-later parts (sleuthkit) |
| qemu-system-x86, qemu-utils, ovmf, zstd, curl, openssl, python3-yaml, gdisk, e2fsprogs, util-linux, exfatprogs (`scripts/prereqs.sh` installs them when missing) | noble | GPL-2.0 (QEMU), BSD-2-Clause-Patent (OVMF), BSD-3-Clause or GPL-2.0 (zstd), curl, Apache-2.0 (OpenSSL), MIT (PyYAML), GPL-2.0-or-later (gdisk, e2fsprogs, util-linux, exfatprogs) |
| cosign (release workflow: keyless signature of `SHA256SUMS`; pin `cosign_linux_amd64`) | 2.6.5 | Apache-2.0 |
| syft (release workflow: SPDX SBOM of the image; pin `syft_linux_amd64`) | 1.57.1 | Apache-2.0 |
| actionlint (lint workflow: checks the workflow files; pin `actionlint_linux_amd64`) | 1.7.7 | MIT |
| GitHub Actions `actions/checkout`, `actions/setup-python`, `actions/upload-artifact`, `actions/download-artifact` (CI runners only, pinned to commit SHAs) | 7.0.1, 7.1.0, 7.0.2, 8.0.2 | MIT |
| PSScriptAnalyzer (Windows CI runner only, PowerShell Gallery) | 1.25.0 (newest GitHub tag; verify on the Gallery) | MIT |
| live-build (`live/build.sh`, the live ISO variant; build host only) | 3.0~a57-1ubuntu49.1 (noble) | GPL-3.0-or-later |

## Local AI (role `tools_ai`, Milestone 4B; decision log 2026-11-15)

Exact versions and hashes are in `ansible/group_vars/all/pins.yml`.

| Component | Version | Licence | Where |
|---|---|---|---|
| llama.cpp (`llama-server`, `llama-mtmd-cli`) | b12030 | MIT | built into the image, `/opt/llama` |
| Qwen3-VL 2B, 4B, 8B, 32B Instruct (GGUF) | Q4_K_M, Q8_0, F16 projectors | Apache-2.0 | ASSETS, by tier |
| SigLIP base patch16-224 (ONNX export) | base-patch16-224 | Apache-2.0 | ASSETS |
| Whisper small (faster-whisper CTranslate2 conversion) | small | MIT | ASSETS |
| NudeNet (wheel, carries the 320n detector) | 3.4.2 | AGPL-3.0 (LICENSE file in the wheel; PyPI metadata says MIT) | `/opt/triage` |
| onnxruntime | 1.32.0 | MIT | `/opt/triage`, `/opt/whisper` |
| numpy | 2.5.4 | BSD-3-Clause AND 0BSD AND MIT AND Zlib AND CC0-1.0 | `/opt/triage`, `/opt/whisper` |
| Pillow | 13.0.0 | MIT-CMU | `/opt/triage` |
| opencv-python-headless | 5.0.0.93 | Apache-2.0 | `/opt/triage` |
| tokenizers | 0.23.3 | Apache-2.0 | `/opt/triage`, `/opt/whisper` |
| flatbuffers, packaging, protobuf | 25.12.19, 26.3, 7.36.2 | Apache-2.0; Apache-2.0 OR BSD-2-Clause; BSD-3-Clause | `/opt/triage`, `/opt/whisper` |
| faster-whisper, ctranslate2 | 1.2.1, 4.9.0 | MIT | `/opt/whisper` |
| av (PyAV) | 19.0.2 | BSD-3-Clause | `/opt/whisper` |
| huggingface-hub, hf-xet | 2.4.0, 1.8.0 | Apache-2.0 | `/opt/whisper` (imported by faster-whisper; offline) |
| httpx2, httpcore2, anyio, h11, idna, truststore | 2.16.0, 2.16.0, 4.16.0, 0.16.0, 3.20, 0.10.5 | BSD-3-Clause, BSD-3-Clause, MIT, MIT, BSD-3-Clause, MIT | `/opt/whisper` |
| click, filelock, fsspec, pyyaml, tqdm, typing-extensions | 8.5.1, 4.2.10, 2026.9.0, 6.0.3, 4.70.1, 4.16.0 | BSD-3-Clause, MIT, BSD-3-Clause, MIT, MPL-2.0 AND MIT, PSF-2.0 | `/opt/whisper` |
| mesa-vulkan-drivers, libvulkan1, vulkan-tools, ffmpeg, poppler-utils, python3-venv | noble | MIT (Mesa), Apache-2.0 (Vulkan loader, vulkan-tools; parts MIT), LGPL-2.1-or-later/GPL-2.0-or-later (ffmpeg), GPL-2.0 or GPL-3.0 (poppler-utils, as its copyright file states; parts Apache-2.0), PSF-2.0 (python3-venv) | image |
| LibreOffice without a GUI: libreoffice-writer-nogui, libreoffice-calc-nogui, libreoffice-impress-nogui (pull in libreoffice-core-nogui, libreoffice-draw-nogui, libreoffice-common, which provides `/usr/bin/soffice`); `soffice --headless --convert-to` for Office documents (4B.9) | 4:24.2.7-0ubuntu0.24.04.7 | MPL-2.0 (parts Apache-2.0, MIT, BSD-2-Clause, BSD-3-Clause, LGPL-3.0-or-later, GPL-2.0-or-later, CC0-1.0, CC-BY-SA-3.0) | image |
| build-essential, cmake, glslc, libvulkan-dev, spirv-headers, pkg-config (llama.cpp build; left installed) | noble | GPL-2.0-or-later (build-essential metapackage), BSD-3-Clause (CMake; parts Apache-2.0, BSD-2-Clause, ISC), Apache-2.0 (glslc/shaderc; parts BSD-3-Clause, GPL-2.0-or-later), Apache-2.0 (libvulkan-dev; parts MIT), MIT (spirv-headers), ISC (pkg-config/pkgconf) | image |
| linux-modules-nvidia (optional, off by default, 4B.15) | per kernel | NVIDIA proprietary (Ubuntu-signed, redistributable by Canonical) | ASSETS, installed offline only when turned on |

## Every pinned download and where it may live (task 2B.18; licence review 6.6)

Generated from `ansible/group_vars/all/pins.yml` by `python3 scripts/check-pins.py
--licences-table`; regenerate it whenever a pin is added (`tests/unit/test_manifest.py` fails
while a pin is missing here). Rule (plan 2B.18): what the build bakes in must be
redistributable; model weights, ClamAV signatures, MalwareBazaar, NSRL, and YARA packs stay
user-fetched onto ASSETS by `scripts/fetch-assets.*`, so the published base image does not
redistribute them. EZ Tools and NudeNet (AGPL-3.0) are staged onto ASSETS until 6.6 confirms
their terms. Build-host downloads tagged `image` (goss) are copied into the image by the build.

**Dissect is baked into the image today.** The plan allows it (2B.18: AGPL tools may be baked
with their licence and a source offer), and `tools_dissect` installs Dissect and its 55 pinned
dependencies (pin `dissect_pypi`, stage `image`; `tools_dissect/files/requirements.txt`) into
`/opt/dissect` during the image build, so every image built from this repository carries
AGPL-3.0-or-later code. The wheels' own licence files are inside the venv; no written source
offer and no copy of the corresponding source is shipped yet. Before any prebuilt image is
published, task 6.6 must decide one of: (a) keep Dissect in the image and publish, with each
release, the AGPL-3.0 text and the corresponding source of the exact pinned versions (the
sdists for the hashes in `requirements.txt`) or a written offer for it; or (b) move
`dissect_pypi` to stage `assets` so it is user-fetched and installed at first boot like NudeNet.
Until 6.6 decides, only self-built images (each user builds their own) are covered.

<!-- pins-table:start -->
| Pin | Version | Licence | Stage | May be baked into the published image |
|---|---|---|---|---|
| `actionlint_linux_amd64` | 1.7.7 | MIT (workflow linter, CI only; never in the image) | build | n/a: build host only |
| `autopsy_zip` | 4.23.1 | Apache-2.0 (bundled third-party parts carry their own licences) | assets | no: user-fetched onto ASSETS (2B.18) |
| `bulk_extractor_source` | 2.1.1 | MIT and US-Government public domain (bundled parts: licenses/ in the tarball) | image | yes: baked by the build |
| `cast_deb` | 1.0.13 | MIT (verify in task 6.6) | image | yes: baked by the build |
| `clamav_daily_cvd` | rolling | Cisco-Talos ClamAV signature terms (unconfirmed, plan 6.6); user-fetched, never baked | assets | no: user-fetched onto ASSETS (2B.18) |
| `clamav_main_cvd` | rolling | Cisco-Talos ClamAV signature terms (unconfirmed, plan 6.6); user-fetched, never baked | assets | no: user-fetched onto ASSETS (2B.18) |
| `cosign_linux_amd64` | 2.6.5 | Apache-2.0 (release signing tool, CI only; never in the image) | build | n/a: build host only |
| `dissect_pypi` | 3.22 | AGPL-3.0-or-later (dependencies: tools_dissect/files/requirements.txt) | image | yes: baked by the build |
| `dotnet_host_9_deb` | 9.0.4-1 | MIT (.NET runtime, Microsoft) | image | yes: baked by the build |
| `dotnet_hostfxr_9_deb` | 9.0.4-1 | MIT (.NET runtime, Microsoft) | image | yes: baked by the build |
| `dotnet_runtime_9_deb` | 9.0.4-1 | MIT (.NET runtime, Microsoft) | image | yes: baked by the build |
| `dotnet_runtime_deps_9_deb` | 9.0.4-1 | MIT (.NET runtime, Microsoft) | image | yes: baked by the build |
| `eztools_amcacheparser` | 1.5.2.0 | MIT (Eric Zimmerman; confirm per tool in task 6.6) | assets | allowed once each repo's MIT licence is confirmed (6.6, unconfirmed) |
| `eztools_appcompatcacheparser` | 1.5.1.0 | MIT (Eric Zimmerman; confirm per tool in task 6.6) | assets | allowed once each repo's MIT licence is confirmed (6.6, unconfirmed) |
| `eztools_bstrings` | 1.5.2.0 | MIT (Eric Zimmerman; confirm per tool in task 6.6) | assets | allowed once each repo's MIT licence is confirmed (6.6, unconfirmed) |
| `eztools_evtxecmd` | 1.5.2.0 | MIT (Eric Zimmerman; confirm per tool in task 6.6) | assets | allowed once each repo's MIT licence is confirmed (6.6, unconfirmed) |
| `eztools_jlecmd` | 1.5.1.0 | MIT (Eric Zimmerman; confirm per tool in task 6.6) | assets | allowed once each repo's MIT licence is confirmed (6.6, unconfirmed) |
| `eztools_lecmd` | 1.5.1.0 | MIT (Eric Zimmerman; confirm per tool in task 6.6) | assets | allowed once each repo's MIT licence is confirmed (6.6, unconfirmed) |
| `eztools_mftecmd` | 1.3.0.0 | MIT (Eric Zimmerman; confirm per tool in task 6.6) | assets | allowed once each repo's MIT licence is confirmed (6.6, unconfirmed) |
| `eztools_pecmd` | 1.5.1.0 | MIT (Eric Zimmerman; confirm per tool in task 6.6) | assets | allowed once each repo's MIT licence is confirmed (6.6, unconfirmed) |
| `eztools_rbcmd` | 1.6.0.0 | MIT (Eric Zimmerman; confirm per tool in task 6.6) | assets | allowed once each repo's MIT licence is confirmed (6.6, unconfirmed) |
| `eztools_recmd` | 2.1.0.0 | MIT (Eric Zimmerman; confirm per tool in task 6.6) | assets | allowed once each repo's MIT licence is confirmed (6.6, unconfirmed) |
| `eztools_sbecmd` | 2.1.0.0 | MIT (Eric Zimmerman; confirm per tool in task 6.6) | assets | allowed once each repo's MIT licence is confirmed (6.6, unconfirmed) |
| `faster_whisper_small_config` | small | MIT (OpenAI Whisper weights; CTranslate2 conversion by Systran) | assets | no: user-fetched onto ASSETS (2B.18) |
| `faster_whisper_small_model` | small | MIT (OpenAI Whisper weights; CTranslate2 conversion by Systran) | assets | no: user-fetched onto ASSETS (2B.18) |
| `faster_whisper_small_tokenizer` | small | MIT (OpenAI Whisper weights; CTranslate2 conversion by Systran) | assets | no: user-fetched onto ASSETS (2B.18) |
| `faster_whisper_small_vocabulary` | small | MIT (OpenAI Whisper weights; CTranslate2 conversion by Systran) | assets | no: user-fetched onto ASSETS (2B.18) |
| `goss_linux_amd64` | 0.4.9 | Apache-2.0 (fetched on the build host; baked into the image at /opt/airlock/bin/goss, the provisioning self-test) | build | yes: fetched on the build host, baked by the build |
| `llama_cpp_source` | b12030 | MIT | image | yes: baked by the build |
| `malwarebazaar_sha256_full` | daily | CC0-1.0 per abuse.ch terms (unconfirmed, plan 6.6); user-fetched, never baked | assets | no: user-fetched onto ASSETS (2B.18) |
| `nsrl_rds_modern_minimal` | 2026.06.1 | NIST NSRL data, US Government work (redistribution unconfirmed, plan 6.6); user-fetched | assets | no: user-fetched onto ASSETS (2B.18) |
| `nvidia_deb_binutils` | 2.42-4ubuntu2.10 | GPL-3.0-or-later (Ubuntu main) | assets | no: opt-in NVIDIA driver set (4B.15); staged only when turned on |
| `nvidia_deb_binutils_common` | 2.42-4ubuntu2.10 | GPL-3.0-or-later (Ubuntu main) | assets | no: opt-in NVIDIA driver set (4B.15); staged only when turned on |
| `nvidia_deb_binutils_x86_64_linux_gnu` | 2.42-4ubuntu2.10 | GPL-3.0-or-later (Ubuntu main) | assets | no: opt-in NVIDIA driver set (4B.15); staged only when turned on |
| `nvidia_deb_libbinutils` | 2.42-4ubuntu2.10 | GPL-3.0-or-later (Ubuntu main) | assets | no: opt-in NVIDIA driver set (4B.15); staged only when turned on |
| `nvidia_deb_libctf0` | 2.42-4ubuntu2.10 | GPL-3.0-or-later (Ubuntu main) | assets | no: opt-in NVIDIA driver set (4B.15); staged only when turned on |
| `nvidia_deb_libctf_nobfd0` | 2.42-4ubuntu2.10 | GPL-3.0-or-later (Ubuntu main) | assets | no: opt-in NVIDIA driver set (4B.15); staged only when turned on |
| `nvidia_deb_libgprofng0` | 2.42-4ubuntu2.10 | GPL-3.0-or-later (Ubuntu main) | assets | no: opt-in NVIDIA driver set (4B.15); staged only when turned on |
| `nvidia_deb_libnvidia_common_580` | 580.178.04-0ubuntu0.24.04.1 | NVIDIA proprietary driver licence (Ubuntu restricted, redistributed by Canonical) | assets | no: opt-in NVIDIA driver set (4B.15); staged only when turned on |
| `nvidia_deb_libnvidia_compute_580` | 580.178.04-0ubuntu0.24.04.1 | NVIDIA proprietary driver licence (Ubuntu restricted, redistributed by Canonical) | assets | no: opt-in NVIDIA driver set (4B.15); staged only when turned on |
| `nvidia_deb_libnvidia_egl_wayland1` | 1:1.1.13-1ubuntu0.1 | MIT (Ubuntu main) | assets | no: opt-in NVIDIA driver set (4B.15); staged only when turned on |
| `nvidia_deb_libnvidia_gl_580` | 580.178.04-0ubuntu0.24.04.1 | NVIDIA proprietary driver licence (Ubuntu restricted, redistributed by Canonical) | assets | no: opt-in NVIDIA driver set (4B.15); staged only when turned on |
| `nvidia_deb_libsframe1` | 2.42-4ubuntu2.10 | GPL-3.0-or-later (Ubuntu main) | assets | no: opt-in NVIDIA driver set (4B.15); staged only when turned on |
| `nvidia_deb_linux_modules_nvidia_580_7_0_0_42_generic` | 7.0.0-42.42~24.04.1 | NVIDIA proprietary objects with GPL-2.0 kernel glue (Ubuntu restricted, Canonical-signed) | assets | no: opt-in NVIDIA driver set (4B.15); staged only when turned on |
| `nvidia_deb_linux_objects_nvidia_580_7_0_0_42_generic` | 7.0.0-42.42~24.04.1 | NVIDIA proprietary objects with GPL-2.0 kernel glue (Ubuntu restricted, Canonical-signed) | assets | no: opt-in NVIDIA driver set (4B.15); staged only when turned on |
| `nvidia_deb_linux_signatures_nvidia_7_0_0_42_generic` | 7.0.0-42.42~24.04.1 | NVIDIA proprietary objects with GPL-2.0 kernel glue (Ubuntu restricted, Canonical-signed) | assets | no: opt-in NVIDIA driver set (4B.15); staged only when turned on |
| `nvidia_deb_nvidia_firmware_580_580_178_04` | 580.178.04-0ubuntu0.24.04.1 | NVIDIA proprietary driver licence (Ubuntu restricted, redistributed by Canonical) | assets | no: opt-in NVIDIA driver set (4B.15); staged only when turned on |
| `nvidia_deb_nvidia_kernel_common_580` | 580.178.04-0ubuntu0.24.04.1 | NVIDIA proprietary driver licence (Ubuntu restricted, redistributed by Canonical) | assets | no: opt-in NVIDIA driver set (4B.15); staged only when turned on |
| `nvidia_deb_ocl_icd_libopencl1` | 2.3.2-1build1 | BSD-2-Clause (Ubuntu main) | assets | no: opt-in NVIDIA driver set (4B.15); staged only when turned on |
| `packer_linux_amd64` | 1.11.2 | BUSL-1.1 (build tool only, never shipped in the image) | build | n/a: build host only |
| `packer_plugin_qemu_linux_amd64` | 1.1.8 | MPL-2.0 (build tool only, never shipped in the image) | build | n/a: build host only |
| `plaso_pypi` | 20261027 | Apache-2.0 (dependencies: tools_timeline/files/requirements.txt) | image | yes: baked by the build |
| `qwen3_vl_2b_instruct_mmproj_gguf` | F16 | Apache-2.0 | assets | no: user-fetched onto ASSETS (2B.18) |
| `qwen3_vl_2b_instruct_q4_k_m_gguf` | Q4_K_M | Apache-2.0 | assets | no: user-fetched onto ASSETS (2B.18) |
| `qwen3_vl_32b_instruct_mmproj_gguf` | F16 | Apache-2.0 | assets | no: user-fetched onto ASSETS (2B.18) |
| `qwen3_vl_32b_instruct_q4_k_m_gguf` | Q4_K_M | Apache-2.0 | assets | no: user-fetched onto ASSETS (2B.18) |
| `qwen3_vl_4b_instruct_mmproj_gguf` | F16 | Apache-2.0 | assets | no: user-fetched onto ASSETS (2B.18) |
| `qwen3_vl_4b_instruct_q4_k_m_gguf` | Q4_K_M | Apache-2.0 | assets | no: user-fetched onto ASSETS (2B.18) |
| `qwen3_vl_8b_instruct_mmproj_gguf` | F16 | Apache-2.0 | assets | no: user-fetched onto ASSETS (2B.18) |
| `qwen3_vl_8b_instruct_q4_k_m_gguf` | Q4_K_M | Apache-2.0 | assets | no: user-fetched onto ASSETS (2B.18) |
| `qwen3_vl_8b_instruct_q8_0_gguf` | Q8_0 | Apache-2.0 | assets | no: user-fetched onto ASSETS (2B.18) |
| `siglip_base_patch16_224_onnx` | base-patch16-224 | Apache-2.0 (google/siglip-base-patch16-224; ONNX export by Xenova) | assets | no: user-fetched onto ASSETS (2B.18) |
| `siglip_base_patch16_224_preprocessor` | base-patch16-224 | Apache-2.0 (google/siglip-base-patch16-224; ONNX export by Xenova) | assets | no: user-fetched onto ASSETS (2B.18) |
| `siglip_base_patch16_224_tokenizer` | base-patch16-224 | Apache-2.0 (google/siglip-base-patch16-224; ONNX export by Xenova) | assets | no: user-fetched onto ASSETS (2B.18) |
| `sleuthkit_java_deb` | 4.15.0-1 | CPL-1.0 and IPL-1.0 and GPL-2.0-or-later (The Sleuth Kit; verify in task 6.6) | assets | no: user-fetched onto ASSETS (2B.18) |
| `syft_linux_amd64` | 1.57.1 | Apache-2.0 (SBOM tool, CI only; never in the image) | build | n/a: build host only |
| `ubuntu_server_iso` | 24.04.5 | Ubuntu archive (mixed free licences, redistributable) | build | n/a: build host only |
| `usncarve_pypi` | 1.2.2 | Apache-2.0 | image | yes: baked by the build |
| `wheel_anyio` | 4.16.0 | MIT | assets | no: user-fetched onto ASSETS (2B.18) |
| `wheel_av` | 19.0.2 | BSD-3-Clause | assets | no: user-fetched onto ASSETS (2B.18) |
| `wheel_click` | 8.5.1 | BSD-3-Clause | assets | no: user-fetched onto ASSETS (2B.18) |
| `wheel_ctranslate2` | 4.9.0 | MIT | assets | no: user-fetched onto ASSETS (2B.18) |
| `wheel_faster_whisper` | 1.2.1 | MIT | assets | no: user-fetched onto ASSETS (2B.18) |
| `wheel_filelock` | 4.2.10 | MIT | assets | no: user-fetched onto ASSETS (2B.18) |
| `wheel_flatbuffers` | 25.12.19 | Apache-2.0 | assets | no: user-fetched onto ASSETS (2B.18) |
| `wheel_fsspec` | 2026.9.0 | BSD-3-Clause | assets | no: user-fetched onto ASSETS (2B.18) |
| `wheel_h11` | 0.16.0 | MIT | assets | no: user-fetched onto ASSETS (2B.18) |
| `wheel_hf_xet` | 1.8.0 | Apache-2.0 | assets | no: user-fetched onto ASSETS (2B.18) |
| `wheel_httpcore2` | 2.16.0 | BSD-3-Clause | assets | no: user-fetched onto ASSETS (2B.18) |
| `wheel_httpx2` | 2.16.0 | BSD-3-Clause | assets | no: user-fetched onto ASSETS (2B.18) |
| `wheel_huggingface_hub` | 2.4.0 | Apache-2.0 | assets | no: user-fetched onto ASSETS (2B.18) |
| `wheel_idna` | 3.20 | BSD-3-Clause | assets | no: user-fetched onto ASSETS (2B.18) |
| `wheel_nudenet` | 3.4.2 | AGPL-3.0 (LICENSE file in the wheel; PyPI metadata says MIT) | assets | no: user-fetched onto ASSETS (2B.18) |
| `wheel_numpy` | 2.5.4 | BSD-3-Clause AND 0BSD AND MIT AND Zlib AND CC0-1.0 | assets | no: user-fetched onto ASSETS (2B.18) |
| `wheel_onnxruntime` | 1.32.0 | MIT | assets | no: user-fetched onto ASSETS (2B.18) |
| `wheel_opencv_python_headless` | 5.0.0.93 | Apache-2.0 | assets | no: user-fetched onto ASSETS (2B.18) |
| `wheel_packaging` | 26.3 | Apache-2.0 OR BSD-2-Clause | assets | no: user-fetched onto ASSETS (2B.18) |
| `wheel_pillow` | 13.0.0 | MIT-CMU | assets | no: user-fetched onto ASSETS (2B.18) |
| `wheel_protobuf` | 7.36.2 | BSD-3-Clause | assets | no: user-fetched onto ASSETS (2B.18) |
| `wheel_pyyaml` | 6.0.3 | MIT | assets | no: user-fetched onto ASSETS (2B.18) |
| `wheel_tokenizers` | 0.23.3 | Apache-2.0 | assets | no: user-fetched onto ASSETS (2B.18) |
| `wheel_tqdm` | 4.70.1 | MPL-2.0 AND MIT | assets | no: user-fetched onto ASSETS (2B.18) |
| `wheel_truststore` | 0.10.5 | MIT | assets | no: user-fetched onto ASSETS (2B.18) |
| `wheel_typing_extensions` | 4.16.0 | PSF-2.0 | assets | no: user-fetched onto ASSETS (2B.18) |
| `yara_forge_core` | 20261101 | Mixed, per source rule set, stated in each set's header in the .yar (20261101: 34 sets; DRL 1.1, MIT, BSD-2-Clause, Apache-2.0, GPL and vendor notices; 18 sets state no licence); user-fetched, never baked (plan 6.6) | assets | no: user-fetched onto ASSETS (2B.18) |
| `yara_signature_base` | 36ab70428fc5b52701b7ee6107c853ff019ed759 | Detection Rule License (DRL) 1.1 (LICENSE file at the pinned commit, read 2026-11-15; attribution terms, plan 6.6); user-fetched | assets | no: user-fetched onto ASSETS (2B.18) |
<!-- pins-table:end -->

Open licence questions (plan 2.6.5 and 6.6), all **unconfirmed** until a person reviews them:

| Item | What the research or the vendor page says | Status |
|---|---|---|
| ClamAV signature databases (`main.cvd`, `daily.cvd`) | Cisco-Talos terms; free to download, redistribution terms not checked | unconfirmed; user-fetched |
| MalwareBazaar export | abuse.ch states its data is CC0; the Auth-Key terms apply to the download | unconfirmed; user-fetched, key never stored |
| NSRL RDSv3 | NIST public data; redistribution of the SQLite build not checked | unconfirmed; user-fetched, off-drive by default |
| EZ Tools | MIT on Eric Zimmerman's repositories (research); each repo's LICENSE to be checked | unconfirmed; staged until checked |
| Dissect | AGPL-3.0; ship the licence and a source offer if baked | baked today by `tools_dissect`; 6.6 decides (a) source with each release or (b) stage it, before any prebuilt image is published (see above) |
| NudeNet | AGPL-3.0 code (see `wheel_nudenet`); model weights' terms to be checked | unconfirmed |
| Qwen3-VL, SigLIP, faster-whisper models | Apache-2.0, Apache-2.0, MIT per their model cards | unconfirmed; user-fetched |
| YARA rule packs (signature-base, YARA Forge) | signature-base: DRL 1.1 (LICENSE file at the pinned commit; attribution kept when shared or when matches are reported). YARA Forge core 20261101: each of its 34 source sets carries its own licence in the .yar header (DRL 1.1, MIT, BSD-2-Clause, Apache-2.0, GPL, vendor notices), and 18 sets state none | read 2026-11-15; user-fetched, never baked; 6.6 confirms that reports keep rule authors and references |
| NVIDIA proprietary driver packages | NVIDIA licence; Canonical redistributes the signed modules | opt-in only (`nvidia_proprietary`) |
