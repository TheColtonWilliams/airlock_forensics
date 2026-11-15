# Licences

The licence of every third-party component AIRLOCK installs, downloads, or calls.

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
| dissect.target (`target-query`, PyPI; NTFS modules' second parser) | 3.25 | AGPL-3.0-or-later (see surviving risk 8) |
| libvshadow-utils (`vshadowinfo`; VSS check, 4C.29) | 20190323 | LGPL-3.0-or-later |
| testdisk (`photorec`; carving, 4C.15) | 7.1 | GPL-2.0-or-later |
| EZ Tools MFTECmd, RBCmd, LECmd, JLECmd (staged on ASSETS; optional second parsers) | pinned by the EZ Tools package | MIT (confirm per repository in 6.6, risk 7) |
| bulk_extractor (optional, carving) | pinned by the carving package | MIT (with public-domain parts) |
| Plaso `log2timeline`/`psort` (optional, timeline) | pinned by the timeline package | Apache-2.0 |

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
| goss (copied into test VMs) | 0.4.9 | Apache-2.0 |
| exfat-fuse (`make-usb.sh` staging mount when the kernel has no exFAT driver; installed by `scripts/prereqs.sh`) | 1.4.0 (noble) | GPL-2.0-or-later |
| faketime / libfaketime (`validation/synthetic/build.sh`: synthetic images at planned times; validation host only) | 0.9.10 (noble) | GPL-2.0-only |
| ntfs-3g, exfatprogs, exfat-fuse, sleuthkit, testdisk (`validation/`: building and checking synthetic images; validation host only) | noble | GPL-2.0-or-later (ntfs-3g, exfatprogs, exfat-fuse, testdisk); CPL-1.0, IBM-PL-1.0, GPL-2.0-or-later parts (sleuthkit) |
| qemu-system-x86, qemu-utils, ovmf, zstd, curl, openssl, python3-yaml, gdisk, e2fsprogs, util-linux, exfatprogs (`scripts/prereqs.sh` installs them when missing) | noble | GPL-2.0 (QEMU), BSD-2-Clause-Patent (OVMF), BSD-3-Clause or GPL-2.0 (zstd), curl, Apache-2.0 (OpenSSL), MIT (PyYAML), GPL-2.0-or-later (gdisk, e2fsprogs, util-linux, exfatprogs) |

## Local AI (role `tools_ai`, Milestone 4B; decision log 2026-11-15)

Exact versions and hashes are in `ansible/group_vars/all/pins.yml`.

| Component | Version | Licence | Where |
|---|---|---|---|
| llama.cpp (`llama-server`, `llama-mtmd-cli`) | b9562 | MIT | built into the image, `/opt/llama` |
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
| mesa-vulkan-drivers, vulkan-tools, ffmpeg, poppler-utils | noble | MIT (Mesa), Apache-2.0 (vulkan-tools), LGPL-2.1-or-later/GPL-2.0-or-later (ffmpeg), GPL-2.0-or-later (poppler-utils) | image |
| linux-modules-nvidia (optional, off by default, 4B.15) | per kernel | NVIDIA proprietary (Ubuntu-signed, redistributable by Canonical) | ASSETS, installed offline only when turned on |

## Every pinned download and where it may live (task 2B.18; licence review 6.6)

Generated from `ansible/group_vars/all/pins.yml` by `python3 scripts/check-pins.py
--licences-table`; regenerate it whenever a pin is added (`tests/unit/test_manifest.py` fails
while a pin is missing here). Rule (plan 2B.18): what the build bakes in must be
redistributable; model weights, ClamAV signatures, MalwareBazaar, NSRL, and YARA packs stay
user-fetched onto ASSETS by `scripts/fetch-assets.*`, so the published base image does not
redistribute them. EZ Tools and the AGPL Python tools (Dissect, NudeNet) may be baked once 6.6
confirms their terms; until then they are staged too.

<!-- pins-table:start -->
| Pin | Version | Licence | Stage | May be baked into the published image |
|---|---|---|---|---|
| `clamav_daily_cvd` | rolling | Cisco-Talos ClamAV signature terms (unconfirmed, plan 6.6); user-fetched, never baked | assets | no: user-fetched onto ASSETS (2B.18) |
| `clamav_main_cvd` | rolling | Cisco-Talos ClamAV signature terms (unconfirmed, plan 6.6); user-fetched, never baked | assets | no: user-fetched onto ASSETS (2B.18) |
| `faster_whisper_small_config` | small | MIT (OpenAI Whisper weights; CTranslate2 conversion by Systran) | assets | no: user-fetched onto ASSETS (2B.18) |
| `faster_whisper_small_model` | small | MIT (OpenAI Whisper weights; CTranslate2 conversion by Systran) | assets | no: user-fetched onto ASSETS (2B.18) |
| `faster_whisper_small_tokenizer` | small | MIT (OpenAI Whisper weights; CTranslate2 conversion by Systran) | assets | no: user-fetched onto ASSETS (2B.18) |
| `faster_whisper_small_vocabulary` | small | MIT (OpenAI Whisper weights; CTranslate2 conversion by Systran) | assets | no: user-fetched onto ASSETS (2B.18) |
| `goss_linux_amd64` | 0.4.9 | Apache-2.0 (test tool; copied into the test VM by tests/run-qemu-tests.sh, never baked into the image) | build | n/a: build host only |
| `llama_cpp_source` | b9562 | MIT | image | yes: baked by the build |
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
| `ubuntu_server_iso` | 24.04.5 | Ubuntu archive (mixed free licences, redistributable) | build | n/a: build host only |
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
| `autopsy_zip` | 4.23.1 | Apache-2.0 (bundled third-party parts carry their own licences) | assets | no: user-fetched onto ASSETS (2B.18) |
| `bulk_extractor_source` | 2.1.1 | MIT and US-Government public domain (bundled parts: licenses/ in the tarball) | image | yes: baked by the build |
| `cast_deb` | 1.0.13 | MIT (verify in task 6.6) | image | yes: baked by the build |
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
| `plaso_pypi` | 20261027 | Apache-2.0 (dependencies: tools_timeline/files/requirements.txt) | image | yes: baked by the build |
| `sleuthkit_java_deb` | 4.15.0-1 | CPL-1.0 and IPL-1.0 and GPL-2.0-or-later (The Sleuth Kit; verify in task 6.6) | assets | no: user-fetched onto ASSETS (2B.18) |
| `usncarve_pypi` | 1.2.2 | Apache-2.0 | image | yes: baked by the build |
| `yara_forge_core` | commit-to-pin | Per-rule licences of the aggregated sources, listed in the package (unconfirmed, plan 6.6) | assets | no: user-fetched onto ASSETS (2B.18) |
| `yara_signature_base` | commit-to-pin | Detection Rule License (DRL) 1.1 (unconfirmed, plan 6.6); user-fetched | assets | no: user-fetched onto ASSETS (2B.18) |
<!-- pins-table:end -->

Open licence questions (plan 2.6.5 and 6.6), all **unconfirmed** until a person reviews them:

| Item | What the research or the vendor page says | Status |
|---|---|---|
| ClamAV signature databases (`main.cvd`, `daily.cvd`) | Cisco-Talos terms; free to download, redistribution terms not checked | unconfirmed; user-fetched |
| MalwareBazaar export | abuse.ch states its data is CC0; the Auth-Key terms apply to the download | unconfirmed; user-fetched, key never stored |
| NSRL RDSv3 | NIST public data; redistribution of the SQLite build not checked | unconfirmed; user-fetched, off-drive by default |
| EZ Tools | MIT on Eric Zimmerman's repositories (research); each repo's LICENSE to be checked | unconfirmed; staged until checked |
| Dissect | AGPL-3.0; ship the licence and a source offer if baked | unconfirmed for baking |
| NudeNet | AGPL-3.0 code (see `wheel_nudenet`); model weights' terms to be checked | unconfirmed |
| Qwen3-VL, SigLIP, faster-whisper models | Apache-2.0, Apache-2.0, MIT per their model cards | unconfirmed; user-fetched |
| YARA rule packs (signature-base, YARA Forge) | DRL-1.1 and per-rule licences | unconfirmed; user-fetched |
| NVIDIA proprietary driver packages | NVIDIA licence; Canonical redistributes the signed modules | opt-in only (`nvidia_proprietary`) |
