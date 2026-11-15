# AIRLOCK base image: Ubuntu 24.04 live-server ISO -> autoinstall -> Ansible -> raw image.
# Tasks 1.1 (template, pinned ISO checksum), 1.4 (Ansible provisioner), 1.6 (post-processor),
# 2B.9 and 2B.17 (drive layout, see http/user-data), 6.1 (dated apt snapshot).
# Run it through scripts/build.sh, which reads pins.yml and main.yml and pins Packer itself.
# Tests: tests/unit/test_packer_template.py, tests/unit/test_packer_user_data.py,
# tests/functional/test_build_packer_scripts.sh.

packer {
  required_version = "= 1.11.2"
  required_plugins {
    qemu = {
      # Installed by scripts/build.sh from releases.hashicorp.com, checked against
      # pins.packer_plugin_qemu_linux_amd64.
      version = "= 1.1.8"
      source  = "github.com/hashicorp/qemu"
    }
  }
}

locals {
  # Absolute, so file paths work the same whatever directory Packer is started from.
  packer_dir = abspath(path.root)

  apt_mirror          = var.use_apt_snapshot ? "https://snapshot.ubuntu.com/ubuntu/${var.apt_snapshot}" : "http://archive.ubuntu.com/ubuntu"
  apt_security_mirror = var.use_apt_snapshot ? "https://snapshot.ubuntu.com/ubuntu/${var.apt_snapshot}" : "http://security.ubuntu.com/ubuntu"

  # GPT drive layout, docs/dev/contract.md section 3. 1 MiB lead-in, BIOSBOOT (1 MiB), EFI,
  # ASSETS, OUTPUT, AIRLOCK_ROOT (takes the rest), and 1 MiB at the end for the backup GPT.
  disk_size_mib = 1 + 1 + var.esp_size_mib + 1024 * (var.assets_partition_gib + var.output_partition_gib + var.root_image_gib) + 1

  image_name = "airlock-${var.airlock_version}.raw"

  user_data = templatefile("${local.packer_dir}/http/user-data", {
    airlock_user         = var.airlock_user
    apt_mirror           = local.apt_mirror
    apt_security_mirror  = local.apt_security_mirror
    assets_partition_gib = var.assets_partition_gib
    build_ssh_public_key = var.build_ssh_public_key
    build_user           = var.build_user
    esp_size_mib         = var.esp_size_mib
    kernel_package       = var.kernel_package
    output_partition_gib = var.output_partition_gib
  })
}

source "qemu" "airlock" {
  iso_url      = var.iso_url
  iso_checksum = "sha256:${var.iso_sha256}"

  output_directory   = var.output_dir
  vm_name            = local.image_name
  format             = "raw"
  disk_size          = "${local.disk_size_mib}M"
  disk_interface     = "virtio"
  disk_discard       = "unmap"
  disk_detect_zeroes = "unmap"
  net_device         = "virtio-net"

  accelerator  = var.accelerator
  cpu_model    = var.accelerator == "kvm" ? "host" : "max"
  cpus         = var.cpus
  memory       = var.memory_mib
  machine_type = "q35"
  headless     = true

  # Build under UEFI so the installer puts the signed shim and grub on the ESP; the base role
  # then adds the removable-path copy and the i386-pc loader (task 1.9).
  efi_boot          = true
  efi_firmware_code = var.ovmf_code
  efi_firmware_vars = var.ovmf_vars

  # Serial console log. packer/scripts/finalize.sh writes AIRLOCK-FINALIZE-OK there and the
  # post-processor refuses an image without it.
  qemuargs = [
    ["-serial", "file:${var.output_dir}/serial.log"],
  ]

  http_content = {
    "/user-data" = local.user_data
    "/meta-data" = file("${local.packer_dir}/http/meta-data")
  }

  boot_wait = var.boot_wait
  boot_command = [
    "c<wait5>",
    "linux /casper/vmlinuz autoinstall ds=\"nocloud;s=http://{{ .HTTPIP }}:{{ .HTTPPort }}/\" console=tty0 console=ttyS0,115200 ---<enter><wait5>",
    "initrd /casper/initrd<enter><wait5>",
    "boot<enter>",
  ]

  communicator         = "ssh"
  ssh_username         = var.build_user
  ssh_private_key_file = var.build_ssh_private_key_file
  ssh_timeout          = var.ssh_timeout

  # Build access is removed inside the guest by an independent systemd unit, so deleting the
  # build user cannot cut the command off half way. On failure the guest never powers off,
  # Packer hits shutdown_timeout, and the build fails.
  shutdown_command = "sudo -n systemd-run --unit=airlock-finalize --collect /bin/bash /var/tmp/airlock-finalize.sh"
  shutdown_timeout = var.shutdown_timeout
}

build {
  name    = "airlock"
  sources = ["source.qemu.airlock"]

  provisioner "shell" {
    execute_command  = "sudo -n env {{ .Vars }} /bin/bash '{{ .Path }}'"
    environment_vars = ["AIRLOCK_BUILD_USER=${var.build_user}"]
    script           = "${local.packer_dir}/scripts/bootstrap.sh"
  }

  # The repo copy that forensic-provision reuses offline (docs/dev/contract.md section 2):
  # ansible/, profiles/ and docs/ (evidence-report cites docs by path), plus tests/goss for the
  # provisioning self-test. bootstrap.sh makes /var/tmp/airlock-repo/tests first.
  provisioner "file" {
    sources = [
      "${local.packer_dir}/../ansible",
      "${local.packer_dir}/../profiles",
      "${local.packer_dir}/../docs",
    ]
    destination = "/var/tmp/airlock-repo/"
  }

  provisioner "file" {
    source      = "${local.packer_dir}/../tests/goss"
    destination = "/var/tmp/airlock-repo/tests/"
  }

  # Build inputs that scripts/build.sh staged and checked on the build host (2B.15, 2B.6):
  # the trusted manifest, its signature and public key, goss, and build-kind.json. The base
  # role (image_inputs.yml) installs them; finalize.sh deletes this folder.
  provisioner "file" {
    source      = "${var.image_inputs_dir}/"
    destination = "/var/tmp/airlock-inputs"
  }

  # Task 1.4: ansible-playbook -c local site.yml inside the guest.
  provisioner "shell" {
    execute_command = "sudo -n env {{ .Vars }} /bin/bash '{{ .Path }}'"
    environment_vars = [
      "AIRLOCK_BUILD_COMMIT=${var.git_commit}",
      "AIRLOCK_BUILD_DATE=${var.build_date}",
      "AIRLOCK_VERSION=${var.airlock_version}",
      "AIRLOCK_IDEMPOTENCE_CHECK=${var.idempotence_check ? "1" : "0"}",
    ]
    script = "${local.packer_dir}/scripts/run-ansible.sh"
  }

  provisioner "file" {
    source      = "${local.packer_dir}/scripts/finalize.sh"
    destination = "/var/tmp/airlock-finalize.sh"
  }

  # Task 1.6: raw image -> zstd, SHA256SUMS.
  post-processor "shell-local" {
    execute_command = ["/bin/bash", "-c", "{{ .Vars }} /bin/bash '{{ .Script }}'"]
    environment_vars = [
      "AIRLOCK_PP_OUTPUT_DIR=${var.output_dir}",
      "AIRLOCK_PP_IMAGE=${local.image_name}",
      "AIRLOCK_PP_SERIAL_LOG=${var.output_dir}/serial.log",
      "AIRLOCK_PP_ZSTD_LEVEL=${var.zstd_level}",
    ]
    script = "${local.packer_dir}/scripts/postprocess.sh"
  }
}
