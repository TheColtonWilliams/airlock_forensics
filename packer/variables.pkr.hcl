# Variables for packer/ubuntu-24.04.pkr.hcl. scripts/build.sh fills every value that comes
# from ansible/group_vars/all/{main,pins}.yml, so those files stay the single source.

variable "airlock_version" {
  type        = string
  description = "Image version, from airlock_version in ansible/group_vars/all/main.yml."
}

variable "iso_url" {
  type        = string
  description = "Ubuntu live-server ISO URL, from pins.ubuntu_server_iso.url."
}

variable "iso_sha256" {
  type        = string
  description = "SHA-256 of the ISO, from pins.ubuntu_server_iso.sha256. Never null."

  validation {
    condition     = can(regex("^[0-9a-f]{64}$", var.iso_sha256))
    error_message = "The iso_sha256 variable must be 64 lowercase hex characters. Fill pins.ubuntu_server_iso.sha256 first."
  }
}

variable "apt_snapshot" {
  type        = string
  description = "Dated snapshot.ubuntu.com timestamp (YYYYMMDDTHHMMSSZ), from apt_snapshot in main.yml."

  validation {
    condition     = can(regex("^[0-9]{8}T[0-9]{6}Z$", var.apt_snapshot))
    error_message = "The apt_snapshot variable must look like 20261101T000000Z."
  }
}

variable "use_apt_snapshot" {
  type        = bool
  default     = true
  description = "Install from the dated snapshot (task 6.1). false uses the live archive."
}

variable "esp_size_mib" {
  type    = number
  default = 512
}

variable "assets_partition_gib" {
  type    = number
  default = 20
}

variable "output_partition_gib" {
  type    = number
  default = 8
}

variable "root_image_gib" {
  type    = number
  default = 14
}

variable "kernel_package" {
  type        = string
  default     = "linux-generic-hwe-24.04"
  description = "Generic-flavour HWE kernel metapackage (tasks 1.3, 1.12)."
}

variable "airlock_user" {
  type    = string
  default = "analyst"
}

variable "build_user" {
  type        = string
  default     = "airlock-build"
  description = "Temporary SSH user for Packer. Deleted by the final step of the build."
}

variable "build_ssh_public_key" {
  type        = string
  description = "Public half of the per-build key that scripts/build.sh generates. Never committed."
}

variable "build_ssh_private_key_file" {
  type        = string
  description = "Private half of the per-build key. Lives in a temporary directory for one build."
}

variable "output_dir" {
  type    = string
  default = "output/airlock"
}

variable "accelerator" {
  type        = string
  default     = "kvm"
  description = "kvm (normal) or tcg (emulation, many times slower)."

  validation {
    condition     = contains(["kvm", "tcg"], var.accelerator)
    error_message = "The accelerator variable must be kvm or tcg."
  }
}

variable "cpus" {
  type    = number
  default = 4
}

variable "memory_mib" {
  type    = number
  default = 4096
}

variable "ovmf_code" {
  type    = string
  default = "/usr/share/OVMF/OVMF_CODE_4M.fd"
}

variable "ovmf_vars" {
  type    = string
  default = "/usr/share/OVMF/OVMF_VARS_4M.fd"
}

variable "boot_wait" {
  type    = string
  default = "10s"
}

variable "ssh_timeout" {
  type    = string
  default = "4h"
}

variable "shutdown_timeout" {
  type    = string
  default = "45m"
}

variable "git_commit" {
  type    = string
  default = "unknown"
}

variable "build_date" {
  type        = string
  default     = "unknown"
  description = "UTC build time, ISO 8601 with Z. scripts/build.sh honours SOURCE_DATE_EPOCH."
}

variable "zstd_level" {
  type    = number
  default = 15
}

variable "idempotence_check" {
  type        = bool
  default     = false
  description = "Run site.yml a second time and fail if any task reports a change."
}
