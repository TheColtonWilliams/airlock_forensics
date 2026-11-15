"""packer/ubuntu-24.04.pkr.hcl and scripts/build.sh (tasks 1.1, 1.4, 1.6, 1.7).

Checks the pinned versions agree everywhere, the ISO checksum comes from pins.yml, the
Ansible provisioner and the zstd post-processor are wired in, and the template passes
'packer validate' (full validation when the pinned QEMU plugin is installed, syntax-only
otherwise).
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parents[2]
HCL = (REPO / "packer" / "ubuntu-24.04.pkr.hcl").read_text()
VARS_HCL = (REPO / "packer" / "variables.pkr.hcl").read_text()
BUILD_SH = (REPO / "scripts" / "build.sh").read_text()
PINS = yaml.safe_load((REPO / "ansible" / "group_vars" / "all" / "pins.yml").read_text())["pins"]


def sh_const(name: str) -> str:
    m = re.search(rf'^{name}="([^"]+)"$', BUILD_SH, re.M)
    assert m, f"{name} not set in scripts/build.sh"
    return m.group(1)


def test_packer_version_pinned_the_same_everywhere() -> None:
    version = sh_const("PACKER_VERSION")
    assert re.search(rf'required_version\s*=\s*"= {re.escape(version)}"', HCL)
    assert PINS[sh_const("PACKER_PIN")]["version"] == version
    assert re.fullmatch(r"[0-9a-f]{64}", PINS[sh_const("PACKER_PIN")]["sha256"])


def test_qemu_plugin_version_pinned_the_same_everywhere() -> None:
    version = sh_const("QEMU_PLUGIN_VERSION")
    block = HCL[HCL.index("required_plugins") :]
    assert re.search(rf'version\s*=\s*"= {re.escape(version)}"', block)
    assert 'source  = "github.com/hashicorp/qemu"' in block
    pin = PINS[sh_const("QEMU_PLUGIN_PIN")]
    assert pin["version"] == version
    assert version in pin["url"]
    assert re.fullmatch(r"[0-9a-f]{64}", pin["sha256"])


def test_iso_checksum_comes_from_the_pin() -> None:
    """1.1: the ISO is verified by the SHA-256 in pins.ubuntu_server_iso."""
    assert 'iso_checksum = "sha256:${var.iso_sha256}"' in HCL
    assert "iso_url      = var.iso_url" in HCL
    assert "pins.ubuntu_server_iso" in BUILD_SH
    iso = PINS["ubuntu_server_iso"]
    assert re.fullmatch(r"[0-9a-f]{64}", iso["sha256"])
    assert "validation" in VARS_HCL[VARS_HCL.index('variable "iso_sha256"') :]


def test_builds_raw_under_uefi_with_layout_sized_disk() -> None:
    assert 'format           = "raw"' in HCL or re.search(r'format\s*=\s*"raw"', HCL)
    assert re.search(r"efi_boot\s*=\s*true", HCL)
    assert re.search(r'disk_size\s*=\s*"\$\{local\.disk_size_mib\}M"', HCL)
    assert "var.root_image_gib" in HCL


def test_ansible_provisioner_runs_site_yml_locally() -> None:
    """1.4: a shell provisioner runs ansible-playbook -c local site.yml in the guest."""
    assert "scripts/run-ansible.sh" in HCL
    run = (REPO / "packer" / "scripts" / "run-ansible.sh").read_text()
    assert re.search(r"ansible-playbook -c local -i inventory\.ini site\.yml", run)
    assert '"airlock_phase": "image"' in run
    assert '"${local.packer_dir}/../ansible"' in HCL


def test_repo_copy_and_build_inputs_are_uploaded() -> None:
    """2B.5, 2B.6, 2B.15: the repo copy has what provisioning reads; the build inputs go in."""
    assert '"${local.packer_dir}/../profiles"' in HCL
    assert '"${local.packer_dir}/../docs"' in HCL
    assert 'source      = "${local.packer_dir}/../tests/goss"' in HCL
    assert 'destination = "/var/tmp/airlock-repo/tests/"' in HCL
    assert 'source      = "${var.image_inputs_dir}/"' in HCL
    assert 'destination = "/var/tmp/airlock-inputs"' in HCL
    # Uploads come before Ansible runs, and the inputs folder is removed at the end.
    assert HCL.index("airlock-inputs") < HCL.index("scripts/run-ansible.sh")
    boot = (REPO / "packer" / "scripts" / "bootstrap.sh").read_text()
    assert '"$repo_stage/tests"' in boot and '"$inputs_stage"' in boot
    fin = (REPO / "packer" / "scripts" / "finalize.sh").read_text()
    assert 'rm -rf -- "$repo_stage" "$inputs_stage" "$vars_file"' in fin
    base_defaults = yaml.safe_load(
        (REPO / "ansible" / "roles" / "base" / "defaults" / "main.yml").read_text()
    )
    assert base_defaults["base_image_inputs_dir"] == "/var/tmp/airlock-inputs"
    assert '"image_inputs_dir": e["AL_INPUTS"]' in BUILD_SH
    assert 'variable "image_inputs_dir"' in VARS_HCL


def test_build_access_removed_before_power_off() -> None:
    """1.5: finalize runs the airlock_finalize tag in its own unit, then powers off."""
    assert "systemd-run --unit=airlock-finalize" in HCL
    fin = (REPO / "packer" / "scripts" / "finalize.sh").read_text()
    assert "--tags airlock_finalize" in fin
    assert '"base_finalize_build": true' in fin
    assert fin.index("AIRLOCK-FINALIZE-OK") < fin.index("$poweroff_cmd\n")


def test_post_processor_compresses_and_hashes() -> None:
    """1.6: raw image -> zstd, SHA256SUMS."""
    assert 'post-processor "shell-local"' in HCL
    assert "scripts/postprocess.sh" in HCL
    pp = (REPO / "packer" / "scripts" / "postprocess.sh").read_text()
    assert "zstd -T0" in pp
    assert "SHA256SUMS" in pp
    assert "AIRLOCK-FINALIZE-OK" in pp


def test_no_github_needed_for_plugins() -> None:
    """1.7: build.sh installs the plugin from the pinned zip, not with 'packer init'."""
    assert "packer init" not in BUILD_SH.replace("# ", "")
    assert "plugins install --path" in BUILD_SH


def _plugin_installed() -> bool:
    if not shutil.which("packer"):
        return False
    res = subprocess.run(
        ["packer", "plugins", "installed"], capture_output=True, text=True, check=False
    )
    return "packer-plugin-qemu_v1.1.8" in res.stdout


@pytest.mark.skipif(shutil.which("packer") is None, reason="packer not installed")
def test_packer_fmt_and_validate(tmp_path: Path) -> None:
    env = {**os.environ, "CHECKPOINT_DISABLE": "1"}
    subprocess.run(["packer", "fmt", "-check", str(REPO / "packer")], check=True, env=env)
    if not _plugin_installed():
        subprocess.run(
            ["packer", "validate", "-syntax-only", str(REPO / "packer")], check=True, env=env
        )
        return
    inputs = tmp_path / "inputs"
    inputs.mkdir()
    (inputs / "build-kind.json").write_text('{"kind": "dev"}\n')
    key = tmp_path / "key"
    subprocess.run(
        ["openssl", "genpkey", "-algorithm", "ed25519", "-out", str(key)],
        check=True,
        capture_output=True,
    )
    iso = PINS["ubuntu_server_iso"]
    main = yaml.safe_load((REPO / "ansible" / "group_vars" / "all" / "main.yml").read_text())
    res = subprocess.run(
        [
            "packer",
            "validate",
            "-var",
            f"airlock_version={main['airlock_version']}",
            "-var",
            f"iso_url={iso['url']}",
            "-var",
            f"iso_sha256={iso['sha256']}",
            "-var",
            f"apt_snapshot={main['apt_snapshot']}",
            "-var",
            "build_ssh_public_key=ssh-ed25519 AAAA unit-test",
            "-var",
            f"build_ssh_private_key_file={key}",
            "-var",
            f"image_inputs_dir={inputs}",
            str(REPO / "packer"),
        ],
        capture_output=True,
        text=True,
        check=False,
        env=env,
    )
    assert res.returncode == 0, res.stdout + res.stderr


@pytest.mark.skipif(shutil.which("packer") is None, reason="packer not installed")
def test_validate_rejects_a_bad_iso_hash(tmp_path: Path) -> None:
    env = {**os.environ, "CHECKPOINT_DISABLE": "1"}
    res = subprocess.run(
        [
            "packer",
            "validate",
            "-var",
            "airlock_version=0",
            "-var",
            "iso_url=x",
            "-var",
            "iso_sha256=null",
            "-var",
            "apt_snapshot=20261101T000000Z",
            "-var",
            "build_ssh_public_key=k",
            "-var",
            f"build_ssh_private_key_file={tmp_path / 'k'}",
            str(REPO / "packer"),
        ],
        capture_output=True,
        text=True,
        check=False,
        env=env,
    )
    assert res.returncode != 0
    assert "iso_sha256" in res.stdout + res.stderr
