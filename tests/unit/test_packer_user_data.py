"""packer/http/user-data: autoinstall YAML and the drive layout (tasks 1.2, 1.3, 2B.9, 2B.17, 6.1).

The file is a Packer templatefile(). These tests render it the way Packer does, from the
values in ansible/group_vars/all/main.yml, and check the result. When Packer and its QEMU
plugin are installed they also render it with 'packer console' and require the same text.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parents[2]
USER_DATA = REPO / "packer" / "http" / "user-data"
TEMPLATE = REPO / "packer" / "ubuntu-24.04.pkr.hcl"
MAIN = yaml.safe_load((REPO / "ansible" / "group_vars" / "all" / "main.yml").read_text())

MIB = 1
GIB = 1024 * MIB
SIZE_RE = re.compile(r"^(\d+)([MG])$")
PUBKEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestKeyOnlyForUnitTests airlock-build-ephemeral"


def template_vars() -> dict[str, object]:
    snap = MAIN["apt_snapshot"]
    mirror = f"https://snapshot.ubuntu.com/ubuntu/{snap}"
    return {
        "airlock_user": MAIN["airlock_user"],
        "apt_mirror": mirror,
        "apt_security_mirror": mirror,
        "assets_partition_gib": MAIN["assets_partition_gib"],
        "build_ssh_public_key": PUBKEY,
        "build_user": "airlock-build",
        "esp_size_mib": MAIN["esp_size_mib"],
        "kernel_package": "linux-generic-hwe-24.04",
        "output_partition_gib": MAIN["output_partition_gib"],
    }


_INTERP = re.compile(r"(\$\$\{)|\$\{\s*([A-Za-z_][A-Za-z0-9_]*)\s*\}")


def render(text: str, values: dict[str, object]) -> str:
    """HCL templatefile(): interpolation only (the file must use no directives)."""
    assert "%{" not in text.replace("%%{", ""), "user-data must not use template directives"

    def sub(m: re.Match[str]) -> str:
        if m.group(1):
            return "${"
        name = m.group(2)
        assert name in values, f"user-data uses ${{{name}}}, which the template does not pass"
        return str(values[name])

    return _INTERP.sub(sub, text)


def placeholders(text: str) -> set[str]:
    return {m.group(2) for m in _INTERP.finditer(text) if m.group(2)}


@pytest.fixture(scope="module")
def rendered() -> str:
    return render(USER_DATA.read_text(), template_vars())


@pytest.fixture(scope="module")
def data(rendered: str) -> dict:
    return yaml.safe_load(rendered)["autoinstall"]


def to_mib(size: str | int) -> int:
    m = SIZE_RE.match(str(size))
    assert m, f"unexpected size {size!r}"
    return int(m.group(1)) * (GIB if m.group(2) == "G" else MIB)


def test_cloud_config_header_and_version(rendered: str, data: dict) -> None:
    assert rendered.startswith("#cloud-config\n")
    assert data["version"] == 1
    assert data["interactive-sections"] == []
    assert data["shutdown"] == "reboot"


def test_placeholders_match_the_packer_template() -> None:
    hcl = TEMPLATE.read_text()
    block = hcl[hcl.index("templatefile(") : hcl.index("})", hcl.index("templatefile("))]
    passed = set(re.findall(r"^\s*([a-z_]+)\s*=", block, re.M))
    assert placeholders(USER_DATA.read_text()) == passed


def test_hardware_neutral_install(data: dict) -> None:
    assert data["drivers"] == {"install": False}
    assert data["oem"] == {"install": False}
    assert data["source"]["search_drivers"] is False
    assert data["refresh-installer"] == {"update": False}


def test_apt_uses_the_dated_snapshot(data: dict) -> None:
    """6.1: primary and security pockets come from snapshot.ubuntu.com/<apt_snapshot>."""
    want = f"https://snapshot.ubuntu.com/ubuntu/{MAIN['apt_snapshot']}"
    apt = data["apt"]
    assert apt["primary"][0]["uri"] == want
    assert apt["security"][0]["uri"] == want
    assert apt["geoip"] is False
    assert apt["fallback"] == "abort"
    assert apt["preserve_sources_list"] is False


def test_generic_hwe_kernel_and_most_modules(data: dict) -> None:
    """1.3: generic kernel, virtual kernels purged, MODULES=most in the initramfs."""
    assert data["kernel"]["package"] == "linux-generic-hwe-24.04"
    late = "\n".join(data["late-commands"])
    for pkg in ("linux-virtual", "linux-image-virtual", "linux-image-virtual-hwe-24.04"):
        assert pkg in late
    assert "apt-get -y purge" in late
    assert "MODULES=most" in late
    assert "update-initramfs -u -k all" in late


def test_storage_partition_plan(data: dict) -> None:
    """2B.9, 2B.17: BIOSBOOT, EFI, ASSETS, OUTPUT, root last; no swap, no LVM."""
    storage = data["storage"]
    assert storage["swap"] == {"size": 0}
    items = storage["config"]
    types = {i["type"] for i in items}
    assert types <= {"disk", "partition", "format", "mount"}, "no LVM, RAID or swap actions"
    disk = next(i for i in items if i["type"] == "disk")
    assert disk["ptable"] == "gpt"
    parts = sorted((i for i in items if i["type"] == "partition"), key=lambda i: i["number"])
    assert [p["id"] for p in parts] == [
        "part-biosboot",
        "part-esp",
        "part-assets",
        "part-output",
        "part-root",
    ]
    assert [p["number"] for p in parts] == [1, 2, 3, 4, 5]
    assert all(p["device"] == disk["id"] for p in parts)
    assert parts[0]["flag"] == "bios_grub"
    assert parts[1]["flag"] == "boot"
    assert parts[1]["grub_device"] is True
    assert parts[4]["size"] == -1, "root takes the rest so it can grow on first boot"
    # ASSETS and OUTPUT are left unformatted for the base role's mkfs.exfat.
    formatted = {i["volume"] for i in items if i["type"] == "format"}
    assert formatted == {"part-esp", "part-root"}
    fs = {i["volume"]: i for i in items if i["type"] == "format"}
    assert fs["part-esp"]["fstype"] == "fat32"
    assert fs["part-root"]["fstype"] == "ext4"
    assert fs["part-root"]["label"] == MAIN["airlock_root_label"]
    mounts = {i["path"]: i["device"] for i in items if i["type"] == "mount"}
    assert mounts == {"/": "fs-root", "/boot/efi": "fs-esp"}


def disk_size_mib() -> int:
    """Same formula as local.disk_size_mib in packer/ubuntu-24.04.pkr.hcl."""
    return (
        1
        + 1
        + MAIN["esp_size_mib"]
        + 1024
        * (MAIN["assets_partition_gib"] + MAIN["output_partition_gib"] + MAIN["root_image_gib"])
        + 1
    )


def test_partition_sizes_add_up(data: dict) -> None:
    """Contract section 3: about 43 GiB raw; root gets root_image_gib after the fixed parts."""
    parts = sorted(
        (i for i in data["storage"]["config"] if i["type"] == "partition"),
        key=lambda i: i["number"],
    )
    fixed = [to_mib(p["size"]) for p in parts[:4]]
    assert fixed == [
        1,
        MAIN["esp_size_mib"],
        MAIN["assets_partition_gib"] * GIB,
        MAIN["output_partition_gib"] * GIB,
    ]
    total = disk_size_mib()
    root = total - 1 - sum(fixed) - 1  # 1 MiB lead-in, 1 MiB backup GPT
    assert root == MAIN["root_image_gib"] * GIB
    assert 42 * GIB <= total <= 44 * GIB, f"raw image is {total / GIB:.2f} GiB, expected about 43"


def test_users_locked_and_build_user_temporary(data: dict) -> None:
    """1.2: analyst has a locked password and no key; the build user is key-only."""
    ud = data["user-data"]
    assert ud["disable_root"] is True
    assert ud["ssh_pwauth"] is False
    users = {u["name"]: u for u in ud["users"]}
    analyst = users[MAIN["airlock_user"]]
    assert analyst["lock_passwd"] is True
    assert "passwd" not in analyst
    assert "hashed_passwd" not in analyst
    assert "ssh_authorized_keys" not in analyst
    assert "sudo" not in analyst, "analyst sudo comes from the base role, not cloud-init"
    build = users["airlock-build"]
    assert build["lock_passwd"] is True
    assert build["ssh_authorized_keys"] == [PUBKEY]
    assert data["ssh"] == {"install-server": True, "allow-pw": False}
    assert "identity" not in data, "no password hash for any account"


def test_no_secret_or_password_hash_in_the_file() -> None:
    text = USER_DATA.read_text()
    assert not re.search(r"\$[156y]\$", text), "no crypt(3) password hash"
    assert "ssh-ed25519 AAAA" not in text and "ssh-rsa AAAA" not in text


def _packer_console_ok() -> bool:
    if not shutil.which("packer"):
        return False
    res = subprocess.run(
        ["packer", "plugins", "installed"], capture_output=True, text=True, check=False
    )
    return "packer-plugin-qemu_v1.1.8" in res.stdout


@pytest.mark.skipif(not _packer_console_ok(), reason="needs packer 1.11.2 and the QEMU plugin")
def test_packer_renders_the_same_text(rendered: str, tmp_path: Path) -> None:
    values = template_vars()
    args = [
        "packer",
        "console",
        "-var",
        f"airlock_version={MAIN['airlock_version']}",
        "-var",
        "iso_url=https://example.invalid/ubuntu.iso",
        "-var",
        "iso_sha256=" + "0" * 64,
        "-var",
        f"apt_snapshot={MAIN['apt_snapshot']}",
        "-var",
        f"build_ssh_public_key={values['build_ssh_public_key']}",
        "-var",
        f"build_ssh_private_key_file={tmp_path / 'key'}",
        "-var",
        f"esp_size_mib={MAIN['esp_size_mib']}",
        "-var",
        f"assets_partition_gib={MAIN['assets_partition_gib']}",
        "-var",
        f"output_partition_gib={MAIN['output_partition_gib']}",
        "-var",
        f"root_image_gib={MAIN['root_image_gib']}",
        str(REPO / "packer"),
    ]
    env = {**os.environ, "CHECKPOINT_DISABLE": "1"}

    def console(expr: str) -> str:
        res = subprocess.run(
            args, input=expr + "\n", capture_output=True, text=True, check=True, env=env
        )
        return res.stdout.strip()

    assert json.loads(console("jsonencode(local.user_data)")) == rendered
    assert int(console("local.disk_size_mib")) == disk_size_mib()
