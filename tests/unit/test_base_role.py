"""ansible/roles/base: structure, templates, and the values its controls write.

Tasks 1.2, 1.5, 1.9, 1.12, 2B.13, 2B.17, 6.1. The behaviour inside the booted image is
checked by tests/goss/base.yaml; these tests catch mistakes before a build.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import jinja2
import pytest
import yaml

REPO = Path(__file__).resolve().parents[2]
ROLE = REPO / "ansible" / "roles" / "base"
MAIN = yaml.safe_load((REPO / "ansible" / "group_vars" / "all" / "main.yml").read_text())
DEFAULTS = yaml.safe_load((ROLE / "defaults" / "main.yml").read_text())
GOSS = yaml.safe_load((REPO / "tests" / "goss" / "base.yaml").read_text())
HELPERS = {"main.yml", "boot_disk_facts.yml"}


def env_vars() -> dict[str, object]:
    return {**MAIN, **DEFAULTS}


def render_template(name: str, **extra: object) -> str:
    env = jinja2.Environment(
        loader=jinja2.FileSystemLoader(str(ROLE / "templates")),
        undefined=jinja2.StrictUndefined,
        keep_trailing_newline=True,
        autoescape=False,  # noqa: S701 - config files, not HTML
    )
    return env.get_template(name).render(**env_vars(), **extra)


def task_files() -> list[Path]:
    return sorted(p for p in (ROLE / "tasks").glob("*.yml") if p.name not in HELPERS)


def imports() -> list[dict]:
    return yaml.safe_load((ROLE / "tasks" / "main.yml").read_text())


def test_every_task_file_is_imported_and_exists() -> None:
    imported = [t["ansible.builtin.import_tasks"] for t in imports()]
    assert len(imported) == len(set(imported))
    for name in imported:
        assert (ROLE / "tasks" / name).is_file(), name
    assert set(imported) >= {p.name for p in task_files()}


@pytest.mark.parametrize("path", task_files(), ids=lambda p: p.name)
def test_each_control_names_its_task_and_test(path: Path) -> None:
    head = path.read_text().split("\n- name:", 1)[0]
    assert re.search(r"Control[^\n]*\d", head) or re.search(r"\(\d+[A-Z]?\.\d+", head), path.name
    assert "Test:" in head or "Tests:" in head, f"{path.name} must name its test"


def test_finalize_files_are_tagged_and_last() -> None:
    entries = imports()
    tagged = [
        e["ansible.builtin.import_tasks"]
        for e in entries
        if "airlock_finalize" in e.get("tags", [])
    ]
    assert tagged == ["no_ssh_server.yml", "build_access.yml", "image_finalize.yml"]
    assert [e["ansible.builtin.import_tasks"] for e in entries[-3:]] == tagged


def test_role_defaults_use_the_role_prefix() -> None:
    assert all(k.startswith("base_") for k in DEFAULTS), "ansible-lint var-naming"


def test_grub_cmdline_has_every_kernel_parameter() -> None:
    """3.3, 3.4, 3A.1 applied by base: every airlock_kernel_cmdline entry, nothing extra."""
    text = render_template("90-airlock.cfg.j2")
    m = re.search(r'^GRUB_CMDLINE_LINUX="([^"]*)"$', text, re.M)
    assert m
    assert m.group(1).split() == MAIN["airlock_kernel_cmdline"]
    assert "noresume" in m.group(1).split()
    assert re.search(r"^GRUB_DISABLE_OS_PROBER=true$", text, re.M)
    assert re.search(r"^GRUB_DISABLE_LINUX_UUID=false$", text, re.M)
    assert "GRUB_DISTRIBUTOR" not in text, "changing it moves shim's EFI folder"


def test_goss_checks_every_kernel_parameter() -> None:
    patterns = GOSS["command"]["kernel-cmdline"]["stdout"]
    assert len(patterns) == len(MAIN["airlock_kernel_cmdline"])
    cmdline = "BOOT_IMAGE=/boot/vmlinuz root=UUID=x ro " + " ".join(MAIN["airlock_kernel_cmdline"])
    for entry in MAIN["airlock_kernel_cmdline"]:
        hits = [
            p
            for p in patterns
            if re.search(p.strip("/"), entry) and re.search(p.strip("/"), cmdline)
        ]
        assert hits, f"no goss pattern matches {entry}"
        # The pattern must fail when the entry is missing.
        without = cmdline.replace(" " + entry, "")
        assert not re.search(hits[0].strip("/"), without), f"pattern for {entry} is too loose"


def test_apt_sources_point_at_the_snapshot() -> None:
    text = render_template("ubuntu.sources.j2")
    assert f"URIs: https://snapshot.ubuntu.com/ubuntu/{MAIN['apt_snapshot']}\n" in text
    assert "Suites: noble noble-updates noble-security\n" in text
    assert re.fullmatch(r"\d{8}T\d{6}Z", MAIN["apt_snapshot"])


def test_gdm_autologin_for_the_analyst() -> None:
    text = render_template("gdm-custom.conf.j2")
    assert "AutomaticLoginEnable=true\n" in text
    assert f"AutomaticLogin={MAIN['airlock_user']}\n" in text
    assert re.search(r"\[xdmcp\]\nEnable=false\n", text)


def _task(path: str, name_part: str) -> dict:
    for task in yaml.safe_load((ROLE / "tasks" / path).read_text()):
        if name_part in task["name"]:
            return task
    raise AssertionError(f"no task containing {name_part!r} in {path}")


def test_data_partitions_mount_options() -> None:
    """2B.13: ASSETS ro,noexec,nosuid,nodev; 2B.17: OUTPUT rw,noexec,nosuid,nodev (analyst)."""
    task = _task("data_mounts.yml", "Mount ASSETS")
    block = task["ansible.builtin.blockinfile"]["block"]
    lines = [ln for ln in block.splitlines() if ln.strip()]
    assert len(lines) == 2
    assert all(ln.startswith("UUID={{") for ln in lines), "fstab by UUID only"
    assets_opts = task["vars"]["base_assets_mount_options"].split(",")
    output_opts = task["vars"]["base_output_mount_options"].strip().split(",")
    for opt in ("ro", "noexec", "nosuid", "nodev", "nofail"):
        assert opt in assets_opts
    for opt in ("rw", "noexec", "nosuid", "nodev", "nofail"):
        assert opt in output_opts
    assert "rw" not in assets_opts
    assert any(o.startswith("uid={{") for o in output_opts)
    rendered = (
        jinja2.Environment(undefined=jinja2.StrictUndefined, autoescape=False)  # noqa: S701
        .from_string(block)
        .render(
            **MAIN,
            base_assets_uuid="1111-AAAA",
            base_output_uuid="2222-BBBB",
            base_assets_mount_options=task["vars"]["base_assets_mount_options"],
            base_output_mount_options=jinja2.Template(task["vars"]["base_output_mount_options"])
            .render(base_analyst_uid=1000, base_parse_gid=998)
            .strip(),
        )
    )
    fields = [ln.split() for ln in rendered.splitlines() if ln.strip()]
    assert fields[0][:3] == ["UUID=1111-AAAA", "/srv/airlock/assets", "exfat"]
    assert fields[1][:3] == ["UUID=2222-BBBB", "/srv/airlock/output", "exfat"]
    out_fields = fields[1][3].split(",")
    assert "uid=1000" in out_fields
    # The parser group can write module work folders; nobody else can read case output.
    assert {"gid=998", "dmask=0007", "fmask=0117"} <= set(out_fields)
    assert all(f[4:] == ["0", "0"] for f in fields), "no dump, no fsck"
    assert MAIN["airlock_assets_mount"] == "/srv/airlock/assets"
    assert MAIN["airlock_output_mount"] == "/srv/airlock/output"


def test_build_info_keys() -> None:
    task = _task("build_info.yml", "Write the build information")
    info = task["vars"]["base_build_info"]
    assert {"build_date", "git_commit", "version", "schema", "apt_snapshot"} <= set(info)
    assert task["when"] == "airlock_phase == 'image'"


def test_analyst_password_is_locked_not_set() -> None:
    task = _task("analyst_user.yml", "locked password")["ansible.builtin.user"]
    assert task["password"] == "!"  # noqa: S105 - "!" is the locked marker, not a password
    assert task["name"] == "{{ airlock_user }}"
    sudo = _task("analyst_sudo.yml", "passwordless sudo")["ansible.builtin.copy"]
    assert "NOPASSWD: ALL" in sudo["content"]
    assert sudo["validate"].startswith("/usr/sbin/visudo -cf")


def test_helpers_referenced_by_tasks_exist() -> None:
    for path in (ROLE / "tasks").glob("*.yml"):
        for src in re.findall(r"^\s+src: ([A-Za-z0-9_.\-]+)\s*$", path.read_text(), re.M):
            if (
                path.name in {"timezone.yml", "desktop.yml", "firstboot.yml", "image_finalize.yml"}
                and "/" in src
            ):
                continue
            if src.endswith(".j2"):
                assert (ROLE / "templates" / src).is_file(), src
            else:
                assert (ROLE / "files" / src).is_file(), f"{path.name}: {src}"


def test_kernel_package_matches_the_autoinstall() -> None:
    hcl = (REPO / "packer" / "variables.pkr.hcl").read_text()
    m = re.search(r'variable "kernel_package" \{[^}]*default\s*=\s*"([^"]+)"', hcl, re.S)
    assert m and m.group(1) == DEFAULTS["base_kernel_package"]


def test_initramfs_modules_cover_usb_nvme_vmd_sata() -> None:
    """1.12: uas, usb-storage, nvme, vmd, ahci and xhci are always in the initramfs."""
    mods = set(DEFAULTS["base_initramfs_modules"])
    assert {"uas", "usb_storage", "nvme", "vmd", "ahci", "xhci_pci", "xhci_hcd"} <= mods
    goss = GOSS["command"]["initramfs-modules"]["stdout"]
    for name in ("uas", "usb-storage", "nvme", "vmd", "ahci"):
        assert any(name.replace("-", "\\-") in p or name in p for p in goss), name
    usb_host = GOSS["command"]["usb-host-drivers"]["exec"]
    assert "xhci-pci" in usb_host and "modules.builtin" in usb_host


def test_uas_quirk_default_names_no_vendor() -> None:
    assert DEFAULTS["base_uas_quirks"] == ""


LIVE_SKIPPED = {
    "boot_disk_facts.yml",
    "partition_layout.yml",
    "data_mounts.yml",
    "grub_cmdline.yml",
    "grub_usb_compat.yml",
    "bootloader.yml",
    "boot_chain.yml",
    "firstboot.yml",
}


def test_live_target_skips_only_drive_steps() -> None:
    """7.2: airlock_target=live skips the steps that only fit an installed drive."""
    assert MAIN["airlock_target"] == "drive"
    skipped = {
        e["ansible.builtin.import_tasks"]
        for e in imports()
        if e.get("when") == "airlock_target != 'live'"
    }
    assert skipped == LIVE_SKIPPED
    live_vars = REPO / "live" / "build.sh"
    if live_vars.is_file():
        assert '"airlock_target": "live"' in live_vars.read_text()


def test_firstboot_unit_runs_before_the_provisioning_unit() -> None:
    """1.10: the first-boot unit orders itself before the unit that really exists."""
    unit = (ROLE / "files" / "airlock-firstboot.service").read_text()
    before = re.search(r"^Before=(.*)$", unit, re.M)
    assert before
    names = before.group(1).split()
    assert "airlock-provision.service" in names
    assert "forensic-provision.service" not in names
    provision = REPO / "ansible" / "roles" / "session_tools" / "files" / "systemd"
    assert (provision / "airlock-provision.service").is_file()
    assert (
        "ConditionKernelCommandLine=!airlock.noprovision"
        in (provision / "airlock-provision.service").read_text()
    )


def test_vm_test_hook_is_installed_and_wired_into_the_default_args() -> None:
    """1.11 harness support: grub variable $airlock_test_args, set only by 06_airlock_vm_test."""
    text = render_template("90-airlock.cfg.j2")
    m = re.search(r'^GRUB_CMDLINE_LINUX_DEFAULT="([^"]*)"$', text, re.M)
    assert m and m.group(1) == r"quiet splash \$airlock_test_args"
    hook = (ROLE / "files" / "06_airlock_vm_test").read_text()
    assert 'set airlock_test_args="airlock.noprovision"' in hook
    tasks = yaml.safe_load((ROLE / "tasks" / "grub_cmdline.yml").read_text())
    copies = [t["ansible.builtin.copy"] for t in tasks if "ansible.builtin.copy" in t]
    assert any(c["src"] == "06_airlock_vm_test" and c["mode"] == "0755" for c in copies)


# ------------------------------------------------------------------ 1.5 offline (finding 1)


def test_packages_install_and_refresh_only_in_the_image_phase() -> None:
    steps = yaml.safe_load((ROLE / "tasks" / "packages.yml").read_text())
    for t in steps:
        apt = t.get("ansible.builtin.apt")
        if apt is not None:
            assert t["when"] == "airlock_phase == 'image'", t["name"]
        else:
            assert t["when"] == "airlock_phase != 'image'", t["name"]
            assert "ansible.builtin.package_facts" not in t  # needs python3-apt; dpkg-query not


def _play_packages(tmp_path: Path, phase: str, pkgs: list[str]) -> subprocess.CompletedProcess:
    play = tmp_path / "play.yml"
    play.write_text(
        "- name: Base packages\n  hosts: localhost\n  connection: local\n"
        "  gather_facts: false\n  become: false\n  tasks:\n    - name: Run packages.yml\n"
        f"      ansible.builtin.import_tasks: {ROLE / 'tasks' / 'packages.yml'}\n",
        encoding="utf-8",
    )
    (tmp_path / "vars.json").write_text(
        json.dumps({"airlock_phase": phase, "base_packages": pkgs}), encoding="utf-8"
    )
    env = {
        **os.environ,
        "ANSIBLE_NOCOLOR": "1",
        "ANSIBLE_LOCALHOST_WARNING": "0",
        "ANSIBLE_INVENTORY_UNPARSED_WARNING": "0",
        "ANSIBLE_PYTHON_INTERPRETER": sys.executable,
    }
    return subprocess.run(
        ["ansible-playbook", "-i", "localhost,", str(play), "-e", f"@{tmp_path / 'vars.json'}"],
        capture_output=True, text=True, env=env, check=False, timeout=600,
    )  # fmt: skip


@pytest.mark.skipif(
    shutil.which("ansible-playbook") is None or shutil.which("dpkg-query") is None,
    reason="needs ansible-playbook and dpkg-query",
)
def test_provision_phase_checks_packages_without_apt(tmp_path: Path) -> None:
    ok = _play_packages(tmp_path, "provision", ["bash", "coreutils"])
    assert ok.returncode == 0, ok.stdout[-3000:]
    assert "apt" not in re.findall(r"TASK \[([^\]]*)\]", ok.stdout)
    bad = _play_packages(tmp_path, "provision", ["bash", "no-such-base-package"])
    assert bad.returncode != 0
    assert "This image is missing no-such-base-package" in bad.stdout
    assert "Reflash the drive" in bad.stdout
