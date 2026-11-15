"""ansible/roles/base: structure, templates, and the values its controls write.

Tasks 1.2, 1.5, 1.9, 1.12, 2B.13, 2B.17, 6.1. The behaviour inside the booted image is
checked by tests/goss/base.yaml; these tests catch mistakes before a build.
"""

from __future__ import annotations

import re
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
