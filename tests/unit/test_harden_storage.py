"""harden_storage controls that can run outside the image (tasks 3.2, 3.3, 3A.1, 3A.2, 3A.4).

The file-editing controls are run for real with ansible-playbook against temporary copies of
fstab, lvm.conf, mdadm.conf, and the GRUB defaults file. Nothing on the host is touched: the
playbook only imports the role's task files, path variables point into tmp_path, and the
handlers are replaced by no-ops.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")

REPO_ROOT = Path(__file__).resolve().parents[2]
ROLE = REPO_ROOT / "ansible" / "roles" / "harden_storage"
GROUP_VARS = REPO_ROOT / "ansible" / "group_vars" / "all" / "main.yml"
REQUIRED = yaml.safe_load((ROLE / "defaults" / "main.yml").read_text(encoding="utf-8"))[
    "harden_storage_required_cmdline"
]

needs_ansible = pytest.mark.skipif(
    shutil.which("ansible-playbook") is None, reason="needs ansible-playbook"
)


def run_tasks(
    tmp_path: Path, task_file: str, extra: dict, start_at: str | None = None
) -> tuple[int, str]:
    """Run one task file of the role on localhost with handlers stubbed out."""
    handlers = yaml.safe_load((ROLE / "handlers" / "main.yml").read_text(encoding="utf-8"))
    play = [
        {
            "name": "harden_storage unit test",
            "hosts": "localhost",
            "connection": "local",
            "gather_facts": False,
            "vars_files": [str(ROLE / "defaults" / "main.yml"), str(GROUP_VARS)],
            "handlers": [
                {"name": h["name"], "ansible.builtin.debug": {"msg": "handler stub"}}
                for h in handlers
            ],
            "tasks": [{"ansible.builtin.import_tasks": str(ROLE / "tasks" / task_file)}],
        }
    ]
    playbook = tmp_path / "play.yml"
    playbook.write_text(yaml.safe_dump(play), encoding="utf-8")
    extra_file = tmp_path / "extra.json"
    extra_file.write_text(json.dumps(extra), encoding="utf-8")
    env = dict(os.environ)
    env.update(
        {
            "ANSIBLE_NOCOLOR": "1",
            "ANSIBLE_LOCALHOST_WARNING": "False",
            "ANSIBLE_INVENTORY_UNPARSED_WARNING": "False",
            "ANSIBLE_RETRY_FILES_ENABLED": "False",
            "ANSIBLE_LOCAL_TEMP": str(tmp_path / "ansible-tmp"),
            "ANSIBLE_CONFIG": str(tmp_path / "none.cfg"),
        }
    )
    argv = ["ansible-playbook", "-i", "localhost,", str(playbook), "-e", f"@{extra_file}"]
    if start_at:
        argv += ["--start-at-task", start_at]
    res = subprocess.run(argv, capture_output=True, text=True, env=env, check=False, timeout=300)
    return res.returncode, res.stdout + res.stderr


def changed_count(output: str) -> int:
    m = re.search(r"localhost\s*:\s*ok=\d+\s+changed=(\d+)", output)
    assert m, output
    return int(m.group(1))


def grub_file(tmp_path: Path, entries: list[str]) -> Path:
    path = tmp_path / "90-airlock.cfg"
    path.write_text(
        "# written by the image role\n"
        f'GRUB_CMDLINE_LINUX_DEFAULT="$GRUB_CMDLINE_LINUX_DEFAULT {" ".join(entries)}"\n',
        encoding="utf-8",
    )
    return path


# ----------------------------------------------------------------- kernel command line


@needs_ansible
def test_kernel_cmdline_accepts_complete_grub_file(tmp_path: Path) -> None:
    path = grub_file(tmp_path, ["quiet", *REQUIRED, "rfkill.default_state=0"])
    rc, out = run_tasks(
        tmp_path, "kernel_cmdline.yml", {"harden_storage_grub_cmdline_file": str(path)}
    )
    assert rc == 0, out


@needs_ansible
@pytest.mark.parametrize("missing", ["noresume", "rd.md=0", "systemd.gpt_auto=0"])
def test_kernel_cmdline_rejects_missing_entry(tmp_path: Path, missing: str) -> None:
    entries = [e for e in REQUIRED if e != missing]
    path = grub_file(tmp_path, entries)
    rc, out = run_tasks(
        tmp_path, "kernel_cmdline.yml", {"harden_storage_grub_cmdline_file": str(path)}
    )
    assert rc != 0
    assert f"does not contain '{missing}'" in out


@needs_ansible
def test_kernel_cmdline_matches_whole_words_only(tmp_path: Path) -> None:
    # "rd.md=01" and "xnoresume" must not count as "rd.md=0" and "noresume".
    entries = [e for e in REQUIRED if e not in {"rd.md=0", "noresume"}] + ["rd.md=01", "xnoresume"]
    path = grub_file(tmp_path, entries)
    rc, out = run_tasks(
        tmp_path, "kernel_cmdline.yml", {"harden_storage_grub_cmdline_file": str(path)}
    )
    assert rc != 0, out


@needs_ansible
def test_kernel_cmdline_rejects_missing_file(tmp_path: Path) -> None:
    rc, out = run_tasks(
        tmp_path, "kernel_cmdline.yml", {"harden_storage_grub_cmdline_file": str(tmp_path / "nope")}
    )
    assert rc != 0
    assert "is missing" in out


@needs_ansible
def test_kernel_cmdline_rejects_shortened_shared_variable(tmp_path: Path) -> None:
    path = grub_file(tmp_path, REQUIRED)
    rc, out = run_tasks(
        tmp_path,
        "kernel_cmdline.yml",
        {"harden_storage_grub_cmdline_file": str(path), "airlock_kernel_cmdline": REQUIRED[1:]},
    )
    assert rc != 0
    assert "airlock_kernel_cmdline" in out


# ----------------------------------------------------------------- swap

FSTAB = """\
# /etc/fstab: static file system information.
UUID=1111-root / ext4 errors=remount-ro 0 1
UUID=2222-efi /boot/efi vfat umask=0077 0 1
/swap.img       none    swap    sw      0       0
UUID=3333-swap none swap sw 0 0
#/dev/sdb2 none swap sw 0 0
UUID=4444-out /srv/airlock/output exfat rw,noexec,nosuid,nodev 0 0
"""


@needs_ansible
def test_swap_lines_commented_and_swapfile_removed(tmp_path: Path) -> None:
    fstab = tmp_path / "fstab"
    fstab.write_text(FSTAB, encoding="utf-8")
    swapfile = tmp_path / "swap.img"
    swapfile.write_bytes(b"\0" * 4096)
    extra = {
        "harden_storage_fstab_path": str(fstab),
        "harden_storage_swap_files": [str(swapfile)],
    }
    start = "Swap | Comment out swap lines in fstab"  # skips the unit masking task
    rc, out = run_tasks(tmp_path, "no_swap.yml", extra, start_at=start)
    assert rc == 0, out
    assert not swapfile.exists()
    active = [
        line for line in fstab.read_text(encoding="utf-8").splitlines() if not line.startswith("#")
    ]
    assert not [line for line in active if re.split(r"\s+", line)[2:3] == ["swap"]]
    assert "UUID=1111-root / ext4 errors=remount-ro 0 1" in active
    assert "UUID=4444-out /srv/airlock/output exfat rw,noexec,nosuid,nodev 0 0" in active
    assert "# AIRLOCK: swap disabled (task 3.3): /swap.img" in fstab.read_text(encoding="utf-8")
    # Second run changes nothing (idempotent).
    rc, out = run_tasks(tmp_path, "no_swap.yml", extra, start_at=start)
    assert rc == 0, out
    assert changed_count(out) == 0, out


# ----------------------------------------------------------------- LVM and md

LVM_CONF = """\
config {
\tchecks = 1
}
global {
\t# event_activation = 1
\tumask = 077
}
activation {
\t# auto_activation_volume_list = [ "vg1" ]
\tudev_sync = 1
}
"""


def _section_of(text: str, needle: str) -> str:
    section = ""
    for line in text.splitlines():
        m = re.match(r"^(\w+) \{", line)
        if m:
            section = m.group(1)
        if needle in line and not line.lstrip().startswith("#"):
            return section
    return ""


@needs_ansible
@pytest.mark.parametrize("already", [False, True])
def test_lvm_autoactivation_off(tmp_path: Path, already: bool) -> None:
    conf = tmp_path / "lvm.conf"
    text = LVM_CONF
    if already:  # an existing setting is replaced, not duplicated
        text = text.replace("\tumask = 077", "\tumask = 077\n\tevent_activation = 1")
    conf.write_text(text, encoding="utf-8")
    extra = {"harden_storage_lvm_conf_path": str(conf)}
    rc, out = run_tasks(tmp_path, "lvm_autoactivation_off.yml", extra)
    assert rc == 0, out
    result = conf.read_text(encoding="utf-8")
    assert _section_of(result, "auto_activation_volume_list = []") == "activation"
    assert _section_of(result, "event_activation = 0") == "global"
    assert len(re.findall(r"^\s*event_activation\s*=", result, re.M)) == 1
    assert "Harden storage | Rebuild initramfs" in out  # initramfs gets the new setting
    rc, out = run_tasks(tmp_path, "lvm_autoactivation_off.yml", extra)
    assert changed_count(out) == 0, out


@needs_ansible
def test_lvm_skipped_when_not_installed(tmp_path: Path) -> None:
    extra = {"harden_storage_lvm_conf_path": str(tmp_path / "absent.conf")}
    rc, out = run_tasks(tmp_path, "lvm_autoactivation_off.yml", extra)
    assert rc == 0, out
    assert not (tmp_path / "absent.conf").exists()


@needs_ansible
@pytest.mark.parametrize(
    "existing", ["HOMEHOST <system>\nMAILADDR root\n", "AUTO +all\nMAILADDR root\n"]
)
def test_md_autoassembly_off(tmp_path: Path, existing: str) -> None:
    conf = tmp_path / "mdadm.conf"
    conf.write_text(existing, encoding="utf-8")
    extra = {"harden_storage_mdadm_conf_path": str(conf)}
    rc, out = run_tasks(tmp_path, "md_autoassembly_off.yml", extra)
    assert rc == 0, out
    lines = conf.read_text(encoding="utf-8").splitlines()
    assert [line for line in lines if line.startswith("AUTO")] == ["AUTO -all"]
    assert "MAILADDR root" in lines
    rc, out = run_tasks(tmp_path, "md_autoassembly_off.yml", extra)
    assert changed_count(out) == 0, out


# ----------------------------------------------------------------- udev rules


def _rules(name: str) -> list[str]:
    text = (ROLE / "files" / name).read_text(encoding="utf-8")
    return [line for line in text.splitlines() if line.strip() and not line.startswith("#")]


def test_readonly_rule_covers_every_disk_family() -> None:
    rule, forget = _rules("00-forensic-ro.rules")
    assert 'SUBSYSTEM=="block"' in rule
    assert 'KERNEL=="sd*|nvme*|mmcblk*|vd*"' in rule
    assert 'RUN+="/usr/local/sbin/airlock-setro %k"' in rule
    assert 'ACTION=="add|change"' in rule
    # A removed disk loses its unlock marker, so the next drive given its name is read-only.
    assert 'ACTION=="remove"' in forget and 'ENV{DEVTYPE}=="disk"' in forget
    assert 'KERNEL=="sd*|nvme*|mmcblk*|vd*"' in forget
    assert 'RUN+="/usr/local/sbin/airlock-setro --forget %k"' in forget


def _rule_number(name: str) -> int:
    match = re.match(r"^(\d+)-", name)
    assert match, name
    return int(match.group(1))


def test_readonly_rule_runs_before_package_rules() -> None:
    """udev runs RUN entries in the order rules add them: the policy must be queued first.

    69-bcache.rules (bcache-register), the multipath and open-iscsi rules, and any rule a package
    adds later all sort after 00-, so airlock-setro has set the flag before they act.
    """
    files = sorted(p.name for p in (ROLE / "files").glob("*-forensic-ro.rules"))
    assert files == ["00-forensic-ro.rules"], "exactly one read-only rule file, numbered 00"
    task = yaml.safe_load((ROLE / "tasks" / "readonly_udev.yml").read_text(encoding="utf-8"))
    installed = [t["ansible.builtin.copy"]["dest"] for t in task if "ansible.builtin.copy" in t]
    assert "/etc/udev/rules.d/00-forensic-ro.rules" in installed
    assert not any("99-forensic-ro" in d for d in installed)
    defaults = yaml.safe_load((ROLE / "defaults" / "main.yml").read_text(encoding="utf-8"))
    # The old late copy is removed from images built before the move.
    assert "99-forensic-ro.rules" in defaults["harden_storage_readonly_rule_old_names"]
    removal = [t for t in task if "ansible.builtin.file" in t]
    assert removal and removal[0]["ansible.builtin.file"]["state"] == "absent"
    for masked in defaults["harden_storage_udev_rules_masked"]:
        assert _rule_number(masked) > _rule_number("00-forensic-ro.rules"), masked
    assert _rule_number("00-forensic-ro.rules") < 60  # before 60-persistent-storage and bcache
    # Stacked-storage activation is off: bcache-tools purged and its rule masked; multipath
    # and open-iscsi rules masked and their daemons masked.
    assert "bcache-tools" in defaults["harden_storage_activation_packages_absent"]
    for rule in ("69-bcache.rules", "56-dm-mpath.rules", "60-multipath.rules"):
        assert rule in defaults["harden_storage_udev_rules_masked"], rule
    assert "70-open-iscsi.rules" in defaults["harden_storage_udev_rules_masked"]
    for unit in ("iscsid.service", "iscsid.socket", "open-iscsi.service", "multipathd.service"):
        assert unit in defaults["harden_storage_daemon_masked_units"], unit


def test_sg_rule_is_root_only_and_final() -> None:
    rules = _rules("99-airlock-sg-root-only.rules")
    assert len(rules) == 2
    for subsystem, rule in zip(("scsi_generic", "bsg"), rules, strict=True):
        assert f'SUBSYSTEM=="{subsystem}"' in rule
        for assign in ('MODE:="0600"', 'OWNER:="root"', 'GROUP:="root"'):
            assert assign in rule


@pytest.mark.skipif(shutil.which("udevadm") is None, reason="needs udevadm")
def test_udev_rules_verify() -> None:
    probe = subprocess.run(["udevadm", "verify", "--help"], capture_output=True, check=False)
    if probe.returncode != 0:
        pytest.skip("udevadm has no verify command (systemd older than 254)")
    files = [
        str(ROLE / "files" / n) for n in ("00-forensic-ro.rules", "99-airlock-sg-root-only.rules")
    ]
    res = subprocess.run(
        ["udevadm", "verify", "--resolve-names=never", *files],
        capture_output=True,
        text=True,
        check=False,
    )
    assert res.returncode == 0, res.stdout + res.stderr


def test_sg_packages_are_not_tool_dependencies() -> None:
    """3A.4 removes SG_IO tools; smartmontools and hdparm stay (guymager depends on them)."""
    absent = yaml.safe_load((ROLE / "defaults" / "main.yml").read_text(encoding="utf-8"))[
        "harden_storage_sg_packages_absent"
    ]
    assert set(absent) == {"sg3-utils", "sg3-utils-udev", "sdparm"}
