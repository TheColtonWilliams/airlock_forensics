"""Static checks of the session_tools role (tasks 4.10, 4.11): one concern per task file, each
naming an existing test, launchers valid, and the package list covering what the helpers call.
The role itself is run for real by tests/functional/test_session_role.sh."""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parents[2]
ROLE = REPO / "ansible" / "roles" / "session_tools"
OWN_TASKS = [
    "packages.yml",
    "parse_user.yml",
    "folders.yml",
    "commands.yml",
    "pylib.yml",
    "log_lib.yml",
    "etc_files.yml",
    "config.yml",
    "repo_copy.yml",
    "desktop_launchers.yml",
    "autostart.yml",
]


def load(path: Path) -> object:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def test_main_only_imports_task_files() -> None:
    tasks = load(ROLE / "tasks" / "main.yml")
    assert isinstance(tasks, list)
    imported = []
    for task in tasks:
        keys = set(task) - {"name", "when"}
        assert keys <= {"ansible.builtin.import_tasks", "ansible.builtin.include_tasks"}, task
        target = task.get("ansible.builtin.import_tasks") or task.get(
            "ansible.builtin.include_tasks"
        )
        imported.append(target)
    assert imported[: len(OWN_TASKS)] == OWN_TASKS
    for name in OWN_TASKS:
        assert (ROLE / "tasks" / name).is_file(), name
    # The provisioning unit (assets package) is included only when present.
    last = tasks[-1]
    assert last["ansible.builtin.include_tasks"] == "provision_unit.yml"
    assert any("is file" in cond for cond in last["when"])


@pytest.mark.parametrize("name", OWN_TASKS)
def test_each_task_file_names_an_existing_test(name: str) -> None:
    text = (ROLE / "tasks" / name).read_text(encoding="utf-8")
    header = "\n".join(line for line in text.splitlines() if line.startswith("#"))
    assert "Test" in header, f"{name}: no Test: comment"
    paths = re.findall(r"tests/[\w/.-]+\.(?:py|sh|yaml)", header)
    assert paths, f"{name}: the Test comment names no test file"
    for p in paths:
        assert (REPO / p).is_file(), f"{name}: names {p}, which does not exist"
    for task in load(ROLE / "tasks" / name):
        module = next(k for k in task if k.startswith("ansible."))
        assert module.startswith("ansible.builtin."), f"{name}: FQCN {module}"


def test_bin_and_pylib_copied_whole() -> None:
    commands = load(ROLE / "tasks" / "commands.yml")[0]["ansible.builtin.copy"]
    assert commands["src"].endswith("/files/bin/")
    assert commands["mode"] == "0755"
    assert commands["dest"] == "{{ session_tools_bin_dir }}/"
    pylib = load(ROLE / "tasks" / "pylib.yml")[0]
    assert pylib["ansible.builtin.copy"]["src"].endswith("/files/pylib/")
    assert pylib["notify"] == "Session tools | Compile Python packages"
    handler = load(ROLE / "handlers" / "main.yml")[0]
    assert handler["name"] == pylib["notify"]
    assert handler["ansible.builtin.command"]["argv"][:3] == ["python3", "-m", "compileall"]


def test_defaults() -> None:
    d = load(ROLE / "defaults" / "main.yml")
    assert d["session_tools_bin_dir"] == "/usr/local/bin"
    assert d["session_tools_log_mode"] == "2750"
    assert d["session_tools_log_group"] == "adm"
    # hwclock (4.15), rfkill, sfdisk + ntfs-3g (3A.3), whiptail prompts, the login terminal.
    for pkg in ("util-linux-extra", "rfkill", "fdisk", "ntfs-3g", "whiptail", "gnome-terminal"):
        assert pkg in d["session_tools_packages"]
    cfg = d["session_tools_config"]
    assert set(cfg) >= {"image_max_age_days", "nsrl_path", "output_dir", "cases_dir", "mount_base"}


def test_parse_user_is_a_nologin_system_user() -> None:
    tasks = load(ROLE / "tasks" / "parse_user.yml")
    group = next(t["ansible.builtin.group"] for t in tasks if "ansible.builtin.group" in t)
    assert group["name"] == "{{ airlock_parse_user }}" and group["system"] is True
    task = next(t["ansible.builtin.user"] for t in tasks if "ansible.builtin.user" in t)
    assert task["name"] == "{{ airlock_parse_user }}"
    assert task["group"] == "{{ airlock_parse_user }}"  # OUTPUT is writable by this group
    assert task["system"] is True
    assert task["shell"] == "/usr/sbin/nologin"
    assert task["create_home"] is False
    assert task["password"] == "!"  # noqa: S105 -- the locked-password marker, not a secret


DESKTOP = ["airlock-session-start.desktop", "airlock-forensic-analyze.desktop"]


@pytest.mark.parametrize("name", DESKTOP)
def test_desktop_files(name: str) -> None:
    path = ROLE / "files" / "desktop" / name
    text = path.read_text(encoding="utf-8")
    assert text.startswith("[Desktop Entry]\n")
    assert "sudo /usr/local/bin/" in text
    if shutil.which("desktop-file-validate"):
        res = subprocess.run(
            ["desktop-file-validate", str(path)], capture_output=True, text=True, check=False
        )
        assert res.returncode == 0, res.stdout + res.stderr
    if name == "airlock-session-start.desktop":
        assert "forensic-session-start --pause-at-end" in text


def test_goss_file_covers_every_session_command() -> None:
    goss = load(REPO / "tests" / "goss" / "session_tools.yaml")
    for cmd in (
        "forensic-session-start",
        "evidence-unlock-output",
        "evidence-mount",
        "evidence-hash",
        "evidence-triage",
    ):
        entry = goss["file"][f"/usr/local/bin/{cmd}"]
        assert entry["mode"] == "0755"
    assert goss["user"]["airlock-parse"]["shell"] == "/usr/sbin/nologin"
    assert goss["file"]["/var/log/forensic-session"]["mode"] == "2750"
    assert "no-network-toggle" in goss["command"]
