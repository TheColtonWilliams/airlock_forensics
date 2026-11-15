"""harden_services checks that run outside the image (tasks 5.3, 5.4).

The snapd pin and the apt periodic settings are fed to apt itself (apt-cache, apt-config) when
apt is installed, so the test proves apt reads them the intended way.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")

REPO_ROOT = Path(__file__).resolve().parents[2]
ROLE = REPO_ROOT / "ansible" / "roles" / "harden_services"
GROUP_VARS = REPO_ROOT / "ansible" / "group_vars" / "all" / "main.yml"


def _task_content(task_file: str, dest: str) -> str:
    tasks = yaml.safe_load((ROLE / "tasks" / task_file).read_text(encoding="utf-8"))
    for task in tasks:
        copy = task.get("ansible.builtin.copy") or {}
        if copy.get("dest") == dest:
            return copy["content"]
    raise AssertionError(f"no copy task for {dest} in {task_file}")


def test_snapd_policy_is_remove() -> None:
    """Decision 5.4 (2026-11-15): snapd is removed."""
    assert yaml.safe_load(GROUP_VARS.read_text(encoding="utf-8"))["snapd_policy"] == "remove"


def test_snapd_pin_text() -> None:
    pin = _task_content("snapd.yml", "/etc/apt/preferences.d/airlock-no-snapd.pref")
    stanza = [line for line in pin.splitlines() if line and not line.startswith("#")]
    assert stanza == ["Package: snapd", "Pin: release a=*", "Pin-Priority: -1"]


@pytest.mark.skipif(shutil.which("apt-cache") is None, reason="needs apt-cache")
def test_apt_has_no_candidate_for_snapd_with_the_pin(tmp_path: Path) -> None:
    base = subprocess.run(
        ["apt-cache", "policy", "snapd"], capture_output=True, text=True, check=False
    )
    if not re.search(r"Candidate: [0-9]", base.stdout):
        pytest.skip("this host's apt lists do not offer snapd, so the pin cannot be shown to work")
    parts = tmp_path / "preferences.d"
    parts.mkdir()
    pin = _task_content("snapd.yml", "/etc/apt/preferences.d/airlock-no-snapd.pref")
    (parts / "airlock-no-snapd.pref").write_text(pin, encoding="utf-8")
    res = subprocess.run(
        [
            "apt-cache",
            "-o",
            f"Dir::Etc::PreferencesParts={parts}",
            "-o",
            "Dir::Etc::Preferences=/dev/null",
            "policy",
            "snapd",
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    assert "Candidate: (none)" in res.stdout, res.stdout


@pytest.mark.skipif(shutil.which("apt-config") is None, reason="needs apt-config")
def test_apt_periodic_jobs_off(tmp_path: Path) -> None:
    conf = tmp_path / "99airlock-no-periodic"
    conf.write_text(
        _task_content("updates_off.yml", "/etc/apt/apt.conf.d/99airlock-no-periodic"),
        encoding="utf-8",
    )
    env = dict(os.environ, APT_CONFIG=str(conf))
    res = subprocess.run(
        ["apt-config", "-c", str(conf), "dump", "APT::Periodic"],
        capture_output=True,
        text=True,
        check=True,
        env=env,
    )
    values = dict(re.findall(r'^APT::Periodic::(\S+) "([^"]*)";', res.stdout, re.M))
    for key in (
        "Enable",
        "Update-Package-Lists",
        "Download-Upgradeable-Packages",
        "Unattended-Upgrade",
        "AutocleanInterval",
    ):
        assert values.get(key) == "0", (key, res.stdout)


def test_update_config_file_sorts_last() -> None:
    """apt reads apt.conf.d in name order; ours must win over 20auto-upgrades and 10periodic."""
    names = ["10periodic", "20auto-upgrades", "50unattended-upgrades", "99airlock-no-periodic"]
    assert sorted(names)[-1] == "99airlock-no-periodic"


def test_masked_units_are_real_unit_names() -> None:
    defaults = yaml.safe_load((ROLE / "defaults" / "main.yml").read_text(encoding="utf-8"))
    unit = re.compile(r"^[A-Za-z0-9:_.@-]+\.(service|socket|timer|path|target)$")
    for key, value in defaults.items():
        if key.endswith(("_masked_units", "_masked_user_units")):
            for name in value:
                assert unit.match(name), f"{key}: {name}"
    # ubuntu-report ships user units on 24.04, not system units.
    assert "ubuntu-report.service" in defaults["harden_services_telemetry_masked_user_units"]
