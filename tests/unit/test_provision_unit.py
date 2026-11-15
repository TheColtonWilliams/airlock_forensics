"""The airlock-provision boot unit and its install task (tasks 2B.4, 2B.7)."""

from __future__ import annotations

import configparser
from pathlib import Path

import yaml

ROLE = Path(__file__).resolve().parents[2] / "ansible" / "roles" / "session_tools"


def unit() -> configparser.ConfigParser:
    cp = configparser.ConfigParser(strict=False, interpolation=None)
    cp.optionxform = str  # type: ignore[assignment,method-assign]
    cp.read(ROLE / "files" / "systemd" / "airlock-provision.service", encoding="utf-8")
    return cp


def test_unit_runs_if_changed_before_the_desktop() -> None:
    cp = unit()
    assert cp["Service"]["ExecStart"] == "/usr/local/bin/forensic-provision --if-changed"
    assert cp["Service"]["Type"] == "oneshot"
    assert "display-manager.service" in cp["Unit"]["Before"]
    after = cp["Unit"]["After"]
    for dep in ("airlock-firstboot.service", "srv-airlock-assets.mount", "local-fs.target"):
        assert dep in after
    assert cp["Unit"]["ConditionKernelCommandLine"] == "!airlock.noprovision"
    assert cp["Install"]["WantedBy"] == "multi-user.target"


def test_unit_never_waits_for_a_network() -> None:
    text = (ROLE / "files" / "systemd" / "airlock-provision.service").read_text(encoding="utf-8")
    assert "network" not in text.lower().replace("never uses a network", "")


def test_task_file_installs_and_enables_the_unit() -> None:
    tasks = yaml.safe_load((ROLE / "tasks" / "provision_unit.yml").read_text(encoding="utf-8"))
    copy = next(t for t in tasks if "ansible.builtin.copy" in t)
    assert copy["ansible.builtin.copy"]["src"] == "systemd/airlock-provision.service"
    assert copy["ansible.builtin.copy"]["dest"] == "/etc/systemd/system/airlock-provision.service"
    enable = next(t for t in tasks if "ansible.builtin.systemd_service" in t)
    assert enable["ansible.builtin.systemd_service"]["enabled"] is True
    assert (ROLE / "files" / "bin" / "forensic-provision").stat().st_mode & 0o111
    assert (ROLE / "files" / "bin" / "forensic-import").stat().st_mode & 0o111
