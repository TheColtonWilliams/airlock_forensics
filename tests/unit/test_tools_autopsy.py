"""Task 4.9: the optional Autopsy role.

Java 17 (the version Autopsy 4.23.1's Running_Linux_OSX.md names) is installed at image time;
the Autopsy zip and the Sleuth Kit Java package come from ASSETS, are checked against their
pins before anything is installed, and only when the profile staged the autopsy feature.
"""

from __future__ import annotations

from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[2]
ROLE = REPO / "ansible" / "roles" / "tools_autopsy"
PINS = yaml.safe_load((REPO / "ansible" / "group_vars" / "all" / "pins.yml").read_text())["pins"]
DEFAULTS = yaml.safe_load((ROLE / "defaults" / "main.yml").read_text())


def tasks(name: str) -> list[dict]:
    return yaml.safe_load((ROLE / "tasks" / name).read_text())


def test_java_17_and_the_libraries_are_image_packages() -> None:
    assert DEFAULTS["tools_autopsy_java_home"].endswith("java-17-openjdk-amd64")
    pkgs = DEFAULTS["tools_autopsy_packages"]
    assert "openjdk-17-jre" in pkgs
    assert "testdisk" in pkgs  # unix_setup.sh refuses to run without PhotoRec
    for dev in ("libewf-dev", "libafflib-dev", "libvhdi-dev", "libvmdk-dev", "libc3p0-java"):
        assert dev in pkgs  # Depends of the sleuthkit-java .deb


def test_pins_are_assets_for_the_autopsy_feature() -> None:
    zip_pin = PINS[DEFAULTS["tools_autopsy_zip_pin"]]
    tsk_pin = PINS[DEFAULTS["tools_autopsy_tsk_java_pin"]]
    for pin in (zip_pin, tsk_pin):
        assert pin["stage"] == "assets"
        assert pin["profiles"] == ["autopsy"]
    assert len(zip_pin["sha256"]) == 64
    assert zip_pin["target"].endswith(f"autopsy-{zip_pin['version']}.zip")
    # unix_setup.sh in the zip asks for sleuthkit-<TSK_VERSION>.jar.
    assert tsk_pin["version"].startswith(DEFAULTS["tools_autopsy_tsk_version"])


def test_staged_files_are_checked_before_install_and_gated() -> None:
    for name in ("sleuthkit_java.yml", "autopsy.yml"):
        steps = tasks(name)
        names = [t["name"] for t in steps]
        check = next(i for i, n in enumerate(names) if "unchanged" in n)
        install = next(i for i, n in enumerate(names) if "Install" in n or "Unpack" in n)
        assert check < install, name
        for t in steps:
            assert "airlock_phase == 'provision'" in t["when"], (name, t["name"])
            assert any("autopsy" in str(c) for c in t["when"]), (name, t["name"])


def test_unix_setup_gets_java_17() -> None:
    setup = next(t for t in tasks("autopsy.yml") if "unix_setup" in t["name"])
    argv = setup["ansible.builtin.command"]["argv"]
    assert argv[1].endswith("/unix_setup.sh")
    assert argv[2:] == ["-j", "{{ tools_autopsy_java_home }}"]
    assert setup["environment"]["JAVA_HOME"] == "{{ tools_autopsy_java_home }}"


def test_role_is_off_by_default() -> None:
    main = yaml.safe_load((REPO / "ansible" / "group_vars" / "all" / "main.yml").read_text())
    assert main["install_autopsy"] is False
    site = yaml.safe_load((REPO / "ansible" / "site.yml").read_text())
    entry = next(
        e
        for p in site
        for e in p["roles"]
        if isinstance(e, dict) and e.get("role") == "tools_autopsy"
    )
    assert entry["when"] == "install_autopsy | bool"
