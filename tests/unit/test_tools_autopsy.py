"""Task 4.9: the optional Autopsy role.

Java 17 (the version Autopsy 4.23.1's Running_Linux_OSX.md names) is installed at image time;
the Autopsy zip and the Sleuth Kit Java package come from ASSETS, are checked against their
pins before anything is installed, and only when the profile staged the autopsy feature.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

import jinja2
import pytest
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


# ------------------------------------------------------------------ offline: Java 17 (finding 2)


def test_role_never_asks_apt_for_java_or_libraries() -> None:
    """Provisioning is offline: Java 17 and the libraries are baked by base, only checked here."""
    for path in (ROLE / "tasks").glob("*.yml"):
        for t in yaml.safe_load(path.read_text()):
            apt = t.get("ansible.builtin.apt")
            if apt is not None:
                assert set(apt) == {"deb", "state"}, (path.name, t["name"])  # local .deb only
                assert apt["deb"].startswith("{{ airlock_assets_files }}/"), t["name"]
    java = tasks("java.yml")
    assert [next(k for k in t if k.startswith("ansible.builtin.")) for t in java] == [
        "ansible.builtin.command",
        "ansible.builtin.assert",
    ]
    assert java[0]["ansible.builtin.command"]["argv"].startswith("{{ tools_autopsy_dpkg_query")
    assert "tools_autopsy_packages" in java[1]["vars"]["tools_autopsy_missing"]


def test_base_bakes_the_same_autopsy_packages_into_every_image() -> None:
    base = yaml.safe_load(
        (REPO / "ansible" / "roles" / "base" / "tasks" / "packages.yml").read_text()
    )
    task = next(t for t in base if "Autopsy" in t["name"])
    assert task["when"] == "airlock_phase == 'image'"
    assert task["vars"]["base_autopsy_prerequisites"] == DEFAULTS["tools_autopsy_packages"]
    assert task["ansible.builtin.apt"]["name"] == "{{ base_autopsy_prerequisites }}"


# ------------------------------------------------------------------ profile.json (finding 11)


def test_role_never_reads_profile_json() -> None:
    """Only forensic-provision's schema-checked features turn Autopsy on, never profile.json."""
    for path in (ROLE / "tasks").glob("*.yml"):
        text = path.read_text()
        assert "ansible.builtin.slurp" not in text, path.name
        assert "from_json" not in text, path.name
    fact = tasks("profile_features.yml")[0]["ansible.builtin.set_fact"]["tools_autopsy_staged"]
    assert "is sameas true" in fact["autopsy"]


# ------------------------------------------------------------------ search server (finding 3)


def _render(name: str, **extra: object) -> str:
    env = jinja2.Environment(undefined=jinja2.StrictUndefined, autoescape=False)  # noqa: S701
    env.filters["quote"] = shlex.quote
    ctx: dict[str, object] = {**DEFAULTS, "pins": PINS, **extra}
    for _ in range(3):  # defaults refer to each other
        ctx = {
            k: env.from_string(v).render(**ctx) if isinstance(v, str) and "{{" in v else v
            for k, v in ctx.items()
        }
    return env.from_string((ROLE / "templates" / name).read_text()).render(**ctx)


def test_launcher_binds_the_search_server_to_loopback(tmp_path: Path) -> None:
    prefix = tmp_path / "autopsy"
    (prefix / "bin").mkdir(parents=True)
    fake = prefix / "bin" / "autopsy"
    fake.write_text(
        '#!/usr/bin/env bash\necho "host=$SOLR_JETTY_HOST jmx=$ENABLE_REMOTE_JMX_OPTS $*"\n'
    )
    fake.chmod(0o755)
    launcher = tmp_path / "launcher.sh"
    launcher.write_text(_render("autopsy.sh.j2", tools_autopsy_prefix=str(prefix)))
    env = {**os.environ, "SOLR_JETTY_HOST": "0.0.0.0"}  # noqa: S104 - the launcher overrides it
    out = subprocess.run(["bash", str(launcher)], capture_output=True, text=True, env=env,
                         check=True).stdout  # fmt: skip
    assert out.strip() == "host=127.0.0.1 jmx=false --nosplash"


def test_solr_settings_block_wins_over_the_zip_settings(tmp_path: Path) -> None:
    """The block appended to autopsy-solr.in.sh overrides anything set above it."""
    include = tmp_path / "autopsy-solr.in.sh"
    block = jinja2.Template(DEFAULTS["tools_autopsy_solr_bind"]).render(
        tools_autopsy_solr_host=DEFAULTS["tools_autopsy_solr_host"]
    )
    include.write_text('SOLR_JETTY_HOST="0.0.0.0"\nSOLR_OPTS="$SOLR_OPTS -Xss256k"\n' + block)
    script = f'source {shlex.quote(str(include))}; echo "$SOLR_JETTY_HOST|$SOLR_OPTS"'
    out = subprocess.run(["bash", "-c", script], capture_output=True, text=True, check=True)
    host, opts = out.stdout.strip().split("|")
    assert host == "127.0.0.1"
    assert opts.split()[-1] == "-Djetty.host=127.0.0.1"
    assert DEFAULTS["tools_autopsy_solr_include_names"][0] == "autopsy-solr.in.sh"


def _fake_zip(tmp_path: Path, *, with_include: bool) -> Path:
    version = PINS[DEFAULTS["tools_autopsy_zip_pin"]]["version"]
    top = f"autopsy-{version}"
    path = tmp_path / "assets" / "files" / "autopsy.zip"
    path.parent.mkdir(parents=True)
    with zipfile.ZipFile(path, "w") as z:
        z.writestr(f"{top}/unix_setup.sh", "#!/bin/bash\nmkdir -p autopsy/modules/ext\n")
        z.writestr(f"{top}/bin/autopsy", "#!/bin/bash\n")
        if with_include:
            z.writestr(f"{top}/autopsy/solr/bin/autopsy-solr.in.sh", 'SOLR_JAVA_MEM="-Xmx2g"\n')
    return path


def _play_autopsy(tmp_path: Path, zip_path: Path) -> subprocess.CompletedProcess[str]:
    pins = dict(PINS)
    pins[DEFAULTS["tools_autopsy_zip_pin"]] = {
        **PINS[DEFAULTS["tools_autopsy_zip_pin"]],
        "sha256": hashlib.sha256(zip_path.read_bytes()).hexdigest(),
        "target": zip_path.name,
    }
    data = {
        "airlock_phase": "provision",
        "airlock_assets_files": str(zip_path.parent),
        "tools_autopsy_install_root": str(tmp_path / "opt"),
        "tools_autopsy_staged": {"autopsy": True},
        "pins": pins,
    }
    (tmp_path / "opt").mkdir(exist_ok=True)
    (tmp_path / "vars.json").write_text(json.dumps(data), encoding="utf-8")
    play = tmp_path / "play.yml"
    play.write_text(
        "- name: Autopsy zip steps into a temporary folder\n"
        "  hosts: localhost\n  connection: local\n  gather_facts: false\n  become: false\n"
        "  tasks:\n    - name: Run autopsy.yml\n      ansible.builtin.include_role:\n"
        "        name: tools_autopsy\n        tasks_from: autopsy.yml\n",
        encoding="utf-8",
    )
    env = {
        **os.environ,
        "ANSIBLE_ROLES_PATH": str(REPO / "ansible" / "roles"),
        "ANSIBLE_NOCOLOR": "1",
        "ANSIBLE_RETRY_FILES_ENABLED": "0",
        "ANSIBLE_LOCALHOST_WARNING": "0",
        "ANSIBLE_INVENTORY_UNPARSED_WARNING": "0",
        "ANSIBLE_PYTHON_INTERPRETER": sys.executable,
    }
    return subprocess.run(
        ["ansible-playbook", "-i", "localhost,", str(play), "-e", f"@{tmp_path / 'vars.json'}"],
        capture_output=True, text=True, env=env, check=False, timeout=600,
    )  # fmt: skip


needs_ansible = pytest.mark.skipif(
    shutil.which("ansible-playbook") is None or shutil.which("unzip") is None or os.geteuid(),
    reason="needs ansible-playbook, unzip and root (files are installed owned by root)",
)


@needs_ansible
def test_role_binds_solr_to_loopback_in_the_unpacked_zip(tmp_path: Path) -> None:
    res = _play_autopsy(tmp_path, _fake_zip(tmp_path, with_include=True))
    assert res.returncode == 0, res.stdout[-3000:] + res.stderr[-2000:]
    include = next((tmp_path / "opt").glob("autopsy-*/autopsy/solr/bin/autopsy-solr.in.sh"))
    text = include.read_text()
    assert 'SOLR_JETTY_HOST="127.0.0.1"' in text
    assert "-Djetty.host=127.0.0.1" in text
    again = _play_autopsy(tmp_path, tmp_path / "assets" / "files" / "autopsy.zip")
    assert again.returncode == 0, again.stdout[-3000:]
    assert re.search(r"localhost\s*:\s*ok=\d+\s+changed=0", again.stdout), again.stdout[-2000:]
    assert include.read_text() == text


@needs_ansible
def test_role_stops_when_the_solr_settings_file_is_missing(tmp_path: Path) -> None:
    res = _play_autopsy(tmp_path, _fake_zip(tmp_path, with_include=False))
    assert res.returncode != 0
    assert "autopsy-solr.in.sh was not found" in res.stdout


def _play_java(tmp_path: Path, packages: list[str]) -> subprocess.CompletedProcess[str]:
    play = tmp_path / "java.yml"
    play.write_text(
        "- name: Autopsy prerequisite check\n"
        "  hosts: localhost\n  connection: local\n  gather_facts: false\n  become: false\n"
        "  tasks:\n    - name: Run java.yml\n      ansible.builtin.include_role:\n"
        "        name: tools_autopsy\n        tasks_from: java.yml\n",
        encoding="utf-8",
    )
    (tmp_path / "java.json").write_text(json.dumps({"tools_autopsy_packages": packages}))
    env = {
        **os.environ,
        "ANSIBLE_ROLES_PATH": str(REPO / "ansible" / "roles"),
        "ANSIBLE_NOCOLOR": "1",
        "ANSIBLE_LOCALHOST_WARNING": "0",
        "ANSIBLE_INVENTORY_UNPARSED_WARNING": "0",
        "ANSIBLE_PYTHON_INTERPRETER": sys.executable,
    }
    return subprocess.run(
        ["ansible-playbook", "-i", "localhost,", str(play), "-e", f"@{tmp_path / 'java.json'}"],
        capture_output=True, text=True, env=env, check=False, timeout=600,
    )  # fmt: skip


@pytest.mark.skipif(
    shutil.which("ansible-playbook") is None or shutil.which("dpkg-query") is None,
    reason="needs ansible-playbook and dpkg-query",
)
def test_java_check_passes_offline_and_names_what_is_missing(tmp_path: Path) -> None:
    ok = _play_java(tmp_path, ["bash", "coreutils"])
    assert ok.returncode == 0, ok.stdout[-3000:]
    bad = _play_java(tmp_path, ["bash", "no-such-package-for-autopsy"])
    assert bad.returncode != 0
    assert "This image has no no-such-package-for-autopsy" in bad.stdout
