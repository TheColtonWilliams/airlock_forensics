"""Task 4.4: the tools_eztools role.

Static checks: the .NET 9 runtime comes from pinned Microsoft .deb files (no apt source left on
the image), every EZ tool the plan names has a stage=assets pin, and each zip is checked against
its pin before it is unpacked.

Run checks (need ansible-playbook and unzip, no root): the role runs at the provision phase
against a fake ASSETS folder, with a stand-in ``dotnet`` and a stand-in tool zip. A zip whose
hash matches is unpacked and gets a wrapper that runs ``dotnet <Tool>.dll``; a zip that does
not match stops the role; without the eztools feature nothing is installed.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import zipfile
from pathlib import Path
from typing import Any

import pytest
import yaml

REPO = Path(__file__).resolve().parents[2]
ROLE = REPO / "ansible" / "roles" / "tools_eztools"
PINS = yaml.safe_load((REPO / "ansible" / "group_vars" / "all" / "pins.yml").read_text())["pins"]
DEFAULTS = yaml.safe_load((ROLE / "defaults" / "main.yml").read_text())
PLAN_TOOLS = {
    "MFTECmd",
    "RBCmd",
    "LECmd",
    "JLECmd",
    "PECmd",
    "EvtxECmd",
    "AmcacheParser",
    "AppCompatCacheParser",
    "RECmd",
    "SBECmd",
    "bstrings",
}


def tasks(name: str) -> list[dict[str, Any]]:
    return yaml.safe_load((ROLE / "tasks" / name).read_text())


def test_every_plan_tool_has_an_assets_pin() -> None:
    tools = {t["name"]: t["pin"] for t in DEFAULTS["tools_eztools_tools"]}
    assert set(tools) == PLAN_TOOLS
    for name, pin_id in tools.items():
        pin = PINS[pin_id]
        assert pin["stage"] == "assets", pin_id
        assert pin["target"] == f"eztools/{name}.zip", pin_id
        assert "eztools" in pin["profiles"], pin_id
        assert pin["url"] == f"https://download.ericzimmermanstools.com/net9/{name}.zip"


def test_dotnet_runtime_is_pinned_debs_without_an_apt_source() -> None:
    pins = DEFAULTS["tools_eztools_dotnet_pins"]
    names = {PINS[p]["url"].rsplit("/", 1)[-1].split("_")[0] for p in pins}
    assert names == {
        "dotnet-host",
        "dotnet-hostfxr-9.0",
        "dotnet-runtime-deps-9.0",
        "dotnet-runtime-9.0",
    }
    for p in pins:
        assert PINS[p]["stage"] == "image"
        assert len(PINS[p]["sha256"] or "") == 64, p
        assert PINS[p]["url"].startswith("https://packages.microsoft.com/")
    text = (ROLE / "tasks" / "dotnet_runtime.yml").read_text()
    assert "apt_repository" not in text and "deb822_repository" not in text
    assert 'checksum: "sha256:{{ pins[item].sha256 }}"' in text
    assert len(DEFAULTS["tools_eztools_ms_key_fingerprint"]) == 40


def test_zip_is_checked_before_it_is_unpacked() -> None:
    names = [t["name"] for t in tasks("unpack.yml")]
    check = next(i for i, n in enumerate(names) if "unchanged" in n)
    unpack = next(i for i, n in enumerate(names) if "Unpack" in n)
    assert check < unpack
    for task in tasks("unpack.yml"):
        assert "airlock_phase == 'provision'" in task["when"], task["name"]


def test_wrapper_template_runs_dotnet_on_the_dll(tmp_path: Path) -> None:
    jinja2 = pytest.importorskip("jinja2")
    env = jinja2.Environment(undefined=jinja2.StrictUndefined, keep_trailing_newline=True)
    env.filters["quote"] = lambda s: "'" + str(s).replace("'", "'\"'\"'") + "'"
    text = env.from_string((ROLE / "templates" / "eztool-wrapper.sh.j2").read_text()).render(
        tools_eztools_tool={"name": "MFTECmd", "pin": "eztools_mftecmd"},
        tools_eztools_dotnet_major="9",
        tools_eztools_dotnet_bin=str(tmp_path / "dotnet"),
        tools_eztools_dll="/opt/eztools/MFTECmd/MFTECmd.dll",
        pins=PINS,
    )
    stub = tmp_path / "dotnet"
    stub.write_text("#!/bin/sh\nprintf '%s\\n' \"$@\"\n")
    stub.chmod(0o755)
    wrapper = tmp_path / "MFTECmd"
    wrapper.write_text(text)
    wrapper.chmod(0o755)
    out = subprocess.run([str(wrapper), "-f", "a b"], capture_output=True, text=True, check=True)
    assert out.stdout.splitlines() == ["/opt/eztools/MFTECmd/MFTECmd.dll", "-f", "a b"]
    if shutil.which("shellcheck"):
        subprocess.run(["shellcheck", "-S", "style", str(wrapper)], check=True)


# ----------------------------------------------------------------------------- role runs
def _need_ansible() -> None:
    for tool in ("ansible-playbook", "unzip"):
        if not shutil.which(tool):
            pytest.skip(f"needs {tool}")


def _run_role(tmp: Path, *, sha: str, feature: bool) -> subprocess.CompletedProcess[str]:
    assets = tmp / "assets"
    prefix = tmp / "opt-eztools"
    bin_dir = tmp / "bin"
    bin_dir.mkdir(exist_ok=True)
    dotnet = tmp / "dotnet"
    dotnet.write_text("#!/bin/sh\necho 'Microsoft.NETCore.App 9.0.4 [/usr/share/dotnet]'\n")
    dotnet.chmod(0o755)
    pins = {
        "eztools_mftecmd": {**PINS["eztools_mftecmd"], "sha256": sha, "version": "test"},
    }
    extra = {
        "airlock_phase": "provision",
        "airlock_assets_mount": str(assets),
        "airlock_assets_files": str(assets / "files"),
        "airlock_profile_features": {"eztools": feature, "autopsy": False},
        "tools_eztools_prefix": str(prefix),
        "tools_eztools_bin_dir": str(bin_dir),
        "tools_eztools_dotnet_bin": str(dotnet),
        "tools_eztools_packages": [],
        "tools_eztools_tools": [{"name": "MFTECmd", "pin": "eztools_mftecmd"}],
        "pins": pins,
    }
    (tmp / "vars.json").write_text(json.dumps(extra))
    (tmp / "play.yml").write_text(
        "- hosts: localhost\n  connection: local\n  gather_facts: false\n"
        "  roles:\n    - role: tools_eztools\n"
    )
    env = {
        **os.environ,
        "ANSIBLE_ROLES_PATH": str(REPO / "ansible" / "roles"),
        "ANSIBLE_LOCALHOST_WARNING": "false",
        "ANSIBLE_INVENTORY_UNPARSED_WARNING": "false",
        "ANSIBLE_NOCOLOR": "1",
        "ANSIBLE_BECOME": "false",
    }
    return subprocess.run(
        [
            "ansible-playbook",
            "-i",
            "localhost,",
            "-e",
            f"@{tmp / 'vars.json'}",
            str(tmp / "play.yml"),
        ],
        capture_output=True,
        text=True,
        env=env,
        cwd=tmp,
        check=False,
        timeout=600,
    )


def _stage_zip(tmp: Path) -> str:
    """A stand-in tool zip with a nested folder, like some EZ Tools zips have."""
    target = tmp / "assets" / "files" / "eztools" / "MFTECmd.zip"
    target.parent.mkdir(parents=True)
    with zipfile.ZipFile(target, "w") as zf:
        zf.writestr("MFTECmd/MFTECmd.dll", b"not a real assembly")
        zf.writestr("MFTECmd/MFTECmd.runtimeconfig.json", "{}")
    return hashlib.sha256(target.read_bytes()).hexdigest()


def test_role_unpacks_a_matching_zip_and_writes_the_wrapper(tmp_path: Path) -> None:
    _need_ansible()
    sha = _stage_zip(tmp_path)
    res = _run_role(tmp_path, sha=sha, feature=True)
    assert res.returncode == 0, res.stdout[-3000:] + res.stderr[-2000:]
    dll = tmp_path / "opt-eztools" / "MFTECmd" / "MFTECmd" / "MFTECmd.dll"
    assert dll.is_file()
    assert (tmp_path / "opt-eztools" / "MFTECmd" / f".airlock-sha256-{sha}").is_file()
    assert (tmp_path / "opt-eztools" / "INSTALLED").read_text() == "MFTECmd\n"
    out = subprocess.run(
        [str(tmp_path / "bin" / "MFTECmd"), "--help"], capture_output=True, text=True, check=True
    )
    assert "Microsoft.NETCore.App 9" in out.stdout  # the stand-in dotnet ran
    wrapper = (tmp_path / "bin" / "MFTECmd").read_text()
    assert str(dll) in wrapper and sha in wrapper
    # Idempotent: a second run changes nothing.
    again = _run_role(tmp_path, sha=sha, feature=True)
    assert again.returncode == 0, again.stdout[-3000:]
    assert "changed=0" in again.stdout


def test_role_refuses_a_zip_that_does_not_match_its_pin(tmp_path: Path) -> None:
    _need_ansible()
    _stage_zip(tmp_path)
    res = _run_role(tmp_path, sha="0" * 64, feature=True)
    assert res.returncode != 0
    assert "does not match its pinned hash" in res.stdout
    assert not (tmp_path / "opt-eztools" / "MFTECmd").exists()
    assert not (tmp_path / "bin" / "MFTECmd").exists()


def test_role_installs_nothing_without_the_eztools_feature(tmp_path: Path) -> None:
    _need_ansible()
    sha = _stage_zip(tmp_path)
    res = _run_role(tmp_path, sha=sha, feature=False)
    assert res.returncode == 0, res.stdout[-3000:]
    assert not (tmp_path / "opt-eztools").exists()
    assert not (tmp_path / "bin" / "MFTECmd").exists()
