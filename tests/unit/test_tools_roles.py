"""Tasks 4.1 to 4.9 and 6.5: shape of the forensic tool roles, and their goss coverage (4.13).

* each role's tasks/main.yml only imports task files, one control per file, and every task
  file names its test in its first comment;
* every module is called by its fully qualified name;
* every Ubuntu package a role installs exists in Ubuntu 24.04 (noble), as checked on
  2026-11-15 (and again with apt-cache when it runs on noble), and the packages noble does not
  have are not asked for;
* tests/goss/tools.yaml checks every package, command link and pinned version the roles set up.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest
import yaml

REPO = Path(__file__).resolve().parents[2]
ROLES = REPO / "ansible" / "roles"
TOOL_ROLES = (
    "tools_acquire",
    "tools_filesystem",
    "tools_dissect",
    "tools_eztools",
    "tools_timeline",
    "tools_carve",
    "tools_media",
    "tools_registry",
    "tools_autopsy",
    "tools_sift",
)
PINS = yaml.safe_load((REPO / "ansible" / "group_vars" / "all" / "pins.yml").read_text())["pins"]
GOSS = yaml.safe_load((REPO / "tests" / "goss" / "tools.yaml").read_text())
GOSS_TEXT = (REPO / "tests" / "goss" / "tools.yaml").read_text()

# Ubuntu 24.04 (noble) archive, checked with apt-cache policy on 2026-11-15.
NOBLE_HAS = {
    "afflib-tools",
    "build-essential",
    "dc3dd",
    "exiv2",
    "ewf-tools",
    "ffmpeg",
    "flex",
    "foremost",
    "gddrescue",
    "gstreamer1.0-gtk3",
    "gstreamer1.0-libav",
    "gstreamer1.0-plugins-base",
    "gstreamer1.0-plugins-good",
    "guymager",
    "hashdeep",
    "libafflib-dev",
    "libc3p0-java",
    "libde265-0",
    "libewf-dev",
    "libewf2",
    "libexpat1",
    "libexpat1-dev",
    "libfsntfs-utils",
    "libgstreamer1.0-0",
    "libheif1",
    "libhivex-bin",
    "libimage-exiftool-perl",
    "libncurses-dev",
    "libpq5",
    "libregf-utils",
    "libsqlite3-dev",
    "libssl-dev",
    "libssl3t64",
    "libtinfo6",
    "libvhdi-dev",
    "libvmdk-dev",
    "libvshadow-utils",
    "mediainfo",
    "ntfs-3g",
    "openjdk-17-jre",
    "pkg-config",
    "python3-libfsntfs",
    "python3-venv",
    "regripper",
    "scalpel",
    "sleuthkit",
    "ssdeep",
    "testdisk",
    "unzip",
    "vinetto",
    "zlib1g",
    "zlib1g-dev",
}
# Named by the plan but not in noble: each is replaced as the decision log (2026-11-15) says.
NOBLE_MISSING = {
    "bulk-extractor",
    "python3-dissect.thumbcache",
    "dotnet-runtime-9.0",
    "python3-pyfsntfs",
}


def role_yaml(role: str, *parts: str) -> Any:
    return yaml.safe_load((ROLES / role / Path(*parts)).read_text())


def task_files(role: str) -> list[Path]:
    return sorted((ROLES / role / "tasks").glob("*.yml"))


def all_tasks(role: str) -> list[dict[str, Any]]:
    out = []
    for f in task_files(role):
        out.extend(yaml.safe_load(f.read_text()) or [])
    return out


def package_lists(role: str) -> dict[str, list[str]]:
    defaults = role_yaml(role, "defaults", "main.yml") or {}
    return {k: v for k, v in defaults.items() if k.endswith("_packages") and isinstance(v, list)}


@pytest.mark.parametrize("role", TOOL_ROLES)
def test_main_only_imports_one_file_per_control(role: str) -> None:
    main = role_yaml(role, "tasks", "main.yml")
    imported = []
    for task in main:
        keys = set(task) - {"name"}
        assert keys == {"ansible.builtin.import_tasks"}, (role, task)
        imported.append(task["ansible.builtin.import_tasks"])
    others = {f.name for f in task_files(role)} - {"main.yml"}
    assert set(imported) == others, f"{role}: imported {imported}, files {sorted(others)}"
    assert len(imported) == len(set(imported))


@pytest.mark.parametrize("role", TOOL_ROLES)
def test_each_control_names_its_test(role: str) -> None:
    for f in task_files(role):
        if f.name == "main.yml":
            continue
        head = []
        for line in f.read_text().splitlines():
            if not line.startswith("#"):
                break
            head.append(line)
        text = "\n".join(head)
        assert re.search(r"^# Control \d", text, re.M), f"{f}: first comment names no control"
        tests = re.findall(r"(tests/[\w./-]+\.(?:ya?ml|py|sh))", text)
        assert "Test:" in text and tests, f"{f}: names no test"
        for t in tests:
            assert (REPO / t).is_file(), f"{f}: names {t}, which does not exist"


@pytest.mark.parametrize("role", TOOL_ROLES)
def test_modules_are_fully_qualified(role: str) -> None:
    allowed = {
        "name",
        "when",
        "loop",
        "loop_control",
        "register",
        "vars",
        "changed_when",
        "environment",
        "tags",
        "become",
        "notify",
        "failed_when",
        "no_log",
    }
    for task in all_tasks(role):
        modules = set(task) - allowed
        assert len(modules) == 1, (role, task.get("name"), modules)
        assert next(iter(modules)).startswith("ansible."), (role, task.get("name"), modules)


@pytest.mark.parametrize("role", TOOL_ROLES)
def test_packages_exist_in_noble(role: str) -> None:
    for key, pkgs in package_lists(role).items():
        for pkg in pkgs:
            assert pkg not in NOBLE_MISSING, f"{role}.{key}: {pkg} is not in noble"
            assert pkg in NOBLE_HAS, f"{role}.{key}: {pkg} was not checked against noble"


def test_packages_resolve_with_apt_cache_on_noble() -> None:
    os_release = Path("/etc/os-release")
    if not shutil.which("apt-cache") or "VERSION_CODENAME=noble" not in (
        os_release.read_text() if os_release.exists() else ""
    ):
        pytest.skip("needs apt-cache on Ubuntu 24.04")
    pkgs = sorted({p for r in TOOL_ROLES for v in package_lists(r).values() for p in v})
    out = subprocess.run(
        ["apt-cache", "policy", *pkgs], capture_output=True, text=True, check=False
    ).stdout
    if "Candidate:" not in out:
        pytest.skip("apt lists are empty here (run apt-get update)")
    missing = [
        p
        for p in pkgs
        if not re.search(rf"^{re.escape(p)}:\n(?:  .*\n)*?  Candidate: (?!\(none\))", out, re.M)
    ]
    assert not missing, f"not in this host's apt sources: {missing}"


def test_goss_checks_every_tool_package() -> None:
    goss_pkgs = set(GOSS["package"])
    skip = {"tools_autopsy", "tools_sift"}  # optional roles: checked conditionally
    for role in TOOL_ROLES:
        if role in skip:
            continue
        for key, pkgs in package_lists(role).items():
            if "build" in key or "runtime" in key:
                continue  # build tools and libraries, not tools an analyst runs
            for pkg in pkgs:
                assert pkg in goss_pkgs, f"tests/goss/tools.yaml has no check for {pkg} ({role})"


def test_goss_checks_every_linked_command() -> None:
    links = (
        role_yaml("tools_dissect", "defaults", "main.yml")["tools_dissect_commands"]
        + role_yaml("tools_timeline", "defaults", "main.yml")["tools_timeline_commands"][:4]
        + role_yaml("tools_media", "defaults", "main.yml")["tools_media_thumbcache_commands"][:1]
        + ["usncarve", "bulk_extractor", "rip.pl"]
    )
    for cmd in links:
        assert re.search(rf"(?<![\w-]){re.escape(cmd)}(?![\w-])", GOSS_TEXT), cmd


def test_goss_versions_match_the_pins() -> None:
    assert f"dissect {PINS['dissect_pypi']['version']}" in GOSS_TEXT
    assert f"dissect=={PINS['dissect_pypi']['version']}" in GOSS_TEXT
    assert f"log2timeline version {PINS['plaso_pypi']['version']}" in GOSS_TEXT
    be = PINS["bulk_extractor_source"]
    assert f"bulk_extractor {be['version']}" in GOSS_TEXT
    assert f"{re.escape(be['version'])} sha256:{be['sha256']}" in GOSS_TEXT
    assert "Microsoft\\.NETCore\\.App 9\\." in GOSS_TEXT
    assert "target-query --version" in GOSS_TEXT


def test_ntfs3g_write_tools_are_diverted_and_checked() -> None:
    d = role_yaml("tools_filesystem", "defaults", "main.yml")
    tools = [Path(t).name for t in d["tools_filesystem_ntfs3g_write_tools"]]
    for must in (
        "ntfsfix",
        "mkntfs",
        "mkfs.ntfs",
        "ntfswipe",
        "ntfsresize",
        "ntfslabel",
        "ntfsclone",
        "ntfscp",
        "ntfsrecover",
    ):
        assert must in tools
    assert "ntfsinfo" not in tools and "ntfs-3g" not in tools  # info tool and the ro driver stay
    check = GOSS["command"]["filesystem-ntfs3g"]
    for t in tools:
        assert re.search(rf"(?<![\w.-]){re.escape(t)}(?![\w.-])", check["exec"]), t
    assert f"diverted={len(tools)}" in check["stdout"]


def test_exiftool_minimum_version_is_enforced() -> None:
    d = role_yaml("tools_media", "defaults", "main.yml")
    assert d["tools_media_exiftool_min_version"] == "12.24"
    text = (ROLES / "tools_media" / "tasks" / "exiftool.yml").read_text()
    assert "is version(tools_media_exiftool_min_version, '>=')" in text
    assert "p[2] >= 24" in GOSS_TEXT


def test_site_runs_every_tool_role() -> None:
    site = yaml.safe_load((REPO / "ansible" / "site.yml").read_text())
    roles = [r["role"] if isinstance(r, dict) else r for play in site for r in play["roles"]]
    for role in TOOL_ROLES:
        assert role in roles, role


def test_venv_roles_install_only_at_image_phase_with_hashes() -> None:
    for role, venv_file in (
        ("tools_dissect", "venv.yml"),
        ("tools_timeline", "plaso_venv.yml"),
        ("tools_carve", "usncarve.yml"),
    ):
        for task in yaml.safe_load((ROLES / role / "tasks" / venv_file).read_text()):
            argv = task.get("ansible.builtin.command", {}).get("argv")
            if isinstance(argv, str) and "_pip" in argv:
                assert "airlock_phase == 'image'" in task["when"], (role, task["name"])
        pip = next(
            v for k, v in role_yaml(role, "defaults", "main.yml").items() if k.endswith("_pip")
        )
        assert "--require-hashes" in pip and "--no-deps" in pip, role


def test_windows_drive_runbook_uses_only_installed_commands() -> None:
    """Task 4.12: every command the runbook tells the examiner to run is set up by a role."""
    doc = (REPO / "docs" / "workflows" / "windows-external-drive.md").read_text()
    blocks = re.findall(r"^```\n(.*?)^```", doc, re.M | re.S)
    assert blocks, "the runbook has no command blocks"
    session_bin = {p.name for p in (ROLES / "session_tools" / "files" / "bin").iterdir()}
    shell = {"mkdir", "sudo", "grep", "find", "lsblk", "blockdev", "umount"}
    ez = {
        t["name"] for t in role_yaml("tools_eztools", "defaults", "main.yml")["tools_eztools_tools"]
    }
    first_words = set()
    for block in blocks:
        for raw in block.splitlines():
            line = raw.strip()
            if not line or line.startswith(("#", "-")) or "=" in line.split()[0]:
                continue
            words = line.split()
            word = words[1] if words[0] == "sudo" else words[0]
            first_words.add(word.split("&&")[0])
    unknown = sorted(
        w
        for w in first_words
        if w not in shell
        and w not in session_bin
        and w not in ez
        and not re.search(rf"(?<![\w.-]){re.escape(w)}(?![\w-])", GOSS_TEXT)
    )
    assert not unknown, f"runbook commands with no goss check or helper: {unknown}"
    for word in ("fls", "icat", "MFTECmd", "target-query", "exiftool", "log2timeline", "RBCmd"):
        assert word in first_words, f"runbook does not use {word}"
