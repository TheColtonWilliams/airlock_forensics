"""dconf keyfiles and locks for harden_storage (3.1) and harden_desktop (5.1, 5.2).

When the dconf CLI is installed, the keyfiles are compiled with ``dconf compile`` and read back
through a profile shaped like the image's (a writable user database over the compiled system
database), so the values and the locks are checked as GNOME would see them.
"""

from __future__ import annotations

import configparser
import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")

REPO_ROOT = Path(__file__).resolve().parents[2]
ROLES = REPO_ROOT / "ansible" / "roles"
DCONF_DIRS = [
    ROLES / "harden_storage" / "files" / "dconf",
    ROLES / "harden_desktop" / "files" / "dconf",
]

EXPECTED = {
    "/org/gnome/desktop/media-handling/automount": "false",
    "/org/gnome/desktop/media-handling/automount-open": "false",
    "/org/gnome/desktop/media-handling/autorun-never": "true",
    "/org/gnome/nautilus/preferences/show-image-thumbnails": "'never'",
    "/org/gnome/desktop/thumbnailers/disable-all": "true",
    "/org/gnome/desktop/screensaver/lock-enabled": "false",
    "/org/gnome/desktop/lockdown/disable-lock-screen": "true",
    "/org/gnome/desktop/session/idle-delay": "uint32 0",
    "/org/gnome/desktop/screensaver/idle-activation-enabled": "false",
    "/org/gnome/desktop/screensaver/ubuntu-lock-on-suspend": "false",
    "/org/gnome/settings-daemon/plugins/power/sleep-inactive-ac-type": "'nothing'",
    "/org/gnome/settings-daemon/plugins/power/sleep-inactive-battery-type": "'nothing'",
    "/org/gnome/settings-daemon/plugins/power/idle-dim": "false",
    "/org/freedesktop/tracker/miner/files/index-recursive-directories": "@as []",
    "/org/freedesktop/tracker/miner/files/enable-monitors": "false",
    "/org/freedesktop/tracker/miner/files/crawling-interval": "-2",
}


def _keyfiles() -> list[Path]:
    return sorted(p for d in DCONF_DIRS for p in d.iterdir() if p.is_file())


def _lockfiles() -> list[Path]:
    return sorted(p for d in DCONF_DIRS for p in (d / "locks").iterdir() if p.is_file())


def _keys_in(path: Path) -> set[str]:
    parser = configparser.ConfigParser(interpolation=None)
    parser.optionxform = str  # type: ignore[assignment,method-assign]
    parser.read_string(path.read_text(encoding="utf-8"))
    return {f"/{section}/{key}" for section in parser.sections() for key in parser[section]}


def _locks_in(path: Path) -> set[str]:
    return {
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.startswith("#")
    }


def test_every_key_is_locked_and_every_lock_has_a_key() -> None:
    for keyfile in _keyfiles():
        lockfile = keyfile.parent / "locks" / keyfile.name
        assert lockfile.is_file(), f"{keyfile.name} has no lock file"
        assert _keys_in(keyfile) == _locks_in(lockfile), keyfile.name
    assert {p.name for p in _keyfiles()} == {p.name for p in _lockfiles()}


def test_expected_values_present() -> None:
    values = {}
    for keyfile in _keyfiles():
        parser = configparser.ConfigParser(interpolation=None)
        parser.optionxform = str  # type: ignore[assignment,method-assign]
        parser.read_string(keyfile.read_text(encoding="utf-8"))
        for section in parser.sections():
            for key, value in parser[section].items():
                values[f"/{section}/{key}"] = value
    for key, value in EXPECTED.items():
        assert values.get(key) == value, key


@pytest.fixture
def compiled_profile(tmp_path: Path) -> dict[str, str]:
    if shutil.which("dconf") is None:
        pytest.skip("needs the dconf CLI (dconf-cli)")
    src = tmp_path / "local.d"
    (src / "locks").mkdir(parents=True)
    for path in _keyfiles():
        shutil.copy(path, src / path.name)
    for path in _lockfiles():
        shutil.copy(path, src / "locks" / path.name)
    db = tmp_path / "local"
    subprocess.run(["dconf", "compile", str(db), str(src)], check=True, capture_output=True)
    profile = tmp_path / "profile"
    profile.write_text(f"user-db:user\nfile-db:{db}\n", encoding="utf-8")
    (tmp_path / "xdg").mkdir()
    env = dict(os.environ)
    env.update(
        {
            "DCONF_PROFILE": str(profile),
            "XDG_CONFIG_HOME": str(tmp_path / "xdg"),
            "XDG_RUNTIME_DIR": str(tmp_path / "xdg"),
        }
    )
    return env


def test_compiled_values_read_back(compiled_profile: dict[str, str]) -> None:
    for key, value in EXPECTED.items():
        res = subprocess.run(
            ["dconf", "read", key], env=compiled_profile, capture_output=True, text=True, check=True
        )
        assert res.stdout.strip() == value, key


def test_compiled_locks_read_back(compiled_profile: dict[str, str]) -> None:
    locked = set()
    for directory in ("/org/gnome/", "/org/freedesktop/"):
        res = subprocess.run(
            ["dconf", "list-locks", directory],
            env=compiled_profile,
            capture_output=True,
            text=True,
            check=True,
        )
        locked |= set(res.stdout.split())
    expected = set().union(*(_locks_in(p) for p in _lockfiles()))
    assert expected <= locked


def test_thumbnailer_removal_keeps_desktop_packages() -> None:
    """Thumbnailers inside packages the desktop needs are diverted, never removed."""
    defaults = yaml.safe_load(
        (ROLES / "harden_desktop" / "defaults" / "main.yml").read_text(encoding="utf-8")
    )
    absent = set(defaults["harden_desktop_thumbnailer_packages_absent"])
    keep = {
        "nautilus",
        "gdm3",
        "gnome-shell",
        "gnome-control-center",
        "librsvg2-common",
        "libgdk-pixbuf-2.0-0",
        "heif-thumbnailer",
        "webp-pixbuf-loader",
        "evince",
        "tracker-miner-fs",
        "gvfs",
        "gvfs-daemons",
    }
    assert not absent & keep


def test_indexer_names_cover_both_releases() -> None:
    defaults = yaml.safe_load(
        (ROLES / "harden_desktop" / "defaults" / "main.yml").read_text(encoding="utf-8")
    )
    units = defaults["harden_desktop_indexer_masked_user_units"]
    assert "tracker-miner-fs-3.service" in units  # Ubuntu 24.04 (GNOME 46)
    assert "localsearch-3.service" in units  # GNOME 47 and later


SCREEN_LOCK_SCHEMAS = (
    "org/gnome/desktop/screensaver",
    "org/gnome/desktop/session",
    "org/gnome/desktop/lockdown",
    "org/gnome/settings-daemon/plugins/power",
)


def test_screen_lock_has_one_owner() -> None:
    """1.2 and 5.1: only harden_desktop sets the screen lock and idle keys (decision log)."""
    owners = []
    for path in sorted(ROLES.glob("*/files/**/*")):
        if not path.is_file() or "locks" in path.parts:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        if any(f"[{schema}]" in text for schema in SCREEN_LOCK_SCHEMAS):
            owners.append(path.relative_to(ROLES).as_posix())
    assert owners == ["harden_desktop/files/dconf/20-airlock-screenlock"]
    base_tasks = (ROLES / "base" / "tasks").glob("*.yml")
    assert not any("screensaver" in p.read_text(encoding="utf-8") for p in base_tasks)


# ----------------------------------------------------------------- LibreOffice hidden (5.1)

DESKTOP_DEFAULTS = yaml.safe_load(
    (ROLES / "harden_desktop" / "defaults" / "main.yml").read_text(encoding="utf-8")
)
MIMEAPPS = ROLES / "harden_desktop" / "files" / "mimeapps.list"
OFFICE_TYPES = (
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    "application/msword",
    "application/vnd.ms-excel",
    "application/vnd.ms-powerpoint",
    "application/vnd.oasis.opendocument.text",
    "application/vnd.oasis.opendocument.spreadsheet",
    "application/vnd.oasis.opendocument.presentation",
    "application/rtf",
    "text/csv",
    "x-scheme-handler/ms-word",
)


def _mimeapps() -> configparser.ConfigParser:
    parser = configparser.ConfigParser(interpolation=None, delimiters=("=",))
    parser.optionxform = str  # type: ignore[assignment,method-assign]
    parser.read_string(MIMEAPPS.read_text(encoding="utf-8"))
    return parser


def test_libreoffice_lists_agree() -> None:
    ids = DESKTOP_DEFAULTS["harden_desktop_libreoffice_desktop_ids"]
    files = DESKTOP_DEFAULTS["harden_desktop_libreoffice_desktop_files_absent"]
    assert [Path(f).name for f in files] == ids
    assert all(f.startswith("/usr/share/applications/") for f in files)
    # Both the -nogui names the image installs and the full package names.
    mailcap = {
        Path(f).name for f in DESKTOP_DEFAULTS["harden_desktop_libreoffice_mailcap_files_absent"]
    }
    for app in ("writer", "calc", "impress", "draw"):
        assert {f"libreoffice-{app}", f"libreoffice-{app}-nogui"} <= mailcap


def test_mimeapps_removes_every_libreoffice_association() -> None:
    parser = _mimeapps()
    assert parser.sections() == ["Removed Associations"]
    removed = parser["Removed Associations"]
    expected = ";".join(DESKTOP_DEFAULTS["harden_desktop_libreoffice_desktop_ids"]) + ";"
    assert dict(removed) and all(v == expected for v in removed.values())
    for mime in OFFICE_TYPES:
        assert mime in removed, mime


def test_mimeapps_covers_the_types_installed_libreoffice_claims() -> None:
    """Where LibreOffice is installed (as in the authoring container), every type it claims."""
    entries = sorted(Path("/usr/share/applications").glob("libreoffice*.desktop"))
    if not entries:
        pytest.skip("no LibreOffice desktop entries on this host")
    removed = _mimeapps()["Removed Associations"]
    for entry in entries:
        parser = configparser.ConfigParser(interpolation=None, strict=False)
        parser.optionxform = str  # type: ignore[assignment,method-assign]
        parser.read_string(entry.read_text(encoding="utf-8"))
        claimed = parser["Desktop Entry"].get("MimeType", "")
        for mime in filter(None, claimed.split(";")):
            assert mime in removed, f"{entry.name}: {mime}"
        assert entry.name in DESKTOP_DEFAULTS["harden_desktop_libreoffice_desktop_ids"]


DPKG_DIVERT_STUB = """#!/usr/bin/env python3
import json, os, sys
db = os.environ["DIVERT_DB"]
state = json.load(open(db)) if os.path.exists(db) else {}
args = sys.argv[1:]
to, path = args[args.index("--divert") + 1], args[args.index("--add") + 1]
assert "--rename" in args and "--local" in args
if path in state:
    print(f"Leaving 'local diversion of {path} to {to}'")
    sys.exit(0)
state[path] = to
if os.path.exists(path):
    os.rename(path, to)
json.dump(state, open(db, "w"))
print(f"Adding 'local diversion of {path} to {to}'")
"""


def _run_libreoffice_tasks(tmp: Path, extra: dict[str, object]) -> str:
    play = tmp / "play.yml"
    play.write_text(
        "- hosts: localhost\n  connection: local\n  gather_facts: false\n  tasks:\n"
        "    - ansible.builtin.import_role:\n        name: harden_desktop\n"
        "        tasks_from: libreoffice_hidden.yml\n",
        encoding="utf-8",
    )
    (tmp / "vars.json").write_text(json.dumps(extra), encoding="utf-8")
    env = {
        **os.environ,
        "PATH": f"{tmp / 'bin'}:{os.environ['PATH']}",
        "DIVERT_DB": str(tmp / "divert.json"),
        "ANSIBLE_ROLES_PATH": str(ROLES),
        "ANSIBLE_LOCALHOST_WARNING": "false",
        "ANSIBLE_INVENTORY_UNPARSED_WARNING": "false",
        "ANSIBLE_NOCOLOR": "1",
    }
    res = subprocess.run(
        ["ansible-playbook", "-i", "localhost,", "-e", f"@{tmp / 'vars.json'}", str(play)],
        capture_output=True, text=True, env=env, cwd=tmp, check=False, timeout=300,
    )  # fmt: skip
    assert res.returncode == 0, res.stdout + res.stderr
    return res.stdout


def test_libreoffice_tasks_hide_every_entry_and_keep_others(tmp_path: Path) -> None:
    """Runs libreoffice_hidden.yml against a stand-in tree with a stub dpkg-divert."""
    if shutil.which("ansible-playbook") is None:
        pytest.skip("needs ansible-playbook")
    if os.geteuid() != 0:
        pytest.skip("the role sets root ownership")
    root = tmp_path / "root"
    apps, local, mime = root / "apps", root / "local-apps", root / "mime"
    for d in (apps, mime, tmp_path / "bin"):
        d.mkdir(parents=True)
    (apps / "libreoffice-startcenter.desktop").write_text("[Desktop Entry]\nName=LO\n")
    (apps / "libreoffice-xsltfilter.desktop").write_text("[Desktop Entry]\nName=LO\n")
    (apps / "libreoffice-future.desktop").write_text("[Desktop Entry]\nName=LO\n")  # unknown name
    (apps / "org.gnome.TextEditor.desktop").write_text("[Desktop Entry]\nName=Editor\n")
    (mime / "libreoffice-writer-nogui").write_text("application/msword; soffice %s\n")
    (mime / "evince").write_text("application/pdf; evince %s\n")
    stub = tmp_path / "bin" / "dpkg-divert"
    stub.write_text(DPKG_DIVERT_STUB)
    stub.chmod(0o755)
    calls = tmp_path / "calls"
    tool = tmp_path / "bin" / "refresh"
    tool.write_text(f'#!/bin/sh\necho "$0 $*" >> {calls}\n')
    tool.chmod(0o755)
    disabled = root / "disabled"
    d = DESKTOP_DEFAULTS
    extra: dict[str, object] = {
        "harden_desktop_libreoffice_disabled_dir": str(disabled),
        "harden_desktop_applications_dirs": [str(apps), str(local)],
        "harden_desktop_mailcap_packages_dir": str(mime),
        "harden_desktop_libreoffice_desktop_files_absent": [
            str(apps / Path(p).name) for p in d["harden_desktop_libreoffice_desktop_files_absent"]
        ],
        "harden_desktop_libreoffice_mailcap_files_absent": [
            str(mime / Path(p).name) for p in d["harden_desktop_libreoffice_mailcap_files_absent"]
        ],
        "harden_desktop_mimeapps_list": str(root / "xdg" / "mimeapps.list"),
        "harden_desktop_update_desktop_database": str(tool),
        "harden_desktop_update_mime": str(tool),
    }
    _run_libreoffice_tasks(tmp_path, extra)

    assert sorted(p.name for p in apps.iterdir()) == ["org.gnome.TextEditor.desktop"]
    assert sorted(p.name for p in mime.iterdir()) == ["evince"]
    assert sorted(p.name for p in (disabled / "applications").iterdir()) == [
        "libreoffice-future.desktop",
        "libreoffice-startcenter.desktop",
        "libreoffice-xsltfilter.desktop",
    ]
    assert [p.name for p in (disabled / "mime-packages").iterdir()] == ["libreoffice-writer-nogui"]
    for desktop_id in d["harden_desktop_libreoffice_desktop_ids"]:
        override = (local / desktop_id).read_text()
        assert "\nHidden=true\n" in override and "\nNoDisplay=true\n" in override
    assert (root / "xdg" / "mimeapps.list").read_bytes() == MIMEAPPS.read_bytes()
    assert len(calls.read_text().splitlines()) == 3  # both application dirs and mailcap

    # Idempotent: nothing left to divert, nothing changes, the caches are not rebuilt again.
    second = _run_libreoffice_tasks(tmp_path, extra)
    assert re.search(r"changed=0\b", second), second
    assert len(calls.read_text().splitlines()) == 3
