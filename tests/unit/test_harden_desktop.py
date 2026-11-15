"""dconf keyfiles and locks for harden_storage (3.1) and harden_desktop (5.1, 5.2).

When the dconf CLI is installed, the keyfiles are compiled with ``dconf compile`` and read back
through a profile shaped like the image's (a writable user database over the compiled system
database), so the values and the locks are checked as GNOME would see them.
"""

from __future__ import annotations

import configparser
import os
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
