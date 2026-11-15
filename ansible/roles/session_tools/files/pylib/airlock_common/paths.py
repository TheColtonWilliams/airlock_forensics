"""On-image paths. The only module that reads the AIRLOCK_* environment overrides.

Tests point these at a temporary directory; on the image the defaults apply.
See docs/dev/contract.md section 2.
"""

from __future__ import annotations

import os
from pathlib import Path

_DEFAULTS: dict[str, str] = {
    "AIRLOCK_OPT_DIR": "/opt/airlock",
    "AIRLOCK_REPO_DIR": "/opt/airlock/repo",
    "AIRLOCK_ETC_DIR": "/etc/airlock",
    "AIRLOCK_STATE_DIR": "/var/lib/airlock",
    "AIRLOCK_SESSION_DIR": "/var/log/forensic-session",
    "AIRLOCK_ASSETS_DIR": "/srv/airlock/assets",
    "AIRLOCK_OUTPUT_DIR": "/srv/airlock/output",
}


def _get(name: str) -> Path:
    return Path(os.environ.get(name) or _DEFAULTS[name])


def opt_dir() -> Path:
    return _get("AIRLOCK_OPT_DIR")


def repo_dir() -> Path:
    if os.environ.get("AIRLOCK_REPO_DIR"):
        return Path(os.environ["AIRLOCK_REPO_DIR"])
    return opt_dir() / "repo"


def etc_dir() -> Path:
    return _get("AIRLOCK_ETC_DIR")


def state_dir() -> Path:
    return _get("AIRLOCK_STATE_DIR")


def session_dir() -> Path:
    return _get("AIRLOCK_SESSION_DIR")


def assets_dir() -> Path:
    return _get("AIRLOCK_ASSETS_DIR")


def output_dir() -> Path:
    return _get("AIRLOCK_OUTPUT_DIR")


def assets_files_dir() -> Path:
    """Where staged files live on the ASSETS partition (``files/<target>``)."""
    return assets_dir() / "files"


def baked_manifest() -> Path:
    """The trusted manifest baked into the image at build time."""
    return state_dir() / "manifest.json"


def manifest_public_key() -> Path:
    return etc_dir() / "manifest-signing.pub.pem"


def build_info() -> Path:
    return etc_dir() / "build-info.json"
