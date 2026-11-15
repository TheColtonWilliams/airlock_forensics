"""Shared pytest fixtures. pyproject.toml puts pylib/ and scripts/ on sys.path."""

from __future__ import annotations

from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
PYLIB = REPO_ROOT / "ansible" / "roles" / "session_tools" / "files" / "pylib"


@pytest.fixture
def airlock_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Point every AIRLOCK_* path at a temporary tree and return its root."""
    for name, sub in {
        "AIRLOCK_OPT_DIR": "opt",
        "AIRLOCK_ETC_DIR": "etc",
        "AIRLOCK_STATE_DIR": "state",
        "AIRLOCK_SESSION_DIR": "session",
        "AIRLOCK_ASSETS_DIR": "assets",
        "AIRLOCK_OUTPUT_DIR": "output",
    }.items():
        d = tmp_path / sub
        d.mkdir()
        monkeypatch.setenv(name, str(d))
    return tmp_path
