"""Task 5.8: hardening runs first and again as the last play, so no tool role can undo it."""

from __future__ import annotations

from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")

REPO_ROOT = Path(__file__).resolve().parents[2]
SITE = REPO_ROOT / "ansible" / "site.yml"
HARDENING = ["harden_storage", "harden_network", "harden_desktop", "harden_services"]


def _role_names(play: dict) -> list[str]:
    names = []
    for entry in play.get("roles") or []:
        names.append(entry if isinstance(entry, str) else entry["role"])
    return names


def _plays() -> list[dict]:
    plays = yaml.safe_load(SITE.read_text(encoding="utf-8"))
    assert isinstance(plays, list)
    assert plays, "site.yml has no plays"
    return plays


def test_first_play_is_base_then_hardening() -> None:
    first = _role_names(_plays()[0])
    assert first[:5] == ["base", *HARDENING]


def test_last_play_is_exactly_the_hardening_roles() -> None:
    last = _plays()[-1]
    assert _role_names(last) == HARDENING
    # Nothing in the last play may be conditional or skipped by tags.
    for entry in last["roles"]:
        if isinstance(entry, dict):
            assert set(entry) == {"role"}, f"hardening role has extra keys: {entry}"
    assert not last.get("tasks")
    assert not last.get("post_tasks")
    assert last.get("become") is True


def test_hardening_roles_run_on_the_same_hosts_as_tools() -> None:
    plays = _plays()
    assert len(plays) >= 3
    hosts = {p.get("hosts") for p in plays}
    assert hosts == {"airlock"}


def test_no_tool_role_after_the_last_hardening() -> None:
    plays = _plays()
    seen_tools_after = [r for p in plays[1:-1] for r in _role_names(p) if r.startswith("harden_")]
    assert seen_tools_after == [], "hardening roles belong in the first and last plays only"
    for play in plays[1:-1]:
        assert not play.get("post_tasks"), "a middle play has post_tasks that run after tools"
