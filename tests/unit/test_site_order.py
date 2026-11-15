"""Task 5.8: hardening runs first and again as the last play, so no tool role can undo it.

Also task 3A.1 ordering: the base role writes /etc/default/grub.d/90-airlock.cfg before
harden_storage (next in the first play) checks it. That pair is run for real with
ansible-playbook against temporary paths.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
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


# ------------------------------------------------- base writes GRUB before harden_storage

ROLES = REPO_ROOT / "ansible" / "roles"
GROUP_VARS = REPO_ROOT / "ansible" / "group_vars" / "all" / "main.yml"


def test_base_imports_grub_cmdline_for_every_drive_build() -> None:
    """3A.1: harden_storage checks the GRUB file that base writes; base must always write it."""
    imports = yaml.safe_load((ROLES / "base" / "tasks" / "main.yml").read_text(encoding="utf-8"))
    entry = next(e for e in imports if e.get("ansible.builtin.import_tasks") == "grub_cmdline.yml")
    assert entry.get("when") in (None, "airlock_target != 'live'")
    assert "tags" not in entry
    base_defaults = yaml.safe_load((ROLES / "base" / "defaults" / "main.yml").read_text())
    storage_defaults = yaml.safe_load(
        (ROLES / "harden_storage" / "defaults" / "main.yml").read_text()
    )
    assert (
        f"{base_defaults['base_grub_defaults_dir']}/90-airlock.cfg"
        == storage_defaults["harden_storage_grub_cmdline_file"]
    )
    handlers = yaml.safe_load((ROLES / "base" / "handlers" / "main.yml").read_text())
    grub = next(h for h in handlers if h["name"] == "Base update grub")
    assert grub["ansible.builtin.command"]["argv"] == ["update-grub"]
    tasks = yaml.safe_load((ROLES / "base" / "tasks" / "grub_cmdline.yml").read_text())
    written = [t for t in tasks if "ansible.builtin.template" in t]
    assert written and all(t.get("notify") == "Base update grub" for t in written)


def _run_play(tmp_path: Path, tasks: list[dict], extra: dict) -> tuple[int, str]:
    handlers = []
    for role in ("base", "harden_storage"):
        for h in yaml.safe_load((ROLES / role / "handlers" / "main.yml").read_text()) or []:
            handlers.append({"name": h["name"], "ansible.builtin.debug": {"msg": "handler stub"}})
    play = [
        {
            "name": "base then harden_storage",
            "hosts": "localhost",
            "connection": "local",
            "gather_facts": False,
            "vars_files": [
                str(ROLES / "base" / "defaults" / "main.yml"),
                str(ROLES / "harden_storage" / "defaults" / "main.yml"),
                str(GROUP_VARS),
            ],
            "handlers": handlers,
            "tasks": tasks,
        }
    ]
    playbook = tmp_path / "play.yml"
    playbook.write_text(yaml.safe_dump(play), encoding="utf-8")
    # The task files are imported outside their role, so copy and template sources resolve
    # next to the playbook; only base's grub_cmdline.yml uses any.
    for sub in ("files", "templates"):
        (tmp_path / sub).symlink_to(ROLES / "base" / sub)
    extra_file = tmp_path / "extra.json"
    extra_file.write_text(json.dumps(extra), encoding="utf-8")
    env = dict(os.environ)
    env.update(
        {
            "ANSIBLE_NOCOLOR": "1",
            "ANSIBLE_LOCALHOST_WARNING": "False",
            "ANSIBLE_INVENTORY_UNPARSED_WARNING": "False",
            "ANSIBLE_RETRY_FILES_ENABLED": "False",
            "ANSIBLE_LOCAL_TEMP": str(tmp_path / "ansible-tmp"),
            "ANSIBLE_CONFIG": str(tmp_path / "none.cfg"),
        }
    )
    argv = ["ansible-playbook", "-i", "localhost,", str(playbook), "-e", f"@{extra_file}"]
    res = subprocess.run(argv, capture_output=True, text=True, env=env, check=False, timeout=300)
    return res.returncode, res.stdout + res.stderr


def _paths(tmp_path: Path) -> dict[str, str]:
    grub_d = tmp_path / "etc" / "default" / "grub.d"
    scripts = tmp_path / "etc" / "grub.d"
    scripts.mkdir(parents=True)
    return {
        "base_grub_defaults_dir": str(grub_d),
        "base_grub_scripts_dir": str(scripts),
        "harden_storage_grub_cmdline_file": str(grub_d / "90-airlock.cfg"),
    }


def _import(role: str, name: str) -> dict:
    return {"ansible.builtin.import_tasks": str(ROLES / role / "tasks" / name)}


needs_root_ansible = pytest.mark.skipif(
    shutil.which("ansible-playbook") is None or os.geteuid() != 0,
    reason="needs ansible-playbook and root (the task files set owner root)",
)


@needs_root_ansible
def test_base_grub_file_satisfies_harden_storage_in_site_order(tmp_path: Path) -> None:
    """The first play's order: base grub_cmdline.yml, then harden_storage kernel_cmdline.yml."""
    extra = _paths(tmp_path)
    tasks = [_import("base", "grub_cmdline.yml"), _import("harden_storage", "kernel_cmdline.yml")]
    rc, out = _run_play(tmp_path, tasks, extra)
    assert rc == 0, out
    cfg = Path(extra["harden_storage_grub_cmdline_file"]).read_text(encoding="utf-8")
    main = yaml.safe_load(GROUP_VARS.read_text(encoding="utf-8"))
    line = next(ln for ln in cfg.splitlines() if ln.startswith("GRUB_CMDLINE_LINUX="))
    assert line.split("=", 1)[1].strip('"').split() == main["airlock_kernel_cmdline"]
    assert "rfkill.default_state=0" in line
    hook = Path(extra["base_grub_scripts_dir"]) / "06_airlock_vm_test"
    assert hook.is_file() and os.access(hook, os.X_OK)


@needs_root_ansible
def test_harden_storage_alone_fails_without_the_base_grub_file(tmp_path: Path) -> None:
    extra = _paths(tmp_path)
    rc, out = _run_play(tmp_path, [_import("harden_storage", "kernel_cmdline.yml")], extra)
    assert rc != 0
    assert "run the base role before harden_storage" in out


@needs_root_ansible
def test_live_target_skips_the_grub_file_on_both_sides(tmp_path: Path) -> None:
    """7.2: the live ISO has no GRUB file; base writes none and harden_storage does not ask."""
    extra = {**_paths(tmp_path), "airlock_target": "live"}
    imports = yaml.safe_load((ROLES / "base" / "tasks" / "main.yml").read_text(encoding="utf-8"))
    entry = next(e for e in imports if e.get("ansible.builtin.import_tasks") == "grub_cmdline.yml")
    tasks = [
        {**_import("base", "grub_cmdline.yml"), "when": entry["when"]},
        _import("harden_storage", "kernel_cmdline.yml"),
    ]
    rc, out = _run_play(tmp_path, tasks, extra)
    assert rc == 0, out
    assert not Path(extra["harden_storage_grub_cmdline_file"]).exists()
