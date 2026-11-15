"""Every hardening control has a test (plan 2.2 / 2.4).

Fails when a unit is masked, a package removed, or a file deleted by a hardening role without a
matching goss check, when a control task file does not name an existing test, or when a role's
tasks/main.yml stops being a plain list of per-control imports.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")

REPO_ROOT = Path(__file__).resolve().parents[2]
ROLES = REPO_ROOT / "ansible" / "roles"
GOSS = REPO_ROOT / "tests" / "goss"
ROLE_GOSS = {
    "harden_storage": "storage.yaml",
    "harden_network": "network.yaml",
    "harden_desktop": "desktop.yaml",
    "harden_services": "services.yaml",
}


def _defaults(role: str) -> dict:
    return yaml.safe_load((ROLES / role / "defaults" / "main.yml").read_text(encoding="utf-8"))


def _goss(role: str) -> dict:
    return yaml.safe_load((GOSS / ROLE_GOSS[role]).read_text(encoding="utf-8"))


def _vars_ending(role: str, suffix: str) -> list[tuple[str, str]]:
    out = []
    for key, value in _defaults(role).items():
        if key.endswith(suffix):
            assert isinstance(value, list), key
            out += [(key, item) for item in value]
    return out


def _is_mask_link(entry: dict | None) -> bool:
    return bool(entry) and entry.get("exists") is True and entry.get("linked-to") == "/dev/null"


@pytest.mark.parametrize("role", sorted(ROLE_GOSS))
def test_every_masked_system_unit_has_a_goss_check(role: str) -> None:
    goss = _goss(role)
    files = goss.get("file", {})
    services = goss.get("service", {})
    units = _vars_ending(role, "_masked_units")
    if role != "harden_desktop":
        assert units, f"{role} masks no system units?"
    for var, unit in units:
        assert _is_mask_link(files.get(f"/etc/systemd/system/{unit}")), (
            f"{role}: {unit} (from {var}) has no goss check that it links to /dev/null"
        )
        assert services.get(unit, {}).get("running") is False, (
            f"{role}: {unit} (from {var}) has no goss check that it is not running"
        )


@pytest.mark.parametrize("role", sorted(ROLE_GOSS))
def test_every_masked_user_unit_has_a_goss_check(role: str) -> None:
    files = _goss(role).get("file", {})
    for var, unit in _vars_ending(role, "_masked_user_units"):
        assert _is_mask_link(files.get(f"/etc/systemd/user/{unit}")), (
            f"{role}: user unit {unit} (from {var}) has no goss check"
        )


@pytest.mark.parametrize("role", sorted(ROLE_GOSS))
def test_every_removed_package_has_a_goss_check(role: str) -> None:
    packages = _goss(role).get("package", {})
    for var, pkg in _vars_ending(role, "_packages_absent"):
        assert packages.get(pkg, {}).get("installed") is False, (
            f"{role}: package {pkg} (from {var}) has no goss check"
        )


@pytest.mark.parametrize("role", sorted(ROLE_GOSS))
def test_every_removed_file_has_a_goss_check(role: str) -> None:
    files = _goss(role).get("file", {})
    removed = (
        _vars_ending(role, "_absent")
        + _vars_ending(role, "_monitor_files")
        + _vars_ending(role, "_swap_files")
    )
    for var, path in removed:
        if var.endswith("_packages_absent"):
            continue
        assert files.get(path, {}).get("exists") is False, (
            f"{role}: {path} (from {var}) has no goss check that it is gone"
        )


def test_masked_udev_rules_have_goss_checks() -> None:
    files = _goss("harden_storage")["file"]
    for _, rule in _vars_ending("harden_storage", "_udev_rules_masked"):
        assert _is_mask_link(files.get(f"/etc/udev/rules.d/{rule}")), rule


def test_kernel_cmdline_entries_are_checked_and_shared() -> None:
    required = _defaults("harden_storage")["harden_storage_required_cmdline"]
    shared = yaml.safe_load(
        (REPO_ROOT / "ansible" / "group_vars" / "all" / "main.yml").read_text(encoding="utf-8")
    )["airlock_kernel_cmdline"]
    patterns = _goss("harden_storage")["command"]["kernel command line"]["stdout"]
    joined = "\n".join(patterns)
    for entry in required:
        assert entry in shared, f"airlock_kernel_cmdline lacks {entry}"
        assert re.escape(entry).replace("\\=", "=") in joined, f"/proc/cmdline check lacks {entry}"
    assert "rfkill.default_state=0" in shared


def test_blocked_radio_modules_are_checked() -> None:
    modules = _defaults("harden_network")["harden_network_blocked_modules"]
    contents = _goss("harden_network")["file"]["/etc/modprobe.d/forensic-radios.conf"]["contents"]
    lsmod = "\n".join(_goss("harden_network")["command"]["no radio modules loaded"]["stdout"])
    for module in modules:
        assert f"install {module} /bin/false" in contents, module
        assert f"^{module}" in lsmod, module
    for required in ("cfg80211", "bluetooth", "btusb"):
        assert required in modules


# ----------------------------------------------------------------- role structure


def _task_files(role: str) -> list[Path]:
    return sorted(p for p in (ROLES / role / "tasks").glob("*.yml") if p.name != "main.yml")


@pytest.mark.parametrize("role", sorted(ROLE_GOSS))
def test_main_only_imports_one_file_per_control(role: str) -> None:
    main = yaml.safe_load((ROLES / role / "tasks" / "main.yml").read_text(encoding="utf-8"))
    imported = []
    for task in main:
        keys = set(task) - {"name"}
        assert keys == {"ansible.builtin.import_tasks"}, f"{role} main.yml: {task}"
        imported.append(task["ansible.builtin.import_tasks"])
    controls = [p.name for p in _task_files(role) if not p.name.startswith("_")]
    assert sorted(imported) == sorted(controls), f"{role}: main.yml and tasks/ disagree"
    assert len(imported) == len(set(imported))


@pytest.mark.parametrize("role", sorted(ROLE_GOSS))
def test_each_control_names_an_existing_test(role: str) -> None:
    for path in _task_files(role):
        if path.name.startswith("_"):
            continue
        header = []
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.startswith("#"):
                break
            header.append(line)
        text = "\n".join(header)
        assert re.search(r"^# Control [0-9A]", text, re.M), f"{path}: no '# Control' comment"
        test_lines = [line for line in header if line.startswith("# Test:")]
        assert test_lines, f"{path}: no '# Test:' comment"
        named = re.findall(r"tests/[\w./-]+\.(?:ya?ml|sh|py)", "\n".join(test_lines))
        assert named, f"{path}: Test comment names no test file"
        for rel in named:
            assert (REPO_ROOT / rel).is_file(), f"{path}: names missing test {rel}"


@pytest.mark.parametrize("role", sorted(ROLE_GOSS))
def test_role_files_and_handlers_exist(role: str) -> None:
    handlers_file = ROLES / role / "handlers" / "main.yml"
    handlers = set()
    if handlers_file.exists():
        handlers = {h["name"] for h in yaml.safe_load(handlers_file.read_text(encoding="utf-8"))}
    defaults = _defaults(role)
    for path in _task_files(role):
        tasks = yaml.safe_load(path.read_text(encoding="utf-8"))
        for task in tasks:
            notify = task.get("notify")
            for name in [notify] if isinstance(notify, str) else notify or []:
                assert name in handlers, f"{path.name}: notifies unknown handler {name!r}"
            for module in ("ansible.builtin.copy", "ansible.builtin.template"):
                src = (task.get(module) or {}).get("src")
                if src:
                    sub = "files" if module.endswith("copy") else "templates"
                    assert (ROLES / role / sub / src).is_file(), f"{path.name}: missing {src}"
            text = yaml.safe_dump(task)
            known = set(defaults)
            for t in tasks:
                known |= {t.get("register")} | set(t.get("vars") or {})
            for var in set(re.findall(rf"\b({role}_[a-z0-9_]+)\b", text)):
                assert var in known, f"{path.name}: undefined {var}"


def test_dconf_profiles_are_identical() -> None:
    storage = (ROLES / "harden_storage" / "files" / "dconf-profile-user").read_bytes()
    desktop = (ROLES / "harden_desktop" / "files" / "dconf-profile-user").read_bytes()
    assert storage == desktop == b"user-db:user\nsystem-db:local\n"
    a = (ROLES / "harden_storage" / "tasks" / "_dconf_profile.yml").read_text(encoding="utf-8")
    b = (ROLES / "harden_desktop" / "tasks" / "_dconf_profile.yml").read_text(encoding="utf-8")
    assert a.replace("storage", "X").replace("desktop", "X") == b.replace("desktop", "X").replace(
        "storage", "X"
    )


def test_no_write_blocker_wording() -> None:
    """Hard rule 2.3.7: the software layer is a policy, never a write blocker."""
    bad = re.compile(r"write[- ]?blocker", re.I)
    for role in ROLE_GOSS:
        for path in (ROLES / role).rglob("*"):
            if not path.is_file():
                continue
            for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
                if bad.search(line):
                    assert re.search(r"not a write blocker|hardware write blocker", line, re.I), (
                        f"{path}: {line.strip()}"
                    )


@pytest.mark.parametrize("role", sorted(ROLE_GOSS))
def test_masks_are_plain_links(role: str) -> None:
    """Masks are /dev/null links, as `systemctl mask` writes them, so they also work in a chroot
    and for units that are not installed yet (a later tool role may install them)."""
    for path in _task_files(role):
        for task in yaml.safe_load(path.read_text(encoding="utf-8")):
            unit = task.get("ansible.builtin.systemd_service") or {}
            assert "masked" not in unit, f"{path.name}: use a /dev/null link, not systemctl mask"
            link = task.get("ansible.builtin.file") or {}
            if link.get("src") == "/dev/null":
                assert link.get("state") == "link"
                assert link.get("force") is True
