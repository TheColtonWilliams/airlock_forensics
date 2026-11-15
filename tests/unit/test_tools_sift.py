"""Task 6.5: the optional SIFT layer (role tools_sift) is off by default, installs only at image
build time from a pinned Cast package, and with install_sift=true every hardening role still
runs after it (site.yml), so tests/goss/sift.yaml can prove radios and automount still hold.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

REPO = Path(__file__).resolve().parents[2]
SITE = yaml.safe_load((REPO / "ansible" / "site.yml").read_text())
MAIN = yaml.safe_load((REPO / "ansible" / "group_vars" / "all" / "main.yml").read_text())
PINS = yaml.safe_load((REPO / "ansible" / "group_vars" / "all" / "pins.yml").read_text())["pins"]
ROLE = REPO / "ansible" / "roles" / "tools_sift"
HARDENING = ("harden_storage", "harden_network", "harden_desktop", "harden_services")


def effective_order(variables: dict[str, Any]) -> list[str]:
    """Roles in the order site.yml runs them, with simple ``<var> | bool`` conditions applied."""
    order: list[str] = []
    for play in SITE:
        for entry in play["roles"]:
            role = entry["role"] if isinstance(entry, dict) else entry
            when = entry.get("when") if isinstance(entry, dict) else None
            if when is not None:
                var = str(when).split("|")[0].strip()
                if not variables.get(var, MAIN.get(var, False)):
                    continue
            order.append(role)
    return order


def test_sift_is_off_by_default_and_gated() -> None:
    assert MAIN["install_sift"] is False
    assert "tools_sift" not in effective_order({})
    gated = [
        e for p in SITE for e in p["roles"] if isinstance(e, dict) and e.get("role") == "tools_sift"
    ]
    assert gated and gated[0]["when"] == "install_sift | bool"


def test_hardening_reapplied_after_sift_when_enabled() -> None:
    order = effective_order({"install_sift": True})
    sift = order.index("tools_sift")
    for role in HARDENING:
        assert role in order[sift + 1 :], f"{role} does not run after tools_sift"
    # Nothing but hardening runs after the last tool layer.
    layers = [i for i, r in enumerate(order) if r.startswith("tools_") or r == "session_tools"]
    last_tool = max(layers)
    assert set(order[last_tool + 1 :]) == set(HARDENING)
    assert SITE[-1]["name"].lower().startswith("re-apply hardening")


def test_autopsy_is_also_optional_and_before_the_reapply() -> None:
    assert MAIN["install_autopsy"] is False
    order = effective_order({"install_autopsy": True, "install_sift": True})
    i = order.index("tools_autopsy")
    for role in HARDENING:
        assert role in order[i + 1 :]


def test_cast_is_pinned_and_sift_installs_only_at_image_build() -> None:
    defaults = yaml.safe_load((ROLE / "defaults" / "main.yml").read_text())
    pin = PINS[defaults["tools_sift_cast_pin"]]
    assert pin["stage"] == "image" and len(pin["sha256"]) == 64
    assert defaults["tools_sift_mode"] == "server"  # desktop mode changes the locked session
    install = yaml.safe_load((ROLE / "tasks" / "sift_install.yml").read_text())
    cast_run = next(t for t in install if "ansible.builtin.command" in t)
    assert cast_run["when"] == "airlock_phase == 'image'"
    argv = cast_run["ansible.builtin.command"]["argv"]
    assert argv[:2] == ["cast", "install"] and "--mode" in argv and "--user" in argv
    assert argv[-1] == "{{ tools_sift_distro }}"
    # Offline provisioning cannot install SIFT, so it stops with a clear message instead.
    stop = install[-1]
    assert (
        "ansible.builtin.assert" in stop
        and "rebuild the image" in stop["ansible.builtin.assert"]["fail_msg"]
    )


def test_goss_sift_checks_radios_and_automount() -> None:
    goss = yaml.safe_load((REPO / "tests" / "goss" / "sift.yaml").read_text())
    cmds = goss["command"]
    assert "rfkill" in cmds["sift-rfkill-nothing-unblocked"]["exec"]
    assert cmds["sift-rfkill-nothing-unblocked"]["stdout"] == ["/^0$/"]
    auto = cmds["sift-automount-off"]
    assert "/^automount=false$/" in auto["stdout"]
    assert "/^automount-open=false$/" in auto["stdout"]
    assert goss["service"]["forensic-rfkill.service"]["enabled"] is True
    assert goss["file"]["/etc/systemd/system/udisks2.service"]["linked-to"] == "/dev/null"
    assert PINS["cast_deb"]["version"] in cmds["sift-layer"]["exec"]
