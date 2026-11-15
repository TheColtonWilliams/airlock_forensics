"""harden_network files checked outside the image (tasks 3.5, 3.6, 3.7)."""

from __future__ import annotations

import configparser
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")
jinja2 = pytest.importorskip("jinja2")

REPO_ROOT = Path(__file__).resolve().parents[2]
ROLE = REPO_ROOT / "ansible" / "roles" / "harden_network"
DEFAULTS = yaml.safe_load((ROLE / "defaults" / "main.yml").read_text(encoding="utf-8"))
NFT = ROLE / "files" / "nftables.conf"


def _nft_chains(text: str) -> dict[str, list[str]]:
    """Map 'table/chain' to the chain's statement lines."""
    chains: dict[str, list[str]] = {}
    table = chain = ""
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if m := re.match(r"table (\w+) (\w+) \{", line):
            table = f"{m.group(1)} {m.group(2)}"
        elif m := re.match(r"chain (\w+) \{", line):
            chain = f"{table}/{m.group(1)}"
            chains[chain] = []
        elif line == "}":
            if chain:
                chain = ""
            else:
                table = ""
        elif chain:
            chains[chain].append(line)
    return chains


def test_nftables_drops_everything_but_loopback() -> None:
    chains = _nft_chains(NFT.read_text(encoding="utf-8"))
    for hook in ("input", "forward", "output"):
        body = chains[f"inet airlock/{hook}"]
        assert f"type filter hook {hook} priority filter; policy drop;" in body
    assert chains["inet airlock/input"][1:] == ['iifname "lo" accept']
    assert chains["inet airlock/output"][1:] == ['oifname "lo" accept']
    assert chains["inet airlock/forward"][1:] == []
    for hook in ("input", "output"):
        assert chains[f"arp airlock_arp/{hook}"] == [
            f"type filter hook {hook} priority filter; policy drop;"
        ]
    # The only accept statements in the whole ruleset are the two loopback ones.
    accepts = [s for body in chains.values() for s in body if "accept" in s]
    assert sorted(accepts) == ['iifname "lo" accept', 'oifname "lo" accept']
    assert NFT.read_text(encoding="utf-8").count("flush ruleset") == 1


@pytest.mark.skipif(shutil.which("nft") is None, reason="needs nft")
def test_nftables_ruleset_parses() -> None:
    res = subprocess.run(["nft", "-c", "-f", str(NFT)], capture_output=True, text=True, check=False)
    if res.returncode != 0 and "Operation not permitted" in res.stderr:
        pytest.skip("nft -c needs CAP_NET_ADMIN here")
    assert res.returncode == 0, res.stderr


def _render_radios() -> str:
    env = jinja2.Environment(keep_trailing_newline=True, autoescape=False)
    tpl = env.from_string((ROLE / "templates" / "forensic-radios.conf.j2").read_text("utf-8"))
    return tpl.render(**DEFAULTS)


def test_radio_modules_blocked() -> None:
    text = _render_radios()
    lines = [line for line in text.splitlines() if line and not line.startswith("#")]
    for module in ("cfg80211", "mac80211", "bluetooth", "btusb"):
        assert f"install {module} /bin/false" in lines
        assert f"blacklist {module}" in lines
    assert "options rfkill default_state=0" in lines


@pytest.mark.skipif(shutil.which("modprobe") is None, reason="needs modprobe")
def test_modprobe_obeys_the_block_list(tmp_path: Path) -> None:
    conf = tmp_path / "forensic-radios.conf"
    conf.write_text(_render_radios(), encoding="utf-8")
    for module in ("cfg80211", "bluetooth", "btusb"):
        res = subprocess.run(
            ["modprobe", "-n", "-v", "-C", str(conf), module],
            capture_output=True,
            text=True,
            check=False,
        )
        assert "install /bin/false" in res.stdout, (module, res.stdout, res.stderr)


def test_rfkill_unit_runs_before_the_network() -> None:
    unit = configparser.ConfigParser(strict=True, interpolation=None)
    unit.optionxform = str  # type: ignore[assignment,method-assign]
    unit.read_string((ROLE / "files" / "forensic-rfkill.service").read_text(encoding="utf-8"))
    before = unit["Unit"]["Before"].split()
    for name in ("NetworkManager.service", "network-pre.target", "systemd-networkd.service"):
        assert name in before
    assert unit["Unit"]["DefaultDependencies"] == "no"
    assert unit["Service"]["Type"] == "oneshot"
    assert unit["Service"]["ExecStart"] == "/usr/sbin/rfkill block all"
    assert unit["Install"]["WantedBy"] == "sysinit.target"


def test_rfkill_rule_blocks_new_radios_and_removes_desktop_access() -> None:
    text = (ROLE / "files" / "72-forensic-rfkill.rules").read_text(encoding="utf-8")
    assert 'ACTION=="add", SUBSYSTEM=="rfkill", ATTR{soft}="1"' in text
    assert 'TAG-="uaccess"' in text
    # Must sort before 73-seat-late.rules, which applies uaccess.
    assert "72-forensic-rfkill.rules" < "73-seat-late.rules"


def test_netif_rule_leaves_interfaces_unmanaged_and_down() -> None:
    rules = [
        line
        for line in (ROLE / "files" / "99-forensic-netif.rules").read_text("utf-8").splitlines()
        if line and not line.startswith("#")
    ]
    assert len(rules) == 1
    rule = rules[0]
    for part in (
        'SUBSYSTEM=="net"',
        'KERNEL!="lo"',
        'ENV{NM_UNMANAGED}="1"',
        "ENV{ID_NET_MANAGED_BY}=",
        'RUN+="/usr/sbin/ip link set dev $name down"',
    ):
        assert part in rule
    # Runs after 80-net-setup-link.rules so $name is the final interface name.
    assert "99-forensic-netif.rules" > "80-net-setup-link.rules"


@pytest.mark.skipif(shutil.which("udevadm") is None, reason="needs udevadm")
def test_network_udev_rules_verify() -> None:
    probe = subprocess.run(["udevadm", "verify", "--help"], capture_output=True, check=False)
    if probe.returncode != 0:
        pytest.skip("udevadm has no verify command")
    files = [str(p) for p in sorted((ROLE / "files").glob("*.rules"))]
    res = subprocess.run(
        ["udevadm", "verify", "--resolve-names=never", *files],
        capture_output=True,
        text=True,
        check=False,
    )
    assert res.returncode == 0, res.stdout + res.stderr


def test_firewall_not_started_during_image_build() -> None:
    """Starting the drop-all firewall would cut the Packer SSH session mid-build."""
    assert DEFAULTS["harden_network_start_firewall"] == "{{ airlock_phase == 'provision' }}"
    tasks = yaml.safe_load((ROLE / "tasks" / "nftables.yml").read_text(encoding="utf-8"))
    starts = [
        t
        for t in tasks
        if (t.get("ansible.builtin.systemd_service") or {}).get("state") in {"started", "restarted"}
    ]
    assert starts
    for task in starts:
        assert "harden_network_start_firewall | bool" in task["when"]


def test_network_role_has_no_downloads() -> None:
    """Hard rule 2.3.1: nothing in the air-gap role fetches anything."""
    for path in ROLE.rglob("*.yml"):
        text = path.read_text(encoding="utf-8")
        for word in ("get_url", "uri:", "update_cache", "git:"):
            assert word not in text, f"{path}: {word}"
    assert os.path.basename(str(NFT)) == "nftables.conf"
