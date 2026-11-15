"""The tools_hashsets role (tasks 4A.1-4A.5, 4A.8).

Static checks: one control per task file, each naming an existing test; every masked unit and
every package has a goss check in tests/goss/hashsets.yaml. Then the role is run for real at
the provisioning phase with every path in a temporary root (no apt, no systemd links), with
staged fixtures standing in for ASSETS and a stand-in ``sigtool`` (real ClamAV databases
cannot be made here). The second run must change nothing, and turning features off removes
what they installed.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest
import yaml

from airlock_common import hashing
from airlock_hashsets import build
from airlock_hashsets import config as hcfg

REPO = Path(__file__).resolve().parents[2]
ROLE = REPO / "ansible" / "roles" / "tools_hashsets"
GOSS = REPO / "tests" / "goss" / "hashsets.yaml"
PYLIB = REPO / "ansible" / "roles" / "session_tools" / "files" / "pylib"
sys.path.insert(0, str(REPO / "tests" / "fixtures" / "hashsets"))
import hashset_fixtures as fx  # noqa: E402


def load(path: Path) -> object:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def defaults() -> dict:
    data = load(ROLE / "defaults" / "main.yml")
    assert isinstance(data, dict)
    return data


def test_main_only_imports_one_file_per_control() -> None:
    tasks = load(ROLE / "tasks" / "main.yml")
    assert isinstance(tasks, list)
    imported = [t["ansible.builtin.import_tasks"] for t in tasks]
    assert len(imported) == len(tasks) == len(set(imported))
    on_disk = sorted(p.name for p in (ROLE / "tasks").glob("*.yml") if p.name != "main.yml")
    assert sorted(imported) == on_disk
    # The masks come before the packages, so install scripts cannot start the units.
    assert imported.index("clamav_daemons_masked.yml") < imported.index("packages.yml")


@pytest.mark.parametrize(
    "name", sorted(p.name for p in (ROLE / "tasks").glob("*.yml") if p.name != "main.yml")
)
def test_each_control_names_an_existing_test(name: str) -> None:
    text = (ROLE / "tasks" / name).read_text(encoding="utf-8")
    head = text.split("\n- name:", 1)[0]
    assert head.startswith("# Control 4A."), name
    tests = re.findall(r"tests/[\w/.-]+\.(?:py|sh|yaml)", head)
    assert tests, f"{name} names no test"
    for t in tests:
        assert (REPO / t).is_file(), f"{name} names {t}, which does not exist"


def test_every_mask_and_package_has_a_goss_check() -> None:
    goss = load(GOSS)
    assert isinstance(goss, dict)
    d = defaults()
    for unit in d["tools_hashsets_masked_units"]:
        f = goss["file"][f"/etc/systemd/system/{unit}"]
        assert f["exists"] is True and f["linked-to"] == "/dev/null", unit
        assert goss["service"][unit]["running"] is False, unit
    for pkg in d["tools_hashsets_packages"]:
        assert goss["package"][pkg]["installed"] is True, pkg
    for pkg in d["tools_hashsets_packages_absent"]:
        assert goss["package"][pkg]["installed"] is False, pkg
    assert "hash-sets-present-and-load" in goss["command"]
    assert "forensic-import-refuses-with-disk" in goss["command"]


def test_pins_exist_for_every_staged_set() -> None:
    pins = load(REPO / "ansible" / "group_vars" / "all" / "pins.yml")
    assert isinstance(pins, dict)
    d = defaults()
    ids = [
        *d["tools_hashsets_clamav_pins"],
        d["tools_hashsets_mbz_pin"],
        d["tools_hashsets_nsrl_pin"],
    ]
    ids += [p["pin"] for p in d["tools_hashsets_yara_packs"]]
    for pid in ids:
        pin = pins["pins"][pid]
        assert pin["stage"] == "assets", pid
        assert set(pin["profiles"]) & {"clamav", "malwarebazaar", "nsrl", "yara"}, pid
    assert pins["pins"]["clamav_main_cvd"]["verify"] == "vendor_signature"
    assert pins["pins"]["malwarebazaar_sha256_full"]["verify"] == "trusted_at_staging"


# --------------------------------------------------------------------------- role run


def _stub_sigtool(folder: Path) -> None:
    folder.mkdir(parents=True, exist_ok=True)
    script = folder / "sigtool"
    script.write_text(
        "#!/bin/sh\nprintf 'Build time: 14 Nov 2026\\nVersion: 27801\\nSignatures: 9\\n"
        "Verification OK.\\n'\n",
        encoding="ascii",
    )
    script.chmod(0o755)


def _asset(path: Path, version: str) -> dict[str, object]:
    return {
        "path": str(path),
        "sha256": hashing.sha256_file(path),
        "size": path.stat().st_size,
        "target": path.name,
        "verify": "sha256",
        "version": version,
    }


@pytest.fixture
def staged(tmp_path: Path) -> dict[str, dict[str, object]]:
    s = tmp_path / "assets"
    s.mkdir()
    (s / "main.cvd").write_bytes(b"ClamAV-VDB:fake-main" + b"\0" * 512)
    (s / "daily.cvd").write_bytes(b"ClamAV-VDB:fake-daily" + b"\0" * 512)
    export = fx.write_mbz_export(s / "full_sha256.zip", ["a" * 64, "b" * 64])
    pack = s / "signature-base.tar.gz"
    import tarfile  # noqa: PLC0415

    with tarfile.open(pack, "w:gz") as tf:
        tf.add(fx.YARA_RULE, "signature-base-abc/yara/airlock-test.yar")
        tf.add(fx.YARA_EXTERNAL_RULE, "signature-base-abc/yara/needs-external.yar")
    db = fx.build_nsrl(tmp_path / "src" / "RDS_2026.06.1_modern_minimal.db")
    nsrl = s / "nsrl.zip"
    with zipfile.ZipFile(nsrl, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.write(db, f"RDS_2026.06.1/{db.name}")
    return {
        "clamav_main_cvd": _asset(s / "main.cvd", "rolling"),
        "clamav_daily_cvd": _asset(s / "daily.cvd", "rolling"),
        "malwarebazaar_sha256_full": _asset(export, "daily"),
        "yara_signature_base": _asset(pack, "abc123"),
        "nsrl_rds_modern_minimal": _asset(nsrl, "2026.06.1"),
    }


def _play(tmp_path: Path, extra: dict) -> subprocess.CompletedProcess[str]:
    root = tmp_path / "root"
    data = {
        "airlock_phase": "provision",
        "airlock_etc_dir": f"{root}/etc/airlock",
        "airlock_session_dir": f"{root}/var/log/forensic-session",
        "airlock_output_mount": f"{root}/srv/airlock/output",
        "airlock_pylib_dir": str(PYLIB),
        "nsrl_on_image": False,
        "tools_hashsets_dir": f"{root}/opt/hashsets",
        "tools_hashsets_yara_dir": f"{root}/opt/yara",
        "tools_hashsets_install_packages": False,
        "tools_hashsets_manage_units": False,
        "tools_hashsets_python": sys.executable,
        **extra,
    }
    (tmp_path / "vars.json").write_text(json.dumps(data, sort_keys=True), encoding="utf-8")
    play = tmp_path / "play.yml"
    play.write_text(
        "- name: Apply tools_hashsets into a temporary root\n"
        "  hosts: localhost\n  connection: local\n  gather_facts: false\n  become: false\n"
        "  roles:\n    - role: tools_hashsets\n",
        encoding="utf-8",
    )
    env = dict(os.environ)
    env.update(
        ANSIBLE_ROLES_PATH=str(REPO / "ansible" / "roles"),
        ANSIBLE_NOCOLOR="1",
        ANSIBLE_RETRY_FILES_ENABLED="0",
        ANSIBLE_LOCALHOST_WARNING="0",
        ANSIBLE_INVENTORY_UNPARSED_WARNING="0",
        ANSIBLE_PYTHON_INTERPRETER=sys.executable,
        PATH=f"{tmp_path / 'bin'}:{env.get('PATH', '/usr/bin:/bin')}",
    )
    return subprocess.run(
        ["ansible-playbook", "-i", "localhost,", str(play), "-e", f"@{tmp_path / 'vars.json'}"],
        capture_output=True,
        text=True,
        env=env,
        check=False,
        timeout=900,
    )


def _changed(out: str) -> int:
    m = re.search(r"localhost\s*:\s*ok=\d+\s+changed=(\d+)", out)
    assert m, out[-2000:]
    return int(m.group(1))


@pytest.mark.skipif(shutil.which("ansible-playbook") is None, reason="needs ansible-playbook")
@pytest.mark.skipif(os.geteuid() != 0, reason="files are installed owned by root, as on the image")
@pytest.mark.skipif(shutil.which("yarac") is None, reason="needs yarac")
def test_role_provisions_offline_and_is_idempotent(
    tmp_path: Path, staged: dict, monkeypatch: pytest.MonkeyPatch
) -> None:
    _stub_sigtool(tmp_path / "bin")
    root = tmp_path / "root"
    (root / "srv" / "airlock" / "output").mkdir(parents=True)
    feats = {"clamav": True, "malwarebazaar": True, "yara": True, "nsrl": True}
    extra = {"airlock_features": feats, "airlock_assets": staged}
    first = _play(tmp_path, extra)
    assert first.returncode == 0, first.stdout[-3000:] + first.stderr[-2000:]
    clam = root / "opt" / "hashsets" / "clamav"
    hsb = (clam / hcfg.MBZ_HSB).read_text().splitlines()
    assert hsb == [f"{c * 64}:*:MalwareBazaar.{c * 16}:73" for c in "ab"]
    assert {p.name for p in clam.glob("*.cvd")} == {"main.cvd", "daily.cvd"}
    assert (root / "opt" / "yara" / "signature-base" / hcfg.YARA_RULES).is_file()
    pack = json.loads((root / "opt" / "yara" / "signature-base" / hcfg.YARA_META).read_text())
    assert pack["version"] == "abc123" and pack["name"] == "Neo23x0 signature-base"
    nsrl_dir = root / "srv" / "airlock" / "output" / "nsrl"  # nsrl_on_image is false
    assert (nsrl_dir / "RDS_2026.06.1_modern_minimal.db").is_file()
    assert not (root / "opt" / "hashsets" / "nsrl").exists()
    log = (root / "var" / "log" / "forensic-session" / "current.log").read_text()
    events = [json.loads(x)["event"] for x in log.splitlines()]
    for ev in ("hashset_applied", "clamav_databases_applied", "yara_pack_applied", "nsrl_applied"):
        assert ev in events, ev

    # What evidence-triage-hash sees.
    monkeypatch.setenv("AIRLOCK_ETC_DIR", str(root / "etc" / "airlock"))
    cfg = hcfg.load()
    assert cfg.nsrl is not None and cfg.nsrl.version == "2026.06.1"
    assert [h.name for h in cfg.hsb] == [hcfg.MBZ_NAME]
    assert cfg.clamav is not None and "27801" in cfg.clamav.version
    assert [y.version for y in cfg.yara] == ["abc123"]
    if shutil.which("clamscan") and shutil.which("yara"):
        ok, lines = build.step_check({"malwarebazaar": True, "yara": True, "nsrl": True})
        assert ok, lines

    second = _play(tmp_path, extra)
    assert second.returncode == 0, second.stdout[-3000:]
    assert _changed(second.stdout) == 0, second.stdout[-3000:]

    # Features turned off at the next import: the applied sets go away (NSRL data stays).
    off = _play(tmp_path, {"airlock_features": {}, "airlock_assets": {}})
    assert off.returncode == 0, off.stdout[-3000:]
    assert not (clam / hcfg.MBZ_HSB).exists() and not list(clam.glob("*.cvd"))
    assert not (root / "opt" / "yara" / "signature-base").exists()
