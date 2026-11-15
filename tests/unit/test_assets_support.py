"""Builders shared by the assets, provisioning and import tests: a fake AIRLOCK drive.

``FakeDrive`` lays out, under ``tmp_path``: a baked signed manifest, the public key, a staged
ASSETS partition with profile.json, a repo copy with site.yml and goss files, a lsblk fixture
with only the boot disk, fake /sys and /proc trees (offline), and stub ``ansible-playbook``,
``goss`` and ``systemctl`` commands that record their calls. A throwaway Ed25519 key is made
with openssl for every test; no key is committed.

The fake ClamAV databases are not signed by ClamAV, so a stand-in ``sigtool`` goes first on
PATH whether or not the real one is installed. It accepts only files that start with
``FAKE_CVD_MAGIC`` (the test fixtures) and fails everything when
``AIRLOCK_TEST_SIGTOOL_FAIL=1``, so the vendor-signature failure path stays tested.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

GOOD_MODEL = b"GGUF" + bytes(range(256)) * 64
GOOD_RULES = b'rule demo { strings: $a = "airlock-test" condition: $a }\n'
FAKE_CVD_MAGIC = b"ClamAV-VDB:test"
DAILY_V1 = FAKE_CVD_MAGIC + b" daily v1\n" + b"\x00" * 300
MB_V1 = b"sha256_hash\n" + b"0" * 64 + b"\n"


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def openssl(*args: str) -> None:
    subprocess.run(["openssl", *args], check=True, capture_output=True)


@dataclass
class FakeDrive:
    root: Path
    files: dict[str, bytes] = field(default_factory=dict)
    calls: Path = field(init=False)

    def __post_init__(self) -> None:
        self.calls = self.root / "calls.log"

    # ------------------------------------------------------------------ paths
    @property
    def assets(self) -> Path:
        return Path(os.environ["AIRLOCK_ASSETS_DIR"])

    @property
    def state(self) -> Path:
        return Path(os.environ["AIRLOCK_STATE_DIR"])

    @property
    def etc(self) -> Path:
        return Path(os.environ["AIRLOCK_ETC_DIR"])

    @property
    def key(self) -> Path:
        return self.root / "keys" / "signing.key.pem"

    @property
    def pub(self) -> Path:
        return self.etc / "manifest-signing.pub.pem"

    # ------------------------------------------------------------------ manifest
    def manifest(self, release: str = "v0.1.0", **overrides: bytes) -> dict[str, Any]:
        model = overrides.get("model", GOOD_MODEL)
        rules = overrides.get("rules", GOOD_RULES)
        files = [
            {"id": "clamav_daily", "url": "https://example.invalid/daily.cvd", "version": "daily",
             "size": None, "sha256": None, "target": "clamav/daily.cvd",
             "profiles": ["clamav"], "verify": "vendor_signature", "license": "GPL-2.0"},
            {"id": "malwarebazaar_full", "url": "https://example.invalid/full.txt",
             "version": "daily", "size": None, "sha256": None, "target": "hashsets/mb.txt",
             "profiles": ["malwarebazaar"], "verify": "trusted_at_staging", "license": "CC0"},
            {"id": "model_tier0", "url": "https://example.invalid/m.gguf", "version": "1",
             "size": len(model), "sha256": sha(model), "target": "models/tier0.gguf",
             "profiles": ["ai_tier0"], "verify": "sha256", "license": "Apache-2.0"},
            {"id": "yara_rules", "url": "https://example.invalid/rules.yar", "version": "abc123",
             "size": len(rules), "sha256": sha(rules), "target": "yara/rules.yar",
             "profiles": ["yara"], "verify": "sha256", "license": "DRL-1.1"},
        ]  # fmt: skip
        features = {"ai_tiers": ["tier0"], "clamav": True, "malwarebazaar": True, "yara": True}
        return {
            "schema": 1,
            "release": release,
            "files": files,
            "profiles": {
                "default": {
                    "description": "test",
                    "features": features,
                    "files": [f["id"] for f in files],
                }
            },
        }

    def write_manifest(self, path: Path, manifest: dict[str, Any], *, sign: bool = True) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        if sign:
            openssl("pkeyutl", "-sign", "-rawin", "-inkey", str(self.key), "-in", str(path),
                    "-out", f"{path}.sig")  # fmt: skip

    # ------------------------------------------------------------------ staging
    def stage(
        self,
        manifest: dict[str, Any],
        contents: dict[str, bytes],
        *,
        profile: str = "default",
        copy_manifest: bool = True,
    ) -> None:
        """Write ASSETS as the fetcher would: files/<target>, manifest, profile.json last."""
        by_id = {f["id"]: f for f in manifest["files"]}
        rows = []
        for fid, data in sorted(contents.items()):
            target = by_id[fid]["target"]
            dest = self.assets / "files" / target
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(data)
            rows.append(
                {
                    "id": fid,
                    "sha256": sha(data),
                    "target": target,
                    "verify": by_id[fid]["verify"],
                    "staged_at": "2026-11-15T00:00:00Z",
                }
            )
        if copy_manifest:
            src = self.root / "release" / "manifest.json"
            self.write_manifest(src, manifest)
            (self.assets / "manifest.json").write_bytes(src.read_bytes())
            (self.assets / "manifest.json.sig").write_bytes(Path(f"{src}.sig").read_bytes())
        doc = {
            "schema": 1, "profile": profile,
            "features": manifest["profiles"][profile]["features"],
            "staged_at": "2026-11-15T00:00:00Z", "fetcher": "test 0", "files": rows,
            "skipped": [], "case_defaults": {"examiner": "", "agency": "", "case_id_prefix": ""},
        }  # fmt: skip
        (self.assets / "profile.json").write_text(json.dumps(doc, sort_keys=True), "utf-8")

    def default_contents(self) -> dict[str, bytes]:
        return {
            "clamav_daily": DAILY_V1,
            "malwarebazaar_full": MB_V1,
            "model_tier0": GOOD_MODEL,
            "yara_rules": GOOD_RULES,
        }

    # ------------------------------------------------------------------ host fakes
    def set_disks(self, extra: bool = False) -> None:
        disks: list[dict[str, Any]] = [
            {"name": "sda", "path": "/dev/sda", "type": "disk", "size": 64_000_000_000,
             "ro": False, "rm": True, "tran": "usb", "mountpoints": [None],
             "children": [{"name": "sda5", "path": "/dev/sda5", "type": "part",
                           "size": 30_000_000_000, "mountpoints": ["/"]}]},
        ]  # fmt: skip
        if extra:
            disks.append({"name": "sdb", "path": "/dev/sdb", "type": "disk",
                          "size": 500_000_000_000, "ro": True, "rm": False, "tran": "sata",
                          "mountpoints": [None]})  # fmt: skip
        fixture = self.root / "lsblk.json"
        fixture.write_text(json.dumps({"blockdevices": disks}), encoding="utf-8")

    def set_network(self, *, up: bool = False, default_route: bool = False) -> None:
        net = self.root / "sys" / "class" / "net"
        for name in ("lo", "eth0"):
            d = net / name
            d.mkdir(parents=True, exist_ok=True)
            is_up = name == "lo" or up
            (d / "flags").write_text("0x1003\n" if is_up else "0x1002\n", encoding="utf-8")
            (d / "operstate").write_text("up\n" if is_up else "down\n", encoding="utf-8")
        route = self.root / "proc" / "net" / "route"
        route.parent.mkdir(parents=True, exist_ok=True)
        lines = ["Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT"]
        if default_route:
            lines.append("eth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0")
        route.write_text("\n".join(lines) + "\n", encoding="utf-8")
        (route.parent / "ipv6_route").write_text(
            "00000000000000000000000000000000 00 00000000000000000000000000000000 00 "
            "00000000000000000000000000000000 ffffffff 00000001 00000000 00200200 lo\n",
            encoding="utf-8",
        )
        (self.root / "proc" / "cpuinfo").write_text("model name\t: Test CPU\n", "utf-8")
        (self.root / "proc" / "meminfo").write_text("MemTotal:       16384 kB\n", "utf-8")


STUB_ANSIBLE = """#!/usr/bin/env bash
set -euo pipefail
printf 'ansible-playbook %s\\n' "$*" >>"$AIRLOCK_TEST_CALLS"
for a in "$@"; do
  case "$a" in @*) cp -- "${a#@}" "$AIRLOCK_TEST_CALLS.vars.json" ;; esac
done
if [[ -n "${AIRLOCK_TEST_ANSIBLE_FAIL_ONCE:-}" && ! -e "$AIRLOCK_TEST_ANSIBLE_FAIL_ONCE" ]]; then
  : >"$AIRLOCK_TEST_ANSIBLE_FAIL_ONCE"
  echo "TASK [demo] fatal: simulated failure"
  exit 2
fi
echo "PLAY RECAP localhost ok=1 changed=0 failed=0"
"""
STUB_GOSS = """#!/usr/bin/env bash
set -euo pipefail
printf 'goss %s\\n' "$*" >>"$AIRLOCK_TEST_CALLS"
if [[ "${AIRLOCK_TEST_GOSS_FAIL:-0}" == 1 ]]; then
  echo '{"summary": {"failed-count": 1, "test-count": 3}}'
  exit 1
fi
echo '{"summary": {"failed-count": 0, "test-count": 3}}'
"""
STUB_SYSTEMCTL = """#!/usr/bin/env bash
printf 'systemctl %s\\n' "$*" >>"$AIRLOCK_TEST_CALLS"
"""
# Stand-in for ClamAV's sigtool: "Verification OK" only for the fake fixture databases.
STUB_SIGTOOL = """#!/usr/bin/env bash
set -euo pipefail
path=""
for a in "$@"; do
  case "$a" in --info=*) path="${a#--info=}" ;; esac
done
printf 'sigtool %s\\n' "$*" >>"$AIRLOCK_TEST_CALLS.sigtool"
printf 'File: %s\\nBuild time: 15 Nov 2026 00:00 +0000\\nVersion: 1\\n' "$path"
if [[ "${AIRLOCK_TEST_SIGTOOL_FAIL:-0}" != 1 && -n "$path" ]] \\
   && [[ "$(head -c 15 -- "$path")" == "ClamAV-VDB:test" ]]; then
  echo "Verification OK."
  exit 0
fi
echo "ERROR: Verification failed"
exit 1
"""


def build_drive(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> FakeDrive:
    """Every AIRLOCK_* path under tmp_path, a signed baked manifest, staged ASSETS, stubs."""
    for name, sub in {
        "AIRLOCK_OPT_DIR": "opt",
        "AIRLOCK_ETC_DIR": "etc",
        "AIRLOCK_STATE_DIR": "state",
        "AIRLOCK_SESSION_DIR": "session",
        "AIRLOCK_ASSETS_DIR": "assets",
        "AIRLOCK_OUTPUT_DIR": "output",
        "AIRLOCK_REPO_DIR": "repo",
    }.items():
        d = tmp_path / sub
        d.mkdir(parents=True, exist_ok=True)
        monkeypatch.setenv(name, str(d))
    drive = FakeDrive(tmp_path)
    drive.key.parent.mkdir(parents=True)
    openssl("genpkey", "-algorithm", "ed25519", "-out", str(drive.key))
    openssl("pkey", "-in", str(drive.key), "-pubout", "-out", str(drive.pub))
    manifest = drive.manifest()
    drive.write_manifest(drive.state / "manifest.json", manifest)
    drive.stage(manifest, drive.default_contents())
    repo = tmp_path / "repo"
    (repo / "ansible").mkdir(parents=True, exist_ok=True)
    for name in ("site.yml", "inventory.ini", "ansible.cfg"):
        (repo / "ansible" / name).write_text("# test\n", encoding="utf-8")
    (repo / "tests" / "goss").mkdir(parents=True, exist_ok=True)
    (repo / "tests" / "goss" / "base.yaml").write_text("file: {}\n", encoding="utf-8")
    stubs = tmp_path / "stubs"
    stubs.mkdir()
    for name, body in (("ansible-playbook", STUB_ANSIBLE), ("goss", STUB_GOSS),
                       ("systemctl", STUB_SYSTEMCTL), ("sigtool", STUB_SIGTOOL)):  # fmt: skip
        (stubs / name).write_text(body, encoding="utf-8")
        (stubs / name).chmod(0o755)
    monkeypatch.setenv("PATH", f"{stubs}:{os.environ['PATH']}")
    monkeypatch.setenv("AIRLOCK_TEST_CALLS", str(drive.calls))
    drive.set_disks()
    drive.set_network()
    monkeypatch.setenv("AIRLOCK_LSBLK_JSON", str(tmp_path / "lsblk.json"))
    monkeypatch.setenv("AIRLOCK_SYSFS_DIR", str(tmp_path / "sys"))
    monkeypatch.setenv("AIRLOCK_PROC_DIR", str(tmp_path / "proc"))
    monkeypatch.setenv("AIRLOCK_ALLOW_NONROOT", "1")
    return drive


@pytest.fixture
def drive(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> FakeDrive:
    return build_drive(tmp_path, monkeypatch)


def session_events(drive: FakeDrive) -> list[dict[str, Any]]:
    log = Path(os.environ["AIRLOCK_SESSION_DIR"]) / "current.log"
    if not log.exists():
        return []
    return [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines() if line]


def test_fake_drive_is_consistent(drive: FakeDrive) -> None:
    """The builder itself: the staged files match the signed baked manifest."""
    manifest = json.loads((drive.state / "manifest.json").read_text(encoding="utf-8"))
    profile = json.loads((drive.assets / "profile.json").read_text(encoding="utf-8"))
    pinned = {f["id"]: f["sha256"] for f in manifest["files"] if f["sha256"]}
    for row in profile["files"]:
        if row["id"] in pinned:
            assert row["sha256"] == pinned[row["id"]]
    assert (drive.state / "manifest.json.sig").stat().st_size == 64
