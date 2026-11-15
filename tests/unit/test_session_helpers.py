"""Unit tests for airlock_session (tasks 4.10, 4.11, 4.15, 4F.6, 2B.14, 3A.3, 4C.22, risk 14)."""

from __future__ import annotations

import builtins
import datetime as dt
import hashlib
import json
import sys
import types
from pathlib import Path

import pytest

from airlock_common import jsonio, proc, ui
from airlock_session import common, hashcmd, mount, start, system, triage, unlock

REPO = Path(__file__).resolve().parents[2]
PYLIB = REPO / "ansible" / "roles" / "session_tools" / "files" / "pylib"
BIN = REPO / "ansible" / "roles" / "session_tools" / "files" / "bin"

MMLS_DOS = """DOS Partition Table
Offset Sector: 0
Units are in 512-byte sectors

      Slot      Start        End          Length       Description
000:  Meta      0000000000   0000000000   0000000001   Primary Table (#0)
001:  -------   0000000000   0000002047   0000002048   Unallocated
002:  000:000   0000002048   0000043007   0000040960   Linux (0x83)
003:  000:001   0000043008   0000131071   0000088064   NTFS / exFAT (0x07)
"""

MMLS_GPT_4K = """GUID Partition Table (EFI)
Offset Sector: 0
Units are in 4096-byte sectors

      Slot      Start        End          Length       Description
000:  Meta      0000000000   0000000000   0000000001   Safety Table
002:  Meta      0000000001   0000000001   0000000001   GPT Header
004:  000       0000000256   0000004351   0000004096
"""


def read_log(env: Path) -> list[dict]:
    path = env / "session" / "current.log"
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def events(env: Path) -> list[str]:
    return [r["event"] for r in read_log(env)]


def last(env: Path, event: str) -> dict:
    return [r for r in read_log(env) if r["event"] == event][-1]


# ------------------------------------------------------------------ triage parsing


def test_parse_mmls_dos() -> None:
    sector, slots = triage.parse_mmls(MMLS_DOS)
    assert sector == 512
    alloc = [s for s in slots if s.allocated]
    assert [(s.start, s.length, s.description) for s in alloc] == [
        (2048, 40960, "Linux (0x83)"),
        (43008, 88064, "NTFS / exFAT (0x07)"),
    ]
    assert len(slots) == 4


def test_parse_mmls_gpt_4k_and_empty_description() -> None:
    sector, slots = triage.parse_mmls(MMLS_GPT_4K)
    assert sector == 4096
    alloc = [s for s in slots if s.allocated]
    assert len(alloc) == 1
    assert (alloc[0].slot, alloc[0].start, alloc[0].description) == ("000", 256, "")


def test_parse_fstype() -> None:
    text = "FILE SYSTEM INFORMATION\n------\nFile System Type: NTFS\nVolume Serial: 1\n"
    assert triage.parse_fstype(text) == "NTFS"
    assert triage.parse_fstype("garbage") == ""


def test_dissect_summary_both_forms() -> None:
    info = {"hostname": "PC1", "os_family": "windows", "ips": [], "domain": None}
    assert triage.dissect_summary(info) == {
        "hostname": "PC1",
        "os_family": "windows",
        "domain": None,
    }
    rows = [
        {"_type": "recorddescriptor", "_data": []},
        {"_type": "record", "name": "hostname", "value": "PC2"},
        {"_type": "record", "name": "os", "value": "windows"},
    ]
    assert triage.dissect_summary(rows) == {"hostname": "PC2", "os": "windows"}
    assert triage.dissect_summary(None) == {}


def test_fsstat_uses_sector_size_and_offset(airlock_env: Path, monkeypatch) -> None:
    calls: list[list[str]] = []

    def fake_run(argv, **_kw):
        calls.append(list(argv))
        return proc.Result(list(argv), 0, "File System Type: Ext4\n", "")

    monkeypatch.setattr(proc, "which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(proc, "run", fake_run)
    info = common.TargetInfo("/x.img", "image", 1 << 24)
    _, slots = triage.parse_mmls(MMLS_GPT_4K)
    vols = triage.run_fsstat(info, 4096, slots, 10)
    assert calls == [["fsstat", "-b", "4096", "-o", "256", "/x.img"]]
    assert vols[0]["offset_bytes"] == 256 * 4096
    assert vols[0]["fs_type"] == "Ext4"
    assert last(airlock_env, "triage_fsstat")["status"] == "filesystem"


# ------------------------------------------------------------------ image age (4F.6)


def write_build_info(env: Path, data: object) -> None:
    (env / "etc" / "build-info.json").write_text(json.dumps(data), encoding="utf-8")


def test_image_age_statuses(airlock_env: Path) -> None:
    now = dt.datetime(2026, 11, 15, 12, 0, tzinfo=dt.UTC)
    assert system.image_age(90, now)["status"] == "missing"
    write_build_info(airlock_env, {"build_date": "2026-11-01T00:00:00Z", "version": "0.1.0"})
    age = system.image_age(90, now)
    assert (age["status"], age["age_days"], age["too_old"], age["version"]) == (
        "ok",
        14,
        False,
        "0.1.0",
    )
    write_build_info(airlock_env, {"build_date": "2026-08-01T00:00:00Z"})
    age = system.image_age(90, now)
    assert (age["status"], age["age_days"], age["too_old"]) == ("too_old", 106, True)
    assert system.image_age(200, now)["status"] == "ok"
    write_build_info(airlock_env, {"build_date": "unknown"})
    assert system.image_age(90, now)["status"] == "unknown_date"
    write_build_info(airlock_env, {"build_date": "2027-06-01T00:00:00Z"})
    assert system.image_age(90, now)["status"] == "clock_before_build"
    (airlock_env / "etc" / "build-info.json").write_text("{nope", encoding="utf-8")
    assert system.image_age(90, now)["status"] == "unreadable"


def test_load_config(airlock_env: Path) -> None:
    cfg = common.load_config()
    assert cfg["image_max_age_days"] == 90
    assert cfg["cases_dir"] == str(airlock_env / "output" / "cases")
    (airlock_env / "etc" / "airlock.conf.json").write_text(
        json.dumps({"image_max_age_days": 30, "nsrl_path": "/n"}), encoding="utf-8"
    )
    cfg = common.load_config()
    assert (cfg["image_max_age_days"], cfg["nsrl_path"]) == (30, "/n")
    (airlock_env / "etc" / "airlock.conf.json").write_text("[1]", encoding="utf-8")
    assert "config_error" in common.load_config()


# ------------------------------------------------------------------ clocks (4.15)


def test_hardware_clock_hwclock_then_sysfs(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(proc, "which", lambda name: "/sbin/hwclock" if name == "hwclock" else None)

    def fake_run(argv, **_kw):
        assert argv == ["hwclock", "--show", "--utc"]
        return proc.Result(list(argv), 0, "2026-11-15 10:00:00.500000+00:00\n", "")

    monkeypatch.setattr(proc, "run", fake_run)
    hw = system.hardware_clock()
    assert (hw["source"], hw["utc"]) == ("hwclock", "2026-11-15T10:00:00.500000Z")

    def failing(argv, **_kw):
        raise proc.ToolError("hwclock exited 1: Cannot access the Hardware Clock")

    monkeypatch.setattr(proc, "run", failing)
    rtc = tmp_path / "class" / "rtc" / "rtc0"
    rtc.mkdir(parents=True)
    (rtc / "date").write_text("2026-11-15\n")
    (rtc / "time").write_text("10:00:01\n")
    monkeypatch.setenv("AIRLOCK_SYSFS", str(tmp_path))
    hw = system.hardware_clock()
    assert (hw["source"], hw["utc"]) == ("sysfs", "2026-11-15T10:00:01Z")
    assert "Cannot access" in hw["errors"][0]
    monkeypatch.setenv("AIRLOCK_SYSFS", str(tmp_path / "none"))
    assert system.hardware_clock()["source"] == "none"


def test_local_time_heuristic() -> None:
    assert system.looks_like_local_time(3600.0)
    assert system.looks_like_local_time(-19800.0 + 20)  # UTC+5:30, 20 s drift
    assert not system.looks_like_local_time(30.0)
    assert not system.looks_like_local_time(1234.0)
    assert not system.looks_like_local_time(None)


def test_parse_reference() -> None:
    assert start.parse_reference("2026-11-15T09:30:00Z") == dt.datetime(
        2026, 11, 15, 9, 30, tzinfo=dt.UTC
    )
    assert start.parse_reference("2026-11-15 10:30:00+01:00") == dt.datetime(
        2026, 11, 15, 9, 30, tzinfo=dt.UTC
    )
    with pytest.raises(ValueError, match="Z at the end"):
        start.parse_reference("2026-11-15T09:30:00")
    with pytest.raises(ValueError, match="not a date"):
        start.parse_reference("yesterday Z")
    with pytest.raises(ValueError, match="empty"):
        start.parse_reference("  ")


# ------------------------------------------------------------------ ASSETS check (2B.14)


def test_asset_check_unavailable_and_failed(monkeypatch) -> None:
    real_import = system.importlib.import_module

    def missing(name: str):
        if name == "airlock_common.assets":
            raise ImportError("No module named 'airlock_common.assets'")
        return real_import(name)

    monkeypatch.setattr(system.importlib, "import_module", missing)
    event, data = system.asset_check(deep=True)
    assert event == "asset_check_unavailable"
    assert "ImportError" in data["reason"]

    monkeypatch.setattr(system.importlib, "import_module", lambda _n: types.SimpleNamespace())
    assert system.asset_check()[0] == "asset_check_unavailable"

    def boom(*, deep: bool):
        raise OSError("ASSETS not mounted")

    mod = types.SimpleNamespace(verify_staged=boom)
    monkeypatch.setattr(system.importlib, "import_module", lambda _n: mod)
    event, data = system.asset_check()
    assert event == "asset_check_failed"
    assert "ASSETS not mounted" in data["reason"]


def test_asset_check_report(monkeypatch) -> None:
    seen: list[bool] = []

    class Report:
        ok = False
        checked = ("a",)
        problems = (("model_x", "sha256 mismatch"),)
        disabled_features = ("ai_tier2",)

        def to_dict(self) -> dict:
            return {
                "ok": self.ok,
                "checked": list(self.checked),
                "problems": [list(p) for p in self.problems],
                "disabled_features": list(self.disabled_features),
            }

    def verify(*, deep: bool) -> Report:
        seen.append(deep)
        return Report()

    monkeypatch.setattr(
        system.importlib, "import_module", lambda _n: types.SimpleNamespace(verify_staged=verify)
    )
    event, data = system.asset_check(deep=False)
    assert event == "asset_check"
    assert seen == [False]
    assert data["deep"] is False
    assert data["problems"] == [["model_x", "sha256 mismatch"]]
    warn = start._asset_warnings(event, data)
    assert "model_x" in warn[0]
    assert "ai_tier2" in warn[0]
    assert "fetcher" in warn[0]


# ------------------------------------------------------------------ disks, radios, network


def fake_tree(tmp_path: Path, monkeypatch) -> Path:
    tree = {
        "blockdevices": [
            {
                "name": "sda",
                "path": "/dev/sda",
                "type": "disk",
                "size": 64 << 30,
                "ro": False,
                "rm": True,
                "children": [
                    {"name": "sda1", "type": "part", "size": 1, "ro": False, "mountpoints": ["/"]}
                ],
            },
            {
                "name": "sdb",
                "path": "/dev/sdb",
                "type": "disk",
                "size": 500 << 30,
                "ro": True,
                "rm": False,
                "model": "Disk B",
                "serial": "SB",
                "children": [{"name": "sdb1", "path": "/dev/sdb1", "type": "part", "size": 2}],
            },
            {"name": "zram0", "path": "/dev/zram0", "type": "disk", "size": 0, "ro": False},
        ]
    }
    path = tmp_path / "lsblk.json"
    path.write_text(json.dumps(tree), encoding="utf-8")
    monkeypatch.setenv("AIRLOCK_LSBLK_JSON", str(path))
    sysfs = tmp_path / "sys"
    for name, ro in {"sda": 0, "sda1": 0, "sdb": 0, "sdb1": 1}.items():
        d = sysfs / "class" / "block" / name
        d.mkdir(parents=True)
        (d / "ro").write_text(f"{ro}\n")
    monkeypatch.setenv("AIRLOCK_SYSFS", str(sysfs))
    monkeypatch.setenv("AIRLOCK_RUN_DIR", str(tmp_path / "run"))
    return sysfs


def test_readonly_flags(tmp_path: Path, monkeypatch) -> None:
    fake_tree(tmp_path, monkeypatch)
    flags = system.readonly_flags()
    assert flags["boot_disk"] == "/dev/sda"
    assert flags["writable_unexpected"] == ["/dev/sdb"]  # sysfs wins over lsblk's stale RO
    names = [d["name"] for d in flags["devices"]]
    assert names == ["sda", "sda1", "sdb", "sdb1"]
    marker = tmp_path / "run" / "rw-allow"
    marker.mkdir(parents=True)
    (marker / "sdb").write_text("{}")
    flags = system.readonly_flags()
    assert flags["writable_unexpected"] == []
    assert all(d["unlocked_for_output"] for d in flags["devices"] if d["disk"] == "sdb")


def test_rfkill_and_network(tmp_path: Path, monkeypatch) -> None:
    sysfs = tmp_path / "sys"
    procfs = tmp_path / "proc"
    r = sysfs / "class" / "rfkill" / "rfkill0"
    r.mkdir(parents=True)
    (r / "type").write_text("bluetooth\n")
    (r / "soft").write_text("1\n")
    (r / "hard").write_text("0\n")
    for name, flags in {"lo": "0x9", "eth0": "0x1002", "wlan0": "0x1003"}.items():
        n = sysfs / "class" / "net" / name
        n.mkdir(parents=True)
        (n / "flags").write_text(flags + "\n")
    (sysfs / "class" / "net" / "wlan0" / "wireless").mkdir()
    (procfs / "net").mkdir(parents=True)
    (procfs / "net" / "route").write_text(
        "Iface\tDestination\tGateway\nwlan0\t00000000\t0101A8C0\nwlan0\t0001A8C0\t00000000\n"
    )
    monkeypatch.setenv("AIRLOCK_SYSFS", str(sysfs))
    monkeypatch.setenv("AIRLOCK_PROCFS", str(procfs))
    rf = system.rfkill_state()
    assert rf["unblocked"] == []
    (r / "soft").write_text("0\n")
    assert system.rfkill_state()["unblocked"] == ["rfkill0 (bluetooth)"]
    net = system.network_state()
    assert net["up_besides_loopback"] == ["wlan0"]
    assert net["default_routes"] == ["ipv4 via wlan0"]
    assert net["ok"] is False
    assert [i["wireless"] for i in net["interfaces"]] == [False, False, True]


def test_tool_versions(monkeypatch) -> None:
    cmds = (
        ("python3", (sys.executable, "--version")),
        ("nothere", ("airlock-no-such-tool-xyz", "--version")),
    )
    out = system.tool_versions(cmds, ("airlock-no-such-package-xyz",))
    assert out["commands"]["python3"]["status"] == "present"
    assert out["commands"]["python3"]["version"].startswith("Python 3")
    assert out["commands"]["nothere"] == {"status": "absent"}
    assert out["packages"]["airlock-no-such-package-xyz"] in {"absent", "unknown (no dpkg-query)"}


def _role_defaults() -> dict:
    import yaml  # noqa: PLC0415 - test-only dependency

    out: dict = {}
    for f in sorted((REPO / "ansible" / "roles").glob("tools_*/defaults/main.yml")):
        out.update(yaml.safe_load(f.read_text(encoding="utf-8")) or {})
    return out


def test_version_table_matches_tool_roles() -> None:
    """Every command and package logged at session start is one a tools role installs."""
    d = _role_defaults()
    installed = {"python3"}
    for key, value in d.items():
        if key.endswith("_packages") and isinstance(value, list):
            installed |= {str(v) for v in value}
    # Pinned .deb files: the package name starts the file name (dotnet-runtime-9.0_9.0.4-1...).
    import yaml  # noqa: PLC0415

    pins = yaml.safe_load((REPO / "ansible/group_vars/all/pins.yml").read_text(encoding="utf-8"))
    for pin in pins["pins"].values():
        url = str(pin.get("url") or "")
        if url.endswith(".deb"):
            installed.add(url.rsplit("/", 1)[-1].split("_", 1)[0])
    missing = [p for p in system.DPKG_PACKAGES if p not in installed]
    assert missing == [], f"not installed by any tools role: {missing}"
    assert "bulk-extractor" not in system.DPKG_PACKAGES  # built from source (tools_carve)

    names = {name: argv for name, argv in system.VERSION_COMMANDS}
    for cmd in ("log2timeline", "psort"):
        assert cmd in d["tools_timeline_commands"] and cmd in names
    assert not [n for n in names if n.endswith(".py")]
    assert "target-query" in d["tools_dissect_commands"]
    assert names["llama-server"][0] == d["tools_ai_llama_prefix"] + "/bin/llama-server"
    assert "llama-server" in d["tools_ai_llama_targets"]
    ez = [t["name"] for t in d["tools_eztools_tools"]]
    assert list(system.EZTOOLS) == ez
    for tool in ez:
        assert names[tool] == (tool, "--version")
    assert {"clamav", "yara"} <= set(d["tools_hashsets_packages"])
    assert names["clamscan"][0] == "clamscan" and names["yara"][0] == "yara"
    assert "bulk_extractor" in names and "photorec" in names


# ------------------------------------------------------------------ forensic-session-start


def no_dialogs(monkeypatch, answers: list[str]) -> None:
    monkeypatch.setattr(ui, "interactive", lambda: True)
    monkeypatch.setattr(ui, "_whiptail", lambda: None)
    feed = iter(answers)
    monkeypatch.setattr(builtins, "input", lambda _prompt="": next(feed))
    monkeypatch.setattr(system, "tool_versions", lambda: {"commands": {}, "packages": {}})
    monkeypatch.setattr(system, "asset_check", lambda deep=True: ("asset_check", {"ok": True}))


def test_start_interactive_prompts(airlock_env: Path, tmp_path: Path, monkeypatch, capsys) -> None:
    fake_tree(tmp_path, monkeypatch)
    no_dialogs(
        monkeypatch,
        [
            "y",  # authority
            "n",  # clock not right
            "not a time",  # rejected
            "2030-01-01T00:00:00Z",  # reference
            "",  # source -> default
            "1",  # write blocker: yes
            "Example blocker",  # model
        ],
    )
    assert start.main([]) == 0
    ev = events(airlock_env)
    assert ev[0] == "session_start"
    assert ev[1] == "authority_ack"
    assert ev[-1] == "session_ready"
    assert last(airlock_env, "authority_ack")["via"] == "prompt"
    clock = last(airlock_env, "clock_check")
    assert (clock["status"], clock["via"]) == ("reference_entered", "prompt")
    assert clock["reference_source"] == "operator's trusted clock"
    assert clock["offset_seconds"] > 0
    assert clock["system_time_changed"] is False
    wb = last(airlock_env, "write_blocker")
    assert (wb["answer"], wb["model"], wb["via"]) == ("yes", "Example blocker", "prompt")
    out = capsys.readouterr().out
    assert "no time zone" in out


def test_start_authority_declined(airlock_env: Path, tmp_path: Path, monkeypatch, capsys) -> None:
    fake_tree(tmp_path, monkeypatch)
    no_dialogs(monkeypatch, ["n"])
    assert start.main([]) == 1
    ev = events(airlock_env)
    assert ev[:2] == ["session_start", "authority_declined"]
    assert "session_ready" not in ev
    assert "not confirmed" in capsys.readouterr().err


def test_start_clock_ok_prompt_and_unknown_blocker(
    airlock_env: Path, tmp_path: Path, monkeypatch
) -> None:
    fake_tree(tmp_path, monkeypatch)
    no_dialogs(monkeypatch, ["y", "", "3"])  # authority, clock right (default yes), unknown
    assert start.main([]) == 0
    assert last(airlock_env, "clock_check")["status"] == "confirmed"
    assert last(airlock_env, "write_blocker")["answer"] == "unknown"
    warnings = last(airlock_env, "session_ready")["warnings"]
    assert any("No hardware write blocker" in w for w in warnings)


def test_start_flags_skip_every_prompt(airlock_env: Path, tmp_path: Path, monkeypatch) -> None:
    fake_tree(tmp_path, monkeypatch)
    no_dialogs(monkeypatch, [])  # any prompt would raise StopIteration
    code = start.main(
        ["--authority-ack", "--clock-ok", "--write-blocker", "no", "--quick-asset-check"]
    )
    assert code == 0
    assert last(airlock_env, "write_blocker")["via"] == "flag"


# ------------------------------------------------------------------ evidence-unlock-output


def test_unlock_resolve(tmp_path: Path, monkeypatch) -> None:
    fake_tree(tmp_path, monkeypatch)
    disk, _ = unlock.resolve_disk("/dev/sdb")
    assert disk.name == "sdb"
    assert unlock.resolve_disk("sdb")[0].name == "sdb"
    with pytest.raises(common.CommandError, match="partition"):
        unlock.resolve_disk("/dev/sdb1")
    with pytest.raises(common.CommandError, match="no drive called"):
        unlock.resolve_disk("/dev/sdq")
    assert unlock._names_match("sdb", disk)
    assert unlock._names_match(" /dev/sdb ", disk)
    assert not unlock._names_match("sdc", disk)
    assert not unlock._names_match("", disk)
    assert "Disk B" in unlock.describe(disk)
    assert "serial SB" in unlock.describe(disk)


def test_unlock_needs_root(airlock_env: Path, monkeypatch, capsys) -> None:
    monkeypatch.setattr(common.os, "geteuid", lambda: 1000)
    assert unlock.main(["/dev/sdb", "--confirm", "sdb"]) == 1
    assert "needs root" in capsys.readouterr().err


def test_run_dir_from_paths(monkeypatch) -> None:
    from airlock_common import paths  # noqa: PLC0415

    monkeypatch.delenv("AIRLOCK_RUN_DIR", raising=False)
    assert paths.run_dir() == Path("/run/airlock")
    assert paths.rw_allow_dir() == Path("/run/airlock/rw-allow")
    monkeypatch.setenv("AIRLOCK_RUN_DIR", "/tmp/x-run")
    assert paths.rw_allow_dir() == Path("/tmp/x-run/rw-allow")


def _unlock_env(airlock_env: Path, tmp_path: Path, monkeypatch, *, fail: bool = False) -> list:
    """Root, the fake tree, and a blockdev stand-in that flips the fake sysfs ro flags."""
    sysfs = fake_tree(tmp_path, monkeypatch)
    monkeypatch.setattr(common.os, "geteuid", lambda: 0)
    calls: list = []

    def fake_blockdev(flag: str, dev_path: str) -> None:
        calls.append((flag, dev_path))
        if fail:
            raise proc.ToolError("blockdev exited 1: Permission denied")
        name = dev_path.rsplit("/", 1)[-1]
        (sysfs / "class" / "block" / name / "ro").write_text("0\n" if flag == "--setrw" else "1\n")

    monkeypatch.setattr(unlock, "_blockdev", fake_blockdev)
    return calls


def test_unlock_writes_and_removes_rw_allow_marker(
    airlock_env: Path, tmp_path: Path, monkeypatch
) -> None:
    calls = _unlock_env(airlock_env, tmp_path, monkeypatch)
    marker = tmp_path / "run" / "rw-allow" / "sdb"  # the kernel name airlock-setro checks
    assert unlock.main(["/dev/sdb", "--confirm", "sdb"]) == 0
    assert marker.is_file()
    assert json.loads(marker.read_text(encoding="utf-8"))["device"] == "/dev/sdb"
    assert ("--setrw", "/dev/sdb") in calls and ("--setrw", "/dev/sdb1") in calls
    assert last(airlock_env, "output_unlocked")["marker"] == str(marker)
    # readonly_flags (session start) now treats sdb as unlocked, not unexpectedly writable.
    assert system.readonly_flags()["writable_unexpected"] == []
    assert unlock.main(["/dev/sdb", "--lock"]) == 0
    assert not marker.exists()
    assert ("--setro", "/dev/sdb1") in calls


def test_unlock_failure_leaves_no_marker(airlock_env: Path, tmp_path: Path, monkeypatch) -> None:
    _unlock_env(airlock_env, tmp_path, monkeypatch, fail=True)
    assert unlock.main(["/dev/sdb", "--confirm", "sdb"]) == 1
    assert not (tmp_path / "run" / "rw-allow" / "sdb").exists()


# ------------------------------------------------------------------ evidence-mount (3A.3)


def test_mount_options_per_filesystem(tmp_path: Path) -> None:
    mp = tmp_path / "m"
    argv, opts = mount.mount_command("ext4", "/dev/loop9", mp)
    assert opts == "ro,noexec,nosuid,nodev,noload"
    assert argv == [
        "mount",
        "-t",
        "ext4",
        "-o",
        "ro,noexec,nosuid,nodev,noload",
        "/dev/loop9",
        str(mp),
    ]
    assert mount.mount_command("ext3", "/dev/loop9", mp)[1].endswith(",noload")
    assert mount.mount_command("ext2", "/dev/loop9", mp)[0][2] == "ext4"
    assert mount.mount_command("xfs", "/dev/loop9", mp)[1] == "ro,noexec,nosuid,nodev,norecovery"
    assert "rescue=nologreplay" in mount.mount_command("btrfs", "/dev/loop9", mp)[1]
    argv, _ = mount.mount_command("ntfs", "/dev/loop9", mp)
    assert argv[:3] == ["ntfs-3g", "-o", "ro,noexec,nosuid,nodev"]
    assert mount.mount_command("vfat", "/dev/loop9", mp)[1] == "ro,noexec,nosuid,nodev"
    for bad in ("", "LVM2_member", "crypto_LUKS", "swap"):
        with pytest.raises(common.CommandError, match="does not mount"):
            mount.mount_command(bad, "/dev/loop9", mp)
    for _, (_, extra) in mount.KERNEL_FS.items():
        assert "rw" not in extra.split(",")


def test_mount_check_image_refusals(tmp_path: Path) -> None:
    e01 = tmp_path / "x.E01"
    e01.write_bytes(mount.EWF_MAGIC + b"\0" * 64)
    with pytest.raises(common.CommandError, match="ewfmount"):
        mount.check_image(str(e01))
    with pytest.raises(common.CommandError, match="does not exist"):
        mount.check_image(str(tmp_path / "nope.img"))
    with pytest.raises(common.CommandError, match="not an image file"):
        mount.check_image(str(tmp_path))
    with pytest.raises(common.CommandError, match="not an image file"):
        mount.check_image("/dev/null")
    ok = tmp_path / "ok.img"
    ok.write_bytes(b"\0" * 1024)
    assert mount.check_image(str(ok)) == ok.resolve()


def test_mount_partition_choice(tmp_path: Path, monkeypatch) -> None:
    img = tmp_path / "d.img"
    img.write_bytes(b"\0" * 4096)
    monkeypatch.setattr(mount, "probe", lambda _p: {"PTTYPE": "gpt"})
    parts = [
        {"number": 1, "offset_bytes": 1048576, "size_bytes": 1 << 20, "type": "x"},
        {"number": 2, "offset_bytes": 2097152, "size_bytes": 1 << 20, "type": "y"},
    ]
    monkeypatch.setattr(mount, "partitions", lambda _i: parts)
    with pytest.raises(common.CommandError, match="--partition N"):
        mount.choose_volume(img, None)
    assert mount.choose_volume(img, 2)["offset_bytes"] == 2097152
    with pytest.raises(common.CommandError, match="no partition 5"):
        mount.choose_volume(img, 5)
    monkeypatch.setattr(mount, "partitions", lambda _i: parts[:1])
    assert mount.choose_volume(img, None)["number"] == 1
    monkeypatch.setattr(mount, "probe", lambda _p: {"TYPE": "ext4"})
    whole = mount.choose_volume(img, None)
    assert (whole["offset_bytes"], whole["size_bytes"]) == (0, 4096)
    with pytest.raises(common.CommandError, match="without --partition"):
        mount.choose_volume(img, 1)


# ------------------------------------------------------------------ evidence-hash


def test_hash_target_logs(airlock_env: Path, tmp_path: Path) -> None:
    img = tmp_path / "a.raw"
    img.write_bytes(b"airlock" * 1000)
    info = common.describe_target(str(img))
    rec = hashcmd.hash_target(info, hashcmd.algorithms(True))
    data = img.read_bytes()
    assert rec["hashes"] == {
        "sha256": hashlib.sha256(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),  # noqa: S324 -- evidence hash, not security
        "md5": hashlib.md5(data).hexdigest(),  # noqa: S324
    }
    logged = last(airlock_env, "evidence_hash")
    assert logged["hashes"] == rec["hashes"]
    assert logged["target"]["kind"] == "image"
    assert events(airlock_env)[:2] == ["session_start", "session_implicit"]


def test_log_renames_reserved_fields(airlock_env: Path) -> None:
    common.log("x", "demo", tool="evil", ts="1", event="e", pid=0, ok=True)
    rec = last(airlock_env, "demo")
    assert rec["tool"] == "x"
    assert (rec["field_tool"], rec["field_ts"], rec["field_event"]) == ("evil", "1", "e")


def test_clean_output_caps_and_strips_colour() -> None:
    text, cut = common.clean_output("\x1b[33mwarning\x1b[0m ok")
    assert (text, cut) == ("warning ok", False)
    text, cut = common.clean_output("x" * 100, cap=10)
    assert (text, cut) == ("x" * 10, True)


# ------------------------------------------------------------------ wording and wrappers


def test_wording_never_calls_the_software_policy_a_write_blocker() -> None:
    """Hard rule 7: every 'write blocker' on screen is the hardware kind or a negation."""
    sources = [*sorted((PYLIB / "airlock_session").glob("*.py"))]
    for path in sources:
        text = path.read_text(encoding="utf-8").lower().replace("\n", " ")
        text = " ".join(text.split())
        idx = text.find("write blocker")
        while idx != -1:
            before = text[max(0, idx - 60) : idx]
            assert "hardware" in before or "not a" in before or "substitute for a" in before, (
                f"{path.name}: '...{text[max(0, idx - 60) : idx + 13]}'"
            )
            idx = text.find("write blocker", idx + 1)


def test_wrappers_follow_the_contract() -> None:
    for name, module in {
        "forensic-session-start": "start",
        "evidence-unlock-output": "unlock",
        "evidence-mount": "mount",
        "evidence-hash": "hashcmd",
        "evidence-triage": "triage",
    }.items():
        text = (BIN / name).read_text(encoding="utf-8")
        assert text.startswith("#!/usr/bin/python3\n")
        assert 'os.environ.get("AIRLOCK_PYLIB", "/opt/airlock/lib/python")' in text
        assert f"from airlock_session.{module} import main" in text
        assert (BIN / name).stat().st_mode & 0o111


def test_every_prompt_has_a_flag() -> None:
    """Each ui.ask_* call in the session helpers names its flag."""
    for path in sorted((PYLIB / "airlock_session").glob("*.py")):
        text = path.read_text(encoding="utf-8")
        start_at = text.find("ui.ask_")
        while start_at != -1:
            call = text[start_at : text.find(")\n", start_at)]
            assert "flag=" in call, f"{path.name}: prompt without flag: {call[:80]}"
            start_at = text.find("ui.ask_", start_at + 1)


def test_jsonio_used_for_records(airlock_env: Path, tmp_path: Path) -> None:
    rec = tmp_path / "r.json"
    jsonio.dump_json(rec, {"b": 1, "a": 2})
    assert rec.read_text().index('"a"') < rec.read_text().index('"b"')
