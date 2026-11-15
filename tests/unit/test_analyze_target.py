"""Target picker, HPA/DCO, SMART, blocker record, filesystem detection, imaging parsers.

Tasks 4C.2, 4C.16, 4C.22, 4C.24, 3A.6, 3A.7, surviving risk 15, 4G.1.
"""

from __future__ import annotations

import json
import stat as stat_mod
import subprocess
from pathlib import Path
from typing import Any

import pytest

from airlock_common import hashing, proc
from forensic_analyze import fsdetect, mode
from forensic_analyze import target as tgt


def _node(name: str, **kw: Any) -> dict[str, Any]:
    base = {
        "name": name,
        "path": f"/dev/{name}",
        "type": "disk",
        "size": 1000,
        "ro": False,
        "rm": False,
        "tran": "",
        "model": "",
        "serial": "",
        "fstype": None,
        "label": None,
        "mountpoints": [None],
        "children": [],
    }
    base.update(kw)
    return base


@pytest.fixture
def lsblk_fixture(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    data = {
        "blockdevices": [
            _node(
                "sda",
                size=64_000_000_000,
                model="AIRLOCK STICK",
                children=[_node("sda5", type="part", fstype="ext4", mountpoints=["/"])],
            ),
            _node(
                "sdb",
                size=500_000_000_000,
                ro=True,
                model="Evidence Disk",
                serial="SER123",
                tran="sata",
                children=[_node("sdb1", type="part", ro=True, fstype="ntfs")],
            ),
            _node("sdc", size=8_000_000_000, ro=False, model="Writable", tran="usb"),
            _node(
                "sdd",
                size=8_000_000_000,
                ro=True,
                children=[_node("sdd1", type="part", ro=True, mountpoints=["/media/x"])],
            ),
            _node("loop0", type="loop", ro=True),
        ]
    }
    path = tmp_path / "lsblk.json"
    path.write_text(json.dumps(data))
    monkeypatch.setenv("AIRLOCK_LSBLK_JSON", str(path))
    return path


def test_candidates_never_list_the_boot_drive(lsblk_fixture: Path, tmp_path: Path) -> None:
    imgs = tmp_path / "images"
    imgs.mkdir()
    (imgs / "case.E01").write_bytes(b"x")
    (imgs / "disk.dd").write_bytes(b"y")
    (imgs / "notes.txt").write_text("no")
    cands = tgt.candidates(imgs)
    names = [c.name for c in cands]
    assert "sda" not in names and "loop0" not in names
    assert names[:3] == ["sdb", "sdc", "sdd"]
    assert {"case.E01", "disk.dd"} <= set(names) and "notes.txt" not in names
    sdb = cands[0]
    assert sdb.readonly and sdb.filesystems == ["ntfs"] and "SER123" in sdb.label()
    assert "WRITABLE" in cands[1].label()


def test_resolve_refuses_boot_mounted_and_missing(
    lsblk_fixture: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class FakeStat:
        st_mode = stat_mod.S_IFBLK | 0o660
        st_size = 0

    monkeypatch.setattr(Path, "exists", lambda self: True)
    monkeypatch.setattr(Path, "stat", lambda self, **kw: FakeStat())
    monkeypatch.setattr(tgt.os.path, "realpath", str)
    with pytest.raises(tgt.TargetError, match="AIRLOCK drive itself"):
        tgt.resolve("/dev/sda")
    with pytest.raises(tgt.TargetError, match="mounted"):
        tgt.resolve("/dev/sdd1")
    with pytest.raises(tgt.TargetError, match="not listed"):
        tgt.resolve("/dev/sdz")
    monkeypatch.setattr(tgt.devices, "is_readonly", lambda p: p.startswith("/dev/sdb"))
    cand = tgt.resolve("/dev/sdb1")
    assert cand.readonly and cand.model == "Evidence Disk" and cand.transport == "sata"
    tgt.require_readonly(cand)
    cand = tgt.resolve("/dev/sdc")
    with pytest.raises(tgt.TargetError, match="not read-only"):
        tgt.require_readonly(cand)


def test_resolve_image_files(tmp_path: Path) -> None:
    img = tmp_path / "x.img"
    img.write_bytes(b"\0" * 1024)
    cand = tgt.resolve(str(img))
    assert cand.kind == "image" and cand.size_bytes == 1024
    tgt.require_readonly(cand)  # images are always opened read-only
    other = tmp_path / "x.docx"
    other.write_text("x")
    with pytest.raises(tgt.TargetError, match="not a known image type"):
        tgt.resolve(str(other))
    with pytest.raises(tgt.TargetError, match="does not exist"):
        tgt.resolve(str(tmp_path / "missing.dd"))


def test_evidence_id() -> None:
    c = tgt.Candidate("/dev/sdb", "device", "sdb", 1, model="Disk X", serial="S1")
    assert tgt.evidence_id(c) == "Disk_X_S1"
    assert tgt.evidence_id(c, "EX-9") == "EX-9"
    assert tgt.evidence_id(tgt.Candidate("/a/b.E01", "image", "b.E01", 1)) == "b.E01"


def test_hdparm_parsers() -> None:
    hpa = tgt.parse_hdparm_n("\n/dev/sdb:\n max sectors   = 976771055/976773168, HPA is enabled\n")
    assert hpa["hpa_enabled"] and hpa["hidden_sectors"] == 2113
    off = tgt.parse_hdparm_n(" max sectors   = 976773168/976773168, HPA is disabled")
    assert not off["hpa_enabled"] and off["hidden_sectors"] == 0
    assert tgt.parse_hdparm_n("garbage") == {"parsed": False}
    dco = tgt.parse_dco(
        "DCO Revision: 0x0001\n"
        "The following features can be selectively disabled via DCO:\n"
        "\tReal max sectors: 976773168\n"
    )
    assert dco["dco_max_sectors"] == 976773168


def test_hpa_dco_only_queries_ata(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[list[str]] = []

    def fake_run(argv: list[str], **kw: Any) -> proc.Result:
        calls.append(list(argv))
        out = (
            " max sectors   = 100/200, HPA is enabled" if "-N" in argv else "Real max sectors: 300"
        )
        return proc.Result(list(argv), 0, out, "")

    monkeypatch.setattr(tgt.proc, "run", fake_run)
    monkeypatch.setattr(tgt.proc, "which", lambda n: "/usr/sbin/hdparm")
    usb = tgt.Candidate("/dev/sdc", "device", "sdc", 1, transport="usb")
    assert tgt.hpa_dco(usb)["status"] == "skipped" and not calls
    ata = tgt.Candidate("/dev/sdb", "device", "sdb", 1, transport="sata")
    res = tgt.hpa_dco(ata)
    assert res["status"] == "queried" and res["hpa"]["hidden_sectors"] == 100 and res["dco_hidden"]
    # Read-only queries only: never -N with a value, never --dco-restore or --dco-freeze.
    assert calls == [["hdparm", "-N", "/dev/sdb"], ["hdparm", "--dco-identify", "/dev/sdb"]]


def test_smart_check(monkeypatch: pytest.MonkeyPatch) -> None:
    data = {
        "smart_status": {"passed": True},
        "ata_smart_attributes": {
            "table": [
                {"id": 5, "name": "Reallocated_Sector_Ct", "raw": {"value": 12}},
                {"id": 9, "name": "Power_On_Hours", "raw": {"value": 999}},
            ]
        },
    }
    monkeypatch.setattr(tgt.proc, "which", lambda n: "/usr/sbin/smartctl")
    monkeypatch.setattr(
        tgt.proc, "run", lambda argv, **kw: proc.Result(list(argv), 4, json.dumps(data), "")
    )
    dev = tgt.Candidate("/dev/sdb", "device", "sdb", 1)
    res = tgt.smart_check(dev)
    assert (
        res["available"] and res["warning"] and res["attributes"] == {"Reallocated_Sector_Ct": 12}
    )
    assert "ddrescue" in tgt.smart_warning_text(res)
    monkeypatch.setattr(tgt.proc, "run", lambda argv, **kw: proc.Result(list(argv), 2, "{}", ""))
    assert tgt.smart_check(dev) == {"available": False}
    monkeypatch.setattr(tgt.proc, "which", lambda n: None)
    assert tgt.smart_check(dev) == {"available": False}


def test_blocker_record() -> None:
    rec = tgt.blocker_record(
        "yes", make="Make", model="M1", firmware="1.0", report_url="https://example.org/r.pdf"
    )
    assert rec.in_use == "yes" and rec.notes == [] and rec.answered_via == "flag"
    assert tgt.blocker_record(None).in_use == "unknown"
    assert tgt.blocker_record(None).answered_via == "default"
    assert "no test report" in tgt.blocker_record("yes").notes[0]
    with pytest.raises(tgt.TargetError):
        tgt.blocker_record("maybe")
    with pytest.raises(tgt.TargetError):
        tgt.blocker_record("yes", report_url="ftp://x")
    assert "second layer" in tgt.ADVISORY_TEXT and "write blocker" in tgt.ADVISORY_TEXT
    assert "software read-only policy" in tgt.ADVISORY_TEXT


# ---------------------------------------------------------------------------------- fsdetect

GPT = """GUID Partition Table (EFI)
Offset Sector: 0
Units are in 512-byte sectors

      Slot      Start        End          Length       Description
000:  Meta      0000000000   0000000000   0000000001   Safety Table
001:  -------   0000000000   0000002047   0000002048   Unallocated
002:  Meta      0000000001   0000000001   0000000001   GPT Header
003:  Meta      0000000002   0000000033   0000000032   Partition Table
004:  000       0000002048   0000043007   0000040960   Basic data partition
005:  001       0000043008   0000083967   0000040960
006:  -------   0000083968   0000131071   0000047104   Unallocated
"""

MBR = """DOS Partition Table
Offset Sector: 0
Units are in 4096-byte sectors

      Slot      Start        End          Length       Description
000:  Meta      0000000000   0000000000   0000000001   Primary Table (#0)
002:  000:000   0000000256   0000002815   0000002560   NTFS / exFAT (0x07)
004:  Meta      0000003072   0000016383   0000013312   DOS Extended (0x05)
005:  Meta      0000003072   0000003072   0000000001   Extended Table (#1)
006:  001:000   0000003328   0000004607   0000001280   Linux (0x83)
"""


def test_parse_mmls() -> None:
    sector, parts = fsdetect.parse_mmls(GPT)
    assert sector == 512 and [(p.start, p.length) for p in parts] == [(2048, 40960), (43008, 40960)]
    sector, parts = fsdetect.parse_mmls(MBR)
    assert sector == 4096 and [p.slot for p in parts] == ["000:000", "001:000"]


def test_bitlocker_signatures() -> None:
    assert fsdetect.is_bitlocker(b"\xebR\x90-FVE-FS-" + b"\0" * 500)
    togo = bytearray(512)
    togo[3:11] = b"MSWIN4.1"
    togo[160:176] = fsdetect.BITLOCKER_TOGO_GUID
    assert fsdetect.is_bitlocker(bytes(togo))
    assert not fsdetect.is_bitlocker(b"\xebR\x90NTFS    " + b"\0" * 500)


def test_normalise_and_label() -> None:
    assert fsdetect.normalise_fs("NTFS") == "ntfs"
    assert fsdetect.normalise_fs("exFAT") == "exfat"
    assert fsdetect.normalise_fs("") == "unknown"
    assert fsdetect.parse_label("Volume Name: EVID\n") == "EVID"
    assert fsdetect.parse_label("Volume Label (from root directory): EXF\n") == "EXF"
    assert fsdetect.image_type("/x/case.E01") == "ewf"
    assert fsdetect.image_type("/dev/sdb") == "raw"


def _fake_tool(outputs: dict[str, tuple[int, str]]) -> Any:
    def tool(argv: list[str], **kw: Any) -> subprocess.CompletedProcess[str]:
        key = " ".join(argv[:1] + [a for a in argv if a in ("-t",)] + argv[-2:-1])
        for k, (rc, out) in outputs.items():
            if key.startswith(k) or k in " ".join(argv):
                return subprocess.CompletedProcess(argv, rc, out, "")
        return subprocess.CompletedProcess(argv, 1, "", "")

    return tool


def test_detect_partitions_and_bitlocker(tmp_path: Path) -> None:
    disk = tmp_path / "disk.raw"
    data = bytearray(84000 * 512)
    data[2048 * 512 + 3 : 2048 * 512 + 11] = b"NTFS    "
    data[43008 * 512 + 3 : 43008 * 512 + 11] = b"-FVE-FS-"
    disk.write_bytes(bytes(data))
    calls: list[list[str]] = []

    def tool(argv: list[str], **kw: Any) -> subprocess.CompletedProcess[str]:
        calls.append(argv)
        if argv[0] == "mmls":
            return subprocess.CompletedProcess(argv, 0, GPT, "")
        if "-t" in argv:
            return subprocess.CompletedProcess(argv, 0, "ntfs\n", "")
        return subprocess.CompletedProcess(argv, 0, "Volume Name: EVID\n", "")

    vols = fsdetect.detect(disk, tool=tool, workdir=tmp_path)
    assert [(v.fs_type, v.bitlocker, v.offset_bytes) for v in vols] == [
        ("ntfs", False, 2048 * 512),
        ("bitlocker", True, 43008 * 512),
    ]
    assert vols[0].label == "EVID"
    assert all("-o" in c for c in calls if c[0] == "fsstat")


def test_detect_whole_disk_when_no_table(tmp_path: Path) -> None:
    disk = tmp_path / "vol.raw"
    disk.write_bytes(b"\0" * 4096)

    def tool(argv: list[str], **kw: Any) -> subprocess.CompletedProcess[str]:
        if argv[0] == "mmls":
            return subprocess.CompletedProcess(argv, 1, "", "Cannot determine")
        if "-t" in argv:
            return subprocess.CompletedProcess(argv, 0, "exfat\n", "")
        return subprocess.CompletedProcess(argv, 0, "", "")

    vols = fsdetect.detect(disk, tool=tool, workdir=tmp_path, size_bytes=4096)
    assert len(vols) == 1 and vols[0].fs_type == "exfat" and vols[0].size_bytes == 4096


def test_key_args_and_unlock_errors(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    rec = tmp_path / "key.txt"
    password = "111111-222222-333333-444444-555555-666666-777777-888888"  # noqa: S105 - fake
    rec.write_text(password + "\n")
    args, secrets = fsdetect.key_args(rec)
    assert args == ["-r", password] and secrets == [password]
    bek = tmp_path / "x.BEK"
    bek.write_bytes(b"\x00\x01binary")
    assert fsdetect.key_args(bek) == (["-f", str(bek)], [])
    with pytest.raises(fsdetect.BitLockerLocked, match="--bitlocker-key-file"):
        fsdetect.unlock("/dev/x", None, tmp_path, tool=_fake_tool({}))
    with pytest.raises(fsdetect.BitLockerLocked, match="not found"):
        fsdetect.unlock("/dev/x", tmp_path / "nope", tmp_path, tool=_fake_tool({}))
    monkeypatch.setattr(fsdetect.proc, "which", lambda n: None)
    with pytest.raises(fsdetect.BitLockerLocked, match="not installed"):
        fsdetect.unlock("/dev/x", rec, tmp_path, tool=_fake_tool({}))


def test_unlock_redacts_and_makes_copy_read_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    password = "111111-222222-333333-444444-555555-666666-777777-888888"  # noqa: S105 - fake
    key = tmp_path / "k.txt"
    key.write_text(password)
    seen: dict[str, Any] = {}
    monkeypatch.setattr(fsdetect.proc, "which", lambda n: "/usr/bin/fve-dd")

    def tool(argv: list[str], **kw: Any) -> subprocess.CompletedProcess[str]:
        seen["redact"] = kw.get("redact")
        Path(argv[argv.index("-o") + 1]).write_bytes(b"decrypted")
        return subprocess.CompletedProcess(argv, 0, "", "")

    res = fsdetect.unlock("/dev/loop9", key, tmp_path / "dec", tool=tool)
    assert seen["redact"] == [password]
    assert password not in res.tool_argv and "<redacted>" in res.tool_argv
    assert res.image.stat().st_mode & 0o222 == 0

    def failing(argv: list[str], **kw: Any) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(argv, 1, "", "Failed")

    with pytest.raises(fsdetect.BitLockerLocked, match="could not be unlocked"):
        fsdetect.unlock("/dev/loop9", key, tmp_path / "dec2", tool=failing)


# -------------------------------------------------------------------------------------- mode


def test_ewfverify_and_ddrescue_map_parsers() -> None:
    text = (
        "MD5 hash calculated over data:\t\tac6a0eded10b215f3e26bf852b438807\n"
        "SHA256 hash calculated over data:\t"
        "297bf0526578f97acac4a82f5b579842626f69a89de26c8318ac595410697c6b\n"
    )
    d = mode.parse_ewfverify(text)
    assert d["md5"].startswith("ac6a") and d["sha256"].startswith("297b")
    mapfile = (
        "# Mapfile. Created by GNU ddrescue version 1.27\n"
        "# current_pos  current_status  current_pass\n"
        "0x00000000     +               1\n"
        "#      pos        size  status\n"
        "0x00000000  0x00100000  +\n"
        "0x00100000  0x00000200  -\n"
        "0x00100200  0x00EFFE00  +\n"
    )
    good, bad = mode.parse_ddrescue_map(mapfile)
    assert bad == 0x200 and good == 0x00100000 + 0x00EFFE00


def test_ddrescue_acquire_with_fake_runner(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    src = tmp_path / "src.img"
    src.write_bytes(b"A" * 8192)
    expected = hashing.hash_file(src)
    calls: list[list[str]] = []

    def fake(argv: list[str], **kw: Any) -> proc.Result:
        calls.append(list(argv))
        Path(argv[3]).write_bytes(src.read_bytes())
        Path(argv[4]).write_text("# m\n0x0 + 1\n0x00000000  0x00002000  +\n")
        return proc.Result(list(argv), 0, "", "")

    monkeypatch.setattr(mode.proc, "which", lambda n: "/usr/bin/ddrescue")
    res = mode.acquire("ddrescue", str(src), tmp_path / "image", expected=expected, run=fake)
    assert res.verified and res.bad_bytes == 0 and len(calls) == 2
    assert calls[0][:2] == ["ddrescue", "-n"] and calls[1][:2] == ["ddrescue", "-r3"]
    with pytest.raises(mode.ModeError):
        mode.acquire("cp", str(src), tmp_path / "x", expected=expected)
    assert "re-examined" in mode.DIRECT_WARNING


def test_rotational_flag(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    disk = tmp_path / "sdb"
    (disk / "queue").mkdir(parents=True)
    (disk / "queue" / "rotational").write_text("0\n")
    (disk / "sdb1").mkdir()
    nodes = {"/dev/sdb": disk, "/dev/sdb1": disk / "sdb1"}
    monkeypatch.setattr(tgt, "_sys_block", nodes.__getitem__)
    assert tgt.rotational("/dev/sdb") is False
    assert tgt.rotational("/dev/sdb1") is False  # partitions use the parent disk's flag
    (disk / "queue" / "rotational").write_text("1\n")
    assert tgt.rotational("/dev/sdb") is True
    monkeypatch.setattr(tgt, "_sys_block", lambda path: tmp_path / "nothing")
    assert tgt.rotational("/dev/sdx") is None
    assert "garbage collection" in tgt.SSD_WARNING
