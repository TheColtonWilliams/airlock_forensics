"""validation/synthetic/synth.py (task 4F.1): encoders, the raw MFT timestomp, the image build.

The encoders are written independently of the parsers under test; here each one is read back
by the on-image parser, so a disagreement between the two shows up. The full build needs root,
FUSE, ntfs-3g, exfat-fuse and libfaketime, and is skipped without them.
"""

from __future__ import annotations

import importlib.util
import os
import shutil
import struct
import subprocess
import sys
import zlib
from pathlib import Path
from typing import Any

import pytest

from forensic_analyze.parsers import recycle, usn

REPO = Path(__file__).resolve().parents[2]


def _load(name: str, rel: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, REPO / rel)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


synth = _load("airlock_validation_synth", "validation/synthetic/synth.py")


def test_time_helpers_round_trip() -> None:
    when = synth.utc("2026-04-15T12:00:00Z")
    ticks = synth.ticks_of(when, 1_234_567)
    assert synth.iso_ticks(ticks) == "2026-04-15T12:00:00.1234567Z"
    assert synth.iso(when) == "2026-04-15T12:00:00Z"


@pytest.mark.parametrize("version", [1, 2])
def test_recycle_i_record_reads_back(version: int) -> None:
    ticks = synth.ticks_of(synth.utc("2026-04-15T12:00:00Z"), 42)
    raw = synth.recycle_i("C:\\Users\\TestUser\\Documents\\draft-01.txt", 1410, ticks, version)
    rec = recycle.parse(raw)
    assert rec.version == version
    assert rec.file_size == 1410
    assert rec.deleted_ticks == ticks
    assert rec.original_path == "C:\\Users\\TestUser\\Documents\\draft-01.txt"
    if version == 1:
        assert len(raw) == 544


def test_recycle_i_rejects_bad_input() -> None:
    with pytest.raises(synth.BuildError):
        synth.recycle_i("C:\\" + "x" * 300, 1, 1, 1)
    with pytest.raises(synth.BuildError):
        synth.recycle_i("C:\\a", 1, 1, 3)


def test_usn_record_reads_back_and_is_plausible() -> None:
    ticks = synth.ticks_of(synth.utc("2026-04-12T10:00:00Z"), 1_111_111)
    raw = synth.usn_v2(
        entry=4101,
        seq=2,
        parent=5,
        parent_seq=5,
        usn=9000,
        ticks=ticks,
        reason=synth.USN_FILE_DELETE | synth.USN_CLOSE,
        name="val-usn-deleted-a.txt",
    )
    assert len(raw) % 8 == 0
    rec = usn.parse_record(raw)
    assert (rec.entry, rec.seq, rec.parent_entry, rec.usn) == (4101, 2, 5, 9000)
    assert rec.name == "val-usn-deleted-a.txt"
    assert rec.is_delete and usn.plausible(rec)
    assert rec.timestamp == ticks


def test_png_is_valid_and_large_enough_to_carve() -> None:
    data = synth.png(64, 48, (30, 110, 200), 4)
    assert data.startswith(b"\x89PNG\r\n\x1a\n") and data.endswith(b"IEND\xaeB`\x82")
    pos = 8
    while pos < len(data):
        (length,) = struct.unpack(">I", data[pos : pos + 4])
        kind = data[pos + 4 : pos + 8]
        body = data[pos + 8 : pos + 8 + length]
        (crc,) = struct.unpack(">I", data[pos + 8 + length : pos + 12 + length])
        assert zlib.crc32(kind + body) & 0xFFFFFFFF == crc
        pos += 12 + length
    # NTFS keeps files under about 700 bytes inside the MFT record: those cannot be carved.
    assert len(data) > 4096
    assert synth.png(64, 48, (30, 110, 200), 4) == data  # deterministic


# -- raw MFT edit on a hand-built image --------------------------------------------------------

CLUSTER = 4096
REC = 1024


def _record(attrs: bytes) -> bytearray:
    rec = bytearray(REC)
    rec[0:4] = b"FILE"
    struct.pack_into("<HH", rec, 4, 0x30, REC // 512 + 1)
    struct.pack_into("<H", rec, 0x14, 0x38)
    struct.pack_into("<H", rec, 0x30, 0x0007)  # update sequence number
    rec[0x38 : 0x38 + len(attrs)] = attrs
    end = 0x38 + len(attrs)
    rec[end : end + 4] = b"\xff\xff\xff\xff"
    synth._refix(rec)
    return rec


def _si_attr(times: tuple[int, int, int, int]) -> bytes:
    value = struct.pack("<4Q", *times) + b"\0" * 16
    head = struct.pack("<IIBBHHH", 0x10, 0x18 + len(value), 0, 0, 0, 0, 0)
    head += struct.pack("<IHBB", len(value), 0x18, 0, 0)
    return head + value


def _data_attr(runs: bytes) -> bytes:
    head = bytearray(0x40)
    struct.pack_into("<II", head, 0, 0x80, 0x40 + 8)
    head[8] = 1  # non-resident
    struct.pack_into("<H", head, 0x20, 0x40)
    return bytes(head) + runs.ljust(8, b"\0")


@pytest.fixture
def fake_ntfs(tmp_path: Path) -> Path:
    img = tmp_path / "fake.img"
    data = bytearray(16 * CLUSTER)
    boot = bytearray(512)
    boot[3:11] = b"NTFS    "
    struct.pack_into("<H", boot, 0x0B, 512)
    boot[0x0D] = CLUSTER // 512
    struct.pack_into("<Q", boot, 0x30, 4)  # $MFT starts at cluster 4
    struct.pack_into("<b", boot, 0x40, -10)  # 1024-byte records
    data[0:512] = boot
    # $MFT in two runs: 1 cluster at LCN 4 (records 0-3), 2 clusters at LCN 10 (records 4-11).
    data[4 * CLUSTER : 4 * CLUSTER + REC] = _record(_data_attr(b"\x11\x01\x04\x11\x02\x06"))
    t = 133_000_000_000_000_000
    target = 10 * CLUSTER + (5 - 4) * REC
    data[target : target + REC] = _record(_si_attr((t + 1, t + 2, t + 3, t + 4)))
    img.write_bytes(bytes(data))
    return img


def test_mft_record_offset_follows_runs(fake_ntfs: Path) -> None:
    assert synth.mft_record_offset(fake_ntfs, 0) == (4 * CLUSTER, REC)
    assert synth.mft_record_offset(fake_ntfs, 5) == (10 * CLUSTER + REC, REC)
    with pytest.raises(synth.BuildError):
        synth.mft_record_offset(fake_ntfs, 40)


def test_set_si_times_rewrites_only_the_given_times(fake_ntfs: Path) -> None:
    t = 133_000_000_000_000_000
    before = synth.read_si_times(fake_ntfs, 5)
    assert before == {"created": t + 1, "modified": t + 2, "changed": t + 3, "accessed": t + 4}
    whole = synth.ticks_of(synth.STOMP_TO)
    synth.set_si_times(fake_ntfs, 5, {"created": whole, "modified": whole, "accessed": whole})
    after = synth.read_si_times(fake_ntfs, 5)
    assert after == {"created": whole, "modified": whole, "changed": t + 3, "accessed": whole}
    raw = fake_ntfs.read_bytes()
    off = 10 * CLUSTER + REC
    # The fixups are back in place: each sector of the record ends with the sequence number.
    assert raw[off + 510 : off + 512] == raw[off + 1022 : off + 1024] == b"\x07\x00"


def test_torn_record_is_refused(fake_ntfs: Path) -> None:
    raw = bytearray(fake_ntfs.read_bytes())
    off = 10 * CLUSTER + REC
    raw[off + 510 : off + 512] = b"\x99\x99"
    fake_ntfs.write_bytes(bytes(raw))
    with pytest.raises(synth.BuildError, match="fixup"):
        synth.set_si_times(fake_ntfs, 5, {"created": 1})


# -- full build (root) ------------------------------------------------------------------------


def _build_prereqs() -> str:
    if os.geteuid() != 0:
        return "needs root"
    for tool in ("mkfs.ntfs", "ntfs-3g", "mkfs.exfat", "mount.exfat-fuse", "istat", "fls"):
        if not shutil.which(tool):
            return f"needs {tool}"
    if not Path("/dev/fuse").exists():
        return "needs /dev/fuse"
    try:
        synth.faketime_lib()
    except synth.BuildError:
        return "needs libfaketime"
    return ""


@pytest.fixture(scope="module")
def built(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, dict[str, Any]]:
    why = _build_prereqs()
    if why:
        pytest.skip(why)
    img = tmp_path_factory.mktemp("synth") / "ntfs.img"
    return img, synth.build_ntfs(img)


def _istat_times(img: Path, entry: int) -> str:
    return subprocess.run(
        ["istat", str(img), str(entry)], capture_output=True, text=True, check=True
    ).stdout


def test_ntfs_build_matches_its_truth(built: tuple[Path, dict[str, Any]]) -> None:
    img, truth = built
    assert truth["image_sha256"] == synth.sha256_file(img)
    listing = subprocess.run(
        ["fls", "-r", "-p", str(img)], capture_output=True, text=True, check=True
    ).stdout.splitlines()
    for f in truth["files"]:
        line = next(ln for ln in listing if ln.endswith("\t" + f["path"].lstrip("/")))
        assert ("*" in line.split("\t")[0]) == (f["state"] == "deleted"), line
    for f in truth["files"]:
        if f["state"] == "live":
            got = synth.utc(f["times"]["created"][:19] + "Z")
            assert abs((got - synth.utc(f["planned"]["created"])).total_seconds()) <= 2, f
    assert {r["version"] for r in truth["recycle_bin"]} == {1, 2}
    assert len(truth["carve"]) == 3


def test_ntfs_timestomps_are_where_the_truth_says(built: tuple[Path, dict[str, Any]]) -> None:
    img, truth = built
    by_method = {s["method"]: s for s in truth["timestomp"]}
    whole = _istat_times(img, by_method["si_raw_whole"]["mft_entry"])
    si, fn = whole.split("$FILE_NAME Attribute Values:")
    assert "Created:\t2019-05-06 07:08:09.000000000" in si
    assert "2019-05-06" not in fn.split("Attributes:")[0]  # $FILE_NAME untouched
    xattr = _istat_times(img, by_method["ntfs3g_xattr"]["mft_entry"])
    _si, fn = xattr.split("$FILE_NAME Attribute Values:")
    # ntfs-3g also rewrites $FILE_NAME, which is why this method is marked not detectable.
    assert "Created:\t2019-05-06 07:08:09" in fn
    assert by_method["ntfs3g_xattr"]["detectable"] is False


def test_exfat_build(tmp_path: Path) -> None:
    why = _build_prereqs()
    if why:
        pytest.skip(why)
    truth = synth.build_exfat(tmp_path / "ex.img")
    assert truth["fs_type"] == "exfat"
    states = {f["path"]: f["state"] for f in truth["files"]}
    assert states["/Data/deleted-01.txt"] == "deleted"
    assert states["/Data/modified-01.txt"] == "live"
    listing = subprocess.run(
        ["fls", "-r", "-p", str(tmp_path / "ex.img")], capture_output=True, text=True, check=True
    ).stdout
    assert "* " in listing and "Data/deleted-01.txt" in listing
