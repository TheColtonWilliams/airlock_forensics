"""Task 4.14: the committed NTFS and exFAT fixtures and their ground truth agree.

* each .zst and its decompressed image match the committed .sha256 file and the ground truth;
* the NTFS ground truth has what the plan asks for: created and deleted files of various sizes
  (resident and non-resident), a Windows 10 ($I version 2) recycle-bin pair under
  S-1-5-21-1111111111-2222222222-3333333333-1001, hostile names, and controlled times;
* the builders are the scripts that made them.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

FIX = Path(__file__).resolve().parents[2] / "tests" / "fixtures"
SID = "S-1-5-21-1111111111-2222222222-3333333333-1001"


def truth(name: str) -> dict[str, Any]:
    return json.loads((FIX / f"{name}.truth.json").read_text(encoding="utf-8"))


def recorded(name: str) -> dict[str, str]:
    out = {}
    for line in (FIX / f"{name}.sha256").read_text().splitlines():
        sha, _, fname = line.partition("  ")
        out[fname] = sha
    return out


@pytest.mark.parametrize("name", ["ntfs-basic", "exfat-basic"])
def test_compressed_fixture_matches_its_hash_file(name: str) -> None:
    sums = recorded(name)
    zst = FIX / f"{name}.img.zst"
    assert hashlib.sha256(zst.read_bytes()).hexdigest() == sums[f"{name}.img.zst"]
    assert truth(name)["image_sha256"] == sums[f"{name}.img"]
    kind = name.partition("-")[0]
    assert truth(name)["built_by"] == f"tests/fixtures/build-{kind}-fixture.sh"
    assert (FIX / f"build-{kind}-fixture.sh").is_file()


@pytest.mark.parametrize("name", ["ntfs-basic", "exfat-basic"])
def test_decompressed_image_matches_ground_truth(name: str, tmp_path: Path) -> None:
    if not shutil.which("zstd"):
        pytest.skip("needs zstd")
    out = tmp_path / f"{name}.img"
    subprocess.run(["zstd", "-q", "-d", "-o", str(out), str(FIX / f"{name}.img.zst")], check=True)
    data = out.read_bytes()
    t = truth(name)
    assert len(data) == t["size_bytes"]
    assert hashlib.sha256(data).hexdigest() == t["image_sha256"]
    if name == "ntfs-basic":
        assert data[3:11] == b"NTFS    "
    else:
        assert data[3:11] == b"EXFAT   "


def test_ntfs_truth_has_deleted_files_of_every_kind() -> None:
    t = truth("ntfs-basic")
    assert t["size_bytes"] == 64 * 1024 * 1024
    files = {f["path"]: f for f in t["files"]}
    deleted = [f for f in t["files"] if f["deleted"] and f["kind"] == "file"]
    sizes = sorted(f["size"] for f in deleted)
    assert sizes[0] < 700, "no resident (small) deleted file"
    assert sizes[-1] > 64 * 1024, "no large non-resident deleted file"
    assert any(f["kind"] == "dir" and f["deleted"] for f in t["files"]), "no deleted folder"
    assert {d["path"] for d in t["deleted"]} <= set(files)
    for d in t["deleted"]:
        assert d["mft_entry"] > 15 and len(d["sha256"]) == 64
    assert set(t["deleted_names"]) == {f["name"] for f in t["files"] if f["deleted"]}
    assert len(t["live"]) >= 5


def test_ntfs_truth_has_hostile_names() -> None:
    names = truth("ntfs-basic")["hostile_names"]
    assert any(n.startswith("=") for n in names)
    assert any(n.startswith("+") for n in names)
    assert any("\u202e" in n for n in names)
    files = truth("ntfs-basic")["files"]
    deleted_hostile = [f for f in files if f["hostile_name"] and f["deleted"]]
    assert deleted_hostile, "no deleted file with a hostile name"


def test_ntfs_truth_recycle_bin_is_windows10_format() -> None:
    t = truth("ntfs-basic")
    present = [r for r in t["recycle_bin"] if not r["i_deleted"]]
    assert present, "no live $I/$R pair"
    rec = present[0]
    assert rec["sid"] == SID
    assert rec["format_version"] == 2
    assert rec["i_name"].startswith("$I") and rec["r_name"] == "$R" + rec["i_name"][2:]
    assert rec["i_path"] == f"/$Recycle.Bin/{SID}/{rec['i_name']}"
    assert rec["original_path"].startswith("C:\\Users\\")
    files = {f["path"]: f for f in t["files"]}
    r_file = files[rec["r_path"]]
    assert r_file["size"] == rec["original_size"]
    # FILETIME agrees with the ISO time.
    epoch_offset = 11_644_473_600
    iso = rec["deleted_time"]
    import datetime as dt  # noqa: PLC0415

    when = dt.datetime.strptime(iso, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.UTC)
    assert rec["deleted_filetime"] == (int(when.timestamp()) + epoch_offset) * 10_000_000
    # $I v2 size: 28-byte header + UTF-16LE path with terminator.
    i_file = files[rec["i_path"]]
    assert i_file["size"] == 28 + 2 * (len(rec["original_path"]) + 1)
    assert any(r["i_deleted"] for r in t["recycle_bin"]), "no emptied recycle-bin pair"


def test_ntfs_truth_times_are_controlled() -> None:
    for f in truth("ntfs-basic")["files"]:
        if f["kind"] != "file":
            continue
        for key in ("crtime", "mtime", "atime"):
            assert f[key].startswith("2026-0"), (f["path"], key, f[key])
            assert f[f"{key}_filetime"] % 10_000_000 == 0


def test_exfat_truth_has_deleted_and_hostile_files() -> None:
    t = truth("exfat-basic")
    assert t["filesystem"] == "exfat"
    assert len(t["deleted"]) >= 2
    assert any(n.startswith("=") for n in t["deleted_names"])
    assert any("\u202e" in n for n in t["hostile_names"])
