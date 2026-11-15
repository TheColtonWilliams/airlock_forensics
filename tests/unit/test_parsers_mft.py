"""Built-in $MFT parser (parsers/mft.py) on a real NTFS image, cross-checked against
The Sleuth Kit (fls) and, when installed, Dissect's MFT record parser."""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

import pytest
from test_parsers_ntfs_fixture import build_ntfs_image, make_ctx, ntfs_tools_ok

from forensic_analyze import extract
from forensic_analyze.parsers import filetime, mft, sds


@pytest.fixture(scope="module")
def image(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, dict[str, Any], Path]:
    why = ntfs_tools_ok()
    if why:
        pytest.skip(why)
    base = tmp_path_factory.mktemp("mft")
    img = base / "fixture.img"
    truth = build_ntfs_image(img)
    ctx, _ = make_ctx(img, base / "run", "probe")
    path = extract.extract_system_file(ctx, ctx.target.volumes[0], "$MFT")
    return img, truth, path


def test_paths_and_deleted_flags_match_fls(image: tuple[Path, dict, Path]) -> None:
    img, truth, path = image
    idx = mft.MftIndex.load(path)
    fls = subprocess.run(
        ["fls", "-r", "-p", str(img)], capture_output=True, text=True, check=True
    ).stdout
    tsk: dict[str, tuple[int, bool]] = {}
    for line in fls.splitlines():
        head, _, name = line.partition("\t")
        if ":" in name or name.startswith("$OrphanFiles"):
            continue
        addr = head.split()[-1].rstrip(":").split("-")[0]
        tsk["/" + name] = (int(addr), "*" in head)
    for p, (entry, deleted) in tsk.items():
        rec = idx.get(entry)
        assert rec is not None, p
        assert idx.path_of(entry) == p
        assert rec.in_use is not deleted, p
    for p in truth["deleted"]:
        assert not idx.get(tsk[p][0]).in_use


def test_record_details(image: tuple[Path, dict, Path]) -> None:
    _, _, path = image
    idx = mft.MftIndex.load(path)
    keep = next(e for e in idx.records if idx.path_of(e) == "/Docs/keep.txt")
    rec = idx.get(keep)
    assert rec.data_size() == 6
    assert {s.name: s.size for s in rec.streams} == {"": 6, "extra": 12}
    assert rec.has_si and filetime.plausible(rec.si_created)
    fn = rec.best_name()
    assert (
        fn
        and fn.name == "keep.txt"
        and fn.namespace in (mft.NS_WIN32, mft.NS_POSIX, mft.NS_WIN32_DOS)
    )
    secure = idx.get(9)
    assert secure.security_id is not None and {s.name for s in secure.streams} == {"$SDS"}


def test_matches_dissect_records(image: tuple[Path, dict, Path]) -> None:
    dmft = pytest.importorskip("dissect.ntfs.mft")
    _, _, path = image
    data = path.read_bytes()
    size = mft.record_size_of(path)
    idx = mft.MftIndex.load(path)
    checked = 0
    for entry, rec in idx.records.items():
        theirs = dmft.MftRecord.from_bytes(data[entry * size : (entry + 1) * size])
        assert theirs.header.SequenceNumber == rec.seq
        assert bool(theirs.header.Flags & 1) == rec.in_use
        if rec.best_name() and theirs.filename:
            assert theirs.filename == rec.best_name().name
        checked += 1
    assert checked > 30


def test_sds_owners_match_dissect(image: tuple[Path, dict, Path]) -> None:
    secure = pytest.importorskip("dissect.ntfs.secure")
    img, _, mft_path = image
    ctx, _ = make_ctx(img, mft_path.parent.parent.parent, "probe")
    sds_path = extract.extract_system_file(ctx, ctx.target.volumes[0], "$Secure:$SDS")
    ours = sds.parse_file(sds_path)
    assert ours
    with open(sds_path, "rb") as fh:
        theirs = secure.Secure(sds=fh)
        for sec_id, entry in ours.items():
            assert str(theirs.lookup(sec_id).owner) == entry.owner_sid


def test_garbage_is_not_a_record() -> None:
    assert mft.parse_record(b"FILE" + b"\xff" * 1020, 3) is None
    assert mft.parse_record(b"\0" * 1024, 3) is None
