"""USN journal parser (parsers/usn.py): V2/V3 layout, journal walking, carving, renames.

The byte layout written by ``build_v2`` is checked against Dissect's independent USN parser
when Dissect is installed (it is a test-only cross-check; the image code is stdlib only).
"""

from __future__ import annotations

import io
import random
import struct

import pytest

from forensic_analyze.parsers import filetime, usn

T = 134_067_000_001_234_567


def rec2(n: int, reason: int, name: str = "file.txt", entry: int = 70) -> bytes:
    return usn.build_v2(
        entry=entry,
        seq=3,
        parent_entry=64,
        parent_seq=1,
        usn=n,
        timestamp=T + n,
        reason=reason,
        name=name,
    )


def test_v2_round_trip() -> None:
    raw = rec2(4096, usn.FILE_DELETE | 0x80000000, "naïve résumé.txt")
    assert len(raw) % 8 == 0
    r = usn.parse_record(raw)
    assert (r.major, r.entry, r.seq, r.parent_entry, r.parent_seq) == (2, 70, 3, 64, 1)
    assert r.usn == 4096 and r.timestamp == T + 4096
    assert r.name == "naïve résumé.txt"
    assert r.is_delete and r.reasons == ["FILE_DELETE", "CLOSE"]
    assert r.iso_time == filetime.to_iso(T + 4096)


def test_v3_low_64_bits_are_the_mft_reference() -> None:
    raw = usn.build_v3(
        entry=99,
        seq=7,
        parent_entry=5,
        parent_seq=5,
        usn=8,
        timestamp=T,
        reason=usn.FILE_CREATE,
        name="v3.txt",
    )
    r = usn.parse_record(raw)
    assert (r.major, r.entry, r.seq, r.parent_entry, r.name) == (3, 99, 7, 5, "v3.txt")


@pytest.mark.parametrize(
    "mutate",
    [
        lambda b: b[:4] + struct.pack("<H", 4) + b[6:],  # major 4 (range record)
        lambda b: struct.pack("<I", 12) + b[4:],  # too short
        lambda b: struct.pack("<I", len(b) + 3) + b[4:],  # not 8-aligned
        lambda b: b[:58] + struct.pack("<H", 200) + b[60:],  # name offset outside
    ],
)
def test_bad_records_are_refused(mutate: object) -> None:
    raw = rec2(1, usn.FILE_CREATE)
    with pytest.raises(usn.UsnError):
        usn.parse_record(mutate(raw))  # type: ignore[operator]


def test_journal_walk_skips_sparse_zeros_and_garbage(tmp_path: pytest.TempPathFactory) -> None:
    body = b"\0" * 65536 + rec2(100, usn.FILE_CREATE) + b"\0" * 24 + rec2(200, usn.FILE_DELETE)
    body += b"\xff" * 16 + rec2(300, usn.CLOSE)
    path = tmp_path / "J"  # type: ignore[operator]
    path.write_bytes(body)
    got = list(usn.iter_journal(path))
    assert [r.usn for r in got] == [100, 200, 300]
    assert got[0].offset == 65536


def test_empty_journal(tmp_path: pytest.TempPathFactory) -> None:
    path = tmp_path / "J"  # type: ignore[operator]
    path.write_bytes(b"")
    assert list(usn.iter_journal(path)) == []


def test_rename_pairs() -> None:
    recs = [
        usn.parse_record(rec2(1, usn.RENAME_OLD_NAME, "old.txt")),
        usn.parse_record(rec2(2, usn.RENAME_NEW_NAME, "new.txt")),
        usn.parse_record(rec2(3, usn.RENAME_OLD_NAME, "lonely.txt", entry=71)),
    ]
    pairs = usn.pair_renames(recs)
    assert [(a.name, b.name if b else None) for a, b in pairs] == [
        ("old.txt", "new.txt"),
        ("lonely.txt", None),
    ]


def test_carving_finds_records_and_ignores_random_bytes() -> None:
    rnd = random.Random(1234)  # noqa: S311 - test noise, not security
    noise = bytes(rnd.getrandbits(8) for _ in range(300_000))
    planted = rec2(5000, usn.FILE_DELETE | 0x80000000, "carved.txt")
    pos = 131_072 + 8 * 1000
    blob = noise[:pos] + planted + noise[pos:] + rec2(6000, usn.FILE_CREATE, "tail.txt")
    got = list(usn.carve(io.BytesIO(blob), chunk=65_536))
    assert [(r.name, r.offset) for r in got] == [
        ("carved.txt", pos),
        ("tail.txt", len(blob) - len(rec2(6000, usn.FILE_CREATE, "tail.txt"))),
    ]
    assert list(usn.carve(io.BytesIO(noise))) == []


def test_carver_incremental_matches_one_shot() -> None:
    blob = b"\x11" * 1000 + b"\0" * 8 * 3 + rec2(7, usn.FILE_DELETE) + b"\x22" * 5000
    blob = blob[: len(blob) - len(blob) % 8]
    one = [(r.offset, r.name) for r in usn.carve(io.BytesIO(blob), chunk=len(blob))]
    carver = usn.Carver()
    parts: list[usn.UsnRecord] = []
    for i in range(0, len(blob), 777 * 8):
        parts += carver.feed(blob[i : i + 777 * 8])
    parts += carver.close()
    assert [(r.offset, r.name) for r in parts] == one != []


def test_layout_matches_dissect_parser() -> None:
    usnjrnl = pytest.importorskip("dissect.ntfs.usnjrnl")
    blob = b"\0" * 4096 + rec2(4096, usn.FILE_DELETE | 0x80000000, "gone.txt")
    blob += usn.build_v3(
        entry=99,
        seq=7,
        parent_entry=5,
        parent_seq=5,
        usn=8,
        timestamp=T,
        reason=usn.FILE_CREATE,
        name="v3.txt",
    )
    theirs = list(usnjrnl.UsnJrnl(io.BytesIO(blob)).records())
    ours = list(usn.iter_buffer(blob))
    assert [r.major for r in ours] == [2, 3]
    # Dissect reads version 2 records only; compare those.
    ours = [r for r in ours if r.major == 2]
    assert len(theirs) == len(ours) == 1
    for a, b in zip(theirs, ours, strict=True):
        assert a.filename == b.name
        assert a.record.FileReferenceNumber.SegmentNumberLowPart == b.entry & 0xFFFFFFFF
        assert a.record.FileReferenceNumber.SequenceNumber == b.seq
        assert a.record.Usn == b.usn
        assert int(a.record.Reason) == b.reason
        assert a.timestamp_ns // 100 * 100 == (b.timestamp - filetime.UNIX_EPOCH_TICKS) * 100
