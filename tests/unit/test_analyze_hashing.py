"""Read-error tolerant target hashing (tasks 4C.17, 4G.8).

A reader that raises EIO stands in for a drive with bad sectors (device-mapper's error target
is not available in the authoring container; see tests/functional/test_faults.sh).
"""

from __future__ import annotations

import errno
import hashlib
from pathlib import Path

from forensic_analyze import runner

SIZE = 3 * 1024 * 1024 + 1536


def _data() -> bytes:
    return bytes((i * 7) % 251 for i in range(SIZE))


def _reader(data: bytes, bad: set[int]):
    def read(offset: int, length: int) -> bytes:
        for sector in range(offset // 512, (offset + length + 511) // 512):
            if sector in bad:
                raise OSError(errno.EIO, "Input/output error")
        return data[offset : offset + length]

    return read


def test_clean_read_matches_hashlib() -> None:
    data = _data()
    res = runner.hash_tolerant(Path("/unused"), reader=_reader(data, set()), size=len(data))
    assert res["complete"] and res["bad_ranges"] == []
    assert res["sha256"] == hashlib.sha256(data).hexdigest()
    assert res["md5"] == hashlib.md5(data).hexdigest()  # noqa: S324


def test_bad_sectors_are_zeros_and_listed() -> None:
    data = _data()
    bad = {10, 11, 12, 4000}
    res = runner.hash_tolerant(Path("/unused"), reader=_reader(data, bad), size=len(data))
    expected = bytearray(data)
    for s in bad:
        expected[s * 512 : s * 512 + 512] = b"\0" * 512
    assert not res["complete"]
    assert res["bad_ranges"] == [[10 * 512, 13 * 512], [4000 * 512, 4001 * 512]]
    assert res["bad_bytes"] == 4 * 512
    assert res["sha256"] == hashlib.sha256(bytes(expected)).hexdigest()
    assert res["unreadable_as"] == "zeros"


def test_hash_or_error_on_a_regular_file(tmp_path: Path) -> None:
    f = tmp_path / "x.img"
    f.write_bytes(b"abc")
    res = runner._hash_or_error(f)
    assert res["complete"] and res["sha256"].startswith("ba7816bf")
    missing = runner._hash_or_error(tmp_path / "missing.img")
    assert "error" in missing and "sha256" not in missing
