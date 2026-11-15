"""Windows recycle bin ``$I`` files (Vista and later), standard library only.

Layout (little endian):

* Version 1 (Windows Vista, 7, 8): ``u64 version = 1``, ``u64 file size``, ``u64 deletion
  time (FILETIME)``, then the original path as 260 UTF-16 characters (520 bytes, NUL padded).
  Total 544 bytes.
* Version 2 (Windows 10 and 11): ``u64 version = 2``, ``u64 file size``, ``u64 deletion
  time``, ``u32 path length in characters (with the final NUL)``, then the path in UTF-16.

The owner is not stored in the file: the folder ``$Recycle.Bin/<SID>/`` names the account SID.
The deleted content is the ``$R`` file with the same suffix.
"""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass
from pathlib import Path

from forensic_analyze.parsers import filetime

V1_PATH_BYTES = 520
V1_SIZE = 24 + V1_PATH_BYTES
MAX_V2_CHARS = 32768
SID_RE = re.compile(r"^S-1-\d+(?:-\d+)+$", re.IGNORECASE)
BIN_PATH_RE = re.compile(r"^/?\$recycle\.bin/(?P<sid>[^/]+)/(?P<name>\$i[^/]*)$", re.IGNORECASE)


class RecycleError(ValueError):
    """Not a ``$I`` file this parser understands."""


@dataclass(frozen=True, slots=True)
class IRecord:
    version: int
    file_size: int
    deleted_ticks: int
    original_path: str

    @property
    def deleted_iso(self) -> str | None:
        return filetime.to_iso(self.deleted_ticks)

    @property
    def original_name(self) -> str:
        return re.split(r"[\\/]", self.original_path)[-1] if self.original_path else ""


def _utf16z(raw: bytes) -> str:
    for i in range(0, len(raw) - 1, 2):
        if raw[i] == 0 and raw[i + 1] == 0:
            raw = raw[:i]
            break
    return raw.decode("utf-16-le", "surrogatepass")


def parse(data: bytes) -> IRecord:
    if len(data) < 24:
        raise RecycleError(f"too short for a $I file ({len(data)} bytes)")
    version, size, ticks = struct.unpack_from("<QQQ", data, 0)
    if version == 1:
        if len(data) < V1_SIZE:
            raise RecycleError(f"version 1 $I file is {len(data)} bytes, expected {V1_SIZE}")
        path = _utf16z(data[24 : 24 + V1_PATH_BYTES])
    elif version == 2:
        if len(data) < 28:
            raise RecycleError("version 2 $I file has no path length")
        chars = struct.unpack_from("<I", data, 24)[0]
        if chars == 0 or chars > MAX_V2_CHARS or 28 + 2 * chars > len(data):
            raise RecycleError(f"version 2 path length {chars} does not fit the file")
        path = _utf16z(data[28 : 28 + 2 * chars])
    else:
        raise RecycleError(f"unknown $I version {version}")
    if ticks and not filetime.plausible(ticks):
        raise RecycleError("deletion time is outside 1980..2100")
    return IRecord(version=version, file_size=size, deleted_ticks=ticks, original_path=path)


def parse_file(path: str | Path) -> IRecord:
    with open(path, "rb") as fh:
        data = fh.read(28 + 2 * MAX_V2_CHARS)
    return parse(data)


def build(original_path: str, size: int, deleted_ticks: int, *, version: int = 2) -> bytes:
    """A ``$I`` file as Windows writes it (for tests and fixtures)."""
    raw = (original_path + "\0").encode("utf-16-le")
    if version == 1:
        if len(raw) > V1_PATH_BYTES:
            raise RecycleError("path too long for a version 1 $I file")
        return struct.pack("<QQQ", 1, size, deleted_ticks) + raw.ljust(V1_PATH_BYTES, b"\0")
    return struct.pack("<QQQI", 2, size, deleted_ticks, len(raw) // 2) + raw


def split_bin_path(path: str) -> tuple[str, str] | None:
    """``(owner_sid, $I name)`` for ``/$Recycle.Bin/<SID>/$I...``, else None."""
    m = BIN_PATH_RE.match(path)
    if not m:
        return None
    return m.group("sid"), m.group("name")


def r_name_for(i_name: str) -> str:
    """The ``$R`` content file name that goes with a ``$I`` name."""
    return "$R" + i_name[2:]


def is_sid(text: str) -> bool:
    return bool(SID_RE.match(text))
