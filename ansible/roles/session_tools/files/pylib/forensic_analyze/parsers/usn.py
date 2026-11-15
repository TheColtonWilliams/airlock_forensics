"""USN change journal records (``$Extend/$UsnJrnl:$J``), standard library only.

USN_RECORD_V2 (major 2) and USN_RECORD_V3 (major 3, 128-bit file IDs; NTFS uses the low 64
bits) are parsed. V4 range records carry no name and are skipped. Layouts are from the
Windows SDK (``winioctl.h``): https://learn.microsoft.com/windows/win32/api/winioctl/

``iter_journal`` walks an extracted ``$J`` stream (which starts with a long sparse region of
zeros). ``carve`` finds records anywhere in raw bytes, for example unallocated space, and
validates each candidate strictly so random data is not reported.
"""

from __future__ import annotations

import mmap
import os
import re
import struct
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

from forensic_analyze.parsers import filetime

V2_HEADER = 0x3C  # 60 bytes before the name
V3_HEADER = 0x4C  # 76 bytes before the name
MAX_RECORD = 0x1000
CHUNK = 8 * 1024 * 1024

REASONS: dict[int, str] = {
    0x00000001: "DATA_OVERWRITE",
    0x00000002: "DATA_EXTEND",
    0x00000004: "DATA_TRUNCATION",
    0x00000010: "NAMED_DATA_OVERWRITE",
    0x00000020: "NAMED_DATA_EXTEND",
    0x00000040: "NAMED_DATA_TRUNCATION",
    0x00000100: "FILE_CREATE",
    0x00000200: "FILE_DELETE",
    0x00000400: "EA_CHANGE",
    0x00000800: "SECURITY_CHANGE",
    0x00001000: "RENAME_OLD_NAME",
    0x00002000: "RENAME_NEW_NAME",
    0x00004000: "INDEXABLE_CHANGE",
    0x00008000: "BASIC_INFO_CHANGE",
    0x00010000: "HARD_LINK_CHANGE",
    0x00020000: "COMPRESSION_CHANGE",
    0x00040000: "ENCRYPTION_CHANGE",
    0x00080000: "OBJECT_ID_CHANGE",
    0x00100000: "REPARSE_POINT_CHANGE",
    0x00200000: "STREAM_CHANGE",
    0x00400000: "TRANSACTED_CHANGE",
    0x00800000: "INTEGRITY_CHANGE",
    0x01000000: "DESIRED_STORAGE_CLASS_CHANGE",
    0x80000000: "CLOSE",
}
KNOWN_REASON_BITS = sum(REASONS)
FILE_CREATE = 0x100
FILE_DELETE = 0x200
RENAME_OLD_NAME = 0x1000
RENAME_NEW_NAME = 0x2000
BASIC_INFO_CHANGE = 0x8000
CLOSE = 0x80000000

_NONZERO = re.compile(rb"[^\x00]")
_V2_MAGIC = re.compile(rb"\x02\x00\x00\x00", re.DOTALL)
_V3_MAGIC = re.compile(rb"\x03\x00\x00\x00", re.DOTALL)


class UsnError(ValueError):
    """Bytes that are not a USN record."""


@dataclass(frozen=True, slots=True)
class UsnRecord:
    offset: int  # byte offset of the record in the source it was read from
    major: int
    minor: int
    entry: int
    seq: int
    parent_entry: int
    parent_seq: int
    usn: int
    timestamp: int  # FILETIME ticks
    reason: int
    source_info: int
    security_id: int
    attributes: int
    name: str

    @property
    def iso_time(self) -> str | None:
        return filetime.to_iso(self.timestamp)

    @property
    def reasons(self) -> list[str]:
        return reason_names(self.reason)

    @property
    def is_delete(self) -> bool:
        return bool(self.reason & FILE_DELETE)


def reason_names(reason: int) -> list[str]:
    return [name for bit, name in sorted(REASONS.items()) if reason & bit]


def reason_text(reason: int) -> str:
    return "|".join(reason_names(reason)) or f"0x{reason:08x}"


def parse_record(buf: bytes | memoryview | mmap.mmap, off: int = 0) -> UsnRecord:
    """Parse one record at ``off``. Raises ``UsnError`` when it is not a valid V2/V3 record."""
    if off + 8 > len(buf):
        raise UsnError("truncated")
    length, major, minor = struct.unpack_from("<IHH", buf, off)
    if length < V2_HEADER or length % 8 or length > MAX_RECORD or off + length > len(buf):
        raise UsnError(f"bad record length {length}")
    if major == 2:
        ref, pref, usn, ts, reason, source, sec, attrs, nlen, noff = struct.unpack_from(
            "<QQqqIIIIHH", buf, off + 8
        )
        entry, seq = ref & 0xFFFFFFFFFFFF, ref >> 48
        pentry, pseq = pref & 0xFFFFFFFFFFFF, pref >> 48
        header = V2_HEADER
    elif major == 3:
        if length < V3_HEADER:
            raise UsnError("short V3 record")
        ref_lo, _ref_hi, pref_lo, _pref_hi = struct.unpack_from("<QQQQ", buf, off + 8)
        usn, ts, reason, source, sec, attrs, nlen, noff = struct.unpack_from(
            "<qqIIIIHH", buf, off + 40
        )
        entry, seq = ref_lo & 0xFFFFFFFFFFFF, ref_lo >> 48
        pentry, pseq = pref_lo & 0xFFFFFFFFFFFF, pref_lo >> 48
        header = V3_HEADER
    else:
        raise UsnError(f"unsupported major version {major}")
    if noff < header or nlen % 2 or noff + nlen > length:
        raise UsnError("name outside the record")
    raw = bytes(buf[off + noff : off + noff + nlen])
    return UsnRecord(
        offset=off,
        major=major,
        minor=minor,
        entry=entry,
        seq=seq,
        parent_entry=pentry,
        parent_seq=pseq,
        usn=usn,
        timestamp=ts,
        reason=reason,
        source_info=source,
        security_id=sec,
        attributes=attrs,
        name=raw.decode("utf-16-le", "surrogatepass"),
    )


def iter_buffer(buf: bytes | memoryview | mmap.mmap, base: int = 0) -> Iterator[UsnRecord]:
    """Records in a journal buffer, skipping zero padding and sparse regions."""
    pos, end = 0, len(buf)
    while pos + 8 <= end:
        length = struct.unpack_from("<I", buf, pos)[0]
        if length == 0:
            m = _NONZERO.search(buf, pos)
            if m is None:
                return
            pos = m.start() & ~7
            if struct.unpack_from("<I", buf, pos)[0] == 0:
                pos += 8
            continue
        try:
            rec = parse_record(buf, pos)
        except UsnError:
            pos += 8
            continue
        if base:
            rec = _rebase(rec, base)
        yield rec
        pos += length


def _rebase(rec: UsnRecord, base: int) -> UsnRecord:
    return UsnRecord(**{**{k: getattr(rec, k) for k in rec.__slots__}, "offset": rec.offset + base})


def iter_journal(path: str | Path) -> Iterator[UsnRecord]:
    """Every record of an extracted ``$J`` file (memory-mapped, so size is no problem)."""
    if os.path.getsize(path) == 0:
        return
    with open(path, "rb") as fh, mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ) as mm:
        yield from iter_buffer(mm)


def plausible(rec: UsnRecord) -> bool:
    """Strict checks for carved candidates: known reason bits, sane time, real name."""
    checks = (
        rec.minor == 0,
        bool(rec.name) and len(rec.name) <= 255,
        rec.reason != 0 and not rec.reason & ~KNOWN_REASON_BITS,
        filetime.plausible(rec.timestamp) and rec.usn >= 0,
        not any(ch in rec.name for ch in "\x00/\\"),
        rec.entry > 0 and rec.parent_entry > 0,
    )
    if not all(checks):
        return False
    try:
        rec.name.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


def _carve_buffer(buf: bytes, base: int, limit: int) -> Iterator[UsnRecord]:
    for magic, header in ((_V2_MAGIC, V2_HEADER), (_V3_MAGIC, V3_HEADER)):
        for m in magic.finditer(buf):
            off = m.start() - 4
            if off < 0 or off % 8 or off >= limit:
                continue
            if off + header > len(buf):
                continue
            if struct.unpack_from("<H", buf, off + header - 2)[0] != header:
                continue
            try:
                rec = parse_record(buf, off)
            except UsnError:
                continue
            if plausible(rec):
                yield _rebase(rec, base)


class Carver:
    """Incremental carver: ``feed`` raw bytes in order, then ``close``; offsets are stream
    offsets. Records are 8-byte aligned inside journal pages and pages are cluster aligned, so
    candidates are only checked at 8-byte aligned stream offsets."""

    def __init__(self) -> None:
        self._carry = b""
        self._base = 0
        self._seen: set[int] = set()

    def _scan(self, buf: bytes, limit: int) -> list[UsnRecord]:
        out = []
        for rec in sorted(_carve_buffer(buf, self._base, limit), key=lambda r: r.offset):
            if rec.offset not in self._seen:
                self._seen.add(rec.offset)
                out.append(rec)
        return out

    def feed(self, data: bytes) -> list[UsnRecord]:
        buf = self._carry + data
        limit = max(len(buf) - MAX_RECORD, 0)
        limit -= limit % 8
        found = self._scan(buf, limit)
        self._carry = buf[limit:]
        self._base += limit
        if len(self._seen) > 1_000_000:
            self._seen = {o for o in self._seen if o >= self._base}
        return found

    def close(self) -> list[UsnRecord]:
        found = self._scan(self._carry, len(self._carry))
        self._base += len(self._carry)
        self._carry = b""
        return found


def carve(stream: BinaryIO, *, chunk: int = CHUNK) -> Iterator[UsnRecord]:
    """Find USN records in raw bytes read from ``stream`` (e.g. unallocated clusters)."""
    carver = Carver()
    while True:
        data = stream.read(chunk)
        if not data:
            break
        yield from carver.feed(data)
    yield from carver.close()


def build_v2(
    *,
    entry: int,
    seq: int,
    parent_entry: int,
    parent_seq: int,
    usn: int,
    timestamp: int,
    reason: int,
    name: str,
    source_info: int = 0,
    security_id: int = 0,
    attributes: int = 0x20,
) -> bytes:
    """A USN_RECORD_V2 as Windows writes it (used to build test data and fixtures)."""
    raw = name.encode("utf-16-le")
    length = (V2_HEADER + len(raw) + 7) & ~7
    head = struct.pack(
        "<IHHQQqqIIIIHH",
        length,
        2,
        0,
        (seq << 48) | entry,
        (parent_seq << 48) | parent_entry,
        usn,
        timestamp,
        reason,
        source_info,
        security_id,
        attributes,
        len(raw),
        V2_HEADER,
    )
    return (head + raw).ljust(length, b"\0")


def build_v3(
    *,
    entry: int,
    seq: int,
    parent_entry: int,
    parent_seq: int,
    usn: int,
    timestamp: int,
    reason: int,
    name: str,
) -> bytes:
    """A USN_RECORD_V3 (128-bit references; NTFS keeps the reference in the low 64 bits)."""
    raw = name.encode("utf-16-le")
    length = (V3_HEADER + len(raw) + 7) & ~7
    head = struct.pack(
        "<IHHQQQQqqIIIIHH",
        length,
        3,
        0,
        (seq << 48) | entry,
        0,
        (parent_seq << 48) | parent_entry,
        0,
        usn,
        timestamp,
        reason,
        0,
        0,
        0x20,
        len(raw),
        V3_HEADER,
    )
    return (head + raw).ljust(length, b"\0")


def pair_renames(records: Iterable[UsnRecord]) -> list[tuple[UsnRecord, UsnRecord | None]]:
    """``(old_name_record, new_name_record)`` pairs: each RENAME_OLD_NAME with the next
    RENAME_NEW_NAME for the same file reference."""
    pending: dict[tuple[int, int], UsnRecord] = {}
    pairs: list[tuple[UsnRecord, UsnRecord | None]] = []
    for rec in records:
        key = (rec.entry, rec.seq)
        if rec.reason & RENAME_OLD_NAME:
            if key in pending:
                pairs.append((pending.pop(key), None))
            pending[key] = rec
        elif rec.reason & RENAME_NEW_NAME and key in pending:
            pairs.append((pending.pop(key), rec))
    pairs.extend((rec, None) for rec in pending.values())
    return sorted(pairs, key=lambda p: p[0].usn)
