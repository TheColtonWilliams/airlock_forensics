"""``$MFT`` records (NTFS 3.x), standard library only.

Reads an extracted ``$MFT`` file record by record, applies the update sequence (fixup) array,
and returns the parts the analysis modules need: entry and sequence numbers, the in-use and
directory flags, ``$STANDARD_INFORMATION`` times (full 100 ns precision), owner and security
IDs, the last USN, every ``$FILE_NAME`` (parent reference, name, namespace, times), and the
``$DATA`` streams (unnamed size and alternate data streams).

Attributes held in extension records (``base_ref`` not zero) are merged into their base
record when the base record's sequence number matches. ``$ATTRIBUTE_LIST`` itself is not
followed; this only matters for files with very many names or streams.
"""

from __future__ import annotations

import mmap
import os
import struct
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

SIG_FILE = b"FILE"
SIG_BAAD = b"BAAD"
FLAG_IN_USE = 0x0001
FLAG_DIRECTORY = 0x0002
ATTR_SI = 0x10
ATTR_LIST = 0x20
ATTR_FN = 0x30
ATTR_DATA = 0x80
ATTR_END = 0xFFFFFFFF
NS_POSIX, NS_WIN32, NS_DOS, NS_WIN32_DOS = 0, 1, 2, 3
ROOT_ENTRY = 5
EXTEND_ENTRY = 11
FIRST_USER_ENTRY = 24
SECTOR = 512
MAX_DEPTH = 256


class MftError(ValueError):
    """The data is not an ``$MFT`` record or file."""


def split_ref(ref: int) -> tuple[int, int]:
    """``(entry, sequence)`` from a 64-bit file reference."""
    return ref & 0xFFFFFFFFFFFF, (ref >> 48) & 0xFFFF


@dataclass(slots=True)
class FileName:
    parent_entry: int
    parent_seq: int
    name: str
    namespace: int
    created: int
    modified: int
    changed: int
    accessed: int
    real_size: int


@dataclass(slots=True)
class Stream:
    name: str  # "" for the unnamed (default) data stream
    size: int
    resident: bool


@dataclass(slots=True)
class MftRecord:
    entry: int
    seq: int
    flags: int
    base_entry: int
    base_seq: int
    link_count: int
    lsn: int
    si_created: int = 0
    si_modified: int = 0
    si_changed: int = 0
    si_accessed: int = 0
    si_attributes: int = 0
    owner_id: int | None = None
    security_id: int | None = None
    usn: int | None = None
    names: list[FileName] = field(default_factory=list)
    streams: list[Stream] = field(default_factory=list)
    has_si: bool = False
    has_attribute_list: bool = False

    @property
    def in_use(self) -> bool:
        return bool(self.flags & FLAG_IN_USE)

    @property
    def is_dir(self) -> bool:
        return bool(self.flags & FLAG_DIRECTORY)

    @property
    def is_base(self) -> bool:
        return self.base_entry == 0

    def best_name(self) -> FileName | None:
        """The Win32 (long) name when there is one, else POSIX, else the DOS 8.3 name."""
        if not self.names:
            return None
        rank = {NS_WIN32: 0, NS_WIN32_DOS: 0, NS_POSIX: 1, NS_DOS: 2}
        return sorted(self.names, key=lambda n: (rank.get(n.namespace, 3), n.name))[0]

    def data_size(self) -> int | None:
        for s in self.streams:
            if s.name == "":
                return s.size
        return None


def _apply_fixups(buf: bytearray) -> bool:
    usa_ofs, usa_count = struct.unpack_from("<HH", buf, 4)
    if usa_count == 0:
        return True
    if usa_ofs + 2 * usa_count > len(buf) or usa_count - 1 > len(buf) // SECTOR:
        return False
    check = buf[usa_ofs : usa_ofs + 2]
    for i in range(1, usa_count):
        end = i * SECTOR
        if buf[end - 2 : end] != check:
            return False
        buf[end - 2 : end] = buf[usa_ofs + 2 * i : usa_ofs + 2 * i + 2]
    return True


def _u64(buf: bytes | bytearray, off: int) -> int:
    return struct.unpack_from("<Q", buf, off)[0]


def parse_record(data: bytes, entry: int) -> MftRecord | None:
    """One record, or None when it is empty, not a FILE record, or its fixups do not match."""
    if len(data) < 48 or data[:4] != SIG_FILE:
        return None
    buf = bytearray(data)
    if not _apply_fixups(buf):
        return None
    seq, link_count, attr_off, flags = struct.unpack_from("<HHHH", buf, 0x10)
    base_entry, base_seq = split_ref(_u64(buf, 0x20))
    rec = MftRecord(
        entry=entry,
        seq=seq,
        flags=flags,
        base_entry=base_entry,
        base_seq=base_seq,
        link_count=link_count,
        lsn=_u64(buf, 0x08),
    )
    used = min(struct.unpack_from("<I", buf, 0x18)[0], len(buf))
    off = attr_off
    while off + 16 <= used:
        atype, alen = struct.unpack_from("<II", buf, off)
        if atype == ATTR_END or alen < 16 or off + alen > used:
            break
        _parse_attribute(rec, buf, off, atype, alen)
        off += alen
    return rec


def _parse_attribute(rec: MftRecord, buf: bytearray, off: int, atype: int, alen: int) -> None:
    non_resident = buf[off + 8]
    name_len = buf[off + 9]
    name_off = struct.unpack_from("<H", buf, off + 10)[0]
    name = ""
    if name_len:
        raw = bytes(buf[off + name_off : off + name_off + 2 * name_len])
        name = raw.decode("utf-16-le", "surrogatepass")
    if atype == ATTR_LIST:
        rec.has_attribute_list = True
        return
    if non_resident:
        if atype == ATTR_DATA and off + 64 <= off + alen:
            size = _u64(buf, off + 48)
            rec.streams.append(Stream(name, size, False))
        return
    vlen, voff = struct.unpack_from("<IH", buf, off + 16)
    start = off + voff
    if start + vlen > off + alen:
        return
    value = bytes(buf[start : start + vlen])
    if atype == ATTR_SI and vlen >= 48:
        c, m, ch, a = struct.unpack_from("<QQQQ", value, 0)
        rec.si_created, rec.si_modified, rec.si_changed, rec.si_accessed = c, m, ch, a
        rec.si_attributes = struct.unpack_from("<I", value, 32)[0]
        rec.has_si = True
        if vlen >= 72:
            rec.owner_id, rec.security_id = struct.unpack_from("<II", value, 48)
            rec.usn = struct.unpack_from("<Q", value, 64)[0]
    elif atype == ATTR_FN and vlen >= 66:
        pentry, pseq = split_ref(_u64(value, 0))
        c, m, ch, a = struct.unpack_from("<QQQQ", value, 8)
        real_size = _u64(value, 48)
        nlen, ns = value[64], value[65]
        raw_name = value[66 : 66 + 2 * nlen]
        rec.names.append(
            FileName(
                parent_entry=pentry,
                parent_seq=pseq,
                name=raw_name.decode("utf-16-le", "surrogatepass"),
                namespace=ns,
                created=c,
                modified=m,
                changed=ch,
                accessed=a,
                real_size=real_size,
            )
        )
    elif atype == ATTR_DATA:
        rec.streams.append(Stream(name, vlen, True))


def record_size_of(path: str | Path) -> int:
    """The record size, read from the first record's allocated-size field (1024 or 4096)."""
    with open(path, "rb") as fh:
        head = fh.read(48)
    if len(head) < 48 or head[:4] != SIG_FILE:
        raise MftError("the first record is not a FILE record")
    size = struct.unpack_from("<I", head, 0x1C)[0]
    if size not in {1024, 2048, 4096}:
        raise MftError(f"unexpected record size {size}")
    return size


def iter_records(path: str | Path, record_size: int | None = None) -> Iterator[MftRecord]:
    """Every parseable record in file order (entry number = position)."""
    size = record_size or record_size_of(path)
    total = os.path.getsize(path)
    if total == 0:
        return
    with open(path, "rb") as fh, mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ) as mm:
        for entry in range(total // size):
            start = entry * size
            if mm[start : start + 4] != SIG_FILE:
                continue
            rec = parse_record(mm[start : start + size], entry)
            if rec is not None:
                yield rec


class MftIndex:
    """All base records of one ``$MFT`` by entry number, with path building."""

    def __init__(self, records: dict[int, MftRecord], skipped: int = 0) -> None:
        self.records = records
        self.skipped = skipped
        self._paths: dict[int, str] = {}

    @classmethod
    def load(cls, path: str | Path) -> MftIndex:
        base: dict[int, MftRecord] = {}
        extensions: list[MftRecord] = []
        total = 0
        for rec in iter_records(path):
            total += 1
            if rec.is_base:
                base[rec.entry] = rec
            else:
                extensions.append(rec)
        for ext in extensions:
            owner = base.get(ext.base_entry)
            if owner is None or owner.seq != ext.base_seq or not ext.in_use:
                continue
            owner.names.extend(ext.names)
            owner.streams.extend(ext.streams)
        size = record_size_of(path) if total else 1024
        slots = os.path.getsize(path) // size
        return cls(base, skipped=slots - total)

    def get(self, entry: int) -> MftRecord | None:
        return self.records.get(entry)

    def ref_matches(self, entry: int, seq: int) -> bool:
        rec = self.records.get(entry)
        if rec is None:
            return False
        # A deleted entry has its sequence number raised by one when it is freed.
        return rec.seq == seq or (not rec.in_use and rec.seq == (seq + 1) & 0xFFFF)

    def path_of(self, entry: int) -> str:
        """Full path from the root (``/`` separated). Unknown parents give ``/$OrphanFiles``."""
        if entry in self._paths:
            return self._paths[entry]
        parts: list[str] = []
        current = entry
        seen: set[int] = set()
        prefix = ""
        for _ in range(MAX_DEPTH):
            if current == ROOT_ENTRY:
                break
            rec = self.records.get(current)
            fn = rec.best_name() if rec else None
            if rec is None or fn is None or current in seen:
                prefix = "/$OrphanFiles"
                break
            seen.add(current)
            parts.append(fn.name)
            parent = self.records.get(fn.parent_entry)
            if fn.parent_entry != ROOT_ENTRY and (
                parent is None or not self.ref_matches(fn.parent_entry, fn.parent_seq)
            ):
                prefix = "/$OrphanFiles"
                break
            current = fn.parent_entry
        path = prefix + "/" + "/".join(reversed(parts)) if parts else (prefix or "/")
        self._paths[entry] = path
        return path

    def path_for_parent(self, parent_entry: int, parent_seq: int, name: str) -> str:
        """Path for a name under a parent reference (as in a USN record)."""
        if parent_entry == ROOT_ENTRY:
            return "/" + name
        if not self.ref_matches(parent_entry, parent_seq):
            return "/$OrphanFiles/" + name
        return self.path_of(parent_entry).rstrip("/") + "/" + name
