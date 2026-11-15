"""NTFS ``$Secure:$SDS`` security descriptor stream, standard library only.

The stream holds entries ``{u32 hash, u32 security_id, u64 offset, u32 length}`` followed by a
self-relative SECURITY_DESCRIPTOR, 16-byte aligned, in 256 KiB blocks each followed by a
256 KiB mirror copy. A file's ``$STANDARD_INFORMATION`` security ID points here; the owner SID
of the descriptor is the account SID that owns the file.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path

BLOCK = 0x40000
HEADER = 20


class SdsError(ValueError):
    """Not a security descriptor entry."""


@dataclass(frozen=True, slots=True)
class SecurityEntry:
    security_id: int
    hash: int
    offset: int
    owner_sid: str | None
    group_sid: str | None


def sid_to_str(data: bytes, off: int) -> str:
    """``S-1-...`` text for a binary SID at ``off``."""
    if off + 8 > len(data):
        raise SdsError("SID outside the data")
    rev, count = data[off], data[off + 1]
    if rev != 1 or count > 15 or off + 8 + 4 * count > len(data):
        raise SdsError("not a SID")
    authority = int.from_bytes(data[off + 2 : off + 8], "big")
    subs = struct.unpack_from(f"<{count}I", data, off + 8)
    return "S-1-" + "-".join(str(x) for x in (authority, *subs))


def sid_to_bytes(sid: str) -> bytes:
    """Binary SID from ``S-1-...`` text (for tests)."""
    parts = sid.split("-")
    if parts[:2] != ["S", "1"] or len(parts) < 3:
        raise SdsError(f"not a SID: {sid}")
    authority = int(parts[2])
    subs = [int(p) for p in parts[3:]]
    return (
        bytes([1, len(subs)]) + authority.to_bytes(6, "big") + struct.pack(f"<{len(subs)}I", *subs)
    )


def parse_descriptor(sd: bytes) -> tuple[str | None, str | None]:
    """``(owner_sid, group_sid)`` of a self-relative security descriptor."""
    if len(sd) < 20 or sd[0] != 1:
        raise SdsError("not a self-relative security descriptor")
    owner_off, group_off = struct.unpack_from("<II", sd, 4)
    owner = sid_to_str(sd, owner_off) if owner_off else None
    group = sid_to_str(sd, group_off) if group_off else None
    return owner, group


def parse(data: bytes) -> dict[int, SecurityEntry]:
    """Every valid entry by security ID (the first copy wins; mirrors are skipped)."""
    out: dict[int, SecurityEntry] = {}
    pos = 0
    size = len(data)
    while pos + HEADER <= size:
        hsh, sec_id, offset, length = struct.unpack_from("<IIQI", data, pos)
        if length < HEADER or offset != pos or pos + length > size:
            nxt = (pos // BLOCK + 1) * BLOCK
            # Mirror blocks sit at odd 256 KiB positions; their entries carry the offset of
            # the primary copy, so they fail the offset check and are skipped here.
            pos = nxt if length == 0 or offset != pos else (pos + 16) & ~15
            continue
        try:
            owner, group = parse_descriptor(data[pos + HEADER : pos + length])
        except SdsError:
            owner, group = None, None
        out.setdefault(sec_id, SecurityEntry(sec_id, hsh, offset, owner, group))
        pos = (pos + length + 15) & ~15
    return out


def parse_file(path: str | Path) -> dict[int, SecurityEntry]:
    return parse(Path(path).read_bytes())


def build_entry(security_id: int, owner_sid: str, group_sid: str, offset: int) -> bytes:
    """One ``$SDS`` entry with a minimal descriptor (owner and group only), for tests."""
    owner = sid_to_bytes(owner_sid)
    group = sid_to_bytes(group_sid)
    sd = struct.pack("<BBHIIII", 1, 0, 0x8000, 20, 20 + len(owner), 0, 0) + owner + group
    length = HEADER + len(sd)
    return struct.pack("<IIQI", 0, security_id, offset, length) + sd
