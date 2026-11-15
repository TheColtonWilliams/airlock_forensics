"""Windows shell link (``.lnk``) files, basic fields, standard library only.

Follows [MS-SHLLINK] (https://learn.microsoft.com/openspecs/windows_protocols/ms-shllink/):
the 76-byte ShellLinkHeader (flags, target attributes, target creation, access, and write
times, target size), the LinkTargetIDList is skipped, LinkInfo gives the volume (drive type,
serial number, label) and the local or network base path, and StringData gives the name,
relative path, and working directory. Command-line arguments are not returned: they are
evidence text with no use in these findings.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path

from forensic_analyze.parsers import filetime

HEADER_SIZE = 0x4C
LINK_CLSID = bytes.fromhex("0114020000000000c000000000000046")
HAS_ID_LIST = 0x01
HAS_LINK_INFO = 0x02
HAS_NAME = 0x04
HAS_RELATIVE_PATH = 0x08
HAS_WORKING_DIR = 0x10
HAS_ARGUMENTS = 0x20
HAS_ICON_LOCATION = 0x40
IS_UNICODE = 0x80
LI_VOLUME_AND_LOCAL = 0x01
LI_NETWORK = 0x02
DRIVE_TYPES = {
    0: "unknown",
    1: "no root directory",
    2: "removable",
    3: "fixed",
    4: "network",
    5: "optical",
    6: "RAM disk",
}
MAX_STRING = 32768


class LnkError(ValueError):
    """Not a shell link file."""


@dataclass(frozen=True, slots=True)
class LnkInfo:
    flags: int
    target_attributes: int
    target_created: int
    target_accessed: int
    target_modified: int
    target_size: int
    local_path: str = ""
    network_path: str = ""
    drive_type: str = ""
    volume_serial: str = ""  # 8 hex digits, as Windows shows it (XXXX-XXXX without the dash)
    volume_label: str = ""
    name: str = ""
    relative_path: str = ""
    working_dir: str = ""

    @property
    def target_path(self) -> str:
        return self.local_path or self.network_path or self.relative_path

    def times(self) -> list[tuple[str, str]]:
        """``(timestamp_desc, iso)`` for each target time that is set."""
        out = []
        for desc, ticks in (
            ("Creation Time (LNK target)", self.target_created),
            ("Content Modification Time (LNK target)", self.target_modified),
            ("Last Access Time (LNK target)", self.target_accessed),
        ):
            iso = filetime.to_iso(ticks)
            if iso:
                out.append((desc, iso))
        return out


def _cstr(data: bytes, off: int, *, unicode: bool) -> str:
    if off <= 0 or off >= len(data):
        return ""
    if unicode:
        end = off
        while end + 1 < len(data) and (data[end] or data[end + 1]):
            end += 2
        return data[off:end].decode("utf-16-le", "surrogatepass")
    end = data.find(b"\0", off)
    end = len(data) if end < 0 else end
    # "ANSI" strings use the system code page, which the file does not record; cp1252 is the
    # common Western default and maps every byte, so nothing is lost.
    return data[off:end].decode("cp1252", "replace")


def _link_info(data: bytes, off: int) -> tuple[dict[str, str], int]:
    if off + 28 > len(data):
        raise LnkError("LinkInfo outside the file")
    size, hsize, flags, vol_off, local_off, net_off, suffix_off = struct.unpack_from(
        "<7I", data, off
    )
    if size < 28 or off + size > len(data):
        raise LnkError("bad LinkInfo size")
    block = data[off : off + size]
    out: dict[str, str] = {}
    local_u = suffix_u = 0
    if hsize >= 0x24 and len(block) >= 0x24:
        local_u, suffix_u = struct.unpack_from("<II", block, 28)
    if flags & LI_VOLUME_AND_LOCAL and vol_off and vol_off + 16 <= len(block):
        vsize, dtype, serial, label_off = struct.unpack_from("<4I", block, vol_off)
        out["drive_type"] = DRIVE_TYPES.get(dtype, f"type {dtype}")
        out["volume_serial"] = f"{serial:08X}"
        vol = block[vol_off : vol_off + vsize]
        if label_off == 0x14 and len(vol) >= 20:
            out["volume_label"] = _cstr(vol, struct.unpack_from("<I", vol, 16)[0], unicode=True)
        else:
            out["volume_label"] = _cstr(vol, label_off, unicode=False)
        base = _cstr(block, local_u, unicode=True) if local_u else ""
        base = base or _cstr(block, local_off, unicode=False)
        suffix = _cstr(block, suffix_u, unicode=True) if suffix_u else ""
        suffix = suffix or _cstr(block, suffix_off, unicode=False)
        out["local_path"] = base + suffix
    if flags & LI_NETWORK and net_off and net_off + 20 <= len(block):
        _nsize, _nflags, name_off = struct.unpack_from("<III", block, net_off)
        net = _cstr(block, net_off + name_off, unicode=False)
        suffix = _cstr(block, suffix_off, unicode=False)
        out["network_path"] = net + ("\\" + suffix if suffix else "")
    return out, size


def _string(data: bytes, off: int, *, unicode: bool) -> tuple[str, int]:
    if off + 2 > len(data):
        raise LnkError("StringData outside the file")
    count = struct.unpack_from("<H", data, off)[0]
    nbytes = count * (2 if unicode else 1)
    if count > MAX_STRING or off + 2 + nbytes > len(data):
        raise LnkError("StringData too long")
    raw = data[off + 2 : off + 2 + nbytes]
    text = raw.decode("utf-16-le", "surrogatepass") if unicode else raw.decode("cp1252", "replace")
    return text, off + 2 + nbytes


def parse(data: bytes) -> LnkInfo:
    if len(data) < HEADER_SIZE:
        raise LnkError("too short for a shell link")
    hsize = struct.unpack_from("<I", data, 0)[0]
    if hsize != HEADER_SIZE or data[4:20] != LINK_CLSID:
        raise LnkError("not a shell link (header size or class ID)")
    flags, attrs, created, accessed, written, size = struct.unpack_from("<IIQQQI", data, 20)
    off = HEADER_SIZE
    if flags & HAS_ID_LIST:
        if off + 2 > len(data):
            raise LnkError("IDList outside the file")
        off += 2 + struct.unpack_from("<H", data, off)[0]
    fields: dict[str, str] = {}
    if flags & HAS_LINK_INFO:
        info, used = _link_info(data, off)
        fields.update(info)
        off += used
    unicode = bool(flags & IS_UNICODE)
    for flag, key in (
        (HAS_NAME, "name"),
        (HAS_RELATIVE_PATH, "relative_path"),
        (HAS_WORKING_DIR, "working_dir"),
        (HAS_ARGUMENTS, ""),
        (HAS_ICON_LOCATION, ""),
    ):
        if flags & flag:
            try:
                text, off = _string(data, off, unicode=unicode)
            except LnkError:
                break
            if key:
                fields[key] = text
    return LnkInfo(
        flags=flags,
        target_attributes=attrs,
        target_created=created,
        target_accessed=accessed,
        target_modified=written,
        target_size=size,
        **fields,
    )


def parse_file(path: str | Path) -> LnkInfo:
    with open(path, "rb") as fh:
        return parse(fh.read(1024 * 1024))


def build(
    local_path: str,
    *,
    created: int,
    accessed: int,
    modified: int,
    size: int,
    serial: int = 0x1234ABCD,
    label: str = "",
    drive_type: int = 3,
    relative_path: str = "",
) -> bytes:
    """A minimal shell link with LinkInfo (ANSI local path) for tests and fixtures."""
    flags = HAS_LINK_INFO | IS_UNICODE | (HAS_RELATIVE_PATH if relative_path else 0)
    header = struct.pack(
        "<I16sIIQQQIiIH10x",
        HEADER_SIZE,
        LINK_CLSID,
        flags,
        0x20,
        created,
        accessed,
        modified,
        size,
        0,
        1,
        0,
    )
    label_b = label.encode("cp1252") + b"\0"
    volume = struct.pack("<4I", 16 + len(label_b), drive_type, serial, 16) + label_b
    path_b = local_path.encode("cp1252") + b"\0"
    head_len = 28
    vol_off = head_len
    local_off = vol_off + len(volume)
    suffix_off = local_off + len(path_b)
    body = volume + path_b + b"\0"
    total = head_len + len(body)
    info = (
        struct.pack("<7I", total, head_len, LI_VOLUME_AND_LOCAL, vol_off, local_off, 0, suffix_off)
        + body
    )
    tail = b""
    if relative_path:
        raw = relative_path.encode("utf-16-le")
        tail = struct.pack("<H", len(raw) // 2) + raw
    return header + info + tail + b"\0\0\0\0"
