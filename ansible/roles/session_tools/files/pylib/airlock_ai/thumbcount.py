"""Count thumbnail-cache entries without extracting any thumbnail (tasks 4C.8, 4B.17).

Stand-alone, standard library only, so it can run as a sandboxed parser:

    python3 -I thumbcount.py FILE

prints one JSON object: ``{"format": "thumbcache" | "thumbs.db" | "unknown", "version",
"entries", "entries_with_data", "error"}``. Formats:

* ``thumbcache_*.db`` (Windows Vista and later): a ``CMMM`` header, then entries that each
  start with ``CMMM`` and their own size; walked by size, bounded by the file size;
* ``Thumbs.db`` (Windows XP and earlier, and folder caches on later systems): an OLE compound
  file; thumbnail streams are counted from the directory (every stream except ``Catalog``).

Only counts leave this script. Thumbnail images are never decoded, written, or shown.
"""

from __future__ import annotations

import json
import struct
import sys
from typing import Any

CFB_MAGIC = bytes.fromhex("D0CF11E0A1B11AE1")
MAX_SECTORS = 1 << 22
END_OF_CHAIN = 0xFFFFFFFE
FREE = 0xFFFFFFFF


def count_thumbcache(data: bytes) -> dict[str, Any]:
    version = struct.unpack_from("<I", data, 4)[0] if len(data) >= 8 else 0
    pos = data.find(b"CMMM", 4)
    entries = with_data = 0
    data_off = 32 if version == 20 else 24  # Vista keeps an 8-byte extension field first
    while 0 < pos <= len(data) - 8 and data[pos : pos + 4] == b"CMMM":
        size = struct.unpack_from("<I", data, pos + 4)[0]
        if size < 8 or pos + size > len(data):
            break
        entries += 1
        if pos + data_off + 4 <= len(data) and struct.unpack_from("<I", data, pos + data_off)[0]:
            with_data += 1
        pos += size
    return {
        "format": "thumbcache",
        "version": version,
        "entries": entries,
        "entries_with_data": with_data,
        "error": "",
    }


def _chain(fat: list[int], start: int) -> list[int]:
    out: list[int] = []
    seen: set[int] = set()
    cur = start
    while cur not in (END_OF_CHAIN, FREE) and cur < len(fat) and cur not in seen:
        seen.add(cur)
        out.append(cur)
        cur = fat[cur]
        if len(out) > MAX_SECTORS:
            break
    return out


def count_cfb(data: bytes) -> dict[str, Any]:
    if len(data) < 512:
        return {"format": "thumbs.db", "entries": 0, "error": "file shorter than a header"}
    shift = struct.unpack_from("<H", data, 0x1E)[0]
    if shift not in (9, 12):
        return {"format": "thumbs.db", "entries": 0, "error": "unexpected sector size"}
    ssize = 1 << shift
    n_fat = struct.unpack_from("<I", data, 0x2C)[0]
    dir_start = struct.unpack_from("<I", data, 0x30)[0]
    difat = list(struct.unpack_from("<109I", data, 0x4C))
    difat_next = struct.unpack_from("<I", data, 0x44)[0]
    hops = 0
    while difat_next not in (END_OF_CHAIN, FREE) and hops < 1024:
        off = (difat_next + 1) * ssize
        if off + ssize > len(data):
            break
        vals = list(struct.unpack_from(f"<{ssize // 4}I", data, off))
        difat += vals[:-1]
        difat_next = vals[-1]
        hops += 1

    def sector(i: int) -> bytes:
        off = (i + 1) * ssize
        return data[off : off + ssize] if off + ssize <= len(data) else b""

    fat: list[int] = []
    for s in [d for d in difat if d not in (FREE, END_OF_CHAIN)][: min(n_fat, MAX_SECTORS)]:
        raw = sector(s)
        if len(raw) == ssize:
            fat += list(struct.unpack(f"<{ssize // 4}I", raw))
    streams = 0
    for s in _chain(fat, dir_start):
        raw = sector(s)
        for off in range(0, len(raw) - 127, 128):
            name_len = struct.unpack_from("<H", raw, off + 64)[0]
            kind = raw[off + 66]
            if kind != 2 or not 2 <= name_len <= 64:
                continue
            name = raw[off : off + name_len - 2].decode("utf-16-le", "replace")
            if name != "Catalog":
                streams += 1
    return {"format": "thumbs.db", "entries": streams, "entries_with_data": streams, "error": ""}


def count(path: str) -> dict[str, Any]:
    try:
        with open(path, "rb") as fh:
            data = fh.read(1 << 30)
    except OSError as exc:
        return {"format": "unknown", "entries": 0, "error": f"cannot read: {exc.strerror}"}
    try:
        if data[:4] == b"CMMM":
            return count_thumbcache(data)
        if data[:8] == CFB_MAGIC:
            return count_cfb(data)
    except struct.error as exc:
        return {"format": "unknown", "entries": 0, "error": f"damaged file: {exc}"}
    return {"format": "unknown", "entries": 0, "error": "not a thumbnail cache"}


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: thumbcount.py FILE", file=sys.stderr)
        raise SystemExit(2)
    print(json.dumps(count(sys.argv[1]), sort_keys=True))
