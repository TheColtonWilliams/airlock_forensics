"""The Sleuth Kit bodyfile (``fls -m``) lines.

Format (TSK 3.x+): ``MD5|name|inode|mode_as_string|UID|GID|size|atime|mtime|ctime|crtime``,
times in whole seconds since 1970 (0 = unknown). ``fls`` marks a deleted name with a trailing
`` (deleted)`` (or `` (deleted-realloc)`` when the metadata entry was reused) and a
``$FILE_NAME`` time line with `` ($FILE_NAME)``. A name may itself hold ``|``, so the fixed
fields are taken from both ends of the line.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

DELETED = " (deleted)"
DELETED_REALLOC = " (deleted-realloc)"
FN_SUFFIX = " ($FILE_NAME)"
_ADDR_RE = re.compile(r"^(\d+)(?:-(\d+)-(\d+))?$")


class BodyfileError(ValueError):
    """A line is not a bodyfile line."""


@dataclass(frozen=True, slots=True)
class BodyEntry:
    line_no: int
    md5: str
    name: str  # without the (deleted) and ($FILE_NAME) markers
    raw_name: str  # as fls wrote it
    inode: str  # TSK metadata address, e.g. "68-128-2" or "16"
    mode: str
    uid: str
    gid: str
    size: int
    atime: int
    mtime: int
    ctime: int
    crtime: int
    deleted: bool  # the name is deleted
    realloc: bool  # deleted name whose metadata entry was reused
    file_name_attr: bool  # times are from $FILE_NAME

    @property
    def entry(self) -> int | None:
        m = _ADDR_RE.match(self.inode)
        return int(m.group(1)) if m else None

    @property
    def attr_type(self) -> int | None:
        m = _ADDR_RE.match(self.inode)
        return int(m.group(2)) if m and m.group(2) else None

    @property
    def is_dir(self) -> bool:
        return self.mode[:1] == "d" or self.mode[2:3] == "d"

    @property
    def allocated(self) -> bool:
        """The metadata entry is allocated (live file, or a reused entry)."""
        return not self.deleted or self.realloc


def split_name(raw: str) -> tuple[str, bool, bool, bool]:
    """``(name, deleted, realloc, file_name_attr)`` from an ``fls -m`` name."""
    name, deleted, realloc = raw, False, False
    if name.endswith(DELETED_REALLOC):
        name, deleted, realloc = name[: -len(DELETED_REALLOC)], True, True
    elif name.endswith(DELETED):
        name, deleted = name[: -len(DELETED)], True
    fn = name.endswith(FN_SUFFIX)
    if fn:
        name = name[: -len(FN_SUFFIX)]
    return name, deleted, realloc, fn


def _int(text: str) -> int:
    text = text.strip()
    if not text or text == "None":
        return 0
    try:
        return int(float(text))
    except ValueError as exc:
        raise BodyfileError(f"not a number: {text[:20]!r}") from exc


def parse_line(line: str, line_no: int = 0) -> BodyEntry:
    parts = line.rstrip("\r\n").split("|")
    if len(parts) < 11:
        raise BodyfileError(f"line {line_no}: {len(parts)} fields, need 11")
    md5 = parts[0]
    tail = parts[-9:]
    raw = "|".join(parts[1:-9])
    name, deleted, realloc, fn = split_name(raw)
    return BodyEntry(
        line_no=line_no,
        md5=md5,
        name=name,
        raw_name=raw,
        inode=tail[0],
        mode=tail[1],
        uid=tail[2],
        gid=tail[3],
        size=_int(tail[4]),
        atime=_int(tail[5]),
        mtime=_int(tail[6]),
        ctime=_int(tail[7]),
        crtime=_int(tail[8]),
        deleted=deleted,
        realloc=realloc,
        file_name_attr=fn,
    )


def iter_file(path: str | Path) -> Iterator[BodyEntry]:
    """Every parseable line of a bodyfile. Bytes that are not UTF-8 stay as surrogate escapes."""
    with open(path, encoding="utf-8", errors="surrogateescape", newline="\n") as fh:
        for n, line in enumerate(fh, start=1):
            if not line.strip():
                continue
            try:
                yield parse_line(line, n)
            except BodyfileError:
                continue
