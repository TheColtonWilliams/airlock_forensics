"""CSV output of Eric Zimmerman's tools (MFTECmd, RBCmd, LECmd, JLECmd).

The tools write UTF-8 CSV (sometimes with a BOM) with a header row. Column names differ a
little between releases, so every lookup takes a list of aliases and ignores case. Times are
UTC, written ``YYYY-MM-DD HH:MM:SS.fffffff``.

Column names used (from the tools' documented CSV output):

* MFTECmd ``$MFT``: EntryNumber, SequenceNumber, InUse, ParentPath, FileName, FileSize,
  IsDirectory, IsAds, Created0x10, LastModified0x10, LastRecordChange0x10, LastAccess0x10,
  Created0x30, SecurityId.
* MFTECmd ``$SDS``: Id, OwnerSid (or Owner).
* RBCmd: SourceName, FileName, FileSize, DeletedOn.
* LECmd and JLECmd: SourceFile, LocalPath, TargetIDAbsolutePath, NetworkPath, RelativePath,
  TargetCreated, TargetModified, TargetAccessed, VolumeSerialNumber, FileSize.
"""

from __future__ import annotations

import csv
import sys
from collections.abc import Iterator
from pathlib import Path

from forensic_analyze.parsers import filetime

csv.field_size_limit(min(sys.maxsize, 2**31 - 1))


def read_rows(path: str | Path) -> Iterator[tuple[int, dict[str, str]]]:
    """``(line_number, row)`` for each data row; keys lower-cased and stripped."""
    with open(path, encoding="utf-8-sig", errors="surrogateescape", newline="") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            clean = {(k or "").strip().lower(): (v or "") for k, v in row.items()}
            yield reader.line_num, clean


def get(row: dict[str, str], *names: str) -> str:
    for name in names:
        value = row.get(name.lower())
        if value not in (None, ""):
            return value.strip()
    return ""


def get_int(row: dict[str, str], *names: str) -> int | None:
    text = get(row, *names)
    if not text:
        return None
    try:
        return int(float(text.replace(",", "")))
    except ValueError:
        return None


def get_bool(row: dict[str, str], *names: str) -> bool | None:
    text = get(row, *names).lower()
    if text in {"true", "1", "yes"}:
        return True
    if text in {"false", "0", "no"}:
        return False
    return None


def get_time(row: dict[str, str], *names: str) -> str | None:
    return filetime.normalise_iso(get(row, *names))


def windows_to_posix(path: str) -> str:
    """``.\\Users\\x`` or ``C:\\Users\\x`` to ``/Users/x`` (volume relative)."""
    text = path.replace("\\", "/")
    if len(text) >= 2 and text[1] == ":":
        text = text[2:]
    while text.startswith("./"):
        text = text[1:]
    if text in {".", ""}:
        return "/"
    return "/" + text.strip("/")


def csv_files(folder: str | Path) -> list[Path]:
    """Every CSV a tool wrote under ``folder``, sorted."""
    return sorted(p for p in Path(folder).rglob("*.csv") if p.is_file())
