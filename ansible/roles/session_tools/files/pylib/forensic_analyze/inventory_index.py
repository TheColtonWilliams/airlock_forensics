"""The file index the ``inventory`` module writes (docs/dev/contract.md section 8a).

``<run>/modules/inventory/files.jsonl`` holds one sorted JSON line per file (directories are
left out) with these keys:

``volume_index``, ``inode`` (The Sleuth Kit metadata address, e.g. ``68-128-2``; pass it to
``extract.export_file``), ``path`` (display-safe, ``/`` separated from the volume root),
``size_bytes``, ``allocated`` (the metadata entry is in use), ``deleted`` (the name is
deleted), ``mtime``, ``atime``, ``ctime``, ``crtime`` (ISO 8601 UTC or null), plus
``inode_ref`` (``v<volume>:<entry>-<sequence>`` as in findings) and, only when the raw name
was not clean UTF-8 text, ``path_b64`` (base64 of the raw bytes).

The ``carve`` module writes ``<run>/modules/carve/carved.jsonl`` in the same format with
``volume_index`` -1, ``inode`` "", and ``carved_path`` (the carved copy, relative to the run
folder). ``iter_files(..., include_carved=True)`` adds those lines.
"""

from __future__ import annotations

import json
import os
import tempfile
from collections.abc import Iterable, Iterator
from pathlib import Path
from typing import Any

from airlock_common import jsonio

FILES_NAME = "files.jsonl"
KEYS = (
    "volume_index",
    "inode",
    "path",
    "size_bytes",
    "allocated",
    "deleted",
    "mtime",
    "atime",
    "ctime",
    "crtime",
)


def index_path(run_dir: str | os.PathLike[str]) -> Path:
    return Path(run_dir) / "modules" / "inventory" / FILES_NAME


def carved_path(run_dir: str | os.PathLike[str]) -> Path:
    return Path(run_dir) / "modules" / "carve" / "carved.jsonl"


def available(run_dir: str | os.PathLike[str]) -> bool:
    """True once the inventory module has written the index for this run."""
    return index_path(run_dir).is_file()


def sort_key(entry: dict[str, Any]) -> tuple[int, str, str]:
    return (int(entry.get("volume_index", 0)), str(entry.get("path", "")), str(entry.get("inode")))


def write_index(path: str | os.PathLike[str], entries: Iterable[dict[str, Any]]) -> int:
    """Write entries sorted by (volume, path, inode), atomically. Returns the line count."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    rows = sorted(entries, key=sort_key)
    fd, tmp = tempfile.mkstemp(prefix=f".{target.name}.", dir=target.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
            for row in rows:
                missing = [k for k in KEYS if k not in row]
                if missing:
                    raise ValueError(f"index line lacks {', '.join(missing)}")
                fh.write(jsonio.dumps_line(row))
                fh.write("\n")
            fh.flush()
            os.fsync(fh.fileno())
        Path(tmp).replace(target)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise
    return len(rows)


def _norm_ext(ext: str) -> str:
    ext = ext.strip().lower()
    return ext if ext.startswith(".") else "." + ext


def _read(path: Path) -> Iterator[dict[str, Any]]:
    if not path.is_file():
        return
    with open(path, encoding="utf-8") as fh:
        for raw in fh:
            text = raw.strip()
            if not text:
                continue
            value = json.loads(text)
            if isinstance(value, dict):
                yield value


def iter_files(
    run_dir: str | os.PathLike[str],
    *,
    extensions: Iterable[str] | None = None,
    include_deleted: bool = True,
    include_carved: bool = False,
    volume_index: int | None = None,
) -> Iterator[dict[str, Any]]:
    """Index lines in file order, optionally only those whose name ends in ``extensions``
    (case-insensitive, with or without the dot). Yields nothing when the index does not exist
    yet (check ``available(run_dir)``). Alternate data streams (``name:stream``) are matched on
    the stream name, so ``file.jpg:Zone.Identifier`` is not a ``.jpg``.
    """
    wanted = {_norm_ext(e) for e in extensions} if extensions is not None else None
    sources = [index_path(run_dir)]
    if include_carved:
        sources.append(carved_path(run_dir))
    for source in sources:
        for entry in _read(source):
            if volume_index is not None and entry.get("volume_index") != volume_index:
                continue
            if not include_deleted and (entry.get("deleted") or not entry.get("allocated", True)):
                continue
            if wanted is not None:
                name = str(entry.get("path", "")).rsplit("/", 1)[-1].lower()
                if not any(name.endswith(ext) for ext in wanted):
                    continue
            yield entry
