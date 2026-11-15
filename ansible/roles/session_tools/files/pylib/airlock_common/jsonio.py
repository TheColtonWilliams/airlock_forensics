"""JSON helpers: sorted keys, UTF-8, one object per line for logs."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any


def dumps(obj: Any, *, indent: int | None = 2) -> str:
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, indent=indent, default=str)


def dumps_line(obj: Any) -> str:
    """One compact JSON object, no trailing newline (JSON-lines)."""
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"), default=str)


def dump_json(path: str | os.PathLike[str], obj: Any, *, indent: int | None = 2) -> None:
    """Write JSON atomically (temp file + rename) with sorted keys and a final newline."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=f".{target.name}.", dir=target.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(dumps(obj, indent=indent))
            fh.write("\n")
            fh.flush()
            os.fsync(fh.fileno())
        Path(tmp).replace(target)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def load_json(path: str | os.PathLike[str]) -> Any:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def append_line(path: str | os.PathLike[str], obj: Any) -> None:
    """Append one JSON object as a line, flushed and fsynced."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    with open(target, "a", encoding="utf-8", newline="\n") as fh:
        fh.write(dumps_line(obj))
        fh.write("\n")
        fh.flush()
        os.fsync(fh.fileno())
