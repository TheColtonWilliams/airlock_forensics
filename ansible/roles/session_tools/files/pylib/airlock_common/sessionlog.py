"""Session log: one JSON object per line under the session folder.

See docs/dev/contract.md section 4. ``python3 -m airlock_common.sessionlog TOOL EVENT k=v ...``
is the bash entry point used by ``lib/airlock-log.sh``.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any

from airlock_common import jsonio, paths, timeutil

CURRENT = "current.log"


def current_path() -> Path:
    return paths.session_dir() / CURRENT


def new_session(tool: str, **fields: Any) -> Path:
    """Start a new session file and point ``current.log`` at it."""
    folder = paths.session_dir()
    folder.mkdir(parents=True, exist_ok=True)
    stamp = timeutil.compact()
    path = folder / f"{stamp}.log"
    n = 1
    while path.exists():
        n += 1
        path = folder / f"{stamp}-{n}.log"
    path.touch(mode=0o640)
    link = folder / CURRENT
    tmp = folder / f".{CURRENT}.tmp"
    tmp.unlink(missing_ok=True)
    tmp.symlink_to(path.name)
    tmp.replace(link)
    _write(path, tool, "session_start", fields)
    return path


def session_path(tool: str) -> Path:
    """The current session file, creating an implicit session if none exists."""
    link = current_path()
    if link.exists():
        return link.resolve()
    path = new_session(tool, implicit=True)
    _write(path, tool, "session_implicit", {})
    return path


def _write(path: Path, tool: str, event: str, fields: dict[str, Any]) -> dict[str, Any]:
    record: dict[str, Any] = dict(fields)
    record.update({"ts": timeutil.iso(), "event": event, "tool": tool, "pid": os.getpid()})
    jsonio.append_line(path, record)
    return record


def log_event(tool: str, event: str, **fields: Any) -> dict[str, Any]:
    """Append one event to the current session log and return the record."""
    return _write(session_path(tool), tool, event, fields)


def _parse_kv(items: list[str]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for item in items:
        key, sep, value = item.partition("=")
        if not sep or not key:
            raise SystemExit(f"sessionlog: expected key=value, got {item!r}")
        out[key] = value
    return out


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) < 2:
        usage = "usage: python3 -m airlock_common.sessionlog TOOL EVENT [key=value ...]"
        print(usage, file=sys.stderr)
        return 2
    tool, event, rest = args[0], args[1], args[2:]
    log_event(tool, event, **_parse_kv(rest))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
