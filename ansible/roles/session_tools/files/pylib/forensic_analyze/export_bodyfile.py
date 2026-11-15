"""``findings.bodyfile``: Sleuth Kit 3.x bodyfile from findings with file times (4D.10).

Each line: ``MD5|name|inode|mode_as_string|UID|GID|size|atime|mtime|ctime|crtime`` with times in
whole seconds since 1970-01-01 UTC (0 = unknown). Feed it to ``mactime -b findings.bodyfile``.

A finding contributes when it has ``datetime``, a ``path``/``filename`` or ``inode_ref``, and a
``timestamp_desc`` that names one of the four MACB times (see ``macb_slot``). Findings for the
same file (same evidence, inode_ref, path, and variant) are merged into one line; a second,
different value for a time already filled starts a further line. A trailing ``(...)`` in
``timestamp_desc`` names a variant, for example ``Creation Time ($FILE_NAME)``, which gets its
own line with the variant added to the name, as ``fls -m`` does. Rows with
``tz_basis = local_unknown_offset`` are left out: the bodyfile has no way to say the time is
not UTC. Times before 1970 are left out (written as 0).

CASE/UCO 1.4 JSON-LD export: planned for later (build plan 4D.10), not built yet.
"""

from __future__ import annotations

import datetime as _dt
import os
import re
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from forensic_analyze import findings

BODYFILE_NAME = "findings.bodyfile"
SLOTS = ("a", "m", "c", "b")  # bodyfile column order after size: atime|mtime|ctime|crtime
_VARIANT_RE = re.compile(r"\s*\(([^()]*)\)\s*$")
_TIME_RE = re.compile(r"^([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})")


def split_desc(desc: str) -> tuple[str, str]:
    """``("Creation Time", "$FILE_NAME")`` from ``"Creation Time ($FILE_NAME)"``."""
    m = _VARIANT_RE.search(desc)
    if not m:
        return desc.strip(), ""
    return desc[: m.start()].strip(), m.group(1).strip()


def macb_slot(desc: str) -> str | None:
    """Which MACB time a ``timestamp_desc`` names: ``m``, ``a``, ``c``, ``b``, or None.

    c (metadata change): contains "metadata", "entry modif", "record modif", "mft modif",
    or "change". b (birth): "creat" or "birth". a: "access". m: "modif", "written", "write".
    Anything else (for example "Deletion Time") is not a MACB time.
    """
    base = split_desc(desc)[0].lower()
    if any(k in base for k in ("metadata", "entry modif", "record modif", "mft modif", "change")):
        return "c"
    if "creat" in base or "birth" in base:
        return "b"
    if "access" in base:
        return "a"
    if any(k in base for k in ("modif", "written", "write")):
        return "m"
    return None


def epoch_seconds(stamp: str) -> int | None:
    """Whole seconds since the epoch for an ISO 8601 Z time; None if before 1970 or bad."""
    m = _TIME_RE.match(stamp)
    if not m:
        return None
    try:
        when = _dt.datetime(*(int(m.group(i)) for i in range(1, 7)), tzinfo=_dt.UTC)
    except ValueError:
        return None
    secs = int((when - _dt.datetime(1970, 1, 1, tzinfo=_dt.UTC)).total_seconds())
    return secs if secs >= 0 else None


_INODE_RE = re.compile(r"^(?:v[0-9]+:)?([0-9]+(?:-[0-9]+)*)$")


def bodyfile_inode(inode_ref: str) -> str:
    """The bodyfile inode column: ``v0:64-1`` becomes ``64-1``. mactime accepts only digits and
    dashes there, so any other form becomes ``0`` (the full ``inode_ref`` stays in findings)."""
    m = _INODE_RE.match(inode_ref)
    return m.group(1) if m else "0"


def _field(text: str) -> str:
    """A bodyfile field: no ``|`` and no line breaks (already display-escaped upstream)."""
    return text.replace("|", "\\u007c").replace("\n", "\\n").replace("\r", "\\r")


@dataclass
class _Record:
    name: str
    inode: str
    md5: str = ""
    size: int | None = None
    times: dict[str, int] = field(default_factory=dict)

    def line(self) -> str:
        cols = [
            self.md5 or "0",
            _field(self.name),
            bodyfile_inode(self.inode),
            "0",
            "0",
            "0",
            str(self.size if self.size is not None else 0),
        ]
        cols += [str(self.times.get(s, 0)) for s in SLOTS]
        return "|".join(cols)


def _name_for(row: dict[str, Any], variant: str) -> str:
    name = str(row.get("path") or row.get("filename") or "")
    if variant:
        name += f" ({variant})"
    if row.get("allocated") is False:
        name += " (deleted)"
    return name


def records(rows: Any) -> list[_Record]:
    """Group finding rows into bodyfile records, in order of first appearance."""
    groups: dict[tuple[str, ...], list[_Record]] = {}
    order: list[_Record] = []
    for row in rows:
        stamp, desc = row.get("datetime"), row.get("timestamp_desc")
        if not stamp or not desc or row.get("tz_basis") == "local_unknown_offset":
            continue
        if not (row.get("path") or row.get("filename") or row.get("inode_ref")):
            continue
        slot = macb_slot(desc)
        secs = epoch_seconds(stamp)
        if slot is None or secs is None:
            continue
        variant = split_desc(desc)[1]
        name = _name_for(row, variant)
        key = (
            str(row.get("evidence_id", "")),
            str(row.get("inode_ref", "")),
            str(row.get("path") or row.get("filename") or ""),
            variant,
            "deleted" if row.get("allocated") is False else "",
        )
        recs = groups.setdefault(key, [])
        target = next((r for r in recs if r.times.get(slot, secs) == secs), None)
        if target is None:
            target = _Record(name=name, inode=str(row.get("inode_ref", "")))
            recs.append(target)
            order.append(target)
        target.times[slot] = secs
        if not target.md5 and row.get("md5"):
            target.md5 = str(row["md5"])
        if target.size is None and isinstance(row.get("size_bytes"), int):
            target.size = int(row["size_bytes"])
    return order


def build(run_dir: str | os.PathLike[str]) -> Path:
    """Write ``<run>/findings.bodyfile`` from ``<run>/findings.jsonl`` and return its path."""
    run = Path(run_dir)
    source = run / findings.FINDINGS_NAME
    target = run / BODYFILE_NAME
    fd, tmp = tempfile.mkstemp(prefix=f".{BODYFILE_NAME}.", dir=run)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
            for rec in records(findings.iter_findings(source)):
                fh.write(rec.line())
                fh.write("\n")
            fh.flush()
            os.fsync(fh.fileno())
        Path(tmp).replace(target)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise
    return target


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) != 1:
        print("usage: python3 -m forensic_analyze.export_bodyfile RUN_DIR", file=sys.stderr)
        return 2
    try:
        print(build(args[0]))
    except (OSError, findings.SchemaError) as exc:
        print(
            f"export_bodyfile: could not build {BODYFILE_NAME}: {exc}. "
            "Check findings.jsonl and free space.",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
