"""Record streams written by Dissect's ``target-query -j``.

Each line is a JSON object. Lines with ``"_type": "recorddescriptor"`` describe a record type
and are skipped; data lines carry ``"_recorddescriptor": [name, hash]``. Paths are Windows
style; on a disk with partitions they start with ``fs<N>\\`` (Dissect's filesystem number),
and on a bare volume they start with ``\\\\``.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from forensic_analyze.parsers import filetime

_GROUP_RE = re.compile(r"^(?P<group>\$fs\$/fs\d+|fs\d+|[a-zA-Z]:|sysvol)(?:/|$)")


def iter_records(path: str | Path) -> Iterator[tuple[int, str, dict[str, Any]]]:
    """``(line_number, record_type, record)`` for every data record; bad lines are skipped."""
    with open(path, encoding="utf-8", errors="surrogateescape") as fh:
        for n, raw in enumerate(fh, start=1):
            text = raw.strip()
            if not text.startswith("{"):
                continue
            try:
                rec = json.loads(text)
            except ValueError:
                continue
            if not isinstance(rec, dict) or rec.get("_type") == "recorddescriptor":
                continue
            desc = rec.get("_recorddescriptor")
            rtype = desc[0] if isinstance(desc, list) and desc else str(rec.get("_type", ""))
            yield n, rtype, rec


def split_path(raw: str | None) -> tuple[str, str]:
    """``(group, path)``: ``group`` is ``fs0``, ``c:`` and so on ("" on a bare volume);
    ``path`` is ``/``-separated from the volume root."""
    text = (raw or "").replace("\\", "/").strip("/")
    group = ""
    m = _GROUP_RE.match(text)
    if m:
        group = m.group("group").lower().replace("$fs$/", "")
        text = text[m.end() :].strip("/")
    if text in {"", "."}:
        return group, "/"
    return group, "/" + text


def time(value: Any) -> str | None:
    return filetime.normalise_iso(str(value)) if value else None
