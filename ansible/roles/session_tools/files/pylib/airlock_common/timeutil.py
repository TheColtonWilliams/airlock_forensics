"""UTC time helpers. Every timestamp AIRLOCK writes is UTC ISO 8601 with a Z."""

from __future__ import annotations

import datetime as _dt


def utcnow() -> _dt.datetime:
    return _dt.datetime.now(_dt.UTC)


def iso(ts: _dt.datetime | None = None, *, micro: bool = True) -> str:
    ts = (ts or utcnow()).astimezone(_dt.UTC)
    if not micro:
        ts = ts.replace(microsecond=0)
    return ts.isoformat().replace("+00:00", "Z")


def compact(ts: _dt.datetime | None = None) -> str:
    """``YYYYMMDDTHHMMSSZ``: used in file names and run IDs."""
    return (ts or utcnow()).astimezone(_dt.UTC).strftime("%Y%m%dT%H%M%SZ")


def parse_iso(value: str) -> _dt.datetime:
    return _dt.datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(_dt.UTC)
