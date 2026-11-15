"""Windows FILETIME helpers: 100-nanosecond ticks since 1601-01-01 UTC."""

from __future__ import annotations

import datetime as _dt
import re

EPOCH_1601 = _dt.datetime(1601, 1, 1, tzinfo=_dt.UTC)
TICKS_PER_SECOND = 10_000_000
# 1601-01-01 to 1970-01-01 in ticks.
UNIX_EPOCH_TICKS = 116_444_736_000_000_000
# Plausible range for real records: 1980-01-01 to 2100-01-01.
MIN_PLAUSIBLE = 119_600_064_000_000_000
MAX_PLAUSIBLE = 157_469_184_000_000_000

_ISO_RE = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?\s*(Z|[+-]00:?00)?$"
)


def to_iso(ticks: int | None) -> str | None:
    """ISO 8601 UTC with ``Z`` and 7 fraction digits (the full FILETIME precision).

    Returns None for 0 (unset) and for values outside what ``datetime`` can show.
    """
    if not ticks or ticks < 0:
        return None
    secs, frac = divmod(ticks, TICKS_PER_SECOND)
    try:
        base = EPOCH_1601 + _dt.timedelta(seconds=secs)
    except OverflowError:
        return None
    if base.year > 9999:
        return None
    return base.strftime("%Y-%m-%dT%H:%M:%S") + f".{frac:07d}Z"


def to_unix_seconds(ticks: int | None) -> int | None:
    """Whole seconds since 1970 (floor), or None for 0."""
    if not ticks:
        return None
    return (ticks - UNIX_EPOCH_TICKS) // TICKS_PER_SECOND


def plausible(ticks: int) -> bool:
    return MIN_PLAUSIBLE <= ticks <= MAX_PLAUSIBLE


def fraction_ticks(ticks: int) -> int:
    """The sub-second part in 100 ns units (0 when the time has no fraction)."""
    return ticks % TICKS_PER_SECOND


def iso_from_unix(seconds: int | float | None) -> str | None:
    """ISO 8601 UTC with ``Z`` from Unix seconds; None for 0 or negative (unknown)."""
    if seconds is None or seconds <= 0:
        return None
    whole = int(seconds)
    stamp = _dt.datetime.fromtimestamp(whole, _dt.UTC).strftime("%Y-%m-%dT%H:%M:%S")
    return stamp + "Z"


def normalise_iso(text: str | None) -> str | None:
    """Turn the time formats tools print into ISO 8601 UTC with ``Z``.

    Accepts ``2024-01-02 03:04:05.1234567``, ``2024-01-02T03:04:05+00:00``, and the ``Z`` form.
    Times without a zone are taken as UTC (EZ Tools and Dissect print UTC). Returns None for
    empty text or the FILETIME zero (1601-01-01T00:00:00).
    """
    if not text:
        return None
    m = _ISO_RE.match(text.strip())
    if not m:
        return None
    y, mo, d, h, mi, s, frac, _zone = m.groups()
    out = f"{y}-{mo}-{d}T{h}:{mi}:{s}"
    if frac:
        out += f".{frac}"
    if out.startswith("1601-01-01T00:00:00") and not (frac or "").strip("0"):
        return None
    try:
        _dt.datetime(int(y), int(mo), int(d), int(h), int(mi), int(s))
    except ValueError:
        return None
    return out + "Z"


def iso_seconds(text: str | None) -> str | None:
    """The ISO time cut to whole seconds (for comparing parsers with different precision)."""
    if not text:
        return None
    return text[:19]
