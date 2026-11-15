"""Examiner and case fields, the authority acknowledgement, and the clock record.

Tasks 4C.25 (case fields with defaults from ASSETS ``profile.json``), 4C.26 (clock record), and
surviving risk 14 (the first screen states that the operator needs permission or legal authority,
and the answer is logged).

The clock record never changes the system time. The examiner reads a trusted clock (a phone, a
radio clock, a time signal) and enters it in UTC; the run stores the difference.
"""

from __future__ import annotations

import datetime as dt
import re
import time
from dataclasses import asdict, dataclass, field
from typing import Any

from airlock_common import hashing, jsonio, paths, timeutil

AUTHORITY_TEXT = (
    "Only examine a drive when you have the owner's permission or the legal authority to do so "
    "(for example a warrant, a court order, or a written consent). AIRLOCK records your answer "
    "and your name in the run record."
)
AUTHORITY_SHA256 = hashing.sha256_bytes(AUTHORITY_TEXT.encode("utf-8"))

_SAFE_ID = re.compile(r"[^A-Za-z0-9._-]+")


class CaseError(ValueError):
    """A case field or clock value is not usable."""


def safe_id(value: str, *, what: str = "case ID") -> str:
    """A case or exhibit ID made safe for a folder name: letters, digits, ``.``, ``_``, ``-``."""
    cleaned = _SAFE_ID.sub("_", value.strip()).strip("._")
    if not cleaned:
        raise CaseError(f"{what} is empty after removing unsafe characters; use letters and digits")
    return cleaned[:80]


def case_defaults() -> dict[str, str]:
    """``case_defaults`` from ASSETS ``profile.json`` (examiner, agency, case_id_prefix)."""
    profile = paths.assets_dir() / "profile.json"
    try:
        data = jsonio.load_json(profile)
    except (OSError, ValueError):
        return {}
    raw = data.get("case_defaults") if isinstance(data, dict) else None
    if not isinstance(raw, dict):
        return {}
    return {k: str(v) for k, v in raw.items() if isinstance(v, str | int | float)}


@dataclass
class CaseInfo:
    case_id: str
    exhibit_id: str
    examiner: str
    authority_ref: str = ""
    notes: str = ""
    agency: str = ""

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


def default_case_id(defaults: dict[str, str], now: dt.datetime | None = None) -> str:
    prefix = defaults.get("case_id_prefix", "") or "CASE-"
    return safe_id(f"{prefix}{(now or timeutil.utcnow()).strftime('%Y%m%d')}")


@dataclass
class AuthorityAck:
    acknowledged: bool
    ts: str
    via: str  # "flag" | "prompt"
    text_sha256: str = AUTHORITY_SHA256
    text: str = AUTHORITY_TEXT

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ClockRecord:
    """Wall-clock and monotonic times for the run, plus the examiner's reference reading."""

    system_utc_at_entry: str = ""
    reference_time: str = ""
    reference_source: str = ""
    clock_offset_seconds: float | None = None
    started_utc: str = ""
    finished_utc: str = ""
    monotonic_start: float = 0.0
    monotonic_end: float | None = None
    duration_s: float | None = None
    system_time_changed: bool = False
    note: str = "System time is never changed by AIRLOCK. The offset is recorded only."
    events: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def mark(self, event: str) -> None:
        """A wall-clock time and a monotonic time side by side."""
        self.events.append(
            {"event": event, "utc": timeutil.iso(), "monotonic": round(time.monotonic(), 6)}
        )


def parse_reference(value: str) -> dt.datetime:
    """Parse an examiner-entered UTC time. Needs a ``Z`` or an explicit offset."""
    text = value.strip()
    if not text:
        raise CaseError("reference time is empty")
    if not (text.endswith(("Z", "z")) or re.search(r"[+-]\d{2}:?\d{2}$", text)):
        raise CaseError(
            "reference time needs a time zone: write it in UTC with a Z, "
            "for example 2026-11-15T14:03:00Z"
        )
    try:
        return timeutil.parse_iso(text.upper() if text.endswith("z") else text)
    except ValueError as exc:
        raise CaseError(f"reference time {value!r} is not ISO 8601: {exc}") from exc


def clock_record(
    reference_time: str = "",
    reference_source: str = "",
    *,
    system_now: dt.datetime | None = None,
) -> ClockRecord:
    """Build the clock record. ``system_now`` is the system time when the value was entered."""
    now = system_now or timeutil.utcnow()
    rec = ClockRecord(
        system_utc_at_entry=timeutil.iso(now),
        started_utc=timeutil.iso(now),
        monotonic_start=round(time.monotonic(), 6),
    )
    if reference_time:
        ref = parse_reference(reference_time)
        rec.reference_time = timeutil.iso(ref)
        rec.reference_source = reference_source.strip() or "not stated"
        rec.clock_offset_seconds = round((now - ref).total_seconds(), 3)
    else:
        rec.reference_source = "not given"
    return rec


def finish_clock(rec: ClockRecord) -> None:
    rec.finished_utc = timeutil.iso()
    rec.monotonic_end = round(time.monotonic(), 6)
    rec.duration_s = round(rec.monotonic_end - rec.monotonic_start, 3)
