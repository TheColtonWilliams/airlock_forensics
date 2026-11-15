"""NTFS interpretation rows (task 4C.27). Every row here is ``derivation: inferred``.

These are patterns code notices in NTFS metadata, not observations of an action:

* ``ntfs_si_before_fn``: the ``$STANDARD_INFORMATION`` creation time is earlier than the
  ``$FILE_NAME`` creation time.
* ``ntfs_si_zero_fraction``: all four ``$STANDARD_INFORMATION`` times have a zero sub-second
  part.
* ``ntfs_si_change_without_usn``: the ``$STANDARD_INFORMATION`` change time lies inside the
  period the USN journal covers, but the journal holds no record for that file near it.

Each pattern has innocent causes, and the messages say so. Rows name the owner only as an
account SID, never a person.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from typing import Any

from forensic_analyze.parsers import filetime
from forensic_analyze.parsers.mft import FIRST_USER_ENTRY, MftIndex, MftRecord
from forensic_analyze.parsers.usn import UsnRecord

TOOL = "forensic-analyze"
VERSION = "ntfs_interp 1"
USN_TOLERANCE_TICKS = 2 * filetime.TICKS_PER_SECOND

MSG_SI_BEFORE_FN = (
    "Inferred, not observed: the $STANDARD_INFORMATION creation time is earlier than the "
    "$FILE_NAME creation time. Programs can change the first time but rarely the second, so "
    "this can point to a changed timestamp. Copying or extracting a file with its original "
    "time kept can also cause it. Check before relying on it."
)
MSG_ZERO_FRACTION = (
    "Inferred, not observed: all four $STANDARD_INFORMATION times have a zero sub-second part. "
    "Windows normally writes a fraction, so the times may have been set by a program. Files "
    "copied from formats that keep whole seconds (zip archives, FAT media) look the same."
)
MSG_NO_USN = (
    "Inferred, not observed: the $STANDARD_INFORMATION change time falls inside the period the "
    "USN journal covers, but the journal has no record for this file within 2 seconds of it. "
    "The time may have been set directly, or the journal records for this file may be gone."
)

OwnerOf = Callable[[MftRecord], str | None]


def _eligible(index: MftIndex, rec: MftRecord) -> bool:
    if rec.entry < FIRST_USER_ENTRY or not rec.has_si or not rec.names:
        return False
    path = index.path_of(rec.entry)
    return not path.startswith("/$Extend")


def _row(
    *,
    artifact: str,
    message: str,
    index: MftIndex,
    rec: MftRecord,
    volume_index: int,
    ticks: int,
    desc: str,
    source_record: str,
    owner: str | None,
    parser: str,
) -> dict[str, Any]:
    path = index.path_of(rec.entry)
    msg = message
    if owner:
        msg += f" The file's owner is account SID {owner}."
    row: dict[str, Any] = {
        "category": "inventory",
        "artifact_type": artifact,
        "message": msg,
        "derivation": "inferred",
        "source_tool": TOOL,
        "tool_version": VERSION,
        "parser": parser,
        "datetime": filetime.to_iso(ticks),
        "timestamp_desc": desc,
        "tz_basis": "utc",
        "path": path,
        "filename": path.rsplit("/", 1)[-1],
        "inode_ref": f"v{volume_index}:{rec.entry}-{rec.seq}",
        "allocated": rec.in_use,
        "source_record": f"{source_record}#entry={rec.entry}",
    }
    if owner:
        row["owner_sid"] = owner
    return row


def interpret_mft(
    index: MftIndex,
    *,
    volume_index: int,
    source_record: str,
    owner_of: OwnerOf | None = None,
) -> list[dict[str, Any]]:
    """``ntfs_si_before_fn`` and ``ntfs_si_zero_fraction`` rows, sorted by entry."""
    rows: list[dict[str, Any]] = []
    for entry in sorted(index.records):
        rec = index.records[entry]
        if not _eligible(index, rec):
            continue
        owner = owner_of(rec) if owner_of else None
        fn = rec.best_name()
        if fn and rec.si_created and fn.created and rec.si_created < fn.created:
            rows.append(
                _row(
                    artifact="ntfs_si_before_fn",
                    message=MSG_SI_BEFORE_FN,
                    index=index,
                    rec=rec,
                    volume_index=volume_index,
                    ticks=rec.si_created,
                    desc="Creation Time ($STANDARD_INFORMATION)",
                    source_record=source_record,
                    owner=owner,
                    parser="airlock.mft",
                )
            )
        times = (rec.si_created, rec.si_modified, rec.si_changed, rec.si_accessed)
        if all(times) and not any(filetime.fraction_ticks(t) for t in times):
            rows.append(
                _row(
                    artifact="ntfs_si_zero_fraction",
                    message=MSG_ZERO_FRACTION,
                    index=index,
                    rec=rec,
                    volume_index=volume_index,
                    ticks=rec.si_modified,
                    desc="Content Modification Time ($STANDARD_INFORMATION)",
                    source_record=source_record,
                    owner=owner,
                    parser="airlock.mft",
                )
            )
    return rows


def usn_window(records: Iterable[UsnRecord]) -> tuple[int, int] | None:
    stamps = [r.timestamp for r in records if filetime.plausible(r.timestamp)]
    if not stamps:
        return None
    return min(stamps), max(stamps)


def interpret_usn(
    index: MftIndex,
    records: list[UsnRecord],
    *,
    volume_index: int,
    source_record: str,
    owner_of: OwnerOf | None = None,
) -> list[dict[str, Any]]:
    """``ntfs_si_change_without_usn`` rows, sorted by entry."""
    window = usn_window(records)
    if window is None:
        return []
    start, end = window
    by_entry: dict[int, list[tuple[int, int]]] = {}
    for r in records:
        by_entry.setdefault(r.entry, []).append((r.seq, r.timestamp))
    rows: list[dict[str, Any]] = []
    for entry in sorted(index.records):
        rec = index.records[entry]
        if not _eligible(index, rec) or not rec.si_changed:
            continue
        if not start <= rec.si_changed <= end:
            continue
        seqs = {rec.seq} if rec.in_use else {rec.seq, (rec.seq - 1) & 0xFFFF}
        near = any(
            seq in seqs and abs(ts - rec.si_changed) <= USN_TOLERANCE_TICKS
            for seq, ts in by_entry.get(entry, [])
        )
        if near:
            continue
        rows.append(
            _row(
                artifact="ntfs_si_change_without_usn",
                message=MSG_NO_USN,
                index=index,
                rec=rec,
                volume_index=volume_index,
                ticks=rec.si_changed,
                desc="Metadata Modification Time ($STANDARD_INFORMATION)",
                source_record=source_record,
                owner=owner_of(rec) if owner_of else None,
                parser="airlock.mft+usn",
            )
        )
    return rows
