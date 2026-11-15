"""Module ``deletion_history`` (task 4C.7, with 4C.27 and 4C.28 parts).

For each NTFS volume:

* USN change journal: ``$Extend/$UsnJrnl:$J`` is copied out (zero pages dropped) and parsed by
  the built-in parser (``parsers/usn.py``, USN_RECORD_V2 and V3). Rows for every
  ``FILE_DELETE`` record and every rename (old and new name paired), with full paths built
  from the ``$MFT``. Dissect's ``usnjrnl`` plugin is the second parser; delete records are
  joined on the USN and compared (``xval``).
* ``$LogFile``: copied out and kept, but not parsed. There is no reliable standard-library
  parser for its delete records and Dissect has none, so a row says so plainly.
* Full preset only: USN records carved from unallocated space (``blkls`` streamed through
  the built-in carver; nothing is written to the output drive but the findings).
* Inferred rows (``ntfs_interp``): ``$STANDARD_INFORMATION`` change times inside the journal's
  period with no journal record near them.

A volume without a USN journal gets an explicit row saying so.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable
from typing import Any

from forensic_analyze import extract, ntfs_interp, xval
from forensic_analyze.api import Module, ModuleContext, ModuleResult, Volume, sorted_rows
from forensic_analyze.parsers import dissect_json, usn
from forensic_analyze.parsers.mft import MftIndex

BUILTIN, DISSECT, CARVED = "airlock", "dissect", "airlock.carve"
VERSION = "usn 1"
COMPARED = ("entry", "time", "reasons", "name")


def _same_micro(a: Any, b: Any) -> bool:
    """Times agree to the microsecond (Dissect prints 6 fraction digits, FILETIME has 7)."""
    return str(a)[:26].ljust(26, "0") == str(b)[:26].ljust(26, "0")


EQUAL = {"time": _same_micro}


def _path(index: MftIndex | None, rec: usn.UsnRecord) -> str:
    if index is None:
        return f"/$OrphanFiles/{rec.name}"
    return index.path_for_parent(rec.parent_entry, rec.parent_seq, rec.name)


def _base(**kw: Any) -> dict[str, Any]:
    return {"category": "deletion", "derivation": "observed", **kw}


def delete_row(
    vol: Volume,
    rec: usn.UsnRecord,
    index: MftIndex | None,
    ref: str,
    status: str | None,
    *,
    parser: str = BUILTIN,
    version: str = VERSION,
    tool: str = "forensic-analyze",
    carved: bool = False,
) -> dict[str, Any]:
    path = _path(index, rec)
    what = "USN record carved from unallocated space" if carved else "USN journal"
    return _base(
        artifact_type="usn_delete_carved" if carved else "usn_delete",
        message=f"{what}: a file was deleted (reasons {usn.reason_text(rec.reason)}).",
        source_tool=tool,
        tool_version=version,
        parser="airlock.usn" if parser == BUILTIN else parser,
        datetime=rec.iso_time,
        timestamp_desc="Deletion Time (USN)",
        tz_basis="utc",
        path=path,
        filename=rec.name,
        inode_ref=f"v{vol.index}:{rec.entry}-{rec.seq}",
        allocated=False,
        xval_status=status,
        source_record=ref,
        text=f"usn={rec.usn}; parent=v{vol.index}:{rec.parent_entry}-{rec.parent_seq}",
    )


def rename_rows(
    vol: Volume, records: Iterable[usn.UsnRecord], index: MftIndex | None, rel: str
) -> list[dict[str, Any]]:
    rows = []
    for old, new in usn.pair_renames(r for r in records if r.reason & (0x1000 | 0x2000)):
        newer = new or old
        rows.append(
            _base(
                artifact_type="usn_rename",
                message=(
                    "USN journal: a file was renamed or moved. The new path is in path; the "
                    "old and new paths are in text."
                    if new
                    else "USN journal: a file was renamed; the record with the new name is gone."
                ),
                source_tool="forensic-analyze",
                tool_version=VERSION,
                parser="airlock.usn",
                datetime=newer.iso_time,
                timestamp_desc="Rename Time (USN)",
                tz_basis="utc",
                path=_path(index, newer),
                filename=newer.name,
                inode_ref=f"v{vol.index}:{old.entry}-{old.seq}",
                source_record=f"{rel}#usn={old.usn}",
                text=f"old path: {_path(index, old)}"
                + (f"; new path: {_path(index, new)}" if new else ""),
            )
        )
    return rows


def dissect_deletes(
    ctx: ModuleContext, vols: list[Volume], ours: dict[int, list[usn.UsnRecord]]
) -> dict[int, list[tuple[usn.UsnRecord, str, str | None]]] | None:
    """Delete records from Dissect's usnjrnl plugin, per volume (matched on shared USNs)."""
    dest = ctx.workdir / "dissect-usnjrnl.jsonl"
    cp = extract.dissect_query(ctx, ["-f", "usnjrnl"], dest)
    if cp is None:
        return None
    rel = extract.relative(ctx, dest)
    groups: dict[str, list[tuple[usn.UsnRecord, str, str | None]]] = {}
    if dest.exists():
        for line_no, rtype, rec in dissect_json.iter_records(dest):
            if "usnjrnl" not in rtype:
                continue
            reasons = {r.strip() for r in str(rec.get("reason") or "").split("|") if r.strip()}
            if "FILE_DELETE" not in reasons:
                continue
            seg = str(rec.get("segment_id") or "")
            entry_s, _, seq_s = seg.partition("#")
            try:
                entry, seq, number = int(entry_s), int(seq_s or 0), int(rec.get("usn"))
            except (TypeError, ValueError):
                continue
            group, path = dissect_json.split_path(rec.get("path"))
            bits = sum(b for b, n in usn.REASONS.items() if n in reasons)
            when = dissect_json.time(rec.get("ts"))
            parsed = usn.UsnRecord(
                offset=-1,
                major=int(rec.get("major") or 0),
                minor=int(rec.get("minor") or 0),
                entry=entry,
                seq=seq,
                parent_entry=0,
                parent_seq=0,
                usn=number,
                timestamp=0,
                reason=bits,
                source_info=0,
                security_id=int(rec.get("security_id") or 0),
                attributes=0,
                name=path.rsplit("/", 1)[-1],
            )
            groups.setdefault(group, []).append((parsed, f"{rel}#L{line_no}", when))
    out: dict[int, list[tuple[usn.UsnRecord, str, str | None]]] = {}
    for _group, recs in sorted(groups.items()):
        numbers = {r.usn for r, _, _ in recs}
        scores = sorted(
            ((len(numbers & {r.usn for r in ours.get(v.index, [])}), v.index) for v in vols),
            reverse=True,
        )
        if len(vols) == 1:
            out.setdefault(vols[0].index, []).extend(recs)
        elif scores and scores[0][0] > 0:
            out.setdefault(scores[0][1], []).extend(recs)
    return out


def carve_unallocated(ctx: ModuleContext, vol: Volume) -> list[usn.UsnRecord]:
    carver = usn.Carver()
    found: list[usn.UsnRecord] = []

    def sink(chunk: bytes) -> None:
        found.extend(carver.feed(chunk))

    cp = extract.stream_tool(ctx, extract.tsk_argv("blkls", ctx, vol), sink)
    found.extend(carver.close())
    if cp.returncode != 0:
        raise extract.ExtractError(f"blkls exited {cp.returncode}: {extract._last_line(cp.stderr)}")
    return found


class DeletionHistory(Module):
    name = "deletion_history"
    title = "Deletion history"
    fs_types = frozenset({"ntfs"})
    order = 30
    description = "USN journal delete and rename records; $LogFile kept; carving in Full."

    def run(self, ctx: ModuleContext) -> ModuleResult:  # noqa: PLR0912, PLR0915
        vols = ctx.target.volumes_of("ntfs")
        full = bool(ctx.options.get("full")) or ctx.options.get("preset") == "full"
        rows: list[dict[str, Any]] = []
        counts: Counter[str] = Counter()
        journals: dict[int, list[usn.UsnRecord]] = {}
        indexes: dict[int, MftIndex | None] = {}
        rels: dict[int, str] = {}
        for vol in vols:
            try:
                indexes[vol.index] = extract.load_mft_index(ctx, vol)
            except extract.ExtractError:
                indexes[vol.index] = None
            try:
                jpath = extract.extract_system_file(ctx, vol, "$UsnJrnl:$J")
            except extract.ExtractError as exc:
                rows.append(
                    _base(
                        artifact_type="usn_journal_absent",
                        message=(
                            f"Volume {vol.index}: no USN journal was found, so no journal delete "
                            "records can be reported for it. Windows creates the journal on "
                            "system volumes; other tools and removable media often have none."
                        ),
                        source_tool="sleuthkit",
                        tool_version=ctx.tool_version("icat"),
                        parser="tsk.icat",
                        inode_ref=f"v{vol.index}:usnjrnl",
                        text=str(exc),
                    )
                )
                continue
            rels[vol.index] = extract.relative(ctx, jpath)
            records = list(usn.iter_journal(jpath))
            journals[vol.index] = records
            counts["usn_records"] += len(records)
            rows.append(
                _base(
                    artifact_type="usn_journal",
                    message=(
                        f"Volume {vol.index}: USN journal read; {len(records)} records, "
                        f"{sum(1 for r in records if r.is_delete)} with FILE_DELETE."
                    ),
                    source_tool="forensic-analyze",
                    tool_version=VERSION,
                    parser="airlock.usn",
                    inode_ref=f"v{vol.index}:usnjrnl",
                    source_record=f"{rels[vol.index]}#all",
                )
            )
        dis = dissect_deletes(ctx, vols, journals)
        for vol in vols:
            records = journals.get(vol.index)
            index = indexes.get(vol.index)
            if records is not None:
                rel = rels[vol.index]
                obs = [
                    xval.Observation(
                        BUILTIN,
                        (vol.index, r.usn),
                        {
                            "entry": (r.entry, r.seq),
                            "time": r.iso_time,
                            "reasons": frozenset(r.reasons),
                            "name": r.name,
                        },
                        f"{rel}#usn={r.usn}",
                    )
                    for r in records
                    if r.is_delete
                ]
                for r, ref, when in (dis or {}).get(vol.index, []):
                    obs.append(
                        xval.Observation(
                            DISSECT,
                            (vol.index, r.usn),
                            {
                                "entry": (r.entry, r.seq),
                                "time": when,
                                "reasons": frozenset(r.reasons),
                                "name": r.name,
                            },
                            ref,
                        )
                    )
                results = xval.join(obs, fields=COMPARED, equal=EQUAL)
                for r in records:
                    if r.is_delete:
                        status = xval.status_of(results, (vol.index, r.usn))
                        rows.append(delete_row(vol, r, index, f"{rel}#usn={r.usn}", status))
                        counts["usn_deletes"] += 1
                for r, ref, when in (dis or {}).get(vol.index, []):
                    row = delete_row(
                        vol,
                        r,
                        index,
                        ref,
                        xval.status_of(results, (vol.index, r.usn)),
                        parser="dissect.ntfs.usnjrnl",
                        tool="dissect",
                        version=ctx.tool_version("target-query"),
                    )
                    row["datetime"] = when
                    rows.append(row)
                    counts["dissect_deletes"] += 1
                rows.extend(rename_rows(vol, records, index, rel))
                ran = [BUILTIN] + ([DISSECT] if (dis or {}).get(vol.index) else [])
                missing = {}
                if dis is None:
                    missing[DISSECT] = "target-query is not installed"
                elif DISSECT not in ran:
                    missing[DISSECT] = "Dissect returned no delete records for this volume"
                rows.append(
                    {
                        **xval.summary_row(
                            "USN delete records",
                            results,
                            volume_index=vol.index,
                            parsers_run=ran,
                            parsers_missing=missing,
                        ),
                        "inode_ref": f"v{vol.index}:usnjrnl",
                    }
                )
                rows.extend(
                    xval.disagreement_rows(
                        "USN delete",
                        results,
                        describe=lambda res, vol=vol: {
                            "inode_ref": f"v{vol.index}:usn{res.key[1]}"
                        },
                    )
                )
                if index is not None:
                    rows.extend(
                        ntfs_interp.interpret_usn(
                            index,
                            records,
                            volume_index=vol.index,
                            source_record=extract.relative(
                                ctx, ctx.run_dir / "extract" / f"v{vol.index}" / "MFT"
                            ),
                            owner_of=extract.owner_resolver(ctx, vol),
                        )
                    )
            rows.append(self._logfile_row(ctx, vol))
            if full:
                rows.extend(self._carved(ctx, vol, index, journals.get(vol.index) or [], counts))
        ordered = sorted_rows(
            [{k: v for k, v in r.items() if v is not None} for r in rows],
            "inode_ref",
            "datetime",
            "parser",
            "artifact_type",
        )
        for r in ordered:
            ctx.emit(r)
        return ModuleResult("ok", counts=dict(sorted(counts.items())))

    @staticmethod
    def _logfile_row(ctx: ModuleContext, vol: Volume) -> dict[str, Any]:
        try:
            path = extract.extract_system_file(ctx, vol, "$LogFile")
        except extract.ExtractError as exc:
            return _base(
                artifact_type="logfile_not_parsed",
                message=f"Volume {vol.index}: the $LogFile could not be copied out.",
                source_tool="sleuthkit",
                tool_version=ctx.tool_version("icat"),
                parser="tsk.icat",
                inode_ref=f"v{vol.index}:2",
                text=str(exc),
            )
        rel = extract.relative(ctx, path)
        return _base(
            artifact_type="logfile_not_parsed",
            message=(
                f"Volume {vol.index}: the $LogFile was copied out but not parsed. This version "
                "has no reliable parser for its delete records (none in the standard library, "
                "none in Dissect), so delete records in it are not reported. Examine the copy "
                "with another tool if they matter."
            ),
            source_tool="sleuthkit",
            tool_version=ctx.tool_version("icat"),
            parser="tsk.icat",
            inode_ref=f"v{vol.index}:2",
            source_record=f"{rel}#all",
        )

    @staticmethod
    def _carved(
        ctx: ModuleContext,
        vol: Volume,
        index: MftIndex | None,
        journal: list[usn.UsnRecord],
        counts: Counter[str],
    ) -> list[dict[str, Any]]:
        try:
            found = carve_unallocated(ctx, vol)
        except Exception as exc:
            return [
                _base(
                    artifact_type="usn_carve_failed",
                    message=f"Volume {vol.index}: carving USN records from unallocated failed.",
                    source_tool="forensic-analyze",
                    tool_version=VERSION,
                    parser="airlock.usn.carve",
                    text=str(exc),
                )
            ]
        known = {(r.usn, r.entry) for r in journal}
        rows = []
        deletes = [r for r in found if r.is_delete and (r.usn, r.entry) not in known]
        counts["usn_carved"] += len(found)
        counts["usn_carved_deletes"] += len(deletes)
        for r in deletes:
            rows.append(
                delete_row(
                    vol,
                    r,
                    index,
                    f"modules/deletion_history#blkls-v{vol.index}@{r.offset}",
                    "single_source",
                    parser="airlock.usn.carve",
                    carved=True,
                )
            )
        rows.append(
            _base(
                artifact_type="usn_carve",
                message=(
                    f"Volume {vol.index}: {len(found)} USN records carved from unallocated space, "
                    f"{len(deletes)} of them delete records not in the current journal."
                ),
                source_tool="forensic-analyze",
                tool_version=VERSION,
                parser="airlock.usn.carve",
                inode_ref=f"v{vol.index}:unallocated",
            )
        )
        return rows


MODULE = DeletionHistory()
