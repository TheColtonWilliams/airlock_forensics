"""Module ``recycle_bin`` (task 4C.6).

Finds every ``$Recycle.Bin/<SID>/$I*`` record (live and deleted) through the inventory index,
copies each one out with ``icat``, and parses it with the built-in ``$I`` parser
(``parsers/recycle.py``, versions 1 and 2). Each record gives the original path, the deletion
time (UTC, from a FILETIME), the original size, and the owner account SID (the folder name).
It is paired with its ``$R`` content file (present, deleted, or missing).

Second and third parsers for the cross-check (``xval``): RBCmd over the copied ``$I`` files
when it is installed, and Dissect's ``recyclebin`` plugin when Dissect recognises a Windows
system on the target. Records are joined on the ``$I`` file; disagreements are listed.
"""

from __future__ import annotations

import re
import shutil
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from forensic_analyze import extract, xval
from forensic_analyze.api import Module, ModuleContext, ModuleResult, Volume, sorted_rows
from forensic_analyze.inventory_index import available, iter_files
from forensic_analyze.parsers import dissect_json, ezcsv, recycle

BUILTIN, RBCMD, DISSECT = "airlock", "rbcmd", "dissect"
PARSER_ORDER = (BUILTIN, RBCMD, DISSECT)
SOURCE_TOOL = {BUILTIN: "forensic-analyze", RBCMD: "RBCmd", DISSECT: "dissect"}
PARSER_NAME = {BUILTIN: "airlock.recycle", RBCMD: "rbcmd", DISSECT: "dissect.recyclebin"}
COMPARED = ("original_path", "deleted", "size")
EQUAL = {"original_path": xval.same_text_ci, "deleted": xval.same_second}
_INFO2_RE = re.compile(r"^/recycler/[^/]+/info2$", re.IGNORECASE)


@dataclass
class IFile:
    volume_index: int
    sid: str
    name: str  # $I file name as on disk
    inode: str  # TSK address
    inode_ref: str
    allocated: bool
    deleted: bool
    export: Path | None = None
    parsed: recycle.IRecord | None = None
    error: str = ""
    r_status: str = "missing"

    @property
    def key(self) -> tuple[int, str, str]:
        return (self.volume_index, self.sid.lower(), self.name.lower())


@dataclass
class Obs:
    parser: str
    key: tuple[int, str, str]
    original_path: str | None
    deleted: str | None
    size: int | None
    ref: str
    extra: dict[str, Any] = field(default_factory=dict)

    def values(self) -> dict[str, Any]:
        return {"original_path": self.original_path, "deleted": self.deleted, "size": self.size}


def _entries(ctx: ModuleContext) -> list[dict[str, Any]]:
    """Index lines from the inventory, or a fresh fls listing when the index is missing."""
    if available(ctx.run_dir):
        return list(iter_files(ctx.run_dir))
    from forensic_analyze.modules.inventory import index_entry, tsk_listing  # noqa: PLC0415

    out: list[dict[str, Any]] = []
    for vol in ctx.target.volumes_of("ntfs"):
        for obs in tsk_listing(ctx, vol, ctx.workdir / f"fls-v{vol.index}.body"):
            line = index_entry(obs, None)
            if line is not None:
                out.append(line)
    return out


def find_ifiles(entries: list[dict[str, Any]]) -> tuple[list[IFile], dict[tuple, str], list[dict]]:
    """``$I`` files, the ``$R`` status by key, and INFO2 lines (old XP recycler)."""
    ifiles: list[IFile] = []
    rfiles: dict[tuple[int, str, str], str] = {}
    info2: list[dict[str, Any]] = []
    for e in entries:
        path = str(e.get("path", ""))
        if ":" in path.rsplit("/", 1)[-1]:
            continue
        vol = int(e.get("volume_index", 0))
        if _INFO2_RE.match(path):
            info2.append(e)
            continue
        m = re.match(r"^/\$recycle\.bin/([^/]+)/(\$[ir][^/]*)$", path, re.IGNORECASE)
        if not m:
            continue
        sid, name = m.group(1), m.group(2)
        state = "present" if e.get("allocated") and not e.get("deleted") else "deleted"
        if name[:2].upper() == "$R":
            key = (vol, sid.lower(), "$i" + name[2:].lower())
            if rfiles.get(key) != "present":
                rfiles[key] = state
            continue
        ifiles.append(
            IFile(
                volume_index=vol,
                sid=sid,
                name=name,
                inode=str(e.get("inode", "")),
                inode_ref=str(e.get("inode_ref") or f"v{vol}:{e.get('inode')}"),
                allocated=bool(e.get("allocated")),
                deleted=bool(e.get("deleted")),
            )
        )
    ifiles.sort(key=lambda f: (f.key, f.deleted, f.inode))
    for f in ifiles:
        f.r_status = rfiles.get(f.key, "missing")
    return ifiles, rfiles, info2


def _volume(ctx: ModuleContext, index: int) -> Volume | None:
    for v in ctx.target.volumes:
        if v.index == index:
            return v
    return None


def export_and_parse(ctx: ModuleContext, f: IFile, export_root: Path) -> None:
    vol = _volume(ctx, f.volume_index)
    if vol is None:
        f.error = "volume not found"
        return
    folder = export_root / f"v{f.volume_index}" / extract.safe_component(f.sid) / f.inode
    name = f.name if re.fullmatch(r"\$I[A-Za-z0-9._-]{0,100}", f.name, re.IGNORECASE) else "$I"
    try:
        f.export = extract.export_file(ctx, vol, f.inode, folder, name=name)
    except (extract.ExtractError, ValueError) as exc:
        f.error = str(exc)
        return
    try:
        f.parsed = recycle.parse_file(f.export)
    except (recycle.RecycleError, OSError) as exc:
        f.error = str(exc)


def rbcmd_obs(ctx: ModuleContext, ifiles: list[IFile], export_root: Path) -> list[Obs]:
    out_dir = ctx.workdir / "rbcmd"
    extract.tool_dir(ctx, out_dir)
    cp = ctx.tool(["RBCmd", "-d", str(export_root), "--csv", str(out_dir), "--csvf", "rbcmd.csv"])
    if cp.returncode != 0:
        raise extract.ExtractError(f"RBCmd exited {cp.returncode}")
    by_path = {str(f.export.resolve()): f for f in ifiles if f.export}
    obs: list[Obs] = []
    for csv_path in ezcsv.csv_files(out_dir):
        rel = extract.relative(ctx, csv_path)
        for line_no, row in ezcsv.read_rows(csv_path):
            src = ezcsv.get(row, "SourceName", "SourceFile")
            match = by_path.get(str(Path(src).resolve())) if src else None
            if match is None:
                continue
            obs.append(
                Obs(
                    parser=RBCMD,
                    key=match.key,
                    original_path=ezcsv.get(row, "FileName") or None,
                    deleted=ezcsv.get_time(row, "DeletedOn"),
                    size=ezcsv.get_int(row, "FileSize"),
                    ref=f"{rel}#L{line_no}",
                )
            )
    return obs


def dissect_obs(ctx: ModuleContext, ifiles: list[IFile]) -> list[Obs] | None:
    dest = ctx.workdir / "dissect-recyclebin.jsonl"
    cp = extract.dissect_query(ctx, ["-f", "recyclebin"], dest)
    if cp is None:
        return None
    by_name: dict[tuple[str, str], list[IFile]] = {}
    for f in ifiles:
        by_name.setdefault((f.sid.lower(), f.name.lower()), []).append(f)
    rel = extract.relative(ctx, dest)
    obs: list[Obs] = []
    if not dest.exists():
        return obs
    for line_no, rtype, rec in dissect_json.iter_records(dest):
        if "recyclebin" not in rtype:
            continue
        _group, src = dissect_json.split_path(rec.get("source"))
        parts = src.strip("/").split("/")
        if len(parts) < 2:
            continue
        cands = by_name.get((parts[-2].lower(), parts[-1].lower()), [])
        live = [c for c in cands if c.allocated]
        if len(live) != 1:
            continue
        size = rec.get("filesize")
        obs.append(
            Obs(
                parser=DISSECT,
                key=live[0].key,
                original_path=str(rec.get("path") or "") or None,
                deleted=dissect_json.time(rec.get("ts")),
                size=size if isinstance(size, int) else None,
                ref=f"{rel}#L{line_no}",
            )
        )
    return obs


def _r_text(status: str) -> str:
    return {
        "present": "Its content file ($R) is present.",
        "deleted": "Its content file ($R) is deleted.",
        "missing": "No content file ($R) was found.",
    }[status]


def entry_row(ctx: ModuleContext, f: IFile, o: Obs, status: str) -> dict[str, Any]:
    sid_ok = recycle.is_sid(f.sid)
    who = f"account SID {f.sid}" if sid_ok else "an account (folder name is not a SID)"
    msg = f"Recycle bin record: a file was moved to the recycle bin by {who}. {_r_text(f.r_status)}"
    if not f.allocated:
        msg += " The $I record itself is deleted; it was read from its unallocated entry."
    name = re.split(r"[\\/]", o.original_path)[-1] if o.original_path else None
    tool = {BUILTIN: "forensic-analyze", RBCMD: "RBCmd", DISSECT: "target-query"}[o.parser]
    return {
        "category": "recycle_bin",
        "artifact_type": "recycle_bin_entry",
        "message": msg,
        "derivation": "observed",
        "source_tool": SOURCE_TOOL[o.parser],
        "tool_version": "recycle 1" if o.parser == BUILTIN else ctx.tool_version(tool),
        "parser": PARSER_NAME[o.parser],
        "datetime": o.deleted,
        "timestamp_desc": "Deletion Time" if o.deleted else None,
        "tz_basis": "utc" if o.deleted else None,
        "path": o.original_path,
        "filename": name or None,
        "size_bytes": o.size,
        "owner_sid": f.sid.upper() if sid_ok else None,
        "inode_ref": f.inode_ref,
        "allocated": f.allocated,
        "xval_status": status,
        "source_record": o.ref,
    }


class RecycleBin(Module):
    name = "recycle_bin"
    title = "Recycle bin"
    fs_types = frozenset({"ntfs"})
    order = 20
    description = "$I and $R pairs: original path, deletion time, owner account SID."

    def run(self, ctx: ModuleContext) -> ModuleResult:  # noqa: PLR0912, PLR0915
        entries = _entries(ctx)
        ifiles, _rfiles, info2 = find_ifiles(entries)
        export_root = ctx.workdir / "export"
        rows: list[dict[str, Any]] = []
        counts: Counter[str] = Counter()
        observations: list[Obs] = []
        for f in ifiles:
            export_and_parse(ctx, f, export_root)
            if f.parsed is None:
                counts["unparsed"] += 1
                rows.append(
                    {
                        "category": "recycle_bin",
                        "artifact_type": "recycle_bin_unparsed",
                        "message": "A recycle bin $I record could not be read or parsed.",
                        "derivation": "observed",
                        "source_tool": "forensic-analyze",
                        "tool_version": "recycle 1",
                        "parser": "airlock.recycle",
                        "path": f"/$Recycle.Bin/{f.sid}/{f.name}",
                        "inode_ref": f.inode_ref,
                        "allocated": f.allocated,
                        "owner_sid": f.sid.upper() if recycle.is_sid(f.sid) else None,
                        "text": f.error,
                    }
                )
                continue
            p = f.parsed
            if f.export is None:
                continue
            observations.append(
                Obs(
                    parser=BUILTIN,
                    key=f.key,
                    original_path=p.original_path or None,
                    deleted=p.deleted_iso,
                    size=p.file_size,
                    ref=f"{extract.relative(ctx, f.export)}#version={p.version}",
                )
            )
        missing: dict[str, str] = {}
        ran = [BUILTIN]
        if shutil.which("RBCmd"):
            if any(f.export for f in ifiles):
                try:
                    observations += rbcmd_obs(ctx, ifiles, export_root)
                    ran.append(RBCMD)
                except extract.ExtractError as exc:
                    missing[RBCMD] = str(exc)
            else:
                missing[RBCMD] = "no $I files to give it"
        else:
            missing[RBCMD] = "not installed (EZ Tools are staged on ASSETS)"
        dis = dissect_obs(ctx, ifiles) if ifiles else []
        if dis is None:
            missing[DISSECT] = "target-query is not installed"
        elif dis:
            observations += dis
            ran.append(DISSECT)
        else:
            missing[DISSECT] = (
                "no records: Dissect reads only live recycle bins on a recognised Windows system"
            )
        results = xval.join(
            [xval.Observation(o.parser, o.key, o.values(), o.ref) for o in observations],
            fields=COMPARED,
            equal=EQUAL,
        )
        by_key = {f.key: f for f in ifiles if f.parsed is not None}
        for o in observations:
            f = by_key.get(o.key)
            if f is None:
                continue
            rows.append(entry_row(ctx, f, o, xval.status_of(results, o.key)))
            counts[f"{o.parser}_records"] += 1
        for f in ifiles:
            if f.parsed is not None:
                counts["deleted_i_records" if not f.allocated else "live_i_records"] += 1
        for e in info2:
            rows.append(
                {
                    "category": "recycle_bin",
                    "artifact_type": "recycle_bin_info2",
                    "message": (
                        "A Windows XP recycle bin index (INFO2) was found. This version does not "
                        "parse INFO2 files; examine it separately."
                    ),
                    "derivation": "observed",
                    "source_tool": "forensic-analyze",
                    "tool_version": "recycle 1",
                    "parser": "airlock.recycle",
                    "path": e.get("path"),
                    "inode_ref": e.get("inode_ref"),
                    "allocated": bool(e.get("allocated")),
                }
            )
        if ifiles:
            rows.append(
                xval.summary_row(
                    "recycle bin records",
                    results,
                    volume_index=None,
                    parsers_run=ran,
                    parsers_missing=missing,
                )
            )

            def describe(res: xval.Result) -> dict[str, Any]:
                f = by_key.get(res.key)  # type: ignore[arg-type]
                return {
                    "inode_ref": f.inode_ref if f else None,
                    "path": f"/$Recycle.Bin/{f.sid}/{f.name}" if f else None,
                }

            rows.extend(xval.disagreement_rows("recycle bin", results, describe=describe))
        else:
            rows.append(
                {
                    "category": "recycle_bin",
                    "artifact_type": "recycle_bin_none",
                    "message": "No recycle bin records ($I files) were found on the NTFS volumes.",
                    "derivation": "observed",
                    "source_tool": "forensic-analyze",
                    "tool_version": "recycle 1",
                    "parser": "airlock.recycle",
                }
            )
        for k, v in xval.counts(results).items():
            counts[f"xval_{k}"] = v
        ordered = sorted_rows(
            [{k: v for k, v in r.items() if v is not None} for r in rows],
            "category",
            "inode_ref",
            "parser",
        )
        for r in ordered:
            ctx.emit(r)
        return ModuleResult("ok", counts=dict(sorted(counts.items())))


MODULE = RecycleBin()
