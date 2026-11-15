"""Module ``inventory`` (tasks 4C.5, 4C.27, 4C.28 part, 4C.29).

Every file and directory on each NTFS volume, live and deleted, from up to three independent
parsers (plan 2.5.3: both parsers' results from the start):

* ``tsk``: The Sleuth Kit ``fls -r -p -m /`` bodyfile (``modules/inventory/fls-v<N>.body``).
* ``dissect``: Dissect ``target-query -f mft --compact -j`` over the whole target
  (``modules/inventory/dissect-mft.jsonl``), records matched to volumes by content.
* ``mftecmd``: MFTECmd over the extracted ``$MFT`` when it is installed
  (``modules/inventory/mftecmd-v<N>/``).

Rows: one ``file_entry`` row per name per parser (category ``inventory``, derivation
``observed``) with path, inode_ref ``v<N>:<entry>-<sequence>``, size, allocated, and the
cross-check status; the four MACB times are in the raw record that ``source_record`` points
to (and the ``timeline`` module emits them as timeline rows). Cross-check summary and
disagreement rows (category ``xval``), inferred NTFS rows from ``ntfs_interp``, and one Volume
Shadow Copy check per volume, which always says what it found, "none found" included.

Writes ``modules/inventory/files.jsonl`` (the index other modules read) from the first parser
that worked, in the order tsk, dissect, mftecmd.
"""

from __future__ import annotations

import datetime as _dt
import re
import shutil
import struct
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from forensic_analyze import extract, ntfs_interp, xval
from forensic_analyze.api import Module, ModuleContext, ModuleResult, Volume, sorted_rows
from forensic_analyze.inventory_index import index_path, write_index
from forensic_analyze.parsers import bodyfile, dissect_json, ezcsv, filetime
from forensic_analyze.parsers.mft import MftIndex

TSK, DISSECT, MFTECMD = "tsk", "dissect", "mftecmd"
PARSER_ORDER = (TSK, DISSECT, MFTECMD)
SOURCE_TOOL = {TSK: "sleuthkit", DISSECT: "dissect", MFTECMD: "MFTECmd"}
BINARY = {TSK: "fls", DISSECT: "target-query", MFTECMD: "MFTECmd"}
COMPARED = ("path", "size", "allocated", "si_created", "si_modified", "si_changed", "si_accessed")
EQUAL = {
    "path": lambda a, b: xval.overlap(_known(a), _known(b)) or not _known(a) or not _known(b),
    "si_created": xval.same_second,
    "si_modified": xval.same_second,
    "si_changed": xval.same_second,
    "si_accessed": xval.same_second,
}
VSS_GUID = bytes.fromhex("6b87083876c1484eb7ae04046e6cc752")
VSS_HEADER_OFFSET = 0x1E00
_MONTHS = {
    m: i
    for i, m in enumerate(
        ["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"], 1
    )
}
_VSS_TIME = re.compile(
    r"([A-Za-z]{3})\s+(\d{1,2}),\s+(\d{4})\s+(\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?\s*UTC"
)


def _known(paths: Any) -> set[str]:
    """Paths a parser really knows (TSK's made-up ``$OrphanFiles`` names do not count)."""
    items = paths if isinstance(paths, set | frozenset) else {paths}
    return {p for p in items if p and not str(p).startswith("/$OrphanFiles")}


@dataclass
class FileObs:
    parser: str
    volume_index: int
    entry: int | None
    stream: str
    paths: set[str]
    is_dir: bool = False
    size: int | None = None
    allocated: bool | None = None
    deleted: bool | None = None
    realloc: bool = False
    si: dict[str, str | None] = field(default_factory=dict)
    owner_sid: str | None = None
    seq: int | None = None
    inode: str = ""
    ref: str = ""

    @property
    def key(self) -> tuple[int, int, str]:
        return (self.volume_index, -1 if self.entry is None else self.entry, self.stream)

    @property
    def path(self) -> str:
        known = sorted(_known(self.paths))
        return known[0] if known else (sorted(self.paths)[0] if self.paths else "")

    def values(self) -> dict[str, Any]:
        return {
            "path": frozenset(self.paths) if self.paths else None,
            "size": None if self.is_dir else self.size,
            "allocated": self.allocated,
            "si_created": self.si.get("created"),
            "si_modified": self.si.get("modified"),
            "si_changed": self.si.get("changed"),
            "si_accessed": self.si.get("accessed"),
        }


def _split_stream(path: str) -> tuple[str, str]:
    head, _, last = path.rpartition("/")
    name, sep, stream = last.partition(":")
    if not sep:
        return path, ""
    return f"{head}/{name}", stream


def _iso(seconds: int) -> str | None:
    return filetime.iso_from_unix(seconds) if seconds > 0 else None


# ----------------------------------------------------------------------------------------------
# Parser 1: The Sleuth Kit
# ----------------------------------------------------------------------------------------------


def tsk_listing(ctx: ModuleContext, vol: Volume, out: Path) -> list[FileObs]:
    """``fls -r -p -m /`` into ``out``; one observation per name line (not $FILE_NAME lines)."""
    cp = ctx.tool(extract.tsk_argv("fls", ctx, vol, "-r", "-p", "-m", "/"), stdout_path=out)
    if cp.returncode != 0:
        raise extract.ExtractError(f"fls exited {cp.returncode}: {extract._last_line(cp.stderr)}")
    rel = extract.relative(ctx, out)
    found: list[FileObs] = []
    for e in bodyfile.iter_file(out):
        if e.file_name_attr or e.mode.startswith("V") or e.entry is None:
            continue
        base, stream = _split_stream(e.name)
        found.append(
            FileObs(
                parser=TSK,
                volume_index=vol.index,
                entry=e.entry,
                stream=stream,
                paths={e.name if stream else base},
                is_dir=e.is_dir and not stream,
                size=e.size,
                allocated=e.allocated,
                deleted=e.deleted,
                realloc=e.realloc,
                si={
                    "created": _iso(e.crtime),
                    "modified": _iso(e.mtime),
                    "changed": _iso(e.ctime),
                    "accessed": _iso(e.atime),
                },
                inode=e.inode,
                ref=f"{rel}#L{e.line_no}",
            )
        )
    return found


# ----------------------------------------------------------------------------------------------
# Parser 2: Dissect
# ----------------------------------------------------------------------------------------------


def dissect_listing(path: Path, rel: str) -> dict[str, list[FileObs]]:
    """Observations per Dissect filesystem group (``""`` for a bare volume, ``fs0``, ...)."""
    by_key: dict[tuple[str, int, str], FileObs] = {}
    for line_no, rtype, rec in dissect_json.iter_records(path):
        if not rtype.startswith("filesystem/ntfs/mft/"):
            continue
        group, full = dissect_json.split_path(rec.get("path"))
        seg = rec.get("segment")
        if not isinstance(seg, int):
            continue
        is_ads = bool(rec.get("ads"))
        base, stream = _split_stream(full) if is_ads else (full, "")
        key = (group, seg, stream)
        obs = by_key.get(key)
        if obs is None:
            obs = by_key[key] = FileObs(
                parser=DISSECT,
                volume_index=-1,
                entry=seg,
                stream=stream,
                paths=set(),
                ref=f"{rel}#L{line_no}",
            )
        obs.paths.add(full if stream else base)
        if rec.get("inuse") is not None:
            obs.allocated = bool(rec.get("inuse"))
            obs.deleted = not obs.allocated
        if "/std" in rtype and not stream:
            size = rec.get("filesize")
            obs.is_dir = size is None and rec.get("resident") is None
            obs.size = size if isinstance(size, int) else None
            obs.owner_sid = rec.get("owner") or None
            obs.si = {
                "created": dissect_json.time(rec.get("creation_time")),
                "modified": dissect_json.time(rec.get("last_modification_time")),
                "changed": dissect_json.time(rec.get("last_change_time")),
                "accessed": dissect_json.time(rec.get("last_access_time")),
            }
            obs.ref = f"{rel}#L{line_no}"
        elif stream and isinstance(rec.get("filesize"), int):
            obs.size = rec["filesize"]
    groups: dict[str, list[FileObs]] = {}
    for (group, _seg, _stream), obs in sorted(by_key.items()):
        groups.setdefault(group, []).append(obs)
    return groups


def map_groups(
    groups: dict[str, list[FileObs]], tsk: dict[int, list[FileObs]], ntfs: list[Volume]
) -> tuple[dict[str, int], list[str]]:
    """Match Dissect filesystem groups to volumes by shared (entry, path) pairs."""
    if len(groups) == 1 and len(ntfs) == 1:
        return {next(iter(groups)): ntfs[0].index}, []
    pairs = {v: {(o.entry, p) for o in obs for p in o.paths} for v, obs in tsk.items()}
    mapping: dict[str, int] = {}
    unmapped: list[str] = []
    taken: set[int] = set()
    for group in sorted(groups):
        mine = {(o.entry, p) for o in groups[group] for p in o.paths}
        scores = sorted(
            (
                (len(mine & pairs.get(v.index, set())), v.index)
                for v in ntfs
                if v.index not in taken
            ),
            reverse=True,
        )
        if scores and scores[0][0] > 0:
            mapping[group] = scores[0][1]
            taken.add(scores[0][1])
        else:
            unmapped.append(group)
    return mapping, unmapped


# ----------------------------------------------------------------------------------------------
# Parser 3: MFTECmd
# ----------------------------------------------------------------------------------------------


def mftecmd_listing(ctx: ModuleContext, vol: Volume, mft: Path, out_dir: Path) -> list[FileObs]:
    extract.tool_dir(ctx, out_dir)
    cp = ctx.tool(["MFTECmd", "-f", str(mft), "--csv", str(out_dir), "--csvf", "mft.csv"])
    if cp.returncode != 0:
        raise extract.ExtractError(f"MFTECmd exited {cp.returncode}")
    found: dict[tuple[int, str], FileObs] = {}
    for csv_path in ezcsv.csv_files(out_dir):
        rel = extract.relative(ctx, csv_path)
        for line_no, row in ezcsv.read_rows(csv_path):
            entry = ezcsv.get_int(row, "EntryNumber")
            if entry is None:
                continue
            name = ezcsv.get(row, "FileName")
            is_ads = bool(ezcsv.get_bool(row, "IsAds"))
            stream = ""
            if is_ads and ":" in name:
                name, _, stream = name.partition(":")
            parent = ezcsv.windows_to_posix(ezcsv.get(row, "ParentPath"))
            full = (parent.rstrip("/") + "/" + name) if name else parent
            key = (entry, stream)
            obs = found.get(key)
            if obs is None:
                in_use = ezcsv.get_bool(row, "InUse")
                obs = found[key] = FileObs(
                    parser=MFTECMD,
                    volume_index=vol.index,
                    entry=entry,
                    stream=stream,
                    paths=set(),
                    is_dir=bool(ezcsv.get_bool(row, "IsDirectory")),
                    size=ezcsv.get_int(row, "FileSize"),
                    allocated=in_use,
                    deleted=None if in_use is None else not in_use,
                    seq=ezcsv.get_int(row, "SequenceNumber"),
                    ref=f"{rel}#L{line_no}",
                )
                if not stream:
                    obs.si = {
                        "created": ezcsv.get_time(row, "Created0x10"),
                        "modified": ezcsv.get_time(row, "LastModified0x10"),
                        "changed": ezcsv.get_time(row, "LastRecordChange0x10"),
                        "accessed": ezcsv.get_time(row, "LastAccess0x10"),
                    }
            obs.paths.add(f"{full}:{stream}" if stream else full)
    return [found[k] for k in sorted(found)]


# ----------------------------------------------------------------------------------------------
# Volume Shadow Copy check (4C.29)
# ----------------------------------------------------------------------------------------------


def _vss_time(text: str) -> str | None:
    m = _VSS_TIME.search(text)
    if not m:
        return None
    mon, day, year, hh, mm, ss, frac = m.groups()
    month = _MONTHS.get(mon.lower())
    if not month:
        return None
    try:
        when = _dt.datetime(int(year), month, int(day), int(hh), int(mm), int(ss))
    except ValueError:
        return None
    out = when.strftime("%Y-%m-%dT%H:%M:%S")
    if frac:
        out += "." + frac[:9]
    return out + "Z"


def parse_vshadowinfo(text: str) -> tuple[int | None, list[str | None]]:
    """``(store count, creation times)``; count None when the output is not understood."""
    if "No Volume Shadow Snapshots found" in text:
        return 0, []
    m = re.search(r"Number of stores:\s*(\d+)", text)
    if not m:
        return None, []
    times = [
        _vss_time(line)
        for line in text.splitlines()
        if line.strip().lower().startswith("creation time")
    ]
    return int(m.group(1)), times


def parse_vss_header(block: bytes, offset: int) -> tuple[bool, int | None]:
    """``(header present, catalog offset)`` from the cluster that holds byte 0x1E00."""
    head = block[offset : offset + 64]
    if len(head) < 56 or head[:16] != VSS_GUID:
        return False, None
    return True, struct.unpack_from("<Q", head, 48)[0]


def vss_check(ctx: ModuleContext, vol: Volume) -> list[dict[str, Any]]:  # noqa: PLR0912
    rows: list[dict[str, Any]] = []
    notes: list[str] = []
    count: int | None = None
    times: list[str | None] = []
    raw_target = not extract.image_args(ctx)
    src = ""
    if shutil.which("vshadowinfo") and raw_target:
        out = ctx.workdir / f"vshadowinfo-v{vol.index}.txt"
        cp = ctx.tool(
            ["vshadowinfo", "-o", str(vol.offset_bytes), str(ctx.target.path)], stdout_path=out
        )
        text = out.read_text(encoding="utf-8", errors="replace") + (cp.stderr or "")
        count, times = parse_vshadowinfo(text)
        src = extract.relative(ctx, out)
        if count is None:
            notes.append(f"vshadowinfo output not understood (exit {cp.returncode})")
    else:
        notes.append(
            "vshadowinfo is not installed" if raw_target else "vshadowinfo cannot read E01 images"
        )
    # Second, independent check: the VSS volume header at byte 0x1E00 of the volume.
    cs = extract.cluster_size(ctx, vol)
    unit, within = divmod(VSS_HEADER_OFFSET, cs)
    hdr_file = ctx.workdir / f"vss-header-v{vol.index}.bin"
    cp = ctx.tool(extract.tsk_argv("blkcat", ctx, vol, str(unit), "1"), stdout_path=hdr_file)
    header: bool | None = None
    catalog: int | None = None
    if cp.returncode == 0:
        header, catalog = parse_vss_header(hdr_file.read_bytes(), within)
    else:
        notes.append("the VSS header could not be read with blkcat")
    base = {
        "category": "inventory",
        "derivation": "observed",
        "inode_ref": f"v{vol.index}:vss",
    }
    if header is None:
        hdr_text = "header not checked"
    elif not header:
        hdr_text = "no VSS header at byte 7680"
    elif not catalog:
        hdr_text = "a VSS header with no catalog"
    else:
        hdr_text = "a VSS header with a catalog"
    if count is not None:
        found = count > 0
        msg = (
            f"Volume {vol.index}: {count} Volume Shadow Copies found by vshadowinfo ({hdr_text}). "
            "This version does not analyse them; examine them separately."
            if found
            else f"Volume {vol.index}: no Volume Shadow Copies found "
            f"(vshadowinfo: none; {hdr_text})."
        )
        rows.append(
            {
                **base,
                "artifact_type": "vss_check",
                "message": msg,
                "source_tool": "libvshadow",
                "tool_version": ctx.tool_version("vshadowinfo"),
                "parser": "vshadowinfo",
                "source_record": f"{src}#all",
                "text": "; ".join(notes) or None,
            }
        )
        for n, when in enumerate(times, start=1):
            rows.append(
                {
                    **base,
                    "artifact_type": "vss_store",
                    "message": f"Volume Shadow Copy store {n} on volume {vol.index}.",
                    "source_tool": "libvshadow",
                    "tool_version": ctx.tool_version("vshadowinfo"),
                    "parser": "vshadowinfo",
                    "datetime": when,
                    "timestamp_desc": "Creation Time (shadow copy)" if when else None,
                    "tz_basis": "utc" if when else None,
                    "source_record": f"{src}#store={n}",
                }
            )
    else:
        if header is None:
            msg = f"Volume {vol.index}: the Volume Shadow Copy check could not be done."
        elif not header or not catalog:
            msg = f"Volume {vol.index}: no Volume Shadow Copies found ({hdr_text})."
        else:
            msg = (
                f"Volume {vol.index}: {hdr_text}, so shadow copies are probably present. They "
                "were not listed (vshadowinfo not available); examine them separately."
            )
        rows.append(
            {
                **base,
                "artifact_type": "vss_check",
                "message": msg,
                "source_tool": "forensic-analyze",
                "tool_version": "vss_header 1",
                "parser": "airlock.vss_header",
                "source_record": f"{extract.relative(ctx, hdr_file)}#{within}",
                "text": "; ".join(notes) or None,
            }
        )
    return rows


# ----------------------------------------------------------------------------------------------
# Rows
# ----------------------------------------------------------------------------------------------


def _message(obs: FileObs) -> str:
    who = {TSK: "The Sleuth Kit (fls)", DISSECT: "Dissect", MFTECMD: "MFTECmd"}[obs.parser]
    if obs.stream:
        kind = "Alternate data stream"
    elif obs.is_dir:
        kind = "Directory"
    else:
        kind = "File"
    if obs.realloc:
        state = "deleted name; its metadata entry now belongs to another file"
    elif obs.allocated is False:
        state = "deleted (metadata entry not allocated)"
    else:
        state = "allocated"
    return f"{kind}, {state}. Listed by {who}."


def file_row(ctx: ModuleContext, obs: FileObs, seq: int | None, status: str | None) -> dict:
    path = obs.path
    seqpart = f"-{seq}" if seq is not None else ""
    entry = "?" if obs.entry is None else str(obs.entry)
    row: dict[str, Any] = {
        "category": "inventory",
        "artifact_type": "file_entry",
        "message": _message(obs),
        "derivation": "observed",
        "source_tool": SOURCE_TOOL[obs.parser],
        "tool_version": ctx.tool_version(BINARY[obs.parser]),
        "parser": obs.parser,
        "path": path,
        "filename": path.rsplit("/", 1)[-1] or "/",
        "inode_ref": f"v{obs.volume_index}:{entry}{seqpart}",
        "allocated": obs.allocated,
        "source_record": obs.ref or None,
        "xval_status": status,
        "owner_sid": obs.owner_sid if obs.owner_sid and obs.owner_sid.startswith("S-1-") else None,
    }
    if obs.size is not None and not obs.is_dir:
        row["size_bytes"] = obs.size
    return row


def index_entry(obs: FileObs, seq: int | None) -> dict[str, Any] | None:
    if obs.is_dir:
        return None
    entry = "?" if obs.entry is None else str(obs.entry)
    return {
        "volume_index": obs.volume_index,
        "inode": obs.inode or entry,
        "inode_ref": f"v{obs.volume_index}:{entry}" + (f"-{seq}" if seq is not None else ""),
        "path": obs.path,
        "size_bytes": obs.size,
        "allocated": bool(obs.allocated),
        "deleted": bool(obs.deleted),
        "mtime": obs.si.get("modified"),
        "atime": obs.si.get("accessed"),
        "ctime": obs.si.get("changed"),
        "crtime": obs.si.get("created"),
    }


def _safe_index_entry(entry: dict[str, Any]) -> dict[str, Any]:
    """files.jsonl must be valid UTF-8: escape the path like findings do, keep raw bytes."""
    from forensic_analyze.findings import safe_path  # noqa: PLC0415 - optional package

    path = str(entry["path"])
    try:
        path.encode("utf-8")
        clean = True
    except UnicodeEncodeError:
        clean = False
    if clean:
        return entry
    display, b64 = safe_path(path)
    return {**entry, "path": display, "path_b64": b64}


# ----------------------------------------------------------------------------------------------
# The module
# ----------------------------------------------------------------------------------------------


class Inventory(Module):
    name = "inventory"
    title = "File inventory"
    fs_types = frozenset({"ntfs"})
    order = 10
    description = "Every file, live and deleted, from The Sleuth Kit, Dissect, and MFTECmd."

    def run(self, ctx: ModuleContext) -> ModuleResult:  # noqa: PLR0912, PLR0915
        vols = ctx.target.volumes_of("ntfs")
        rows: list[dict[str, Any]] = []
        system_rows: list[dict[str, Any]] = []
        counts: Counter[str] = Counter()
        missing: dict[str, str] = {}
        tsk: dict[int, list[FileObs]] = {}
        mfte: dict[int, list[FileObs]] = {}
        mft_index: dict[int, MftIndex] = {}
        failures: list[str] = []

        for vol in vols:
            try:
                tsk[vol.index] = tsk_listing(ctx, vol, ctx.workdir / f"fls-v{vol.index}.body")
            except Exception as exc:
                failures.append(f"fls on volume {vol.index}: {exc}")
                ctx.log("inventory_parser_failed", parser=TSK, volume=vol.index, error=str(exc))
            try:
                mft_index[vol.index] = extract.load_mft_index(ctx, vol)
            except extract.ExtractError as exc:
                failures.append(str(exc))
            if shutil.which("MFTECmd"):
                try:
                    mft_path = extract.extract_system_file(ctx, vol, "$MFT")
                    mfte[vol.index] = mftecmd_listing(
                        ctx, vol, mft_path, ctx.workdir / f"mftecmd-v{vol.index}"
                    )
                except Exception as exc:
                    failures.append(f"MFTECmd on volume {vol.index}: {exc}")
            else:
                missing[MFTECMD] = "not installed (EZ Tools are staged on ASSETS)"

        # Dissect reads the whole target once; its filesystems are matched to volumes.
        dis: dict[int, list[FileObs]] = {}
        dpath = ctx.workdir / "dissect-mft.jsonl"
        try:
            cp = extract.dissect_query(ctx, ["-f", "mft", "--compact"], dpath)
        except Exception as exc:
            cp = None
            failures.append(f"Dissect: {exc}")
        if cp is None:
            missing.setdefault(DISSECT, "target-query is not installed")
        else:
            groups = dissect_listing(dpath, extract.relative(ctx, dpath)) if dpath.exists() else {}
            if cp.returncode != 0 and not groups:
                failures.append(
                    f"Dissect target-query exited {cp.returncode}: {extract._last_line(cp.stderr)}"
                )
            mapping, unmapped = map_groups(groups, tsk, vols)
            for group, vindex in mapping.items():
                for obs in groups[group]:
                    obs.volume_index = vindex
                dis.setdefault(vindex, []).extend(groups[group])
            for group in unmapped:
                system_rows.append(
                    {
                        "category": "system",
                        "artifact_type": "parser_note",
                        "message": (
                            "Dissect reported an NTFS filesystem that could not be matched to a "
                            "volume; its records are kept but not compared."
                        ),
                        "derivation": "observed",
                        "source_tool": "dissect",
                        "tool_version": ctx.tool_version("target-query"),
                        "parser": DISSECT,
                        "text": f"Dissect filesystem group: {group or '(bare volume)'}",
                        "source_record": f"{extract.relative(ctx, dpath)}#group={group}",
                    }
                )

        index_lines: list[dict[str, Any]] = []
        for vol in vols:
            per_parser = {
                TSK: tsk.get(vol.index),
                DISSECT: dis.get(vol.index),
                MFTECMD: mfte.get(vol.index),
            }
            ran = [p for p in PARSER_ORDER if per_parser[p] is not None]
            if not ran:
                continue
            idx = mft_index.get(vol.index)
            observations = [
                xval.Observation(o.parser, o.key, o.values(), o.ref)
                for p in ran
                for o in per_parser[p] or []
                if not o.realloc and o.entry is not None
            ]
            results = xval.join(observations, fields=COMPARED, equal=EQUAL)

            def seq_of(o: FileObs, idx: MftIndex | None = idx) -> int | None:
                if o.seq is not None:
                    return o.seq
                rec = idx.get(o.entry) if idx and o.entry is not None else None
                return rec.seq if rec else None

            for p in ran:
                for o in per_parser[p] or []:
                    status = None if o.realloc else xval.status_of(results, o.key)
                    rows.append(file_row(ctx, o, seq_of(o), status))
                    counts[f"{p}_entries"] += 1
                    if o.allocated is False or o.realloc:
                        counts[f"{p}_deleted"] += 1
            primary = ran[0]
            for o in per_parser[primary] or []:
                line = index_entry(o, seq_of(o))
                if line is not None:
                    index_lines.append(_safe_index_entry(line))
            notrun = {
                p: missing.get(p, "failed or produced no output")
                for p in PARSER_ORDER
                if p not in ran
            }
            rows.append(
                {
                    **xval.summary_row(
                        "MFT file entries",
                        results,
                        volume_index=vol.index,
                        parsers_run=ran,
                        parsers_missing=notrun,
                    ),
                    "inode_ref": f"v{vol.index}:mft",
                }
            )

            def describe(res: xval.Result, vol: Volume = vol) -> dict[str, Any]:
                path = ""
                for ob in res.observations:
                    known = sorted(_known(ob.values.get("path") or set()))
                    if known:
                        path = known[0]
                        break
                return {
                    "path": path or None,
                    "inode_ref": f"v{vol.index}:{res.key[1]}",
                }

            rows.extend(xval.disagreement_rows("MFT file entry", results, describe=describe))
            for k, v in xval.counts(results).items():
                counts[f"xval_{k}"] += v
            if idx is not None:
                rel = extract.relative(ctx, ctx.run_dir / "extract" / f"v{vol.index}" / "MFT")
                rows.extend(
                    ntfs_interp.interpret_mft(
                        idx,
                        volume_index=vol.index,
                        source_record=rel,
                        owner_of=extract.owner_resolver(ctx, vol),
                    )
                )
            try:
                rows.extend(vss_check(ctx, vol))
            except Exception as exc:
                failures.append(f"VSS check on volume {vol.index}: {exc}")
                rows.append(
                    {
                        "category": "inventory",
                        "artifact_type": "vss_check",
                        "message": f"Volume {vol.index}: the Volume Shadow Copy check failed.",
                        "derivation": "observed",
                        "source_tool": "forensic-analyze",
                        "tool_version": "vss_header 1",
                        "parser": "airlock.vss_header",
                        "text": str(exc),
                    }
                )

        for text in failures:
            system_rows.append(
                {
                    "category": "system",
                    "artifact_type": "parser_error",
                    "message": "A parser step of the inventory failed; other parsers still ran.",
                    "derivation": "observed",
                    "source_tool": "forensic-analyze",
                    "tool_version": "inventory 1",
                    "parser": "inventory",
                    "text": text,
                }
            )
        listed = any(tsk.get(v.index) is not None or dis.get(v.index) for v in vols)
        if not listed:
            for r in system_rows:
                ctx.emit(r)
            return ModuleResult(
                "failed", "no parser could list the NTFS volumes: " + "; ".join(failures)
            )
        n = write_index(index_path(ctx.run_dir), index_lines)
        counts["index_files"] = n
        ordered = sorted_rows(
            [{k: v for k, v in r.items() if v is not None} for r in rows],
            "inode_ref",
            "path",
            "parser",
            "artifact_type",
        )
        for r in ordered + system_rows:
            ctx.emit(r)
        return ModuleResult("ok", counts=dict(sorted(counts.items())))


MODULE = Inventory()
