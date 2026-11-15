"""Module ``users`` (task 4C.13): what ties files to an account. Never names a person.

For each NTFS volume:

* Owner SIDs: each file's ``$STANDARD_INFORMATION`` security ID looked up in
  ``$Secure:$SDS`` (built-in parsers). One summary row per owner account SID, the per-file
  list in ``modules/users/owners-v<N>.jsonl``. Cross-checked against Dissect's owner field
  (per file) and MFTECmd ``--sds`` (per security ID) when they are available.
* Shortcut (``.lnk``) files: copied out and parsed (``parsers/lnk.py``): target path, target
  times, size, volume serial and type. LECmd is the second parser when installed.
* Jump Lists: parsed with JLECmd when installed; otherwise a row says how many were found and
  that they were not parsed.

Rows say "account SID"; a profile folder name is never reported as a person.
"""

from __future__ import annotations

import re
import shutil
from collections import Counter
from pathlib import Path
from typing import Any

from airlock_common import jsonio
from forensic_analyze import extract, xval
from forensic_analyze.api import Module, ModuleContext, ModuleResult, Volume, sorted_rows
from forensic_analyze.inventory_index import iter_files
from forensic_analyze.parsers import dissect_json, ezcsv, lnk
from forensic_analyze.parsers.mft import FIRST_USER_ENTRY, MftIndex

VERSION = "users 1"
WELL_KNOWN = {
    "S-1-1-0": "well-known group Everyone",
    "S-1-5-18": "built-in Local System account",
    "S-1-5-19": "built-in Local Service account",
    "S-1-5-20": "built-in Network Service account",
    "S-1-5-32-544": "built-in Administrators group",
    "S-1-5-32-545": "built-in Users group",
    "S-1-3-0": "well-known Creator Owner",
}
_INODE_REF = re.compile(r"^v\d+:(\d+)(?:-(\d+))?$")
JUMPLIST_EXT = (".automaticdestinations-ms", ".customdestinations-ms")


def describe_sid(sid: str) -> str:
    if sid in WELL_KNOWN:
        return WELL_KNOWN[sid]
    if re.fullmatch(r"S-1-5-80(-\d+){5}", sid):
        return "a Windows service account"
    if re.fullmatch(r"S-1-5-21(-\d+){3}-500", sid):
        return "the built-in Administrator account of a Windows system (RID 500)"
    if re.fullmatch(r"S-1-5-21(-\d+){3}-\d+", sid):
        return "a local or domain account"
    return "an account or group"


def _row(**kw: Any) -> dict[str, Any]:
    return {"category": "users", "derivation": "observed", **kw}


# ----------------------------------------------------------------------------------------------
# Owners
# ----------------------------------------------------------------------------------------------


def owner_table(ctx: ModuleContext, vol: Volume, index: MftIndex) -> list[dict[str, Any]]:
    owner = extract.owner_resolver(ctx, vol)
    out = []
    for entry in sorted(index.records):
        rec = index.records[entry]
        sid = owner(rec)
        if not sid:
            continue
        out.append(
            {
                "entry": entry,
                "seq": rec.seq,
                "in_use": rec.in_use,
                "path": index.path_of(entry),
                "security_id": rec.security_id,
                "owner_sid": sid,
            }
        )
    return out


def dissect_owners(ctx: ModuleContext, vol: Volume) -> tuple[dict[int, str], str] | None:
    """Per-entry owner from Dissect's MFT records (the inventory's output when it exists)."""
    shared = ctx.run_dir / "modules" / "inventory" / "dissect-mft.jsonl"
    if shared.with_name(shared.name + ".done").exists():
        path = shared
    else:
        path = ctx.workdir / "dissect-mft.jsonl"
        if extract.dissect_query(ctx, ["-f", "mft", "--compact"], path) is None:
            return None
    if not path.exists():
        return {}, ""
    groups: dict[str, dict[int, str]] = {}
    for _n, rtype, rec in dissect_json.iter_records(path):
        if "/std" not in rtype or not rec.get("owner"):
            continue
        group, _p = dissect_json.split_path(rec.get("path"))
        seg = rec.get("segment")
        if isinstance(seg, int):
            groups.setdefault(group, {})[seg] = str(rec["owner"])
    ntfs = ctx.target.volumes_of("ntfs")
    if len(groups) == 1 and len(ntfs) == 1:
        return next(iter(groups.values())), extract.relative(ctx, path)
    # Several filesystems: Dissect numbers them fs0, fs1, ... in partition order.
    order = sorted(g for g in groups if g.startswith("fs"))
    pos = [v.index for v in ntfs].index(vol.index)
    if pos < len(order):
        return groups[order[pos]], extract.relative(ctx, path)
    return {}, extract.relative(ctx, path)


def dissect_owner_table(
    ctx: ModuleContext, vol: Volume
) -> tuple[tuple[dict[int, str], str] | None, str]:
    """``dissect_owners`` unless the inventory left Dissect's MFT pass out of this run (bounded
    mode: running the same whole-target query here would cost the time it saved). Returns the
    owners (or None) and, when None, why."""
    limited = extract.dissect_mft_limit(ctx.run_dir)
    if limited:
        return None, f"left out (coverage limit set by the inventory): {limited.get('reason', '')}"
    dis = dissect_owners(ctx, vol)
    return dis, "" if dis is not None else "target-query is not installed"


def mftecmd_sds(ctx: ModuleContext, vol: Volume) -> tuple[dict[int, str], str] | None:
    if not shutil.which("MFTECmd"):
        return None
    sds_path = extract.extract_system_file(ctx, vol, "$Secure:$SDS")
    out_dir = ctx.workdir / f"mftecmd-sds-v{vol.index}"
    extract.tool_dir(ctx, out_dir)
    cp = ctx.tool(["MFTECmd", "-f", str(sds_path), "--csv", str(out_dir), "--csvf", "sds.csv"])
    if cp.returncode != 0:
        raise extract.ExtractError(f"MFTECmd --sds exited {cp.returncode}")
    table: dict[int, str] = {}
    ref = ""
    for csv_path in ezcsv.csv_files(out_dir):
        ref = extract.relative(ctx, csv_path)
        for _n, row in ezcsv.read_rows(csv_path):
            sec = ezcsv.get_int(row, "Id", "SecurityId")
            sid = ezcsv.get(row, "OwnerSid", "Owner")
            if sec is not None and sid.startswith("S-1-"):
                table[sec] = sid
    return table, ref


def owner_rows(ctx: ModuleContext, vol: Volume, counts: Counter[str]) -> list[dict[str, Any]]:
    try:
        index = extract.load_mft_index(ctx, vol)
    except extract.ExtractError as exc:
        return [
            _row(
                artifact_type="owner_sid_unavailable",
                message=f"Volume {vol.index}: file owners could not be read ($MFT not available).",
                source_tool="forensic-analyze",
                tool_version=VERSION,
                parser="airlock.sds",
                text=str(exc),
            )
        ]
    try:
        security = extract.load_security(ctx, vol)
    except extract.ExtractError:
        security = {}
    table = owner_table(ctx, vol, index)
    out_path = ctx.workdir / f"owners-v{vol.index}.jsonl"
    with open(out_path, "w", encoding="utf-8", newline="\n") as fh:
        for n, line in enumerate(table, start=1):
            line["line"] = n
            fh.write(jsonio.dumps_line(line) + "\n")
    rel = extract.relative(ctx, out_path)
    rows: list[dict[str, Any]] = []
    per_sid: Counter[str] = Counter(t["owner_sid"] for t in table)
    user_files: Counter[str] = Counter(
        t["owner_sid"] for t in table if t["entry"] >= FIRST_USER_ENTRY
    )
    first_line: dict[str, int] = {}
    for t in table:
        first_line.setdefault(t["owner_sid"], t["line"])
    for sid in sorted(per_sid):
        if not sid.startswith("S-1-"):
            continue
        rows.append(
            _row(
                artifact_type="owner_sid_summary",
                message=(
                    f"Account SID {sid} ({describe_sid(sid)}) owns {per_sid[sid]} files and "
                    f"folders on volume {vol.index} ({user_files[sid]} outside the NTFS "
                    "system files). Ownership shows which account a file belongs to, not which "
                    "person used it."
                ),
                source_tool="forensic-analyze",
                tool_version=VERSION,
                parser="airlock.sds",
                owner_sid=sid,
                inode_ref=f"v{vol.index}:owners",
                source_record=f"{rel}#L{first_line[sid]}",
            )
        )
    counts["owner_sids"] += len(per_sid)
    counts["owned_entries"] += len(table)
    if not security:
        rows.append(
            _row(
                artifact_type="owner_sid_unavailable",
                message=f"Volume {vol.index}: $Secure:$SDS could not be read; owners unknown.",
                source_tool="forensic-analyze",
                tool_version=VERSION,
                parser="airlock.sds",
            )
        )
    # Cross-checks.
    missing: dict[str, str] = {}
    ours_by_entry = {t["entry"]: t["owner_sid"] for t in table}
    dis, dis_missing = dissect_owner_table(ctx, vol)
    obs = [
        xval.Observation("airlock", (vol.index, e), {"owner": s}, f"{rel}#entry={e}")
        for e, s in ours_by_entry.items()
    ]
    if dis is None:
        missing["dissect"] = dis_missing
    else:
        dmap, dref = dis
        obs += [
            xval.Observation("dissect", (vol.index, e), {"owner": s}, f"{dref}#segment={e}")
            for e, s in dmap.items()
            if e in index.records
        ]
        if not dmap:
            missing["dissect"] = "Dissect reported no owners for this volume"
    res_files = xval.join(obs, fields=("owner",))
    rows.append(
        {
            **xval.summary_row(
                "file owner SIDs",
                res_files,
                volume_index=vol.index,
                parsers_run=sorted({o.parser for o in obs}),
                parsers_missing=missing,
            ),
            "inode_ref": f"v{vol.index}:owners",
        }
    )
    rows.extend(
        xval.disagreement_rows(
            "file owner",
            res_files,
            describe=lambda r: {
                "inode_ref": f"v{vol.index}:{r.key[1]}",
                "path": index.path_of(r.key[1]),
            },
        )
    )
    try:
        sds_x = mftecmd_sds(ctx, vol)
    except extract.ExtractError as exc:
        sds_x = None
        missing["mftecmd"] = str(exc)
    if sds_x is not None:
        etable, eref = sds_x
        sobs = [
            xval.Observation("airlock", (vol.index, k), {"owner": v.owner_sid}, f"{rel}#sec={k}")
            for k, v in security.items()
            if v.owner_sid
        ] + [
            xval.Observation("mftecmd", (vol.index, k), {"owner": v}, f"{eref}#id={k}")
            for k, v in etable.items()
        ]
        res_sds = xval.join(sobs, fields=("owner",))
        rows.append(
            {
                **xval.summary_row(
                    "$SDS security descriptors",
                    res_sds,
                    volume_index=vol.index,
                    parsers_run=["airlock", "mftecmd"],
                    parsers_missing={},
                ),
                "inode_ref": f"v{vol.index}:sds",
            }
        )
        rows.extend(
            xval.disagreement_rows(
                "$SDS descriptor",
                res_sds,
                describe=lambda r: {"inode_ref": f"v{vol.index}:sds{r.key[1]}"},
            )
        )
    return rows


# ----------------------------------------------------------------------------------------------
# LNK files and Jump Lists
# ----------------------------------------------------------------------------------------------


def _entry_of(line: dict[str, Any]) -> int | None:
    m = _INODE_REF.match(str(line.get("inode_ref", "")))
    return int(m.group(1)) if m else None


def lnk_rows(  # noqa: PLR0912, PLR0915
    ctx: ModuleContext, vol: Volume, counts: Counter[str]
) -> list[dict[str, Any]]:
    lines = [
        e
        for e in iter_files(ctx.run_dir, extensions=[".lnk"], volume_index=vol.index)
        if ":" not in str(e.get("path", "")).rsplit("/", 1)[-1]
    ]
    if not lines:
        return []
    try:
        owner = extract.owner_resolver(ctx, vol)
        index: MftIndex | None = extract.load_mft_index(ctx, vol)
    except extract.ExtractError:
        index = None
    export_root = ctx.workdir / "export" / "lnk" / f"v{vol.index}"
    rows: list[dict[str, Any]] = []
    obs: list[xval.Observation] = []
    exported: dict[str, dict[str, Any]] = {}
    keyed: list[tuple[dict[str, Any], tuple[int, str]]] = []
    for e in lines:
        name = extract.safe_component(str(e["path"]).rsplit("/", 1)[-1])
        if not name.lower().endswith(".lnk"):
            name += ".lnk"
        try:
            dest = extract.export_file(
                ctx, vol, str(e["inode"]), export_root / str(e["inode"]), name=name
            )
        except (extract.ExtractError, ValueError) as exc:
            counts["lnk_export_failed"] += 1
            ctx.log("lnk_export_failed", path=str(e.get("path")), error=str(exc))
            continue
        rel = extract.relative(ctx, dest)
        entry = _entry_of(e)
        rec = index.get(entry) if index and entry is not None else None
        sid = owner(rec) if rec else None
        try:
            info = lnk.parse_file(dest)
        except (lnk.LnkError, OSError) as exc:
            counts["lnk_unparsed"] += 1
            rows.append(
                _row(
                    artifact_type="lnk_unparsed",
                    message="A shortcut (LNK) file could not be parsed.",
                    source_tool="forensic-analyze",
                    tool_version="lnk 1",
                    parser="airlock.lnk",
                    path=e["path"],
                    inode_ref=e.get("inode_ref"),
                    allocated=bool(e.get("allocated")),
                    owner_sid=sid,
                    source_record=f"{rel}#0",
                    text=str(exc),
                )
            )
            continue
        counts["lnk_parsed"] += 1
        exported[str(dest.resolve())] = e
        times = info.times()
        obs.append(
            xval.Observation(
                "airlock",
                (vol.index, str(e["inode"])),
                {
                    "target": info.target_path or None,
                    "modified": dict(times).get("Content Modification Time (LNK target)"),
                },
                f"{rel}#0",
            )
        )
        detail = [f"target: {info.target_path or '(none)'}"]
        if info.volume_serial:
            detail.append(f"volume serial: {info.volume_serial}")
        if info.drive_type:
            detail.append(f"drive type: {info.drive_type}")
        if info.volume_label:
            detail.append(f"volume label: {info.volume_label}")
        if info.working_dir:
            detail.append(f"working folder: {info.working_dir}")
        who = f" The shortcut is owned by account SID {sid}." if sid else ""
        base = {
            "source_tool": "forensic-analyze",
            "tool_version": "lnk 1",
            "parser": "airlock.lnk",
            "path": e["path"],
            "inode_ref": e.get("inode_ref"),
            "allocated": bool(e.get("allocated")),
            "owner_sid": sid,
            "source_record": f"{rel}#0",
            "text": "; ".join(detail),
        }
        lnk_row = _row(
            artifact_type="lnk_file",
            message=(
                "Shortcut (LNK) file: it records a target path, the target's times and "
                f"size, and the volume the target was on.{who}"
            ),
            size_bytes=info.target_size,
            **base,
        )
        rows.append(lnk_row)
        keyed.append((lnk_row, (vol.index, str(e["inode"]))))
        for desc, iso in times:
            rows.append(
                _row(
                    artifact_type="lnk_target_time",
                    message=f"Shortcut (LNK) file: {desc.split(' (')[0].lower()} of its target.",
                    datetime=iso,
                    timestamp_desc=desc,
                    tz_basis="utc",
                    **base,
                )
            )
    ran = ["airlock"]
    missing: dict[str, str] = {}
    if shutil.which("LECmd") and exported:
        out_dir = ctx.workdir / f"lecmd-v{vol.index}"
        extract.tool_dir(ctx, out_dir)
        cp = ctx.tool(
            ["LECmd", "-d", str(export_root), "--csv", str(out_dir), "--csvf", "lecmd.csv"]
        )
        if cp.returncode == 0:
            ran.append("lecmd")
            for csv_path in ezcsv.csv_files(out_dir):
                cref = extract.relative(ctx, csv_path)
                for line_no, row in ezcsv.read_rows(csv_path):
                    src = ezcsv.get(row, "SourceFile")
                    e = exported.get(str(Path(src).resolve())) if src else None
                    if e is None:
                        continue
                    target = ezcsv.get(row, "LocalPath", "TargetIDAbsolutePath", "NetworkPath")
                    obs.append(
                        xval.Observation(
                            "lecmd",
                            (vol.index, str(e["inode"])),
                            {
                                "target": target or None,
                                "modified": ezcsv.get_time(row, "TargetModified"),
                            },
                            f"{cref}#L{line_no}",
                        )
                    )
        else:
            missing["lecmd"] = f"LECmd exited {cp.returncode}"
    else:
        missing["lecmd"] = "not installed (EZ Tools are staged on ASSETS)"
    results = xval.join(
        obs,
        fields=("target", "modified"),
        equal={"target": xval.same_text_ci, "modified": xval.same_second},
    )
    for row, key in keyed:
        if key in results:
            row["xval_status"] = results[key].status
    rows.append(
        {
            **xval.summary_row(
                "shortcut (LNK) files",
                results,
                volume_index=vol.index,
                parsers_run=ran,
                parsers_missing=missing,
            ),
            "inode_ref": f"v{vol.index}:lnk",
        }
    )
    rows.extend(
        xval.disagreement_rows(
            "shortcut (LNK)", results, describe=lambda r: {"inode_ref": f"v{vol.index}:{r.key[1]}"}
        )
    )
    return rows


def jumplist_rows(ctx: ModuleContext, vol: Volume, counts: Counter[str]) -> list[dict[str, Any]]:
    lines = list(iter_files(ctx.run_dir, extensions=JUMPLIST_EXT, volume_index=vol.index))
    lines = [e for e in lines if ":" not in str(e.get("path", "")).rsplit("/", 1)[-1]]
    if not lines:
        return []
    counts["jumplists_found"] += len(lines)
    if not shutil.which("JLECmd"):
        return [
            _row(
                artifact_type="jumplist_not_parsed",
                message=(
                    f"Volume {vol.index}: {len(lines)} Jump List files found but not parsed: "
                    "JLECmd is not installed (EZ Tools are staged on ASSETS)."
                ),
                source_tool="forensic-analyze",
                tool_version=VERSION,
                parser="airlock.users",
                inode_ref=f"v{vol.index}:jumplists",
            )
        ]
    export_root = ctx.workdir / "export" / "jumplists" / f"v{vol.index}"
    by_dest: dict[str, dict[str, Any]] = {}
    for e in lines:
        name = extract.safe_component(str(e["path"]).rsplit("/", 1)[-1])
        try:
            dest = extract.export_file(
                ctx, vol, str(e["inode"]), export_root / str(e["inode"]), name=name
            )
        except (extract.ExtractError, ValueError):
            counts["jumplist_export_failed"] += 1
            continue
        by_dest[str(dest.resolve())] = e
    out_dir = ctx.workdir / f"jlecmd-v{vol.index}"
    extract.tool_dir(ctx, out_dir)
    cp = ctx.tool(["JLECmd", "-d", str(export_root), "--csv", str(out_dir), "--csvf", "jle.csv"])
    rows: list[dict[str, Any]] = []
    if cp.returncode != 0:
        return [
            _row(
                artifact_type="jumplist_not_parsed",
                message=f"Volume {vol.index}: JLECmd failed (exit {cp.returncode}).",
                source_tool="JLECmd",
                tool_version=ctx.tool_version("JLECmd"),
                parser="jlecmd",
                inode_ref=f"v{vol.index}:jumplists",
            )
        ]
    for csv_path in ezcsv.csv_files(out_dir):
        cref = extract.relative(ctx, csv_path)
        for line_no, row in ezcsv.read_rows(csv_path):
            src = ezcsv.get(row, "SourceFile")
            e = by_dest.get(str(Path(src).resolve())) if src else None
            if e is None:
                continue
            target = ezcsv.get(row, "LocalPath", "TargetIDAbsolutePath", "Path", "NetworkPath")
            when = ezcsv.get_time(row, "LastModified", "TargetModified")
            counts["jumplist_entries"] += 1
            rows.append(
                _row(
                    artifact_type="jumplist_entry",
                    message="Jump List entry: a target the application recorded as used.",
                    source_tool="JLECmd",
                    tool_version=ctx.tool_version("JLECmd"),
                    parser="jlecmd",
                    path=e["path"],
                    inode_ref=e.get("inode_ref"),
                    allocated=bool(e.get("allocated")),
                    datetime=when,
                    timestamp_desc="Last Used Time (Jump List)" if when else None,
                    tz_basis="utc" if when else None,
                    source_record=f"{cref}#L{line_no}",
                    text=f"target: {target}" if target else None,
                )
            )
    return rows


class Users(Module):
    name = "users"
    title = "Users and accounts"
    fs_types = frozenset({"ntfs"})
    order = 40
    description = "Owner account SIDs, shortcut (LNK) files, Jump Lists."

    def run(self, ctx: ModuleContext) -> ModuleResult:
        rows: list[dict[str, Any]] = []
        counts: Counter[str] = Counter()
        for vol in ctx.target.volumes_of("ntfs"):
            rows.extend(owner_rows(ctx, vol, counts))
            rows.extend(lnk_rows(ctx, vol, counts))
            rows.extend(jumplist_rows(ctx, vol, counts))
        ordered = sorted_rows(
            [{k: v for k, v in r.items() if v is not None} for r in rows],
            "inode_ref",
            "path",
            "artifact_type",
            "datetime",
        )
        for r in ordered:
            ctx.emit(r)
        return ModuleResult("ok", counts=dict(sorted(counts.items())))


MODULE = Users()
