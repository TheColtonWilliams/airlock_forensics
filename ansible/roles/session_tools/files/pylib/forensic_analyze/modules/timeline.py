"""Module ``timeline`` (task 4C.14).

With Plaso installed: ``log2timeline`` over the whole target, then ``psort`` to CSV
(``modules/timeline/timeline.csv``, the ``dynamic`` output: datetime, timestamp_desc, source,
source_long, message, parser, display_name, tag). One ``plaso_event`` row per event.

Without Plaso: the timeline is built from file system times only, from The Sleuth Kit bodyfile
of each volume (the inventory's ``fls-v<N>.body`` when it exists, else a new ``fls -m``), run
through ``mactime`` (CSV kept as ``mactime-v<N>.csv``) or, when ``mactime`` is missing, read
directly. One ``fs_time`` row per file per time (M, A, C, B; ``$FILE_NAME`` times marked).
A ``timeline_source`` row always says which way the timeline was built and what it lacks.

Plaso's message text comes from evidence; it goes in ``text`` and is never treated as an
instruction.
"""

from __future__ import annotations

import csv
import re
import shutil
from collections import Counter
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from forensic_analyze import extract
from forensic_analyze.api import Module, ModuleContext, ModuleResult, Volume, sorted_rows
from forensic_analyze.parsers import bodyfile, filetime

VERSION = "timeline 1"
LETTERS = {
    "m": "Content Modification Time",
    "a": "Last Access Time",
    "c": "Metadata Modification Time",
    "b": "Creation Time",
}
SKIP_FS = {"unknown", "", "swap", "bitlocker"}
_PLASO_PREFIX = re.compile(r"^[A-Z0-9_]+:")


def plaso_binaries() -> tuple[str, str] | None:
    l2t = shutil.which("log2timeline.py") or shutil.which("log2timeline")
    ps = shutil.which("psort.py") or shutil.which("psort")
    if l2t and ps:
        return l2t, ps
    return None


def _display_path(name: str) -> str | None:
    text = _PLASO_PREFIX.sub("", name.strip()).replace("\\", "/")
    return text if text.startswith("/") else None


def plaso_rows(ctx: ModuleContext, l2t: str, psort: str) -> tuple[list[dict[str, Any]], str]:
    storage = ctx.workdir / "timeline.plaso"
    out_csv = ctx.workdir / "timeline.csv"
    storage.unlink(missing_ok=True)
    cp = ctx.tool(
        [
            l2t,
            "--quiet",
            "--status_view",
            "none",
            "--unattended",
            "--partitions",
            "all",
            "--volumes",
            "all",
            "--vss_stores",
            "none",
            "--storage_file",
            str(storage),
            str(ctx.target.path),
        ]
    )
    if cp.returncode != 0 or not storage.exists():
        raise extract.ExtractError(
            f"log2timeline exited {cp.returncode}: {extract._last_line(cp.stderr)}"
        )
    cp = ctx.tool(
        [
            psort,
            "--quiet",
            "--status_view",
            "none",
            "-o",
            "dynamic",
            "-w",
            str(out_csv),
            str(storage),
        ]
    )
    if cp.returncode != 0 or not out_csv.exists():
        raise extract.ExtractError(f"psort exited {cp.returncode}: {extract._last_line(cp.stderr)}")
    rel = extract.relative(ctx, out_csv)
    version = ctx.tool_version(Path(l2t).name)
    rows: list[dict[str, Any]] = []
    with open(out_csv, encoding="utf-8", errors="surrogateescape", newline="") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            when = filetime.normalise_iso(row.get("datetime") or "")
            desc = (row.get("timestamp_desc") or "").strip() or None
            source_long = (row.get("source_long") or row.get("source") or "event").strip()
            parser = (row.get("parser") or "unknown").strip() or "unknown"
            rows.append(
                {
                    "category": "timeline",
                    "artifact_type": "plaso_event",
                    "message": f"Plaso event: {desc or 'time'} ({source_long}).",
                    "derivation": "observed",
                    "source_tool": "plaso",
                    "tool_version": version,
                    "parser": f"plaso.{parser}",
                    "datetime": when,
                    "timestamp_desc": desc if when else None,
                    "tz_basis": "utc" if when else None,
                    "path": _display_path(row.get("display_name") or ""),
                    "text": (row.get("message") or "")[:4000] or None,
                    "source_record": f"{rel}#L{reader.line_num}",
                }
            )
    return rows, rel


def _desc(letter: str, file_name_attr: bool) -> str:
    base = LETTERS[letter]
    return f"{base} ($FILE_NAME)" if file_name_attr else base


def _inode_ref(vol: Volume, inode: str) -> str:
    m = re.match(r"^(\d+)", inode)
    return f"v{vol.index}:{m.group(1)}" if m else f"v{vol.index}:?"


def mactime_events(path: Path) -> Iterator[tuple[int, str, str, str, int | None, str]]:
    """``(line, iso, letters, meta, size, name)`` from ``mactime -d -y -z UTC`` output."""
    with open(path, encoding="utf-8", errors="surrogateescape", newline="") as fh:
        reader = csv.reader(fh)
        for row in reader:
            if len(row) < 8 or row[0] == "Date":
                continue
            when = filetime.normalise_iso(row[0])
            if not when:
                continue
            try:
                size = int(row[1])
            except ValueError:
                size = None
            yield reader.line_num, when, row[2], row[6], size, ",".join(row[7:])


def fs_time_rows(ctx: ModuleContext, vol: Volume, body: Path) -> tuple[list[dict], str]:
    rows: list[dict[str, Any]] = []
    tool = "mactime" if shutil.which("mactime") else ""
    if tool:
        out = ctx.workdir / f"mactime-v{vol.index}.csv"
        cp = ctx.tool(["mactime", "-b", str(body), "-d", "-y", "-z", "UTC"], stdout_path=out)
        if cp.returncode != 0:
            tool = ""
    if tool:
        rel = extract.relative(ctx, out)
        for line, when, letters, meta, size, raw in mactime_events(out):
            name, deleted, realloc, fn = bodyfile.split_name(raw)
            for letter in letters:
                if letter not in LETTERS:
                    continue
                rows.append(
                    _fs_row(
                        ctx,
                        vol,
                        when,
                        letter,
                        fn,
                        name,
                        meta,
                        size,
                        deleted and not realloc,
                        f"{rel}#L{line}",
                        "tsk.mactime",
                    )
                )
        return rows, "mactime"
    rel = extract.relative(ctx, body)
    for e in bodyfile.iter_file(body):
        for letter, secs in (("m", e.mtime), ("a", e.atime), ("c", e.ctime), ("b", e.crtime)):
            when = filetime.iso_from_unix(secs)
            if when:
                rows.append(
                    _fs_row(
                        ctx,
                        vol,
                        when,
                        letter,
                        e.file_name_attr,
                        e.name,
                        e.inode,
                        e.size,
                        not e.allocated,
                        f"{rel}#L{e.line_no}",
                        "tsk.bodyfile",
                    )
                )
    return rows, "bodyfile"


def _fs_row(  # noqa: PLR0917 - private row builder
    ctx: ModuleContext,
    vol: Volume,
    when: str,
    letter: str,
    fn: bool,
    name: str,
    meta: str,
    size: int | None,
    deleted: bool,
    ref: str,
    parser: str,
) -> dict[str, Any]:
    return {
        "category": "timeline",
        "artifact_type": "fs_time",
        "message": "File system time from The Sleuth Kit (Plaso is not installed).",
        "derivation": "observed",
        "source_tool": "sleuthkit",
        "tool_version": ctx.tool_version("fls"),
        "parser": parser,
        "datetime": when,
        "timestamp_desc": _desc(letter, fn),
        "tz_basis": "utc",
        "path": name,
        "filename": name.rsplit("/", 1)[-1] or "/",
        "inode_ref": _inode_ref(vol, meta),
        "allocated": not deleted,
        "size_bytes": size if size is not None and size >= 0 else None,
        "source_record": ref,
    }


def volume_body(ctx: ModuleContext, vol: Volume) -> Path:
    shared = ctx.run_dir / "modules" / "inventory" / f"fls-v{vol.index}.body"
    if vol.fs_type == "ntfs" and shared.is_file() and shared.stat().st_size > 0:
        return shared
    out = ctx.workdir / f"fls-v{vol.index}.body"
    cp = ctx.tool(extract.tsk_argv("fls", ctx, vol, "-r", "-p", "-m", "/"), stdout_path=out)
    if cp.returncode != 0:
        raise extract.ExtractError(f"fls exited {cp.returncode}: {extract._last_line(cp.stderr)}")
    return out


class Timeline(Module):
    name = "timeline"
    title = "Timeline"
    fs_types = None
    order = 100
    description = "Plaso super-timeline, or file system times when Plaso is not installed."

    def run(self, ctx: ModuleContext) -> ModuleResult:
        rows: list[dict[str, Any]] = []
        counts: Counter[str] = Counter()
        notes: list[str] = []
        how = ""
        bins = plaso_binaries()
        if bins:
            try:
                prows, rel = plaso_rows(ctx, *bins)
                rows.extend(prows)
                counts["plaso_events"] = len(prows)
                how = f"Timeline built with Plaso over the whole target ({rel})."
            except extract.ExtractError as exc:
                notes.append(f"Plaso failed: {exc}; file system times used instead")
                bins = None
        if not bins:
            used = set()
            for vol in ctx.target.volumes:
                if vol.fs_type in SKIP_FS or vol.bitlocker:
                    notes.append(f"volume {vol.index} ({vol.fs_type or 'unknown'}) skipped")
                    continue
                try:
                    body = volume_body(ctx, vol)
                    vrows, tool = fs_time_rows(ctx, vol, body)
                except extract.ExtractError as exc:
                    notes.append(f"volume {vol.index}: {exc}")
                    continue
                used.add(tool)
                rows.extend(vrows)
                counts["fs_times"] += len(vrows)
            how = (
                "Timeline built from file system times only (The Sleuth Kit "
                f"{' and '.join(sorted(used)) or 'bodyfile'}), because Plaso is not installed or "
                "failed. It has no event log, registry, or browser times."
            )
        rows.append(
            {
                "category": "timeline",
                "artifact_type": "timeline_source",
                "message": how,
                "derivation": "observed",
                "source_tool": "forensic-analyze",
                "tool_version": VERSION,
                "parser": "plaso" if bins else "sleuthkit",
                "text": "; ".join(notes) or None,
            }
        )
        ordered = sorted_rows(
            [{k: v for k, v in r.items() if v is not None} for r in rows],
            "datetime",
            "inode_ref",
            "path",
            "timestamp_desc",
        )
        for r in ordered:
            ctx.emit(r)
        return ModuleResult("ok", counts=dict(sorted(counts.items())))


MODULE = Timeline()
