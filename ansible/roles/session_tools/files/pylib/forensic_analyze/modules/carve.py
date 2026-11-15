"""Module ``carve`` (task 4C.15). Full preset only.

For each volume with a known filesystem:

1. ``blkls`` copies the unallocated clusters into ``modules/carve/export/unalloc-v<N>.blkls``
   (after checking the output drive has room: for NTFS the exact free space comes from
   ``$Bitmap``, otherwise the volume size is assumed).
2. PhotoRec carves images, video, audio, and documents from that copy into
   ``modules/carve/carved/v<N>/`` (``/cmd`` with the whole copy, paranoid mode, the file
   families below only).
3. bulk_extractor scans the same copy when it is installed (``modules/carve/bulk-v<N>/``);
   only the number of features per kind is reported, never their content.

Carved files are listed in ``modules/carve/carved.jsonl`` in the inventory index format
(``volume_index`` -1, ``inode`` "", ``carved_path`` relative to the run folder,
``source_volume``, ``offset_bytes`` in the unallocated copy) so the image, video, and audio
modules pick them up with ``inventory_index.iter_files(run_dir, include_carved=True)``. Both
``export/`` and ``carved/`` are removed by the end-of-run purge (4C.19).
"""

from __future__ import annotations

import re
import shutil
from collections import Counter
from pathlib import Path
from typing import Any

from airlock_common import hashing
from forensic_analyze import extract
from forensic_analyze.api import Module, ModuleContext, ModuleResult, Volume, sorted_rows
from forensic_analyze.inventory_index import carved_path, write_index

VERSION = "carve 1"
GIB = 1024**3
MARGIN = 1 * GIB
SKIP_FS = {"unknown", "", "swap", "bitlocker"}
# PhotoRec file families. Names checked against PhotoRec 7.1 (Ubuntu 24.04): "riff" covers AVI
# and WAV, "mov" covers MP4, M4A, 3GP and HEIF, "zip" covers the Office XML formats, "doc" the
# older OLE formats. Plain text is left out on purpose: it yields thousands of fragments.
FAMILIES: dict[str, tuple[str, ...]] = {
    "images": ("jpg", "png", "gif", "bmp", "tif"),
    "video": ("mov", "mkv", "riff", "asf", "mpg", "flv"),
    "audio": ("mp3", "ogg", "flac"),
    "documents": ("pdf", "doc", "zip"),
}
EXT_FAMILY = {
    **{e: "images" for e in ("jpg", "jpeg", "png", "gif", "bmp", "tif", "tiff", "webp", "heic")},
    **{
        e: "video"
        for e in (
            "mov",
            "mp4",
            "m4v",
            "3gp",
            "mkv",
            "webm",
            "avi",
            "wmv",
            "asf",
            "mpg",
            "mpeg",
            "flv",
        )
    },
    **{e: "audio" for e in ("mp3", "ogg", "flac", "wav", "m4a", "wma", "opus")},
    **{
        e: "documents"
        for e in ("pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "odt", "zip", "rtf", "txt")
    },
}
_PHOTOREC_NAME = re.compile(r"^[ft](\d+)(?:_[^.]*)?\.", re.IGNORECASE)


def photorec_cmd(families: dict[str, tuple[str, ...]] = FAMILIES) -> str:
    """The ``/cmd`` script: whole copy, paranoid, only the chosen file types, then search."""
    parts = [
        "partition_none",
        "options",
        "paranoid",
        "keep_corrupted_file_no",
        "fileopt",
        "everything",
        "disable",
    ]
    for exts in families.values():
        for ext in exts:
            parts += [ext, "enable"]
    parts.append("search")
    return ",".join(parts)


def free_bytes_ntfs(ctx: ModuleContext, vol: Volume) -> int | None:
    """Unallocated bytes from ``$Bitmap`` (one bit per cluster, 0 = free)."""
    try:
        path = extract.extract_system_file(ctx, vol, "$Bitmap")
    except extract.ExtractError:
        return None
    cs = extract.cluster_size(ctx, vol)
    clusters = vol.size_bytes // cs if vol.size_bytes else None
    data = path.read_bytes()
    used = sum(bin(b).count("1") for b in data)
    total = len(data) * 8 if clusters is None else min(clusters, len(data) * 8)
    return max(total - used, 0) * cs


def needed_bytes(ctx: ModuleContext, vol: Volume) -> int:
    if vol.fs_type == "ntfs":
        free = free_bytes_ntfs(ctx, vol)
        if free is not None:
            return free
    return vol.size_bytes


def _row(**kw: Any) -> dict[str, Any]:
    return {"category": "carve", "derivation": "observed", **kw}


def carve_volume(
    ctx: ModuleContext, vol: Volume, counts: Counter[str], index_lines: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    need = needed_bytes(ctx, vol)
    free = shutil.disk_usage(ctx.workdir).free
    if need + MARGIN > free:
        return [
            _row(
                artifact_type="carve_skipped",
                message=(
                    f"Volume {vol.index}: carving skipped. Copying its unallocated space needs "
                    f"about {need // 1024**2} MiB plus 1 GiB spare, and the output drive has "
                    f"{free // 1024**2} MiB free. Use a larger output drive."
                ),
                source_tool="forensic-analyze",
                tool_version=VERSION,
                parser="carve",
                inode_ref=f"v{vol.index}:unallocated",
            )
        ]
    export = ctx.workdir / "export"
    export.mkdir(parents=True, exist_ok=True)
    unalloc = export / f"unalloc-v{vol.index}.blkls"
    cp = ctx.tool(extract.tsk_argv("blkls", ctx, vol), stdout_path=unalloc)
    if cp.returncode != 0:
        raise extract.ExtractError(f"blkls exited {cp.returncode}: {extract._last_line(cp.stderr)}")
    size = unalloc.stat().st_size
    digest = hashing.sha256_file(unalloc)
    rows.append(
        _row(
            artifact_type="unallocated_copy",
            message=f"Volume {vol.index}: unallocated space copied for carving ({size} bytes).",
            source_tool="sleuthkit",
            tool_version=ctx.tool_version("blkls"),
            parser="tsk.blkls",
            inode_ref=f"v{vol.index}:unallocated",
            size_bytes=size,
            sha256=digest,
            source_record=f"{extract.relative(ctx, unalloc)}#all",
        )
    )
    counts["unallocated_bytes"] += size
    if size == 0:
        return rows
    if shutil.which("photorec"):
        rows.extend(_photorec(ctx, vol, unalloc, counts, index_lines))
    else:
        rows.append(_missing("photorec", vol, "PhotoRec (testdisk package) is not installed"))
    if shutil.which("bulk_extractor"):
        rows.extend(_bulk(ctx, vol, unalloc, counts))
    else:
        rows.append(_missing("bulk_extractor", vol, "bulk_extractor is not installed"))
    return rows


def _missing(tool: str, vol: Volume, why: str) -> dict[str, Any]:
    return _row(
        artifact_type="carve_tool_missing",
        message=f"Volume {vol.index}: {why}; that carving step did not run.",
        source_tool="forensic-analyze",
        tool_version=VERSION,
        parser=tool,
        inode_ref=f"v{vol.index}:unallocated",
    )


def _photorec(
    ctx: ModuleContext,
    vol: Volume,
    unalloc: Path,
    counts: Counter[str],
    index_lines: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    out = ctx.workdir / "carved" / f"v{vol.index}"
    if out.exists():
        shutil.rmtree(out)
    extract.tool_dir(ctx, out)
    cp = ctx.tool(
        ["photorec", "/log", "/d", str(out / "recup"), "/cmd", str(unalloc), photorec_cmd()]
    )
    rows: list[dict[str, Any]] = []
    if cp.returncode != 0:
        return [
            _row(
                artifact_type="carve_failed",
                message=f"Volume {vol.index}: PhotoRec failed (exit {cp.returncode}).",
                source_tool="photorec",
                tool_version=ctx.tool_version("photorec"),
                parser="photorec",
                text=extract._last_line(cp.stderr) or None,
            )
        ]
    version = ctx.tool_version("photorec")
    for f in sorted(p for p in out.rglob("*") if p.is_file()):
        if f.name in {"report.xml", "photorec.log"}:
            continue
        ext = f.suffix.lower().lstrip(".")
        family = EXT_FAMILY.get(ext, "other")
        m = _PHOTOREC_NAME.match(f.name)
        offset = int(m.group(1)) * 512 if m else None
        rel = extract.relative(ctx, f)
        hashes = hashing.hash_file(f, ("sha256", "md5"))
        line = {
            "volume_index": -1,
            "inode": "",
            "path": "/" + rel,
            "carved_path": rel,
            "size_bytes": f.stat().st_size,
            "allocated": False,
            "deleted": True,
            "mtime": None,
            "atime": None,
            "ctime": None,
            "crtime": None,
            "source_volume": vol.index,
            "offset_bytes": offset,
            "family": family,
            "sha256": hashes["sha256"],
        }
        index_lines.append(line)
        counts[f"carved_{family}"] += 1
        rows.append(
            _row(
                artifact_type="carved_file",
                message=(
                    f"File carved by PhotoRec from unallocated space of volume {vol.index} "
                    f"({family}). Carved files have no name, folder, or times."
                ),
                source_tool="photorec",
                tool_version=version,
                parser="photorec",
                path="/" + rel,
                filename=f.name,
                size_bytes=line["size_bytes"],
                sha256=hashes["sha256"],
                md5=hashes["md5"],
                allocated=False,
                inode_ref=f"v{vol.index}:carved",
                source_record=f"{rel}#offset={offset}" if offset is not None else f"{rel}#0",
            )
        )
    return rows


def _bulk(ctx: ModuleContext, vol: Volume, unalloc: Path, counts: Counter[str]) -> list[dict]:
    out = ctx.workdir / f"bulk-v{vol.index}"
    if out.exists():
        shutil.rmtree(out)
    cp = ctx.tool(["bulk_extractor", "-q", "-o", str(out), str(unalloc)])
    if cp.returncode != 0:
        return [
            _row(
                artifact_type="carve_failed",
                message=f"Volume {vol.index}: bulk_extractor failed (exit {cp.returncode}).",
                source_tool="bulk_extractor",
                tool_version=ctx.tool_version("bulk_extractor"),
                parser="bulk_extractor",
            )
        ]
    rows = []
    for feat in sorted(out.glob("*.txt")):
        if feat.name.endswith(("_histogram.txt", "_stopped.txt")) or feat.name == "report.txt":
            continue
        with open(feat, encoding="utf-8", errors="replace") as fh:
            n = sum(1 for ln in fh if ln.strip() and not ln.startswith("#"))
        if not n:
            continue
        kind = feat.stem
        counts[f"bulk_{kind}"] += n
        rows.append(
            _row(
                artifact_type="bulk_extractor_features",
                message=(
                    f"bulk_extractor found {n} '{kind}' features in unallocated space of volume "
                    f"{vol.index}. Their content is in the feature file, not in this report."
                ),
                source_tool="bulk_extractor",
                tool_version=ctx.tool_version("bulk_extractor"),
                parser="bulk_extractor",
                inode_ref=f"v{vol.index}:unallocated",
                source_record=f"{extract.relative(ctx, feat)}#all",
            )
        )
    return rows


class Carve(Module):
    name = "carve"
    title = "Carving unallocated space"
    fs_types = None
    order = 110
    description = "PhotoRec and bulk_extractor over unallocated space (Full preset)."

    def run(self, ctx: ModuleContext) -> ModuleResult:
        preset = str(ctx.options.get("preset", ""))
        if preset not in {"full", "custom"} and not ctx.options.get("full"):
            return ModuleResult("skipped", "carving runs only with the Full preset")
        rows: list[dict[str, Any]] = []
        counts: Counter[str] = Counter()
        index_lines: list[dict[str, Any]] = []
        for vol in ctx.target.volumes:
            if vol.fs_type in SKIP_FS or vol.bitlocker:
                continue
            try:
                rows.extend(carve_volume(ctx, vol, counts, index_lines))
            except extract.ExtractError as exc:
                rows.append(
                    _row(
                        artifact_type="carve_failed",
                        message=f"Volume {vol.index}: carving failed.",
                        source_tool="forensic-analyze",
                        tool_version=VERSION,
                        parser="carve",
                        text=str(exc),
                    )
                )
        write_index(carved_path(ctx.run_dir), index_lines)
        ordered = sorted_rows(
            [{k: v for k, v in r.items() if v is not None} for r in rows],
            "inode_ref",
            "path",
            "artifact_type",
        )
        for r in ordered:
            ctx.emit(r)
        return ModuleResult("ok", counts=dict(sorted(counts.items())))


MODULE = Carve()
