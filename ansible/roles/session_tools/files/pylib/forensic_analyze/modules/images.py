"""Module ``images`` (task 4C.8): export, exiftool metadata, thumbnail caches, screening,
and descriptions of cleared images.

* Every image the inventory lists (live, deleted, carved) is exported read-only, hashed, and
  read by ``exiftool -j -n -G`` in the sandbox. EXIF capture times become timeline rows (local
  time, offset unknown unless the file records one).
* Each image is screened (NudeNet + SigLIP, ``airlock_ai.screen``). Flagged or unscreened files
  are deleted from the export folder at once and never described (4B.17).
* Cleared images are described by the local model (``describe_image`` prompt).
* ``thumbcache_*.db`` and ``Thumbs.db`` files are counted with ``airlock_ai/thumbcount.py``
  (entries only; no thumbnail is extracted or shown), and the copy is deleted.

Nothing here displays an image. Rows carry metadata, counts, scores, and descriptions only.
"""

from __future__ import annotations

import json
import shutil
import sys
from collections import Counter
from pathlib import Path
from typing import Any

from airlock_ai import config as aicfg
from airlock_ai import thumbcount
from airlock_ai.describe import Describer, DescribeResult
from airlock_ai.screen import IMAGE_EXTENSIONS, screen_paths
from forensic_analyze import media
from forensic_analyze.api import ModuleContext
from forensic_analyze.inventory_index import iter_files

THUMB_NAMES = ("thumbs.db",)
THUMB_PREFIX = "thumbcache_"


def _first(meta: dict[str, Any], tag: str) -> Any:
    """The first value of ``tag`` in any exiftool group (File, PNG, EXIF, ...), sorted."""
    for key in sorted(meta):
        if key.rsplit(":", 1)[-1] == tag and meta[key] not in (None, ""):
            return meta[key]
    return None


class ImagesModule(media.MediaModule):
    name = "images"
    title = "Images"
    order = 60
    category = "images"
    kind = "image"
    extensions = IMAGE_EXTENSIONS
    max_bytes = 200 * 1024**2
    description = "Image metadata, thumbnail-cache counts, screening, and descriptions."

    def metadata(self, ctx: ModuleContext, item: media.MediaItem) -> None:
        media.need_path(item)
        stem = item.path.name
        out = ctx.workdir / "metadata" / f"{stem}.exiftool.json"
        data = media.run_json_tool(ctx, ["exiftool", "-j", "-n", "-G", str(item.path)], out)
        if isinstance(data, list) and data and isinstance(data[0], dict):
            item.meta = data[0]
            item.meta_record = f"modules/{ctx.module}/metadata/{stem}.exiftool.json#0"

    def metadata_rows(self, ctx: ModuleContext, item: media.MediaItem) -> list[dict[str, Any]]:
        if not item.meta:
            return []
        m = item.meta
        ftype = str(m.get("File:FileType") or "unknown type")
        w, h = _first(m, "ImageWidth"), _first(m, "ImageHeight")
        dims = f", {w}x{h}" if w and h else ""
        camera = " with camera fields" if m.get("EXIF:Make") or m.get("EXIF:Model") else ""
        gps = " with GPS position" if m.get("EXIF:GPSLatitude") is not None else ""
        rows = [
            media.metadata_row(
                ctx,
                item,
                self.category,
                self.kind,
                f"Image metadata: {ftype}{dims}{camera}{gps}.",
                "exiftool",
            )
        ]
        for key, offset, desc in (
            ("EXIF:DateTimeOriginal", "EXIF:OffsetTimeOriginal", "EXIF DateTimeOriginal"),
            ("EXIF:CreateDate", "EXIF:OffsetTimeDigitized", "EXIF CreateDate"),
        ):
            when = media.exif_datetime(m, key, offset)
            if when is None:
                continue
            rows.append(
                {
                    **media.metadata_row(
                        ctx,
                        item,
                        self.category,
                        self.kind,
                        f"Image capture time recorded in the file ({desc}).",
                        "exiftool",
                    ),
                    "artifact_type": "image_exif_time",
                    "datetime": when[0],
                    "timestamp_desc": desc,
                    "tz_basis": when[1],
                }
            )
        return rows

    def screen_batch(
        self, ctx: ModuleContext, items: list[media.MediaItem], thr: aicfg.Thresholds
    ) -> None:
        paths = [i.path for i in items if i.path is not None]
        known = {str(i.path.resolve()): i.sha256 for i in items if i.path is not None}
        results = screen_paths(
            [p.resolve() for p in paths],
            None,
            thr,
            run_tool=media.ctx_runner(ctx),
            workdir=ctx.workdir / "screen",
            known_sha256=known,
        )
        for item, res in zip([i for i in items if i.path is not None], results, strict=True):
            item.screen = res

    def describe(
        self, ctx: ModuleContext, item: media.MediaItem, d: Describer, counts: Counter[str]
    ) -> list[DescribeResult]:
        media.need_path(item)
        return [d.image(item.path, item.sha256)]

    def extra_pass(self, ctx: ModuleContext, counts: Counter[str]) -> None:
        caches = []
        for e in iter_files(ctx.run_dir, extensions=[".db"]):
            name = str(e.get("path", "")).rsplit("/", 1)[-1].lower()
            if name in THUMB_NAMES or name.startswith(THUMB_PREFIX):
                caches.append(media.MediaItem(e))
        caches.sort(key=lambda i: (int(i.entry.get("volume_index", 0)), str(i.entry["path"])))
        pending = ctx.workdir / "export" / ".pending" / "thumbs"
        script = Path(thumbcount.__file__).resolve()
        for item in caches:
            media.export_item(ctx, item, pending)
            if item.error or item.path is None:
                counts["thumbcache_errors"] += 1
                continue
            try:
                cp = ctx.tool(
                    [sys.executable, "-I", str(script), str(item.path)],
                    timeout=600,
                    extra_ro=[str(script.parent)],
                )
                info = (
                    json.loads(cp.stdout or "{}")
                    if cp.returncode == 0
                    else {"error": "counter failed"}
                )
            except (ValueError, OSError) as exc:
                info = {"error": str(exc)}
            finally:
                media.discard(item)  # counts only: the cache itself is never kept
            counts["thumbcache_files"] += 1
            n = int(info.get("entries", 0) or 0)
            counts["thumbcache_entries"] += n
            fmt = info.get("format", "unknown")
            msg = (
                f"Thumbnail cache ({fmt}): {n} entries, "
                f"{int(info.get('entries_with_data', 0) or 0)} with image data. "
                "Thumbnails were not extracted or shown."
            )
            if info.get("error"):
                msg = f"Thumbnail cache could not be counted: {info['error']}"
            ctx.emit(
                {
                    **media.base_row(item, self.category),
                    "artifact_type": "thumbnail_cache",
                    "message": msg,
                    "derivation": "observed",
                    "source_tool": "forensic-analyze",
                    "tool_version": "airlock thumbcount 1",
                    "parser": "airlock_ai.thumbcount",
                }
            )
        shutil.rmtree(pending, ignore_errors=True)


MODULE = ImagesModule()
