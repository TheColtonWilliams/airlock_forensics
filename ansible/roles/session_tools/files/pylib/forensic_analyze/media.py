"""Shared machinery for the media modules: images, video, audio, documents (4C.8 to 4C.11).

Flow for each file the inventory lists with a matching extension (live and deleted; carved files
go through the same flow from the ``carve`` module, see below):

1. stop if ``forensic-escalate`` has marked the run (``<run>/ESCALATED``), before every batch
   and every export;
2. export it read-only with ``extract.export_file`` (icat) into ``export/.pending/``, hash it
   (SHA-256, MD5), and read its metadata (exiftool, mediainfo, ffprobe) in the sandbox;
3. images and videos: screen it (``airlock_ai.screen`` / ``airlock_ai.video``). A cleared
   file moves to ``export/``; a flagged file, or one that could not be screened, is deleted at
   once: it is never kept, copied on, shown, or sent to a model (task 4B.17). Audio and
   documents are not screened, so their modules check the content type first
   (:meth:`MediaModule.content_route`: ffprobe streams, exiftool MIME type, magic bytes). A
   file whose content is a picture or video despite its extension goes through the same
   screening; one whose type cannot be confirmed is deleted with a "not screened (content
   type mismatch)" row;
4. describe what was kept with the local model (``airlock_ai.describe``), if a tier is staged;
5. emit rows: observed metadata rows, AI-generated screening rows (score, label, threshold,
   sensitive_flag, model and prompt SHA-256), AI-generated description rows. Rows never carry
   image content: counts, scores, metadata, and descriptions of cleared files only.

Exports live under ``modules/<name>/export/`` so ``cleanup.purge_exports`` and
``forensic-escalate`` find them.

Carved files (``modules/carve/carved.jsonl``, ``volume_index`` -1). The ``carve`` module runs
last (order 110), after the media modules, so it calls :func:`process_carved` on its own
output: each media module runs the flow above on the carved files of its types, in place (they
are never copied). A carved image or video that is flagged, could not be screened, is too large
to screen, or has a type the screening step does not read is deleted from the carve folder at
once and its index line is marked ``removed``: no copy is kept anywhere in or outside the run
and nothing is displayed. A ``carved_media_removed`` row records it with the SHA-256 and MD5
(plan 4B.17). The main pass of each media module leaves carved lines alone, so a resumed run
does not screen them twice.
"""

from __future__ import annotations

import contextlib
import datetime as dt
import json
import os
import re
import shutil
import subprocess
from collections import Counter
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from airlock_ai import AI_LABEL, escalate, llm
from airlock_ai import config as aicfg
from airlock_ai import video as aivideo
from airlock_ai.describe import Describer, DescribeResult
from airlock_ai.screen import ScreenError, ScreenResult, screen_paths
from airlock_common import hashing, proc
from forensic_analyze import extract
from forensic_analyze.api import Module, ModuleContext, ModuleResult, Volume
from forensic_analyze.inventory_index import available, carved_path, iter_files, write_index

CARVED_VERSION = "media carved 1"
ESCALATED_REASON = "stopped: forensic-escalate was run for this run; exports are frozen"
BATCH = 64
_EXT_RE = re.compile(r"^\.[a-z0-9]{1,10}$")
_EXIF_DATE = re.compile(r"^(\d{4}):(\d{2}):(\d{2}) (\d{2}):(\d{2}):(\d{2})(\.\d+)?")


class Escalated(RuntimeError):
    """The operator ran forensic-escalate; the module must stop now."""


def check_escalated(ctx: ModuleContext) -> None:
    if escalate.is_escalated(ctx.run_dir):
        raise Escalated(ESCALATED_REASON)


def ctx_runner(ctx: ModuleContext, *, gpu: bool = False) -> Any:
    """``ctx.tool`` as an ``airlock_ai`` RunTool; ``gpu`` asks for render nodes when supported."""
    from airlock_ai.tools import gpu_render_nodes  # noqa: PLC0415

    def run(argv: Sequence[str], **kw: Any) -> subprocess.CompletedProcess[str]:
        nodes = gpu_render_nodes() if gpu else []
        if nodes:
            return ctx.tool(argv, devices=nodes, **kw)
        return ctx.tool(argv, **kw)

    return run


@dataclass
class MediaItem:
    entry: dict[str, Any]
    carved: bool = False
    path: Path | None = None  # the exported (or carved) copy while it exists
    sha256: str = ""
    md5: str = ""
    error: str = ""
    kept: bool = False
    removed: str = ""  # carved only: why the carved file was deleted (4B.17)
    screen_failure: str = ""  # carved only: why the screening step could not run
    screen: ScreenResult | None = None
    screen_note: str = ""  # extra text for the screening row (frames, covered span)
    # Content-type check of an unscreened module: "" (content matches), "image" or "video"
    # (screen it as that), or "unknown" (not screened: deleted). ``route_reason`` says why.
    route: str = ""
    route_reason: str = ""
    meta: dict[str, Any] = field(default_factory=dict)
    meta_record: str = ""
    extra_rows: list[dict[str, Any]] = field(default_factory=list)

    @property
    def ref(self) -> str:
        e = self.entry
        if self.carved:
            return f"carved:{e.get('carved_path', '')}"
        return f"v{e.get('volume_index')}:{e.get('inode')}"

    @property
    def ext(self) -> str:
        name = str(self.entry.get("path", "")).rsplit("/", 1)[-1]
        ext = os.path.splitext(name)[1].lower()
        return ext if _EXT_RE.match(ext) else ""


def need_path(item: MediaItem) -> Path:
    """The item's exported copy; a hook called without one is a programming error."""
    if item.path is None:
        raise RuntimeError("no exported copy for this item")
    return item.path


def base_row(item: MediaItem, category: str) -> dict[str, Any]:
    e = item.entry
    row: dict[str, Any] = {
        "category": category,
        "path": e.get("path") or None,
        "filename": str(e.get("path", "")).rsplit("/", 1)[-1] or None,
        "inode_ref": e.get("inode_ref") or (None if item.carved else item.ref),
        "size_bytes": e.get("size_bytes"),
        "allocated": e.get("allocated"),
        "sha256": item.sha256 or None,
        "md5": item.md5 or None,
    }
    if e.get("path_b64"):
        row["path_b64"] = e["path_b64"]
    return row


def _safe_name(item: MediaItem) -> str:
    if item.carved:
        return Path(str(item.entry.get("carved_path", "carved"))).name
    return f"v{item.entry.get('volume_index')}_{item.entry.get('inode')}{item.ext}"


def _volume(ctx: ModuleContext, index: int) -> Volume | None:
    return next((v for v in ctx.target.volumes if v.index == index), None)


def select(
    ctx: ModuleContext,
    extensions: Iterable[str],
    max_bytes: int,
    counts: Counter[str],
    *,
    carved: bool = False,
    oversize: list[MediaItem] | None = None,
) -> list[MediaItem]:
    """Index lines with a matching extension: live and deleted files, or (``carved=True``)
    only the carve module's files that are still there. Lines over ``max_bytes`` are counted
    and, when ``oversize`` is given, collected there."""
    items: list[MediaItem] = []
    for e in iter_files(ctx.run_dir, extensions=sorted(extensions), include_carved=carved):
        if (int(e.get("volume_index", 0)) < 0) != carved or e.get("removed"):
            continue
        size = int(e.get("size_bytes") or 0)
        if size <= 0:
            counts["empty"] += 1
            continue
        if size > max_bytes:
            counts["too_large"] += 1
            if oversize is not None:
                oversize.append(MediaItem(e, carved=carved))
            continue
        items.append(MediaItem(e, carved=carved))
    items.sort(
        key=lambda i: (
            int(i.entry.get("volume_index", 0)),
            str(i.entry.get("path")),
            str(i.entry.get("inode")),
            str(i.entry.get("carved_path", "")),
        )
    )
    return items


def export_item(ctx: ModuleContext, item: MediaItem, dest: Path) -> None:
    """Copy the file out read-only (icat) and hash it. Carved files are used in place."""
    check_escalated(ctx)
    try:
        if item.carved:
            p = _carved_file(ctx, item)
            if p is None or not p.is_file():
                raise extract.ExtractError("carved file not found in the carve folder of this run")
            item.path = p
        else:
            vol = _volume(ctx, int(item.entry.get("volume_index", 0)))
            if vol is None:
                raise extract.ExtractError("volume not found on the target")
            item.path = extract.export_file(
                ctx, vol, str(item.entry.get("inode")), dest, name=_safe_name(item)
            )
        h = hashing.hash_file(item.path)
        item.sha256, item.md5 = h["sha256"], h["md5"]
    except (extract.ExtractError, ValueError, OSError, proc.ToolError) as exc:
        item.error = str(exc)
        if item.path is not None and not item.carved:
            item.path.unlink(missing_ok=True)
        item.path = None


def keep(item: MediaItem, export_dir: Path) -> None:
    """Move a cleared pending copy to ``export/`` (carved files stay where carve put them)."""
    if item.path is None:
        return
    if not item.carved:
        export_dir.mkdir(parents=True, exist_ok=True)
        dest = export_dir / item.path.name
        item.path.replace(dest)
        item.path = dest
    item.kept = True


def discard(item: MediaItem) -> None:
    """Delete a pending copy now: flagged or unscreened content is never kept (4B.17).

    A carved file is not a copy made here; :func:`remove_carved` deletes it."""
    if item.path is not None and not item.carved:
        item.path.unlink(missing_ok=True)
    item.path = None
    item.kept = False


def _carved_file(ctx: ModuleContext, item: MediaItem) -> Path | None:
    """The carved file inside ``modules/carve/carved/`` of this run, or None."""
    rel = str(item.entry.get("carved_path") or "")
    if not rel:
        return None
    root = (ctx.run_dir / "modules" / "carve" / "carved").resolve()
    p = (ctx.run_dir / rel).resolve()
    return p if root in p.parents else None


def remove_carved(ctx: ModuleContext, item: MediaItem, why: str) -> None:
    """Delete a flagged or unscreened carved file where carve left it (4B.17).

    Nothing is copied first: the file is unlinked in place, so no copy is kept anywhere. The
    hashes stay on the item for the ``carved_media_removed`` row; they are computed here when
    the file was never exported (too large, unsupported type).
    """
    p = item.path if item.path is not None else _carved_file(ctx, item)
    if p is not None and p.is_file():
        if not item.sha256:
            with contextlib.suppress(OSError, ValueError):
                h = hashing.hash_file(p)
                item.sha256, item.md5 = h["sha256"], h["md5"]
        p.unlink()
    item.path = None
    item.kept = False
    item.removed = why


REMOVED_WHY = {
    "flagged": "was flagged by the screening models",
    "not_screened": "could not be screened",
    "too_large": "is too large to screen",
    "unsupported": "is of a type the screening step cannot read",
}


def carved_removed_row(item: MediaItem, category: str, kind: str) -> dict[str, Any]:
    """The record of a deleted carved file: where it was, its hashes, and why it went."""
    why = REMOVED_WHY.get(item.removed, item.removed or "was not cleared")
    row = {
        **base_row(item, category),
        "artifact_type": "carved_media_removed",
        "message": (
            f"Carved {kind} file {why}; it was deleted from the carve folder at once. No copy "
            "is kept anywhere and it was never shown. Only its hashes are recorded."
            + (" Do not re-carve it to look at it." if item.removed == "flagged" else "")
        ),
        "derivation": "observed",
        "source_tool": "forensic-analyze",
        "tool_version": CARVED_VERSION,
        "parser": "forensic_analyze.media",
        "label": item.removed or "not_cleared",
    }
    if item.screen_failure:
        row["text"] = item.screen_failure
    if item.removed == "flagged":
        row["sensitive_flag"] = True
    return row


def run_json_tool(
    ctx: ModuleContext, argv: list[str], out: Path, timeout: float = 600
) -> dict[str, Any] | list[Any] | None:
    """Run a metadata tool that prints JSON; keep its raw output at ``out``."""
    out.parent.mkdir(parents=True, exist_ok=True)
    try:
        cp = ctx.tool(argv, timeout=timeout, stdout_path=out)
    except proc.ToolError:
        return None
    if cp.returncode != 0:
        out.unlink(missing_ok=True)
        return None
    try:
        return json.loads(out.read_text(encoding="utf-8", errors="replace") or "null")
    except ValueError:
        return None


def exif_datetime(meta: dict[str, Any], key: str, offset_key: str) -> tuple[str, str] | None:
    """(ISO 8601 with Z, tz_basis) for an EXIF date; local time unless an offset is recorded."""
    raw = str(meta.get(key) or "")
    m = _EXIF_DATE.match(raw)
    if not m:
        return None
    y, mo, d, h, mi, s = (int(g) for g in m.groups()[:6])
    try:
        stamp = dt.datetime(y, mo, d, h, mi, s)
    except ValueError:
        return None
    off = str(meta.get(offset_key) or "")
    om = re.fullmatch(r"([+-])(\d{2}):(\d{2})", off)
    if om:
        sign = 1 if om.group(1) == "+" else -1
        delta = dt.timedelta(hours=int(om.group(2)), minutes=int(om.group(3)))
        utc = stamp - sign * delta
        return utc.strftime("%Y-%m-%dT%H:%M:%SZ"), "local_with_offset"
    return stamp.strftime("%Y-%m-%dT%H:%M:%SZ"), "local_unknown_offset"


# ---------------------------------------------------------------------------------------------
# AI rows
# ---------------------------------------------------------------------------------------------


def _join(*parts: str) -> str:
    return "; ".join(p for p in parts if p)


def screening_rows(
    item: MediaItem, res: ScreenResult, category: str, thr: aicfg.Thresholds, *, extra: str = ""
) -> list[dict[str, Any]]:
    """Two AI-generated rows: the nudity detector and the zero-shot labels."""
    base = base_row(item, category)
    if res.verdict == "error":
        if item.route:
            why = f"content type mismatch: {item.route_reason}"
        elif "not fully screened" in res.error:
            why = "not every frame or page could be screened"
        else:
            why = "the classifiers could not score it"
        return [
            {
                **base,
                "artifact_type": "screen_error",
                "message": f"Not screened ({why}); not kept, not described.",
                "derivation": "observed",
                "source_tool": "evidence-screen",
                "tool_version": res.backend or "unknown",
                "parser": "airlock_ai.screen",
                "text": _join(res.error or "; ".join(res.reasons), extra)[:500] or None,
            }
        ]
    if res.flagged:
        tail = f"flagged ({res.category}); not kept, not described. Do not open it."
    else:
        tail = "not flagged by these models at these thresholds."
    scores = "; ".join(f"{k}={v:.4f}" for k, v in sorted(res.label_scores.items()))
    common = {
        **base,
        "derivation": "ai_generated",
        "parser": "airlock_ai.screen",
        "prompt_sha256": res.label_prompts_sha256,
        "sensitive_flag": res.flagged,
    }
    nud = res.nudity_score if res.nudity_score is not None else 0.0
    top_label, top_score = res.top_label()
    rows = [
        {
            **common,
            "artifact_type": "screen_nudity",
            "message": f"{AI_LABEL} screening (nudity detector): {tail}",
            "source_tool": "NudeNet",
            "tool_version": res.model_ids.get("nudenet", "unknown"),
            "model_id": res.model_ids.get("nudenet", "unknown"),
            "model_sha256": res.model_sha256.get("nudenet"),
            "score": round(nud, 6),
            "label": "nudity (detector)",
            "threshold": thr.nudity,
            "sensitive_flag": nud >= thr.nudity,
        },
        {
            **common,
            "artifact_type": "screen_labels",
            "message": f"{AI_LABEL} screening (zero-shot labels): {tail}",
            "source_tool": "SigLIP",
            "tool_version": res.model_ids.get("siglip", "unknown"),
            "model_id": res.model_ids.get("siglip", "unknown"),
            "model_sha256": res.model_sha256.get("siglip"),
            "score": round(top_score, 6),
            "label": top_label or "neutral",
            "threshold": thr.labels.get(top_label, 1.0) if top_label else 1.0,
            "sensitive_flag": any(
                res.label_scores.get(label, 0.0) >= limit for label, limit in thr.labels.items()
            ),
            "text": "; ".join(x for x in (scores, extra) if x) or None,
        },
    ]
    for r in rows:
        if not r.get("model_sha256") or len(str(r["model_sha256"])) != 64:
            r["model_sha256"] = "0" * 64  # unknown model hash: marked, never omitted
            r["message"] += " Model hash unknown."
    return rows


def description_row(item: MediaItem, res: DescribeResult, category: str) -> dict[str, Any]:
    base = base_row(item, category)
    if res.status in {"described", "model_declined"} and len(res.model_sha256) == 64:
        declined = res.status == "model_declined"
        what = res.kind.replace("_", " ")
        return {
            **base,
            "artifact_type": f"ai_{res.kind}" if not declined else "model_declined",
            "message": (
                f"{AI_LABEL} {what} (triage, not evidence)"
                if not declined
                else f"{AI_LABEL}: the model declined or gave no answer ({what}); "
                "the file is listed, not dropped"
            ),
            "derivation": "ai_generated",
            "source_tool": "llama.cpp" if res.prompt_id != "whisper_settings" else "faster-whisper",
            "tool_version": res.tier or "unknown",
            "parser": f"airlock_ai.{res.prompt_id}",
            "model_id": res.model_id or "unknown",
            "model_sha256": res.model_sha256,
            "prompt_sha256": res.prompt_sha256,
            "label": res.status,
            "text": res.description or res.detail or None,
        }
    return {
        **base,
        "artifact_type": "ai_not_described",
        "message": f"Not described: {res.detail or res.status}",
        "derivation": "observed",
        "source_tool": "evidence-describe",
        "tool_version": res.tier or "none",
        "parser": "airlock_ai.describe",
        "label": res.status,
    }


class DescribeSession:
    """Starts the local model server once per module, only when there is something to send."""

    def __init__(self, ctx: ModuleContext) -> None:
        self.ctx = ctx
        self.describer: Describer | None = None
        self.reason = ""
        self._server: llm.LlamaServer | None = None
        self._tried = False
        self._logged: set[tuple[str, str]] = set()

    def get(self) -> Describer | None:
        if self._tried:
            return self.describer
        self._tried = True
        if not self.ctx.options.get("ai_describe", True):
            self.reason = "descriptions are turned off for this run"
            return None
        try:
            client = llm.LlamaClient()
            self._server = llm.LlamaServer(client)
            live = self._server.__enter__()
            self.describer = Describer(live)
        except (llm.LlmError, aicfg.ConfigError, proc.ToolError, OSError) as exc:
            self.reason = f"the local model is not available ({exc})"
            self.describer = None
            self.close()
        return self.describer

    def used(self, res: DescribeResult) -> None:
        key = (res.model_sha256, res.prompt_sha256)
        if res.model_sha256 and key not in self._logged:
            self._logged.add(key)
            self.ctx.log(
                "model_used",
                model_id=res.model_id,
                model_sha256=res.model_sha256,
                prompt_id=res.prompt_id,
                prompt_sha256=res.prompt_sha256,
                tier=res.tier,
                seed=res.seed,
            )

    def close(self) -> None:
        if self._server is not None:
            with contextlib.suppress(Exception):
                self._server.__exit__(None, None, None)
            self._server = None


# ---------------------------------------------------------------------------------------------
# Module template
# ---------------------------------------------------------------------------------------------


@dataclass
class CarvedTally:
    """Carved paths (relative to the run folder) cleared by a screening module, and removed."""

    cleared: set[str] = field(default_factory=set)
    removed: dict[str, str] = field(default_factory=dict)


# Carved families the screening step must clear before a carved file may stay (carve.EXT_FAMILY).
SCREENED_FAMILIES: dict[str, tuple[str, str]] = {
    "images": ("images", "image"),
    "video": ("video", "video"),
}


def process_carved(ctx: ModuleContext, modules: Sequence[MediaModule]) -> dict[str, int]:
    """Run each media module over the carve module's files (call it with carve's context).

    Afterwards every carved image or video that no screening module cleared (a type the
    screening step does not read, an empty file) is deleted too, and ``carved.jsonl`` is
    rewritten with ``removed`` set on each deleted file's line. Fails closed: a carved picture
    stays only when the classifiers cleared it. Raises :class:`Escalated` when the run was
    escalated (carved files are then left as they are: frozen).
    """
    tally = CarvedTally()
    counts: Counter[str] = Counter()
    for mod in modules:
        for k, v in mod.run_carved(ctx, tally).items():
            counts[f"{mod.name}_{k}"] += v
    leftovers = []
    for e in iter_files(ctx.run_dir, include_carved=True):
        rel = str(e.get("carved_path", ""))
        if int(e.get("volume_index", 0)) >= 0 or e.get("removed") or not rel:
            continue
        family = str(e.get("family", ""))
        if family in SCREENED_FAMILIES and rel not in tally.cleared and rel not in tally.removed:
            leftovers.append(MediaItem(e, carved=True))
    for item in sorted(leftovers, key=lambda i: str(i.entry.get("carved_path"))):
        check_escalated(ctx)
        category, kind = SCREENED_FAMILIES[str(item.entry.get("family"))]
        remove_carved(ctx, item, "unsupported")
        tally.removed[str(item.entry.get("carved_path"))] = "unsupported"
        counts["carved_removed_unsupported"] += 1
        ctx.emit(carved_removed_row(item, category, kind))
    if tally.removed:
        mark_removed(ctx.run_dir, tally.removed)
    counts["carved_removed"] = len(tally.removed)
    return _plain(counts)


def mark_removed(run_dir: Path, removed: dict[str, str]) -> None:
    """Rewrite ``carved.jsonl`` with ``removed: <why>`` on the lines of deleted carved files."""
    lines = []
    for e in iter_files(run_dir, include_carved=True):
        if int(e.get("volume_index", 0)) >= 0:
            continue
        why = removed.get(str(e.get("carved_path", "")))
        lines.append({**e, "removed": why} if why else e)
    write_index(carved_path(run_dir), lines)


class MediaModule(Module):
    """Template for the four media modules; subclasses fill in the hooks."""

    category = ""
    kind = ""
    extensions: frozenset[str] = frozenset()
    max_bytes = 1024**3
    screened = True

    # -- hooks ---------------------------------------------------------------------------------

    def metadata(self, ctx: ModuleContext, item: MediaItem) -> None:
        """Fill ``item.meta``/``item.meta_record``; emit nothing yet."""

    def metadata_rows(self, ctx: ModuleContext, item: MediaItem) -> list[dict[str, Any]]:
        return []

    def screen_batch(
        self, ctx: ModuleContext, items: list[MediaItem], thr: aicfg.Thresholds
    ) -> None:
        """Set ``item.screen`` for each item."""

    def describe(
        self, ctx: ModuleContext, item: MediaItem, d: Describer, counts: Counter[str]
    ) -> list[DescribeResult]:
        return []

    def kept_extras(
        self, ctx: ModuleContext, item: MediaItem, counts: Counter[str]
    ) -> list[dict[str, Any] | DescribeResult]:
        """Rows for a kept file that need no model server (extracted text, transcripts)."""
        return []

    def screen_extra(self, item: MediaItem) -> str:
        """Extra text for the screening row (video: frames screened, covered span, flagged
        timestamps; a routed file: why it was screened)."""
        parts = [item.screen_note]
        if item.route:
            parts.insert(0, f"content type mismatch: {item.route_reason}; screened as {item.route}")
        return "; ".join(x for x in parts if x)

    def content_route(self, ctx: ModuleContext, item: MediaItem) -> tuple[str, str]:
        """Unscreened modules: ``(route, reason)`` from the file's real content type (see
        :class:`MediaItem`). ``("", "")`` keeps the file unscreened, as its extension says."""
        return "", ""

    def extra_pass(self, ctx: ModuleContext, counts: Counter[str]) -> None:
        """Anything after the main pass (thumbnail caches)."""

    # -- template ------------------------------------------------------------------------------

    def run(self, ctx: ModuleContext) -> ModuleResult:
        counts: Counter[str] = Counter()
        try:
            check_escalated(ctx)
        except Escalated as exc:
            return ModuleResult("failed", str(exc))
        if not available(ctx.run_dir):
            return ModuleResult("skipped", "the inventory module has not listed any files")
        items = select(ctx, self.extensions, self.max_bytes, counts)
        try:
            self._process(ctx, items, counts, extra_pass=True)
        except Escalated as exc:
            return ModuleResult("failed", str(exc), _plain(counts))
        return ModuleResult("ok", "", _plain(counts))

    def run_carved(self, ctx: ModuleContext, tally: CarvedTally | None = None) -> dict[str, int]:
        """The same flow over the carve module's files of this module's types, in place.

        Called by ``carve`` with its own context (rows go to the carve module's part file).
        Flagged, unscreened, and too-large carved files of a screened type are deleted
        (:func:`remove_carved`). Raises :class:`Escalated` when the run was escalated.
        """
        counts: Counter[str] = Counter()
        check_escalated(ctx)
        oversize: list[MediaItem] = []
        items = select(ctx, self.extensions, self.max_bytes, counts, carved=True, oversize=oversize)
        if self.screened:
            for item in oversize:
                check_escalated(ctx)
                remove_carved(ctx, item, "too_large")
                counts["carved_removed"] += 1
                ctx.emit(carved_removed_row(item, self.category, self.kind))
        self._process(ctx, items, counts, extra_pass=False)
        if tally is not None:
            for item in (*oversize, *items):
                rel = str(item.entry.get("carved_path", ""))
                if item.removed:
                    tally.removed[rel] = item.removed
                elif item.kept and self.screened:
                    tally.cleared.add(rel)
        return _plain(counts)

    def _process(
        self, ctx: ModuleContext, items: list[MediaItem], counts: Counter[str], *, extra_pass: bool
    ) -> None:
        thr = aicfg.load_thresholds()
        counts["files"] += len(items)
        export_dir = ctx.workdir / "export"
        pending = export_dir / ".pending"
        session = DescribeSession(ctx)
        try:
            for start in range(0, len(items), BATCH):
                self._batch(
                    ctx, items[start : start + BATCH], thr, export_dir, pending, session, counts
                )
            if extra_pass:
                self.extra_pass(ctx, counts)
        except Escalated:
            for it in items:
                if it.path is not None and not it.kept:
                    discard(it)  # pending copies only; carved files stay frozen as they are
            raise
        finally:
            session.close()
            shutil.rmtree(pending, ignore_errors=True)
        if session.reason and counts["describe_candidates"]:
            ctx.emit(
                {
                    "category": self.category,
                    "artifact_type": "ai_status",
                    "message": f"Descriptions skipped for {counts['describe_candidates']} files: "
                    f"{session.reason}.",
                    "derivation": "observed",
                    "source_tool": "evidence-describe",
                    "tool_version": "none",
                    "parser": "airlock_ai.describe",
                }
            )

    def _screen(self, ctx: ModuleContext, live: list[MediaItem], thr: aicfg.Thresholds) -> None:
        try:
            self.screen_batch(ctx, live, thr)
        except Escalated:
            raise
        except Exception as exc:
            # The main pass fails the module (nothing was kept). Carved files already sit in
            # the run folder, so they are treated as unscreened and removed instead.
            if not all(i.carved for i in live):
                raise
            for i in live:
                i.screen = None
                i.screen_failure = f"{type(exc).__name__}: {exc}"[:300]

    def _batch(  # noqa: PLR0917
        self,
        ctx: ModuleContext,
        batch: list[MediaItem],
        thr: aicfg.Thresholds,
        export_dir: Path,
        pending: Path,
        session: DescribeSession,
        counts: Counter[str],
    ) -> None:
        check_escalated(ctx)
        for item in batch:
            export_item(ctx, item, pending)
            if item.error:
                counts["export_errors"] += 1
                if item.carved and self.screened:
                    remove_carved(ctx, item, "not_screened")  # unread is not cleared
                    counts["carved_removed"] += 1
                continue
            counts["exported"] += 1
            self.metadata(ctx, item)
            if not self.screened:
                item.route, item.route_reason = self.content_route(ctx, item)
        live = [i for i in batch if not i.error]
        if self.screened and live:
            self._screen(ctx, live, thr)
        routed = [i for i in live if i.route]
        if routed:
            counts["content_mismatch"] += len(routed)
            screen_routed(ctx, routed, thr)
        for item in live:
            check_escalated(ctx)
            res = item.screen
            must_clear = self.screened or bool(item.route)
            if not must_clear or (res is not None and res.cleared):
                keep(item, export_dir)
                counts["cleared" if must_clear else "kept"] += 1
            else:
                why = "flagged" if res is not None and res.flagged else "not_screened"
                if item.carved:
                    remove_carved(ctx, item, why)
                    counts["carved_removed"] += 1
                else:
                    discard(item)
                counts[why] += 1
        for item in batch:
            self._emit_item(ctx, item, thr, session, counts)

    def _emit_error(self, ctx: ModuleContext, item: MediaItem) -> None:
        ctx.emit(
            {
                **base_row(item, self.category),
                "artifact_type": f"{self.kind}_export_error",
                "message": f"Could not export this {self.kind} file: {item.error}"[:300],
                "derivation": "observed",
                "source_tool": "sleuthkit",
                "tool_version": ctx.tool_version("icat"),
                "parser": "icat",
            }
        )
        if item.removed:
            ctx.emit(carved_removed_row(item, self.category, self.kind))

    def _emit_item(
        self,
        ctx: ModuleContext,
        item: MediaItem,
        thr: aicfg.Thresholds,
        session: DescribeSession,
        counts: Counter[str],
    ) -> None:
        if item.error:
            self._emit_error(ctx, item)
            return
        for row in self.metadata_rows(ctx, item):
            ctx.emit(row)
        if item.screen is not None:
            extra = self.screen_extra(item)
            for row in screening_rows(item, item.screen, self.category, thr, extra=extra):
                ctx.emit(row)
        for row in item.extra_rows:
            ctx.emit(row)
        if item.removed:
            ctx.emit(carved_removed_row(item, self.category, self.kind))
        if not item.kept:
            return
        check_escalated(ctx)
        for out in self.kept_extras(ctx, item, counts):
            if isinstance(out, DescribeResult):
                counts[out.status] += 1
                session.used(out)
                ctx.emit(description_row(item, out, self.category))
            else:
                ctx.emit(out)
        counts["describe_candidates"] += 1
        d = session.get()
        if d is None:
            return
        check_escalated(ctx)
        for res in self.describe(ctx, item, d, counts):
            counts[res.status] += 1
            session.used(res)
            ctx.emit(description_row(item, res, self.category))


def _not_screened(item: MediaItem, why: str) -> ScreenResult:
    return ScreenResult(str(item.path or ""), item.sha256, "error", error=f"not screened: {why}")


def screen_routed(ctx: ModuleContext, items: Sequence[MediaItem], thr: aicfg.Thresholds) -> None:
    """Screen files an unscreened module found to hold pictures or video (``item.route``).

    Sets ``item.screen`` on each. Fails closed: a file that could not be screened gets an
    ``error`` verdict, so it is deleted like any unscreened picture."""
    run_tool = ctx_runner(ctx)
    work = ctx.workdir / "screen"
    imgs = [i for i in items if i.route == "image" and i.path is not None]
    for item in items:
        if item.route not in {"image", "video"} or item.path is None:
            item.screen = _not_screened(item, item.route_reason or "content type unknown")
    if imgs:
        check_escalated(ctx)
        try:
            results = screen_paths(
                [i.path.resolve() for i in imgs if i.path is not None],
                None,
                thr,
                run_tool=run_tool,
                workdir=work,
                known_sha256={str(i.path.resolve()): i.sha256 for i in imgs if i.path},
            )
            for item, res in zip(imgs, results, strict=True):
                item.screen = res
        except (ScreenError, aicfg.ConfigError, proc.ToolError, OSError) as exc:
            for item in imgs:
                item.screen = _not_screened(item, f"{type(exc).__name__}: {exc}"[:300])
    for item in items:
        if item.route != "video" or item.path is None:
            continue
        check_escalated(ctx)
        try:
            vs = aivideo.screen_video(item.path.resolve(), item.sha256, run_tool, work, thr)
            item.screen = vs.result
            item.screen_note = vs.note()
        except (ScreenError, aicfg.ConfigError, proc.ToolError, OSError) as exc:
            item.screen = _not_screened(item, f"{type(exc).__name__}: {exc}"[:300])


# Magic bytes of picture formats, checked when no metadata tool could name the content type.
_IMAGE_MAGIC: tuple[bytes, ...] = (
    b"\xff\xd8\xff",  # JPEG
    b"\x89PNG\r\n\x1a\n",
    b"GIF87a",
    b"GIF89a",
    b"II*\x00",  # TIFF and TIFF-based raw formats
    b"MM\x00*",
    b"II+\x00",  # BigTIFF
    b"MM\x00+",
    b"8BPS",  # Photoshop
    b"\x00\x00\x01\x00",  # ICO
    b"\x00\x00\x00\x0cjP  ",  # JPEG 2000
    b"\x00\x00\x00\x0cJXL ",
    b"\xff\x0a",  # JPEG XL codestream
)
_IMAGE_BRANDS = frozenset({b"heic", b"heix", b"hevc", b"heim", b"heis", b"mif1", b"msf1", b"avif"})
_AV_MAGIC: tuple[bytes, ...] = (
    b"\x1a\x45\xdf\xa3",  # Matroska, WebM
    b"FLV",
    b"\x30\x26\xb2\x75",  # ASF (WMV, WMA)
    b"\x00\x00\x01\xba",  # MPEG program stream
    b"\x00\x00\x01\xb3",  # MPEG video
    b"OggS",
    b"ID3",
    b"fLaC",
    b"#!AMR",
    b".RMF",
)
_DOC_MAGIC: tuple[bytes, ...] = (
    b"%PDF",
    b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",  # OLE compound file (doc, xls, ppt, wps)
    b"PK\x03\x04",  # ZIP-based (docx, xlsx, pptx, odt, pages)
    b"{\\rtf",
    b"\xffWPC",  # WordPerfect
)


def sniff(path: Path) -> str:
    """``image``, ``av`` (audio or video container), ``document``, ``text``, or ``""`` from the
    first bytes of a file. Only used when exiftool and ffprobe could not name the type."""
    try:
        with open(path, "rb") as fh:
            head = fh.read(4096)
    except OSError:
        return ""
    checks: tuple[tuple[str, bool], ...] = (
        ("image", head.startswith(_IMAGE_MAGIC)),
        ("image", head[:4] == b"RIFF" and head[8:12] == b"WEBP"),
        ("image", head[:2] == b"BM" and head[6:10] == b"\x00\x00\x00\x00" and len(head) >= 26),
        ("image", re.match(rb"P[1-7][ \t\r\n]", head[:3]) is not None and len(head) > 3),
        ("image", head[4:8] == b"ftyp" and head[8:12] in _IMAGE_BRANDS),
        ("av", head[4:8] == b"ftyp"),
        ("av", head[:4] in {b"RIFF", b"FORM"} or head.startswith(_AV_MAGIC)),
        ("av", len(head) > 188 and head[0] == 0x47 and head[188] == 0x47),  # MPEG-TS
        ("av", head[:2] in {b"\xff\xfb", b"\xff\xf3", b"\xff\xf2", b"\xff\xf1", b"\xff\xf9"}),
        ("document", head.startswith(_DOC_MAGIC)),
        ("text", _looks_like_text(head)),
    )
    return next((kind for kind, hit in checks if hit), "")


def _looks_like_text(head: bytes) -> bool:
    if not head:
        return True
    if head.startswith((b"\xff\xfe", b"\xfe\xff")):
        return True  # UTF-16 with a byte order mark
    text = head.decode("utf-8", "ignore")
    if len(text.encode("utf-8")) < len(head) - 4:
        return False  # not UTF-8 (a few bytes may be a character cut at the end)
    control = sum(1 for ch in text if ord(ch) < 32 and ch not in "\t\n\r\f")
    return control <= len(text) // 50


def av_route(fp: Any) -> tuple[str, str]:
    """Route for a file ffprobe read: ``video`` when it holds any video or picture stream."""
    if not isinstance(fp, dict):
        return "unknown", "ffprobe could not read it"
    pics = moving = 0
    for s in fp.get("streams") or []:
        if not isinstance(s, dict) or s.get("codec_type") != "video":
            continue
        disp = s.get("disposition") if isinstance(s.get("disposition"), dict) else {}
        if int(disp.get("attached_pic", 0) or 0) == 1:
            pics += 1
        else:
            moving += 1
    fmt = fp.get("format") if isinstance(fp.get("format"), dict) else {}
    name = str(fmt.get("format_name") or "unknown format")
    if moving and (name.endswith("_pipe") or name == "image2"):
        return "image", f"ffprobe reads it as a still picture ({name})"
    if moving:
        return "video", f"ffprobe found {moving} picture or video stream(s) ({name})"
    if pics:
        return "video", f"ffprobe found {pics} attached picture(s) ({name})"
    return "", ""


def ffprobe_json(ctx: ModuleContext, item: MediaItem) -> dict[str, Any] | None:
    """ffprobe JSON for an item (raw output kept under ``metadata/``), or None."""
    path = need_path(item)
    out = ctx.workdir / "metadata" / f"{_safe_name(item)}.ffprobe.json"
    fp = run_json_tool(
        ctx,
        [
            "ffprobe",
            "-v",
            "error",
            "-print_format",
            "json",
            "-show_format",
            "-show_streams",
            str(path),
        ],
        out,
    )
    return fp if isinstance(fp, dict) else None


def _plain(counts: Counter[str]) -> dict[str, int]:
    return {k: int(v) for k, v in sorted(counts.items())}


def mediainfo_ffprobe(ctx: ModuleContext, item: MediaItem, sub: str) -> None:
    """mediainfo and ffprobe JSON for audio and video; raw output kept under ``metadata/``."""
    need_path(item)
    base = ctx.workdir / "metadata"
    stem = _safe_name(item)
    mi = run_json_tool(
        ctx, ["mediainfo", "--Output=JSON", str(item.path)], base / f"{stem}.mediainfo.json"
    )
    fp = ffprobe_json(ctx, item)
    item.meta = {"mediainfo": mi, "ffprobe": fp, "kind": sub}
    if fp is not None:
        item.meta_record = f"modules/{ctx.module}/metadata/{stem}.ffprobe.json#format"
    elif mi is not None:
        item.meta_record = f"modules/{ctx.module}/metadata/{stem}.mediainfo.json#media"


def av_summary(meta: dict[str, Any]) -> tuple[str, float | None, str]:
    """(format name, duration seconds, stream summary) from ffprobe output."""
    fp = meta.get("ffprobe") if isinstance(meta.get("ffprobe"), dict) else {}
    fmt = fp.get("format", {}) if isinstance(fp, dict) else {}
    name = str(fmt.get("format_name") or "unknown")
    dur: float | None
    try:
        dur = float(fmt.get("duration"))
    except (TypeError, ValueError):
        dur = None
    streams = []
    for s in fp.get("streams", []) if isinstance(fp, dict) else []:
        kind = s.get("codec_type", "?")
        codec = s.get("codec_name", "?")
        if kind == "video":
            streams.append(f"video {codec} {s.get('width', '?')}x{s.get('height', '?')}")
        elif kind == "audio":
            streams.append(f"audio {codec} {s.get('sample_rate', '?')} Hz")
    return name, dur, ", ".join(streams) or "no streams read"


def metadata_row(  # noqa: PLR0917
    ctx: ModuleContext, item: MediaItem, category: str, kind: str, message: str, tool: str
) -> dict[str, Any]:
    return {
        **base_row(item, category),
        "artifact_type": f"{kind}_metadata",
        "message": message,
        "derivation": "observed",
        "source_tool": tool,
        "tool_version": ctx.tool_version(tool),
        "parser": tool,
        "source_record": item.meta_record or None,
    }
