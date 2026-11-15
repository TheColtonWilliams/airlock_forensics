"""Shared machinery for the media modules: images, video, audio, documents (4C.8 to 4C.11).

Flow for each file the inventory lists with a matching extension (live, deleted, and carved):

1. stop if ``forensic-escalate`` has marked the run (``<run>/ESCALATED``), before every batch
   and every export;
2. export it read-only with ``extract.export_file`` (icat) into ``export/.pending/``, hash it
   (SHA-256, MD5), and read its metadata (exiftool, mediainfo, ffprobe) in the sandbox;
3. images and videos: screen it (``airlock_ai.screen`` / ``airlock_ai.video``). A cleared
   file moves to ``export/``; a flagged file, or one that could not be screened, is deleted at
   once: it is never kept, copied on, shown, or sent to a model (task 4B.17);
4. describe what was kept with the local model (``airlock_ai.describe``), if a tier is staged;
5. emit rows: observed metadata rows, AI-generated screening rows (score, label, threshold,
   sensitive_flag, model and prompt SHA-256), AI-generated description rows. Rows never carry
   image content: counts, scores, metadata, and descriptions of cleared files only.

Exports live under ``modules/<name>/export/`` so ``cleanup.purge_exports`` and
``forensic-escalate`` find them.
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
from airlock_ai.describe import Describer, DescribeResult
from airlock_ai.screen import ScreenResult
from airlock_common import hashing, proc
from forensic_analyze import extract
from forensic_analyze.api import Module, ModuleContext, ModuleResult, Volume
from forensic_analyze.inventory_index import available, iter_files

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
    screen: ScreenResult | None = None
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
    ctx: ModuleContext, extensions: Iterable[str], max_bytes: int, counts: Counter[str]
) -> list[MediaItem]:
    items: list[MediaItem] = []
    for e in iter_files(ctx.run_dir, extensions=sorted(extensions), include_carved=True):
        size = int(e.get("size_bytes") or 0)
        if size <= 0:
            counts["empty"] += 1
            continue
        if size > max_bytes:
            counts["too_large"] += 1
            continue
        items.append(MediaItem(e, carved=int(e.get("volume_index", 0)) < 0))
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
            p = (ctx.run_dir / str(item.entry.get("carved_path", ""))).resolve()
            if ctx.run_dir.resolve() not in p.parents or not p.is_file():
                raise extract.ExtractError("carved file not found in the run folder")
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
    """Delete a pending copy now: flagged or unscreened content is never kept (4B.17)."""
    if item.path is not None and not item.carved:
        item.path.unlink(missing_ok=True)
    item.path = None
    item.kept = False


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


def screening_rows(
    item: MediaItem, res: ScreenResult, category: str, thr: aicfg.Thresholds, *, extra: str = ""
) -> list[dict[str, Any]]:
    """Two AI-generated rows: the nudity detector and the zero-shot labels."""
    base = base_row(item, category)
    if res.verdict == "error":
        return [
            {
                **base,
                "artifact_type": "screen_error",
                "message": "Not screened (the classifiers could not score it); not kept, not "
                "described.",
                "derivation": "observed",
                "source_tool": "evidence-screen",
                "tool_version": res.backend or "unknown",
                "parser": "airlock_ai.screen",
                "text": (res.error or "; ".join(res.reasons))[:500] or None,
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
        """Extra text for the screening row (video: frames screened, flagged timestamps)."""
        return ""

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
        thr = aicfg.load_thresholds()
        items = select(ctx, self.extensions, self.max_bytes, counts)
        counts["files"] = len(items)
        export_dir = ctx.workdir / "export"
        pending = export_dir / ".pending"
        session = DescribeSession(ctx)
        try:
            for start in range(0, len(items), BATCH):
                self._batch(
                    ctx, items[start : start + BATCH], thr, export_dir, pending, session, counts
                )
            self.extra_pass(ctx, counts)
        except Escalated as exc:
            for it in items:
                if it.path is not None and not it.kept:
                    discard(it)
            return ModuleResult("failed", str(exc), _plain(counts))
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
        return ModuleResult("ok", "", _plain(counts))

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
                continue
            counts["exported"] += 1
            self.metadata(ctx, item)
        live = [i for i in batch if not i.error]
        if self.screened and live:
            self.screen_batch(ctx, live, thr)
        for item in live:
            check_escalated(ctx)
            res = item.screen
            if not self.screened or (res is not None and res.cleared):
                keep(item, export_dir)
                counts["cleared" if self.screened else "kept"] += 1
            else:
                discard(item)
                counts["flagged" if res is not None and res.flagged else "not_screened"] += 1
        for item in batch:
            self._emit_item(ctx, item, thr, session, counts)

    def _emit_item(
        self,
        ctx: ModuleContext,
        item: MediaItem,
        thr: aicfg.Thresholds,
        session: DescribeSession,
        counts: Counter[str],
    ) -> None:
        if item.error:
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
            return
        for row in self.metadata_rows(ctx, item):
            ctx.emit(row)
        if self.screened and item.screen is not None:
            extra = self.screen_extra(item)
            for row in screening_rows(item, item.screen, self.category, thr, extra=extra):
                ctx.emit(row)
        for row in item.extra_rows:
            ctx.emit(row)
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
            str(item.path),
        ],
        base / f"{stem}.ffprobe.json",
    )
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
