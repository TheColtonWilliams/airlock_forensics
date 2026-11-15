"""Module ``documents`` (task 4C.11): export, metadata, text extraction, summary.

Each document is exported read-only and read by exiftool for its metadata (author fields are
kept in the raw record only; rows never name a person). Its content type is then checked
against an allowlist (:meth:`DocumentsModule.content_route`): a picture or video under a
document name (exiftool MIME type, any picture or video stream ffprobe can read, or magic
bytes when exiftool cannot name it) is screened like an image or a video and kept only if
cleared; it gets no text extraction, transcript, or summary. A file that is neither a document
of the family its extension claims (``airlock_ai.documents.DOCUMENT_MIME``) nor screenable
(sound, an archive, a database, an unknown type) is not kept, with a "Not screened (content
type mismatch: ...)" row. Pictures embedded in a document are not screened (see
docs/known-limitations.md). Text comes from ``pdftotext`` or a
headless LibreOffice conversion in the sandbox (``airlock_ai.documents``). Scanned PDF pages
are rendered, screened like images, and only cleared pages are read by the model's OCR
prompt. The summary uses the fixed ``summarize_document`` prompt with the document text inside
a delimited data block: text from evidence is data, never an instruction.
"""

from __future__ import annotations

from collections import Counter
from typing import Any

from airlock_ai import documents as aidocs
from airlock_ai.describe import Describer, DescribeResult
from forensic_analyze import media
from forensic_analyze.api import ModuleContext

TEXT_EXCERPT = 2000


class DocumentsModule(media.MediaModule):
    name = "documents"
    title = "Documents"
    order = 90
    category = "documents"
    kind = "document"
    extensions = aidocs.DOCUMENT_EXTENSIONS
    max_bytes = 512 * 1024**2
    screened = False
    description = "Document metadata, extracted text, OCR of scanned pages, and summaries."

    def metadata(self, ctx: ModuleContext, item: media.MediaItem) -> None:
        media.need_path(item)
        stem = item.path.name
        out = ctx.workdir / "metadata" / f"{stem}.exiftool.json"
        data = media.run_json_tool(ctx, ["exiftool", "-j", "-n", "-G", str(item.path)], out)
        if isinstance(data, list) and data and isinstance(data[0], dict):
            item.meta = data[0]
            item.meta_record = f"modules/{ctx.module}/metadata/{stem}.exiftool.json#0"

    def content_route(  # noqa: PLR0911 - one return per outcome, in order
        self, ctx: ModuleContext, item: media.MediaItem
    ) -> tuple[str, str]:
        """Keep a file only when it is a document of the family its extension claims.

        1. exiftool says ``image/*``: screen it as an image.
        2. ffprobe reads a picture or video stream from it (whatever exiftool said: a Y4M
           video is "text/plain" to exiftool, MXF and SWF are "application/*"): screen it as
           an image or video.
        3. Sound, or sound with cover art: not a document, not kept here.
        4. exiftool's MIME type is on the family's list (``airlock_ai.documents``): keep it.
        5. exiftool could not name it: keep it only if its first bytes look like a document
           or text.
        6. Anything else (an archive, a database, an unknown type): not kept.
        """
        path = media.need_path(item)
        mime = str(item.meta.get("File:MIMEType") or "").strip() if item.meta else ""
        major = mime.split("/", 1)[0].lower()
        if major == "image":
            return "image", f"exiftool reports {mime}"
        sniffed = ""
        if mime:
            source = f"exiftool reports {mime}"
        else:
            sniffed = media.sniff(path)
            if sniffed == "image":
                return "image", (
                    "exiftool could not name the type and its first bytes are a picture format"
                )
            source = "exiftool could not name the type"
        fp = media.ffprobe_json(ctx, item)
        route, why = media.av_route(fp) if fp is not None else ("", "")
        if route in {"image", "video"}:
            return route, f"{source}; {why}"
        if route == "embedded" or major in {"audio", "video"} or sniffed == "av":
            what = "sound with embedded pictures" if route == "embedded" else "sound or video"
            if fp is None:
                what += ", and ffprobe could not read it"
            return "unknown", f"{source}: {what}, not a document"
        if mime:
            if aidocs.mime_allowed(item.ext, mime):
                return "", ""
            fam = aidocs.family(item.ext) or "document"
            return "unknown", (
                f"{source}, which is not a {fam} document type, and no picture or video "
                "stream could be read from it"
            )
        if sniffed in {"document", "text"}:
            return "", ""
        return "unknown", (
            "exiftool could not name the type and it does not look like a document or text"
        )

    def metadata_rows(self, ctx: ModuleContext, item: media.MediaItem) -> list[dict[str, Any]]:
        if not item.meta:
            return []
        m = item.meta
        ftype = str(m.get("File:FileType") or "unknown type")
        pages = m.get("PDF:PageCount")
        extra = f", {pages} pages" if pages else ""
        return [
            media.metadata_row(
                ctx,
                item,
                self.category,
                self.kind,
                f"Document metadata: {ftype}{extra}.",
                "exiftool",
            )
        ]

    def kept_extras(
        self, ctx: ModuleContext, item: media.MediaItem, counts: Counter[str]
    ) -> list[dict[str, Any] | DescribeResult]:
        """Text extraction needs no model: it runs even when no tier is staged."""
        path = media.need_path(item)
        if item.route:
            return []  # picture, video, or sound content: screened, never read as a document
        doc = aidocs.extract_text(path, media.ctx_runner(ctx), ctx.workdir / "ai-work" / "x")
        item.meta["_doctext"] = doc
        if doc.error:
            counts["text_errors"] += 1
            return [
                {
                    **media.base_row(item, self.category),
                    "artifact_type": "document_text_error",
                    "message": f"No text extracted: {doc.error}"[:300],
                    "derivation": "observed",
                    "source_tool": doc.method.split()[0],
                    "tool_version": ctx.tool_version(doc.method.split()[0]),
                    "parser": "airlock_ai.documents",
                }
            ]
        if not doc.text.strip():
            return []
        counts["text_extracted"] += 1
        out = ctx.workdir / "text" / f"{path.name}.txt"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(doc.text, encoding="utf-8")
        tool = doc.method.split()[0]
        return [
            {
                **media.base_row(item, self.category),
                "artifact_type": "document_text",
                "message": f"Text extracted ({doc.method}): {len(doc.text)} characters, "
                f"{len(doc.scanned_pages)} scanned pages.",
                "derivation": "observed",
                "source_tool": tool,
                "tool_version": ctx.tool_version(tool) if tool != "read" else "python",
                "parser": f"airlock_ai.documents.{tool}",
                "text": doc.text[:TEXT_EXCERPT],
                "source_record": f"modules/{ctx.module}/text/{out.name}#all",
            }
        ]

    def describe(
        self, ctx: ModuleContext, item: media.MediaItem, d: Describer, counts: Counter[str]
    ) -> list[DescribeResult]:
        path = media.need_path(item)
        if item.route:
            return []
        doc = item.meta.get("_doctext")
        if doc is not None and doc.error:
            return []
        out = aidocs.process(
            path, item.sha256, media.ctx_runner(ctx), d, ctx.workdir / "ai-work", doc=doc
        )
        counts["ocr_pages"] += int(out.extra.get("ocr_pages", 0))
        counts["ocr_pages_flagged"] += int(out.extra.get("ocr_flagged", 0))
        return out.results


MODULE = DocumentsModule()
