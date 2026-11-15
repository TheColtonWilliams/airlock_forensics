"""Module ``documents`` (task 4C.11): export, metadata, text extraction, summary.

Each document is exported read-only and read by exiftool for its metadata (author fields are
kept in the raw record only; rows never name a person). Text comes from ``pdftotext`` or a
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
