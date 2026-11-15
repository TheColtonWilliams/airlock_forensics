"""Documents: text extraction, OCR of scanned pages, and a summary (task 4B.9).

Extraction runs the stock tools in the parser sandbox (no network):

* PDF: ``pdftotext -layout -enc UTF-8``; a page with almost no text is treated as scanned;
* word-processor files: ``soffice --headless --convert-to txt:Text`` with a private profile;
* spreadsheets: ``soffice --headless --convert-to csv``;
* presentations: ``soffice --headless --convert-to pdf``, then ``pdftotext``;
* plain text: read directly (UTF-8 with replacement).

Scanned pages are rendered with ``pdftoppm``, screened like any image, and only cleared pages
go to the model's OCR prompt. Rendered pages are deleted straight after.

The summary uses the fixed ``summarize_document`` prompt; the document text is sent only inside
a delimited data block (``airlock_ai.datablock``), never as part of an instruction.
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from airlock_ai import llm
from airlock_ai.screen import screen_paths
from airlock_ai.tools import RunTool, tool_dir
from airlock_common import proc

WRITER = frozenset({".doc", ".docx", ".odt", ".rtf", ".wpd", ".wps", ".pages"})
CALC = frozenset({".xls", ".xlsx", ".ods", ".xlsm"})
IMPRESS = frozenset({".ppt", ".pptx", ".odp"})
PLAIN = frozenset({".txt", ".csv", ".md", ".log", ".json", ".xml", ".html", ".htm", ".eml"})
DOCUMENT_EXTENSIONS = frozenset({".pdf"}) | WRITER | CALC | IMPRESS | PLAIN
MAX_TEXT_BYTES = 8 * 1024 * 1024
SCANNED_PAGE_CHARS = 20
MAX_OCR_PAGES = 20


@dataclass
class DocText:
    text: str
    method: str
    pages: int = 0
    scanned_pages: list[int] = field(default_factory=list)
    error: str = ""


def _read_text(p: Path) -> str:
    with open(p, "rb") as fh:
        return fh.read(MAX_TEXT_BYTES).decode("utf-8", "replace")


def _pdftotext(run_tool: RunTool, pdf: Path, out: Path) -> DocText:
    cp = run_tool(
        ["pdftotext", "-layout", "-enc", "UTF-8", str(pdf), str(out)],
        timeout=1800,
        extra_ro=[str(pdf.parent)],
    )
    if cp.returncode != 0 or not out.exists():
        last = ((cp.stderr or "").strip().splitlines() or ["no output"])[-1]
        return DocText("", "pdftotext", error=f"pdftotext failed: {last[:200]}")
    text = _read_text(out)
    out.unlink(missing_ok=True)
    pages = text.split("\f")
    if pages and not pages[-1].strip():
        pages = pages[:-1]
    scanned = [i + 1 for i, pg in enumerate(pages) if len(pg.strip()) < SCANNED_PAGE_CHARS]
    return DocText(text.replace("\f", "\n"), "pdftotext", len(pages), scanned)


def _soffice(run_tool: RunTool, src: Path, workdir: Path, fmt: str) -> Path | None:
    outdir = workdir / "soffice-out"
    profile = workdir / "soffice-profile"
    tool_dir(outdir)
    tool_dir(profile)
    exe = proc.which("soffice") or proc.which("libreoffice") or "soffice"
    cp = run_tool(
        [
            exe,
            f"-env:UserInstallation=file://{profile}",
            "--headless",
            "--norestore",
            "--nologo",
            "--nodefault",
            "--convert-to",
            fmt,
            "--outdir",
            str(outdir),
            str(src),
        ],
        timeout=1800,
        memory_bytes=8 * 1024**3,
        extra_ro=[str(src.parent)],
    )
    produced = sorted(outdir.iterdir())
    if cp.returncode != 0 or not produced:
        return None
    return produced[0]


def extract_text(doc: Path, run_tool: RunTool, workdir: Path) -> DocText:  # noqa: PLR0911
    ext = doc.suffix.lower()
    tool_dir(workdir)
    try:
        if ext == ".pdf":
            return _pdftotext(run_tool, doc, workdir / "pdftotext.txt")
        if ext in PLAIN:
            return DocText(_read_text(doc), "read")
        if ext in WRITER | CALC:
            fmt = "csv" if ext in CALC else "txt:Text"
            out = _soffice(run_tool, doc, workdir, fmt)
            if out is None:
                return DocText("", "soffice", error="LibreOffice could not convert the file")
            return DocText(_read_text(out), f"soffice {fmt}")
        if ext in IMPRESS:
            out = _soffice(run_tool, doc, workdir, "pdf")
            if out is None:
                return DocText("", "soffice", error="LibreOffice could not convert the file")
            res = _pdftotext(run_tool, out, workdir / "pdftotext.txt")
            res.method = "soffice pdf + pdftotext"
            res.scanned_pages = []  # slides with pictures only are not scanned pages
            return res
    except proc.ToolError as exc:
        return DocText("", "none", error=str(exc))
    finally:
        shutil.rmtree(workdir / "soffice-out", ignore_errors=True)
        shutil.rmtree(workdir / "soffice-profile", ignore_errors=True)
    return DocText("", "none", error=f"no text extractor for {ext or 'files without a suffix'}")


def render_pages(pdf: Path, pages: list[int], run_tool: RunTool, out_dir: Path) -> list[Path]:
    tool_dir(out_dir)
    made: list[Path] = []
    for page in pages[:MAX_OCR_PAGES]:
        prefix = out_dir / f"page-{page:04d}"
        cp = run_tool(
            [
                "pdftoppm",
                "-r",
                "150",
                "-png",
                "-singlefile",
                "-f",
                str(page),
                "-l",
                str(page),
                str(pdf),
                str(prefix),
            ],
            timeout=600,
            extra_ro=[str(pdf.parent)],
        )
        png = prefix.with_suffix(".png")
        if cp.returncode == 0 and png.exists():
            made.append(png)
    return made


def process(
    path: Path,
    sha256: str,
    run_tool: RunTool,
    describer: Any,
    workdir: Path,
    *,
    screen_backend: str | None = None,
    doc: DocText | None = None,
) -> Any:
    """Extract (unless ``doc`` is given), OCR cleared scanned pages, summarise.

    Returns ``describe.ProcessOutput``.
    """
    from airlock_ai.describe import DescribeResult, ProcessOutput  # noqa: PLC0415

    tier = describer.tier if describer else ""
    if doc is None:
        doc = extract_text(path, run_tool, workdir / f"doc-{sha256[:16]}")
    results: list[DescribeResult] = []
    extra: dict[str, Any] = {"doctext": doc, "ocr_pages": 0, "ocr_flagged": 0}
    if doc.error:
        results.append(
            DescribeResult(str(path), sha256, "document", "error", tier=tier, detail=doc.error)
        )
        return ProcessOutput(results, extra)
    text = doc.text
    if doc.scanned_pages and path.suffix.lower() == ".pdf" and describer is not None:
        pages_dir = workdir / f"pages-{sha256[:16]}"
        try:
            imgs = render_pages(path, doc.scanned_pages, run_tool, pages_dir)
            screened = (
                screen_paths(
                    imgs,
                    None,
                    backend=screen_backend,
                    run_tool=run_tool,
                    workdir=workdir / "screen",
                )
                if imgs
                else []
            )
            ocr_parts: list[str] = []
            for img, res in zip(imgs, screened, strict=True):
                if not res.cleared:
                    extra["ocr_flagged"] += 1
                    continue
                try:
                    r = describer.image(img, res.sha256, kind="document_ocr", prompt_id="ocr_page")
                except llm.LlmError as exc:
                    r = DescribeResult(
                        str(img), res.sha256, "document_ocr", "error", tier=tier, detail=str(exc)
                    )
                r.path, r.sha256 = str(path), sha256
                r.detail = f"page {img.stem.split('-')[-1].lstrip('0') or '0'}" + (
                    f"; {r.detail}" if r.detail else ""
                )
                results.append(r)
                extra["ocr_pages"] += 1
                if r.status == "described" and r.description.strip().upper() != "EMPTY":
                    ocr_parts.append(r.description)
            if ocr_parts:
                text = text + "\n" + "\n".join(ocr_parts)
        finally:
            shutil.rmtree(pages_dir, ignore_errors=True)
    if not text.strip():
        results.append(
            DescribeResult(
                str(path),
                sha256,
                "document_summary",
                "error",
                tier=tier,
                detail="no text could be extracted",
            )
        )
    elif describer is not None:
        try:
            results.append(
                describer.text(
                    text,
                    str(path),
                    sha256,
                    kind="document_summary",
                    prompt_id="summarize_document",
                    data_kind="document text",
                )
            )
        except llm.LlmError as exc:
            results.append(
                DescribeResult(
                    str(path), sha256, "document_summary", "error", tier=tier, detail=str(exc)
                )
            )
    return ProcessOutput(results, extra)
