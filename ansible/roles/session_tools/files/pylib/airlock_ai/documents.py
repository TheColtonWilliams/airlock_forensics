"""Documents: text extraction, OCR of scanned pages, and a summary (task 4B.9).

Extraction runs the stock tools in the parser sandbox (no network):

* PDF: ``pdftotext -layout -enc UTF-8``; a page with almost no text is treated as scanned;
* word-processor files: ``soffice --headless --convert-to txt:Text`` with a private profile;
* spreadsheets: ``soffice --headless --convert-to csv`` with the CSV filter's "all sheets"
  option (LibreOffice 7.2 or later), which writes one file per sheet; the sheets are joined
  in workbook order, each under its name (LibreOffice prints "Writing sheet NAME -> FILE" in
  that order). An older LibreOffice writes the first sheet only, and the method says so;
* presentations: ``soffice --headless --convert-to pdf``, then ``pdftotext``;
* plain text: read directly (UTF-8 with replacement).

Content type: :data:`DOCUMENT_MIME` lists, per extension family, the exiftool MIME types that
are documents of that family (:func:`mime_allowed`). The ``documents`` module keeps only files
whose type is on that list or that it screened as pictures or video; anything else is not kept.

Scanned pages are rendered with ``pdftoppm``, screened like any image, and only cleared pages
go to the model's OCR prompt. Rendered pages are deleted straight after.

The summary uses the fixed ``summarize_document`` prompt; the document text is sent only inside
a delimited data block (``airlock_ai.datablock``), never as part of an instruction.
"""

from __future__ import annotations

import shutil
from collections.abc import Sequence
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
# LibreOffice CSV export (filter "Text - txt - csv (StarCalc)"): comma, double quote, UTF-8,
# first line 1, default cell formats, default language, text cells not all quoted, special
# numbers detected, cell contents as shown (dates stay dates), values not formulas, spaces
# kept, and token 12 = -1: every sheet, one file each (LibreOffice 7.2 or later).
CSV_ALL_SHEETS = "csv:Text - txt - csv (StarCalc):44,34,UTF8,1,,0,false,true,true,false,false,-1"
_WRITING_SHEET = "Writing sheet "

_OOXML = "application/vnd.openxmlformats-officedocument."
_ODF = "application/vnd.oasis.opendocument."
_TEXTUAL = frozenset({"text/plain", "text/html", "text/xml", "application/xml"})
# exiftool File:MIMEType values that are documents of each extension family. Cross-family
# names that Office programs open as their own (an HTML or CSV file saved as .xls, RTF saved
# as .doc) are listed; archives (application/zip), databases, and every picture, video, or
# sound type are not.
DOCUMENT_MIME: dict[str, frozenset[str]] = {
    "pdf": frozenset({"application/pdf"}),
    "word-processor": _TEXTUAL
    | {
        "application/msword",
        _OOXML + "wordprocessingml.document",
        _OOXML + "wordprocessingml.template",
        "application/vnd.ms-word.document.macroenabled.12",
        "application/vnd.ms-word.template.macroenabled.12",
        _ODF + "text",
        _ODF + "text-template",
        "text/rtf",
        "application/rtf",
        "application/vnd.wordperfect",
        "application/vnd.ms-works",
        "application/x-iwork-pages-sffpages",
    },
    "spreadsheet": _TEXTUAL
    | {
        "text/csv",
        "application/vnd.ms-excel",
        _OOXML + "spreadsheetml.sheet",
        _OOXML + "spreadsheetml.template",
        "application/vnd.ms-excel.sheet.macroenabled.12",
        "application/vnd.ms-excel.template.macroenabled.12",
        _ODF + "spreadsheet",
        _ODF + "spreadsheet-template",
    },
    "presentation": frozenset(
        {
            "application/vnd.ms-powerpoint",
            _OOXML + "presentationml.presentation",
            _OOXML + "presentationml.slideshow",
            _OOXML + "presentationml.template",
            "application/vnd.ms-powerpoint.presentation.macroenabled.12",
            "application/vnd.ms-powerpoint.slideshow.macroenabled.12",
            _ODF + "presentation",
            _ODF + "presentation-template",
        }
    ),
    "text": _TEXTUAL
    | {
        "text/csv",
        "text/markdown",
        "text/x-markdown",
        "text/x-log",
        "text/rtf",
        "text/calendar",
        "text/vcard",
        "text/x-vcard",
        "text/tab-separated-values",
        "application/json",
        "application/xhtml+xml",
        "message/rfc822",
    },
}


def family(ext: str) -> str:
    """The extension family a document name claims (a key of :data:`DOCUMENT_MIME`)."""
    ext = ext.lower()
    if ext == ".pdf":
        return "pdf"
    if ext in WRITER:
        return "word-processor"
    if ext in CALC:
        return "spreadsheet"
    if ext in IMPRESS:
        return "presentation"
    if ext in PLAIN:
        return "text"
    return ""


def mime_allowed(ext: str, mime: str) -> bool:
    """Whether exiftool's MIME type ``mime`` is a document of the family ``ext`` claims."""
    base = mime.split(";", 1)[0].strip().lower()
    return bool(base) and base in DOCUMENT_MIME.get(family(ext), frozenset())


@dataclass
class DocText:
    text: str
    method: str
    pages: int = 0
    scanned_pages: list[int] = field(default_factory=list)
    error: str = ""


def _read_text(p: Path, limit: int = MAX_TEXT_BYTES) -> str:
    with open(p, "rb") as fh:
        return fh.read(max(0, limit)).decode("utf-8", "replace")


def _strip_bom(text: str) -> str:
    return text.removeprefix("\ufeff")


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


def _soffice_run(
    run_tool: RunTool, src: Path, workdir: Path, fmt: str
) -> tuple[list[Path], str, Path]:
    """Convert ``src`` with headless LibreOffice: (files written, its stdout, output folder).
    The file list is empty when the conversion failed."""
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
    produced = sorted(p for p in outdir.iterdir() if p.is_file())
    if cp.returncode != 0:
        return [], cp.stdout or "", outdir
    return produced, cp.stdout or "", outdir


def _soffice(run_tool: RunTool, src: Path, workdir: Path, fmt: str) -> Path | None:
    produced, _out, _dir = _soffice_run(run_tool, src, workdir, fmt)
    return produced[0] if produced else None


def sheet_order(stdout: str, produced: Sequence[Path]) -> list[tuple[str, Path]]:
    """(sheet name, CSV file) in workbook order.

    LibreOffice prints ``Writing sheet NAME -> FOLDER/FILE`` for each sheet, in order; a line
    is matched to a file it wrote by the file name, so how the folder is spelled does not
    matter. Files that no such line names follow in name order, named after the part of the
    file name after ``<source stem>-``. A sheet line whose file is missing is left out.
    """
    by_name = {p.name: p for p in produced}
    out: list[tuple[str, Path]] = []
    seen: set[str] = set()
    for line in stdout.splitlines():
        if not line.startswith(_WRITING_SHEET):
            continue
        fname = line.rsplit("/", 1)[-1]
        if fname not in by_name or fname in seen:
            continue
        head, sep, _folder = line[: -len(fname) - 1].rpartition(" -> ")
        if not sep:
            continue
        seen.add(fname)
        out.append((head[len(_WRITING_SHEET) :], by_name[fname]))
    for p in produced:
        if p.name not in seen:
            out.append((p.stem.split("-", 1)[1] if "-" in p.stem else p.stem, p))
    return out


def _spreadsheet(run_tool: RunTool, src: Path, workdir: Path) -> DocText:
    produced, stdout, _outdir = _soffice_run(run_tool, src, workdir, CSV_ALL_SHEETS)
    if not produced:
        return DocText("", "soffice", error="LibreOffice could not convert the file")
    if len(produced) == 1 and produced[0].name == f"{src.stem}.csv":
        # No per-sheet file name: this LibreOffice ignored the all-sheets option.
        text = _strip_bom(_read_text(produced[0]))
        return DocText(text, "soffice csv (first sheet only: LibreOffice older than 7.2)")
    sheets = sheet_order(stdout, produced)
    parts: list[str] = []
    left = MAX_TEXT_BYTES
    for i, (name, path) in enumerate(sheets, 1):
        if left <= 0:
            break
        body = _strip_bom(_read_text(path, left))
        part = f"=== Sheet {i}: {name} ===\n{body.rstrip(chr(10))}\n"
        left -= len(part.encode("utf-8"))
        parts.append(part)
    return DocText("\n".join(parts), f"soffice csv ({len(sheets)} sheets)", pages=len(sheets))


def extract_text(doc: Path, run_tool: RunTool, workdir: Path) -> DocText:  # noqa: PLR0911
    ext = doc.suffix.lower()
    tool_dir(workdir)
    try:
        if ext == ".pdf":
            return _pdftotext(run_tool, doc, workdir / "pdftotext.txt")
        if ext in PLAIN:
            return DocText(_read_text(doc), "read")
        if ext in CALC:
            return _spreadsheet(run_tool, doc, workdir)
        if ext in WRITER:
            out = _soffice(run_tool, doc, workdir, "txt:Text")
            if out is None:
                return DocText("", "soffice", error="LibreOffice could not convert the file")
            return DocText(_strip_bom(_read_text(out)), "soffice txt:Text")
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
