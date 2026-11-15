"""Module ``documents`` (4C.11, 4B.9): text extraction, OCR of cleared scanned pages, and a
summary where document text is data, never instructions."""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from test_module_images import (
    NEUTRAL,
    llama_stub,
    media_ctx,
    run_dir,  # noqa: F401 - pytest fixture
    stage_inventory,
)

from airlock_ai import config as cfgmod
from airlock_ai import documents as aidocs
from forensic_analyze.modules import documents

pytestmark = pytest.mark.skipif(shutil.which("pdftotext") is None, reason="needs poppler-utils")


@pytest.fixture
def echo_llm(tmp_path: Path, monkeypatch):
    d = tmp_path / "llm"
    d.mkdir()
    yield from llama_stub(d, monkeypatch, mode="echo")


def test_documents_text_ocr_and_summary(run_dir: Path, monkeypatch, echo_llm):  # noqa: F811
    stage_inventory(
        run_dir,
        {
            "/Docs/report.pdf": NEUTRAL / "report-two-pages.pdf",
            "/Docs/planted.pdf": NEUTRAL / "planted-instruction.pdf",
            "/Docs/scan.pdf": NEUTRAL / "scanned-page.pdf",
        },
        monkeypatch,
    )
    ctx, rows = media_ctx(run_dir, "documents")
    res = documents.MODULE.run(ctx)
    assert res.status == "ok", res.reason
    assert res.counts["kept"] == 3 and res.counts["ocr_pages"] == 1
    text_rows = {r["path"]: r for r in rows if r["artifact_type"] == "document_text"}
    assert "office chairs" in text_rows["/Docs/report.pdf"]["text"]
    assert text_rows["/Docs/report.pdf"]["derivation"] == "observed"
    reqs = echo_llm.requests()
    summary_prompt = cfgmod.load_prompt("summarize_document").sha256
    ocr_prompt = cfgmod.load_prompt("ocr_page").sha256
    summaries = [r for r in reqs if r["system_sha256"] == summary_prompt]
    assert len(summaries) == 2  # the scan's only text came from OCR of a cleared page ...
    ocr = [r for r in reqs if r["system_sha256"] == ocr_prompt]
    assert len(ocr) == 1 and len(ocr[0]["images"]) == 1  # ... which went as an image
    planted = next(r for r in summaries if "PWNED" in r["user_text"])
    lines = planted["user_text"].splitlines()
    assert lines[0].startswith("<<<DATA ") and lines[-1].startswith("<<<END DATA ")
    assert all("PWNED" not in ln for ln in (lines[0], lines[-1]))
    ai = [r for r in rows if r["derivation"] == "ai_generated"]
    assert {r["artifact_type"] for r in ai} == {"ai_document_summary", "model_declined"}
    # The echo stub gives no text for an image, so OCR counts as declined: listed, not dropped.
    declined = next(r for r in ai if r["artifact_type"] == "model_declined")
    assert declined["path"] == "/Docs/scan.pdf" and declined["label"] == "model_declined"
    assert all(len(r["prompt_sha256"]) == 64 for r in ai)
    assert not list(ctx.workdir.rglob("page-*.png"))  # rendered pages are temporary


def test_extract_text_plain_and_unknown(tmp_path: Path):
    txt = tmp_path / "a.txt"
    txt.write_text("hello\x00world", encoding="utf-8")
    assert aidocs.extract_text(txt, None, tmp_path / "w").text == "hello\x00world"
    other = tmp_path / "a.bin"
    other.write_bytes(b"x")
    assert aidocs.extract_text(other, None, tmp_path / "w").error


@pytest.mark.skipif(shutil.which("soffice") is None, reason="needs LibreOffice")
def test_extract_text_libreoffice(tmp_path: Path):
    from test_module_images import tool_runner  # noqa: PLC0415

    src = tmp_path / "note.rtf"
    src.write_text(r"{\rtf1\ansi Plain note about chairs.}", encoding="ascii")
    doc = aidocs.extract_text(src, tool_runner(tmp_path), tmp_path / "w")
    assert doc.error == "" and "chairs" in doc.text
    assert not (tmp_path / "w" / "soffice-profile").exists()


def test_text_extracted_without_a_model(run_dir: Path, monkeypatch):  # noqa: F811
    from airlock_ai import llm  # noqa: PLC0415

    monkeypatch.setenv(llm.URL_ENV, "http://127.0.0.1:9")
    monkeypatch.setenv(llm.NO_START_ENV, "1")
    stage_inventory(run_dir, {"/Docs/report.pdf": NEUTRAL / "report-two-pages.pdf"}, monkeypatch)
    ctx, rows = media_ctx(run_dir, "documents")
    assert documents.MODULE.run(ctx).status == "ok"
    kinds = [r["artifact_type"] for r in rows]
    assert "document_text" in kinds and "ai_status" in kinds
    assert not any(r["derivation"] == "ai_generated" for r in rows)


def test_pictures_under_document_names_are_screened(run_dir: Path, monkeypatch, tmp_path: Path):  # noqa: F811
    """Finding 9: a picture renamed .txt or .docx is screened, never kept unscreened."""
    blob = tmp_path / "blob.bin"
    blob.write_bytes(bytes(range(256)) * 16)
    note = tmp_path / "note.txt"
    note.write_text("Meeting moved to Tuesday.\n", encoding="utf-8")
    stage_inventory(
        run_dir,
        {
            "/Docs/notes.txt": NEUTRAL / "shapes-squares.png",  # stub: flagged
            "/Docs/photo.docx": NEUTRAL / "landscape.png",  # stub: cleared
            "/Docs/blob.txt": blob,  # type unknown: not kept
            "/Docs/real.txt": note,
        },
        monkeypatch,
    )
    ctx, rows = media_ctx(
        run_dir, "documents", options={"preset": "standard", "ai_describe": False}
    )
    res = documents.MODULE.run(ctx)
    assert res.status == "ok", res.reason
    assert res.counts["content_mismatch"] == 3
    assert (res.counts["kept"], res.counts["cleared"], res.counts["flagged"]) == (1, 1, 1)
    assert res.counts["not_screened"] == 1
    kept = sorted(p.name for p in (ctx.workdir / "export").iterdir() if p.is_file())
    assert len(kept) == 2  # real.txt and the cleared picture
    errs = {r["path"]: r for r in rows if r["artifact_type"] == "screen_error"}
    assert set(errs) == {"/Docs/blob.txt"}
    assert errs["/Docs/blob.txt"]["message"].startswith("Not screened (content type mismatch")
    nud = {r["path"]: r for r in rows if r["artifact_type"] == "screen_nudity"}
    assert nud["/Docs/notes.txt"]["sensitive_flag"] is True
    assert nud["/Docs/photo.docx"]["sensitive_flag"] is False
    text = {r["path"] for r in rows if r["artifact_type"].startswith("document_text")}
    assert text == {"/Docs/real.txt"}  # screened pictures are never read as documents


GENERATOR = NEUTRAL.parent / "make-document-fixtures.py"


def document_fixtures(out: Path) -> Path:
    """Generated neutral documents and containers (see make-document-fixtures.py)."""
    subprocess.run([sys.executable, "-I", str(GENERATOR), str(out)], check=True)
    return out


def ffmpeg_clip(out: Path, fmt: str, codec: str) -> Path:
    """A 2 s solid-colour clip in container ``fmt`` (generated by ffmpeg, no source media).
    Two seconds: the screening samples one frame every 2 s, and a clip under 1 s yields none
    (it is then not cleared, which would hide what this test checks)."""
    subprocess.run(
        [
            "ffmpeg",
            "-nostdin",
            "-loglevel",
            "error",
            "-y",
            "-f",
            "lavfi",
            "-i",
            "color=c=0x40a070:s=32x32:d=2:r=25",
            "-c:v",
            codec,
            "-f",
            fmt,
            str(out),
        ],
        check=True,
    )
    return out


def test_document_mime_allowlist():
    ooxml = "application/vnd.openxmlformats-officedocument."
    assert aidocs.mime_allowed(".docx", ooxml + "wordprocessingml.document")
    assert aidocs.mime_allowed(".DOC", "application/msword")
    assert aidocs.mime_allowed(".doc", "text/rtf")  # RTF saved as .doc
    assert aidocs.mime_allowed(".xls", "text/html")  # a web table saved as .xls
    assert aidocs.mime_allowed(".xlsm", "application/vnd.ms-excel.sheet.macroEnabled.12")
    assert aidocs.mime_allowed(".pdf", "application/pdf")
    assert aidocs.mime_allowed(".txt", "text/plain; charset=utf-8")
    assert aidocs.mime_allowed(".eml", "message/rfc822")
    assert aidocs.mime_allowed(".json", "application/json")
    for ext, mime in (
        (".docx", "application/zip"),  # an archive is not a document
        (".doc", "application/mxf"),
        (".xls", "application/x-shockwave-flash"),
        (".ppt", "application/vnd.adobe.photoshop"),
        (".pptx", "application/pdf"),  # a PDF under a presentation name
        (".pdf", "text/plain"),
        (".txt", "application/x-sqlite3"),
        (".txt", "application/octet-stream"),
        (".txt", ""),
        (".exe", "text/plain"),  # not a document extension at all
    ):
        assert not aidocs.mime_allowed(ext, mime), (ext, mime)
    assert aidocs.family(".odp") == "presentation" and aidocs.family(".bin") == ""


@pytest.mark.skipif(
    shutil.which("ffmpeg") is None or shutil.which("exiftool") is None,
    reason="needs ffmpeg and exiftool",
)
def test_video_and_unknown_types_under_document_names(
    run_dir: Path,  # noqa: F811
    monkeypatch,
    tmp_path: Path,
):
    """Item A: a document is kept only if its type is a document of its family. Video that
    exiftool calls text/plain (Y4M) or application/* (MXF, SWF), and a Photoshop picture, are
    screened; an archive or sound under a document name is not kept."""
    fx = document_fixtures(tmp_path / "fx")
    note = tmp_path / "note.txt"
    note.write_text("Meeting moved to Tuesday.\n", encoding="utf-8")
    inodes = stage_inventory(
        run_dir,
        {
            "/Docs/frames.txt": fx / "solid.y4m",
            "/Docs/clip.doc": ffmpeg_clip(tmp_path / "clip.mxf", "mxf", "mpeg2video"),
            "/Docs/anim.xls": ffmpeg_clip(tmp_path / "anim.swf", "swf", "flv1"),
            "/Docs/layers.ppt": fx / "solid.psd",
            "/Docs/archive.docx": fx / "plain.zip",
            "/Docs/tone.txt": NEUTRAL / "tone-440hz.wav",
            "/Docs/note.docx": fx / "note.docx",
            "/Docs/sheets.xlsx": fx / "sheets.xlsx",
            "/Docs/real.txt": note,
        },
        monkeypatch,
    )
    ctx, rows = media_ctx(
        run_dir, "documents", options={"preset": "standard", "ai_describe": False}
    )
    res = documents.MODULE.run(ctx)
    assert res.status == "ok", res.reason
    assert res.counts["content_mismatch"] == 6
    assert (res.counts["kept"], res.counts["cleared"], res.counts["not_screened"]) == (3, 4, 2)
    labels = {r["path"]: r for r in rows if r["artifact_type"] == "screen_labels"}
    assert set(labels) == {
        "/Docs/frames.txt",
        "/Docs/clip.doc",
        "/Docs/anim.xls",
        "/Docs/layers.ppt",
    }
    assert "exiftool reports text/plain" in labels["/Docs/frames.txt"]["text"]
    assert "yuv4mpegpipe" in labels["/Docs/frames.txt"]["text"]
    assert "screened as video" in labels["/Docs/clip.doc"]["text"]
    assert "screened as video" in labels["/Docs/anim.xls"]["text"]
    assert "screened as image" in labels["/Docs/layers.ppt"]["text"]
    errs = {r["path"]: r for r in rows if r["artifact_type"] == "screen_error"}
    assert set(errs) == {"/Docs/archive.docx", "/Docs/tone.txt"}
    assert (
        "application/zip, which is not a word-processor document type"
        in (errs["/Docs/archive.docx"]["message"])
    )
    assert "not a document" in errs["/Docs/tone.txt"]["message"]
    for r in errs.values():
        assert r["message"].startswith("Not screened (content type mismatch")
    exported = {p.name for p in (ctx.workdir / "export").iterdir() if p.is_file()}
    assert len(exported) == 7  # four cleared pictures or videos and the three documents
    assert exported == {
        f"v0_{inodes[p]}{Path(p).suffix}"
        for p in inodes
        if p not in {"/Docs/archive.docx", "/Docs/tone.txt"}
    }
    text = {r["path"] for r in rows if r["artifact_type"].startswith("document_text")}
    # Screened files are never read as documents.
    assert text <= {"/Docs/note.docx", "/Docs/sheets.xlsx", "/Docs/real.txt"}
    assert "/Docs/real.txt" in text


def test_sheet_order_follows_libreoffice(tmp_path: Path):
    out = tmp_path / "soffice-out"
    out.mkdir()
    files = [out / n for n in ("s-Alpha.csv", "s-Mid.csv", "s-Zeta.csv", "s-Extra.csv")]
    for f in files:
        f.write_text("x\n", encoding="utf-8")
    stdout = (
        "convert /x/s.xlsx as a Calc document using filter : ...\n"
        # LibreOffice may spell the folder differently: matched by file name.
        "Writing sheet Zeta -> /elsewhere/soffice-out/s-Zeta.csv\n"
        f"Writing sheet Alpha -> {out}/s-Alpha.csv\n"
        f"Writing sheet Gone -> {out}/s-Gone.csv\n"  # no such file: left out
        f"Writing sheet Mid -> {out}/s-Mid.csv\n"
    )
    got = aidocs.sheet_order(stdout, sorted(files))
    assert [(n, p.name) for n, p in got] == [
        ("Zeta", "s-Zeta.csv"),
        ("Alpha", "s-Alpha.csv"),
        ("Mid", "s-Mid.csv"),
        ("Extra", "s-Extra.csv"),  # written but not announced: after the others
    ]
    # A sheet name holding " -> " survives.
    odd = out / "s-a -> b.csv"
    odd.write_text("y\n", encoding="utf-8")
    got = aidocs.sheet_order(f"Writing sheet a -> b -> {out}/s-a -> b.csv\n", [odd])
    assert got == [("a -> b", odd)]


def fake_soffice(stdout: str, sheets: dict[str, str]):
    """A RunTool that records argv and writes ``sheets`` (file name: text) to --outdir."""
    calls: list[list[str]] = []

    def run(argv, **kw):
        calls.append([str(a) for a in argv])
        outdir = Path(argv[argv.index("--outdir") + 1])
        for name, text in sheets.items():
            (outdir / name).write_text(text, encoding="utf-8")
        return subprocess.CompletedProcess(argv, 0, stdout.replace("OUT", str(outdir)), "")

    return run, calls


def test_spreadsheet_exports_every_sheet_argv_and_join(tmp_path: Path):
    """Item D: the CSV filter's token 12 is -1 (every sheet), and the per-sheet files are
    joined in the order LibreOffice wrote them, each under its sheet name."""
    src = tmp_path / "book.xlsx"
    src.write_bytes(b"PK\x03\x04")
    run, calls = fake_soffice(
        "Writing sheet Zeta -> OUT/book-Zeta.csv\nWriting sheet Alpha -> OUT/book-Alpha.csv\n",
        {"book-Alpha.csv": "tables,two\n", "book-Zeta.csv": "﻿chairs,four\n"},
    )
    doc = aidocs.extract_text(src, run, tmp_path / "w")
    argv = calls[0]
    fmt = argv[argv.index("--convert-to") + 1]
    assert fmt == aidocs.CSV_ALL_SHEETS
    name, tokens = fmt.split(":", 1)[1].rsplit(":", 1)
    assert name == "Text - txt - csv (StarCalc)"
    assert tokens.split(",")[11] == "-1" and tokens.split(",")[2] == "UTF8"
    assert doc.error == "" and doc.method == "soffice csv (2 sheets)" and doc.pages == 2
    assert doc.text == "=== Sheet 1: Zeta ===\nchairs,four\n\n=== Sheet 2: Alpha ===\ntables,two\n"
    assert not (tmp_path / "w" / "soffice-out").exists()

    # An older LibreOffice ignores token 12 and writes <stem>.csv: the method says so.
    run, _calls = fake_soffice("", {"book.csv": "chairs,four\n"})
    doc = aidocs.extract_text(src, run, tmp_path / "w2")
    assert doc.text == "chairs,four\n" and "first sheet only" in doc.method


@pytest.mark.skipif(shutil.which("soffice") is None, reason="needs LibreOffice")
@pytest.mark.parametrize("name", ["sheets.xlsx", "sheets.ods"])
def test_extract_text_every_sheet_with_libreoffice(tmp_path: Path, name: str):
    """Item D against the installed LibreOffice: both sheets, in workbook order (Zeta is the
    first sheet, so name order would be wrong)."""
    from test_module_images import tool_runner  # noqa: PLC0415

    fx = document_fixtures(tmp_path / "fx")
    doc = aidocs.extract_text(fx / name, tool_runner(tmp_path), tmp_path / "w")
    assert doc.error == "", doc
    assert doc.method == "soffice csv (2 sheets)"
    zeta, alpha = doc.text.index("=== Sheet 1: Zeta ==="), doc.text.index("=== Sheet 2: Alpha ===")
    assert zeta < alpha
    assert "chairs,four" in doc.text[zeta:alpha] and "tables," in doc.text[alpha:]


@pytest.mark.skipif(shutil.which("soffice") is None, reason="needs LibreOffice")
def test_extract_text_minimal_docx(tmp_path: Path):
    from test_module_images import tool_runner  # noqa: PLC0415

    fx = document_fixtures(tmp_path / "fx")
    doc = aidocs.extract_text(fx / "note.docx", tool_runner(tmp_path), tmp_path / "w")
    assert doc.error == "" and doc.text.strip() == (
        "The meeting about office chairs moved to Tuesday."
    )
