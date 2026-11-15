"""Module ``documents`` (4C.11, 4B.9): text extraction, OCR of cleared scanned pages, and a
summary where document text is data, never instructions."""

from __future__ import annotations

import shutil
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
