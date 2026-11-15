#!/usr/bin/env python3
"""Write neutral document and container test files into a folder (standard library only).

Usage: make-document-fixtures.py OUTDIR

Deterministic, generated material only (hard rule 2.3.5): short plain sentences about office
furniture, and solid colour pictures. Nothing here is a photograph or shows a person.

* ``note.docx``: the smallest OOXML word-processor package LibreOffice opens (content types,
  one relationship, one paragraph);
* ``sheets.xlsx`` and ``sheets.ods``: two-sheet workbooks whose sheets are deliberately not in
  name order ("Zeta" first, then "Alpha"), so a reader that sorts by name is caught; the ODS
  also holds a date cell;
* ``plain.zip``: a ZIP archive holding one text file (not an Office package);
* ``solid.y4m``: a YUV4MPEG2 video, 2 s (ten frames) of one flat colour, which exiftool calls
  ``text/plain`` and ffprobe reads as video;
* ``solid.psd``: a Photoshop file, an 8 x 8 flat colour picture (exiftool:
  ``application/vnd.adobe.photoshop``; ffprobe: ``psd_pipe``).
"""

from __future__ import annotations

import struct
import sys
import zipfile
from pathlib import Path

STAMP = (1980, 1, 1, 0, 0, 0)
XML = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
PKG_REL = "http://schemas.openxmlformats.org/package/2006/relationships"
DOC_REL = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
OFFICE_DOC = DOC_REL + "/officeDocument"
CT_NS = "http://schemas.openxmlformats.org/package/2006/content-types"
SHEET_NS = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
OOXML = "application/vnd.openxmlformats-officedocument."


def _zip(path: Path, members: list[tuple[str, str]], *, stored_first: bool = False) -> None:
    with zipfile.ZipFile(path, "w") as z:
        for i, (name, text) in enumerate(members):
            info = zipfile.ZipInfo(name, STAMP)
            info.compress_type = (
                zipfile.ZIP_STORED if stored_first and i == 0 else zipfile.ZIP_DEFLATED
            )
            info.external_attr = 0o644 << 16
            z.writestr(info, text.encode("utf-8"))


def _types(defaults: dict[str, str], overrides: dict[str, str]) -> str:
    d = "".join(f'<Default Extension="{k}" ContentType="{v}"/>' for k, v in defaults.items())
    o = "".join(f'<Override PartName="{k}" ContentType="{v}"/>' for k, v in overrides.items())
    return f'{XML}<Types xmlns="{CT_NS}">{d}{o}</Types>'


def _rels(targets: list[tuple[str, str]]) -> str:
    body = "".join(
        f'<Relationship Id="rId{i}" Type="{t}" Target="{target}"/>'
        for i, (t, target) in enumerate(targets, 1)
    )
    return f'{XML}<Relationships xmlns="{PKG_REL}">{body}</Relationships>'


DEFAULTS = {
    "rels": "application/vnd.openxmlformats-package.relationships+xml",
    "xml": "application/xml",
}


def docx(path: Path) -> None:
    w = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
    doc = (
        f'{XML}<w:document xmlns:w="{w}"><w:body>'
        "<w:p><w:r><w:t>The meeting about office chairs moved to Tuesday.</w:t></w:r></w:p>"
        "</w:body></w:document>"
    )
    _zip(
        path,
        [
            (
                "[Content_Types].xml",
                _types(
                    DEFAULTS, {"/word/document.xml": OOXML + "wordprocessingml.document.main+xml"}
                ),
            ),
            ("_rels/.rels", _rels([(OFFICE_DOC, "word/document.xml")])),
            ("word/document.xml", doc),
        ],
    )


def _sheet_xml(cells: list[str]) -> str:
    row = "".join(
        f'<c r="{chr(65 + i)}1" t="inlineStr"><is><t>{c}</t></is></c>' for i, c in enumerate(cells)
    )
    data = f'<sheetData><row r="1">{row}</row></sheetData>'
    return f'{XML}<worksheet xmlns="{SHEET_NS}">{data}</worksheet>'


def xlsx(path: Path) -> None:
    sheets = [("Zeta", ["chairs", "four"]), ("Alpha", ["tables", "two"])]
    wb_sheets = "".join(
        f'<sheet name="{name}" sheetId="{i}" r:id="rId{i}"/>'
        for i, (name, _c) in enumerate(sheets, 1)
    )
    workbook = (
        f'{XML}<workbook xmlns="{SHEET_NS}" xmlns:r="{DOC_REL}"><sheets>{wb_sheets}</sheets>'
        "</workbook>"
    )
    overrides = {"/xl/workbook.xml": OOXML + "spreadsheetml.sheet.main+xml"}
    members: list[tuple[str, str]] = []
    for i, (_name, cells) in enumerate(sheets, 1):
        overrides[f"/xl/worksheets/sheet{i}.xml"] = OOXML + "spreadsheetml.worksheet+xml"
        members.append((f"xl/worksheets/sheet{i}.xml", _sheet_xml(cells)))
    ws_rel = DOC_REL + "/worksheet"
    _zip(
        path,
        [
            ("[Content_Types].xml", _types(DEFAULTS, overrides)),
            ("_rels/.rels", _rels([(OFFICE_DOC, "xl/workbook.xml")])),
            ("xl/workbook.xml", workbook),
            (
                "xl/_rels/workbook.xml.rels",
                _rels([(ws_rel, f"worksheets/sheet{i}.xml") for i in range(1, len(sheets) + 1)]),
            ),
            *members,
        ],
    )


def ods(path: Path) -> None:
    ns = (
        'xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" '
        'xmlns:table="urn:oasis:names:tc:opendocument:xmlns:table:1.0" '
        'xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0"'
    )

    def cell(text: str) -> str:
        value = f"<text:p>{text}</text:p>"
        return f'<table:table-cell office:value-type="string">{value}</table:table-cell>'

    date = (
        '<table:table-cell office:value-type="date" office:date-value="2024-03-05">'
        "<text:p>2024-03-05</text:p></table:table-cell>"
    )
    content = (
        f'{XML}<office:document-content {ns} office:version="1.2"><office:body>'
        "<office:spreadsheet>"
        f'<table:table table:name="Zeta"><table:table-row>{cell("chairs")}{cell("four")}'
        "</table:table-row></table:table>"
        f'<table:table table:name="Alpha"><table:table-row>{cell("tables")}{date}'
        "</table:table-row></table:table>"
        "</office:spreadsheet></office:body></office:document-content>"
    )
    mime = "application/vnd.oasis.opendocument.spreadsheet"
    manifest = (
        f"{XML}<manifest:manifest "
        'xmlns:manifest="urn:oasis:names:tc:opendocument:xmlns:manifest:1.0" '
        'manifest:version="1.2">'
        f'<manifest:file-entry manifest:full-path="/" manifest:media-type="{mime}"/>'
        '<manifest:file-entry manifest:full-path="content.xml" manifest:media-type="text/xml"/>'
        "</manifest:manifest>"
    )
    _zip(
        path,
        [("mimetype", mime), ("content.xml", content), ("META-INF/manifest.xml", manifest)],
        stored_first=True,
    )


def plain_zip(path: Path) -> None:
    _zip(path, [("note.txt", "A list of office furniture.\n")])


def y4m(path: Path, w: int = 16, h: int = 16, frames: int = 10) -> None:
    head = f"YUV4MPEG2 W{w} H{h} F5:1 Ip A1:1 C420jpeg\n".encode("ascii")
    frame = b"FRAME\n" + bytes([41]) * (w * h) + bytes([240]) * (w * h // 2)
    path.write_bytes(head + frame * frames)


def psd(path: Path, w: int = 8, h: int = 8) -> None:
    header = b"8BPS" + struct.pack(">H6xHIIHH", 1, 3, h, w, 8, 3)
    sections = struct.pack(">III", 0, 0, 0)  # colour mode data, image resources, layers
    planes = bytes([60]) * (w * h) + bytes([120]) * (w * h) + bytes([180]) * (w * h)
    path.write_bytes(header + sections + struct.pack(">H", 0) + planes)


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: make-document-fixtures.py OUTDIR", file=sys.stderr)
        return 2
    out = Path(argv[1])
    out.mkdir(parents=True, exist_ok=True)
    docx(out / "note.docx")
    xlsx(out / "sheets.xlsx")
    ods(out / "sheets.ods")
    plain_zip(out / "plain.zip")
    y4m(out / "solid.y4m")
    psd(out / "solid.psd")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
