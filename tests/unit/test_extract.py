"""NTFS extraction helpers (extract.py): system files, cache, zero-page dropping, export guard,
inventory index reader."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import pytest
from test_parsers_ntfs_fixture import build_ntfs_image, make_ctx, ntfs_tools_ok

from forensic_analyze import extract
from forensic_analyze.inventory_index import KEYS, iter_files, write_index


@pytest.fixture(scope="module")
def image(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, dict[str, Any]]:
    why = ntfs_tools_ok()
    if why:
        pytest.skip(why)
    img = tmp_path_factory.mktemp("ex") / "fixture.img"
    return img, build_ntfs_image(img)


def test_system_files_are_copied_and_cached(image: tuple[Path, dict], tmp_path: Path) -> None:
    img, _ = image
    calls: list[list[str]] = []
    ctx, _ = make_ctx(img, tmp_path / "run", "inventory")
    real = ctx.tool

    def counting(argv: list[str], **kw: Any) -> Any:
        calls.append([str(a) for a in argv])
        return real(argv, **kw)

    ctx.tool = counting
    vol = ctx.target.volumes[0]
    mft = extract.extract_system_file(ctx, vol, "$MFT")
    assert mft == tmp_path / "run" / "extract" / "v0" / "MFT"
    assert mft.read_bytes()[:4] == b"FILE"
    meta = json.loads((mft.parent / "MFT.json").read_text())
    assert meta["address"] == "0" and meta["stream_size"] == mft.stat().st_size
    assert len(meta["stream_sha256"]) == 64
    sds = extract.extract_system_file(ctx, vol, "$Secure:$SDS")
    assert json.loads((sds.parent / "Secure_SDS.json").read_text())["address"].startswith("9-128-")
    n = len(calls)
    assert extract.extract_system_file(ctx, vol, "$MFT") == mft
    assert len(calls) == n, "second call uses the cache"
    assert all(c[0] in {"icat", "fls"} for c in calls)
    assert all("-o" in c for c in calls)
    with pytest.raises(extract.ExtractError, match="not found"):
        extract.extract_system_file(ctx, vol, "$UsnJrnl:$J")
    with pytest.raises(ValueError, match="unknown system file"):
        extract.extract_system_file(ctx, vol, "$Boot")


def test_export_deleted_file_content(image: tuple[Path, dict], tmp_path: Path) -> None:
    img, _ = image
    ctx, _ = make_ctx(img, tmp_path / "run", "x")
    vol = ctx.target.volumes[0]
    addr = extract.lookup(ctx, vol, "5", "Docs")
    assert addr
    idx = extract.load_mft_index(ctx, vol)
    gone = next(e for e in idx.records if idx.path_of(e) == "/Docs/gone.txt")
    out = extract.export_file(ctx, vol, gone, ctx.workdir / "export", name="../gone.txt")
    assert out.parent == ctx.workdir / "export"
    assert out.name == "gone.txt"  # the name is made safe: no separators, no leading dots
    assert out.read_text() == "plan for tuesday\n"
    with pytest.raises(ValueError, match="outside the run folder"):
        extract.export_file(ctx, vol, gone, tmp_path / "elsewhere")
    with pytest.raises(ValueError, match="not a metadata address"):
        extract.export_file(ctx, vol, "68; rm -rf /", ctx.workdir / "export")


def test_zero_pages_are_dropped_while_streaming(tmp_path: Path) -> None:
    from test_parsers_ntfs_fixture import tool_runner  # noqa: PLC0415

    class Ctx:
        def __init__(self) -> None:
            self.tool = tool_runner(tmp_path)

    script = (
        "import sys; o=sys.stdout.buffer; o.write(b'\\0'*40960); o.write(b'A'*5000);"
        "o.write(b'\\0'*8192); o.write(b'B'*100)"
    )
    dest = tmp_path / "J"
    writer = extract._PageWriter(dest, drop_zero_pages=True)
    cp = extract.stream_tool(Ctx(), [sys.executable, "-c", script], writer)  # type: ignore[arg-type]
    writer.close()
    assert cp.returncode == 0
    data = dest.read_bytes()
    assert writer.size == 40960 + 5000 + 8192 + 100
    assert data.lstrip(b"\0").startswith(b"A" * 5000)
    assert len(data) < 3 * 4096 and data.count(b"B") == 100
    assert writer.runs[0][0] == 40960


def test_stream_tool_missing_tool_does_not_hang(tmp_path: Path) -> None:
    from test_parsers_ntfs_fixture import tool_runner  # noqa: PLC0415

    from airlock_common import proc  # noqa: PLC0415

    class Ctx:
        tool = staticmethod(tool_runner(tmp_path))

    with pytest.raises(proc.ToolError):
        extract.stream_tool(Ctx(), ["no-such-tool-airlock"], lambda _b: None)  # type: ignore[arg-type]


def test_index_reader(tmp_path: Path) -> None:
    run = tmp_path / "run"
    base = dict.fromkeys(KEYS)
    lines = [
        {
            **base,
            "volume_index": 0,
            "inode": "70-128-2",
            "path": "/b/Photo.JPG",
            "allocated": True,
            "deleted": False,
        },
        {
            **base,
            "volume_index": 0,
            "inode": "71-128-2",
            "path": "/a/x.jpg:Zone.Identifier",
            "allocated": True,
            "deleted": False,
        },
        {
            **base,
            "volume_index": 1,
            "inode": "72-128-2",
            "path": "/c/gone.png",
            "allocated": False,
            "deleted": True,
        },
    ]
    write_index(run / "modules" / "inventory" / "files.jsonl", lines)
    assert [e["path"] for e in iter_files(run)] == [
        "/a/x.jpg:Zone.Identifier",
        "/b/Photo.JPG",
        "/c/gone.png",
    ]
    assert [e["path"] for e in iter_files(run, extensions=["jpg", ".png"])] == [
        "/b/Photo.JPG",
        "/c/gone.png",
    ]
    assert [e["path"] for e in iter_files(run, include_deleted=False)] == [
        "/a/x.jpg:Zone.Identifier",
        "/b/Photo.JPG",
    ]
    assert [e["path"] for e in iter_files(run, volume_index=1)] == ["/c/gone.png"]
    assert list(iter_files(tmp_path / "none")) == []
    with pytest.raises(ValueError, match="lacks"):
        write_index(run / "bad.jsonl", [{"path": "/x"}])
