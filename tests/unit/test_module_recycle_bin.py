"""Module recycle_bin (4C.6) and its RBCmd cross-check (4C.28)."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import pytest
from test_parsers_ntfs_fixture import SID, build_ntfs_image, make_ctx, ntfs_tools_ok, stub_tool

from forensic_analyze.modules import inventory, recycle_bin


@pytest.fixture(scope="module")
def image(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, dict[str, Any]]:
    why = ntfs_tools_ok()
    if why:
        pytest.skip(why)
    img = tmp_path_factory.mktemp("rb") / "fixture.img"
    return img, build_ntfs_image(img)


def run(img: Path, run_dir: Path, *, with_inventory: bool = True) -> tuple[Any, list[dict]]:
    shared: dict[str, Any] = {}
    if with_inventory:
        ctx, _ = make_ctx(img, run_dir, "inventory", shared=shared)
        assert inventory.MODULE.run(ctx).status == "ok"
    ctx, rows = make_ctx(img, run_dir, "recycle_bin", shared=shared)
    return recycle_bin.MODULE.run(ctx), rows


NAMES = {
    "C:\\Users\\Test\\Documents\\draft.txt": "$IAB12CD.txt",
    "C:\\Users\\Test\\Downloads\\manual.pdf": "$IEF34GH.pdf",
    "C:\\Temp\\scratch.txt": "$IZZ99YY.txt",
}


def entries(rows: list[dict], parser: str = "airlock.recycle") -> dict[str, dict]:
    """Recycle bin rows of one parser by their $I name (known from the original path)."""
    out = {}
    for r in rows:
        if r["artifact_type"] == "recycle_bin_entry" and r["parser"] == parser:
            out[NAMES[r["path"]]] = r
    return out


@pytest.mark.parametrize("with_inventory", [True, False])
def test_recycle_entries_match_ground_truth(
    image: tuple[Path, dict], tmp_path: Path, with_inventory: bool
) -> None:
    img, truth = image
    res, rows = run(img, tmp_path / "run", with_inventory=with_inventory)
    assert res.status == "ok"
    found = entries(rows)
    assert set(found) == set(truth["recycle"])
    for name, want in truth["recycle"].items():
        r = found[name]
        assert r["path"] == want["path"]
        assert r["filename"] == want["path"].rsplit("\\", 1)[-1]
        assert r["datetime"] == want["deleted"]
        assert r["timestamp_desc"] == "Deletion Time"
        assert r["tz_basis"] == "utc"
        assert r["size_bytes"] == want["size"]
        assert r["owner_sid"] == SID
        assert r["allocated"] is want["allocated"]
        assert f"account SID {SID}" in r["message"]
        assert f"#version={want['version']}" in r["source_record"]
        assert {"present": "is present", "missing": "No content file", "deleted": "is deleted"}[
            want["r"]
        ] in r["message"]
        assert r["xval_status"] == "single_source"
        # Raw bytes of the Windows path are kept (the path holds backslashes).
        assert "path_b64" in r


def test_summary_says_single_parser(image: tuple[Path, dict], tmp_path: Path) -> None:
    img, _ = image
    _, rows = run(img, tmp_path / "run")
    summary = [r for r in rows if r["artifact_type"] == "xval_summary"]
    assert len(summary) == 1
    if "rbcmd" not in summary[0]["message"]:
        assert "only one parser was available" in summary[0]["message"]
        assert "rbcmd: not installed" in summary[0]["text"]


RBCMD_STUB = r"""
import csv, sys
from pathlib import Path
args = sys.argv[1:]
src = Path(args[args.index("-d") + 1])
out = Path(args[args.index("--csv") + 1]) / args[args.index("--csvf") + 1]
rows = []
for f in sorted(src.rglob("$I*")):
    data = f.read_bytes()
    import struct
    ver, size, ft = struct.unpack_from("<QQQ", data)
    if ver == 2:
        n = struct.unpack_from("<I", data, 24)[0]
        name = data[28:28 + 2 * n].decode("utf-16-le").rstrip("\0")
    else:
        name = data[24:544].decode("utf-16-le").split("\0")[0]
    secs = (ft - 116444736000000000) / 1e7
    import datetime as dt
    when = dt.datetime.fromtimestamp(secs, dt.UTC).strftime("%Y-%m-%d %H:%M:%S")
    if name.endswith("manual.pdf"):
        size = 9999  # planted disagreement
    rows.append([str(f), "$I", name, str(size), when])
with open(out, "w", newline="", encoding="utf-8-sig") as fh:
    w = csv.writer(fh)
    w.writerow(["SourceName", "FileType", "FileName", "FileSize", "DeletedOn"])
    w.writerows(rows)
"""


def test_rbcmd_second_parser_and_disagreement(
    image: tuple[Path, dict], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    img, truth = image
    stub_tool(tmp_path / "bin", "RBCmd", RBCMD_STUB)
    monkeypatch.setenv("PATH", f"{tmp_path / 'bin'}:{os.environ['PATH']}")
    res, rows = run(img, tmp_path / "run")
    assert res.status == "ok"
    rb = entries(rows, "rbcmd")
    assert set(rb) == set(truth["recycle"])
    ours = entries(rows)
    assert ours["$IAB12CD.txt"]["xval_status"] == "agree"
    assert ours["$IEF34GH.pdf"]["xval_status"] == "disagree"
    assert rb["$IEF34GH.pdf"]["size_bytes"] == 9999
    dis = [r for r in rows if r["artifact_type"] == "xval_disagreement"]
    assert len(dis) == 1
    assert "rbcmd=9999" in dis[0]["text"] and "airlock=2048" in dis[0]["text"]
    assert dis[0]["path"].endswith("$IEF34GH.pdf")


def test_no_recycle_bin_is_reported(tmp_path: Path) -> None:
    why = ntfs_tools_ok()
    if why:
        pytest.skip(why)
    import subprocess  # noqa: PLC0415

    img = tmp_path / "empty.img"
    with open(img, "wb") as fh:
        fh.truncate(16 * 1024 * 1024)
    subprocess.run(["mkfs.ntfs", "-Q", "-F", str(img)], check=True, capture_output=True)
    res, rows = run(img, tmp_path / "run")
    assert res.status == "ok"
    assert [r["artifact_type"] for r in rows] == ["recycle_bin_none"]
