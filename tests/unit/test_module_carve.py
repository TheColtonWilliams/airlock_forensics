"""Module carve (4C.15): Full preset only; PhotoRec over a blkls copy of unallocated space."""

from __future__ import annotations

import hashlib
import shutil
from collections import namedtuple
from pathlib import Path
from typing import Any

import pytest
from test_module_images import STUB_SCORES
from test_parsers_ntfs_fixture import build_ntfs_image, make_ctx, ntfs_tools_ok

from airlock_ai import llm
from forensic_analyze.inventory_index import iter_files
from forensic_analyze.modules import carve


@pytest.fixture(scope="module")
def image(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, dict[str, Any]]:
    why = ntfs_tools_ok()
    if why:
        pytest.skip(why)
    img = tmp_path_factory.mktemp("carve") / "fixture.img"
    return img, build_ntfs_image(img)


FULL = {"preset": "full", "full": True}


def test_skipped_outside_full(image: tuple[Path, dict], tmp_path: Path) -> None:
    img, _ = image
    ctx, rows = make_ctx(img, tmp_path / "run", "carve", options={"preset": "standard"})
    res = carve.MODULE.run(ctx)
    assert res.status == "skipped" and "Full preset" in res.reason
    assert rows == []


def _no_model(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(llm.URL_ENV, "http://127.0.0.1:9")  # nothing listens: no descriptions
    monkeypatch.setenv(llm.NO_START_ENV, "1")


@pytest.mark.skipif(not shutil.which("photorec"), reason="needs photorec (testdisk)")
def test_carves_deleted_picture(
    image: tuple[Path, dict], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    img, truth = image
    run = tmp_path / "run"
    _no_model(monkeypatch)
    # The stub screening backend clears the fixture picture (neutral scores), so it stays.
    monkeypatch.setenv("AIRLOCK_SCREEN_BACKEND", f"stub:{STUB_SCORES}")
    ctx, rows = make_ctx(img, run, "carve", options=FULL)
    res = carve.MODULE.run(ctx)
    assert res.status == "ok"
    files = [r for r in rows if r["artifact_type"] == "carved_file"]
    hit = [r for r in files if r["sha256"] == truth["png_sha256"]]
    assert hit, [r.get("filename") for r in files]
    assert hit[0]["allocated"] is False
    assert hit[0]["path"].startswith("/modules/carve/carved/v0/")
    copy = next(r for r in rows if r["artifact_type"] == "unallocated_copy")
    assert copy["source_record"] == "modules/carve/export/unalloc-v0.blkls#all"
    carved = list(iter_files(run, include_carved=True))
    pngs = [c for c in carved if c["volume_index"] == -1 and c["sha256"] == truth["png_sha256"]]
    assert pngs and pngs[0]["family"] == "images"
    assert (run / pngs[0]["carved_path"]).is_file()
    assert pngs[0]["carved_path"].startswith("modules/carve/carved/")
    if not shutil.which("bulk_extractor"):
        assert any(r["artifact_type"] == "carve_tool_missing" for r in rows)
    screened = [r for r in rows if r["artifact_type"] == "screen_nudity"]
    assert any(r["sha256"] == truth["png_sha256"] for r in screened)


@pytest.mark.skipif(not shutil.which("photorec"), reason="needs photorec (testdisk)")
@pytest.mark.skipif(Path("/opt/triage").exists(), reason="the classifier venv is installed here")
def test_carved_picture_removed_without_classifiers(
    image: tuple[Path, dict], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """No classifiers staged (minimal profile): a carved picture cannot be screened, so it is
    deleted at once and only its hashes are recorded (4B.17)."""
    img, truth = image
    run = tmp_path / "run"
    _no_model(monkeypatch)
    monkeypatch.delenv("AIRLOCK_SCREEN_BACKEND", raising=False)
    monkeypatch.setenv("AIRLOCK_OPT_DIR", str(tmp_path / "no-opt"))
    ctx, rows = make_ctx(img, run, "carve", options=FULL)
    res = carve.MODULE.run(ctx)
    assert res.status == "ok", res.reason
    gone = [r for r in rows if r["artifact_type"] == "carved_media_removed"]
    hit = [r for r in gone if r["sha256"] == truth["png_sha256"]]
    assert hit and hit[0]["label"] == "not_screened", gone
    carved = [c for c in iter_files(run, include_carved=True) if c["sha256"] == truth["png_sha256"]]
    assert carved and carved[0]["removed"] == "not_screened"
    assert not (run / carved[0]["carved_path"]).exists()
    for p in run.rglob("*.png"):
        assert hashlib.sha256(p.read_bytes()).hexdigest() != truth["png_sha256"], p
    files = [r for r in rows if r["artifact_type"] == "carved_file"]
    row = next(r for r in files if r["sha256"] == truth["png_sha256"])
    assert "Deleted after screening (not_screened)" in row["message"]


def test_not_enough_room(
    image: tuple[Path, dict], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    img, _ = image
    usage = namedtuple("usage", "total used free")
    monkeypatch.setattr(carve.shutil, "disk_usage", lambda _p: usage(10, 10, 1024))
    ctx, rows = make_ctx(img, tmp_path / "run", "carve", options=FULL)
    assert carve.MODULE.run(ctx).status == "ok"
    assert [r["artifact_type"] for r in rows] == ["carve_skipped"]
    assert "Use a larger output drive" in rows[0]["message"]
    assert not (tmp_path / "run" / "modules" / "carve" / "export").exists()


def test_free_space_from_bitmap(image: tuple[Path, dict], tmp_path: Path) -> None:
    img, _ = image
    ctx, _ = make_ctx(img, tmp_path / "run", "carve", options=FULL)
    free = carve.free_bytes_ntfs(ctx, ctx.target.volumes[0])
    assert free is not None and 0 < free < img.stat().st_size


def test_photorec_command_has_only_known_types() -> None:
    cmd = carve.photorec_cmd().split(",")
    assert cmd[0] == "partition_none" and cmd[-1] == "search"
    assert "txt" not in cmd and "everything" in cmd
