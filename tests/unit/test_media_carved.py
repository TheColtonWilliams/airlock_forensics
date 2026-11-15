"""Carved media (plan 4B.17): flagged or unscreened carved files are deleted, never kept.

The carve module runs after the media modules, so it hands its carved files to them
(``media.process_carved``). Fixtures are neutral shapes and text renders only; the stub screening
backend (tests/fixtures/ai/stub-scores.json) decides which one counts as "flagged".
"""

from __future__ import annotations

import hashlib
import json
import shutil
from collections import Counter
from pathlib import Path
from typing import Any

import pytest
from test_module_images import NEUTRAL, media_ctx, run_dir  # noqa: F401 - pytest fixture

from airlock_ai import llm
from forensic_analyze import inventory_index, media
from forensic_analyze.modules import carve, images

CARVED = {
    "f0000100.png": NEUTRAL / "landscape.png",  # cleared by the stub scores
    "f0000200.png": NEUTRAL / "shapes-squares.png",  # stub: flagged
    "f0000300.png": NEUTRAL / "text-render.png",  # stub: cannot be scored
    "f0000400.heic": NEUTRAL / "shapes-triangle.png",  # a type the screening step cannot read
}


def sha(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def stage_carved(run: Path, files: dict[str, Path]) -> dict[str, str]:
    """Copy fixtures into the carve folder and write carved.jsonl as carve does."""
    out = run / "modules" / "carve" / "carved" / "v0" / "recup.1"
    out.mkdir(parents=True)
    lines, rels = [], {}
    for name, src in sorted(files.items()):
        dest = out / name
        shutil.copyfile(src, dest)
        rel = dest.relative_to(run).as_posix()
        rels[name] = rel
        ext = dest.suffix.lstrip(".")
        lines.append(
            {
                "volume_index": -1,
                "inode": "",
                "path": "/" + rel,
                "carved_path": rel,
                "size_bytes": dest.stat().st_size,
                "allocated": False,
                "deleted": True,
                "mtime": None,
                "atime": None,
                "ctime": None,
                "crtime": None,
                "source_volume": 0,
                "offset_bytes": int(name[1:8]) * 512,
                "family": carve.EXT_FAMILY.get(ext, "other"),
                "sha256": sha(dest),
            }
        )
    inventory_index.write_index(inventory_index.carved_path(run), lines)
    return rels


def no_model(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(llm.URL_ENV, "http://127.0.0.1:9")  # nothing listens: no descriptions
    monkeypatch.setenv(llm.NO_START_ENV, "1")


def all_hashes(root: Path) -> set[str]:
    return {sha(p) for p in root.rglob("*") if p.is_file()}


def test_flagged_and_unscreened_carved_images_are_deleted(
    run_dir: Path,  # noqa: F811 - fixture
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    no_model(monkeypatch)
    rels = stage_carved(run_dir, CARVED)
    ctx, rows = media_ctx(run_dir, "carve", options={"preset": "full", "full": True})
    counts: Counter[str] = Counter()
    removed = carve.screen_carved(ctx, counts)

    assert removed == {
        rels["f0000200.png"]: "flagged",
        rels["f0000300.png"]: "not_screened",
        rels["f0000400.heic"]: "unsupported",
    }
    assert (run_dir / rels["f0000100.png"]).is_file()  # cleared: stays where carve put it
    for name in ("f0000200.png", "f0000300.png", "f0000400.heic"):
        assert not (run_dir / rels[name]).exists(), name
    # No copy of a removed file anywhere in the run folder (no export, no pending copy).
    left = all_hashes(run_dir)
    for name in ("f0000200.png", "f0000300.png", "f0000400.heic"):
        assert sha(CARVED[name]) not in left, name
    assert sha(CARVED["f0000100.png"]) in left

    gone = {r["path"][1:]: r for r in rows if r["artifact_type"] == "carved_media_removed"}
    assert set(gone) == set(removed)
    flagged = gone[rels["f0000200.png"]]
    assert flagged["sha256"] == sha(CARVED["f0000200.png"])  # the hash is kept
    assert len(flagged["md5"]) == 32
    assert flagged["sensitive_flag"] is True and flagged["label"] == "flagged"
    assert flagged["derivation"] == "observed" and flagged["category"] == "images"
    assert "No copy is kept" in flagged["message"]
    heic = gone[rels["f0000400.heic"]]
    assert heic["sha256"] == sha(CARVED["f0000400.heic"]) and heic["label"] == "unsupported"
    assert counts["media_carved_removed"] == 3
    # Screening rows for the carved pictures come first, AI-labelled, as for live files.
    nud = [r for r in rows if r["artifact_type"] == "screen_nudity"]
    assert {r["path"][1:] for r in nud} == {rels["f0000100.png"], rels["f0000200.png"]}

    # carved.jsonl now says which lines were removed; later readers skip them.
    lines = list(inventory_index.iter_files(run_dir, include_carved=True))
    marks = {ln["carved_path"]: ln.get("removed") for ln in lines}
    assert marks[rels["f0000100.png"]] is None
    assert marks[rels["f0000200.png"]] == "flagged"
    items = media.select(ctx, images.MODULE.extensions, 1 << 30, Counter(), carved=True)
    assert [i.entry["carved_path"] for i in items] == [rels["f0000100.png"]]
    # No row carries image content.
    blob = json.dumps(rows)
    assert "base64" not in blob and "data:image" not in blob


def test_main_media_pass_leaves_carved_lines_alone(
    run_dir: Path,  # noqa: F811 - fixture
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A resumed images module must not screen (or report) carve's files a second time."""
    no_model(monkeypatch)
    stage_carved(run_dir, {"f0000100.png": NEUTRAL / "landscape.png"})
    inventory_index.write_index(inventory_index.index_path(run_dir), [])
    ctx, rows = media_ctx(run_dir, "images")
    res = images.MODULE.run(ctx)
    assert res.status == "ok" and res.counts.get("files", 0) == 0
    assert rows == []


def test_oversize_carved_image_is_removed_unscreened(
    run_dir: Path,  # noqa: F811 - fixture
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    no_model(monkeypatch)
    rels = stage_carved(run_dir, {"f0000100.png": NEUTRAL / "landscape.png"})
    monkeypatch.setattr(images.ImagesModule, "max_bytes", 10)
    ctx, rows = media_ctx(run_dir, "carve")
    out = media.process_carved(ctx, [images.MODULE])
    assert not (run_dir / rels["f0000100.png"]).exists()
    row = next(r for r in rows if r["artifact_type"] == "carved_media_removed")
    assert row["label"] == "too_large" and row["sha256"] == sha(NEUTRAL / "landscape.png")
    assert out["carved_removed"] == 1
    assert not [r for r in rows if r["artifact_type"].startswith("screen_")]


def test_escalated_run_leaves_carved_files_frozen(
    run_dir: Path,  # noqa: F811 - fixture
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    no_model(monkeypatch)
    rels = stage_carved(run_dir, CARVED)
    (run_dir / "ESCALATED").write_text("{}", encoding="utf-8")
    ctx, rows = media_ctx(run_dir, "carve")
    with pytest.raises(media.Escalated):
        media.process_carved(ctx, [images.MODULE])
    assert all((run_dir / rel).is_file() for rel in rels.values())
    assert rows == []


def test_carve_module_marks_removed_files(
    run_dir: Path,  # noqa: F811 - fixture
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The carve module's own carved_file row says the file was deleted after screening."""
    no_model(monkeypatch)
    rels: dict[str, str] = {}

    def fake_volume(
        ctx: Any, vol: Any, counts: Counter[str], index_lines: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        del vol
        rels.update(stage_carved(ctx.run_dir, {"f0000200.png": NEUTRAL / "shapes-squares.png"}))
        index_lines.extend(inventory_index.iter_files(ctx.run_dir, include_carved=True))
        rel = rels["f0000200.png"]
        counts["carved_images"] += 1
        return [
            {
                "category": "carve",
                "derivation": "observed",
                "artifact_type": "carved_file",
                "message": "File carved by PhotoRec.",
                "source_tool": "photorec",
                "tool_version": "test",
                "parser": "photorec",
                "path": "/" + rel,
                "sha256": sha(NEUTRAL / "shapes-squares.png"),
                "source_record": f"{rel}#0",
            }
        ]

    monkeypatch.setattr(carve, "carve_volume", fake_volume)
    ctx, rows = media_ctx(run_dir, "carve", options={"preset": "full", "full": True})
    res = carve.MODULE.run(ctx)
    assert res.status == "ok", res.reason
    cf = next(r for r in rows if r["artifact_type"] == "carved_file")
    assert "Deleted after screening (flagged)" in cf["message"]
    assert "source_record" not in cf or cf["source_record"] is None
    assert not (run_dir / rels["f0000200.png"]).exists()
    assert res.counts["media_carved_removed"] == 1
