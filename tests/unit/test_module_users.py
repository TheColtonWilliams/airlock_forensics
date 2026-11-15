"""Module users (4C.13): owner account SIDs, LNK files, Jump Lists; LECmd cross-check."""

from __future__ import annotations

import os
import shutil
from pathlib import Path
from typing import Any

import pytest
from test_parsers_ntfs_fixture import build_ntfs_image, make_ctx, ntfs_tools_ok, stub_tool

from forensic_analyze.modules import inventory, users


@pytest.fixture(scope="module")
def image(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, dict[str, Any]]:
    why = ntfs_tools_ok()
    if why:
        pytest.skip(why)
    img = tmp_path_factory.mktemp("users") / "fixture.img"
    return img, build_ntfs_image(img)


def run(img: Path, run_dir: Path) -> tuple[Any, list[dict]]:
    shared: dict[str, Any] = {}
    ctx, _ = make_ctx(img, run_dir, "inventory", shared=shared)
    assert inventory.MODULE.run(ctx).status == "ok"
    ctx, rows = make_ctx(img, run_dir, "users", shared=shared)
    return users.MODULE.run(ctx), rows


def test_owner_sids_from_sds(image: tuple[Path, dict], tmp_path: Path) -> None:
    img, _ = image
    res, rows = run(img, tmp_path / "run")
    assert res.status == "ok"
    owners = [r for r in rows if r["artifact_type"] == "owner_sid_summary"]
    # mkfs.ntfs gives the NTFS system files to the Administrators group SID.
    assert any(r["owner_sid"] == "S-1-5-32-544" for r in owners)
    for r in rows:
        assert "person" not in r["message"].lower() or "not which person" in r["message"]
    for r in owners:
        assert r["message"].startswith(f"Account SID {r['owner_sid']}")
    listing = (tmp_path / "run" / "modules" / "users" / "owners-v0.jsonl").read_text()
    assert "S-1-5-32-544" in listing
    summary = [r for r in rows if r.get("inode_ref") == "v0:owners" and r["category"] == "xval"]
    assert len(summary) == 1
    if shutil.which("target-query"):
        assert "disagree" in summary[0]["message"] and " 0 disagree" in summary[0]["message"]


def test_lnk_target_and_times(image: tuple[Path, dict], tmp_path: Path) -> None:
    img, truth = image
    _, rows = run(img, tmp_path / "run")
    want = truth["lnk"]
    files = [r for r in rows if r["artifact_type"] == "lnk_file"]
    assert len(files) == 1
    f = files[0]
    assert f["path"] == want["path"]
    assert f"target: {want['target']}" in f["text"]
    assert f"volume serial: {want['serial']}" in f["text"]
    assert f["size_bytes"] == 4321
    assert f["xval_status"] == "single_source"
    times = {
        r["timestamp_desc"]: r["datetime"] for r in rows if r["artifact_type"] == "lnk_target_time"
    }
    assert times == {
        "Creation Time (LNK target)": want["times"]["created"],
        "Content Modification Time (LNK target)": want["times"]["modified"],
        "Last Access Time (LNK target)": want["times"]["accessed"],
    }


def test_jumplists_reported_when_jlecmd_missing(image: tuple[Path, dict], tmp_path: Path) -> None:
    if shutil.which("JLECmd"):
        pytest.skip("JLECmd installed here")
    img, _ = image
    _, rows = run(img, tmp_path / "run")
    jl = [r for r in rows if r["artifact_type"] == "jumplist_not_parsed"]
    assert len(jl) == 1 and "1 Jump List files found" in jl[0]["message"]


LECMD_STUB = r"""
import csv, sys
from pathlib import Path
args = sys.argv[1:]
src = Path(args[args.index("-d") + 1])
out = Path(args[args.index("--csv") + 1]) / args[args.index("--csvf") + 1]
with open(out, "w", newline="", encoding="utf-8") as fh:
    w = csv.writer(fh)
    w.writerow(["SourceFile", "LocalPath", "TargetModified"])
    for f in sorted(src.rglob("*.lnk")):
        w.writerow([str(f), "C:\\Users\\Test\\Documents\\report.txt", "2026-10-02 12:15:30"])
"""

JLECMD_STUB = r"""
import csv, sys
from pathlib import Path
args = sys.argv[1:]
src = Path(args[args.index("-d") + 1])
out = Path(args[args.index("--csv") + 1]) / args[args.index("--csvf") + 1]
with open(out, "w", newline="", encoding="utf-8") as fh:
    w = csv.writer(fh)
    w.writerow(["SourceFile", "LocalPath", "LastModified"])
    for f in sorted(src.rglob("*.automaticDestinations-ms")):
        w.writerow([str(f), "C:\\Users\\Test\\Documents\\plan.txt", "2026-10-05 01:02:03.1234567"])
"""


def test_lecmd_and_jlecmd_when_installed(
    image: tuple[Path, dict], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    img, _ = image
    stub_tool(tmp_path / "bin", "LECmd", LECMD_STUB)
    stub_tool(tmp_path / "bin", "JLECmd", JLECMD_STUB)
    monkeypatch.setenv("PATH", f"{tmp_path / 'bin'}:{os.environ['PATH']}")
    _, rows = run(img, tmp_path / "run")
    f = next(r for r in rows if r["artifact_type"] == "lnk_file")
    assert f["xval_status"] == "agree"
    summary = next(r for r in rows if r.get("inode_ref") == "v0:lnk")
    assert "1 agree" in summary["message"]
    jl = [r for r in rows if r["artifact_type"] == "jumplist_entry"]
    assert len(jl) == 1
    assert jl[0]["datetime"] == "2026-10-05T01:02:03.1234567Z"
    assert "plan.txt" in jl[0]["text"]


def test_describe_sid_never_names_people() -> None:
    assert users.describe_sid("S-1-5-18") == "built-in Local System account"
    assert "account" in users.describe_sid("S-1-5-21-1-2-3-1001")
    assert "RID 500" in users.describe_sid("S-1-5-21-1-2-3-500")
