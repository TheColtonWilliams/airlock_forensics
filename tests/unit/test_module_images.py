"""Module ``images`` (4C.8) and the shared media machinery (4B.17, 4G.10).

Also holds the helpers the other media-module tests import (``media_ctx``, ``stage_inventory``,
``llama_stub``): a ModuleContext whose ``emit`` validates every row against schema.json, an
inventory index written with the real ``inventory_index.write_index``, ``export_file`` replaced
by a copy from the fixture folder, and the stub model server on 127.0.0.1.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import struct
import subprocess
import sys
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from airlock_ai import config as cfgmod
from airlock_ai import llm, thumbcount
from airlock_common import proc
from forensic_analyze import extract, findings, inventory_index
from forensic_analyze.api import ModuleContext, Target, Volume
from forensic_analyze.modules import images

REPO = Path(__file__).resolve().parents[2]
AI_FIX = REPO / "tests" / "fixtures" / "ai"
NEUTRAL = AI_FIX / "neutral"
STUB_SCORES = AI_FIX / "stub-scores.json"
RUN_ID = "R-20261115T000000Z-a1b2c3"
EVIDENCE_SHA = "e" * 64


def sha(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def tool_runner(workdir: Path) -> Any:
    """ctx.tool stand-in: no sandbox, same keyword arguments, never raises on exit status."""

    def run(argv: list[str], **kw: Any) -> subprocess.CompletedProcess[str]:
        res = proc.run(
            [str(a) for a in argv],
            check=False,
            timeout=kw.get("timeout"),
            stdout_path=kw.get("stdout_path"),
            cwd=workdir,
        )
        return subprocess.CompletedProcess(res.argv, res.returncode, res.stdout, res.stderr)

    return run


def media_ctx(
    run_dir: Path, module: str, *, options: dict | None = None, events: list | None = None
) -> tuple[ModuleContext, list[dict[str, Any]]]:
    rows: list[dict[str, Any]] = []
    workdir = run_dir / "modules" / module
    workdir.mkdir(parents=True, exist_ok=True)

    def emit(row: dict[str, Any]) -> None:
        full = findings.normalise_row(row)
        full.update(run_id=RUN_ID, evidence_id="EX-1", evidence_sha256=EVIDENCE_SHA)
        errors = findings.validate_row(full, part=True)
        assert not errors, (errors, row)
        rows.append(full)

    def log(event: str, **fields: Any) -> None:
        if events is not None:
            events.append({"event": event, **fields})

    ctx = ModuleContext(
        run_id=RUN_ID,
        module=module,
        target=Target(
            path=run_dir / "evidence.img",
            kind="image",
            evidence_id="EX-1",
            volumes=(Volume(0, 0, 1 << 20, "ntfs"),),
        ),
        run_dir=run_dir,
        workdir=workdir,
        options=options or {"preset": "standard"},
        emit=emit,
        tool=tool_runner(workdir),
        log=log,
        tool_version=lambda name: f"{name} test",
        shared={},
    )
    return ctx, rows


def stage_inventory(
    run_dir: Path,
    files: dict[str, Path],
    monkeypatch: pytest.MonkeyPatch,
    *,
    deleted: set[str] = frozenset(),
) -> dict[str, str]:
    """Index ``{evidence path: fixture file}``; export_file copies the fixture. Returns
    ``{evidence path: inode}``."""
    entries, by_inode, inodes = [], {}, {}
    for i, (path, src) in enumerate(sorted(files.items())):
        inode = f"{100 + i}-128-1"
        by_inode[inode] = src
        inodes[path] = inode
        entries.append(
            {
                "volume_index": 0,
                "inode": inode,
                "path": path,
                "size_bytes": src.stat().st_size,
                "allocated": path not in deleted,
                "deleted": path in deleted,
                "mtime": None,
                "atime": None,
                "ctime": None,
                "crtime": None,
                "inode_ref": f"v0:{100 + i}-1",
            }
        )
    inventory_index.write_index(inventory_index.index_path(run_dir), entries)

    def fake_export(
        ctx: ModuleContext,
        volume: Volume,
        inode: str,
        dest_dir: Any,
        *,
        name: str | None = None,
        recover: bool = False,
    ) -> Path:
        del recover
        dest = Path(dest_dir)
        assert ctx.run_dir in dest.parents  # exports stay inside the run folder
        dest.mkdir(parents=True, exist_ok=True)
        out = dest / (name or f"v{volume.index}_{inode}")
        shutil.copyfile(by_inode[str(inode)], out)
        return out

    monkeypatch.setattr(extract, "export_file", fake_export)
    return inodes


class LlamaStub:
    def __init__(self, url: str, log: Path, model: Path) -> None:
        self.url, self.log, self.model = url, log, model

    def requests(self) -> list[dict]:
        if not self.log.exists():
            return []
        return [json.loads(x) for x in self.log.read_text(encoding="utf-8").splitlines()]


def llama_stub(
    tmp: Path, monkeypatch: pytest.MonkeyPatch, mode: str = "describe"
) -> Iterator[LlamaStub]:
    model = tmp / "stub-model.gguf"
    model.write_bytes(b"GGUF stub")
    port_file, log = tmp / "stub.port", tmp / "stub-requests.jsonl"
    p = subprocess.Popen(
        [
            sys.executable,
            str(AI_FIX / "stub_llama_server.py"),
            "--port-file",
            str(port_file),
            "--log",
            str(log),
            "--model-file",
            str(model),
            "--mode",
            mode,
        ]
    )
    for _ in range(100):
        if port_file.exists() and port_file.read_text(encoding="ascii"):
            break
        time.sleep(0.05)
    url = f"http://127.0.0.1:{port_file.read_text(encoding='ascii')}"
    monkeypatch.setenv(llm.URL_ENV, url)
    monkeypatch.setenv(llm.NO_START_ENV, "1")
    monkeypatch.setenv(llm.RUN_DIR_ENV, str(tmp / "no-run-dir"))
    try:
        yield LlamaStub(url, log, model)
    finally:
        p.terminate()
        p.wait(timeout=10)


@pytest.fixture
def stub_llm(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[LlamaStub]:
    d = tmp_path / "llm"
    d.mkdir()
    yield from llama_stub(d, monkeypatch)


@pytest.fixture
def run_dir(airlock_env: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv("AIRLOCK_SCREEN_BACKEND", f"stub:{STUB_SCORES}")
    d = airlock_env / "output" / "cases" / "C1" / RUN_ID
    (d / "modules").mkdir(parents=True)
    return d


IMAGES = {
    "/Users/u/Pictures/landscape.png": NEUTRAL / "landscape.png",
    "/Users/u/Pictures/shapes-squares.png": NEUTRAL / "shapes-squares.png",  # stub: flagged
    "/Users/u/Pictures/text-render.png": NEUTRAL / "text-render.png",  # stub: cannot score
    "/Users/u/Pictures/=cmd|calc.png": NEUTRAL / "shapes-circle.png",
}


def _by(rows: list[dict], artifact: str) -> dict[str, list[dict]]:
    out: dict[str, list[dict]] = {}
    for r in rows:
        if r["artifact_type"] == artifact:
            out.setdefault(r.get("path", ""), []).append(r)
    return out


def test_images_flagged_never_kept_or_described(run_dir: Path, monkeypatch, stub_llm: LlamaStub):
    stage_inventory(run_dir, IMAGES, monkeypatch, deleted={"/Users/u/Pictures/landscape.png"})
    events: list = []
    ctx, rows = media_ctx(run_dir, "images", events=events)
    res = images.MODULE.run(ctx)
    assert res.status == "ok", res.reason
    assert res.counts["files"] == 4
    assert (res.counts["cleared"], res.counts["flagged"], res.counts["not_screened"]) == (2, 1, 1)
    kept = sorted(p.name for p in (ctx.workdir / "export").iterdir() if p.is_file())
    assert kept == ["v0_100-128-1.png", "v0_101-128-1.png"]  # the two cleared files only
    assert not (ctx.workdir / "export" / ".pending").exists()
    # The model saw the cleared files and nothing else.
    sent = {i for r in stub_llm.requests() for i in r["images"]}
    assert sent == {sha(NEUTRAL / "landscape.png"), sha(NEUTRAL / "shapes-circle.png")}
    # Screening rows: AI-generated, with score, label, threshold, flag, model and prompt hashes.
    nud = _by(rows, "screen_nudity")
    flagged = nud["/Users/u/Pictures/shapes-squares.png"][0]
    assert flagged["sensitive_flag"] is True and flagged["derivation"] == "ai_generated"
    assert flagged["score"] == pytest.approx(0.91) and flagged["threshold"] == 0.30
    assert "not kept, not described" in flagged["message"]
    assert len(flagged["model_sha256"]) == 64 and len(flagged["prompt_sha256"]) == 64
    assert "/Users/u/Pictures/text-render.png" in _by(rows, "screen_error")
    desc = _by(rows, "ai_image")
    assert set(desc) == {"/Users/u/Pictures/landscape.png", "/Users/u/Pictures/=cmd|calc.png"}
    d = desc["/Users/u/Pictures/landscape.png"][0]
    assert d["message"].startswith("AI-generated") and d["model_sha256"] == sha(stub_llm.model)
    assert d["prompt_sha256"] == cfgmod.load_prompt("describe_image").sha256
    assert d["allocated"] is False
    assert not any(r["artifact_type"] == "ai_image" and r.get("sensitive_flag") for r in rows)
    assert any(e["event"] == "model_used" for e in events)
    # No row carries image bytes or a thumbnail.
    blob = json.dumps(rows)
    assert "base64" not in blob and "data:image" not in blob


def test_images_without_model_still_screens(run_dir: Path, monkeypatch):
    monkeypatch.setenv(llm.URL_ENV, "http://127.0.0.1:9")  # nothing listens
    monkeypatch.setenv(llm.NO_START_ENV, "1")
    stage_inventory(run_dir, IMAGES, monkeypatch)
    ctx, rows = media_ctx(run_dir, "images")
    res = images.MODULE.run(ctx)
    assert res.status == "ok"
    status = [r for r in rows if r["artifact_type"] == "ai_status"]
    assert len(status) == 1 and "Descriptions skipped for 2 files" in status[0]["message"]
    assert not [r for r in rows if r["artifact_type"] == "ai_image"]


def test_escalated_run_exports_nothing(run_dir: Path, monkeypatch):
    stage_inventory(run_dir, IMAGES, monkeypatch)
    (run_dir / "ESCALATED").write_text("{}", encoding="utf-8")
    ctx, rows = media_ctx(run_dir, "images")
    res = images.MODULE.run(ctx)
    assert res.status == "failed" and "forensic-escalate" in res.reason
    assert not (ctx.workdir / "export").exists()
    assert rows == []


def test_no_inventory_is_skipped(run_dir: Path):
    ctx, _ = media_ctx(run_dir, "images")
    assert images.MODULE.run(ctx).status == "skipped"


def thumbcache_bytes(n: int) -> bytes:
    header = b"CMMM" + struct.pack("<IIIII", 21, 1, 24, 0, n)
    body = b""
    for i in range(n):
        data = b"\x00" * 16 if i % 2 == 0 else b""
        tail = b"\x11" * 8 + struct.pack("<IIII", 0, 0, len(data), 0) + b"\x00" * 16 + data
        body += b"CMMM" + struct.pack("<I", 8 + len(tail)) + tail
    return header + body


def cfb_bytes(streams: list[str]) -> bytes:
    """A minimal OLE compound file: header, one FAT sector, one directory sector."""
    ss = 512
    header = bytearray(ss)
    header[0:8] = thumbcount.CFB_MAGIC
    struct.pack_into("<H", header, 0x1E, 9)
    struct.pack_into("<I", header, 0x2C, 1)  # one FAT sector
    struct.pack_into("<I", header, 0x30, 1)  # directory starts at sector 1
    struct.pack_into("<I", header, 0x44, 0xFFFFFFFE)
    difat = [0] + [0xFFFFFFFF] * 108
    struct.pack_into("<109I", header, 0x4C, *difat)
    fat = [0xFFFFFFFD, 0xFFFFFFFE] + [0xFFFFFFFF] * 126
    fat_sector = struct.pack("<128I", *fat)
    dir_sector = bytearray(ss)
    names = ["Root Entry", *streams]
    for i, name in enumerate(names[:4]):
        enc = (name + "\0").encode("utf-16-le")
        off = i * 128
        dir_sector[off : off + len(enc)] = enc
        struct.pack_into("<H", dir_sector, off + 64, len(enc))
        dir_sector[off + 66] = 5 if i == 0 else 2
    return bytes(header) + fat_sector + bytes(dir_sector)


def test_thumbcount_formats(tmp_path: Path):
    tc = tmp_path / "thumbcache_256.db"
    tc.write_bytes(thumbcache_bytes(3))
    assert thumbcount.count(str(tc))["entries"] == 3
    assert thumbcount.count(str(tc))["entries_with_data"] == 2
    db = tmp_path / "Thumbs.db"
    db.write_bytes(cfb_bytes(["Catalog", "1", "2"]))
    info = thumbcount.count(str(db))
    assert (info["format"], info["entries"]) == ("thumbs.db", 2)
    junk = tmp_path / "junk.db"
    junk.write_bytes(b"CMMM\x15\x00\x00\x00" + b"\xff" * 10)
    assert thumbcount.count(str(junk))["error"] == ""  # damaged: counts what it can, no crash


def test_thumbnail_caches_counted_not_kept(run_dir: Path, monkeypatch, tmp_path: Path):
    tc = tmp_path / "thumbcache_256.db"
    tc.write_bytes(thumbcache_bytes(5))
    db = tmp_path / "Thumbs.db"
    db.write_bytes(cfb_bytes(["Catalog", "1", "2"]))
    stage_inventory(
        run_dir,
        {
            "/Users/u/AppData/Local/Microsoft/Windows/Explorer/thumbcache_256.db": tc,
            "/Users/u/Pictures/Thumbs.db": db,
        },
        monkeypatch,
    )
    monkeypatch.setenv(llm.NO_START_ENV, "1")
    ctx, rows = media_ctx(run_dir, "images")
    res = images.MODULE.run(ctx)
    assert res.counts["thumbcache_files"] == 2 and res.counts["thumbcache_entries"] == 7
    msgs = sorted(r["message"] for r in rows if r["artifact_type"] == "thumbnail_cache")
    assert "Thumbnail cache (thumbcache): 5 entries" in msgs[0] + msgs[1]
    assert all("not extracted or shown" in m for m in msgs)
    leftover = [p for p in (ctx.workdir / "export").rglob("*") if p.is_file()]
    assert leftover == []


@pytest.mark.skipif(shutil.which("exiftool") is None, reason="needs exiftool")
def test_exif_metadata_and_capture_time(run_dir: Path, monkeypatch, tmp_path: Path):
    img = tmp_path / "photo.png"
    shutil.copyfile(NEUTRAL / "landscape.png", img)
    subprocess.run(
        [
            "exiftool",
            "-q",
            "-overwrite_original",
            "-EXIF:DateTimeOriginal=2024:01:02 03:04:05",
            "-EXIF:OffsetTimeOriginal=+02:00",
            str(img),
        ],
        check=True,
    )
    stage_inventory(run_dir, {"/DCIM/photo.png": img}, monkeypatch)
    monkeypatch.setenv(llm.NO_START_ENV, "1")
    monkeypatch.setenv(llm.URL_ENV, "http://127.0.0.1:9")
    ctx, rows = media_ctx(run_dir, "images")
    images.MODULE.run(ctx)
    meta = next(r for r in rows if r["artifact_type"] == "image_metadata")
    assert meta["message"].startswith("Image metadata: PNG, 128x96")
    assert meta["source_record"].startswith("modules/images/metadata/")
    assert (run_dir / meta["source_record"].split("#")[0]).is_file()
    t = next(r for r in rows if r["artifact_type"] == "image_exif_time")
    assert t["datetime"] == "2024-01-02T01:04:05Z" and t["tz_basis"] == "local_with_offset"


def test_media_modules_registered_with_contract_orders():
    from forensic_analyze.modules import all_modules, load_errors  # noqa: PLC0415

    found = {m.name: m.order for m in all_modules()}
    for name, order in {"images": 60, "video": 70, "audio": 80, "documents": 90}.items():
        assert found.get(name) == order, load_errors()
