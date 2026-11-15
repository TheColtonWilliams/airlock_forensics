"""Module deletion_history (4C.7): USN journal, $LogFile honesty, Full-preset carving,
Dissect cross-check (4C.28), and the "$SI change without USN" inference (4C.27).

ntfs-3g (used to build the fixture) does not write a USN journal, and cannot create files in
``$Extend``. So the journal tests seed the run's extraction cache with a journal built byte by
byte (``parsers.usn.build_v2``) whose records point at real entries of the fixture, and the
Dissect side is a stand-in ``target-query`` that prints records in Dissect's JSON format.
``test_parsers_usn.py`` checks the byte layout against Dissect's own USN parser.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from test_parsers_ntfs_fixture import build_ntfs_image, make_ctx, ntfs_tools_ok, stub_tool

from airlock_common import jsonio
from forensic_analyze import extract, ntfs_interp
from forensic_analyze.modules import deletion_history
from forensic_analyze.parsers import filetime, usn
from forensic_analyze.parsers.mft import FileName, MftIndex, MftRecord

CLOSE = 0x80000000


@pytest.fixture(scope="module")
def image(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, dict[str, Any]]:
    why = ntfs_tools_ok()
    if why:
        pytest.skip(why)
    img = tmp_path_factory.mktemp("dh") / "fixture.img"
    return img, build_ntfs_image(img)


def entry_of(img: Path, run: Path, path: str) -> tuple[int, int]:
    ctx, _ = make_ctx(img, run, "probe")
    idx = extract.load_mft_index(ctx, ctx.target.volumes[0])
    e = next(n for n in idx.records if idx.path_of(n) == path)
    return e, idx.get(e).seq


T0 = 134_067_000_001_234_567  # 2025-11-02 (any plausible FILETIME)


def seed_journal(run: Path, records: list[bytes]) -> None:
    d = run / "extract" / "v0"
    d.mkdir(parents=True, exist_ok=True)
    (d / "UsnJrnl_J").write_bytes(b"\0" * 8192 + b"".join(records))
    jsonio.dump_json(d / "UsnJrnl_J.json", {"name": "$UsnJrnl:$J", "seeded_by": "test"})


def journal(img: Path, run: Path) -> dict[str, Any]:
    gone, gone_seq = entry_of(img, run, "/Docs/gone.txt")
    docs, docs_seq = entry_of(img, run, "/Docs")
    keep, keep_seq = entry_of(img, run, "/Docs/keep.txt")
    rec_seq = gone_seq - 1  # the MFT raises the sequence number when the entry is freed
    recs = [
        usn.build_v2(
            entry=gone,
            seq=rec_seq,
            parent_entry=docs,
            parent_seq=docs_seq,
            usn=100,
            timestamp=T0,
            reason=usn.FILE_CREATE,
            name="gone.txt",
        ),
        usn.build_v2(
            entry=gone,
            seq=rec_seq,
            parent_entry=docs,
            parent_seq=docs_seq,
            usn=200,
            timestamp=T0 + 10**7,
            reason=usn.FILE_DELETE | CLOSE,
            name="gone.txt",
        ),
        usn.build_v2(
            entry=keep,
            seq=keep_seq,
            parent_entry=docs,
            parent_seq=docs_seq,
            usn=300,
            timestamp=T0 + 2 * 10**7,
            reason=usn.RENAME_OLD_NAME,
            name="draft.txt",
        ),
        usn.build_v2(
            entry=keep,
            seq=keep_seq,
            parent_entry=docs,
            parent_seq=docs_seq,
            usn=400,
            timestamp=T0 + 2 * 10**7,
            reason=usn.RENAME_NEW_NAME,
            name="keep.txt",
        ),
    ]
    seed_journal(run, recs)
    return {"gone": (gone, rec_seq), "keep": (keep, keep_seq)}


def run_module(img: Path, run: Path, **kw: Any) -> tuple[Any, list[dict]]:
    ctx, rows = make_ctx(img, run, "deletion_history", **kw)
    return deletion_history.MODULE.run(ctx), rows


def no_dissect(monkeypatch: pytest.MonkeyPatch, _tmp: Path) -> None:
    """Hide target-query so a test sees only the built-in parser."""
    monkeypatch.setenv("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")


def test_usn_delete_records_with_full_paths(
    image: tuple[Path, dict], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    img, _ = image
    run = tmp_path / "run"
    refs = journal(img, run)
    no_dissect(monkeypatch, tmp_path)
    res, rows = run_module(img, run)
    assert res.status == "ok"
    deletes = [r for r in rows if r["artifact_type"] == "usn_delete"]
    assert len(deletes) == 1
    d = deletes[0]
    assert d["path"] == "/Docs/gone.txt"
    assert d["filename"] == "gone.txt"
    assert d["inode_ref"] == f"v0:{refs['gone'][0]}-{refs['gone'][1]}"
    assert d["datetime"] == filetime.to_iso(T0 + 10**7)
    assert d["category"] == "deletion" and d["derivation"] == "observed"
    assert "FILE_DELETE" in d["message"]
    assert d["source_record"] == "extract/v0/UsnJrnl_J#usn=200"
    assert d["xval_status"] == "single_source"
    ren = [r for r in rows if r["artifact_type"] == "usn_rename"]
    assert len(ren) == 1
    assert ren[0]["path"] == "/Docs/keep.txt"
    assert "old path: /Docs/draft.txt" in ren[0]["text"]
    summary = next(r for r in rows if r["artifact_type"] == "xval_summary")
    assert "only one parser" in summary["message"]


def test_logfile_is_kept_but_reported_not_parsed(
    image: tuple[Path, dict], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    img, _ = image
    no_dissect(monkeypatch, tmp_path)
    _, rows = run_module(img, tmp_path / "run")
    lf = [r for r in rows if r["artifact_type"] == "logfile_not_parsed"]
    assert len(lf) == 1
    assert "not parsed" in lf[0]["message"]
    assert lf[0]["source_record"] == "extract/v0/LogFile#all"
    assert (tmp_path / "run" / "extract" / "v0" / "LogFile").stat().st_size > 0


def test_missing_journal_is_explicit(
    image: tuple[Path, dict], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    img, _ = image
    no_dissect(monkeypatch, tmp_path)
    _, rows = run_module(img, tmp_path / "run")
    absent = [r for r in rows if r["artifact_type"] == "usn_journal_absent"]
    assert len(absent) == 1
    assert "no USN journal" in absent[0]["message"]


TQ_STUB = r"""
import json, sys
args = sys.argv[1:]
if "usnjrnl" not in args:
    sys.exit(0)
print(json.dumps({"_type": "recorddescriptor", "_data": ["filesystem/ntfs/usnjrnl", []]}))
print(json.dumps({
    "ts": "%(ts)s", "usn": 200, "segment_id": "%(seg)s",
    "path": "\\\\Docs\\gone.txt", "reason": "FILE_DELETE|CLOSE", "security_id": 0,
    "source": "0", "attr": "ARCHIVE", "major": 2, "minor": 0,
    "_type": "record", "_recorddescriptor": ["filesystem/ntfs/usnjrnl", 1]}))
"""


@pytest.mark.parametrize("shift_us", [0, 5_000_000])
def test_dissect_cross_check(
    image: tuple[Path, dict], tmp_path: Path, monkeypatch: pytest.MonkeyPatch, shift_us: int
) -> None:
    img, _ = image
    run = tmp_path / "run"
    refs = journal(img, run)
    when = filetime.to_iso(T0 + 10**7 + shift_us * 10)
    ts = when[:26] + "+00:00"
    stub_tool(
        tmp_path / "bin",
        "target-query",
        TQ_STUB % {"ts": ts, "seg": f"{refs['gone'][0]}#{refs['gone'][1]}"},
    )
    monkeypatch.setenv("PATH", f"{tmp_path / 'bin'}:/usr/sbin:/usr/bin:/sbin:/bin")
    _, rows = run_module(img, run)
    deletes = [r for r in rows if r["artifact_type"] == "usn_delete"]
    assert {r["parser"] for r in deletes} == {"airlock.usn", "dissect.ntfs.usnjrnl"}
    want = "agree" if shift_us == 0 else "disagree"
    assert {r["xval_status"] for r in deletes} == {want}
    dis = [r for r in rows if r["artifact_type"] == "xval_disagreement"]
    assert len(dis) == (0 if shift_us == 0 else 1)
    if dis:
        assert "time" in dis[0]["message"]


def test_full_preset_carves_unallocated(
    image: tuple[Path, dict], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    img, truth = image
    no_dissect(monkeypatch, tmp_path)
    _, rows = run_module(img, tmp_path / "run", options={"preset": "full", "full": True})
    carved = [r for r in rows if r["artifact_type"] == "usn_delete_carved"]
    assert any(r["filename"] == truth["carved_usn_name"] for r in carved), rows
    summary = [r for r in rows if r["artifact_type"] == "usn_carve"]
    assert len(summary) == 1
    _, std = run_module(img, tmp_path / "std")
    assert not [r for r in std if r["artifact_type"].startswith("usn_carve")]


def test_si_change_without_usn_is_inferred() -> None:
    t0 = T0

    def rec(entry: int, changed: int) -> MftRecord:
        r = MftRecord(entry=entry, seq=1, flags=1, base_entry=0, base_seq=0, link_count=1, lsn=0)
        r.si_created = r.si_modified = r.si_accessed = t0 + 1
        r.si_changed = changed
        r.has_si = True
        r.names.append(FileName(5, 5, f"f{entry}", 1, t0 + 1, 0, 0, 0, 0))
        return r

    idx = MftIndex(
        {
            5: MftRecord(entry=5, seq=5, flags=3, base_entry=0, base_seq=0, link_count=1, lsn=0),
            100: rec(100, t0 + 50 * 10**7),  # journal has a record 1 s away: fine
            101: rec(101, t0 + 60 * 10**7),  # inside the window, no record: inferred row
            102: rec(102, t0 + 10**12),  # outside the journal window: no row
        }
    )
    records = [
        usn.parse_record(
            usn.build_v2(
                entry=100,
                seq=1,
                parent_entry=5,
                parent_seq=5,
                usn=1,
                timestamp=t0 + 51 * 10**7,
                reason=usn.BASIC_INFO_CHANGE,
                name="f100",
            )
        ),
        usn.parse_record(
            usn.build_v2(
                entry=7,
                seq=1,
                parent_entry=5,
                parent_seq=5,
                usn=2,
                timestamp=t0,
                reason=usn.FILE_CREATE,
                name="x",
            )
        ),
        usn.parse_record(
            usn.build_v2(
                entry=7,
                seq=1,
                parent_entry=5,
                parent_seq=5,
                usn=3,
                timestamp=t0 + 100 * 10**7,
                reason=CLOSE,
                name="x",
            )
        ),
    ]
    rows = ntfs_interp.interpret_usn(idx, records, volume_index=0, source_record="extract/v0/MFT")
    assert [r["path"] for r in rows] == ["/f101"]
    assert rows[0]["derivation"] == "inferred"
    assert rows[0]["artifact_type"] == "ntfs_si_change_without_usn"
    assert json.dumps(rows[0])  # plain JSON types only
