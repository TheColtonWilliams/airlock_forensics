"""Module inventory (4C.5), its cross-check (4C.28), NTFS interpretation (4C.27), VSS (4C.29)."""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

import pytest
from test_parsers_ntfs_fixture import build_ntfs_image, make_ctx, ntfs_tools_ok, stub_tool

from forensic_analyze import ntfs_interp
from forensic_analyze.inventory_index import KEYS, available, iter_files
from forensic_analyze.modules import inventory
from forensic_analyze.parsers import filetime
from forensic_analyze.parsers.mft import FileName, MftIndex, MftRecord

HAVE_DISSECT = shutil.which("target-query") is not None


@pytest.fixture(scope="module")
def image(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, dict[str, Any]]:
    why = ntfs_tools_ok()
    if why:
        pytest.skip(why)
    img = tmp_path_factory.mktemp("inv") / "fixture.img"
    return img, build_ntfs_image(img)


def run_inventory(img: Path, run: Path, **kw: Any) -> tuple[Any, list[dict[str, Any]]]:
    ctx, rows = make_ctx(img, run, "inventory", **kw)
    return inventory.MODULE.run(ctx), rows


def test_deleted_files_found_by_every_parser(image: tuple[Path, dict], tmp_path: Path) -> None:
    img, truth = image
    res, rows = run_inventory(img, tmp_path / "run")
    assert res.status == "ok", res.reason
    entries = [r for r in rows if r["artifact_type"] == "file_entry"]
    parsers = {"tsk", "dissect"} if HAVE_DISSECT else {"tsk"}
    for path in truth["deleted"]:
        seen = {r["parser"] for r in entries if r.get("path") == path}
        assert parsers <= seen, (path, seen)
        for r in entries:
            if r.get("path") == path:
                assert r["allocated"] is False
                assert r["derivation"] == "observed"
                assert r["inode_ref"].startswith("v0:")
                assert r["xval_status"] == ("agree" if HAVE_DISSECT else "single_source")
    for path in truth["live"]:
        assert any(r.get("path") == path and r["allocated"] for r in entries)
    assert any(r.get("path") == truth["ads"] for r in entries), "alternate data stream listed"


def test_index_written_for_other_modules(image: tuple[Path, dict], tmp_path: Path) -> None:
    img, truth = image
    run = tmp_path / "run"
    run_inventory(img, run)
    assert available(run)
    lines = list(iter_files(run))
    for line in lines:
        assert set(KEYS) <= set(line)
    by_path = {ln["path"]: ln for ln in lines}
    for path in truth["deleted"]:
        assert by_path[path]["deleted"] is True
        assert by_path[path]["allocated"] is False
    assert by_path["/Docs/keep.txt"]["size_bytes"] == 6
    assert by_path["/Docs/keep.txt"]["mtime"].endswith("Z")
    lnks = list(iter_files(run, extensions=["LNK"]))
    assert [ln["path"] for ln in lnks] == [truth["lnk"]["path"]]
    # The ADS "keep.txt:extra" is not a .txt file for consumers filtering on extensions.
    txt = {ln["path"] for ln in iter_files(run, extensions=[".txt"])}
    assert "/Docs/keep.txt" in txt and truth["ads"] not in txt
    raw = (run / "modules" / "inventory" / "files.jsonl").read_text().splitlines()
    assert raw == sorted(
        raw,
        key=lambda s: (
            json.loads(s)["volume_index"],
            json.loads(s)["path"],
            json.loads(s)["inode"],
        ),
    )


def test_rows_are_deterministic(image: tuple[Path, dict], tmp_path: Path) -> None:
    img, _ = image
    _, a = run_inventory(img, tmp_path / "a")
    _, b = run_inventory(img, tmp_path / "b")
    assert a == b


def test_vss_none_found_is_explicit(image: tuple[Path, dict], tmp_path: Path) -> None:
    img, _ = image
    _, rows = run_inventory(img, tmp_path / "run")
    vss = [r for r in rows if r["artifact_type"] == "vss_check"]
    assert len(vss) == 1
    assert "no Volume Shadow Copies found" in vss[0]["message"]


def test_xval_summary_names_missing_mftecmd(
    image: tuple[Path, dict], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    img, _ = image
    monkeypatch.setenv("PATH", "/usr/bin:/bin:/usr/local/bin")
    if shutil.which("MFTECmd"):
        pytest.skip("MFTECmd is installed here")
    _, rows = run_inventory(img, tmp_path / "run")
    summary = [r for r in rows if r["artifact_type"] == "xval_summary"]
    assert len(summary) == 1
    assert "mftecmd: not installed" in summary[0]["text"]


MFTECMD_STUB = r"""
import csv, sys
from pathlib import Path
args = sys.argv[1:]
out = Path(args[args.index("--csv") + 1]) / args[args.index("--csvf") + 1]
cols = ["EntryNumber", "SequenceNumber", "InUse", "ParentPath", "FileName", "FileSize",
        "IsDirectory", "IsAds", "Created0x10", "LastModified0x10"]
rows = [
    # keep.txt with a wrong size (a planted disagreement), gone.txt as it is.
    ["{keep}", "{keepseq}", "True", ".\\Docs", "keep.txt", "999", "False", "False", "", ""],
    ["{gone}", "{goneseq}", "False", ".\\Docs", "gone.txt", "17", "False", "False", "", ""],
]
with open(out, "w", newline="", encoding="utf-8") as fh:
    w = csv.writer(fh)
    w.writerow(cols)
    w.writerows(rows)
"""


def test_mftecmd_rows_and_disagreements(
    image: tuple[Path, dict], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    img, _ = image
    first, _ = make_ctx(img, tmp_path / "probe", "inventory")
    from forensic_analyze import extract  # noqa: PLC0415

    vol = first.target.volumes[0]
    idx = extract.load_mft_index(first, vol)
    keep = next(e for e, r in idx.records.items() if idx.path_of(e) == "/Docs/keep.txt")
    gone = next(e for e, r in idx.records.items() if idx.path_of(e) == "/Docs/gone.txt")
    body = MFTECMD_STUB.format(
        keep=keep, keepseq=idx.get(keep).seq, gone=gone, goneseq=idx.get(gone).seq
    )
    stub_tool(tmp_path / "bin", "MFTECmd", body)
    monkeypatch.setenv("PATH", f"{tmp_path / 'bin'}:{__import__('os').environ['PATH']}")
    res, rows = run_inventory(img, tmp_path / "run")
    assert res.status == "ok"
    mrows = [r for r in rows if r["parser"] == "mftecmd"]
    assert {r["path"] for r in mrows} == {"/Docs/keep.txt", "/Docs/gone.txt"}
    gone_m = next(r for r in mrows if r["path"] == "/Docs/gone.txt")
    assert gone_m["allocated"] is False and gone_m["xval_status"] == "agree"
    dis = [r for r in rows if r["artifact_type"] == "xval_disagreement"]
    assert len(dis) == 1
    assert dis[0]["path"] == "/Docs/keep.txt"
    assert "size" in dis[0]["message"] and "mftecmd=999" in dis[0]["text"]
    assert "tsk=6" in dis[0]["text"]
    keep_rows = [r for r in rows if r.get("path") == "/Docs/keep.txt" and "parser" in r]
    assert all(
        r.get("xval_status") == "disagree" for r in keep_rows if r["category"] == "inventory"
    )


def test_exfat_is_not_applicable() -> None:
    from forensic_analyze.api import Target, Volume  # noqa: PLC0415

    t = Target(Path("/x"), "image", "E", volumes=(Volume(0, 0, 1, "exfat"),))
    ok, why = inventory.MODULE.applicable(t)
    assert not ok and "ntfs" in why


# -- 4C.27: inferred NTFS rows on synthetic records ------------------------------------------


def _rec(entry: int, si: tuple[int, int, int, int], fn_created: int) -> MftRecord:
    rec = MftRecord(entry=entry, seq=1, flags=1, base_entry=0, base_seq=0, link_count=1, lsn=0)
    rec.si_created, rec.si_modified, rec.si_changed, rec.si_accessed = si
    rec.has_si = True
    rec.names.append(FileName(5, 5, f"f{entry}.txt", 1, fn_created, 0, 0, 0, 0))
    return rec


def test_ntfs_interp_rows_are_inferred() -> None:
    t0 = 134_000_000_000_000_000
    frac = 1_234_567
    idx = MftIndex(
        {
            5: MftRecord(entry=5, seq=5, flags=3, base_entry=0, base_seq=0, link_count=1, lsn=0),
            # SI created a year before FN created.
            100: _rec(100, (t0, t0 + frac, t0 + frac, t0 + frac), t0 + 315_360_000_000_000),
            # Every SI time on a whole second.
            101: _rec(101, (t0, t0 + 10**7, t0 + 2 * 10**7, t0 + 3 * 10**7), t0),
            # Ordinary file.
            102: _rec(102, (t0 + frac, t0 + frac, t0 + frac, t0 + frac), t0 + frac),
        }
    )
    rows = ntfs_interp.interpret_mft(
        idx, volume_index=0, source_record="extract/v0/MFT", owner_of=lambda r: "S-1-5-18"
    )
    kinds = {(r["artifact_type"], r["path"]) for r in rows}
    assert kinds == {
        ("ntfs_si_before_fn", "/f100.txt"),
        ("ntfs_si_zero_fraction", "/f101.txt"),
    }
    for r in rows:
        assert r["derivation"] == "inferred"
        assert "account SID S-1-5-18" in r["message"]
        assert "person" not in r["message"].lower()
        assert r["datetime"].endswith("Z")
    assert rows[0]["datetime"] == filetime.to_iso(t0)


# -- 4C.29: the VSS check's parsers --------------------------------------------------------

VSHADOWINFO_TWO = """vshadowinfo 20190323

Volume Shadow Snapshot information:
\tNumber of stores:\t2

Store: 1
\tIdentifier\t\t: 600f0f7e-0000-0000-0000-000000000001
\tCreation time\t\t: Jun 01, 2020 10:11:12.123456700 UTC

Store: 2
\tIdentifier\t\t: 600f0f7e-0000-0000-0000-000000000002
\tCreation time\t\t: Jun 02, 2020 01:02:03.000000000 UTC
"""


def test_vshadowinfo_output() -> None:
    assert inventory.parse_vshadowinfo("No Volume Shadow Snapshots found.\n") == (0, [])
    assert inventory.parse_vshadowinfo(VSHADOWINFO_TWO) == (
        2,
        ["2020-06-01T10:11:12.123456700Z", "2020-06-02T01:02:03.000000000Z"],
    )
    assert inventory.parse_vshadowinfo("garbage") == (None, [])


def test_vss_header_bytes() -> None:
    import struct  # noqa: PLC0415

    block = bytearray(4096)
    within = 0x1E00 % 4096
    head = inventory.VSS_GUID + struct.pack("<IIQQQQ", 1, 1, 0, 0, 0, 0x1E0000)
    block[within : within + len(head)] = head
    assert inventory.parse_vss_header(bytes(block), within) == (True, 0x1E0000)
    assert inventory.parse_vss_header(bytes(4096), within) == (False, None)


# ---------------------------------------------------------------------------------------------
# Bounded mode: the Dissect cross-check has a file-count limit and a time budget (scale).
# ---------------------------------------------------------------------------------------------


def test_dissect_plan_and_settings(airlock_env: Path) -> None:
    lim = inventory.DissectLimits(max_files=100, budget_s=3600)
    assert inventory.dissect_plan(100, lim) == ""
    assert "more than the limit of 100" in inventory.dissect_plan(101, lim)
    # 300 000 files at 57 ms is about 4.75 h: over the default limit and budget.
    assert "limit of 50000" in inventory.dissect_plan(300_000, inventory.DissectLimits())
    budget_only = inventory.DissectLimits(max_files=0, budget_s=60)
    assert "time budget of 1 min" in inventory.dissect_plan(5000, budget_only)
    assert inventory.dissect_plan(5000, inventory.DissectLimits(max_files=0, budget_s=0)) == ""
    # Defaults, then airlock.conf.json, then the run options.
    assert inventory.dissect_limits({}) == inventory.DissectLimits()
    conf = airlock_env / "etc" / "airlock.conf.json"
    conf.write_text(json.dumps({"inventory": {"dissect_max_files": 7}}), encoding="utf-8")
    got = inventory.dissect_limits({})
    assert (got.max_files, got.budget_s, got.source) == (7, 3600.0, str(conf))
    got = inventory.dissect_limits({"dissect_budget_s": 5})
    assert (got.max_files, got.budget_s, got.source) == (7, 5.0, "run options")
    assert inventory.dissect_limits({"dissect_max_files": "x"}).max_files == 7  # bad value ignored


def test_dissect_crosscheck_skipped_above_limit(
    image: tuple[Path, dict], tmp_path: Path, airlock_env: Path
) -> None:
    """A small threshold leaves Dissect out; TSK stays complete; the limit is stated."""
    from evidence_report.render import coverage_limits  # noqa: PLC0415

    img, truth = image
    run = tmp_path / "run"
    events: list[dict[str, Any]] = []
    ctx, rows = make_ctx(img, run, "inventory", options={"preset": "quick", "dissect_max_files": 2})
    object.__setattr__(ctx, "log", lambda event, **f: events.append({"event": event, **f}))
    res = inventory.MODULE.run(ctx)
    assert res.status == "ok", res.reason
    entries = [r for r in rows if r["artifact_type"] == "file_entry"]
    assert {r["parser"] for r in entries} <= {"tsk", "mftecmd"}  # no Dissect rows
    for path in truth["deleted"] + truth["live"]:
        assert any(r.get("path") == path and r["parser"] == "tsk" for r in entries), path
    assert not (run / "modules" / "inventory" / "dissect-mft.jsonl").exists()
    limit = [r for r in rows if r["artifact_type"] == "coverage_limit"]
    assert len(limit) == 1 and limit[0]["category"] == "xval"
    assert (
        "Coverage limit" in limit[0]["message"]
        and "more than the limit of 2" in (limit[0]["message"])
    )
    summary = next(r for r in rows if r["artifact_type"] == "xval_summary")
    assert "dissect: left out (coverage limit)" in summary["text"]
    assert res.counts["dissect_crosscheck_limited"] == 1
    assert res.counts["dissect_crosscheck_files"] > 2
    marker = run / "modules" / "inventory" / "dissect-mft.jsonl.limited"
    assert json.loads(marker.read_text(encoding="utf-8"))["max_files"] == 2
    ev = [e for e in events if e["event"] == "coverage_limit"]
    assert len(ev) == 1 and ev[0]["parser"] == "dissect"
    # What the runner puts in run.json reaches the report's limitations section.
    lines = coverage_limits({"module_events": {"inventory": [{"ts": "x", **ev[0]}]}})
    assert lines and lines[0].startswith("inventory, inventory cross-check: ")
    # The users module does not run the same whole-target query either.
    from forensic_analyze import extract  # noqa: PLC0415
    from forensic_analyze.modules import users  # noqa: PLC0415

    uctx, _ = make_ctx(img, run, "users")
    assert extract.dissect_mft_limit(run)["files"] == res.counts["dissect_crosscheck_files"]
    dis, why = users.dissect_owner_table(uctx, uctx.target.volumes[0])
    assert dis is None and why.startswith("left out (coverage limit")


def test_dissect_crosscheck_stopped_at_budget(
    image: tuple[Path, dict], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    img, truth = image
    stubs = tmp_path / "stubs"
    stub_tool(stubs, "target-query", "import time\nprint('{}')\ntime.sleep(30)\n")
    monkeypatch.setenv("PATH", f"{stubs}:/usr/bin:/bin")
    opts = {"preset": "quick", "dissect_max_files": 0, "dissect_budget_s": 1}
    res, rows = run_inventory(img, tmp_path / "run", options=opts)
    assert res.status == "ok", res.reason
    limit = [r for r in rows if r["artifact_type"] == "coverage_limit"]
    assert len(limit) == 1 and "time budget" in limit[0]["message"]
    assert not (tmp_path / "run" / "modules" / "inventory" / "dissect-mft.jsonl").exists()
    entries = [r for r in rows if r["artifact_type"] == "file_entry"]
    for path in truth["deleted"]:
        assert any(r.get("path") == path and r["parser"] == "tsk" for r in entries), path
    assert not [r for r in rows if r["artifact_type"] == "parser_error"]
