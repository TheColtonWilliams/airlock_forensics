"""Write tracer arithmetic on fake block stat files (task 3A.5; the real counter test is
tests/functional/test_tracer.sh)."""

from __future__ import annotations

from pathlib import Path

from forensic_analyze import tracer

LINE = "{r} 0 {rs} 10 {w} 0 {ws} 5 0 20 30 {d} 0 {ds} 1 {f} 2\n"


def _write(
    p: Path, *, r: int = 0, w: int = 0, ws: int = 0, d: int = 0, ds: int = 0, f: int = 0
) -> None:
    p.write_text(LINE.format(r=r, rs=r * 8, w=w, ws=ws, d=d, ds=ds, f=f))


def test_parse_stat_fields() -> None:
    c = tracer.parse_stat(LINE.format(r=5, rs=40, w=3, ws=24, d=2, ds=16, f=1))
    assert c["read_ios"] == 5 and c["write_ios"] == 3 and c["write_sectors"] == 24
    assert c["discard_ios"] == 2 and c["discard_sectors"] == 16 and c["flush_ios"] == 1
    old_kernel = tracer.parse_stat("1 0 8 1 2 0 16 1 0 2 2")
    assert old_kernel["write_ios"] == 2 and old_kernel["discard_ios"] == 0


def test_counts_writes_discards_and_flushes(tmp_path: Path) -> None:
    dev = tmp_path / "sdz"
    dev.mkdir()
    stat = dev / "stat"
    _write(stat, r=10)
    tr = tracer.WriteTracer("/dev/sdz", sys_root=tmp_path)
    assert tr.result.method == "block_stat"
    tr.start()
    _write(stat, r=500, w=4, ws=32, d=1, ds=2048, f=1)
    res = tr.stop()
    assert res.delta["write_ios"] == 4 and res.delta["discard_ios"] == 1
    assert res.write_requests == 6 and res.clean is False
    assert res.to_dict()["expected"] == 0


def test_reads_only_is_clean(tmp_path: Path) -> None:
    (tmp_path / "sdz").mkdir()
    stat = tmp_path / "sdz" / "stat"
    _write(stat, r=1)
    tr = tracer.WriteTracer("/dev/sdz", sys_root=tmp_path)
    tr.start()
    _write(stat, r=99999)
    assert tr.stop().write_requests == 0 and tr.result.clean is True


def test_file_target_and_missing_device(tmp_path: Path) -> None:
    na = tracer.WriteTracer(None)
    na.start()
    assert na.stop().method == "not_applicable" and na.result.clean is None
    gone = tracer.WriteTracer("/dev/nothere", sys_root=tmp_path)
    gone.start()
    res = gone.stop()
    assert res.method == "unavailable" and res.write_requests is None


def test_trace_device_for() -> None:
    assert tracer.trace_device_for("/dev/sdb", "device", None) == "/dev/sdb"
    assert tracer.trace_device_for("/x.img", "image", "/dev/loop3") == "/dev/loop3"
    assert tracer.trace_device_for("/x.img", "image", None) is None
