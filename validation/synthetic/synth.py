#!/usr/bin/env python3
"""Build synthetic NTFS and exFAT validation images with a ground-truth manifest (task 4F.1).

Run through ``validation/synthetic/build.sh`` (needs root, FUSE, ``mkfs.ntfs``, ``ntfs-3g``,
``mkfs.exfat``, ``mount.exfat-fuse`` and libfaketime). Host side only: never on the USB system.

How the times are made known:

* Every file is written through a FUSE driver (``ntfs-3g`` or ``mount.exfat-fuse``) that runs
  under libfaketime. Before each step the builder writes the step's time into the libfaketime
  timestamp file, so the driver stamps the file with that time. Times are planned, then read
  back (NTFS ``$STANDARD_INFORMATION`` through the ``system.ntfs_times`` extended attribute)
  and the read-back values are stored as ground truth. A read-back more than ``TOLERANCE_S``
  from the plan stops the build.
* Steps run in time order and nothing is created after the deletions, so the deleted files'
  MFT entries and clusters are not reused.

Timestomping, three ways (all on NTFS):

* ``ntfs3g_xattr``: ``system.ntfs_times`` set through ``ntfs-3g`` (what ``setfattr`` does).
  Checked on ntfs-3g 2022.10.3: it sets the ``$STANDARD_INFORMATION`` times **and** the
  ``$FILE_NAME`` times in the MFT record, and stamps the change time with the clock. No
  inferred pattern can see it; ground truth marks it ``detectable: false`` (a known limit).
* ``si_raw_whole``: the four ``$STANDARD_INFORMATION`` times are rewritten in the MFT record of
  the unmounted image with whole seconds, earlier than ``$FILE_NAME`` (like tools that call
  ``NtSetInformationFile``). Expected: ``ntfs_si_before_fn`` and ``ntfs_si_zero_fraction``.
* ``si_raw_keep_fraction``: creation, modification and access rewritten with a sub-second part,
  change time kept (like ``SetFileTime``). Expected: ``ntfs_si_before_fn``.

Recycle bin entries are Windows-format ``$I``/``$R`` pairs (version 2 and version 1), written by
this file's own encoder, not by the parser under test.

Every file is generated text or generated shapes. No real user data, no media of people.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import time
import zlib
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

GENERATOR = "validation/synthetic/synth.py 1"
SCHEMA = 1
TOLERANCE_S = 2
SID = "S-1-5-21-4001-4002-4003-1001"
WIN_USER_DIR = "C:\\Users\\TestUser\\Documents"
EPOCH_1601 = dt.datetime(1601, 1, 1, tzinfo=dt.UTC)
TICKS = 10_000_000
FAKETIME_LIBS = (
    "/usr/lib/x86_64-linux-gnu/faketime/libfaketime.so.1",
    "/usr/lib/aarch64-linux-gnu/faketime/libfaketime.so.1",
    "/usr/lib/faketime/libfaketime.so.1",
    "/usr/local/lib/faketime/libfaketime.so.1",
)
ATTR_SI = 0x10
ATTR_END = 0xFFFFFFFF


class BuildError(RuntimeError):
    """The image could not be built as planned."""


# -- time helpers ------------------------------------------------------------------------------


def utc(text: str) -> dt.datetime:
    """``2026-03-02T09:00:00Z`` (optionally with up to 7 fraction digits) to an aware datetime."""
    return dt.datetime.fromisoformat(text.replace("Z", "+00:00")).astimezone(dt.UTC)


def ticks_of(when: dt.datetime, frac: int = 0) -> int:
    """FILETIME (100 ns since 1601) of a whole-second ``when`` plus ``frac`` ticks."""
    delta = when - EPOCH_1601
    return (delta.days * 86400 + delta.seconds) * TICKS + delta.microseconds * 10 + frac


def iso_ticks(ticks: int) -> str:
    """FILETIME to ISO 8601 UTC with 7 fraction digits and ``Z``."""
    secs, frac = divmod(ticks, TICKS)
    base = EPOCH_1601 + dt.timedelta(seconds=secs)
    return base.strftime("%Y-%m-%dT%H:%M:%S") + f".{frac:07d}Z"


def iso(when: dt.datetime) -> str:
    return when.astimezone(dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


# -- encoders (independent of the parsers under test) -----------------------------------------


def recycle_i(original_path: str, size: int, deleted_ticks: int, version: int) -> bytes:
    """A Windows ``$I`` record. Version 1: Vista to 8; version 2: Windows 10 and 11."""
    head = struct.pack("<QQQ", version, size, deleted_ticks)
    name = original_path.encode("utf-16-le") + b"\0\0"
    if version == 1:
        if len(name) > 520:
            raise BuildError(f"path too long for a version 1 $I record: {original_path}")
        return head + name.ljust(520, b"\0")
    if version == 2:
        return head + struct.pack("<I", len(name) // 2) + name
    raise BuildError(f"unknown $I version {version}")


def usn_v2(
    *,
    entry: int,
    seq: int,
    parent: int,
    parent_seq: int,
    usn: int,
    ticks: int,
    reason: int,
    name: str,
) -> bytes:
    """One USN_RECORD_V2, padded to 8 bytes."""
    raw = name.encode("utf-16-le")
    length = (60 + len(raw) + 7) // 8 * 8
    head = struct.pack(
        "<IHHQQqqIIIIHH",
        length,
        2,
        0,
        entry | (seq << 48),
        parent | (parent_seq << 48),
        usn,
        ticks,
        reason,
        0,
        0,
        0x20,
        len(raw),
        60,
    )
    return (head + raw).ljust(length, b"\0")


USN_FILE_CREATE = 0x100
USN_FILE_DELETE = 0x200
USN_CLOSE = 0x80000000


def png(width: int, height: int, colour: tuple[int, int, int], stripe: int) -> bytes:
    """A striped coloured rectangle with seeded noise, as PNG (generated shapes only).

    The noise keeps the file a few KiB after compression, so NTFS stores it in clusters
    (non-resident) and a deleted copy is left in unallocated space for the carvers.
    """
    seed = hashlib.sha256(bytes(colour) + struct.pack("<HHH", width, height, stripe)).digest()
    noise = b"".join(
        hashlib.sha256(seed + i.to_bytes(4, "little")).digest()
        for i in range(width * height * 3 // 32 + 1)
    )
    rows = []
    for y in range(height):
        band = (y // stripe) % 2
        c = colour if band else tuple(255 - v for v in colour)
        line = bytearray(bytes(c) * width)
        for x in range(len(line)):
            line[x] ^= noise[y * width * 3 + x] & 0x3F
        rows.append(b"\x00" + bytes(line))
    raw = b"".join(rows)

    def chunk(kind: bytes, data: bytes) -> bytes:
        return (
            struct.pack(">I", len(data))
            + kind
            + data
            + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)
        )

    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", ihdr)
        + chunk(b"IDAT", zlib.compress(raw, 9))
        + chunk(b"IEND", b"")
    )


def text_body(tag: str, lines: int) -> bytes:
    return "".join(
        f"{tag} line {i:04d}: generated validation text.\n" for i in range(lines)
    ).encode()


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(4 * 1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


# -- raw MFT editing (timestomp of $STANDARD_INFORMATION only) ---------------------------------


def _ntfs_geometry(fh: Any) -> tuple[int, int, int]:
    """(cluster size, MFT start byte, MFT record size) from the NTFS boot sector."""
    fh.seek(0)
    boot = fh.read(512)
    if boot[3:11] != b"NTFS    ":
        raise BuildError("not an NTFS boot sector")
    bps = struct.unpack_from("<H", boot, 0x0B)[0]
    cluster = bps * boot[0x0D]
    mft_lcn = struct.unpack_from("<Q", boot, 0x30)[0]
    cpr = struct.unpack_from("<b", boot, 0x40)[0]
    rec_size = cpr * cluster if cpr > 0 else 1 << -cpr
    return cluster, mft_lcn * cluster, rec_size


def _unfix(rec: bytearray, sector: int = 512) -> None:
    usa_off, usa_count = struct.unpack_from("<HH", rec, 4)
    usn = rec[usa_off : usa_off + 2]
    for i in range(1, usa_count):
        end = i * sector - 2
        if rec[end : end + 2] != usn:
            raise BuildError("MFT record fixup mismatch (torn record)")
        rec[end : end + 2] = rec[usa_off + 2 * i : usa_off + 2 * i + 2]


def _refix(rec: bytearray, sector: int = 512) -> None:
    usa_off, usa_count = struct.unpack_from("<HH", rec, 4)
    usn = rec[usa_off : usa_off + 2]
    for i in range(1, usa_count):
        end = i * sector - 2
        rec[usa_off + 2 * i : usa_off + 2 * i + 2] = rec[end : end + 2]
        rec[end : end + 2] = usn


def _attrs(rec: bytes | bytearray) -> Iterator[tuple[int, int]]:
    """(type, offset) of each attribute in a fixed-up MFT record."""
    off = struct.unpack_from("<H", rec, 0x14)[0]
    while off + 8 <= len(rec):
        kind, length = struct.unpack_from("<II", rec, off)
        if kind == ATTR_END or length == 0:
            return
        yield kind, off
        off += length


def _decode_runs(rec: bytes | bytearray, attr_off: int) -> list[tuple[int, int]]:
    """(LCN, cluster count) runs of a non-resident attribute."""
    runs_off = attr_off + struct.unpack_from("<H", rec, attr_off + 0x20)[0]
    pos, lcn, out = runs_off, 0, []
    while rec[pos]:
        head = rec[pos]
        nlen, olen = head & 0x0F, head >> 4
        pos += 1
        count = int.from_bytes(rec[pos : pos + nlen], "little")
        pos += nlen
        delta = int.from_bytes(rec[pos : pos + olen], "little", signed=True) if olen else 0
        pos += olen
        lcn += delta
        out.append((lcn, count))
    return out


def mft_record_offset(image: Path, entry: int) -> tuple[int, int]:
    """Byte offset and size of MFT ``entry`` in ``image`` (follows the $MFT data runs)."""
    with open(image, "rb") as fh:
        cluster, mft_start, rec_size = _ntfs_geometry(fh)
        fh.seek(mft_start)
        rec0 = bytearray(fh.read(rec_size))
        if rec0[:4] != b"FILE":
            raise BuildError("MFT record 0 has no FILE signature")
        _unfix(rec0)
        data_off = next((o for k, o in _attrs(rec0) if k == 0x80), None)
        if data_off is None or not rec0[data_off + 8]:
            raise BuildError("$MFT has no non-resident $DATA attribute")
        want = entry * rec_size
        for lcn, count in _decode_runs(rec0, data_off):
            span = count * cluster
            if want < span:
                return lcn * cluster + want, rec_size
            want -= span
    raise BuildError(f"MFT entry {entry} lies beyond the $MFT data runs")


def set_si_times(image: Path, entry: int, times: dict[str, int]) -> None:
    """Rewrite ``$STANDARD_INFORMATION`` times of MFT ``entry`` in an unmounted image.

    ``times`` keys: ``created``, ``modified``, ``changed``, ``accessed`` (FILETIME ticks); a key
    left out keeps its value. ``$FILE_NAME`` is not touched.
    """
    order = {"created": 0, "modified": 8, "changed": 16, "accessed": 24}
    off, size = mft_record_offset(image, entry)
    with open(image, "r+b") as fh:
        fh.seek(off)
        rec = bytearray(fh.read(size))
        if rec[:4] != b"FILE":
            raise BuildError(f"MFT entry {entry} has no FILE signature")
        _unfix(rec)
        si = next((o for k, o in _attrs(rec) if k == ATTR_SI), None)
        if si is None or rec[si + 8]:
            raise BuildError(f"MFT entry {entry} has no resident $STANDARD_INFORMATION")
        value = si + struct.unpack_from("<H", rec, si + 0x14)[0]
        for key, ticks in times.items():
            struct.pack_into("<Q", rec, value + order[key], ticks)
        _refix(rec)
        fh.seek(off)
        fh.write(rec)


def read_si_times(image: Path, entry: int) -> dict[str, int]:
    off, size = mft_record_offset(image, entry)
    with open(image, "rb") as fh:
        fh.seek(off)
        rec = bytearray(fh.read(size))
    _unfix(rec)
    si = next(o for k, o in _attrs(rec) if k == ATTR_SI)
    value = si + struct.unpack_from("<H", rec, si + 0x14)[0]
    c, m, ch, a = struct.unpack_from("<4Q", rec, value)
    return {"created": c, "modified": m, "changed": ch, "accessed": a}


# -- running tools -----------------------------------------------------------------------------


def run(argv: list[str], *, env: dict[str, str] | None = None) -> str:
    res = subprocess.run(argv, capture_output=True, text=True, env=env, check=False)
    if res.returncode != 0:
        raise BuildError(f"{argv[0]} failed (exit {res.returncode}): {res.stderr.strip()[-300:]}")
    return res.stdout


def faketime_lib() -> str:
    env = os.environ.get("AIRLOCK_FAKETIME_LIB")
    for cand in ((env,) if env else ()) + FAKETIME_LIBS:
        if cand and Path(cand).is_file():
            return cand
    raise BuildError("libfaketime is missing. Install it (sudo apt-get install faketime).")


class Clock:
    """Sets the time seen by a FUSE driver started under libfaketime."""

    def __init__(self, folder: Path) -> None:
        self.file = folder / "faketime"
        self.now: dt.datetime | None = None
        self.set(utc("2026-01-01T00:00:00Z"))

    def env(self) -> dict[str, str]:
        return {
            **os.environ,
            "LD_PRELOAD": faketime_lib(),
            "FAKETIME_TIMESTAMP_FILE": str(self.file),
            "FAKETIME_NO_CACHE": "1",
            "TZ": "UTC",
        }

    def set(self, when: dt.datetime) -> None:
        self.now = when
        self.file.write_text("@" + when.strftime("%Y-%m-%d %H:%M:%S") + "\n", encoding="ascii")
        time.sleep(0.05)


@contextmanager
def ntfs_mounted(image: Path, clock: Clock) -> Iterator[Path]:
    mnt = Path(tempfile.mkdtemp(prefix="airlock-synth-ntfs."))
    run(["ntfs-3g", "-o", "streams_interface=windows", str(image), str(mnt)], env=clock.env())
    try:
        yield mnt
    finally:
        os.sync()
        subprocess.run(["umount", str(mnt)], check=False, capture_output=True)
        mnt.rmdir()


@contextmanager
def exfat_mounted(image: Path, clock: Clock) -> Iterator[Path]:
    loop = run(["losetup", "-f", "--show", str(image)]).strip()
    mnt = Path(tempfile.mkdtemp(prefix="airlock-synth-exfat."))
    try:
        # Some hosts attach new loop devices read-only by policy; this one is ours.
        run(["blockdev", "--setrw", loop])
        run(["mount.exfat-fuse", loop, str(mnt)], env=clock.env())
        try:
            yield mnt
        finally:
            os.sync()
            subprocess.run(["umount", str(mnt)], check=False, capture_output=True)
    finally:
        subprocess.run(["losetup", "-d", loop], check=False, capture_output=True)
        mnt.rmdir()


def ntfs_times(path: Path) -> dict[str, int]:
    """$STANDARD_INFORMATION times through ntfs-3g: created, modified, accessed, changed."""
    raw = os.getxattr(path, "system.ntfs_times")
    c, m, a, ch = struct.unpack("<4Q", raw[:32])
    return {"created": c, "modified": m, "accessed": a, "changed": ch}


def check_close(label: str, got_ticks: int, planned: dt.datetime) -> None:
    diff = abs(got_ticks - ticks_of(planned)) / TICKS
    if diff > TOLERANCE_S:
        raise BuildError(
            f"{label}: time on disk is {iso_ticks(got_ticks)}, planned {iso(planned)}. "
            "libfaketime did not reach the FUSE driver; check LD_PRELOAD is allowed."
        )


# -- the NTFS set ------------------------------------------------------------------------------

T_DIRS = utc("2026-03-02T09:00:00Z")
T_CREATE = utc("2026-03-02T09:10:00Z")
T_CREATE_MOD = utc("2026-03-05T14:00:00Z")
T_CREATE_DEL = utc("2026-03-06T11:00:00Z")
T_CREATE_RB = utc("2026-03-07T10:00:00Z")
T_CREATE_STOMP = utc("2026-03-08T09:00:00Z")
T_MODIFY = utc("2026-04-10T16:30:00Z")
T_STOMP_XATTR = utc("2026-04-18T13:00:00Z")
T_DELETE = utc("2026-04-20T08:15:00Z")
STOMP_TO = utc("2019-05-06T07:08:09Z")

LIVE = [
    ("/Data/created-01.txt", text_body("created-01", 20)),
    ("/Data/created-02.txt", text_body("created-02", 300)),
    (
        "/Data/Sub/created-03.csv",
        b"id,value\n" + b"".join(b"%d,%d\n" % (i, i * i) for i in range(50)),
    ),
    ("/Users/TestUser/Documents/notes-01.txt", text_body("notes-01", 40)),
]
MODIFIED = [
    ("/Data/modified-01.txt", text_body("modified-01 v1", 10), text_body("modified-01 v2", 5)),
    ("/Users/TestUser/Documents/modified-02.txt", text_body("modified-02 v1", 3), b"appended\n"),
]
DELETED_TEXT = [
    ("/Data/deleted-01.txt", text_body("deleted-01", 12)),
    ("/Data/Sub/deleted-02.txt", text_body("deleted-02", 400)),
    ("/Archive/deleted-03.log", text_body("deleted-03", 2)),
]
DELETED_PNG = [
    ("/Pictures/shape-01.png", png(64, 48, (30, 110, 200), 4)),
    ("/Pictures/shape-02.png", png(120, 80, (200, 60, 40), 6)),
    ("/Pictures/shape-03.png", png(90, 90, (40, 160, 70), 9)),
]
# (stored name, original Windows path, content, $I version, deletion time with fraction)
RECYCLED = [
    (
        "$IVAL001.txt",
        "draft-01.txt",
        text_body("draft-01", 30),
        2,
        ("2026-04-15T12:00:00Z", 1_234_567),
    ),
    ("$IVAL002.txt", "report-02.txt", text_body("report-02", 8), 2, ("2026-04-15T12:05:30Z", 42)),
    ("$IVAL003.txt", "plan-03.txt", text_body("plan-03", 15), 1, ("2026-04-16T07:45:00Z", 0)),
]
USN_RECORDS = [
    # (name, entry, seq, parent, reason, time, fraction)
    (
        "val-usn-deleted-a.txt",
        4101,
        2,
        5,
        USN_FILE_DELETE | USN_CLOSE,
        "2026-04-12T10:00:00Z",
        1_111_111,
    ),
    (
        "val-usn-deleted-b.docx",
        4102,
        3,
        5,
        USN_FILE_DELETE | USN_CLOSE,
        "2026-04-12T10:00:05Z",
        2_222_222,
    ),
    ("val-usn-created-c.txt", 4103, 1, 5, USN_FILE_CREATE, "2026-04-12T10:00:09Z", 3_333_333),
]
STOMPS = [
    ("/Data/stomp-xattr-01.txt", "ntfs3g_xattr", False, []),
    ("/Data/stomp-si-01.txt", "si_raw_whole", True, ["ntfs_si_before_fn", "ntfs_si_zero_fraction"]),
    ("/Data/stomp-si-02.txt", "si_raw_whole", True, ["ntfs_si_before_fn", "ntfs_si_zero_fraction"]),
    ("/Data/stomp-si-03.txt", "si_raw_keep_fraction", True, ["ntfs_si_before_fn"]),
]


def _write(mnt: Path, rel: str, data: bytes) -> Path:
    p = mnt / rel.lstrip("/")
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(data)
    return p


def build_ntfs(out: Path, *, size_mib: int = 64) -> dict[str, Any]:  # noqa: PLR0912, PLR0915
    """Build ``out`` (an NTFS image) and return its ground truth."""
    out.unlink(missing_ok=True)
    with open(out, "wb") as fh:
        fh.truncate(size_mib * 1024 * 1024)
    run(["mkfs.ntfs", "-Q", "-F", "-L", "AIRLOCKVAL", str(out)])
    files: list[dict[str, Any]] = []
    recycle: list[dict[str, Any]] = []
    stomps: list[dict[str, Any]] = []
    carve: list[dict[str, Any]] = []
    entries: dict[str, int] = {}
    work = Path(tempfile.mkdtemp(prefix="airlock-synth-clock."))
    try:
        clock = Clock(work)
        with ntfs_mounted(out, clock) as mnt:
            clock.set(T_DIRS)
            for d in ("Data/Sub", "Archive", "Pictures", "Users/TestUser/Documents"):
                (mnt / d).mkdir(parents=True, exist_ok=True)
            rb = mnt / "$Recycle.Bin" / SID
            rb.mkdir(parents=True)

            clock.set(T_CREATE)
            for rel, data in LIVE:
                _write(mnt, rel, data)
                files.append(_entry(rel, data, "live", created=T_CREATE, modified=T_CREATE))
            clock.set(T_CREATE_MOD)
            for rel, first, _more in MODIFIED:
                _write(mnt, rel, first)
            clock.set(T_CREATE_DEL)
            for rel, data in DELETED_TEXT + DELETED_PNG:
                _write(mnt, rel, data)
            usn_blob = b"".join(
                usn_v2(
                    entry=e,
                    seq=s,
                    parent=p,
                    parent_seq=5,
                    usn=9000 + i * 128,
                    ticks=ticks_of(utc(t), f),
                    reason=r,
                    name=n,
                )
                for i, (n, e, s, p, r, t, f) in enumerate(USN_RECORDS)
            )
            _write(mnt, "/Archive/usn-fragment.bin", usn_blob.ljust(16384, b"\0"))
            clock.set(T_CREATE_RB)
            rb_sources = []
            for _i, name, data, _v, _t in RECYCLED:
                rel = f"/Users/TestUser/Documents/{name}"
                _write(mnt, rel, data)
                rb_sources.append(rel)
            clock.set(T_CREATE_STOMP)
            for rel, *_rest in STOMPS:
                _write(mnt, rel, text_body(rel.rsplit("/", 1)[-1], 6))
            os.sync()

            clock.set(T_MODIFY)
            for rel, first, more in MODIFIED:
                with open(mnt / rel.lstrip("/"), "ab") as fh:
                    fh.write(more)
                files.append(
                    _entry(rel, first + more, "live", created=T_CREATE_MOD, modified=T_MODIFY)
                )

            # Recycle: move the file to $R..., write $I... with the deletion time.
            for (iname, name, data, version, (when, frac)), src in zip(
                RECYCLED, rb_sources, strict=True
            ):
                deleted = utc(when)
                clock.set(deleted)
                rname = "$R" + iname[2:]
                os.rename(mnt / src.lstrip("/"), rb / rname)
                win_path = f"{WIN_USER_DIR}\\{name}"
                (rb / iname).write_bytes(
                    recycle_i(win_path, len(data), ticks_of(deleted, frac), version)
                )
                recycle.append(
                    {
                        "sid": SID,
                        "i_path": f"/$Recycle.Bin/{SID}/{iname}",
                        "r_path": f"/$Recycle.Bin/{SID}/{rname}",
                        "original_path": win_path,
                        "deleted": iso_ticks(ticks_of(deleted, frac)),
                        "size": len(data),
                        "version": version,
                        "r_state": "present",
                        "r_sha256": sha256(data),
                    }
                )

            clock.set(T_STOMP_XATTR)
            for rel, method, detectable, patterns in STOMPS:
                p = mnt / rel.lstrip("/")
                entries[rel] = os.stat(p).st_ino
                st = ntfs_times(p)
                check_close(rel, st["created"], T_CREATE_STOMP)
                rec: dict[str, Any] = {
                    "path": rel,
                    "method": method,
                    "detectable": detectable,
                    "expected_patterns": patterns,
                    "fn_created": iso_ticks(st["created"]),
                }
                if method == "ntfs3g_xattr":
                    v = ticks_of(STOMP_TO)
                    os.setxattr(p, "system.ntfs_times", struct.pack("<4Q", v, v, v, v))
                    rec["note"] = (
                        "ntfs-3g also sets $FILE_NAME times and stamps the change time; "
                        "no inferred pattern applies"
                    )
                stomps.append(rec)

            # Read back the final $STANDARD_INFORMATION times of live files.
            for f in files:
                st = ntfs_times(mnt / f["path"].lstrip("/"))
                check_close(f["path"] + " created", st["created"], utc(f["planned"]["created"]))
                check_close(f["path"] + " modified", st["modified"], utc(f["planned"]["modified"]))
                f["times"] = {k: iso_ticks(v) for k, v in sorted(st.items())}

            os.sync()
            clock.set(T_DELETE)
            for rel, data in DELETED_TEXT + DELETED_PNG:
                (mnt / rel.lstrip("/")).unlink()
                files.append(_entry(rel, data, "deleted", created=T_CREATE_DEL, deleted=T_DELETE))
            (mnt / "Archive/usn-fragment.bin").unlink()
            files.append(
                _entry(
                    "/Archive/usn-fragment.bin",
                    usn_blob.ljust(16384, b"\0"),
                    "deleted",
                    created=T_CREATE_DEL,
                    deleted=T_DELETE,
                )
            )
            for rel, data in DELETED_PNG:
                carve.append(
                    {"type": "png", "sha256": sha256(data), "size": len(data), "from": rel}
                )
    finally:
        shutil.rmtree(work, ignore_errors=True)

    # SI-only timestomps, written into the unmounted image's MFT records.
    for rec in stomps:
        entry = entries[rec["path"]]
        rec["mft_entry"] = entry
        if rec["method"] == "si_raw_whole":
            v = ticks_of(STOMP_TO)
            set_si_times(out, entry, {"created": v, "modified": v, "changed": v, "accessed": v})
        elif rec["method"] == "si_raw_keep_fraction":
            v = ticks_of(STOMP_TO, 4_567_891)
            set_si_times(out, entry, {"created": v, "modified": v, "accessed": v})
        si = read_si_times(out, entry)
        rec["si_after"] = {k: iso_ticks(t) for k, t in sorted(si.items())}

    usn = [
        {
            "name": n,
            "entry": e,
            "seq": s,
            "reason": r,
            "deleted": bool(r & USN_FILE_DELETE),
            "timestamp": iso_ticks(ticks_of(utc(t), f)),
        }
        for n, e, s, _p, r, t, f in USN_RECORDS
    ]
    return _truth(
        "ntfs-synthetic",
        out,
        "ntfs",
        files=files,
        recycle_bin=recycle,
        timestomp=stomps,
        carve=carve,
        usn_records=usn,
        classes=[
            "live_files",
            "deleted_files",
            "recycle_bin",
            "timestamps",
            "timestomp",
            "carving",
            "usn_carved",
        ],
    )


def _entry(
    rel: str,
    data: bytes,
    state: str,
    *,
    created: dt.datetime,
    modified: dt.datetime | None = None,
    deleted: dt.datetime | None = None,
) -> dict[str, Any]:
    planned = {"created": iso(created), "modified": iso(modified or created)}
    if deleted:
        planned["deleted"] = iso(deleted)
    return {
        "path": rel,
        "state": state,
        "size": len(data),
        "sha256": sha256(data),
        "planned": planned,
        "times": None,
    }


# -- the exFAT set -----------------------------------------------------------------------------

EX_LIVE = [
    ("/Data/created-01.txt", text_body("ex-created-01", 25)),
    ("/Data/created-02.txt", text_body("ex-created-02", 3)),
]
EX_MODIFIED = [("/Data/modified-01.txt", text_body("ex-modified v1", 4), b"appended\n")]
EX_DELETED = [
    ("/Data/deleted-01.txt", text_body("ex-deleted-01", 9)),
    ("/Pictures/shape-ex-01.png", png(72, 40, (120, 40, 160), 5)),
]


def build_exfat(out: Path, *, size_mib: int = 32) -> dict[str, Any]:
    """Build ``out`` (an exFAT image) and return its ground truth."""
    out.unlink(missing_ok=True)
    with open(out, "wb") as fh:
        fh.truncate(size_mib * 1024 * 1024)
    run(["mkfs.exfat", "-L", "AIRLOCKEX", str(out)])
    files: list[dict[str, Any]] = []
    carve: list[dict[str, Any]] = []
    work = Path(tempfile.mkdtemp(prefix="airlock-synth-clock."))
    try:
        clock = Clock(work)
        with exfat_mounted(out, clock) as mnt:
            clock.set(T_DIRS)
            for d in ("Data", "Pictures"):
                (mnt / d).mkdir()
            clock.set(T_CREATE)
            for rel, data in EX_LIVE:
                _write(mnt, rel, data)
                files.append(_entry(rel, data, "live", created=T_CREATE, modified=T_CREATE))
            clock.set(T_CREATE_MOD)
            for rel, first, _more in EX_MODIFIED:
                _write(mnt, rel, first)
            clock.set(T_CREATE_DEL)
            for rel, data in EX_DELETED:
                _write(mnt, rel, data)
            os.sync()
            clock.set(T_MODIFY)
            for rel, first, more in EX_MODIFIED:
                with open(mnt / rel.lstrip("/"), "ab") as fh:
                    fh.write(more)
                files.append(
                    _entry(rel, first + more, "live", created=T_CREATE_MOD, modified=T_MODIFY)
                )
            for f in files:
                st = os.stat(mnt / f["path"].lstrip("/"))
                got = ticks_of(dt.datetime.fromtimestamp(int(st.st_mtime), dt.UTC))
                check_close(f["path"] + " modified", got, utc(f["planned"]["modified"]))
                # exFAT keeps 10 ms for creation and modification; the driver gives no
                # creation time to user space, so the planned creation time is the truth.
                f["times"] = {"modified": iso_ticks(got), "created": f["planned"]["created"]}
            os.sync()
            clock.set(T_DELETE)
            for rel, data in EX_DELETED:
                (mnt / rel.lstrip("/")).unlink()
                files.append(_entry(rel, data, "deleted", created=T_CREATE_DEL, deleted=T_DELETE))
                if rel.endswith(".png"):
                    carve.append(
                        {"type": "png", "sha256": sha256(data), "size": len(data), "from": rel}
                    )
    finally:
        shutil.rmtree(work, ignore_errors=True)
    return _truth(
        "exfat-synthetic",
        out,
        "exfat",
        files=files,
        recycle_bin=[],
        timestomp=[],
        carve=carve,
        usn_records=[],
        classes=["live_files", "deleted_files", "timestamps", "carving"],
    )


def _truth(set_id: str, image: Path, fs_type: str, **parts: Any) -> dict[str, Any]:
    parts["files"] = sorted(parts["files"], key=lambda f: f["path"])
    return {
        "schema": SCHEMA,
        "set": set_id,
        "kind": "synthetic",
        "generator": GENERATOR,
        "fs_type": fs_type,
        "image": image.name,
        "image_sha256": sha256_file(image),
        "image_size": image.stat().st_size,
        "time_basis": "utc",
        "tolerance_s": TOLERANCE_S,
        "thresholds": {"recall_min": 1.0, "false_positives_max": 0},
        **parts,
    }


def write_truth(path: Path, truth: dict[str, Any]) -> None:
    path.write_text(json.dumps(truth, sort_keys=True, indent=2, ensure_ascii=False) + "\n")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Build synthetic validation images (task 4F.1).")
    ap.add_argument("--out", type=Path, required=True, help="folder for the images and truth")
    ap.add_argument("--only", choices=("ntfs", "exfat"), help="build one set only")
    args = ap.parse_args(argv)
    if os.geteuid() != 0:
        print("synth: needs root (FUSE mounts and loop devices). Run with sudo.", file=sys.stderr)
        return 1
    args.out.mkdir(parents=True, exist_ok=True)
    builders = {"ntfs": build_ntfs, "exfat": build_exfat}
    try:
        for kind, build in builders.items():
            if args.only and args.only != kind:
                continue
            img = args.out / f"{kind}-synthetic.img"
            truth = build(img)
            write_truth(args.out / f"{kind}-synthetic.truth.json", truth)
            print(f"synth: built {img} ({len(truth['files'])} files in the ground truth)")
    except (BuildError, OSError) as exc:
        print(f"synth: {exc}. Fix that and run build.sh again.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
