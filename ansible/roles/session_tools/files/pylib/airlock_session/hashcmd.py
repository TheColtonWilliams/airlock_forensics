"""evidence-hash: hash a drive or image in one read pass and log it (task 4.10).

SHA-256 and MD5 always (SWGDE: more than one algorithm), SHA-1 with ``--sha1``. The target is
opened read-only (``O_RDONLY``) through :mod:`airlock_common.hashing`; nothing is written to it.
The result is appended to the session log and printed (``--json`` for one JSON object).
"""

from __future__ import annotations

import argparse
import time
from typing import Any

from airlock_common import hashing, jsonio, timeutil
from airlock_session.common import (
    TargetInfo,
    describe_target,
    human_size,
    log,
    open_session_log,
    run_main,
)

TOOL = "evidence-hash"
LABELS = {"sha256": "SHA-256", "sha1": "SHA-1", "md5": "MD5"}


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=TOOL,
        description="Hash a drive or image read-only (SHA-256 and MD5) and log the result.",
    )
    p.add_argument("target", help="a drive (for example /dev/sdb) or an image file")
    p.add_argument("--sha1", action="store_true", help="also compute SHA-1 in the same pass")
    p.add_argument("--json", action="store_true", help="print the result as one JSON object")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return run_main(TOOL, lambda: run(args))


def algorithms(sha1: bool) -> tuple[str, ...]:
    return ("sha256", "sha1", "md5") if sha1 else ("sha256", "md5")


def hash_target(info: TargetInfo, algos: tuple[str, ...], *, tool: str = TOOL) -> dict[str, Any]:
    """Hash ``info.path`` in one pass and log an ``evidence_hash`` event. Returns the record."""
    started = timeutil.iso()
    t0 = time.monotonic()
    digests = hashing.hash_file(info.path, algos)
    seconds = round(time.monotonic() - t0, 3)
    record: dict[str, Any] = {
        "target": info.to_dict(),
        "algorithms": list(algos),
        "hashes": digests,
        "started": started,
        "finished": timeutil.iso(),
        "seconds": seconds,
        "bytes_read": info.size_bytes,
    }
    log(tool, "evidence_hash", **record)
    return record


def run(args: argparse.Namespace) -> int:
    open_session_log(TOOL)
    info = describe_target(args.target)
    if not args.json:
        what = "drive" if info.kind == "device" else "image"
        print(f"Hashing {what} {info.path} ({human_size(info.size_bytes)}) read-only ...")
        if info.kind == "device" and info.readonly is False:
            print(
                "Note: this drive's software read-only flag is off. Hashing only reads it, "
                "but check that this is the drive you meant."
            )
    record = hash_target(info, algorithms(args.sha1))
    if args.json:
        print(jsonio.dumps(record))
        return 0
    for algo in record["algorithms"]:
        print(f"{LABELS[algo]:<8} {record['hashes'][algo]}")
    print(f"Read {record['bytes_read']} bytes in {record['seconds']} s. Logged to the session log.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
