"""evidence-hash: hash a drive or image in one read pass and log it (task 4.10).

SHA-256 and MD5 always (SWGDE: more than one algorithm), SHA-1 with ``--sha1``. The target is
opened read-only (``O_RDONLY``) through :mod:`airlock_common.hashing`; nothing is written to it.
The result is appended to the session log and printed (``--json`` for one JSON object).
``bytes_read`` is the number of bytes the digests cover; if it differs from the size seen before
hashing, the record says so (``complete: false``), a warning is logged and printed, and the
command exits 1.
"""

from __future__ import annotations

import argparse
import sys
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


def size_warning(info: TargetInfo, bytes_read: int) -> str:
    """The warning when the digests cover a different number of bytes than the target's size."""
    if bytes_read == info.size_bytes:
        return ""
    return (
        f"the hash covers {bytes_read} bytes but {info.path} was {info.size_bytes} bytes when "
        "hashing started; the target changed size or a read ended early. Do not record this "
        "hash as the hash of the whole target; check the target and hash it again."
    )


def hash_target(info: TargetInfo, algos: tuple[str, ...], *, tool: str = TOOL) -> dict[str, Any]:
    """Hash ``info.path`` in one pass and log an ``evidence_hash`` event. Returns the record.

    ``bytes_read`` is the number of bytes the digests actually cover. When it differs from the
    size seen before hashing (``expected_bytes``), ``complete`` is false, ``warning`` says so,
    an ``evidence_hash_size_mismatch`` event is logged and the warning goes to stderr.
    """
    started = timeutil.iso()
    t0 = time.monotonic()
    digests, bytes_read = hashing.hash_file_counted(info.path, algos)
    seconds = round(time.monotonic() - t0, 3)
    warning = size_warning(info, bytes_read)
    record: dict[str, Any] = {
        "target": info.to_dict(),
        "algorithms": list(algos),
        "hashes": digests,
        "started": started,
        "finished": timeutil.iso(),
        "seconds": seconds,
        "bytes_read": bytes_read,
        "expected_bytes": info.size_bytes,
        "complete": not warning,
    }
    if warning:
        record["warning"] = warning
    log(tool, "evidence_hash", **record)
    if warning:
        log(
            tool,
            "evidence_hash_size_mismatch",
            path=info.path,
            bytes_read=bytes_read,
            expected_bytes=info.size_bytes,
        )
        print(f"{tool}: WARNING: {warning}", file=sys.stderr)
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
    code = 0 if record["complete"] else 1
    if args.json:
        print(jsonio.dumps(record))
        return code
    for algo in record["algorithms"]:
        print(f"{LABELS[algo]:<8} {record['hashes'][algo]}")
    print(f"Read {record['bytes_read']} bytes in {record['seconds']} s. Logged to the session log.")
    if not record["complete"]:
        print(
            f"Expected {record['expected_bytes']} bytes. The hash does not cover the whole "
            "target; see the warning above."
        )
    return code


if __name__ == "__main__":
    raise SystemExit(main())
