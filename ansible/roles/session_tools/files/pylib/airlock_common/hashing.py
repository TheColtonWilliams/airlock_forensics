"""Hashing files and block devices, read-only, in 4 MiB blocks."""

from __future__ import annotations

import hashlib
import os
from collections.abc import Iterable

BLOCK = 4 * 1024 * 1024
DEFAULT_ALGOS: tuple[str, ...] = ("sha256", "md5")


def hash_stream_fd(
    fd: int, algos: Iterable[str] = DEFAULT_ALGOS, *, limit: int | None = None
) -> dict[str, str]:
    hashers = {a: hashlib.new(a) for a in algos}
    remaining = limit
    while True:
        want = BLOCK if remaining is None else min(BLOCK, remaining)
        if want == 0:
            break
        chunk = os.read(fd, want)
        if not chunk:
            break
        for h in hashers.values():
            h.update(chunk)
        if remaining is not None:
            remaining -= len(chunk)
    return {a: h.hexdigest() for a, h in hashers.items()}


def hash_file(
    path: str | os.PathLike[str], algos: Iterable[str] = DEFAULT_ALGOS, *, limit: int | None = None
) -> dict[str, str]:
    """Hash a regular file or a block device opened O_RDONLY. ``limit`` caps bytes read."""
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOATIME", 0)
    try:
        fd = os.open(path, flags)
    except PermissionError:
        # O_NOATIME needs ownership; retry without it.
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
    try:
        return hash_stream_fd(fd, algos, limit=limit)
    finally:
        os.close(fd)


def sha256_file(path: str | os.PathLike[str]) -> str:
    return hash_file(path, ("sha256",))["sha256"]


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
