"""Hashing files and block devices, read-only, in 4 MiB blocks."""

from __future__ import annotations

import hashlib
import os
from collections.abc import Iterable

BLOCK = 4 * 1024 * 1024
DEFAULT_ALGOS: tuple[str, ...] = ("sha256", "md5")


def hash_stream_fd_counted(
    fd: int, algos: Iterable[str] = DEFAULT_ALGOS, *, limit: int | None = None
) -> tuple[dict[str, str], int]:
    """Hash ``fd`` to its end (or ``limit``). Returns the digests and the bytes actually hashed."""
    hashers = {a: hashlib.new(a) for a in algos}
    remaining = limit
    total = 0
    while True:
        want = BLOCK if remaining is None else min(BLOCK, remaining)
        if want == 0:
            break
        chunk = os.read(fd, want)
        if not chunk:
            break
        for h in hashers.values():
            h.update(chunk)
        total += len(chunk)
        if remaining is not None:
            remaining -= len(chunk)
    return {a: h.hexdigest() for a, h in hashers.items()}, total


def hash_stream_fd(
    fd: int, algos: Iterable[str] = DEFAULT_ALGOS, *, limit: int | None = None
) -> dict[str, str]:
    return hash_stream_fd_counted(fd, algos, limit=limit)[0]


def _open_ro(path: str | os.PathLike[str]) -> int:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOATIME", 0)
    try:
        return os.open(path, flags)
    except PermissionError:
        # O_NOATIME needs ownership; retry without it.
        return os.open(path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))


def hash_file_counted(
    path: str | os.PathLike[str], algos: Iterable[str] = DEFAULT_ALGOS, *, limit: int | None = None
) -> tuple[dict[str, str], int]:
    """:func:`hash_file`, also returning the number of bytes the digests cover."""
    fd = _open_ro(path)
    try:
        return hash_stream_fd_counted(fd, algos, limit=limit)
    finally:
        os.close(fd)


def hash_file(
    path: str | os.PathLike[str], algos: Iterable[str] = DEFAULT_ALGOS, *, limit: int | None = None
) -> dict[str, str]:
    """Hash a regular file or a block device opened O_RDONLY. ``limit`` caps bytes read."""
    return hash_file_counted(path, algos, limit=limit)[0]


def sha256_file(path: str | os.PathLike[str]) -> str:
    return hash_file(path, ("sha256",))["sha256"]


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
