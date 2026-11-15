"""NTFS extraction helpers (docs/dev/contract.md section 8a), read-only, never mounting.

* ``extract_system_file(ctx, volume, name) -> Path`` copies ``$MFT``, ``$UsnJrnl:$J``,
  ``$LogFile``, ``$Secure:$SDS`` (and ``$Bitmap``) out of an NTFS volume with ``icat`` into
  ``<run>/extract/v<index>/``. A copy made earlier in the run is reused. Each copy has a
  ``<name>.json`` beside it with the metadata address, size, and SHA-256 of the stream.
  ``$UsnJrnl:$J`` is mostly sparse (zeros); its zero 4 KiB pages are dropped while copying so
  the copy holds only the records, and the dropped ranges are listed in the ``.json``.
* ``export_file(ctx, volume, inode, dest_dir) -> Path`` copies one file's content (live or
  deleted) with ``icat`` into a folder inside the run folder.
* Small helpers shared by the NTFS modules: ``tsk_argv``, ``fsstat_info``, ``lookup``.

Every tool runs through ``ctx.tool`` (sandboxed, logged in ``run.json``). Tools write to a
file the runner opens, or to a pipe read here, so the parse user never needs write access to
``extract/``.
"""

from __future__ import annotations

import contextlib
import hashlib
import os
import re
import shutil
import subprocess
import tempfile
import threading
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from airlock_common import jsonio
from forensic_analyze.api import ModuleContext, Volume
from forensic_analyze.parsers import sds
from forensic_analyze.parsers.mft import MftError, MftIndex, MftRecord
from forensic_analyze.parsers.sds import SecurityEntry

PAGE = 4096
READ_CHUNK = 1024 * 1024
_SAFE_RE = re.compile(r"[^A-Za-z0-9._$=+-]+")
_FLS_LINE = re.compile(
    r"^(?P<type>\S+)\s+(?:\*\s+)?(?P<addr>[0-9]+(?:-[0-9]+-[0-9]+)?):\t(?P<name>.*)$"
)


class ExtractError(RuntimeError):
    """A system file or file could not be copied out (absent, or the tool failed)."""


@dataclass(frozen=True)
class SystemFile:
    name: str  # as the caller names it: "$MFT"
    cache_name: str  # file name under extract/v<index>/
    address: str = ""  # fixed TSK metadata address, or "" to look it up
    parent_dir: str = ""  # directory inode to list when looking it up
    entry_name: str = ""  # name in that directory listing
    drop_zero_pages: bool = False


SYSTEM_FILES: dict[str, SystemFile] = {
    "$MFT": SystemFile("$MFT", "MFT", address="0"),
    "$LogFile": SystemFile("$LogFile", "LogFile", address="2"),
    "$Bitmap": SystemFile("$Bitmap", "Bitmap", address="6"),
    "$Secure:$SDS": SystemFile(
        "$Secure:$SDS", "Secure_SDS", parent_dir="5", entry_name="$Secure:$SDS"
    ),
    "$UsnJrnl:$J": SystemFile(
        "$UsnJrnl:$J", "UsnJrnl_J", parent_dir="11", entry_name="$UsnJrnl:$J", drop_zero_pages=True
    ),
}


# ----------------------------------------------------------------------------------------------
# Tool argument helpers
# ----------------------------------------------------------------------------------------------


def sector_offset(volume: Volume) -> int:
    """The volume start in 512-byte sectors (what ``-o`` means for the Sleuth Kit tools)."""
    return volume.offset_bytes // 512


def image_args(ctx: ModuleContext) -> list[str]:
    """``-i ewf`` for E01 sets, nothing for raw images and devices."""
    suffix = str(ctx.target.path).lower()
    if suffix.endswith((".e01", ".ex01", ".s01", ".l01")):
        return ["-i", "ewf"]
    return []


def tsk_argv(tool: str, ctx: ModuleContext, volume: Volume, *rest: str) -> list[str]:
    """``[tool, (-i ewf), -o <sector>, <target>, *rest]``."""
    return [tool, *image_args(ctx), "-o", str(sector_offset(volume)), str(ctx.target.path), *rest]


def extract_dir(ctx: ModuleContext, volume: Volume) -> Path:
    d = ctx.run_dir / "extract" / f"v{volume.index}"
    d.mkdir(parents=True, exist_ok=True)
    return d


def safe_component(text: str, *, limit: int = 120) -> str:
    """A file name that is safe on exFAT and in a shell-free path: no separators, no controls."""
    clean = _SAFE_RE.sub("_", text).strip("._") or "file"
    return clean[:limit]


def _last_line(text: str) -> str:
    lines = [ln for ln in (text or "").strip().splitlines() if ln.strip()]
    return lines[-1][:200] if lines else ""


def fsstat_info(ctx: ModuleContext, volume: Volume) -> dict[str, str]:
    """Key/value lines of ``fsstat`` for the volume (cached for the run in ``ctx.shared``)."""
    key = f"extract.fsstat.v{volume.index}"
    cached = ctx.shared.get(key)
    if isinstance(cached, dict):
        return cached
    cp = ctx.tool(tsk_argv("fsstat", ctx, volume))
    info: dict[str, str] = {}
    for line in (cp.stdout or "").splitlines():
        k, sep, v = line.partition(":")
        if sep and k.strip() and k.strip() not in info:
            info[k.strip()] = v.strip()
    ctx.shared[key] = info
    return info


def cluster_size(ctx: ModuleContext, volume: Volume) -> int:
    info = fsstat_info(ctx, volume)
    for k in ("Cluster Size", "Block Size"):
        with contextlib.suppress(KeyError, ValueError):
            return int(info[k])
    return 4096


def volume_serial(ctx: ModuleContext, volume: Volume) -> str:
    """The NTFS volume serial number as fsstat prints it (16 hex digits), or ""."""
    return fsstat_info(ctx, volume).get("Volume Serial Number", "")


def lookup(ctx: ModuleContext, volume: Volume, dir_inode: str, name: str) -> str | None:
    """The TSK metadata address of ``name`` in one directory (non-recursive ``fls``)."""
    cp = ctx.tool(tsk_argv("fls", ctx, volume, dir_inode))
    if cp.returncode != 0:
        return None
    for line in (cp.stdout or "").splitlines():
        m = _FLS_LINE.match(line)
        if m and m.group("name") == name and "*" not in line.split("\t", 1)[0]:
            return m.group("addr")
    return None


# ----------------------------------------------------------------------------------------------
# Streaming a tool's output through a pipe
# ----------------------------------------------------------------------------------------------


def stream_tool(
    ctx: ModuleContext, argv: list[str], sink: Callable[[bytes], None], **kw: Any
) -> subprocess.CompletedProcess[str]:
    """Run ``argv`` with stdout going to ``sink`` chunk by chunk (nothing kept in memory).

    The runner opens the write end of a named pipe in a private temporary folder; a reader
    thread here feeds ``sink``. If ``sink`` fails (for example the output drive is full) the
    rest of the output is drained so the tool can finish, and the error is raised afterwards.
    """
    tmp = Path(tempfile.mkdtemp(prefix="airlock-pipe-"))
    fifo = tmp / "stdout"
    os.mkfifo(fifo, 0o600)
    errors: list[BaseException] = []

    def reader() -> None:
        try:
            with open(fifo, "rb") as fh:
                while True:
                    chunk = fh.read(READ_CHUNK)
                    if not chunk:
                        break
                    if errors:
                        continue
                    try:
                        sink(chunk)
                    except BaseException as exc:  # keep draining; re-raised by the caller
                        errors.append(exc)
        except OSError as exc:
            errors.append(exc)

    thread = threading.Thread(target=reader, name="airlock-pipe", daemon=True)
    thread.start()
    try:
        cp = ctx.tool(argv, stdout_path=fifo, **kw)
    except BaseException:
        _unblock(fifo)
        thread.join(timeout=30)
        raise
    finally:
        # The tool never opened the pipe (it failed to start): let the reader finish.
        if thread.is_alive():
            _unblock(fifo)
        thread.join(timeout=60)
        shutil.rmtree(tmp, ignore_errors=True)
    if errors:
        raise errors[0]
    return cp


def _unblock(fifo: Path) -> None:
    with contextlib.suppress(OSError):
        fd = os.open(fifo, os.O_WRONLY | os.O_NONBLOCK)
        os.close(fd)


class _PageWriter:
    """Writes a stream to a file, hashing all of it, optionally dropping zero 4 KiB pages."""

    def __init__(self, path: Path, *, drop_zero_pages: bool) -> None:
        self.fh = open(path, "wb")  # noqa: SIM115 - closed by close()
        self.drop = drop_zero_pages
        self.sha = hashlib.sha256()
        self.size = 0
        self.written = 0
        self.dropped = 0
        self.runs: list[list[int]] = []  # [source_offset, copy_offset, length]
        self._pending = b""

    def __call__(self, chunk: bytes) -> None:
        self.sha.update(chunk)
        if not self.drop:
            self.fh.write(chunk)
            self.size += len(chunk)
            self.written += len(chunk)
            return
        data = self._pending + chunk
        full = len(data) - len(data) % PAGE
        self._pages(data[:full])
        self._pending = data[full:]

    def _pages(self, data: bytes) -> None:
        zero = bytes(PAGE)
        for i in range(0, len(data), PAGE):
            page = data[i : i + PAGE]
            src = self.size
            self.size += len(page)
            if page == zero[: len(page)]:
                self.dropped += len(page)
                continue
            if self.runs and self.runs[-1][0] + self.runs[-1][2] == src:
                self.runs[-1][2] += len(page)
            else:
                self.runs.append([src, self.written, len(page)])
            self.fh.write(page)
            self.written += len(page)

    def close(self) -> None:
        if self._pending:
            self._pages(self._pending)
            self._pending = b""
        self.fh.flush()
        os.fsync(self.fh.fileno())
        self.fh.close()


# ----------------------------------------------------------------------------------------------
# Public API
# ----------------------------------------------------------------------------------------------


def system_file_address(ctx: ModuleContext, volume: Volume, name: str) -> str | None:
    spec = SYSTEM_FILES.get(name)
    if spec is None:
        raise ValueError(f"unknown system file {name!r}; known: {', '.join(SYSTEM_FILES)}")
    if spec.address:
        return spec.address
    return lookup(ctx, volume, spec.parent_dir, spec.entry_name)


def cached_meta(ctx: ModuleContext, volume: Volume, name: str) -> dict[str, Any] | None:
    """The ``.json`` record of an earlier copy, or None."""
    spec = SYSTEM_FILES[name]
    meta = ctx.run_dir / "extract" / f"v{volume.index}" / f"{spec.cache_name}.json"
    if not meta.exists():
        return None
    try:
        data = jsonio.load_json(meta)
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def extract_system_file(ctx: ModuleContext, volume: Volume, name: str) -> Path:
    """Copy an NTFS system file out of ``volume`` (cached per run). Raises ``ExtractError``."""
    spec = SYSTEM_FILES.get(name)
    if spec is None:
        raise ValueError(f"unknown system file {name!r}; known: {', '.join(SYSTEM_FILES)}")
    out_dir = extract_dir(ctx, volume)
    dest = out_dir / spec.cache_name
    meta_path = out_dir / f"{spec.cache_name}.json"
    if dest.exists() and meta_path.exists():
        return dest
    address = system_file_address(ctx, volume, name)
    if not address:
        raise ExtractError(f"{name} not found on volume {volume.index}")
    argv = tsk_argv("icat", ctx, volume, address)
    tmp = out_dir / f".{spec.cache_name}.partial"
    writer = _PageWriter(tmp, drop_zero_pages=spec.drop_zero_pages)
    try:
        cp = stream_tool(ctx, argv, writer)
    finally:
        writer.close()
    if cp.returncode != 0:
        tmp.unlink(missing_ok=True)
        raise ExtractError(f"icat could not copy {name} ({address}): {_last_line(cp.stderr)}")
    if writer.size == 0:
        tmp.unlink(missing_ok=True)
        raise ExtractError(f"{name} ({address}) is empty on volume {volume.index}")
    tmp.replace(dest)
    jsonio.dump_json(
        meta_path,
        {
            "name": name,
            "volume_index": volume.index,
            "address": address,
            "argv": [str(a) for a in argv],
            "stream_size": writer.size,
            "stream_sha256": writer.sha.hexdigest(),
            "copy_size": writer.written,
            "zero_pages_dropped_bytes": writer.dropped,
            "runs": writer.runs if spec.drop_zero_pages else [],
        },
    )
    ctx.log(
        "system_file_extracted",
        name=name,
        volume=volume.index,
        address=address,
        size=writer.size,
        sha256=writer.sha.hexdigest(),
    )
    return dest


def _inside(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
    except ValueError:
        return False
    return True


def export_file(
    ctx: ModuleContext,
    volume: Volume,
    inode: str | int,
    dest_dir: str | os.PathLike[str],
    *,
    name: str | None = None,
    recover: bool = False,
) -> Path:
    """Copy one file's content with ``icat`` (works for deleted files whose data is intact).

    ``inode`` is a TSK metadata address (``68``, ``68-128-2`` for a named stream). The copy is
    ``dest_dir/<name>`` (``name`` is made safe; default ``v<index>_<inode>``). ``dest_dir`` must
    be inside the run folder. ``recover=True`` adds ``icat -r`` (recovery mode for deleted
    files on filesystems where it applies). Raises ``ExtractError`` when icat fails.
    """
    out_dir = Path(dest_dir)
    if not _inside(out_dir, ctx.run_dir):
        raise ValueError(f"export folder {out_dir} is outside the run folder")
    addr = str(inode)
    if not re.fullmatch(r"[0-9]+(?:-[0-9]+(?:-[0-9]+)?)?", addr):
        raise ValueError(f"not a metadata address: {addr!r}")
    out_dir.mkdir(parents=True, exist_ok=True)
    fname = safe_component(name) if name else f"v{volume.index}_{addr}"
    dest = out_dir / fname
    extra = ["-r"] if recover else []
    argv = [
        "icat",
        *image_args(ctx),
        "-o",
        str(sector_offset(volume)),
        *extra,
        str(ctx.target.path),
        addr,
    ]
    cp = ctx.tool(argv, stdout_path=dest)
    if cp.returncode != 0:
        dest.unlink(missing_ok=True)
        raise ExtractError(f"icat could not copy {addr}: {_last_line(cp.stderr)}")
    return dest


def relative(ctx: ModuleContext, path: Path) -> str:
    """``path`` relative to the run folder, ``/`` separated (for ``source_record``)."""
    return path.resolve().relative_to(ctx.run_dir.resolve()).as_posix()


# ----------------------------------------------------------------------------------------------
# Parsed views shared by the NTFS modules (cached for the run in ctx.shared)
# ----------------------------------------------------------------------------------------------


def load_mft_index(ctx: ModuleContext, volume: Volume) -> MftIndex:
    """The volume's ``$MFT`` parsed by the built-in parser. Raises ``ExtractError``."""
    key = f"extract.mft_index.v{volume.index}"
    cached = ctx.shared.get(key)
    if isinstance(cached, MftIndex):
        return cached
    path = extract_system_file(ctx, volume, "$MFT")
    try:
        index = MftIndex.load(path)
    except (MftError, OSError, ValueError) as exc:
        raise ExtractError(f"$MFT on volume {volume.index} could not be parsed: {exc}") from exc
    ctx.shared[key] = index
    return index


def load_security(ctx: ModuleContext, volume: Volume) -> dict[int, SecurityEntry]:
    """``$Secure:$SDS`` parsed: security ID -> owner and group SID. Raises ``ExtractError``."""
    key = f"extract.sds.v{volume.index}"
    cached = ctx.shared.get(key)
    if isinstance(cached, dict):
        return cached
    path = extract_system_file(ctx, volume, "$Secure:$SDS")
    try:
        table = sds.parse_file(path)
    except (sds.SdsError, OSError) as exc:
        raise ExtractError(f"$SDS on volume {volume.index} could not be parsed: {exc}") from exc
    ctx.shared[key] = table
    return table


def owner_resolver(ctx: ModuleContext, volume: Volume) -> Callable[[MftRecord], str | None]:
    """A function giving a record's owner account SID (``$SI`` security ID -> ``$SDS``)."""
    try:
        table = load_security(ctx, volume)
    except ExtractError:
        table = {}

    def owner(rec: MftRecord) -> str | None:
        if rec.security_id is None:
            return None
        entry = table.get(rec.security_id)
        return entry.owner_sid if entry else None

    return owner


def dissect_query(
    ctx: ModuleContext, functions: list[str], dest: Path
) -> subprocess.CompletedProcess[str] | None:
    """Run Dissect's ``target-query -j`` over the whole target into ``dest`` (JSON lines).

    Returns None when ``target-query`` is not installed. An earlier complete output (a
    ``<dest>.done`` marker beside it) is reused, so several modules can share one run.
    """
    done = dest.with_name(dest.name + ".done")
    if dest.exists() and done.exists():
        return subprocess.CompletedProcess(["target-query"], 0, "", "")
    if not shutil.which("target-query"):
        return None
    dest.parent.mkdir(parents=True, exist_ok=True)
    argv = ["target-query", "--no-cache", "-q", *functions, "-j", str(ctx.target.path)]
    cp = ctx.tool(argv, stdout_path=dest)
    if cp.returncode == 0:
        done.write_text("ok\n", encoding="utf-8")
    return cp


def tool_dir(ctx: ModuleContext, path: Path) -> Path:
    """A folder inside the module's work folder that a sandboxed tool may write to.

    The runner makes only the work folder itself writable for the parse user; a sub-folder
    made here gets the same owner, group, and mode (best effort: exFAT has no owners).
    """
    path.mkdir(parents=True, exist_ok=True)
    try:
        st = ctx.workdir.stat()
        current = path
        while current != ctx.workdir and ctx.workdir in current.parents:
            with contextlib.suppress(OSError):
                os.chown(current, st.st_uid, st.st_gid)
                os.chmod(current, st.st_mode & 0o7777)
            current = current.parent
    except OSError:
        pass
    return path
