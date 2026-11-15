"""How the AI helpers run external programs.

Every model and parser call goes through a ``RunTool``: a callable with the signature of
``forensic_analyze.api.ModuleContext.tool`` (``argv``, ``timeout``, ``stdout_path``,
``extra_ro``, ``memory_bytes``) that returns a ``subprocess.CompletedProcess`` and does not raise
on a non-zero exit. Inside a ``forensic-analyze`` run that is ``ctx.tool`` (sandboxed and
recorded in ``run.json``). The stand-alone commands use ``sandbox_runner``, the same parser
sandbox (no network, unprivileged user when run as root, seccomp, limits).
"""

from __future__ import annotations

import contextlib
import os
import subprocess
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

from airlock_common import proc

RunTool = Callable[..., subprocess.CompletedProcess[str]]


def sandbox_runner(workdir: Path, *, devices: Sequence[str] = ()) -> RunTool:
    """A ``RunTool`` that runs each call in the parser sandbox with ``workdir`` writable."""
    from forensic_analyze import sandbox as sb  # noqa: PLC0415 - optional at import time

    box = sb.Sandbox(devices=list(devices))
    workdir.mkdir(parents=True, exist_ok=True)
    box.prepare_writable(workdir)  # before any sub-folder is made (see tool_dir)

    def run(argv: Sequence[str], **kw: Any) -> subprocess.CompletedProcess[str]:
        kw.pop("sandbox", None)
        kw.pop("redact", None)
        try:
            cp, _rec = box.run(
                [str(a) for a in argv],
                workdir=workdir,
                timeout=kw.get("timeout"),
                memory_bytes=kw.get("memory_bytes"),
                stdout_path=Path(kw["stdout_path"]) if kw.get("stdout_path") else None,
                extra_ro=[str(p) for p in kw.get("extra_ro", ())],
            )
        except sb.LimitExceeded as exc:
            raise proc.ToolError(str(exc)) from exc
        except FileNotFoundError as exc:
            raise proc.ToolError(str(exc)) from exc
        return cp

    return run


def gpu_render_nodes() -> list[str]:
    """``/dev/dri/renderD*`` nodes, for model runs that may use the GPU through Vulkan."""
    dri = Path("/dev/dri")
    if not dri.is_dir():
        return []
    return sorted(str(p) for p in dri.glob("renderD*"))


def tool_dir(path: Path) -> Path:
    """Create ``path`` (and missing parents) with the owner, group, and mode of the nearest
    existing parent, so a sandboxed tool running as the parse user can write into it.

    The runner and ``sandbox_runner`` make only the work folder writable for that user; a
    folder root creates below it would otherwise be root-owned (best effort: exFAT has no
    owners, and its mount options decide).
    """
    missing: list[Path] = []
    cur = path
    while not cur.exists():
        missing.append(cur)
        cur = cur.parent
    path.mkdir(parents=True, exist_ok=True)
    try:
        st = cur.stat()
    except OSError:
        return path
    for d in reversed(missing):
        with contextlib.suppress(OSError):
            os.chown(d, st.st_uid, st.st_gid)
        with contextlib.suppress(OSError):
            os.chmod(d, st.st_mode & 0o7777)
    return path
