"""ModuleContext construction (docs/dev/contract.md sections 8 and 8a).

``ToolRecorder`` runs every external tool for the run (sandboxed by default), and records the
exact command line, tool version, binary path and SHA-256, sandbox method, limits, return code,
and duration. Those records go into ``run.json``.

``ctx.tool(argv, *, sandbox=True, timeout=None, stdout_path=None, memory_bytes=None,
extra_ro=(), redact=(), devices=())`` returns a ``subprocess.CompletedProcess`` with text
output; it does not raise on a non-zero exit. It raises ``airlock_common.proc.ToolError`` when
the tool is missing or breaks its time limit. ``devices`` adds device nodes (a GPU render node)
for that call only.

``ctx.emit(row)`` writes through ``forensic_analyze.findings.FindingsWriter`` (validated against
``schema.json``). If the findings package is not installed, a minimal internal writer is used
and ``run.json`` says so.
"""

from __future__ import annotations

import os
import shlex
import shutil
import subprocess
import time
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from airlock_common import hashing, jsonio, proc, sessionlog, timeutil
from forensic_analyze import sandbox as sb
from forensic_analyze.api import ModuleContext, Target

TOOL_NAME = "forensic-analyze"


class _FallbackWriter:
    """Minimal findings writer used only when ``forensic_analyze.findings`` is missing."""

    def __init__(
        self, part_path: Path, *, run_id: str, evidence_id: str, evidence_sha256: str, module: str
    ) -> None:
        self.part_path = part_path
        self.base = {
            "run_id": run_id,
            "evidence_id": evidence_id,
            "evidence_sha256": evidence_sha256,
        }
        self.module = module
        self.count = 0
        part_path.parent.mkdir(parents=True, exist_ok=True)
        self._fh = open(part_path, "w", encoding="utf-8", newline="\n")  # noqa: SIM115

    def emit(self, row: dict[str, Any]) -> None:
        full = {**row, **self.base}
        self._fh.write(jsonio.dumps_line(full) + "\n")
        self.count += 1

    def close(self) -> None:
        self._fh.flush()
        os.fsync(self._fh.fileno())
        self._fh.close()


def findings_backend() -> str:
    try:
        from forensic_analyze import findings  # noqa: F401, PLC0415
    except ImportError:
        return "internal-fallback"
    return "forensic_analyze.findings"


def open_writer(
    part_path: Path, *, run_id: str, evidence_id: str, evidence_sha256: str, module: str
) -> Any:
    try:
        from forensic_analyze.findings import FindingsWriter  # noqa: PLC0415
    except ImportError:
        return _FallbackWriter(
            part_path,
            run_id=run_id,
            evidence_id=evidence_id,
            evidence_sha256=evidence_sha256,
            module=module,
        )
    return FindingsWriter(
        part_path,
        run_id=run_id,
        evidence_id=evidence_id,
        evidence_sha256=evidence_sha256,
        module=module,
    )


@dataclass
class BinaryInfo:
    path: str
    sha256: str
    version: str


class ToolRecorder:
    """Runs tools for the whole run and keeps the records for ``run.json``."""

    def __init__(self, sandbox: sb.Sandbox, log_path: Path) -> None:
        self.sandbox = sandbox
        self.log_path = log_path
        self.records: list[dict[str, Any]] = []
        self.binaries: dict[str, BinaryInfo] = {}
        self._versions: dict[str, str] = {}

    # -- versions and hashes -------------------------------------------------------------------

    def binary(self, name_or_path: str) -> BinaryInfo | None:
        exe = name_or_path if os.path.isabs(name_or_path) else shutil.which(name_or_path)
        if not exe or not Path(exe).exists():
            return None
        real = os.path.realpath(exe)
        if real not in self.binaries:
            try:
                digest = hashing.sha256_file(real)
            except OSError:
                digest = ""
            self.binaries[real] = BinaryInfo(real, digest, self.version(exe))
        return self.binaries[real]

    def version(self, name_or_path: str) -> str:
        exe = name_or_path if os.path.isabs(name_or_path) else shutil.which(name_or_path)
        if not exe:
            return "not installed"
        real = os.path.realpath(exe)
        if real in self._versions:
            return self._versions[real]
        ver = _dpkg_version(real) or self._self_reported(exe) or "unknown"
        self._versions[real] = ver
        return ver

    def _self_reported(self, exe: str) -> str:
        """``-V`` or ``--version``, run inside the sandbox like any other parser call."""
        probe = self.log_path.parent / "version-probe"
        for flag in ("-V", "--version"):
            try:
                cp, _rec = self.sandbox.run([exe, flag], workdir=probe, timeout=20)
            except (sb.SandboxError, OSError):
                continue
            text = (cp.stdout or cp.stderr).strip()
            if cp.returncode == 0 and text:
                return text.splitlines()[0][:200]
        return ""

    # -- running -------------------------------------------------------------------------------

    def run(
        self,
        module: str,
        argv: Sequence[str],
        *,
        workdir: Path,
        sandbox: bool = True,
        timeout: float | None = None,
        stdout_path: str | os.PathLike[str] | None = None,
        memory_bytes: int | None = None,
        extra_ro: Sequence[str] = (),
        redact: Sequence[str] = (),
        devices: Sequence[str] = (),
    ) -> subprocess.CompletedProcess[str]:
        args = [str(a) for a in argv]
        if not args:
            raise ValueError("empty argv")
        info = self.binary(args[0])
        if info is None:
            self._record(module, args, redact, None, None, 127, 0.0, "not installed")
            raise proc.ToolError(f"{args[0]}: not installed or not on PATH")
        args[0] = shutil.which(args[0]) or args[0]
        started = time.monotonic()
        out_path = Path(stdout_path) if stdout_path else None
        if sandbox:
            try:
                cp, rec = self.sandbox.run(
                    args,
                    workdir=workdir,
                    timeout=timeout,
                    memory_bytes=memory_bytes,
                    stdout_path=out_path,
                    extra_ro=extra_ro,
                    devices=devices,
                )
            except sb.LimitExceeded as exc:
                self._record(
                    module, args, redact, info, None, -9, time.monotonic() - started, str(exc)
                )
                raise proc.ToolError(str(exc)) from exc
            self._record(
                module, args, redact, info, rec.to_dict(), cp.returncode, rec.duration_s, ""
            )
            return cp
        try:
            res = proc.run(
                args,
                check=False,
                timeout=timeout,
                stdout_path=str(out_path) if out_path else None,
                cwd=workdir,
            )
        except proc.ToolError as exc:
            self._record(module, args, redact, info, None, -9, time.monotonic() - started, str(exc))
            raise
        self._record(
            module, args, redact, info, None, res.returncode, time.monotonic() - started, ""
        )
        return subprocess.CompletedProcess(res.argv, res.returncode, res.stdout, res.stderr)

    def _record(  # noqa: PLR0917 - private, one call shape per outcome
        self,
        module: str,
        args: list[str],
        redact: Sequence[str],
        info: BinaryInfo | None,
        sandbox: dict[str, Any] | None,
        returncode: int,
        duration: float,
        error: str,
    ) -> None:
        shown = ["<redacted>" if a in redact else a for a in args]
        rec = {
            "module": module,
            "argv": shown,
            "command_line": shlex.join(shown),
            "returncode": returncode,
            "duration_s": round(duration, 3),
            "started_utc": timeutil.iso(),
            "binary": info.path if info else "",
            "binary_sha256": info.sha256 if info else "",
            "version": info.version if info else "",
            "sandbox": sandbox or {"method": "unsandboxed"},
            "error": error,
        }
        self.records.append(rec)
        jsonio.append_line(self.log_path, {"event": "tool_run", "ts": timeutil.iso(), **rec})

    def versions(self) -> dict[str, dict[str, str]]:
        return {
            Path(p).name: {"path": b.path, "sha256": b.sha256, "version": b.version}
            for p, b in sorted(self.binaries.items())
        }


def _dpkg_version(path: str) -> str:
    if not shutil.which("dpkg-query"):
        return ""
    for candidate in (path, path.replace("/usr/", "/", 1)):
        try:
            owner = subprocess.run(
                ["dpkg-query", "-S", candidate],
                capture_output=True,
                text=True,
                timeout=20,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            return ""
        if owner.returncode == 0 and owner.stdout:
            pkg = owner.stdout.split(":", 1)[0].split(",")[0].strip()
            ver = subprocess.run(
                ["dpkg-query", "-W", "-f", "${Version}", pkg],
                capture_output=True,
                text=True,
                timeout=20,
                check=False,
            )
            if ver.returncode == 0 and ver.stdout.strip():
                return f"{pkg} {ver.stdout.strip()}"
    return ""


@dataclass
class ModuleHandles:
    ctx: ModuleContext
    writer: Any
    log_events: list[dict[str, Any]]


def build_context(
    *,
    run_id: str,
    module: str,
    target: Target,
    run_dir: Path,
    options: dict[str, Any],
    recorder: ToolRecorder,
    shared: dict[str, Any],
    evidence_sha256: str,
    run_log: Path,
) -> ModuleHandles:
    """A fresh ModuleContext for ``module`` with its writer and log sink."""
    workdir = run_dir / "modules" / module
    workdir.mkdir(parents=True, exist_ok=True)
    writer = open_writer(
        workdir / "findings.part.jsonl",
        run_id=run_id,
        evidence_id=target.evidence_id,
        evidence_sha256=evidence_sha256,
        module=module,
    )
    events: list[dict[str, Any]] = []

    def log(event: str, **fields: Any) -> None:
        rec = {"ts": timeutil.iso(), "event": event, "module": module, **fields}
        events.append(rec)
        jsonio.append_line(run_log, rec)
        sessionlog.log_event(TOOL_NAME, event, module=module, run_id=run_id, **fields)

    def tool(argv: Sequence[str], **kw: Any) -> subprocess.CompletedProcess[str]:
        return recorder.run(module, argv, workdir=workdir, **kw)

    ctx = ModuleContext(
        run_id=run_id,
        module=module,
        target=target,
        run_dir=run_dir,
        workdir=workdir,
        options=options,
        emit=writer.emit,
        tool=tool,
        log=log,
        tool_version=recorder.version,
        shared=shared,
    )
    return ModuleHandles(ctx, writer, events)
