"""Run external tools with argument lists only (never a shell) and record what ran."""

from __future__ import annotations

import shlex
import shutil
import subprocess
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path


class ToolError(RuntimeError):
    """A tool exited non-zero, timed out, or was missing."""


@dataclass
class Result:
    argv: list[str]
    returncode: int
    stdout: str
    stderr: str
    command_line: str = field(init=False)

    def __post_init__(self) -> None:
        self.command_line = shlex.join(self.argv)


def run(
    argv: Sequence[str],
    *,
    check: bool = True,
    timeout: float | None = None,
    input_text: str | None = None,
    env: Mapping[str, str] | None = None,
    cwd: str | Path | None = None,
    stdout_path: str | Path | None = None,
) -> Result:
    """Run ``argv`` without a shell. ``stdout_path`` streams stdout to a file instead of memory."""
    args = [str(a) for a in argv]
    if not args:
        raise ValueError("empty argv")
    try:
        if stdout_path is not None:
            with open(stdout_path, "wb") as out:
                cp = subprocess.run(
                    args,
                    stdout=out,
                    stderr=subprocess.PIPE,
                    timeout=timeout,
                    input=None if input_text is None else input_text.encode(),
                    env=None if env is None else dict(env),
                    cwd=cwd,
                    check=False,
                )
            stdout = ""
            stderr = cp.stderr.decode("utf-8", "replace")
        else:
            cp = subprocess.run(
                args,
                capture_output=True,
                timeout=timeout,
                input=input_text,
                text=True,
                encoding="utf-8",
                errors="replace",
                env=None if env is None else dict(env),
                cwd=cwd,
                check=False,
            )
            stdout, stderr = cp.stdout, cp.stderr
    except FileNotFoundError as exc:
        raise ToolError(f"{args[0]}: not installed or not on PATH") from exc
    except subprocess.TimeoutExpired as exc:
        raise ToolError(f"{args[0]}: timed out after {timeout} s") from exc
    res = Result(args, cp.returncode, stdout, stderr)
    if check and cp.returncode != 0:
        last = (stderr.strip().splitlines() or [""])[-1]
        raise ToolError(f"{args[0]} exited {cp.returncode}: {last}")
    return res


def which(name: str) -> str | None:
    return shutil.which(name)
