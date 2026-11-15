"""``clamscan``, ``yara``, and ``ssdeep`` over aliased file names (task 4A.6).

Every file is reached through a symlink named ``f0000000``, ``f0000001``, ... in a working
folder. Tools get only those names (in a list file or as arguments) and print only those
names, so a file name that came from evidence (newlines, ``: FOUND``, shell characters) is
never passed to a tool and never confuses the output parser. Results are mapped back to the
caller's index.

``runner`` is ``ModuleContext.tool`` (sandboxed, logged in ``run.json``) inside
``forensic-analyze``, or the sandbox runner built by ``triage.default_runner`` for
``evidence-triage-hash``. It takes an argument list plus ``timeout``, ``stdout_path``,
``extra_ro`` (folders the tool may read), and ``memory_bytes``, and returns a
``subprocess.CompletedProcess``. ClamAV never gets ``--remove``, ``--move`` or ``--copy``:
it only reads.
"""

from __future__ import annotations

import csv
import io
import os
import subprocess
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from airlock_common import proc

Runner = Callable[..., subprocess.CompletedProcess[str]]

ALIAS_FMT = "f{:07d}"
SSDEEP_BATCH = 400
GIB = 1024**3
CLAMSCAN_MEMORY = 6 * GIB  # main + daily signatures need about 1.5 GiB resident
YARA_MEMORY = 4 * GIB


class ScanError(RuntimeError):
    """A scanner could not run at all (missing, failed to load its rules, killed)."""


@dataclass
class ScanResult:
    hits: dict[int, list[str]] = field(default_factory=dict)  # index -> signature or rule names
    errors: dict[int, str] = field(default_factory=dict)  # index -> per-file problem

    def add(self, index: int, name: str) -> None:
        names = self.hits.setdefault(index, [])
        if name not in names:
            names.append(name)


class Aliases:
    """Symlinks ``folder/f0000000`` -> each file, in input order."""

    def __init__(self, files: Sequence[Path], folder: Path) -> None:
        self.folder = folder
        folder.mkdir(parents=True, exist_ok=True)
        self.paths: list[Path] = []
        for i, f in enumerate(files):
            link = folder / ALIAS_FMT.format(i)
            if link.is_symlink() or link.exists():
                link.unlink()
            link.symlink_to(os.path.abspath(f))
            self.paths.append(link)
        self._by_name = {p.name: i for i, p in enumerate(self.paths)}
        # Folders the aliased files live in: bound read-only into the sandbox with the aliases.
        self.read_dirs = sorted({os.path.dirname(os.path.abspath(f)) for f in files})

    def index_of(self, text: str) -> int | None:
        """Index for an alias as a tool printed it (full path or bare name)."""
        name = text.strip().strip('"')
        prefix = str(self.folder) + os.sep
        if name.startswith(prefix):
            name = name[len(prefix) :]
        return self._by_name.get(name)

    def write_list(self, indexes: Sequence[int], path: Path) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("".join(f"{self.paths[i]}\n" for i in indexes), encoding="utf-8")
        return path

    def split_line(self, line: str) -> tuple[int, str] | None:
        """``<alias><sep><rest>`` as clamscan prints it -> (index, rest)."""
        prefix = str(self.folder) + os.sep
        if not line.startswith(prefix):
            return None
        rest = line[len(prefix) :]
        name, sep, tail = rest.partition(":")
        idx = self._by_name.get(name)
        if idx is None or not sep:
            return None
        return idx, tail.strip()


def _run(
    runner: Runner, argv: list[str], *, timeout: float, ro: Sequence[str], memory: int = 0
) -> subprocess.CompletedProcess[str]:
    kw: dict[str, object] = {"timeout": timeout, "extra_ro": list(ro)}
    if memory:
        kw["memory_bytes"] = memory
    try:
        return runner(argv, **kw)
    except proc.ToolError as exc:
        raise ScanError(str(exc)) from exc
    except FileNotFoundError as exc:
        raise ScanError(f"{argv[0]}: not installed or not on PATH") from exc


def _last(text: str) -> str:
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    return lines[-1][:300] if lines else ""


# --------------------------------------------------------------------------- ClamAV


def clamscan(
    runner: Runner,
    aliases: Aliases,
    indexes: Sequence[int],
    databases: Sequence[Path],
    *,
    list_path: Path,
    max_mib: int,
    timeout: float,
) -> ScanResult:
    """Scan the given files with exactly ``databases`` (``-d`` each). No daemon, read only."""
    res = ScanResult()
    if not indexes or not databases:
        return res
    listing = aliases.write_list(indexes, list_path)
    argv = [
        "clamscan",
        "--no-summary",
        "--infected",
        "--stdout",
        f"--max-filesize={max_mib}M",
        f"--max-scansize={max_mib}M",
        *[a for db in databases for a in ("-d", str(db))],
        f"--file-list={listing}",
    ]
    ro = sorted({str(Path(db).parent) for db in databases} | {str(aliases.folder)})
    ro = sorted({*ro, *aliases.read_dirs})
    cp = _run(runner, argv, timeout=timeout, ro=ro, memory=CLAMSCAN_MEMORY)
    for line in (cp.stdout or "").splitlines():
        parsed = aliases.split_line(line.rstrip())
        if parsed is None:
            continue
        idx, tail = parsed
        if tail.endswith(" FOUND"):
            res.add(idx, tail[: -len(" FOUND")].strip())
        elif tail.endswith(" ERROR"):
            res.errors[idx] = "clamscan: " + tail[: -len(" ERROR")].strip()[:200]
    if cp.returncode not in (0, 1) and not res.hits and not res.errors:
        raise ScanError(f"clamscan exited {cp.returncode}: {_last(cp.stderr or cp.stdout)}")
    return res


# --------------------------------------------------------------------------- YARA


def yara(
    runner: Runner,
    aliases: Aliases,
    indexes: Sequence[int],
    rules: Path,
    *,
    list_path: Path,
    per_file_timeout: int,
    timeout: float,
) -> ScanResult:
    """Scan with one compiled rule pack. External variables stay empty (set at compile time):
    evidence file names are never given to YARA."""
    res = ScanResult()
    if not indexes:
        return res
    listing = aliases.write_list(indexes, list_path)
    argv = [
        "yara",
        "--compiled-rules",
        "--no-warnings",
        "--print-namespace",
        f"--timeout={per_file_timeout}",
        "--scan-list",
        str(rules),
        str(listing),
    ]
    cp = _run(
        runner,
        argv,
        timeout=timeout,
        ro=sorted({str(rules.parent), str(aliases.folder), *aliases.read_dirs}),
        memory=YARA_MEMORY,
    )
    for line in (cp.stdout or "").splitlines():
        rule, _sep, target = line.rstrip().rpartition(" ")
        idx = aliases.index_of(target)
        if idx is not None and rule:
            res.add(idx, rule.removeprefix("default:"))
    for line in (cp.stderr or "").splitlines():
        # "error scanning <alias>: <reason>"
        text = line.strip()
        if text.startswith("error scanning "):
            target, _sep, reason = text[len("error scanning ") :].partition(": ")
            idx = aliases.index_of(target)
            if idx is not None:
                res.errors[idx] = f"yara: {reason.strip()[:200]}"
    if cp.returncode != 0 and not res.hits and not res.errors:
        raise ScanError(f"yara exited {cp.returncode}: {_last(cp.stderr)}")
    return res


# --------------------------------------------------------------------------- ssdeep


def _csv_rows(text: str) -> list[list[str]]:
    return [r for r in csv.reader(io.StringIO(text)) if r]


def ssdeep_hashes(
    runner: Runner, aliases: Aliases, indexes: Sequence[int], *, timeout: float
) -> dict[int, str]:
    """Context-triggered piecewise hash of each file (``ssdeep -s -c -b``)."""
    out: dict[int, str] = {}
    idx_list = list(indexes)
    for start in range(0, len(idx_list), SSDEEP_BATCH):
        part = idx_list[start : start + SSDEEP_BATCH]
        argv = ["ssdeep", "-s", "-c", "-b", *[str(aliases.paths[i]) for i in part]]
        cp = _run(runner, argv, timeout=timeout, ro=[str(aliases.folder), *aliases.read_dirs])
        for row in _csv_rows(cp.stdout or ""):
            if len(row) < 2 or row[0].startswith("ssdeep,"):
                continue
            idx = aliases.index_of(os.path.basename(row[-1]))
            if idx is not None:
                out[idx] = row[0]
    return out


def ssdeep_match(
    runner: Runner,
    aliases: Aliases,
    indexes: Sequence[int],
    known: Path,
    *,
    threshold: int,
    timeout: float,
) -> dict[int, list[tuple[str, int]]]:
    """Fuzzy matches against one list of known ssdeep hashes: index -> [(known name, score)]."""
    out: dict[int, list[tuple[str, int]]] = {}
    idx_list = list(indexes)
    for start in range(0, len(idx_list), SSDEEP_BATCH):
        part = idx_list[start : start + SSDEEP_BATCH]
        argv = ["ssdeep", "-s", "-c", "-b", "-t", str(max(0, threshold)), "-m", str(known)]
        argv += [str(aliases.paths[i]) for i in part]
        cp = _run(
            runner,
            argv,
            timeout=timeout,
            ro=sorted({str(known.parent), str(aliases.folder), *aliases.read_dirs}),
        )
        for row in _csv_rows(cp.stdout or ""):
            if len(row) < 3:
                continue
            idx = aliases.index_of(os.path.basename(row[0]))
            try:
                score = int(row[-1])
            except ValueError:
                continue
            if idx is not None and score > threshold:
                out.setdefault(idx, []).append((row[1], score))
    return out


# --------------------------------------------------------------------------- versions


def tool_version(runner: Runner, name: str) -> str:
    """The version a tool reports, or "" if it is missing."""
    flag = {"clamscan": "--version", "yara": "--version", "ssdeep": "-V"}.get(name, "--version")
    try:
        cp = runner([name, flag], timeout=120)
    except (proc.ToolError, FileNotFoundError):
        return ""
    return _last(cp.stdout or cp.stderr)[:120]
