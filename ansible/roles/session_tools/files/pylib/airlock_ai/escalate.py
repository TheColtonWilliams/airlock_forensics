"""``forensic-escalate``: the operator-run stop control (task 4B.18).

Run it when you suspect child sexual abuse material, or any other material you must not keep
processing. It:

1. writes ``<run>/ESCALATED`` first, so every module stops exporting at once;
2. stops the running ``forensic-analyze`` (process ID in ``<run>/forensic-analyze.pid``) and
   every process it started: SIGTERM, then SIGKILL after a grace period;
3. freezes exports: every export folder of the run (``modules/*/export``, ``exports``,
   ``carved``, ``extract``, ``decrypted``) is made read-only, and the marker stops new ones;
4. records only the path, the finding ID, and the SHA-256 (in ``<run>/escalation.json``,
   ``run.json``, and the session log);
5. shows the stop-and-contact-law-enforcement guidance.

It never opens, hashes, copies, moves, or deletes the file in question. The SHA-256 comes from
the findings rows or from the operator, never from reading the file.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import signal
import stat
import sys
import time
from collections.abc import Iterator
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from airlock_common import jsonio, paths, sessionlog, timeutil, ui

TOOL = "forensic-escalate"
PID_FILE = "forensic-analyze.pid"
MARKER = "ESCALATED"
RECORD = "escalation.json"
EXPORT_DIR_NAMES = ("export", "exports", "carved")
RUN_EXPORT_DIRS = ("extract", "decrypted")
PROCESS_NAMES = ("forensic-analyze", "forensic_analyze")

GUIDANCE = """\
STOP. The analysis has been halted and its exports frozen.

What to do now:
  1. Do not open, view, copy, move, or delete the file, or any other file from this drive.
  2. Do not run any more analysis on this drive. Leave the evidence drive and this USB stick
     as they are. Shut the computer down normally when you are told to, not before.
  3. Contact law enforcement now.
     In the United States: the FBI (tips.fbi.gov) or your local Internet Crimes Against
     Children (ICAC) task force.
     Elsewhere: your national police.
  4. Tell them the case and run IDs, the finding ID, the path, and the SHA-256 shown above.
     Write down when you saw the indication and what it was (a file name, a description,
     a count). Do not describe or reproduce the content.

AIRLOCK does not and cannot tell anyone's age. This record is a stop, not a finding."""


class EscalateError(RuntimeError):
    """The stop control could not do its job; the message says what to do."""


@dataclass
class Escalation:
    utc: str
    run_dir: str
    run_id: str
    finding_id: str
    path: str
    sha256: str
    stopped_pids: list[int] = field(default_factory=list)
    killed_pids: list[int] = field(default_factory=list)
    frozen_dirs: list[str] = field(default_factory=list)
    process_found: bool = False

    def record(self) -> dict[str, Any]:
        """What is written down: only path, finding ID, and hash, plus what was done."""
        return asdict(self)


def is_escalated(run_dir: str | os.PathLike[str]) -> bool:
    """True once ``forensic-escalate`` has been run for this run folder."""
    return (Path(run_dir) / MARKER).exists()


# ---------------------------------------------------------------------------------------------
# Finding the run and the item
# ---------------------------------------------------------------------------------------------


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def read_pid(run_dir: Path) -> int | None:
    try:
        text = (run_dir / PID_FILE).read_text(encoding="ascii").strip()
    except OSError:
        return None
    return int(text) if text.isdigit() else None


def _cmdline(pid: int) -> str:
    try:
        raw = Path(f"/proc/{pid}/cmdline").read_bytes()
    except OSError:
        return ""
    return raw.replace(b"\0", b" ").decode("utf-8", "replace")


def is_analyzer(pid: int) -> bool:
    """Guard against a reused PID: only signal a process that is forensic-analyze."""
    cmd = _cmdline(pid)
    return any(name in cmd for name in PROCESS_NAMES) or bool(
        os.environ.get("AIRLOCK_ESCALATE_ANY_PID")
    )


def running_runs(root: Path | None = None) -> list[Path]:
    """Run folders under ``<output>/cases/*/*`` whose pid file names a live analyzer."""
    base = (root or paths.output_dir()) / "cases"
    found: list[Path] = []
    for pid_file in sorted(base.glob(f"*/*/{PID_FILE}")):
        pid = read_pid(pid_file.parent)
        if pid and _pid_alive(pid) and is_analyzer(pid):
            found.append(pid_file.parent)
    return found


def _iter_rows(run_dir: Path) -> Iterator[dict[str, Any]]:
    sources = [run_dir / "findings.jsonl"]
    sources += sorted((run_dir / "modules").glob("*/findings.part.jsonl"))
    for src in sources:
        try:
            fh = open(src, encoding="utf-8")  # noqa: SIM115 - closed below
        except OSError:
            continue
        with fh:
            for line in fh:
                with contextlib.suppress(ValueError):
                    row = json.loads(line)
                    if isinstance(row, dict):
                        yield row


def lookup(run_dir: Path, finding_id: str, path: str) -> tuple[str, str, str]:
    """(finding_id, path, sha256) from the run's rows. Reads findings, never the file."""
    for row in _iter_rows(run_dir):
        if finding_id and row.get("finding_id") == finding_id:
            return finding_id, str(row.get("path", "")), str(row.get("sha256", ""))
    if path:
        for row in _iter_rows(run_dir):
            if row.get("path") == path and row.get("sha256"):
                return str(row.get("finding_id", "")), path, str(row["sha256"])
    return finding_id, path, ""


# ---------------------------------------------------------------------------------------------
# Stopping and freezing
# ---------------------------------------------------------------------------------------------


def descendants(pid: int) -> list[int]:
    """Every process whose parent chain leads to ``pid`` (from /proc)."""
    children: dict[int, list[int]] = {}
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            fields = (entry / "stat").read_text(encoding="ascii", errors="replace")
        except OSError:
            continue
        # The command name is in parentheses and may contain spaces.
        rest = fields.rsplit(")", 1)[-1].split()
        if len(rest) >= 2 and rest[1].isdigit():
            children.setdefault(int(rest[1]), []).append(int(entry.name))
    out: list[int] = []
    todo = [pid]
    while todo:
        cur = todo.pop()
        for c in children.get(cur, []):
            if c not in out:
                out.append(c)
                todo.append(c)
    return out


def stop_process(pid: int, *, grace_s: float = 10.0) -> tuple[list[int], list[int]]:
    """SIGTERM the analyzer and its descendants, SIGKILL whatever is left. Returns both lists."""
    targets = [pid, *descendants(pid)]
    stopped: list[int] = []
    for p in targets:
        try:
            os.kill(p, signal.SIGTERM)
            stopped.append(p)
        except ProcessLookupError:
            continue
        except PermissionError as exc:
            raise EscalateError(
                "not allowed to stop the analysis; run forensic-escalate with sudo"
            ) from exc
    deadline = time.monotonic() + grace_s
    while time.monotonic() < deadline and any(_pid_alive(p) and not _zombie(p) for p in targets):
        time.sleep(0.2)
    killed: list[int] = []
    for p in [*targets, *descendants(pid)]:
        if _pid_alive(p) and not _zombie(p):
            with contextlib.suppress(ProcessLookupError):
                os.kill(p, signal.SIGKILL)
                killed.append(p)
    return stopped, killed


def _zombie(pid: int) -> bool:
    try:
        text = Path(f"/proc/{pid}/stat").read_text(encoding="ascii", errors="replace")
    except OSError:
        return True
    state = text.rsplit(")", 1)[-1].split()
    return bool(state) and state[0] in {"Z", "X"}


def export_dirs(run_dir: Path) -> list[Path]:
    found: list[Path] = []
    modules = run_dir / "modules"
    if modules.is_dir():
        for mod in sorted(p for p in modules.iterdir() if p.is_dir()):
            for name in EXPORT_DIR_NAMES:
                cand = mod / name
                if cand.is_dir() and not cand.is_symlink():
                    found.append(cand)
    for name in RUN_EXPORT_DIRS:
        cand = run_dir / name
        if cand.is_dir() and not cand.is_symlink():
            found.append(cand)
    return found


def freeze(run_dir: Path) -> list[str]:
    """Make every export folder and file read-only (files 0444, folders 0555)."""
    frozen: list[str] = []
    ro_file = stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH
    ro_dir = ro_file | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH
    for folder in export_dirs(run_dir):
        for dirpath, dirs, files in os.walk(folder, topdown=False):
            for name in files:
                p = Path(dirpath) / name
                if not p.is_symlink():
                    with contextlib.suppress(OSError):
                        os.chmod(p, ro_file)
            for name in dirs:
                p = Path(dirpath) / name
                if not p.is_symlink():
                    with contextlib.suppress(OSError):
                        os.chmod(p, ro_dir)
        with contextlib.suppress(OSError):
            os.chmod(folder, ro_dir)
        frozen.append(folder.relative_to(run_dir).as_posix())
    return frozen


def escalate(
    run_dir: Path | None,
    *,
    finding_id: str = "",
    path: str = "",
    sha256: str = "",
    grace_s: float = 10.0,
) -> Escalation:
    """Do the whole stop. ``run_dir`` None records the escalation in the session log only."""
    utc = timeutil.iso()
    if run_dir is None:
        esc = Escalation(utc, "", "", finding_id, path, sha256)
        _log(esc)
        return esc
    finding_id, path, found_sha = lookup(run_dir, finding_id, path)
    esc = Escalation(utc, str(run_dir), run_dir.name, finding_id, path, sha256 or found_sha)
    # 1. The marker first: modules check it before every export.
    jsonio.dump_json(
        run_dir / MARKER,
        {"utc": utc, "finding_id": esc.finding_id, "path": esc.path, "sha256": esc.sha256},
    )
    # 2. Stop the run.
    pid = read_pid(run_dir)
    if pid and _pid_alive(pid) and is_analyzer(pid):
        esc.process_found = True
        esc.stopped_pids, esc.killed_pids = stop_process(pid, grace_s=grace_s)
    # 3. Freeze exports.
    esc.frozen_dirs = freeze(run_dir)
    # 4. Record.
    jsonio.dump_json(run_dir / RECORD, esc.record())
    run_json = run_dir / "run.json"
    if run_json.exists():
        try:
            doc = jsonio.load_json(run_json)
            doc["status"] = "escalated"
            doc["escalation"] = esc.record()
            jsonio.dump_json(run_json, doc)
        except (OSError, ValueError):
            pass  # escalation.json is the record; run.json may be mid-write
    _log(esc)
    return esc


def _log(esc: Escalation) -> None:
    with contextlib.suppress(OSError):
        sessionlog.log_event(
            TOOL,
            "escalated",
            run_id=esc.run_id,
            finding_id=esc.finding_id,
            path=esc.path,
            sha256=esc.sha256,
            stopped=len(esc.stopped_pids),
            frozen=len(esc.frozen_dirs),
        )


# ---------------------------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:  # noqa: PLR0911 - one exit per failure
    ap = argparse.ArgumentParser(
        prog=TOOL,
        description=(
            "Stop control for suspected illegal material: halts forensic-analyze, freezes "
            "exports, records only path, finding ID, and hash. Never opens the file."
        ),
    )
    ap.add_argument("--run", metavar="RUN_DIR", help="the run folder (default: the running one)")
    ap.add_argument("--finding", default="", metavar="F-000123", help="finding ID, if known")
    ap.add_argument("--path", default="", help="path of the item as shown in the findings")
    ap.add_argument("--sha256", default="", help="SHA-256 of the item, if shown")
    ap.add_argument("--grace", type=float, default=10.0, help="seconds before SIGKILL")
    ap.add_argument("--yes", action="store_true", help="do not ask for confirmation")
    args = ap.parse_args(argv)
    sha = args.sha256.strip().lower()
    if sha and (len(sha) != 64 or any(c not in "0123456789abcdef" for c in sha)):
        print(
            "forensic-escalate: --sha256 must be 64 hex characters. Copy it again.", file=sys.stderr
        )
        return 2
    run_dir: Path | None
    if args.run:
        run_dir = Path(args.run)
        if not run_dir.is_dir():
            print(
                f"forensic-escalate: {run_dir} is not a run folder. Check the path.",
                file=sys.stderr,
            )
            return 2
    else:
        live = running_runs()
        if len(live) > 1:
            print(
                "forensic-escalate: more than one analysis is running; pass --run RUN_DIR.",
                file=sys.stderr,
            )
            return 2
        run_dir = live[0] if live else None
    if not args.yes:
        try:
            ok = ui.ask_yes_no(
                TOOL,
                "Stop the analysis now and freeze its exports? The run cannot continue afterwards.",
                default=True,
                flag="--yes",
            )
        except ui.NonInteractiveError as exc:
            print(f"forensic-escalate: {exc}.", file=sys.stderr)
            return 2
        if not ok:
            print("Nothing was changed.")
            return 1
    try:
        esc = escalate(
            run_dir, finding_id=args.finding, path=args.path, sha256=sha, grace_s=args.grace
        )
    except (EscalateError, OSError) as exc:
        print(f"forensic-escalate: {exc}.", file=sys.stderr)
        return 1
    print(f"Run:        {esc.run_id or '(no run found; recorded in the session log)'}")
    print(f"Finding ID: {esc.finding_id or '(not given)'}")
    print(f"Path:       {esc.path or '(not given)'}")
    print(f"SHA-256:    {esc.sha256 or '(not known; the file was not read)'}")
    if run_dir is not None:
        stopped = "stopped" if esc.process_found else "was not running"
        print(f"Analysis {stopped}; {len(esc.frozen_dirs)} export folder(s) frozen.")
    print()
    print(GUIDANCE)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
