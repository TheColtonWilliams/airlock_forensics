"""evidence-triage: a first look at a drive or image, written to the session log (task 4.10).

Runs, in order, and logs each result:

1. ``mmls`` (The Sleuth Kit): the partition table;
2. ``fsstat`` on every allocated partition (or on the whole target when there is no table);
3. the evidence hash (SHA-256 and MD5, one read pass);
4. Dissect ``target-info --json`` (or ``target-query -f osinfo -j`` when only that exists).

Every tool opens the target read-only. A missing tool is logged as ``tool_missing`` and the
rest still runs. Tool output comes from the evidence: it is stored as data in the log and is
never passed to a shell.
"""

from __future__ import annotations

import argparse
import json
import re
from dataclasses import asdict, dataclass
from typing import Any

from airlock_common import jsonio, proc
from airlock_session import hashcmd
from airlock_session.common import (
    TargetInfo,
    clean_output,
    describe_target,
    human_size,
    log,
    open_session_log,
    run_main,
)

TOOL = "evidence-triage"
DEFAULT_TIMEOUT = 900.0

_ROW = re.compile(r"^(\d+):\s+(\S+)\s+(\d+)\s+(\d+)\s+(\d+)(?:\s+(.*))?$")
_UNITS = re.compile(r"Units are in (\d+)-byte sectors")
_FSTYPE = re.compile(r"^File System Type:\s*(.+)$", re.MULTILINE)


@dataclass
class Slot:
    slot: str
    start: int
    end: int
    length: int
    description: str

    @property
    def allocated(self) -> bool:
        return self.slot != "Meta" and not self.slot.startswith("-")


def parse_mmls(text: str) -> tuple[int, list[Slot]]:
    """Sector size and slots from ``mmls`` output."""
    m = _UNITS.search(text)
    sector = int(m.group(1)) if m else 512
    slots: list[Slot] = []
    for line in text.splitlines():
        row = _ROW.match(line.strip())
        if row:
            slots.append(
                Slot(
                    row.group(2),
                    int(row.group(3)),
                    int(row.group(4)),
                    int(row.group(5)),
                    (row.group(6) or "").strip(),
                )
            )
    return sector, slots


def parse_fstype(text: str) -> str:
    m = _FSTYPE.search(text)
    return m.group(1).strip() if m else ""


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=TOOL,
        description=(
            "First look at a drive or image: partition table (mmls), filesystem details "
            "(fsstat), hash, and Dissect target information, all logged. Read-only."
        ),
    )
    p.add_argument("target", help="a drive (for example /dev/sdb) or an image file")
    p.add_argument("--no-hash", action="store_true", help="skip the hash (it reads everything)")
    p.add_argument("--no-dissect", action="store_true", help="skip Dissect target information")
    p.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT,
        metavar="SECONDS",
        help=f"time limit for each tool (default {DEFAULT_TIMEOUT:.0f})",
    )
    p.add_argument("--json", action="store_true", help="print the summary as one JSON object")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return run_main(TOOL, lambda: run(args))


def _tool(name: str) -> str | None:
    path = proc.which(name)
    if not path:
        log(TOOL, "tool_missing", command=name)
    return path


def _run_tool(argv: list[str], timeout: float) -> dict[str, Any]:
    try:
        res = proc.run(argv, check=False, timeout=timeout, input_text="")
    except proc.ToolError as exc:
        return {"argv": argv, "returncode": None, "error": str(exc), "output": ""}
    out, cut = clean_output(res.stdout)
    err, err_cut = clean_output(res.stderr, 16 * 1024)
    return {
        "argv": argv,
        "returncode": res.returncode,
        "output": out,
        "output_truncated": cut,
        "stderr": err,
        "stderr_truncated": err_cut,
    }


def run_mmls(info: TargetInfo, timeout: float) -> tuple[int, list[Slot]] | None:
    if not _tool("mmls"):
        return None
    result = _run_tool(["mmls", info.path], timeout)
    sector, slots = parse_mmls(result["output"]) if result["returncode"] == 0 else (512, [])
    log(
        TOOL,
        "triage_mmls",
        has_partition_table=bool(slots),
        sector_size=sector,
        slots=[{**asdict(s), "allocated": s.allocated} for s in slots],
        **result,
    )
    return sector, slots


def run_fsstat(
    info: TargetInfo, sector: int, slots: list[Slot], timeout: float
) -> list[dict[str, Any]]:
    if not _tool("fsstat"):
        return []
    volumes: list[tuple[str, int, int, str]] = [
        (s.slot, s.start, s.length, s.description) for s in slots if s.allocated and s.length
    ]
    if not slots:
        volumes = [("whole", 0, info.size_bytes // max(sector, 1), "no partition table")]
    found: list[dict[str, Any]] = []
    for slot, start, length, desc in volumes:
        argv = ["fsstat"]
        if sector != 512:
            argv += ["-b", str(sector)]
        if start:
            argv += ["-o", str(start)]
        argv.append(info.path)
        result = _run_tool(argv, timeout)
        fs_type = parse_fstype(result["output"]) if result["returncode"] == 0 else ""
        entry = {
            "slot": slot,
            "start_sector": start,
            "length_sectors": length,
            "offset_bytes": start * sector,
            "description": desc,
            "fs_type": fs_type,
            "status": "filesystem" if fs_type else "no_filesystem_found",
        }
        log(TOOL, "triage_fsstat", **entry, **result)
        found.append(entry)
    return found


SUMMARY_KEYS = ("hostname", "domain", "os", "os_family", "os_version", "timezone")


def dissect_summary(parsed: Any) -> dict[str, Any]:
    """Main facts from ``target-info --json`` (an object) or osinfo records (name/value rows)."""
    facts: dict[str, Any] = {}
    if isinstance(parsed, dict):
        facts = dict(parsed)
    elif isinstance(parsed, list):
        for rec in parsed:
            if isinstance(rec, dict) and rec.get("_type") == "record" and "name" in rec:
                facts[str(rec["name"])] = rec.get("value")
    return {k: facts[k] for k in SUMMARY_KEYS if k in facts}


def run_dissect(info: TargetInfo, timeout: float) -> dict[str, Any] | None:
    if proc.which("target-info"):
        argv = ["target-info", "--json", "-q", info.path]
    elif proc.which("target-query"):
        argv = ["target-query", "-f", "osinfo", "-j", "-q", info.path]
    else:
        log(TOOL, "tool_missing", command="target-info")
        return None
    result = _run_tool(argv, timeout)
    parsed: Any = None
    if result["returncode"] == 0 and not result["output_truncated"]:
        try:
            parsed = json.loads(result["output"])
        except ValueError:
            try:
                parsed = [json.loads(ln) for ln in result["output"].splitlines() if ln.strip()]
            except ValueError:
                parsed = None
    summary = dissect_summary(parsed)
    log(TOOL, "triage_dissect", info=parsed, summary=summary, **result)
    return {"tool": argv[0], "returncode": result["returncode"], "summary": summary}


def run(args: argparse.Namespace) -> int:
    open_session_log(TOOL)
    info = describe_target(args.target)
    log(TOOL, "triage_start", target=info.to_dict())
    if not args.json:
        print(f"Triage of {info.path} ({info.kind}, {human_size(info.size_bytes)}), read-only.")
    summary: dict[str, Any] = {"target": info.to_dict()}

    mm = run_mmls(info, args.timeout)
    sector, slots = mm if mm is not None else (512, [])
    summary["partition_table"] = bool(slots)
    summary["partitions"] = [asdict(s) for s in slots if s.allocated]
    summary["volumes"] = run_fsstat(info, sector, slots, args.timeout)

    if not args.no_hash:
        if not args.json:
            print("Hashing (reads the whole target once) ...", flush=True)
        rec = hashcmd.hash_target(info, hashcmd.algorithms(False), tool=TOOL)
        summary["hashes"] = rec["hashes"]
    if not args.no_dissect:
        summary["dissect"] = run_dissect(info, args.timeout)

    log(TOOL, "triage_done", **{k: v for k, v in summary.items() if k != "target"})
    if args.json:
        print(jsonio.dumps(summary))
        return 0
    _print_summary(summary)
    return 0


def _print_summary(summary: dict[str, Any]) -> None:
    print(f"Partition table: {'yes' if summary['partition_table'] else 'none found'}")
    for v in summary["volumes"]:
        fs = v["fs_type"] or "no filesystem found"
        print(f"  slot {v['slot']}: at byte {v['offset_bytes']}, {fs} ({v['description']})")
    for algo, value in (summary.get("hashes") or {}).items():
        print(f"{hashcmd.LABELS.get(algo, algo):<8} {value}")
    dis = summary.get("dissect")
    if dis:
        facts = ", ".join(f"{k}={v}" for k, v in dis["summary"].items() if v) or "no OS details"
        print(f"Dissect ({dis['tool']}): {facts}")
    print("Full tool output is in the session log.")


if __name__ == "__main__":
    raise SystemExit(main())
