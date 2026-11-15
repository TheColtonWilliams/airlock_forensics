"""Hash triage: hash, drop known-good, flag known-bad (tasks 4A.6, 4D.8).

For each file, in this order:

1. MD5, SHA-1 and SHA-256 in one read-only pass (``airlock_common.hashing``).
2. NSRL RDSv3 lookup, SHA-256 first (``nsrl``); a match is known software and is dropped from
   the scans below. The algorithm that matched is recorded.
3. ``clamscan`` with the ClamAV databases and every ``.hsb`` hash set (MalwareBazaar), no
   daemon. Files ClamAV cannot scan (2 GiB or more) are matched against the ``.hsb`` sets here.
4. ``yara`` with each compiled rule pack.
5. ``ssdeep`` fuzzy hash of the rest, matched against any known-hash lists. Fuzzy matches are
   ``inferred``; every other match is ``observed``.

Results go to a spreadsheet-safe CSV (UTF-8 with BOM, CRLF, every text cell escaped and
neutralised against formulas by ``forensic_analyze.csvsafe``) and the counts to the session
log. Nothing is ever written next to the input files.

``evidence-triage-hash`` (``main``) wraps ``triage_paths`` for folders, files, or a list file.
"""

from __future__ import annotations

import argparse
import contextlib
import csv
import os
import shutil
import stat
import subprocess
import sys
import tempfile
from collections import Counter
from collections.abc import Iterator, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from airlock_common import hashing, proc, sessionlog
from airlock_hashsets import TOOL, scanners
from airlock_hashsets import config as hcfg
from airlock_hashsets.nsrl import NsrlDb, NsrlError

OBSERVED = "observed"
INFERRED = "inferred"

CSV_COLUMNS: tuple[str, ...] = (
    "path",
    "size_bytes",
    "md5",
    "sha1",
    "sha256",
    "verdict",
    "nsrl",
    "nsrl_match_algorithm",
    "hash_hits",
    "clamav_hits",
    "yara_hits",
    "ssdeep",
    "fuzzy_hits",
    "notes",
)


@dataclass(frozen=True)
class Match:
    """One hash-set or signature match for one file."""

    kind: str  # nsrl_known_good | hash_hit | clamav_hit | yara_hit
    hashset_name: str
    hashset_version: str
    match_algorithm: str  # sha256 | sha1 | md5 | clamav | yara | ssdeep
    label: str
    derivation: str  # observed | inferred
    source_tool: str  # nsrl (sqlite3) | clamscan | yara | ssdeep | hsb (Python)
    score: float | None = None

    def short(self) -> str:
        text = f"{self.hashset_name} {self.hashset_version}: {self.label}"
        return text if self.score is None else f"{text} ({self.score:g})"


@dataclass
class TriageResult:
    path: str  # as shown to the examiner (the evidence path inside forensic-analyze)
    file: Path  # the file that was read
    size_bytes: int | None = None
    md5: str = ""
    sha1: str = ""
    sha256: str = ""
    ssdeep: str = ""
    nsrl: Match | None = None
    matches: list[Match] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def hashed(self) -> bool:
        return bool(self.sha256)

    @property
    def known_good(self) -> bool:
        return self.nsrl is not None

    @property
    def flagged(self) -> bool:
        return bool(self.matches)

    @property
    def verdict(self) -> str:
        if not self.hashed:
            return "error"
        if self.flagged:
            return "flagged"
        if self.known_good:
            return "known_good"
        return "no_match"

    def of_kind(self, kind: str, *, algorithm: str | None = None) -> list[Match]:
        return [
            m
            for m in self.matches
            if m.kind == kind and (algorithm is None or m.match_algorithm == algorithm)
        ]


@dataclass
class TriageRun:
    results: list[TriageResult]
    counts: dict[str, int]
    sets_used: list[dict[str, Any]]
    tool_versions: dict[str, str]
    warnings: list[str]
    csv_path: Path
    csv_sha256: str = ""
    nsrl_info: dict[str, Any] = field(default_factory=dict)


# --------------------------------------------------------------------------- runners


def plain_runner(workdir: Path) -> scanners.Runner:
    """No sandbox (tests, or ``--no-sandbox``): ``airlock_common.proc.run`` in ``workdir``."""

    def run(argv: Sequence[str], **kw: Any) -> subprocess.CompletedProcess[str]:
        res = proc.run(
            [str(a) for a in argv],
            check=False,
            timeout=kw.get("timeout"),
            stdout_path=kw.get("stdout_path"),
            cwd=workdir,
        )
        return subprocess.CompletedProcess(res.argv, res.returncode, res.stdout, res.stderr)

    return run


def default_runner(workdir: Path, read_only: Sequence[str]) -> tuple[scanners.Runner, str]:
    """The parser sandbox from ``forensic_analyze.sandbox`` (no network, parse user, limits).

    Returns the runner and the sandbox method (``none`` when not root: tests and dry use)."""
    from forensic_analyze import sandbox as sb  # noqa: PLC0415 - optional at import time

    box = sb.Sandbox(ro_paths=list(read_only))

    def run(argv: Sequence[str], **kw: Any) -> subprocess.CompletedProcess[str]:
        try:
            cp, _rec = box.run(
                [str(a) for a in argv],
                workdir=workdir,
                timeout=kw.get("timeout"),
                memory_bytes=kw.get("memory_bytes"),
                stdout_path=kw.get("stdout_path"),
                extra_ro=kw.get("extra_ro") or (),
            )
        except FileNotFoundError as exc:
            raise proc.ToolError(str(exc)) from exc
        except sb.SandboxError as exc:
            raise proc.ToolError(str(exc)) from exc
        return cp

    return run, box.method


# --------------------------------------------------------------------------- steps


def _hash_all(results: list[TriageResult]) -> None:
    for r in results:
        try:
            st = os.stat(r.file)
            if not stat.S_ISREG(st.st_mode):
                r.errors.append("not a regular file")
                continue
            r.size_bytes = st.st_size
            h = hashing.hash_file(r.file, ("md5", "sha1", "sha256"))
        except OSError as exc:
            r.errors.append(f"cannot read: {exc.strerror or exc}")
            continue
        r.md5, r.sha1, r.sha256 = h["md5"], h["sha1"], h["sha256"]


def _nsrl(cfg: hcfg.Config, results: list[TriageResult], run: TriageRun) -> None:
    if cfg.nsrl is None:
        return
    files = {
        str(i): {"sha256": r.sha256, "sha1": r.sha1, "md5": r.md5}
        for i, r in enumerate(results)
        if r.hashed
    }
    try:
        with NsrlDb(cfg.nsrl.path) as db:
            version = cfg.nsrl.version or db.version or "unknown release"
            run.nsrl_info = {**db.describe(), "version": version}
            found = db.lookup(files)
    except NsrlError as exc:
        run.warnings.append(f"NSRL database not used: {exc}")
        return
    for key, m in found.items():
        results[int(key)].nsrl = Match(
            "nsrl_known_good", "NSRL RDS", version, m.algorithm, "NSRL RDS", OBSERVED, "nsrl"
        )
    run.sets_used.append({"name": "NSRL RDS", "version": version, "kind": "nsrl"})


def _hsb_set_for(cfg: hcfg.Config, signature: str) -> hcfg.HashSet | None:
    for s in cfg.hsb:
        prefix = str(s.details.get("prefix") or "")
        if prefix and signature.startswith(prefix):
            return s
    return None


def _clam_match(cfg: hcfg.Config, signature: str) -> Match:
    sig = signature.removesuffix(".UNOFFICIAL")
    hs = _hsb_set_for(cfg, sig)
    if hs is not None:
        return Match("hash_hit", hs.name, hs.version, "sha256", sig, OBSERVED, "clamscan")
    name = cfg.clamav.name if cfg.clamav else "ClamAV"
    version = cfg.clamav.version if cfg.clamav else hcfg.UNVERSIONED
    return Match("clamav_hit", name, version, "clamav", sig, OBSERVED, "clamscan")


def _hsb_lines(path: Path) -> Iterator[tuple[str, str, str]]:
    with open(path, encoding="utf-8", errors="replace") as fh:
        for raw in fh:
            parts = raw.strip().split(":")
            if len(parts) >= 3 and not raw.startswith("#"):
                yield parts[0].lower(), parts[1], parts[2]


def _large_file_hsb(cfg: hcfg.Config, results: list[TriageResult], big: list[int]) -> None:
    """ClamAV cannot scan files of 2 GiB or more: match them against the .hsb sets here."""
    algo_of = {64: "sha256", 40: "sha1", 32: "md5"}
    for hs in cfg.hsb:
        wanted: dict[str, list[int]] = {}
        for i in big:
            r = results[i]
            for value in (r.sha256, r.sha1, r.md5):
                wanted.setdefault(value, []).append(i)
        for value, size, name in _hsb_lines(hs.path):
            for i in wanted.get(value, []):
                if size not in ("*", str(results[i].size_bytes)):
                    continue
                algo = algo_of.get(len(value), "hash")
                results[i].matches.append(
                    Match("hash_hit", hs.name, hs.version, algo, name, OBSERVED, "hsb")
                )


@dataclass
class _Scan:
    """State shared by the scan steps of one triage run."""

    cfg: hcfg.Config
    results: list[TriageResult]
    aliases: scanners.Aliases
    todo: list[int]  # indexes still to scan: hashed and not known good
    runner: scanners.Runner
    work: Path
    run: TriageRun

    def clamav(self) -> None:
        cfg, results, run = self.cfg, self.results, self.run
        if not cfg.clamav_dbs or not self.todo:
            return
        limit = cfg.clamscan_max_mib * 1024 * 1024
        small = [i for i in self.todo if (results[i].size_bytes or 0) < limit]
        big = [i for i in self.todo if (results[i].size_bytes or 0) >= limit]
        if big:
            _large_file_hsb(cfg, results, big)
            for i in big:
                results[i].notes.append(
                    f"not scanned by ClamAV (over {cfg.clamscan_max_mib} MiB); hash sets checked"
                )
        try:
            res = scanners.clamscan(
                self.runner,
                self.aliases,
                small,
                cfg.clamav_dbs,
                list_path=self.work / "clamscan.list",
                max_mib=cfg.clamscan_max_mib,
                timeout=cfg.tool_timeout,
            )
        except scanners.ScanError as exc:
            run.warnings.append(f"ClamAV scan did not run: {exc}")
            for i in small:
                results[i].notes.append("ClamAV scan did not run")
            return
        for i, sigs in res.hits.items():
            results[i].matches += [_clam_match(cfg, s) for s in sigs]
        for i, err in res.errors.items():
            results[i].errors.append(err)
        if cfg.clamav is not None:
            run.sets_used.append(
                {"name": cfg.clamav.name, "version": cfg.clamav.version, "kind": "clamav"}
            )
        run.sets_used += [{"name": s.name, "version": s.version, "kind": "hsb"} for s in cfg.hsb]

    def yara(self) -> None:
        cfg, results, run = self.cfg, self.results, self.run
        for pack in cfg.yara:
            if not self.todo:
                return
            try:
                res = scanners.yara(
                    self.runner,
                    self.aliases,
                    self.todo,
                    pack.path,
                    list_path=self.work / "yara.list",
                    per_file_timeout=cfg.yara_timeout,
                    timeout=cfg.tool_timeout,
                )
            except scanners.ScanError as exc:
                run.warnings.append(f"YARA pack {pack.name} did not run: {exc}")
                continue
            for i, rules in res.hits.items():
                results[i].matches += [
                    Match("yara_hit", pack.name, pack.version, "yara", rule, OBSERVED, "yara")
                    for rule in rules
                ]
            for i, err in res.errors.items():
                results[i].errors.append(f"{pack.name}: {err}")
            run.sets_used.append({"name": pack.name, "version": pack.version, "kind": "yara"})

    def ssdeep(self) -> None:
        cfg, results, run = self.cfg, self.results, self.run
        if not self.todo:
            return
        try:
            hashes = scanners.ssdeep_hashes(
                self.runner, self.aliases, self.todo, timeout=cfg.tool_timeout
            )
        except scanners.ScanError as exc:
            run.warnings.append(f"ssdeep did not run: {exc}")
            return
        for i, value in hashes.items():
            results[i].ssdeep = value
        for known in cfg.ssdeep:
            try:
                found = scanners.ssdeep_match(
                    self.runner,
                    self.aliases,
                    self.todo,
                    known.path,
                    threshold=cfg.ssdeep_threshold,
                    timeout=cfg.tool_timeout,
                )
            except scanners.ScanError as exc:
                run.warnings.append(f"ssdeep list {known.name} not matched: {exc}")
                continue
            for i, pairs in found.items():
                results[i].matches += [
                    Match(
                        "hash_hit",
                        known.name,
                        known.version,
                        "ssdeep",
                        name,
                        INFERRED,
                        "ssdeep",
                        score,
                    )
                    for name, score in sorted(pairs)
                ]
            run.sets_used.append({"name": known.name, "version": known.version, "kind": "ssdeep"})


# --------------------------------------------------------------------------- CSV and counts


def _join(items: Sequence[str]) -> str:
    return " | ".join(items)


def csv_row(r: TriageResult) -> dict[str, object]:
    hash_hits = [m for m in r.matches if m.kind == "hash_hit" and m.derivation == OBSERVED]
    fuzzy = [m for m in r.matches if m.match_algorithm == "ssdeep"]
    return {
        "path": r.path,
        "size_bytes": r.size_bytes,
        "md5": r.md5,
        "sha1": r.sha1,
        "sha256": r.sha256,
        "verdict": r.verdict,
        "nsrl": r.nsrl.hashset_version if r.nsrl else "",
        "nsrl_match_algorithm": r.nsrl.match_algorithm if r.nsrl else "",
        "hash_hits": _join([m.short() for m in hash_hits]),
        "clamav_hits": _join([m.short() for m in r.of_kind("clamav_hit")]),
        "yara_hits": _join([m.short() for m in r.of_kind("yara_hit")]),
        "ssdeep": r.ssdeep,
        "fuzzy_hits": _join([m.short() for m in fuzzy]),
        "notes": _join(r.errors + r.notes),
    }


def write_csv(results: Sequence[TriageResult], out_csv: Path) -> Path:
    """Write the triage CSV atomically: UTF-8 with BOM, CRLF, safe cells."""
    from forensic_analyze.csvsafe import csv_cell  # noqa: PLC0415 - shared CSV safety rules

    out_csv.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=f".{out_csv.name}.", dir=out_csv.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8-sig", newline="") as fh:
            w = csv.writer(fh, lineterminator="\r\n")
            w.writerow(CSV_COLUMNS)
            for r in results:
                row = csv_row(r)
                w.writerow([csv_cell(row[c]) for c in CSV_COLUMNS])
        Path(tmp).replace(out_csv)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise
    return out_csv


def count(results: Sequence[TriageResult]) -> dict[str, int]:
    c: Counter[str] = Counter()
    c["files"] = len(results)
    for r in results:
        c[r.verdict] += 1
        c["files_with_errors"] += bool(r.errors)
        for m in r.matches:
            key = "fuzzy_hits" if m.match_algorithm == "ssdeep" else f"{m.kind}s"
            c[key] += 1
        if r.nsrl is not None:
            c[f"nsrl_{r.nsrl.match_algorithm}"] += 1
    for k in ("known_good", "flagged", "no_match", "error", "hash_hits", "clamav_hits"):
        c.setdefault(k, 0)
    c.setdefault("yara_hits", 0)
    c.setdefault("fuzzy_hits", 0)
    return dict(sorted(c.items()))


# --------------------------------------------------------------------------- entry points


def triage_run(
    paths: Sequence[str | os.PathLike[str]],
    out_csv: str | os.PathLike[str],
    *,
    display: Sequence[str] | None = None,
    cfg: hcfg.Config | None = None,
    runner: scanners.Runner | None = None,
    workdir: Path | None = None,
    log: bool = True,
    tool: str = TOOL,
    versions: dict[str, str] | None = None,
) -> TriageRun:
    """Triage ``paths``; ``display`` gives the path to show per file (default: the path).

    ``versions`` (tool name to version) skips asking each scanner for its version."""
    cfg = cfg or hcfg.load()
    files = [Path(p) for p in paths]
    shown = list(display) if display is not None else [str(p) for p in files]
    if len(shown) != len(files):
        raise ValueError("display must give one path per file")
    results = [TriageResult(s, f) for s, f in zip(shown, files, strict=True)]
    run = TriageRun(results, {}, [], {}, list(cfg.problems), Path(out_csv))
    own_tmp = workdir is None
    work = Path(tempfile.mkdtemp(prefix="airlock-triage-")) if workdir is None else workdir
    work.mkdir(parents=True, exist_ok=True)
    try:
        if runner is None:
            parents = sorted({str(f.resolve().parent) for f in files})
            runner, _method = default_runner(work, [*parents, *cfg.db_dirs()])
        _hash_all(results)
        _nsrl(cfg, results, run)
        todo = [i for i, r in enumerate(results) if r.hashed and not r.known_good]
        aliases = scanners.Aliases([r.file for r in results], work / "alias")
        scan = _Scan(cfg, results, aliases, todo, runner, work, run)
        scan.clamav()
        scan.yara()
        scan.ssdeep()
        for name in ("clamscan", "yara", "ssdeep"):
            known = (versions or {}).get(name)
            run.tool_versions[name] = known or scanners.tool_version(runner, name) or "missing"
    finally:
        if own_tmp:
            shutil.rmtree(work, ignore_errors=True)
        else:
            shutil.rmtree(work / "alias", ignore_errors=True)
    run.counts = count(results)
    write_csv(results, run.csv_path)
    run.csv_sha256 = hashing.sha256_file(run.csv_path)
    if log:
        with contextlib.suppress(OSError):
            sessionlog.log_event(
                tool,
                "hash_triage",
                counts=run.counts,
                csv=str(run.csv_path),
                csv_sha256=run.csv_sha256,
                hashsets=run.sets_used,
                tool_versions=run.tool_versions,
                warnings=run.warnings,
            )
    return run


def triage_paths(
    paths: Sequence[str | os.PathLike[str]], out_csv: str | os.PathLike[str], **kw: Any
) -> list[TriageResult]:
    """Contract entry point (docs/dev/contract.md 8a): triage files, write the CSV."""
    return triage_run(paths, out_csv, **kw).results


# --------------------------------------------------------------------------- CLI


def _walk(root: Path) -> Iterator[Path]:
    """Regular files under ``root``, sorted, never following symlinks."""
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames.sort()
        for name in sorted(filenames):
            p = Path(dirpath) / name
            if p.is_file() and not p.is_symlink():
                yield p


def collect_inputs(inputs: Sequence[str], list_file: str | None) -> tuple[list[Path], list[Path]]:
    """Files to triage and the input roots (folders and files) they came from."""
    roots: list[Path] = []
    files: list[Path] = []
    named = list(inputs)
    if list_file:
        with open(list_file, encoding="utf-8", errors="surrogateescape") as fh:
            named += [ln.rstrip("\r\n") for ln in fh if ln.strip()]
    for item in named:
        p = Path(item)
        if p.is_symlink():
            raise FileNotFoundError(f"{item}: is a symbolic link; give the real file or folder")
        if p.is_dir():
            roots.append(p.resolve())
            files += list(_walk(p))
        elif p.is_file():
            roots.append(p.resolve().parent)
            files.append(p)
        else:
            raise FileNotFoundError(f"{item}: not found (give a folder, a file, or --list FILE)")
    return files, roots


def _inside(path: Path, roots: Sequence[Path]) -> bool:
    p = path.resolve()
    return any(p == r or r in p.parents for r in roots)


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog=TOOL,
        description="Hash files and check them against NSRL (known software), ClamAV, "
        "MalwareBazaar, YARA, and ssdeep lists. Offline; reads files only.",
    )
    ap.add_argument("inputs", nargs="*", help="folders (searched recursively) or files")
    ap.add_argument("--list", dest="list_file", help="file with one path per line")
    ap.add_argument("-o", "--output", required=True, help="CSV to write (not on the evidence)")
    ap.add_argument(
        "--no-sandbox", action="store_true", help="run the scanners without the parser sandbox"
    )
    ap.add_argument("--quiet", action="store_true", help="print only the summary line")
    return ap


def _fail(message: str, code: int = 1) -> int:
    print(f"{TOOL}: {message}", file=sys.stderr)
    with contextlib.suppress(OSError):
        sessionlog.log_event(TOOL, "failed", reason=message, exit_code=code)
    return code


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not args.inputs and not args.list_file:
        return _fail("nothing to check. Give a folder, files, or --list FILE.", 2)
    try:
        files, roots = collect_inputs(args.inputs, args.list_file)
    except (FileNotFoundError, OSError) as exc:
        return _fail(f"{exc}. Check the path and rerun.", 2)
    out = Path(args.output)
    if _inside(out.parent if not out.exists() else out, roots):
        return _fail(
            "the output CSV would be written inside the folder being checked. Write it to the "
            "OUTPUT drive instead (for example -o /srv/airlock/output/triage.csv)."
        )
    cfg = hcfg.load()
    with tempfile.TemporaryDirectory(prefix="airlock-triage-") as tmp:
        work = Path(tmp)
        runner = plain_runner(work) if args.no_sandbox else None
        try:
            run = triage_run(files, out, cfg=cfg, runner=runner, workdir=work)
        except (OSError, proc.ToolError) as exc:
            return _fail(f"triage failed: {exc}. Check the output drive is writable and rerun.")
    c = run.counts
    if not args.quiet:
        for w in run.warnings:
            print(f"{TOOL}: note: {w}")
        for r in run.results:
            if r.flagged:
                labels = "; ".join(m.short() for m in r.matches)
                print(f"FLAGGED  {csv_safe_display(r.path)}  {labels}")
    print(
        f"{TOOL}: {c['files']} files: {c['known_good']} known software (NSRL), "
        f"{c['flagged']} flagged, {c['no_match']} no match, {c['error']} not readable. "
        f"CSV: {run.csv_path}"
    )
    return 0


def csv_safe_display(text: str) -> str:
    from forensic_analyze.csvsafe import display_escape  # noqa: PLC0415

    return display_escape(text)


if __name__ == "__main__":
    raise SystemExit(main())
