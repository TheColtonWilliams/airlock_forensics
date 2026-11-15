"""Provisioning steps for hash sets and signatures, run offline by the ``tools_hashsets`` role.

``python3 -P -m airlock_hashsets.build <step> ...`` with PYTHONPATH set to the pylib folder.
Every step reads a file that ``forensic-provision`` has already checked against the signed
manifest (or, for daily files, the hash the fetcher recorded), writes only under its
destination folder, prints one JSON object (``changed`` tells Ansible whether anything was
written), logs what it applied to the session log, and does nothing on a rerun with the same
input (idempotent).

Steps:

* ``mbz-hsb`` (4A.4): MalwareBazaar full SHA-256 export (zip or text) to a ClamAV ``.hsb``.
  Each line becomes ``<sha256>:*:MalwareBazaar.<first 16 hex>:73``: the size is unknown, and
  ClamAV accepts a ``*`` size only with a minimum functionality level of 73 (checked with
  ClamAV 1.5.4, which refuses a wildcard line without it). Snapshot date and hashes are logged.
* ``clamav`` (4A.3): ``sigtool --info`` must report ``Verification OK`` for each ``.cvd`` or
  ``.cld`` (ClamAV's own signature); the databases are then copied to the ClamAV folder and
  their versions recorded.
* ``yara`` (4A.5): a rule pack archive (tar or zip) is unpacked safely and compiled with
  ``yarac``; external variables (``filename``, ``filepath``, ...) are defined empty so rules
  that use them compile, and evidence names are never passed at scan time. Files that do not
  compile are skipped and listed.
* ``nsrl`` (4A.2): the NSRL RDSv3 SQLite file is extracted from its zip, opened read-only to
  prove it is usable, and its release recorded.
"""

from __future__ import annotations

import argparse
import contextlib
import datetime as dt
import io
import json
import os
import re
import shutil
import sys
import tarfile
import tempfile
import zipfile
from collections.abc import Iterator, Sequence
from pathlib import Path, PurePosixPath
from typing import Any

from airlock_common import hashing, jsonio, proc, sessionlog, timeutil
from airlock_hashsets import config as hcfg
from airlock_hashsets.nsrl import NsrlDb, NsrlError

TOOL = "tools_hashsets"
HSB_FLEVEL = 73
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
SNAPSHOT_RE = re.compile(r"last\s+updated\s*:\s*([0-9]{4}-[0-9]{2}-[0-9]{2}[^#]*?)\s*(?:#|$)", re.I)
MAX_TEXT_BYTES = 4 * 1024**3  # refuse an export that unpacks to more than this
MAX_RULE_BYTES = 512 * 1024**2
YARA_EXTERNALS: tuple[str, ...] = ("filename", "filepath", "extension", "filetype", "owner", "md5")
YARA_SUFFIXES: tuple[str, ...] = (".yar", ".yara")


class BuildError(RuntimeError):
    """A step cannot be applied; the message says why and what to do."""


# --------------------------------------------------------------------------- helpers


def _atomic_write_bytes(path: Path, chunks: Iterator[bytes]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as fh:
            for chunk in chunks:
                fh.write(chunk)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, 0o644)
        Path(tmp).replace(path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def _copy(src: Path, dest: Path) -> None:
    def chunks() -> Iterator[bytes]:
        with open(src, "rb") as fh:
            while block := fh.read(hashing.BLOCK):
                yield block

    _atomic_write_bytes(dest, chunks())


def _load(path: Path) -> dict[str, Any]:
    try:
        data = jsonio.load_json(path)
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _same(meta: dict[str, Any], **want: Any) -> bool:
    return bool(meta) and all(meta.get(k) == v for k, v in want.items())


def _log(event: str, **fields: Any) -> None:
    with contextlib.suppress(OSError):
        sessionlog.log_event(TOOL, event, **fields)


def _check_source(path: Path, sha256: str | None) -> str:
    if not path.is_file():
        raise BuildError(f"{path} is not on ASSETS. Restage the drive with fetch-assets.")
    actual = hashing.sha256_file(path)
    if sha256 and actual != sha256.lower():
        raise BuildError(
            f"{path} does not match the checked SHA-256 (changed since it was verified). "
            "Restage the drive with fetch-assets and run 'sudo forensic-import'."
        )
    return actual


# --------------------------------------------------------------------------- MalwareBazaar


def _export_text(source: Path) -> Iterator[str]:
    """Lines of the export, from a zip (one .txt member) or a plain text file."""
    if zipfile.is_zipfile(source):
        with zipfile.ZipFile(source) as zf:
            members = [i for i in zf.infolist() if not i.is_dir()]
            texts = [i for i in members if i.filename.lower().endswith((".txt", ".csv"))]
            if len(texts) != 1:
                names = ", ".join(i.filename for i in members[:5])
                raise BuildError(f"expected one .txt file in the MalwareBazaar zip, found: {names}")
            info = texts[0]
            if info.file_size > MAX_TEXT_BYTES:
                raise BuildError("the MalwareBazaar export unpacks to more than 4 GiB; refusing")
            with zf.open(info) as raw:
                yield from io.TextIOWrapper(raw, encoding="utf-8", errors="replace")
        return
    with open(source, encoding="utf-8", errors="replace") as fh:
        yield from fh


def parse_export(source: Path) -> tuple[list[str], str]:
    """Sorted unique SHA-256 values and the snapshot date from the export header."""
    hashes: set[str] = set()
    snapshot = ""
    for n, raw in enumerate(_export_text(source), start=1):
        line = raw.strip()
        if not line:
            continue
        if line.startswith("#"):
            m = SNAPSHOT_RE.search(line)
            if m and not snapshot:
                snapshot = m.group(1).strip()
            continue
        value = line.split(",")[0].strip().strip('"').lower()
        if not SHA256_RE.match(value):
            raise BuildError(
                f"line {n} of the MalwareBazaar export is not a SHA-256 value; the file is "
                "damaged or not the full SHA-256 export. Restage it with fetch-assets."
            )
        hashes.add(value)
    if not hashes:
        raise BuildError("the MalwareBazaar export holds no SHA-256 values; restage it.")
    return sorted(hashes), snapshot


def hsb_line(sha256: str) -> str:
    return f"{sha256}:*:{hcfg.MBZ_PREFIX}{sha256[:16]}:{HSB_FLEVEL}\n"


def step_mbz(source: Path, source_sha256: str | None, dest: Path, staged_at: str) -> dict[str, Any]:
    actual = _check_source(source, source_sha256)
    hsb = dest / hcfg.MBZ_HSB
    meta_path = dest / hcfg.MBZ_META
    meta = _load(meta_path)
    if (
        _same(meta, source_sha256=actual)
        and hsb.is_file()
        and hashing.sha256_file(hsb) == meta.get("hsb_sha256")
    ):
        return {"changed": False, **meta}
    hashes, snapshot = parse_export(source)

    def chunks() -> Iterator[bytes]:
        buf: list[str] = []
        for h in hashes:
            buf.append(hsb_line(h))
            if len(buf) >= 10000:
                yield "".join(buf).encode("ascii")
                buf.clear()
        if buf:
            yield "".join(buf).encode("ascii")

    _atomic_write_bytes(hsb, chunks())
    meta = {
        "applied_at": timeutil.iso(),
        "entries": len(hashes),
        "flevel": HSB_FLEVEL,
        "hsb": str(hsb),
        "hsb_sha256": hashing.sha256_file(hsb),
        "name": hcfg.MBZ_NAME,
        "prefix": hcfg.MBZ_PREFIX,
        "schema": 1,
        "snapshot": snapshot or staged_at or "unknown",
        "snapshot_source": "export header" if snapshot else "staging time",
        "source": str(source),
        "source_sha256": actual,
    }
    jsonio.dump_json(meta_path, meta)
    _log("hashset_applied", **{k: meta[k] for k in sorted(meta) if k != "applied_at"})
    return {"changed": True, **meta}


# --------------------------------------------------------------------------- ClamAV


def sigtool_info(path: Path) -> dict[str, str]:
    """``sigtool --info``; raises unless ClamAV's own signature verifies."""
    try:
        res = proc.run(["sigtool", f"--info={path}"], check=False, timeout=900)
    except proc.ToolError as exc:
        raise BuildError(f"sigtool could not run ({exc}). Reflash the drive.") from exc
    info: dict[str, str] = {}
    for line in res.stdout.splitlines():
        key, sep, value = line.partition(":")
        if sep:
            info[key.strip().lower().replace(" ", "_")] = value.strip()
    if res.returncode != 0 or "Verification OK" not in res.stdout:
        raise BuildError(
            f"{path.name}: ClamAV signature check failed (sigtool). The file is damaged or not "
            "from ClamAV. Restage it with fetch-assets."
        )
    return info


def step_clamav(sources: Sequence[Path], dest: Path) -> dict[str, Any]:
    dest.mkdir(parents=True, exist_ok=True)
    meta_path = dest / hcfg.CLAMAV_META
    old = {str(r.get("file")): r for r in _load(meta_path).get("databases") or []}
    records: list[dict[str, Any]] = []
    changed = False
    for src in sorted(sources, key=lambda p: p.name):
        if src.suffix.lower() not in (".cvd", ".cld"):
            raise BuildError(f"{src.name} is not a ClamAV .cvd or .cld file")
        sha = hashing.sha256_file(src)
        target = dest / src.name
        prev = old.get(src.name)
        unchanged = prev and prev.get("sha256") == sha and target.is_file()
        if unchanged and hashing.sha256_file(target) == sha:
            records.append(prev)
            continue
        info = sigtool_info(src)
        _copy(src, target)
        changed = True
        records.append(
            {
                "build_time": info.get("build_time", ""),
                "file": src.name,
                "name": src.stem,
                "sha256": sha,
                "signatures": info.get("signatures", ""),
                "verified": "sigtool: Verification OK",
                "version": info.get("version", ""),
            }
        )
    keep = {r["file"] for r in records} | {hcfg.MBZ_HSB}
    for stale in sorted(dest.iterdir()):
        if stale.suffix.lower() in (".cvd", ".cld") and stale.name not in keep:
            stale.unlink()
            changed = True
    meta = {"databases": records, "schema": 1}
    if changed or _load(meta_path).get("databases") != records:
        jsonio.dump_json(meta_path, {**meta, "applied_at": timeutil.iso()})
        _log("clamav_databases_applied", databases=records)
        changed = True
    return {"changed": changed, **meta}


# --------------------------------------------------------------------------- YARA


def _safe_member(name: str) -> PurePosixPath | None:
    p = PurePosixPath(name)
    if p.is_absolute() or any(part in ("", "..") for part in p.parts):
        return None
    return p


def unpack_rules(archive: Path, dest: Path) -> list[Path]:
    """Unpack only ``.yar``/``.yara`` files from a tar or zip, refusing unsafe names."""
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True)
    out: list[Path] = []
    total = 0
    if zipfile.is_zipfile(archive):
        with zipfile.ZipFile(archive) as zf:
            for info in zf.infolist():
                rel = _safe_member(info.filename)
                if info.is_dir() or rel is None or rel.suffix.lower() not in YARA_SUFFIXES:
                    continue
                total += info.file_size
                if total > MAX_RULE_BYTES:
                    raise BuildError("the rule pack unpacks to more than 512 MiB; refusing")
                target = dest / rel
                target.parent.mkdir(parents=True, exist_ok=True)
                with zf.open(info) as src, open(target, "wb") as fh:
                    shutil.copyfileobj(src, fh)
                out.append(target)
    elif tarfile.is_tarfile(archive):
        with tarfile.open(archive) as tf:
            for member in tf.getmembers():
                rel = _safe_member(member.name)
                if not member.isfile() or rel is None or rel.suffix.lower() not in YARA_SUFFIXES:
                    continue
                total += member.size
                if total > MAX_RULE_BYTES:
                    raise BuildError("the rule pack unpacks to more than 512 MiB; refusing")
                tf.extract(member, dest, filter="data")
                out.append(dest / rel)
    elif archive.suffix.lower() in YARA_SUFFIXES:
        target = dest / archive.name
        shutil.copyfile(archive, target)
        out.append(target)
    else:
        raise BuildError(f"{archive.name} is not a tar or zip archive of YARA rules")
    return sorted(out)


def _yarac(files: Sequence[Path], out: Path) -> proc.Result:
    defines = [a for name in YARA_EXTERNALS for a in ("-d", f"{name}=")]
    return proc.run(
        ["yarac", *defines, *[str(f) for f in files], str(out)], check=False, timeout=3600
    )


def compile_rules(files: Sequence[Path], out: Path) -> tuple[list[Path], list[dict[str, str]]]:
    """Compile all files into ``out``; on failure, keep only the files that compile alone."""
    if not files:
        raise BuildError("the rule pack holds no .yar or .yara files")
    tmp = out.with_name(f".{out.name}.tmp")
    if _yarac(files, tmp).returncode == 0:
        tmp.replace(out)
        return list(files), []
    good: list[Path] = []
    skipped: list[dict[str, str]] = []
    probe = out.with_name(f".{out.name}.probe")
    for f in files:
        res = _yarac([f], probe)
        if res.returncode == 0:
            good.append(f)
        else:
            reason = (res.stderr.strip().splitlines() or ["did not compile"])[-1]
            skipped.append({"file": f.name, "reason": reason[:200]})
    probe.unlink(missing_ok=True)
    if not good or _yarac(good, tmp).returncode != 0:
        tmp.unlink(missing_ok=True)
        raise BuildError("no file in the rule pack compiles with this YARA version")
    tmp.replace(out)
    return good, skipped


def step_yara(
    source: Path, source_sha256: str | None, dest: Path, name: str, version: str
) -> dict[str, Any]:
    actual = _check_source(source, source_sha256)
    rules = dest / hcfg.YARA_RULES
    meta_path = dest / hcfg.YARA_META
    yarac_version = proc.run(["yarac", "--version"], check=False, timeout=60).stdout.strip()
    meta = _load(meta_path)
    same = _same(meta, source_sha256=actual, yarac=yarac_version, name=name, version=version)
    if same and rules.is_file() and hashing.sha256_file(rules) == meta.get("rules_sha256"):
        return {"changed": False, **meta}
    dest.mkdir(parents=True, exist_ok=True)
    files = unpack_rules(source, dest / "src")
    good, skipped = compile_rules(files, rules)
    os.chmod(rules, 0o644)
    src_root = dest / "src"
    meta = {
        "applied_at": timeutil.iso(),
        "externals_empty": list(YARA_EXTERNALS),
        "name": name,
        "rule_files": len(good),
        "rules": str(rules),
        "rules_sha256": hashing.sha256_file(rules),
        "schema": 1,
        "skipped": skipped,
        "source": str(source),
        "source_sha256": actual,
        "version": version,
        "yarac": yarac_version,
    }
    meta["files"] = [str(f.relative_to(src_root)) for f in good]
    jsonio.dump_json(meta_path, meta)
    _log(
        "yara_pack_applied",
        name=name,
        version=version,
        source_sha256=actual,
        rules_sha256=meta["rules_sha256"],
        rule_files=len(good),
        skipped=len(skipped),
    )
    return {"changed": True, **{k: v for k, v in meta.items() if k != "files"}}


# --------------------------------------------------------------------------- NSRL


def step_nsrl(source: Path, source_sha256: str | None, dest: Path, version: str) -> dict[str, Any]:
    actual = _check_source(source, source_sha256)
    meta_path = dest / hcfg.NSRL_META
    meta = _load(meta_path)
    db_path = dest / str(meta.get("db_file") or "_")
    same = _same(meta, source_sha256=actual) and db_path.is_file()
    if same and db_path.stat().st_size == meta.get("db_size"):
        return {"changed": False, **meta}
    dest.mkdir(parents=True, exist_ok=True)
    if zipfile.is_zipfile(source):
        with zipfile.ZipFile(source) as zf:
            dbs = [
                i
                for i in zf.infolist()
                if not i.is_dir() and PurePosixPath(i.filename).suffix.lower() in hcfg.NSRL_SUFFIXES
            ]
            if not dbs:
                raise BuildError("the NSRL zip holds no .db file; restage it with fetch-assets")
            info = max(dbs, key=lambda i: i.file_size)
            name = PurePosixPath(info.filename).name
            target = dest / name

            def chunks() -> Iterator[bytes]:
                with zf.open(info) as raw:
                    while block := raw.read(hashing.BLOCK):
                        yield block

            _atomic_write_bytes(target, chunks())
    else:
        name = source.name
        target = dest / name
        _copy(source, target)
    try:
        with NsrlDb(target) as db:
            info_db = db.describe()
    except NsrlError as exc:
        target.unlink(missing_ok=True)
        raise BuildError(f"the NSRL file is not usable: {exc}") from exc
    for old in dest.iterdir():
        if old.is_file() and old.suffix.lower() in hcfg.NSRL_SUFFIXES and old.name != name:
            old.unlink()
    meta = {
        "applied_at": timeutil.iso(),
        "db_file": name,
        "db_size": target.stat().st_size,
        "indexed": info_db["indexed"],
        "schema": 1,
        "source": str(source),
        "source_sha256": actual,
        "version": version or str(info_db.get("version") or ""),
    }
    jsonio.dump_json(meta_path, meta)
    _log("nsrl_applied", **{k: meta[k] for k in sorted(meta) if k != "applied_at"})
    return {"changed": True, **meta}


# --------------------------------------------------------------------------- self-check


def _loads(argv: list[str]) -> str:
    """An empty string when the tool loads its database and scans an empty file, else why."""
    with tempfile.TemporaryDirectory(prefix="airlock-hs-check-") as tmp:
        empty = Path(tmp) / "empty"
        empty.write_bytes(b"")
        try:
            res = proc.run([*argv, str(empty)], check=False, timeout=900)
        except proc.ToolError as exc:
            return str(exc)
    if res.returncode == 0:
        return ""
    return ((res.stderr or res.stdout).strip().splitlines() or ["failed"])[-1][:200]


def step_check(features: dict[str, Any] | None = None) -> tuple[bool, list[str]]:
    """Every hash set the applied profile turned on is present and loads (task 4A.8)."""
    from airlock_common import assets  # noqa: PLC0415 - only the self-check needs it

    if features is None:
        features = (assets.load_applied() or {}).get("features") or {}
    cfg = hcfg.load()
    lines: list[str] = []
    ok = True

    def need(cond: bool, good: str, bad: str) -> None:
        nonlocal ok
        lines.append(f"ok: {good}" if cond else f"MISSING: {bad}")
        ok = ok and cond

    for tool in ("clamscan", "sigtool", "yara", "yarac", "ssdeep"):
        need(proc.which(tool) is not None, f"{tool} installed", f"{tool} is not installed")
    if features.get("malwarebazaar"):
        mbz = [h for h in cfg.hsb if h.name == hcfg.MBZ_NAME]
        need(bool(mbz), "MalwareBazaar .hsb present", "no MalwareBazaar .hsb")
        if mbz:
            err = _loads(["clamscan", "--no-summary", "-d", str(mbz[0].path)])
            need(not err, f"clamscan loads {mbz[0].path.name}", f"clamscan: {err}")
    if features.get("clamav"):
        vendor = [p for p in cfg.clamav_dbs if p.suffix in (".cvd", ".cld")]
        need(bool(vendor), "ClamAV databases present", "no ClamAV .cvd or .cld databases")
        if vendor:
            dbs = [a for p in vendor for a in ("-d", str(p))]
            err = _loads(["clamscan", "--no-summary", *dbs])
            need(not err, "clamscan loads the ClamAV databases", f"clamscan: {err}")
    if features.get("yara"):
        need(bool(cfg.yara), "YARA rule packs present", "no compiled YARA rule pack")
        for pack in cfg.yara:
            err = _loads(["yara", "--compiled-rules", "--no-warnings", str(pack.path)])
            need(not err, f"yara loads {pack.name}", f"yara {pack.name}: {err}")
    if features.get("nsrl"):
        need(cfg.nsrl is not None, "NSRL database found", "no NSRL database (see nsrl_path)")
        if cfg.nsrl is not None:
            try:
                with NsrlDb(cfg.nsrl.path):
                    pass
                need(True, f"NSRL opens read-only ({cfg.nsrl.path})", "")
            except NsrlError as exc:
                need(False, "", f"NSRL: {exc}")
    lines.append("hash sets: ok" if ok else "hash sets: problems found")
    return ok, lines


# --------------------------------------------------------------------------- CLI


def _parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="airlock_hashsets.build", description=__doc__)
    sub = ap.add_subparsers(dest="step", required=True)
    m = sub.add_parser("mbz-hsb", help="MalwareBazaar export to a ClamAV .hsb")
    m.add_argument("--source", type=Path, required=True)
    m.add_argument("--source-sha256", default="")
    m.add_argument("--dest", type=Path, required=True)
    m.add_argument("--staged-at", default="")
    c = sub.add_parser("clamav", help="check ClamAV databases with sigtool and install them")
    c.add_argument("--source", type=Path, action="append", required=True)
    c.add_argument("--dest", type=Path, required=True)
    y = sub.add_parser("yara", help="unpack and compile one YARA rule pack")
    y.add_argument("--source", type=Path, required=True)
    y.add_argument("--source-sha256", default="")
    y.add_argument("--dest", type=Path, required=True)
    y.add_argument("--name", required=True)
    y.add_argument("--version", required=True)
    n = sub.add_parser("nsrl", help="extract the NSRL RDSv3 SQLite database")
    n.add_argument("--source", type=Path, required=True)
    n.add_argument("--source-sha256", default="")
    n.add_argument("--dest", type=Path, required=True)
    n.add_argument("--version", default="")
    k = sub.add_parser("check", help="check the applied hash sets are present and load")
    k.add_argument("--features", default="", help="JSON object (default: the applied profile)")
    return ap


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.step == "check":
        feats = json.loads(args.features) if args.features else None
        ok, lines = step_check(feats)
        print("\n".join(lines))
        return 0 if ok else 1
    try:
        if args.step == "mbz-hsb":
            staged = args.staged_at or dt.datetime.now(dt.UTC).strftime("%Y-%m-%d")
            out = step_mbz(args.source, args.source_sha256 or None, args.dest, staged)
        elif args.step == "clamav":
            out = step_clamav(args.source, args.dest)
        elif args.step == "yara":
            out = step_yara(
                args.source, args.source_sha256 or None, args.dest, args.name, args.version
            )
        else:
            out = step_nsrl(args.source, args.source_sha256 or None, args.dest, args.version)
    except (BuildError, OSError, proc.ToolError) as exc:
        print(f"airlock_hashsets.build {args.step}: {exc}", file=sys.stderr)
        _log("hashset_failed", step=args.step, reason=str(exc))
        return 1
    print(json.dumps(out, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
