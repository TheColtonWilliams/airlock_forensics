"""Where the applied hash sets live and what each one is.

``/etc/airlock/hashsets.json`` (written by the ``tools_hashsets`` role) names the folders;
the metadata files next to each set (written by ``airlock_hashsets.build`` at provisioning)
give its name, version, and snapshot date. The NSRL database may live off the image: the
``nsrl_path`` key of ``/etc/airlock/airlock.conf.json`` (a file or a folder) is tried first,
then the folders in ``nsrl_dirs``.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from airlock_common import paths

CONFIG_NAME = "hashsets.json"
AIRLOCK_CONF = "airlock.conf.json"

DEFAULTS: dict[str, Any] = {
    "schema": 1,
    "clamav_dir": "/opt/hashsets/clamav",
    "nsrl_dirs": ["/opt/hashsets/nsrl"],
    "yara_dir": "/opt/yara",
    "ssdeep_dir": "/opt/hashsets/ssdeep",
    # ClamAV cannot scan files of 2 GiB or more; larger files are matched against the .hsb
    # sets in Python instead (triage._large_file_hsb).
    "clamscan_max_filesize_mib": 2047,
    "yara_timeout_s": 60,
    "ssdeep_threshold": 60,
    "tool_timeout_s": 7200,
}

# Database files clamscan loads from the ClamAV folder, in this order.
CLAMAV_DB_SUFFIXES: tuple[str, ...] = (".cvd", ".cld", ".hsb", ".hdb", ".ndb", ".ldb")
NSRL_SUFFIXES: tuple[str, ...] = (".db", ".sqlite", ".sqlite3")

CLAMAV_META = "databases.json"
MBZ_HSB = "malwarebazaar.hsb"
MBZ_META = "malwarebazaar.json"
MBZ_NAME = "MalwareBazaar"
MBZ_PREFIX = "MalwareBazaar."
YARA_RULES = "rules.yarc"
YARA_META = "pack.json"
NSRL_META = "nsrl.json"
SSDEEP_SUFFIX = ".ssdeep"
UNVERSIONED = "unversioned"


@dataclass(frozen=True)
class HashSet:
    """One applied hash set or rule pack."""

    kind: str  # nsrl | clamav | hsb | yara | ssdeep
    name: str
    version: str
    path: Path
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "name": self.name,
            "version": self.version,
            "path": str(self.path),
            **{k: v for k, v in sorted(self.details.items()) if k not in {"kind", "path"}},
        }


@dataclass
class Config:
    raw: dict[str, Any]
    nsrl: HashSet | None
    clamav_dbs: list[Path]
    clamav: HashSet | None
    hsb: list[HashSet]
    yara: list[HashSet]
    ssdeep: list[HashSet]
    problems: list[str] = field(default_factory=list)

    @property
    def clamscan_max_mib(self) -> int:
        value = self.raw.get("clamscan_max_filesize_mib")
        return 2047 if value is None else max(0, min(int(value), 2047))

    @property
    def yara_timeout(self) -> int:
        return int(self.raw.get("yara_timeout_s") or 60)

    @property
    def ssdeep_threshold(self) -> int:
        return int(self.raw.get("ssdeep_threshold") or 0)

    @property
    def tool_timeout(self) -> float:
        return float(self.raw.get("tool_timeout_s") or 7200)

    def db_dirs(self) -> list[str]:
        """Folders the scanners read (bound read-only into the parser sandbox)."""
        out: set[str] = set()
        for p in self.clamav_dbs:
            out.add(str(p.parent))
        for s in [*self.yara, *self.ssdeep]:
            out.add(str(s.path.parent))
        return sorted(out)

    def sets(self) -> list[HashSet]:
        out = [s for s in (self.nsrl, self.clamav) if s is not None]
        return out + self.hsb + self.yara + self.ssdeep

    def describe(self) -> dict[str, Any]:
        return {
            "sets": [s.to_dict() for s in self.sets()],
            "clamav_databases": [str(p) for p in self.clamav_dbs],
            "problems": list(self.problems),
        }


def _read_json(path: Path) -> dict[str, Any] | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def load_raw() -> dict[str, Any]:
    raw = dict(DEFAULTS)
    data = _read_json(paths.etc_dir() / CONFIG_NAME)
    if data:
        raw.update({k: v for k, v in data.items() if v is not None})
    return raw


def _nsrl_candidates(raw: dict[str, Any]) -> list[Path]:
    out: list[Path] = []
    conf = _read_json(paths.etc_dir() / AIRLOCK_CONF) or {}
    if isinstance(conf.get("nsrl_path"), str) and conf["nsrl_path"].strip():
        out.append(Path(conf["nsrl_path"].strip()))
    dirs = raw.get("nsrl_dirs") or []
    out += [Path(str(d)) for d in (dirs if isinstance(dirs, list) else [dirs]) if d]
    return out


def find_nsrl(raw: dict[str, Any]) -> Path | None:
    """The NSRL SQLite file: ``nsrl_path`` (file or folder) first, then ``nsrl_dirs``."""
    for cand in _nsrl_candidates(raw):
        if cand.is_file():
            return cand
        if cand.is_dir():
            found = sorted(
                p for p in cand.iterdir() if p.is_file() and p.suffix.lower() in NSRL_SUFFIXES
            )
            if found:
                return found[-1]  # newest release when names carry the release
    return None


def _nsrl_set(raw: dict[str, Any]) -> HashSet | None:
    db = find_nsrl(raw)
    if db is None:
        return None
    meta = _read_json(db.parent / NSRL_META) or {}
    version = str(meta.get("version") or "")
    return HashSet("nsrl", "NSRL RDS", version, db, {"meta": meta} if meta else {})


def _clamav(raw: dict[str, Any]) -> tuple[list[Path], HashSet | None, list[HashSet]]:
    folder = Path(str(raw.get("clamav_dir") or DEFAULTS["clamav_dir"]))
    if not folder.is_dir():
        return [], None, []
    order = {s: i for i, s in enumerate(CLAMAV_DB_SUFFIXES)}
    dbs = sorted(
        (p for p in folder.iterdir() if p.is_file() and p.suffix.lower() in order),
        key=lambda p: (order[p.suffix.lower()], p.name),
    )
    meta = _read_json(folder / CLAMAV_META) or {}
    versions = []
    for rec in meta.get("databases") or []:
        if isinstance(rec, dict) and rec.get("name"):
            versions.append(f"{rec['name']} {rec.get('version') or '?'}")
    vendor = [p for p in dbs if p.suffix.lower() in {".cvd", ".cld"}]
    clam = None
    if vendor or [p for p in dbs if p.suffix.lower() != ".hsb"]:
        version = ", ".join(versions) or ", ".join(p.stem for p in vendor) or UNVERSIONED
        clam = HashSet("clamav", "ClamAV", version, folder, {"databases": versions})
    hsb: list[HashSet] = []
    for p in dbs:
        if p.suffix.lower() != ".hsb":
            continue
        if p.name == MBZ_HSB:
            m = _read_json(folder / MBZ_META) or {}
            ver = str(m.get("snapshot") or m.get("staged_at") or UNVERSIONED)
            hsb.append(HashSet("hsb", MBZ_NAME, ver, p, {"prefix": MBZ_PREFIX, "meta": m}))
        else:
            m = _read_json(p.with_suffix(".json")) or {}
            hsb.append(
                HashSet(
                    "hsb",
                    str(m.get("name") or p.stem),
                    str(m.get("version") or UNVERSIONED),
                    p,
                    {"prefix": str(m.get("prefix") or ""), "meta": m},
                )
            )
    return dbs, clam, hsb


def _yara(raw: dict[str, Any]) -> list[HashSet]:
    folder = Path(str(raw.get("yara_dir") or DEFAULTS["yara_dir"]))
    if not folder.is_dir():
        return []
    out = []
    for sub in sorted(p for p in folder.iterdir() if p.is_dir()):
        rules = sub / YARA_RULES
        if not rules.is_file():
            continue
        meta = _read_json(sub / YARA_META) or {}
        out.append(
            HashSet(
                "yara",
                str(meta.get("name") or sub.name),
                str(meta.get("version") or UNVERSIONED),
                rules,
                {"meta": meta},
            )
        )
    return out


def _ssdeep(raw: dict[str, Any]) -> list[HashSet]:
    folder = Path(str(raw.get("ssdeep_dir") or DEFAULTS["ssdeep_dir"]))
    if not folder.is_dir():
        return []
    out = []
    for p in sorted(folder.glob(f"*{SSDEEP_SUFFIX}")):
        meta = _read_json(p.with_suffix(".json")) or {}
        out.append(
            HashSet(
                "ssdeep",
                str(meta.get("name") or p.stem),
                str(meta.get("version") or UNVERSIONED),
                p,
                {"meta": meta},
            )
        )
    return out


def load() -> Config:
    """Everything applied on this system. Missing sets are simply absent."""
    raw = load_raw()
    dbs, clam, hsb = _clamav(raw)
    cfg = Config(
        raw=raw,
        nsrl=_nsrl_set(raw),
        clamav_dbs=dbs,
        clamav=clam,
        hsb=hsb,
        yara=_yara(raw),
        ssdeep=_ssdeep(raw),
    )
    if cfg.nsrl is None:
        cfg.problems.append(
            "no NSRL database found (set nsrl_path in /etc/airlock/airlock.conf.json); "
            "known-good files are not dropped"
        )
    if not dbs:
        cfg.problems.append("no ClamAV databases or .hsb hash sets installed")
    if not cfg.yara:
        cfg.problems.append("no compiled YARA rule packs installed")
    return cfg
