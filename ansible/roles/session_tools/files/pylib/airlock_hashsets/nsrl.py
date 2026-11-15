"""Read-only lookups in an NSRL RDSv3 SQLite database (task 4A.2, 4D.8).

RDSv3 keeps one row per known file in table ``FILE`` with ``sha256``, ``sha1``, ``md5``,
``crc32``, ``file_name``, ``file_size``, ``package_id``; the release is in table ``VERSION``.
The column names and the hex case are detected rather than assumed, so a later release or
the ``minimal`` and full builds all work.

Matching order: SHA-256 first. SHA-1, then MD5, are used only for rows that carry no SHA-256
(older data), and the algorithm that produced each match is recorded. A row whose SHA-256
differs from the file's never matches on a weaker hash, so a crafted MD5 or SHA-1 collision
cannot make a file look known.

The database is opened ``mode=ro&immutable=1``: nothing is written, no journal or lock file
is created, so it can sit on a read-only or exFAT drive.
"""

from __future__ import annotations

import re
import sqlite3
import urllib.parse
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

ALGOS: tuple[str, ...] = ("sha256", "sha1", "md5")
HEX_LEN = {"sha256": 64, "sha1": 40, "md5": 32}
CHUNK = 500
_IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


class NsrlError(RuntimeError):
    """The file is not a usable NSRL database."""


@dataclass(frozen=True)
class NsrlMatch:
    algorithm: str  # sha256 | sha1 | md5
    value: str  # the matching hash, lower-case


def _quote(name: str) -> str:
    if not _IDENT.match(name):
        raise NsrlError(f"unexpected column or table name {name!r}")
    return f'"{name}"'


class NsrlDb:
    """One NSRL database, opened read-only. Use as a context manager."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        if not self.path.is_file():
            raise NsrlError(f"{self.path}: not found")
        uri = "file:" + urllib.parse.quote(str(self.path.resolve())) + "?mode=ro&immutable=1"
        try:
            self.conn = sqlite3.connect(uri, uri=True)
            self.conn.execute("PRAGMA query_only = ON")
            self.table, self.columns = self._find_table()
        except sqlite3.DatabaseError as exc:
            raise NsrlError(f"{self.path}: not an SQLite database ({exc})") from exc
        self.upper = self._hex_upper()
        self.indexed = self._indexed_columns()
        self.version = self._version()

    # ------------------------------------------------------------------ discovery

    def _find_table(self) -> tuple[str, dict[str, str]]:
        rows = self.conn.execute(
            "SELECT name FROM sqlite_master WHERE type IN ('table', 'view') ORDER BY name"
        ).fetchall()
        names = [str(r[0]) for r in rows]
        # Prefer the RDSv3 table name, then any table that has a sha256 column.
        names.sort(key=lambda n: (n.upper() != "FILE", n))
        for name in names:
            if not _IDENT.match(name):
                continue
            cols = {
                str(c[1]).lower(): str(c[1])
                for c in self.conn.execute(f"PRAGMA table_info({_quote(name)})")
            }
            found = {a: cols[a] for a in ALGOS if a in cols}
            if "sha256" in found:
                return name, found
        raise NsrlError(f"{self.path}: no table with a sha256 column (not an RDSv3 database)")

    def _hex_upper(self) -> bool:
        col = _quote(self.columns["sha256"])
        row = self.conn.execute(
            f"SELECT {col} FROM {_quote(self.table)} WHERE {col} IS NOT NULL AND {col} != '' "  # noqa: S608 - names checked by _quote
            "LIMIT 1"
        ).fetchone()
        return bool(row) and str(row[0]) != str(row[0]).lower()

    def _indexed_columns(self) -> set[str]:
        out: set[str] = set()
        for idx in self.conn.execute(f"PRAGMA index_list({_quote(self.table)})").fetchall():
            name = str(idx[1])
            if not _IDENT.match(name):
                continue
            info = self.conn.execute(f"PRAGMA index_info({_quote(name)})").fetchall()
            if info and info[0][2] is not None:
                out.add(str(info[0][2]).lower())  # leading column only
        return out

    def _version(self) -> str:
        try:
            cur = self.conn.execute('SELECT * FROM "VERSION" LIMIT 1')
        except sqlite3.DatabaseError:
            return ""
        row = cur.fetchone()
        if not row:
            return ""
        cols = [str(d[0]).lower() for d in cur.description]
        rec = dict(zip(cols, row, strict=True))
        for key in ("version", "build_set", "release"):
            if rec.get(key):
                return str(rec[key])
        return ""

    def describe(self) -> dict[str, object]:
        return {
            "path": str(self.path),
            "table": self.table,
            "columns": sorted(self.columns),
            "indexed": sorted(self.indexed & set(self.columns)),
            "hex_upper": self.upper,
            "version": self.version,
        }

    # ------------------------------------------------------------------ lookups

    def _norm(self, value: str) -> str:
        return value.upper() if self.upper else value.lower()

    def _fallback_clause(self, algo: str) -> str:
        if algo == "sha256":
            return ""
        col = _quote(self.columns["sha256"])
        return f" AND ({col} IS NULL OR {col} = '')"

    def _query_indexed(self, algo: str, wanted: set[str]) -> set[str]:
        col = _quote(self.columns[algo])
        found: set[str] = set()
        values = sorted(wanted)
        for i in range(0, len(values), CHUNK):
            part = [self._norm(v) for v in values[i : i + CHUNK]]
            marks = ",".join("?" * len(part))
            # Names are checked by _quote; the values are bound parameters.
            sql = f"SELECT DISTINCT {col} FROM {_quote(self.table)} WHERE {col} IN ({marks})"  # noqa: S608
            sql += self._fallback_clause(algo)
            found |= {str(r[0]).lower() for r in self.conn.execute(sql, part)}
        return found

    def _query_scan(self, algo: str, wanted: set[str]) -> set[str]:
        """No index on the column: one streaming pass over the table."""
        col = _quote(self.columns[algo])
        sql = f"SELECT {col} FROM {_quote(self.table)} WHERE {col} IS NOT NULL"  # noqa: S608
        sql += self._fallback_clause(algo)
        found: set[str] = set()
        for (value,) in self.conn.execute(sql):
            v = str(value).lower()
            if v in wanted:
                found.add(v)
                if len(found) == len(wanted):
                    break
        return found

    def lookup_values(self, algo: str, values: Iterable[str]) -> set[str]:
        """The subset of ``values`` (hex) present for ``algo``, lower-case."""
        if algo not in self.columns:
            return set()
        wanted = {v.lower() for v in values if v and len(v) == HEX_LEN[algo]}
        if not wanted:
            return set()
        if algo in self.indexed:
            return self._query_indexed(algo, wanted)
        return self._query_scan(algo, wanted)

    def lookup(self, files: dict[str, dict[str, str]]) -> dict[str, NsrlMatch]:
        """``files`` maps a key to ``{"sha256", "sha1", "md5"}``; returns the matched keys."""
        out: dict[str, NsrlMatch] = {}
        for algo in ALGOS:
            pending = {k: h[algo] for k, h in files.items() if k not in out and h.get(algo)}
            if not pending:
                continue
            hits = self.lookup_values(algo, pending.values())
            for key, value in pending.items():
                if value.lower() in hits:
                    out[key] = NsrlMatch(algo, value.lower())
        return out

    def close(self) -> None:
        self.conn.close()

    def __enter__(self) -> NsrlDb:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()
