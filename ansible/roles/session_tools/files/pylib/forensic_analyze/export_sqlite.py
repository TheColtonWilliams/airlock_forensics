"""``case.sqlite``: the findings as one SQLite table plus ready-made views (4D.5).

Built only from ``findings.jsonl``. One table ``findings`` with one column per schema field
(``rowid`` order = finding order), indexes on ``datetime`` and ``category``, and seven views.
The view definitions are documented in docs/schema.md; ``VIEWS`` below is the source.

The file holds no build timestamps and uses fixed PRAGMA settings, so two builds from the same
``findings.jsonl`` hold the same rows in the same order.
"""

from __future__ import annotations

import os
import sqlite3
import sys
import tempfile
from pathlib import Path
from typing import Any

from forensic_analyze import findings

SQLITE_NAME = "case.sqlite"
# "AIRL" as a 32-bit integer, so `file` and other tools can tell what the database is.
APPLICATION_ID = 0x4149524C

_ORDER_TIME = "substr(datetime, 1, 19), rtrim(substr(datetime, 20), '.0Z'), rowid"

VIEWS: dict[str, str] = {
    # Fixed text from this file only; no row data is ever formatted into SQL.
    "v_timeline": f"SELECT * FROM findings WHERE datetime IS NOT NULL ORDER BY {_ORDER_TIME}",  # noqa: S608
    "v_deleted": (
        "SELECT * FROM findings WHERE allocated = 0 OR category = 'deletion' ORDER BY rowid"
    ),
    "v_recycle_bin": "SELECT * FROM findings WHERE category = 'recycle_bin' ORDER BY rowid",
    "v_media": (
        "SELECT * FROM findings WHERE category IN ('images', 'video', 'audio') ORDER BY rowid"
    ),
    "v_hash_hits": "SELECT * FROM findings WHERE category IN ('malware', 'hash') ORDER BY rowid",
    # Media screening results only: a hash or malware hit also has a label and a score, but
    # it is not a classifier screening result (docs/schema.md).
    "v_flags": (
        "SELECT * FROM findings WHERE category IN ('images', 'video', 'audio', 'documents') "
        "AND (substr(artifact_type, 1, 7) = 'screen_' OR artifact_type = 'carved_media_removed') "
        "AND (sensitive_flag = 1 OR (label IS NOT NULL AND score IS NOT NULL)) ORDER BY rowid"
    ),
    "v_disagreements": "SELECT * FROM findings WHERE xval_status = 'disagree' ORDER BY rowid",
}

_SQL_TYPES = {"string": "TEXT", "integer": "INTEGER", "number": "REAL", "boolean": "INTEGER"}


def columns() -> list[tuple[str, str, str]]:
    """``(name, sql_type, json_type)`` for every schema field, in ``findings.FIELDS`` order."""
    props = findings.load_schema()["properties"]
    out = []
    for name in findings.FIELDS:
        json_type = props[name]["type"]
        out.append((name, _SQL_TYPES[json_type], json_type))
    return out


def _create_sql() -> list[str]:
    required = set(findings.REQUIRED_FIELDS)
    cols = []
    for name, sql_type, json_type in columns():
        parts = [f'"{name}"', sql_type]
        if name in required:
            parts.append("NOT NULL")
        if name == "finding_id":
            parts.append("UNIQUE")
        if json_type == "boolean":
            parts.append(f'CHECK ("{name}" IN (0, 1))')
        cols.append(" ".join(parts))
    stmts = [
        "CREATE TABLE findings (\n  " + ",\n  ".join(cols) + "\n)",
        "CREATE INDEX idx_findings_datetime ON findings (datetime)",
        "CREATE INDEX idx_findings_category ON findings (category)",
        "CREATE TABLE export_info (key TEXT PRIMARY KEY, value TEXT NOT NULL)",
    ]
    stmts += [f"CREATE VIEW {name} AS {sql}" for name, sql in VIEWS.items()]
    return stmts


def _value(value: Any, json_type: str) -> Any:
    if value is None:
        return None
    if json_type == "boolean":
        return 1 if value else 0
    if json_type == "number":
        return float(value)
    return value


def build(run_dir: str | os.PathLike[str]) -> Path:
    """Write ``<run>/case.sqlite`` from ``<run>/findings.jsonl`` and return its path."""
    run = Path(run_dir)
    source = run / findings.FINDINGS_NAME
    target = run / SQLITE_NAME
    cols = columns()
    names = [c[0] for c in cols]
    # Column names come from schema.json, never from row data; values are bound parameters.
    quoted = ", ".join(f'"{n}"' for n in names)
    marks = ", ".join("?" for _ in names)
    insert = f"INSERT INTO findings ({quoted}) VALUES ({marks})"  # noqa: S608
    fd, tmp = tempfile.mkstemp(prefix=f".{SQLITE_NAME}.", dir=run)
    os.close(fd)
    Path(tmp).unlink()
    try:
        con = sqlite3.connect(tmp, isolation_level=None)
        try:
            con.execute("PRAGMA page_size = 4096")
            con.execute("PRAGMA encoding = 'UTF-8'")
            con.execute("PRAGMA journal_mode = OFF")
            con.execute("PRAGMA synchronous = OFF")
            con.execute(f"PRAGMA application_id = {APPLICATION_ID}")
            con.execute(f"PRAGMA user_version = {findings.SCHEMA_VERSION}")
            con.execute("BEGIN")
            for stmt in _create_sql():
                con.execute(stmt)
            count = 0
            batch: list[tuple[Any, ...]] = []
            for row in findings.iter_findings(source):
                errors = findings.validate_row(row)
                if errors:
                    raise findings.SchemaError(errors, where=f"{source} row {count + 1}")
                batch.append(tuple(_value(row.get(n), t) for n, _, t in cols))
                count += 1
                if len(batch) >= 5000:
                    con.executemany(insert, batch)
                    batch.clear()
            if batch:
                con.executemany(insert, batch)
            info = {
                "schema_version": str(findings.SCHEMA_VERSION),
                "findings_sha256": findings.file_sha256(source),
                "row_count": str(count),
                "source": findings.FINDINGS_NAME,
            }
            con.executemany(
                "INSERT INTO export_info (key, value) VALUES (?, ?)", sorted(info.items())
            )
            con.execute("COMMIT")
            con.execute("VACUUM")
        finally:
            con.close()
        Path(tmp).replace(target)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise
    return target


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) != 1:
        print("usage: python3 -m forensic_analyze.export_sqlite RUN_DIR", file=sys.stderr)
        return 2
    try:
        print(build(args[0]))
    except (OSError, sqlite3.Error, findings.SchemaError) as exc:
        print(
            f"export_sqlite: could not build {SQLITE_NAME}: {exc}. "
            "Check findings.jsonl and free space.",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
