"""``findings.csv``: the single flat file, safe to open in a spreadsheet (4D.6, 4D.7).

Generated from ``findings.jsonl`` only. Rules (also in docs/schema.md):

* UTF-8 with a byte order mark, RFC 4180: comma separated, CRLF record ends, ``"`` quoting
  only where needed (``csv.QUOTE_MINIMAL``), ``""`` for a quote inside a cell.
* Fixed column set: ``datetime``, ``timestamp_desc``, ``message`` first (the Timesketch
  import columns), then every other schema field in ``findings.FIELDS`` order. Empty cell =
  field absent.
* Text cells: newline, carriage return, and tab are written as the two characters ``\\n``,
  ``\\r``, ``\\t``; other control, bidi, and invisible characters as ``\\uXXXX``. So every record
  is exactly one line, and nothing can reorder or hide text on screen.
* A text cell whose raw value starts with ``=``, ``+``, ``-``, ``@`` (or their full-width
  forms), after any leading whitespace, or starts with a tab or carriage return, gets a
  leading ``'``. Number cells are written as plain numbers and are not changed.
* ``path_b64`` keeps the raw bytes of hostile names; base64 decoders that skip non-alphabet
  characters ignore a leading ``'`` (``findings.decode_path_b64`` strips it).
* Rows produced by a model (``derivation`` = ``ai_generated``) have ``message`` prefixed with
  ``AI-generated:`` so the label survives outside the report.
"""

from __future__ import annotations

import csv
import os
import sys
import tempfile
from pathlib import Path
from typing import Any

from forensic_analyze import findings
from forensic_analyze.csvsafe import csv_cell

CSV_NAME = "findings.csv"
TIMESKETCH_COLUMNS: tuple[str, ...] = ("datetime", "timestamp_desc", "message")
COLUMNS: tuple[str, ...] = TIMESKETCH_COLUMNS + tuple(
    f for f in findings.FIELDS if f not in TIMESKETCH_COLUMNS
)
AI_LABEL = "AI-generated: "


def csv_row(row: dict[str, Any]) -> list[str]:
    """The CSV cells for one finding, in ``COLUMNS`` order."""
    values = dict(row)
    message = values.get("message")
    if (
        values.get("derivation") == "ai_generated"
        and isinstance(message, str)
        and not message.startswith(AI_LABEL)
    ):
        values["message"] = AI_LABEL + message
    return [csv_cell(values.get(c)) for c in COLUMNS]


def build(run_dir: str | os.PathLike[str]) -> Path:
    """Write ``<run>/findings.csv`` from ``<run>/findings.jsonl`` and return its path."""
    run = Path(run_dir)
    source = run / findings.FINDINGS_NAME
    target = run / CSV_NAME
    fd, tmp = tempfile.mkstemp(prefix=f".{CSV_NAME}.", dir=run)
    try:
        with os.fdopen(fd, "w", encoding="utf-8-sig", newline="") as fh:
            writer = csv.writer(
                fh, dialect="excel", quoting=csv.QUOTE_MINIMAL, lineterminator="\r\n"
            )
            writer.writerow(COLUMNS)
            for n, row in enumerate(findings.iter_findings(source), 1):
                errors = findings.validate_row(row)
                if errors:
                    raise findings.SchemaError(errors, where=f"{source} row {n}")
                writer.writerow(csv_row(row))
            fh.flush()
            os.fsync(fh.fileno())
        Path(tmp).replace(target)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise
    return target


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) != 1:
        print("usage: python3 -m forensic_analyze.export_csv RUN_DIR", file=sys.stderr)
        return 2
    try:
        print(build(args[0]))
    except (OSError, findings.SchemaError) as exc:
        print(
            f"export_csv: could not build {CSV_NAME}: {exc}. Check findings.jsonl and free space.",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
