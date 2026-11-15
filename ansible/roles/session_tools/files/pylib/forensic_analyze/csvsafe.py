"""Make evidence-derived text safe to show and safe to open in a spreadsheet.

Two jobs, both standard library only:

* ``display_escape`` turns text that came from evidence (file names, document text) into a
  string that cannot reorder or hide characters on screen: control characters, bidi overrides,
  invisible format characters, line and paragraph separators, and lone surrogates are shown as
  escapes such as ``\\u202e``. Newline, carriage return, and tab become ``\\n``, ``\\r``, ``\\t``.
* ``neutralise_formula`` adds a leading ``'`` to a cell a spreadsheet would read as a formula.

``csv_cell`` combines the two for one CSV cell. Other packages (report inputs, hash triage,
AI CSVs) import these instead of writing their own. Rules are documented in docs/schema.md.
"""

from __future__ import annotations

import math
import unicodedata

# Characters a spreadsheet treats as the start of a formula (ASCII and full-width forms).
FORMULA_START = frozenset("=+-@" + "".join(map(chr, (0xFF1D, 0xFF0B, 0xFF0D, 0xFF20))))
# A cell whose raw value starts with one of these is neutralised even before whitespace stripping.
FORMULA_START_RAW = frozenset("\t\r")
NEUTRALISER = "'"

_SHORT_ESCAPES = {"\n": "\\n", "\r": "\\r", "\t": "\\t"}
# Unicode categories shown escaped: control, format (bidi marks, zero-width), surrogate,
# line separator, paragraph separator, unassigned private-use is left alone.
_ESCAPE_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Zl", "Zp"})


def needs_escape(ch: str) -> bool:
    """True if ``ch`` must not be shown raw (it could hide, reorder, or break a line)."""
    return unicodedata.category(ch) in _ESCAPE_CATEGORIES


def escape_char(ch: str) -> str:
    """The visible escape for one character: ``\\n``, ``\\u202e`` or ``\\U000e0001``."""
    short = _SHORT_ESCAPES.get(ch)
    if short is not None:
        return short
    cp = ord(ch)
    if cp > 0xFFFF:
        return f"\\U{cp:08x}"
    return f"\\u{cp:04x}"


def display_escape(text: str) -> str:
    """Escape every character that ``needs_escape``. Other text, backslashes included, is kept."""
    if not any(needs_escape(c) for c in text):
        return text
    return "".join(escape_char(c) if needs_escape(c) else c for c in text)


def is_safe_display(text: str) -> bool:
    """True if ``text`` holds nothing ``display_escape`` would change."""
    return not any(needs_escape(c) for c in text)


def starts_like_formula(raw: str) -> bool:
    """True if a spreadsheet could read ``raw`` as a formula.

    Checked on the raw value: a leading tab or carriage return, or a formula character as the
    first character after leading whitespace is stripped (some spreadsheets skip spaces).
    """
    if not raw:
        return False
    if raw[0] in FORMULA_START_RAW:
        return True
    stripped = raw.lstrip()
    return bool(stripped) and stripped[0] in FORMULA_START


def neutralise_formula(raw: str, shown: str | None = None) -> str:
    """Return ``shown`` (default ``raw``) with a leading ``'`` if ``raw`` starts like a formula."""
    out = raw if shown is None else shown
    if starts_like_formula(raw):
        return NEUTRALISER + out
    return out


def format_number(value: int | float) -> str:
    """Numbers as plain decimal text. Non-finite floats are refused by the schema."""
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("non-finite number")
        return repr(value)
    return str(value)


def csv_cell(value: object) -> str:
    """One CSV cell: escaped for display and neutralised against formulas.

    ``None`` is empty, booleans are ``true``/``false``, numbers are plain decimal text and are
    not neutralised (a value such as ``-1.5`` is a number, not a formula). Everything else is
    treated as text.
    """
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int | float):
        return format_number(value)
    raw = str(value)
    return neutralise_formula(raw, display_escape(raw))
