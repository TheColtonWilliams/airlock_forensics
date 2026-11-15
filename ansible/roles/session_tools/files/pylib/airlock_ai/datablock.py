"""Evidence text as data, never as instructions (hard rule 2.3.9, contract section 7).

Text taken from evidence (document text, transcripts, OCR output) reaches a model only inside
one delimited data block. The delimiter carries a tag derived from the SHA-256 of the cleaned
text, so the text cannot close the block early (it would have to contain a hash of itself).
Before wrapping, control and bidi characters are removed, any ``<<<`` or ``>>>`` sequence is
broken up, and long text is cut to ``max_chars`` with a marker. The fixed prompt files say,
before the block, that everything inside it is data to describe and never instructions.

Filenames and paths are never sent to a model at all.
"""

from __future__ import annotations

import hashlib
import unicodedata

DEFAULT_MAX_CHARS = 12000
_DROP_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Co", "Cn"})
_KEEP = frozenset({"\n", "\t"})


def clean(text: str) -> str:
    """Remove control, format (bidi, zero-width), surrogate, and unassigned characters."""
    out = []
    for ch in text:
        if ch in _KEEP:
            out.append(ch)
            continue
        if unicodedata.category(ch) in _DROP_CATEGORIES:
            continue
        out.append(ch)
    cleaned = "".join(out)
    # Break up anything that looks like a delimiter so evidence cannot fake one.
    while "<<<" in cleaned or ">>>" in cleaned:
        cleaned = cleaned.replace("<<<", "< < <").replace(">>>", "> > >")
    return cleaned


def wrap(text: str, *, kind: str = "document text", max_chars: int = DEFAULT_MAX_CHARS) -> str:
    """Return ``text`` cleaned, truncated, and enclosed in a tagged data block."""
    body = clean(text)
    truncated = len(body) > max_chars
    if truncated:
        body = body[:max_chars]
    tag = hashlib.sha256(body.encode("utf-8", "surrogatepass")).hexdigest()[:16]
    lines = [
        f"<<<DATA {tag} kind={kind}>>>",
        body,
    ]
    if truncated:
        lines.append(f"[cut at {max_chars} characters]")
    lines.append(f"<<<END DATA {tag}>>>")
    return "\n".join(lines)
